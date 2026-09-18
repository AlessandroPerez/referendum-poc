//! Protocol flow tests over the full HTTPS cluster: coercion (ruse PIN),
//! wrong PIN, re-vote last-wins, revocation with tally filtering,
//! new-device recovery, PIN re-send, CAT/rate-limit negatives, idempotent
//! casting, and the public wbb-ui smoke.
//!
//! `wbb_policy_enforcement` lives in `voting.rs`.

use super::helpers::{get_json, ElectionCluster, ElectionOpts};

/// V7: the ruse-PIN ballot is accepted by both BBs - indistinguishable from
/// a real cast - and silently filtered by the tally ACC check; the valid-PIN
/// ballot is counted.
#[tokio::test]
async fn coercion_ruse_pin() {
    let mut cluster = ElectionCluster::start(2, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    cluster.open_voting().await;

    let pin0 = cluster.pin(0).await;
    let ruse = cluster.ruse_pin(0).await;
    assert_ne!(ruse, pin0, "ruse PIN differs from the real PIN");

    // The coerced cast: locally verifiable, accepted by both BBs.
    let ruse_verify = cluster
        .voter_post(
            0,
            "/api/pin/verify",
            serde_json::json!({ "passphrase": cluster.passphrases[0], "pin": ruse }),
        )
        .await;
    assert_eq!(ruse_verify["valid"], true, "ruse PIN verifies locally");
    let ruse_vote = cluster.vote_and_cast(0, "reject", ruse).await;

    // The real cast, after the coercer leaves.
    let real_vote = cluster.vote_and_cast(0, "approve", pin0).await;
    assert_ne!(ruse_vote["digest"], real_vote["digest"]);

    // Coercer view at cast time: both responses expose exactly the same
    // shape (digest + emoji), and both ballots land on the public log.
    for vote in [&ruse_vote, &real_vote] {
        assert!(vote["digest"].is_string());
        assert!(!vote["emoji"].as_array().unwrap().is_empty());
    }
    assert_eq!(
        cluster.entry_type_count("ballot_digest").await,
        4,
        "ruse and real casts are indistinguishable on the WBB (2 each)"
    );
    assert_eq!(
        cluster.entry_type_count("cast_intended_proof").await,
        4,
        "the coerced voter confirms the ruse ballot too - indistinguishable"
    );

    let pin1 = cluster.pin(1).await;
    cluster.vote_and_cast(1, "approve", pin1).await;

    cluster.close_voting().await;
    let outcome = cluster.tally().await;
    assert_eq!(outcome.released, 6, "3 casts x 2 BBs");
    assert_eq!(outcome.reconciled, 3);
    assert_eq!(outcome.deduped, 3, "ruse and real ballots do not merge");
    assert_eq!(outcome.valid, 2, "the ruse ballot dies at the ACC check");
    assert_eq!(outcome.legitimate, 2);
    assert_eq!(
        (outcome.counts.blank, outcome.counts.si, outcome.counts.no),
        (0, 2, 0),
        "only the valid-PIN ballots count"
    );

    let report = cluster.audit().await;
    assert!(report.ok(), "audit:\n{}", report.render());
}

/// V5 negative: a wrong-PIN ballot passes the BB proof checks but is
/// filtered by the ACC check at tally.
#[tokio::test]
async fn wrong_pin() {
    let mut cluster = ElectionCluster::start(3, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    cluster.open_voting().await;

    let pin = cluster.pin(0).await;
    let wrong = (pin + 1) % 100_000_000;
    cluster.vote_and_cast(0, "reject", wrong).await;
    cluster.vote_and_cast(0, "approve", pin).await;
    let pin1 = cluster.pin(1).await;
    cluster.vote_and_cast(1, "approve", pin1).await;
    let pin2 = cluster.pin(2).await;
    cluster.vote_and_cast(2, "blank", pin2).await;

    cluster.close_voting().await;
    let outcome = cluster.tally().await;
    assert_eq!(outcome.released, 8, "4 casts x 2 BBs");
    assert_eq!(outcome.reconciled, 4);
    assert_eq!(
        outcome.deduped, 4,
        "different PINs do not merge in ox dedup"
    );
    assert_eq!(outcome.valid, 3, "wrong-PIN ballot dies at the ACC check");
    assert_eq!(outcome.legitimate, 3);
    assert_eq!(
        (outcome.counts.blank, outcome.counts.si, outcome.counts.no),
        (1, 2, 0),
        "the wrong-PIN reject never counts"
    );
}

/// Sec. 3.9 step 10: two valid ballots from the same credential - only the
/// last-cast one survives the ox fingerprint dedup.
#[tokio::test]
async fn revote_last_wins() {
    let mut cluster = ElectionCluster::start(3, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    cluster.open_voting().await;

    let pin = cluster.pin(0).await;
    cluster.vote_and_cast(0, "approve", pin).await;
    cluster.vote_and_cast(0, "reject", pin).await;
    let pin1 = cluster.pin(1).await;
    cluster.vote_and_cast(1, "approve", pin1).await;
    let pin2 = cluster.pin(2).await;
    cluster.vote_and_cast(2, "blank", pin2).await;

    cluster.close_voting().await;
    let outcome = cluster.tally().await;
    assert_eq!(outcome.released, 8, "4 casts x 2 BBs");
    assert_eq!(outcome.reconciled, 4);
    assert_eq!(
        outcome.deduped, 3,
        "same credential + PIN merges: last wins"
    );
    assert_eq!(outcome.valid, 3);
    assert_eq!(outcome.legitimate, 3);
    assert_eq!(
        (outcome.counts.blank, outcome.counts.si, outcome.counts.no),
        (1, 1, 1),
        "voter 1's later reject wins over the earlier approve"
    );
}

/// V9: a revoked vid's earlier ballot is illegitimate at tally; the
/// re-issued spare credential votes; the commitment entry is on the WBB.
#[tokio::test]
async fn revocation() {
    let mut cluster = ElectionCluster::start(2, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    cluster.open_voting().await;

    // Voter 1 casts with the ORIGINAL credential (vid 1), then revokes.
    let pin0 = cluster.pin(0).await;
    cluster.vote_and_cast(0, "approve", pin0).await;

    let revoked = cluster
        .voter_post(
            0,
            "/api/revoke",
            serde_json::json!({ "passphrase": cluster.passphrases[0] }),
        )
        .await;
    let new_vid = revoked["vid"].as_u64().unwrap();
    assert_eq!(new_vid, 9, "first spare vid is n_voters + 1 ");
    assert_eq!(
        cluster.entry_type_count("revocation_commitment").await,
        1,
        "revocation commitment published (Sec. 3.7.5)"
    );

    // The re-issued credential delivers a fresh PIN and votes.
    super::helpers::wait_pin_ready(
        &cluster.client,
        &cluster.voter_urls[0],
        &cluster.passphrases[0],
    )
    .await;
    let retrieved = cluster
        .voter_post(
            0,
            "/api/pin/retrieve",
            serde_json::json!({ "passphrase": cluster.passphrases[0] }),
        )
        .await;
    let new_pin = retrieved["pin"].as_u64().unwrap();
    assert_ne!(new_pin, pin0, "spare credential has a different PIN");
    cluster.vote_and_cast(0, "reject", new_pin).await;

    let pin1 = cluster.pin(1).await;
    cluster.vote_and_cast(1, "approve", pin1).await;

    // A7: the eligible list swaps vid 1 for spare vid 9.
    cluster.close_voting().await;
    let outcome = cluster.tally().await;
    let eligible = get_json(
        &cluster.client,
        &format!("{}/voters/eligible", cluster.er_base()),
    )
    .await;
    let vids: Vec<u64> = serde_json::from_value(eligible["vids"].clone()).unwrap();
    assert!(!vids.contains(&1), "revoked vid must not be eligible");
    assert!(vids.contains(&9), "spare vid must be eligible");

    assert_eq!(outcome.released, 6, "3 casts x 2 BBs");
    assert_eq!(outcome.reconciled, 3);
    assert_eq!(outcome.deduped, 3, "old and spare credentials do not merge");
    assert_eq!(outcome.valid, 3, "all three ballots pass the ACC check");
    assert_eq!(
        outcome.legitimate, 2,
        "the revoked credential's ballot is filtered as illicit"
    );
    assert_eq!(
        (outcome.counts.blank, outcome.counts.si, outcome.counts.no),
        (0, 1, 1),
        "only the spare-credential and voter-2 ballots count"
    );

    let report = cluster.audit().await;
    assert!(report.ok(), "audit:\n{}", report.render());
}

/// V8: passphrase recovery restores the credential on a fresh device;
/// a wrong passphrase fails closed.
#[tokio::test]
async fn new_device() {
    let mut cluster = ElectionCluster::start(1, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    let pin = cluster.pin(0).await;

    // A fresh voter-server = a new device with empty local state.
    let fresh = cluster
        .spawn_voter_server_as("voter-1", "voter-1-newdevice")
        .await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let wrong = cluster
        .client
        .post(format!("{fresh}/api/device/recover"))
        .json(&serde_json::json!({
            "fiscal_id": "VOTER-001",
            "passphrase": "wrong-wrong-wrong-wrong-wrong-wrong"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(wrong.status(), 401, "wrong passphrase must fail closed");

    let recovered = super::helpers::post_json(
        &cluster.client,
        &format!("{fresh}/api/device/recover"),
        serde_json::json!({
            "fiscal_id": "VOTER-001",
            "passphrase": cluster.passphrases[0]
        }),
    )
    .await;
    assert_eq!(recovered["vid"], 1);
    assert_eq!(recovered["pin_set"], true);

    // The recovered device shows and verifies the ORIGINAL PIN.
    let shown = super::helpers::post_json(
        &cluster.client,
        &format!("{fresh}/api/pin"),
        serde_json::json!({ "passphrase": cluster.passphrases[0] }),
    )
    .await;
    assert_eq!(shown["pin"].as_u64().unwrap(), pin);
    let verify = super::helpers::post_json(
        &cluster.client,
        &format!("{fresh}/api/pin/verify"),
        serde_json::json!({ "passphrase": cluster.passphrases[0], "pin": pin }),
    )
    .await;
    assert_eq!(verify["valid"], true, "voting ability restored");
}

/// V6: a re-delivered PIN equals the original and keeps verifying.
#[tokio::test]
async fn pin_resend() {
    let mut cluster = ElectionCluster::start(1, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    let pin = cluster.pin(0).await;

    let resent = cluster
        .voter_post(
            0,
            "/api/pin/resend",
            serde_json::json!({ "passphrase": cluster.passphrases[0] }),
        )
        .await;
    assert_eq!(
        resent["pin"].as_u64().unwrap(),
        pin,
        "re-delivered PIN equals the original (Sec. 3.7.2)"
    );
    let verify = cluster
        .voter_post(
            0,
            "/api/pin/verify",
            serde_json::json!({ "passphrase": cluster.passphrases[0], "pin": pin }),
        )
        .await;
    assert_eq!(verify["valid"], true, "functionality restored");
}

/// V12 negatives: the CAT rate limit is enforced over distinct ballot
/// commitments, casting without tokens/a ballot fails, and the BB rejects
/// malformed CAT material.
#[tokio::test]
async fn rate_limit_and_cat() {
    let mut cluster = ElectionCluster::start(
        1,
        ElectionOpts {
            max_casts_per_voter: Some(2),
            ..Default::default()
        },
    )
    .await;
    cluster.enroll_all().await;
    cluster.open_voting().await;
    let pin = cluster.pin(0).await;

    // Cast before vote: no held ballot -> 400.
    let no_ballot = cluster
        .client
        .post(format!("{}/api/cast", cluster.voter_urls[0]))
        .json(&serde_json::json!({ "passphrase": cluster.passphrases[0] }))
        .send()
        .await
        .unwrap();
    assert_eq!(no_ballot.status(), 400, "cast before vote must fail");

    // Two distinct commitments pass; the idempotent re-cast of the second
    // burns no budget; the third distinct commitment is rate-limited.
    cluster.vote_and_cast(0, "approve", pin).await;
    cluster.vote(0, "reject", pin).await;
    let cast2 = cluster.cast(0).await;
    let recast = cluster.cast(0).await;
    assert_eq!(
        recast["receipts"], cast2["receipts"],
        "idempotent replay returns the same receipts without burning budget"
    );
    cluster.vote(0, "blank", pin).await;
    let limited = cluster
        .client
        .post(format!("{}/api/cast", cluster.voter_urls[0]))
        .json(&serde_json::json!({ "passphrase": cluster.passphrases[0] }))
        .send()
        .await
        .unwrap();
    assert!(
        !limited.status().is_success(),
        "3rd distinct ballot commitment must be rate-limited (max 2)"
    );

    // CAT negatives straight at the authorities: casting tokens without the
    // registration bearer are refused, and the BB rejects malformed intake.
    let no_bearer = cluster
        .client
        .post(format!("{}/tokens/casting", cluster.er_base()))
        .json(&serde_json::json!({ "comm_b": "00", "signature": "AA==" }))
        .send()
        .await
        .unwrap();
    assert!(
        no_bearer.status().is_client_error(),
        "casting tokens require the registration session (got {})",
        no_bearer.status()
    );
    let malformed = cluster
        .client
        .post(format!("https://127.0.0.1:{}/ballots", cluster.ports.bb[0]))
        .json(&serde_json::json!({ "ballot": {}, "rndcomm": "zz", "casting_token": "AAAA" }))
        .send()
        .await
        .unwrap();
    assert!(
        malformed.status().is_client_error(),
        "BB must reject malformed CAT material (got {})",
        malformed.status()
    );

    // -- commB binding + single-use, at the ER enforcement point.
    //    Mint REAL casting tokens with a test-owned device: DIP assertion ->
    //    ER login -> device registration with our own AtSK -> /tokens/casting.
    //    (BB intake calls this same /tokens/verify and maps `valid: false`
    //    to 401 Unauthorized - asserted in the voting tests.) ------------------------------
    use base64::Engine as _;
    use ed25519_dalek::Signer as _;
    let b64 = &base64::engine::general_purpose::STANDARD;
    let b64url = &base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let dip = super::helpers::post_json(
        &cluster.client,
        &format!("https://127.0.0.1:{}/authenticate", cluster.ports.dip),
        serde_json::json!({ "fiscal_id": "VOTER-002" }),
    )
    .await;
    let login = super::helpers::post_json(
        &cluster.client,
        &format!("{}/login", cluster.er_base()),
        serde_json::json!({ "assertion": dip["assertion"], "signature": dip["signature"] }),
    )
    .await;
    let reg_token = login["registration_token"].as_str().unwrap().to_string();

    let at_sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let registered = cluster
        .client
        .post(format!("{}/devices", cluster.er_base()))
        .json(&serde_json::json!({
            "registration_token": reg_token,
            "at_pk": hex::encode(at_sk.verifying_key().to_bytes()),
        }))
        .send()
        .await
        .unwrap();
    assert!(registered.status().is_success(), "device registration");

    let comm_bytes = [9u8; 32];
    let comm_b = b64url.encode(comm_bytes);
    let minted: serde_json::Value = {
        let response = cluster
            .client
            .post(format!("{}/tokens/casting", cluster.er_base()))
            .header("Authorization", format!("Bearer {reg_token}"))
            .json(&serde_json::json!({
                "comm_b": comm_b,
                "signature": b64.encode(at_sk.sign(&comm_bytes).to_bytes()),
            }))
            .send()
            .await
            .unwrap();
        assert!(response.status().is_success(), "casting token mint");
        response.json().await.unwrap()
    };
    let token = minted["casting_tokens"][0].as_str().unwrap().to_string();

    let internal_token =
        std::fs::read_to_string(cluster.ceremony_dir().join("internal-api-token.txt"))
            .unwrap()
            .trim()
            .to_string();
    let verify = |token: String, comm: String, consume: bool| {
        let client = cluster.client.clone();
        let url = format!("{}/tokens/verify", cluster.er_base());
        let bearer = format!("Bearer {internal_token}");
        async move {
            let response = client
                .post(url)
                .header("Authorization", bearer)
                .json(&serde_json::json!({
                    "token": token,
                    "expected_type": "casting",
                    "consume": consume,
                    "comm_b": comm,
                }))
                .send()
                .await
                .unwrap();
            assert!(response.status().is_success());
            let body: serde_json::Value = response.json().await.unwrap();
            body["valid"].as_bool().unwrap()
        }
    };

    let wrong_comm = b64url.encode([10u8; 32]);
    assert!(
        !verify(token.clone(), wrong_comm, false).await,
        "a commB different from the token's binding must not verify"
    );
    assert!(
        verify(token.clone(), comm_b.clone(), true).await,
        "the bound commB verifies and consumes the single-use token"
    );
    assert!(
        !verify(token, comm_b.clone(), true).await,
        "a consumed casting token must not be reusable"
    );

    // -- The same two negatives observed at the BB intake itself (
    //    both map to 401). A released ballot with two inner elements
    //    swapped deserializes fine but has a fresh digest, so the intake
    //    proceeds past the idempotency lookup to token verification. ------
    let bb_token = std::fs::read_to_string(cluster.ceremony_dir().join("bb-1-service-token.txt"))
        .unwrap()
        .trim()
        .to_string();
    let released: serde_json::Value = {
        let response = cluster
            .client
            .get(format!("https://127.0.0.1:{}/ballots", cluster.ports.bb[0]))
            .header("Authorization", format!("Bearer {bb_token}"))
            .send()
            .await
            .unwrap();
        assert!(response.status().is_success(), "ballot release");
        response.json().await.unwrap()
    };
    let mut foreign_ballot = released[0]["ballot"].clone();
    assert!(
        swap_first_distinct_array_pair(&mut foreign_ballot),
        "expected a swappable element pair in the released ballot"
    );

    let token2 = minted["casting_tokens"][1].as_str().unwrap();
    let cast_at_bb = || async {
        cluster
            .client
            .post(format!("https://127.0.0.1:{}/ballots", cluster.ports.bb[0]))
            .json(&serde_json::json!({
                "ballot": foreign_ballot,
                "rndcomm": hex::encode([1u8; 32]),
                "casting_token": token2,
            }))
            .send()
            .await
            .unwrap()
            .status()
    };
    // The recomputed commB cannot match token2's binding -> 401.
    assert_eq!(cast_at_bb().await, 401, "commB mismatch is a BB-level 401");
    // token2 was NOT consumed by the mismatch; consume it legitimately...
    assert!(
        verify(token2.to_string(), comm_b, true).await,
        "a mismatched attempt must not consume the token"
    );
    // ...and the consumed token is now refused at the BB too.
    assert_eq!(
        cast_at_bb().await,
        401,
        "consumed-token reuse is a BB-level 401"
    );
}

/// Sec. 3.9 step 2 / Sec. 3.10 1(d): a ballot that was cast but never confirmed
/// (no cast-as-intended disclosure) is accepted by the BBs yet discarded at
/// release, never counted, and its absence is not a censorship finding.
#[tokio::test]
async fn unconfirmed_ballot_excluded() {
    let mut cluster = ElectionCluster::start(4, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    cluster.open_voting().await;

    for (i, option) in ["approve", "reject", "blank"].iter().enumerate() {
        let pin = cluster.pin(i).await;
        cluster.vote_and_cast(i, option, pin).await;
    }
    let pin3 = cluster.pin(3).await;
    let unconfirmed = cluster.vote_and_cast_unconfirmed(3, "approve", pin3).await;
    let status = cluster
        .voter_post(
            3,
            "/api/ballot/status",
            serde_json::json!({ "passphrase": cluster.passphrases[3] }),
        )
        .await;
    assert_eq!(
        status["no_bot"], true,
        "the unconfirmed ballot WAS accepted"
    );

    assert_eq!(
        cluster.entry_type_count("ballot_digest").await,
        8,
        "4 casts x 2 BBs"
    );
    assert_eq!(
        cluster.entry_type_count("cast_intended_proof").await,
        6,
        "only 3 ballots were confirmed"
    );

    cluster.close_voting().await;
    let outcome = cluster.tally().await;
    assert_eq!(
        outcome.released, 6,
        "the unconfirmed ballot is not released"
    );
    assert_eq!(outcome.reconciled, 3);
    assert_eq!(outcome.legitimate, 3);
    assert_eq!(
        (outcome.counts.blank, outcome.counts.si, outcome.counts.no),
        (1, 1, 1),
        "voter 4's unconfirmed approve is not counted"
    );
    let released_digests: Vec<String> = {
        let entries = cluster.wbb.client.entries().await.unwrap();
        entries
            .entries
            .iter()
            .filter_map(|e| e.entry.get("data").and_then(|v| v.as_str()))
            .filter_map(|b64| {
                use base64::Engine as _;
                base64::engine::general_purpose::STANDARD.decode(b64).ok()
            })
            .filter_map(|d| referendum_poc::protocol::voting::parse_wbb_data(&d))
            .filter(|p| p.entry_type == "encrypted_ballot")
            .map(|p| p.content)
            .collect()
    };
    assert_eq!(released_digests.len(), 6);

    let report = cluster.audit().await;
    assert!(report.ok(), "audit:\n{}", report.render());
    assert!(
        report
            .steps
            .iter()
            .any(|s| s.name == "cai_confirmation" && s.ok),
        "the auditor re-verifies every released confirmation"
    );
    drop(unconfirmed);
}

/// A4 seam: a ballot cast after `close-voting` is refused by the BBs (its
/// digest can no longer be published), leaves no stored state, and is not
/// counted - the election stays auditable.
#[tokio::test]
async fn late_cast_rejected() {
    let mut cluster = ElectionCluster::start(4, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    cluster.open_voting().await;

    for (i, option) in ["approve", "reject", "blank"].iter().enumerate() {
        let pin = cluster.pin(i).await;
        cluster.vote_and_cast(i, option, pin).await;
    }
    // Voter 4 builds a ballot in time but casts after the window closes.
    let pin3 = cluster.pin(3).await;
    let late = cluster.vote(3, "approve", pin3).await;
    cluster.close_voting().await;

    let cast = cluster
        .client
        .post(format!("{}/api/cast", cluster.voter_urls[3]))
        .json(&serde_json::json!({ "passphrase": cluster.passphrases[3] }))
        .send()
        .await
        .unwrap();
    assert!(
        !cast.status().is_success(),
        "a cast after close-voting must be refused (got {})",
        cast.status()
    );
    // Nothing was stored: the BB has no receipt for the late digest.
    let receipt = cluster
        .client
        .get(format!(
            "https://127.0.0.1:{}/receipts/{}",
            cluster.ports.bb[0],
            late["digest"].as_str().unwrap()
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(receipt.status(), 404, "the late ballot was rolled back");
    assert_eq!(cluster.entry_type_count("ballot_digest").await, 6);

    let outcome = cluster.tally().await;
    assert_eq!(outcome.released, 6);
    assert_eq!(
        (outcome.counts.blank, outcome.counts.si, outcome.counts.no),
        (1, 1, 1),
        "the late ballot is not counted"
    );
    let report = cluster.audit().await;
    assert!(report.ok(), "audit:\n{}", report.render());
}

/// A credential can be revoked as soon as the voter has enrolled, i.e. while
/// the board is still in its setup window (Sec. 3.7.5); once voting is over
/// the request is refused and must not burn a spare credential.
#[tokio::test]
async fn revocation_during_enrollment_and_after_close() {
    let mut cluster = ElectionCluster::start(3, ElectionOpts::default()).await;
    cluster.enroll_all().await;

    // Voter 1 revokes BEFORE the voting window opens.
    let revoked = cluster
        .voter_post(
            0,
            "/api/revoke",
            serde_json::json!({ "passphrase": cluster.passphrases[0] }),
        )
        .await;
    let first_spare = revoked["vid"].as_u64().unwrap();
    assert_eq!(
        first_spare, 9,
        "first spare vid is the election's n_voters + 1"
    );
    let rows = get_json(
        &cluster.client,
        &format!("{}/api/entries", cluster.ui_base()),
    )
    .await;
    let commitments: Vec<_> = rows
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["entry_type"] == "revocation_commitment")
        .collect();
    assert_eq!(commitments.len(), 1);
    assert_eq!(
        commitments[0]["phase"], "setup",
        "stamped with the board's phase"
    );

    // The re-issued credential works once voting opens.
    cluster.open_voting().await;
    super::helpers::wait_pin_ready(
        &cluster.client,
        &cluster.voter_urls[0],
        &cluster.passphrases[0],
    )
    .await;
    let retrieved = cluster
        .voter_post(
            0,
            "/api/pin/retrieve",
            serde_json::json!({ "passphrase": cluster.passphrases[0] }),
        )
        .await;
    cluster
        .vote_and_cast(0, "approve", retrieved["pin"].as_u64().unwrap())
        .await;

    // After close-voting a revocation is refused...
    cluster.close_voting().await;
    let late = cluster
        .client
        .post(format!("{}/api/revoke", cluster.voter_urls[1]))
        .json(&serde_json::json!({ "passphrase": cluster.passphrases[1] }))
        .send()
        .await
        .unwrap();
    assert!(
        !late.status().is_success(),
        "revocation after close: {}",
        late.status()
    );
    assert_eq!(cluster.entry_type_count("revocation_commitment").await, 1);
    // The voter server relays the refusal; the electoral roll's own 409 and
    // the "no spare is burnt" property are checked in
    // `failed_revocation_burns_no_spare`, which can make a publication fail.
    let eligible = get_json(
        &cluster.client,
        &format!("{}/voters/eligible", cluster.er_base()),
    )
    .await;
    let vids: Vec<u64> = serde_json::from_value(eligible["vids"].clone()).unwrap();
    assert!(vids.contains(&2) && vids.contains(&first_spare) && !vids.contains(&1));
}

/// Two revocation requests of the SAME voter racing each other must form a
/// chain (1 -> 9 -> 10): the second revokes the id the first one issued. If
/// the voter's current id were read before the requests are serialised, both
/// would revoke id 1, leaving spare 9 enrolled, never revoked, and its
/// registration token alive - that is what this test catches. (It cannot hit
/// the microsecond window between publication and the state change; that one
/// is closed by construction: the lock is held until every change is made.)
#[tokio::test]
async fn concurrent_revocations_of_one_voter_chain() {
    use referendum_poc::clients::{dip::DipClient, er::ErClient};

    let mut cluster = ElectionCluster::start(1, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    let er = ErClient::new(
        cluster.client.clone(),
        reqwest::Url::parse(&cluster.er_base()).unwrap(),
    );
    let dip = DipClient::new(
        cluster.client.clone(),
        reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.dip)).unwrap(),
    );
    let auth = dip.authenticate("VOTER-001").await.expect("eID assertion");

    let (a, b) = tokio::join!(
        er.revoke(&auth.assertion, &auth.signature),
        er.revoke(&auth.assertion, &auth.signature)
    );
    let (a, b) = (a.expect("first revocation"), b.expect("second revocation"));
    let (first, second) = if a.vid.value() < b.vid.value() {
        (a, b)
    } else {
        (b, a)
    };
    assert_eq!((first.vid.value(), second.vid.value()), (9, 10));
    assert_eq!(cluster.entry_type_count("revocation_commitment").await, 2);

    // Id 9 was issued and then revoked by the second request: its registration
    // token is dead, while the final id's token works.
    assert!(
        er.pin_request_tokens(&first.registration_token)
            .await
            .is_err(),
        "the intermediate spare id must have been revoked"
    );
    er.pin_request_tokens(&second.registration_token)
        .await
        .expect("the final id is live");

    // The voter now holds id 10, and only id 10 is eligible.
    let login = er
        .login(&auth.assertion, &auth.signature)
        .await
        .expect("login");
    assert_eq!(login.vid.value(), 10);
    let eligible = get_json(
        &cluster.client,
        &format!("{}/voters/eligible", cluster.er_base()),
    )
    .await;
    let vids: Vec<u64> = serde_json::from_value(eligible["vids"].clone()).unwrap();
    assert!(
        vids.contains(&10) && !vids.contains(&9) && !vids.contains(&1),
        "{vids:?}"
    );
}

/// Spare ids are allocated from what the BOARD shows, not from one process's
/// memory: an electoral roll that starts with empty memory must not hand out
/// an id another voter already holds, must recognise its own earlier
/// commitment, and must say so when the spares run out.
#[tokio::test]
async fn spare_ids_follow_the_board_across_restarts() {
    use referendum_poc::clients::{dip::DipClient, er::ErClient, er::ErError};

    let mut cluster = ElectionCluster::start(1, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    let dip = DipClient::new(
        cluster.client.clone(),
        reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.dip)).unwrap(),
    );
    let voter1 = dip.authenticate("VOTER-001").await.unwrap();
    let voter2 = dip.authenticate("VOTER-002").await.unwrap();
    let voter3 = dip.authenticate("VOTER-003").await.unwrap();

    // Voter 1 revokes on the cluster's electoral roll: first spare.
    let er1 = ErClient::new(
        cluster.client.clone(),
        reqwest::Url::parse(&cluster.er_base()).unwrap(),
    );
    let first = er1
        .revoke(&voter1.assertion, &voter1.signature)
        .await
        .unwrap();
    assert_eq!(first.vid.value(), 9);

    // A second electoral roll with EMPTY memory faces the same board.
    let fresh_url = cluster.spawn_er_with_board(cluster.wbb_url.as_str()).await;
    let fresh = ErClient::new(
        cluster.client.clone(),
        reqwest::Url::parse(&fresh_url).unwrap(),
    );
    // Another voter must get the NEXT id, not voter 1's.
    let second = fresh
        .revoke(&voter2.assertion, &voter2.signature)
        .await
        .unwrap();
    assert_eq!(
        second.vid.value(),
        10,
        "id 9 is taken according to the board"
    );
    // Voter 1 asking again is recognised by their published commitment.
    let again = fresh
        .revoke(&voter1.assertion, &voter1.signature)
        .await
        .unwrap();
    assert_eq!(again.vid.value(), 9);
    assert_eq!(cluster.entry_type_count("revocation_commitment").await, 2);
    // Both spares are gone: the next voter is told so.
    match fresh.revoke(&voter3.assertion, &voter3.signature).await {
        Err(ErError::Http(status, body)) => {
            assert_eq!(status, reqwest::StatusCode::CONFLICT);
            assert!(body.contains("no spare credential"), "{body}");
        }
        other => panic!("expected 409 when spares are exhausted, got {other:?}"),
    }
}

/// A stand-in bulletin board for fault injection: it reports the `setup`
/// phase, serves the entries it accepted, and refuses `POST /submit` with 503
/// until `accept` is switched on.
#[derive(Clone, Default)]
struct FlakyBoard {
    accept: std::sync::Arc<std::sync::atomic::AtomicBool>,
    submissions: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    entries: std::sync::Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
}

impl FlakyBoard {
    /// Start a listener on the shared state and return the board's base URL.
    async fn serve(&self) -> String {
        use axum::{
            extract::State,
            http::StatusCode,
            routing::{get, post},
            Json, Router,
        };
        use std::sync::atomic::Ordering;
        let app = Router::new()
            .route(
                "/wbb/phase",
                get(|| async { Json(serde_json::json!({ "phase": "setup" })) }),
            )
            .route(
                "/wbb/entries",
                get(|State(board): State<FlakyBoard>| async move {
                    let entries = board.entries.lock().unwrap().clone();
                    Json(serde_json::json!({ "count": entries.len(), "entries": entries }))
                }),
            )
            .route(
                "/wbb/submit",
                post(
                    |State(board): State<FlakyBoard>, Json(entry): Json<serde_json::Value>| async move {
                        board.submissions.fetch_add(1, Ordering::SeqCst);
                        if !board.accept.load(Ordering::SeqCst) {
                            return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({})));
                        }
                        let mut entries = board.entries.lock().unwrap();
                        let leaf_index = entries.len();
                        entries.push(serde_json::json!({
                            "leaf_index": leaf_index, "timestamp": 1, "entry": entry
                        }));
                        (StatusCode::OK, Json(serde_json::json!({ "status": "published" })))
                    },
                ),
            )
            .with_state(self.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/wbb/", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        url
    }
}

/// Sec. 3.7.5 bookkeeping under failure. A revocation whose commitment could
/// not be published must change nothing (no spare credential burnt, the voter
/// keeps the old id); one that WAS published but whose answer got lost must be
/// adopted on retry, not published a second time; and once voting is over the
/// electoral roll answers 409.
#[tokio::test]
async fn failed_revocation_burns_no_spare() {
    use referendum_poc::clients::{dip::DipClient, er::ErClient, er::ErError};
    use std::sync::atomic::Ordering;

    let mut cluster = ElectionCluster::start(1, ElectionOpts::default()).await;
    cluster.enroll_all().await;

    let board = FlakyBoard::default();
    let er_url = cluster.spawn_er_with_board(&board.serve().await).await;
    let er = ErClient::new(
        cluster.client.clone(),
        reqwest::Url::parse(&er_url).unwrap(),
    );
    let dip = DipClient::new(
        cluster.client.clone(),
        reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.dip)).unwrap(),
    );
    let auth = dip.authenticate("VOTER-001").await.expect("eID assertion");

    // 1. The board refuses the commitment: the revocation fails...
    assert!(er.revoke(&auth.assertion, &auth.signature).await.is_err());
    assert_eq!(
        board.submissions.load(Ordering::SeqCst),
        1,
        "the publication was really attempted"
    );
    // ...and nothing changed: the voter still logs in under the original id.
    let login = er
        .login(&auth.assertion, &auth.signature)
        .await
        .expect("login");
    assert_eq!(
        login.vid.value(),
        1,
        "a failed revocation leaves the voter untouched"
    );

    // 2. The board recovers: the retry gets the FIRST spare id, so the failed
    //    attempt did not burn one.
    board.accept.store(true, Ordering::SeqCst);
    let revoked = er
        .revoke(&auth.assertion, &auth.signature)
        .await
        .expect("revocation");
    assert_eq!(
        revoked.vid.value(),
        9,
        "first spare id = the election's n_voters + 1"
    );
    assert_eq!(board.entries.lock().unwrap().len(), 1);

    // 3. Lost answer: a commitment that is already on the board is adopted,
    //    not published again. A fresh electoral roll (empty memory, like one
    //    that crashed before recording the result) faces the same board,
    //    which now refuses any new submission.
    board.accept.store(false, Ordering::SeqCst);
    let submissions_before = board.submissions.load(Ordering::SeqCst);
    let reborn_url = cluster.spawn_er_with_board(&board.serve().await).await;
    let reborn = ErClient::new(
        cluster.client.clone(),
        reqwest::Url::parse(&reborn_url).unwrap(),
    );
    let adopted = reborn
        .revoke(&auth.assertion, &auth.signature)
        .await
        .expect("the published commitment is adopted");
    assert_eq!(adopted.vid.value(), 9);
    assert_eq!(
        board.submissions.load(Ordering::SeqCst),
        submissions_before,
        "an already published commitment must not be submitted again"
    );
    assert_eq!(board.entries.lock().unwrap().len(), 1);

    // 4. After close-voting the real electoral roll answers 409.
    cluster.open_voting().await;
    cluster.close_voting().await;
    let real = ErClient::new(
        cluster.client.clone(),
        reqwest::Url::parse(&cluster.er_base()).unwrap(),
    );
    match real.revoke(&auth.assertion, &auth.signature).await {
        Err(ErError::Http(status, _)) => assert_eq!(status, reqwest::StatusCode::CONFLICT),
        other => panic!("expected 409 after close-voting, got {other:?}"),
    }
}

/// Cast-as-intended choice (Sec. 3.8.4 steps 9-11): the voter picks which
/// value to open only AFTER the ballot is cast, the published disclosure
/// opens exactly that slot, and once a choice has left the device a
/// different one is refused (opening both slots would reveal the vote).
#[tokio::test]
async fn cai_choice_after_cast() {
    let mut cluster = ElectionCluster::start(2, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    cluster.open_voting().await;

    // The control values stay sealed until the ballot has been cast.
    let pin0 = cluster.pin(0).await;
    cluster.vote(0, "approve", pin0).await;
    let values_url = format!("{}/api/cai/values", cluster.voter_urls[0]);
    let early = cluster
        .client
        .post(&values_url)
        .json(&serde_json::json!({ "passphrase": cluster.passphrases[0] }))
        .send()
        .await
        .unwrap();
    assert!(
        early.status().is_client_error(),
        "values before the cast: {}",
        early.status()
    );

    // Voter 1: build + cast first, choose afterwards - the sum at list level.
    let vote = cluster.vote_and_cast_unconfirmed(0, "approve", pin0).await;
    let digest = vote["digest"].as_str().unwrap().to_string();

    // Step 9: after the cast the app shows code and sum; their difference is
    // the index of the chosen option ("approve" = 1), modulo 100.
    let values = cluster
        .voter_post(
            0,
            "/api/cai/values",
            serde_json::json!({ "passphrase": cluster.passphrases[0] }),
        )
        .await;
    let (code, sum) = (
        values["l1_code"].as_u64().unwrap(),
        values["l1_sum"].as_u64().unwrap(),
    );
    assert!(code < 100 && sum < 100);
    assert_eq!(
        (sum + 100 - code) % 100,
        1,
        "sum - code is the chosen index"
    );
    let l2_code = values["l2_code"].as_u64().unwrap();
    let confirm = cluster
        .voter_post(
            0,
            "/api/confirm",
            serde_json::json!({ "passphrase": cluster.passphrases[0], "l1": "sum", "l2": "code" }),
        )
        .await;
    assert_eq!(confirm["l1"], "sum");
    assert_eq!(confirm["l2"], "code");
    assert_eq!(
        confirm["l1_value"].as_u64().unwrap(),
        sum,
        "the opened value is the shown sum"
    );
    assert_eq!(confirm["l2_value"].as_u64().unwrap(), l2_code);

    // The published proof opens exactly the chosen slots, nothing else.
    let rows = get_json(
        &cluster.client,
        &format!("{}/api/entries", cluster.ui_base()),
    )
    .await;
    let proofs: Vec<_> = rows
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["entry_type"] == "cast_intended_proof" && r["payload"]["digest"] == digest)
        .collect();
    assert_eq!(proofs.len(), 2, "one proof per ballot box");
    for proof in proofs {
        let disclosure = &proof["payload"]["disclosure"];
        let slots = |level: &str| -> Vec<String> {
            disclosure[level]
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect()
        };
        assert_eq!(slots("l1"), ["Sum"], "list level opens the sum only");
        assert_eq!(slots("l2"), ["Code"], "candidate level opens the code only");
        // Steps 13-16: the ballot box publishes the decoded value, which the
        // voter compares with the one the app showed.
        let opened = &proof["payload"]["opened"];
        assert_eq!(opened["l1"], serde_json::json!({ "Sum": sum }));
        assert_eq!(opened["l2"], serde_json::json!({ "Code": l2_code }));
    }

    // An unknown slot name is rejected outright.
    let pin1 = cluster.pin(1).await;
    cluster.vote_and_cast_unconfirmed(1, "reject", pin1).await;
    let confirm_url = format!("{}/api/confirm", cluster.voter_urls[1]);
    let post = |body: serde_json::Value| {
        let client = cluster.client.clone();
        let url = confirm_url.clone();
        async move { client.post(url).json(&body).send().await.unwrap() }
    };
    let bogus =
        post(serde_json::json!({ "passphrase": cluster.passphrases[1], "l1": "both" })).await;
    assert!(bogus.status().is_client_error(), "got {}", bogus.status());

    // Voter 2 chooses (code, code) but the window closes first: the BBs can
    // no longer publish, so the confirmation fails AFTER the choice was
    // pinned on the device.
    cluster.close_voting().await;
    let first = post(serde_json::json!({
        "passphrase": cluster.passphrases[1], "l1": "code", "l2": "code"
    }))
    .await;
    assert!(
        !first.status().is_success(),
        "confirmation after close must fail"
    );

    // Asking for the OTHER slot now is refused by the app itself...
    let other = post(serde_json::json!({
        "passphrase": cluster.passphrases[1], "l1": "sum", "l2": "code"
    }))
    .await;
    assert!(!other.status().is_success());
    let message = other.json::<serde_json::Value>().await.unwrap()["error"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        message.contains("already chosen"),
        "expected the pinned-choice refusal, got {message:?}"
    );
    // ...while repeating the same choice is a plain retry (it reaches the
    // BBs again and fails there, not on the pin).
    let retry = post(serde_json::json!({
        "passphrase": cluster.passphrases[1], "l1": "code", "l2": "code"
    }))
    .await;
    let retry_message = retry.json::<serde_json::Value>().await.unwrap()["error"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        !retry_message.contains("already chosen"),
        "{retry_message:?}"
    );
    // A coin toss by the app cannot override the pinned choice either.
    let toss = post(serde_json::json!({ "passphrase": cluster.passphrases[1] })).await;
    let toss_message = toss.json::<serde_json::Value>().await.unwrap()["error"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(!toss_message.contains("already chosen"), "{toss_message:?}");
}

/// Swap the first pair of adjacent, distinct elements found in any array of
/// the document - turns a released ballot into one that still deserializes
/// but has a fresh digest.
fn swap_first_distinct_array_pair(value: &mut serde_json::Value) -> bool {
    match value {
        serde_json::Value::Array(items) => {
            for i in 0..items.len().saturating_sub(1) {
                if items[i] != items[i + 1] {
                    items.swap(i, i + 1);
                    return true;
                }
            }
            items.iter_mut().any(swap_first_distinct_array_pair)
        }
        serde_json::Value::Object(map) => map.values_mut().any(swap_first_distinct_array_pair),
        _ => false,
    }
}

/// Idempotent intake: re-casting the same held ballot is idempotent - same receipts, no
/// duplicate WBB entries.
#[tokio::test]
async fn idempotent_casting() {
    let mut cluster = ElectionCluster::start(1, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    cluster.open_voting().await;
    let pin = cluster.pin(0).await;

    cluster.vote(0, "approve", pin).await;
    let first = cluster.cast(0).await;
    let replay = cluster.cast(0).await;
    assert_eq!(
        first["receipts"], replay["receipts"],
        "identical receipts on replay"
    );
    assert_eq!(
        cluster.entry_type_count("ballot_digest").await,
        2,
        "one digest entry per BB - no duplicates from the replay"
    );
    assert_eq!(cluster.entry_type_count("ballot_metadata").await, 2);
}

/// `wbb_ui_smoke`: the public page and its proxy endpoints respond and
/// a cast ballot's digest is findable.
#[tokio::test]
async fn wbb_ui_smoke() {
    let mut cluster = ElectionCluster::start(1, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    cluster.open_voting().await;
    let pin = cluster.pin(0).await;
    let vote = cluster.vote_and_cast(0, "approve", pin).await;
    let digest = vote["digest"].as_str().unwrap();

    let ui = cluster.ui_base();
    let page = cluster
        .client
        .get(format!("{ui}/"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(page.contains("Public Bulletin Board"));

    let phase = get_json(&cluster.client, &format!("{ui}/api/phase")).await;
    assert_eq!(phase["phase"], "voting");

    let checkpoint = cluster
        .client
        .get(format!("{ui}/api/checkpoint"))
        .send()
        .await
        .unwrap();
    assert!(
        checkpoint.status().is_success(),
        "checkpoint proxy responds"
    );

    let rows = get_json(&cluster.client, &format!("{ui}/api/entries")).await;
    let rows = rows.as_array().unwrap();
    assert!(!rows.is_empty());
    let found = rows.iter().any(|r| {
        r["entry_type"] == "ballot_digest" && r["payload"]["digest"] == serde_json::json!(digest)
    });
    assert!(found, "digest search finds the cast ballot");

    let first_index = rows[0]["leaf_index"].as_i64().unwrap();
    let one = get_json(&cluster.client, &format!("{ui}/api/entries/{first_index}")).await;
    assert_eq!(one["leaf_index"], serde_json::json!(first_index));

    // No validators are registered under test (they are a demo facility):
    // every row reports zero of zero and the page hides the semaphore.
    let validators = get_json(&cluster.client, &format!("{ui}/api/validators")).await;
    assert_eq!(validators["validators"], serde_json::json!([]));
    assert!(rows
        .iter()
        .all(|r| r["validators_total"] == 0 && r["validations"] == serde_json::json!([])));
    assert!(rows[0]["leaf_hash"].as_str().is_some_and(|h| h.len() == 64));
}
