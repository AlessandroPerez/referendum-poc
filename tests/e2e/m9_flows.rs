//! §13 flow tests over the full HTTPS cluster: coercion (ruse PIN),
//! wrong PIN, re-vote last-wins, revocation with tally filtering,
//! new-device recovery, PIN re-send, CAT/rate-limit negatives, idempotent
//! casting, and the public wbb-ui smoke.
//!
//! `wbb_policy_enforcement` (§13) lives in `m6_integration.rs`.

use super::helpers::{get_json, ElectionCluster, ElectionOpts};

/// V7: the ruse-PIN ballot is accepted by both BBs — indistinguishable from
/// a real cast — and silently filtered by the tally ACC check; the valid-PIN
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

    let pin1 = cluster.pin(1).await;
    cluster.vote_and_cast(1, "approve", pin1).await;

    cluster.close_voting().await;
    let outcome = cluster.tally().await;
    assert_eq!(outcome.released, 6, "3 casts × 2 BBs");
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
    assert_eq!(outcome.released, 8, "4 casts × 2 BBs");
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

/// §3.9 step 10: two valid ballots from the same credential — only the
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
    assert_eq!(outcome.released, 8, "4 casts × 2 BBs");
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
    assert_eq!(new_vid, 9, "first spare vid is n_voters + 1 (D12)");
    assert_eq!(
        cluster.entry_type_count("revocation_commitment").await,
        1,
        "revocation commitment published (§3.7.5)"
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

    assert_eq!(outcome.released, 6, "3 casts × 2 BBs");
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
        "re-delivered PIN equals the original (§3.7.2)"
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

    // Cast before vote: no held ballot → 400.
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

    // ── commB binding + single-use, at the ER enforcement point (§13).
    //    Mint REAL casting tokens with a test-owned device: DIP assertion →
    //    ER login → device registration with our own AtSK → /tokens/casting.
    //    (BB intake calls this same /tokens/verify and maps `valid: false`
    //    to 401 Unauthorized — asserted in M6.) ──────────────────────────────
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

    // ── The same two negatives observed at the BB intake itself (§13:
    //    both map to 401). A released ballot with two inner elements
    //    swapped deserializes fine but has a fresh digest, so the intake
    //    proceeds past the idempotency lookup to token verification. ──────
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
    // The recomputed commB cannot match token2's binding → 401.
    assert_eq!(cast_at_bb().await, 401, "commB mismatch is a BB-level 401");
    // token2 was NOT consumed by the mismatch; consume it legitimately…
    assert!(
        verify(token2.to_string(), comm_b, true).await,
        "a mismatched attempt must not consume the token"
    );
    // …and the consumed token is now refused at the BB too.
    assert_eq!(
        cast_at_bb().await,
        401,
        "consumed-token reuse is a BB-level 401"
    );
}

/// Swap the first pair of adjacent, distinct elements found in any array of
/// the document — turns a released ballot into one that still deserializes
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

/// §12: re-casting the same held ballot is idempotent — same receipts, no
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
        "one digest entry per BB — no duplicates from the replay"
    );
    assert_eq!(cluster.entry_type_count("ballot_metadata").await, 2);
}

/// §13 `wbb_ui_smoke`: the public page and its proxy endpoints respond and
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
}
