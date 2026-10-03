//! Protocol flow tests over the full HTTPS cluster: coercion (ruse PIN),
//! wrong PIN, re-vote last-wins, revocation with tally filtering,
//! new-device recovery, PIN re-send, CAT/rate-limit negatives, idempotent
//! casting, and the public wbb-ui smoke.
//!
//! `wbb_policy_enforcement` lives in `voting.rs`.

use std::time::Duration;

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
    let ruse = cluster.ruse_pin(0, pin0).await;
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

    // The point of the ruse (Sec. 3.7.3): a coercer who kept the digest of the
    // ballot they cast must not be able to tell, from the board, that it was
    // the one discarded. It is discarded AFTER the mix (Sec. 3.9 step 22), so
    // the published mix must say nothing about where a vote came from: the
    // ballots are trimmed of every identifier before it (step 11).
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD;
    let entries = cluster.wbb.client.entries().await.unwrap();
    let mixes: Vec<String> = entries
        .entries
        .iter()
        .filter_map(|sequenced| {
            let data = b64.decode(sequenced.entry.get("data")?.as_str()?).ok()?;
            let parsed = referendum_poc::protocol::voting::parse_wbb_data(&data)?;
            (parsed.entry_type == "mixed_ballots")
                .then(|| String::from_utf8(b64.decode(parsed.content).ok()?).ok())
                .flatten()
        })
        .collect();
    assert_eq!(mixes.len(), 2, "the vote mix and the credential mix");
    for mix in &mixes {
        for field in ["receipt", "seq_no", "received_at_unix_ms", "bb_id"] {
            assert!(
                !mix.contains(field),
                "a published mix must not carry `{field}`: it would say which ballot each \
                 shuffled vote came from, and so which one was discarded"
            );
        }
    }
}

/// V5 negative and Sec. 3.9 step 10, in one election: a wrong-PIN ballot
/// passes the BB proof checks but is filtered by the ACC check at tally, and
/// of two valid ballots from one credential only the last-cast one survives
/// the ox fingerprint dedup.
#[tokio::test]
async fn a_wrong_pin_ballot_dies_and_the_last_valid_ballot_wins() {
    let mut cluster = ElectionCluster::start(3, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    cluster.open_voting().await;

    let pin = cluster.pin(0).await;
    let wrong = (pin + 1) % 100_000;
    cluster.vote_and_cast(0, "reject", wrong).await;
    cluster.vote_and_cast(0, "approve", pin).await;
    cluster.vote_and_cast(0, "reject", pin).await;
    let pin1 = cluster.pin(1).await;
    cluster.vote_and_cast(1, "approve", pin1).await;
    let pin2 = cluster.pin(2).await;
    cluster.vote_and_cast(2, "blank", pin2).await;

    cluster.close_voting().await;
    let outcome = cluster.tally().await;
    assert_eq!(outcome.released, 10, "5 casts x 2 BBs");
    assert_eq!(outcome.reconciled, 5);
    assert_eq!(
        outcome.deduped, 4,
        "the valid re-vote merges with the earlier valid ballot (last wins); a different PIN \
         does not merge"
    );
    assert_eq!(
        outcome.valid, 3,
        "the wrong-PIN ballot dies at the ACC check"
    );
    assert_eq!(outcome.legitimate, 3);
    assert_eq!(
        (outcome.counts.blank, outcome.counts.si, outcome.counts.no),
        (1, 1, 1),
        "voter 0's later valid reject wins; the wrong-PIN reject never counts"
    );
}

/// V9: a revoked vid's earlier ballot is illegitimate at tally; the
/// re-issued spare credential votes; the commitment entry is on the WBB.
#[tokio::test]
async fn revocation() {
    let mut cluster = ElectionCluster::start(2, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    // Identifiers are a private random assignment: ask the harness for it.
    let vids_of = cluster.vid_assignment();
    let (voter1, voter2, spare1, spare2) = (vids_of[0], vids_of[1], vids_of[8], vids_of[9]);
    let _ = (voter1, voter2, spare1, spare2);
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
    assert_eq!(new_vid, spare1, "the first spare identifier");
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
    let eligible = super::helpers::get_json_with_token(
        &cluster.client,
        &format!("{}/voters/eligible", cluster.er_base()),
        &cluster.admin_token(),
    )
    .await;
    let vids: Vec<u64> = serde_json::from_value(eligible["vids"].clone()).unwrap();
    assert!(!vids.contains(&voter1), "revoked vid must not be eligible");
    assert!(vids.contains(&spare1), "spare vid must be eligible");

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
    // Identifiers are a private random assignment: ask the harness for it.
    let vids_of = cluster.vid_assignment();
    let (voter1, voter2, spare1, spare2) = (vids_of[0], vids_of[1], vids_of[8], vids_of[9]);
    let _ = (voter1, voter2, spare1, spare2);
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
    assert_eq!(recovered["vid"], voter1);
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
        .json(&serde_json::json!({ "passphrase": cluster.passphrases[0], "pin": pin }))
        .send()
        .await
        .unwrap();
    assert_eq!(no_ballot.status(), 400, "cast before vote must fail");

    // Two distinct commitments pass; the idempotent re-cast of the second
    // burns no budget; the third distinct commitment is rate-limited.
    cluster.vote_and_cast(0, "approve", pin).await;
    cluster.vote(0, "reject", pin).await;
    let cast2 = cluster.cast(0, pin).await;
    let recast = cluster.cast(0, pin).await;
    assert_eq!(
        recast["receipts"], cast2["receipts"],
        "idempotent replay returns the same receipts without burning budget"
    );
    cluster.vote(0, "blank", pin).await;
    let limited = cluster
        .client
        .post(format!("{}/api/cast", cluster.voter_urls[0]))
        .json(&serde_json::json!({ "passphrase": cluster.passphrases[0], "pin": pin }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        limited.status(),
        403,
        "3rd distinct ballot commitment is over the limit (max 2)"
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
        .json(&serde_json::json!({ "ballot": {}, "rndcomm": "zz", "casting_token": {} }))
        .send()
        .await
        .unwrap();
    assert!(
        malformed.status().is_client_error(),
        "BB must reject malformed CAT material (got {})",
        malformed.status()
    );

    // -- Casting tokens are verified BY THE BALLOT BOX ALONE (Sec. 5.2,
    //    Sec. 5.3.1.6 step 6). Mint REAL tokens with a test-owned device:
    //    DIP assertion -> ER login -> device registration with our own AtSK
    //    -> /tokens/casting, for the commitment of a ballot we then present.
    use base64::Engine as _;
    use ed25519_dalek::Signer as _;
    use referendum_poc::protocol::voting::comm_b;
    let b64 = &base64::engine::general_purpose::STANDARD;

    // A released ballot with two inner elements swapped still deserializes
    // but has a fresh digest and broken proofs: intake gets past the
    // idempotency lookup, checks the token, and only THEN rejects the ballot.
    // So 401 means "token refused" and 400 means "token accepted".
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
    let rndcomm = [1u8; 32];
    let commitment = comm_b(
        &serde_json::from_value(foreign_ballot.clone()).expect("still a ballot"),
        &rndcomm,
    )
    .unwrap();

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

    let minted: serde_json::Value = {
        let response = cluster
            .client
            .post(format!("{}/tokens/casting", cluster.er_base()))
            .header("Authorization", format!("Bearer {reg_token}"))
            .json(&serde_json::json!({
                "comm_b": commitment,
                "signature": b64.encode(at_sk.sign(commitment.as_bytes()).to_bytes()),
            }))
            .send()
            .await
            .unwrap();
        assert!(response.status().is_success(), "casting token mint");
        response.json().await.unwrap()
    };
    let tokens = minted["casting_tokens"].as_array().unwrap().clone();
    assert_eq!(tokens.len(), 2, "one token per ballot box");
    assert_eq!(
        (tokens[0]["bb_id"].as_u64(), tokens[1]["bb_id"].as_u64()),
        (Some(1), Some(2))
    );
    // Anonymous: the token names the commitment, the ballot box and a
    // validity - never the voter.
    let mut fields: Vec<&str> = tokens[0]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    fields.sort_unstable();
    assert_eq!(fields, ["bb_id", "comm_b", "expires_at_ms", "signature"]);

    let cast = |bb: usize, token: serde_json::Value, rnd: [u8; 32]| {
        let client = cluster.client.clone();
        let url = format!("https://127.0.0.1:{}/ballots", cluster.ports.bb[bb]);
        let ballot = foreign_ballot.clone();
        async move {
            client
                .post(url)
                .json(&serde_json::json!({
                    "ballot": ballot,
                    "rndcomm": hex::encode(rnd),
                    "casting_token": token,
                }))
                .send()
                .await
                .unwrap()
                .status()
        }
    };

    // The right token at the right ballot box is ACCEPTED (the ballot itself
    // is then rejected for its broken proofs): no ER call was needed.
    assert_eq!(
        cast(0, tokens[0].clone(), rndcomm).await,
        400,
        "token accepted, ballot invalid"
    );
    // The same token at the OTHER ballot box: wrong audience.
    assert_eq!(
        cast(1, tokens[0].clone(), rndcomm).await,
        401,
        "a token is for one ballot box"
    );
    assert_eq!(
        cast(1, tokens[1].clone(), rndcomm).await,
        400,
        "its own token works there"
    );
    // Another opening: the recomputed commitment is not the token's.
    assert_eq!(
        cast(0, tokens[0].clone(), [2u8; 32]).await,
        401,
        "commB mismatch"
    );
    // Any edited field breaks the ER's signature.
    let mut stretched = tokens[0].clone();
    stretched["expires_at_ms"] = serde_json::json!(u64::MAX);
    assert_eq!(
        cast(0, stretched, rndcomm).await,
        401,
        "validity cannot be stretched"
    );
    let mut retargeted = tokens[0].clone();
    retargeted["bb_id"] = serde_json::json!(2);
    assert_eq!(
        cast(1, retargeted, rndcomm).await,
        401,
        "a token cannot be re-targeted"
    );
    let mut forged = tokens[0].clone();
    forged["signature"] = serde_json::json!(b64.encode([0u8; 64]));
    assert_eq!(cast(0, forged, rndcomm).await, 401, "forged signature");

    // The ER has no part in any of this: the ballot box holds the ER's PUBLIC
    // key and no client for the ER at all, so a redemption cannot reach it.
}

/// Casting policy and validity (Sec. 5.3.1.6 steps 4 and 6): an expired token
/// is refused by the ballot boxes, and the ER refuses tokens for a NEW ballot
/// too soon after the previous one - while a re-cast of the same ballot is
/// always possible.
#[tokio::test]
async fn casting_token_validity_and_pacing() {
    // Tokens that expire the moment they are issued: nothing can be cast.
    // Validity is a wall-clock notion (issuer and ballot box must share a
    // time base), so this runs on the wall clock.
    let mut expired = ElectionCluster::start(
        1,
        ElectionOpts {
            casting_token_ttl_s: Some(0),
            wall_clock_tau: Some((1, 2)),
            ..Default::default()
        },
    )
    .await;
    expired.enroll_all().await;
    expired.open_voting().await;
    let pin = expired.pin(0).await;
    expired.vote(0, "approve", pin).await;
    let cast = expired
        .client
        .post(format!("{}/api/cast", expired.voter_urls[0]))
        .json(&serde_json::json!({ "passphrase": expired.passphrases[0], "pin": pin }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        cast.status(),
        502,
        "the ballot boxes refuse the expired token"
    );
    let body: serde_json::Value = cast.json().await.unwrap();
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("refused the casting token"),
        "{body}"
    );
    assert_eq!(expired.entry_type_count("ballot_digest").await, 0);
    drop(expired);

    // "Not too recently": one hour between two different ballots.
    let mut paced = ElectionCluster::start(
        1,
        ElectionOpts {
            min_cast_interval_s: Some(3600),
            ..Default::default()
        },
    )
    .await;
    paced.enroll_all().await;
    paced.open_voting().await;
    let pin = paced.pin(0).await;
    let vote = paced.vote_and_cast_unconfirmed(0, "approve", pin).await;
    assert!(vote["digest"].is_string());
    assert_eq!(paced.entry_type_count("ballot_digest").await, 2);

    // The SAME ballot again is never "too soon": a voter who lost the answer
    // repeats the cast, gets the same digest, and nothing new is published.
    let again = paced
        .voter_post(
            0,
            "/api/cast",
            serde_json::json!({ "passphrase": paced.passphrases[0], "pin": pin }),
        )
        .await;
    assert_eq!(again["digest"], vote["digest"]);
    assert_eq!(again["receipts"].as_array().unwrap().len(), 2);
    assert_eq!(paced.entry_type_count("ballot_digest").await, 2);

    // A second, different ballot right away is refused by the ER...
    paced.vote(0, "reject", pin).await;
    let too_soon = paced
        .client
        .post(format!("{}/api/cast", paced.voter_urls[0]))
        .json(&serde_json::json!({ "passphrase": paced.passphrases[0], "pin": pin }))
        .send()
        .await
        .unwrap();
    assert_eq!(too_soon.status(), 429, "a new ballot too soon");
    assert_eq!(
        paced.entry_type_count("ballot_digest").await,
        2,
        "nothing new was cast"
    );
}

/// Sec. 3.10 1(c)-(d), A9: a ballot counts on ONE ballot box's published
/// confirmation, provided it opens on the released ballot. Here one box
/// never receives the voter's disclosure (a stand-in in front of it drops
/// `/cai`): the app still delivers it to the other box, the board shows one
/// confirmation, the ballot is counted and the audit passes. A rule that
/// needed two confirmations would let one box veto any ballot it chooses,
/// indistinguishably from a voter who never confirmed.
#[tokio::test]
async fn one_valid_confirmation_is_enough() {
    use super::helpers::{passthrough, spawn_stand_in, Intercept};

    let mut cluster = ElectionCluster::start(3, ElectionOpts::default()).await;
    cluster.enroll(0).await;
    cluster.enroll(1).await;
    cluster.open_voting().await;
    for (i, option) in ["approve", "blank"].iter().enumerate() {
        let pin = cluster.pin(i).await;
        cluster.vote_and_cast(i, option, pin).await;
    }

    // BB-1 never sees the third voter's disclosure: the stand-in answers
    // `/cai` with an error without forwarding it; everything else goes
    // through. The voter's device talks to BB-1 through it.
    let drop_cai: Intercept = std::sync::Arc::new(|path, _| {
        (path == "cai").then(|| {
            (
                reqwest::StatusCode::SERVICE_UNAVAILABLE,
                axum::body::Bytes::from_static(b"{\"error\":\"down\"}"),
            )
        })
    });
    let real_bb1 =
        reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.bb[0])).unwrap();
    let stand_in = spawn_stand_in(
        &real_bb1,
        cluster.client.clone(),
        passthrough(),
        Some(drop_cai),
    )
    .await;
    let voter = cluster
        .spawn_voter_with_peers(&[("bb-1", stand_in.to_string())])
        .await;

    let passphrase = super::helpers::enroll_on(&cluster.client, &voter, "VOTER-003").await;
    let post = |path: &str, body: serde_json::Value| {
        let url = format!("{voter}{path}");
        let client = cluster.client.clone();
        async move { super::helpers::post_json(&client, &url, body).await }
    };
    let pin = post("/api/pin", serde_json::json!({ "passphrase": passphrase })).await["pin"]
        .as_u64()
        .unwrap();
    let vote = post(
        "/api/vote",
        serde_json::json!({ "passphrase": passphrase, "option": "reject", "pin": pin }),
    )
    .await;
    let cast = post(
        "/api/cast",
        serde_json::json!({ "passphrase": passphrase, "pin": pin }),
    )
    .await;
    assert_eq!(cast["refused_bb_ids"], serde_json::json!([]), "{cast}");
    let confirm = post(
        "/api/confirm",
        serde_json::json!({
            "passphrase": passphrase, "pin": pin, "digest": vote["digest"],
            "l1": "code", "l2": "sum",
        }),
    )
    .await;
    assert_eq!(confirm["will_be_counted"], true, "{confirm}");
    assert_eq!(confirm["silent_boxes"], serde_json::json!([1]), "{confirm}");
    assert_eq!(confirm["lying_boxes"], serde_json::json!([]), "{confirm}");
    let digest = confirm["digest"].as_str().unwrap().to_string();
    let verified = get_json(
        &cluster.client,
        &format!("{}/api/verify/{digest}", cluster.voter_urls[0]),
    )
    .await;
    assert_eq!(verified["confirmations"].as_array().unwrap().len(), 1);
    assert_eq!(verified["confirmed"], true, "one confirmation is enough");

    cluster.close_voting().await;
    let outcome = cluster.tally().await;
    assert_eq!(
        (outcome.counts.blank, outcome.counts.si, outcome.counts.no),
        (1, 1, 1),
        "the ballot confirmed through one box is counted"
    );
    let report = cluster.audit().await;
    assert!(report.ok(), "audit:\n{}", report.render());
    // BB-1 never received the disclosure and released the ballot on the
    // board's word - what A9 asks of it (Sec. 3.8.4 step 15, Sec. 3.9 step
    // 2): no box may be named for that lawful release.
    for step in report.warnings() {
        assert!(
            !step.detail.contains("BB-1") && !step.detail.contains("BB-2"),
            "no box may be named for a lawful release:\n{}",
            report.render()
        );
    }
}

/// A confirmation a ballot box makes up - a genuine disclosure of ANOTHER
/// ballot, re-labelled with the digest of one the voter never confirmed -
/// looks like a confirmation on the board, and the board cannot tell (only
/// the released ballot can). At tally the disclosure does not open on that
/// ballot: it is not counted, and the audit names the box that published
/// the forgery. The result is unchanged.
#[tokio::test]
async fn a_forged_confirmation_counts_for_nothing_and_names_its_box() {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD;

    let mut cluster = ElectionCluster::start(3, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    cluster.open_voting().await;
    for (i, option) in ["approve", "reject"].iter().enumerate() {
        let pin = cluster.pin(i).await;
        cluster.vote_and_cast(i, option, pin).await;
    }
    let pin2 = cluster.pin(2).await;
    let unconfirmed = cluster.vote_and_cast_unconfirmed(2, "approve", pin2).await;
    let digest = unconfirmed["digest"].as_str().unwrap().to_string();

    // BB-1 publishes, under its own key, voter 0's disclosure re-labelled
    // with the unconfirmed digest.
    let entries = cluster.wbb.client.entries().await.unwrap();
    let mut payload = entries
        .entries
        .iter()
        .find_map(|sequenced| {
            let data = b64.decode(sequenced.entry.get("data")?.as_str()?).ok()?;
            let parsed = referendum_poc::protocol::voting::parse_wbb_data(&data)?;
            if parsed.entry_type != "cast_intended_proof" {
                return None;
            }
            let payload = parsed.decode_payload::<serde_json::Value>().ok()?;
            (payload["bb_id"] == 1).then_some(payload)
        })
        .expect("a confirmation by BB-1");
    payload["digest"] = serde_json::json!(digest);
    let data = format!(
        "voting,BB,cast_intended_proof,1,{}",
        b64.encode(serde_json::to_string(&payload).unwrap())
    );
    let entry = referendum_poc::clients::wbb::sign_entry(
        data.as_bytes(),
        "BB-1",
        entries.entries.last().unwrap().timestamp + 1,
        &cluster.signing_key("bb-1"),
    );
    cluster
        .wbb
        .client
        .submit_and_wait(&entry, std::time::Duration::from_secs(20))
        .await
        .expect("published");

    // During voting the board can only say "published and confirmed".
    let verified = get_json(
        &cluster.client,
        &format!("{}/api/verify/{digest}", cluster.voter_urls[2]),
    )
    .await;
    assert_eq!(verified["confirmations"].as_array().unwrap().len(), 1);
    assert_eq!(verified["confirmed"], true);

    // The tally re-opens the disclosure on the released ballot - and BB-1
    // does not even release it (it never received a disclosure), so
    // nothing counts: the forgery bought nothing and the box is named.
    cluster.close_voting().await;
    let outcome = cluster.tally().await;
    assert_eq!(outcome.reconciled, 2, "only the two confirmed ballots");
    assert_eq!((outcome.counts.si, outcome.counts.no), (1, 1));
    let report = cluster.audit().await;
    assert!(report.ok(), "audit:\n{}", report.render());
    let warned = report
        .warnings()
        .find(|s| s.name == "release_completeness" || s.name == "cai_confirmation")
        .unwrap_or_else(|| panic!("BB-1 must be named:\n{}", report.render()));
    assert!(warned.detail.contains("BB-1"), "{}", warned.detail);
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
            serde_json::json!({ "passphrase": cluster.passphrases[3], "pin": pin3 }),
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
        .json(&serde_json::json!({ "passphrase": cluster.passphrases[3], "pin": pin3 }))
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
    // Identifiers are a private random assignment: ask the harness for it.
    let vids_of = cluster.vid_assignment();
    let (voter1, voter2, spare1, spare2) = (vids_of[0], vids_of[1], vids_of[8], vids_of[9]);
    let _ = (voter1, voter2, spare1, spare2);

    // Voter 1 revokes BEFORE the voting window opens.
    let revoked = cluster
        .voter_post(
            0,
            "/api/revoke",
            serde_json::json!({ "passphrase": cluster.passphrases[0] }),
        )
        .await;
    let first_spare = revoked["vid"].as_u64().unwrap();
    assert_eq!(first_spare, spare1, "the first spare identifier");
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
    let eligible = super::helpers::get_json_with_token(
        &cluster.client,
        &format!("{}/voters/eligible", cluster.er_base()),
        &cluster.admin_token(),
    )
    .await;
    let vids: Vec<u64> = serde_json::from_value(eligible["vids"].clone()).unwrap();
    assert!(vids.contains(&voter2) && vids.contains(&first_spare) && !vids.contains(&voter1));
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
    // Identifiers are a private random assignment: ask the harness for it.
    let vids_of = cluster.vid_assignment();
    let (voter1, voter2, spare1, spare2) = (vids_of[0], vids_of[1], vids_of[8], vids_of[9]);
    let _ = (voter1, voter2, spare1, spare2);
    let er = ErClient::new(
        cluster.client.clone(),
        reqwest::Url::parse(&cluster.er_base()).unwrap(),
    );
    let dip = DipClient::new(
        cluster.client.clone(),
        reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.dip)).unwrap(),
    );
    // Two concurrent requests, each with its own login: an eID assertion is
    // accepted once.
    let auth_a = dip.authenticate("VOTER-001").await.expect("eID assertion");
    let auth_b = dip.authenticate("VOTER-001").await.expect("eID assertion");

    let (a, b) = tokio::join!(
        er.revoke(&auth_a.assertion, &auth_a.signature),
        er.revoke(&auth_b.assertion, &auth_b.signature)
    );
    let (a, b) = (a.expect("first revocation"), b.expect("second revocation"));
    // The first to be served got the first spare.
    let (first, second) = if a.vid.value() == spare1 {
        (a, b)
    } else {
        (b, a)
    };
    assert_eq!((first.vid.value(), second.vid.value()), (spare1, spare2));
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
    let auth = dip.authenticate("VOTER-001").await.expect("eID assertion");
    let login = er
        .login(&auth.assertion, &auth.signature)
        .await
        .expect("login");
    assert_eq!(login.vid.value(), spare2);
    let eligible = super::helpers::get_json_with_token(
        &cluster.client,
        &format!("{}/voters/eligible", cluster.er_base()),
        &cluster.admin_token(),
    )
    .await;
    let vids: Vec<u64> = serde_json::from_value(eligible["vids"].clone()).unwrap();
    assert!(
        vids.contains(&spare2) && !vids.contains(&spare1) && !vids.contains(&voter1),
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
    // Identifiers are a private random assignment: ask the harness for it.
    let vids_of = cluster.vid_assignment();
    let (voter1, voter2, spare1, spare2) = (vids_of[0], vids_of[1], vids_of[8], vids_of[9]);
    let _ = (voter1, voter2, spare1, spare2);
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
    assert_eq!(first.vid.value(), spare1);

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
        spare2,
        "the first spare is taken according to the board"
    );
    // Voter 1 asking again (with a fresh login) is recognised by their
    // published commitment.
    let voter1_again = dip.authenticate("VOTER-001").await.unwrap();
    let again = fresh
        .revoke(&voter1_again.assertion, &voter1_again.signature)
        .await
        .unwrap();
    assert_eq!(again.vid.value(), spare1);
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

/// Sec. 3.5.3: the pseudonymous identifier a voter is given is the electoral
/// roll's private choice, so the app does not take it on the roll's word. The
/// roll committed to a tree of (voter, identifier) pairs at setup and
/// published its root; the identifier handed out must come with a proof that
/// it is the pair committed for THIS voter.
///
/// Without that, a roll can hand a targeted voter an identifier nobody holds:
/// the ballot is cast, confirmed and shown as counted, and then dropped by
/// the last filter - with every audit step green.
#[tokio::test]
async fn an_identifier_the_roll_cannot_prove_is_refused() {
    use axum::{extract::State, routing::post, Json, Router};

    let cluster = ElectionCluster::start(2, ElectionOpts::default()).await;

    // A stand-in electoral roll: it answers like the real one but swaps the
    // identifier for another of the pool, keeping the proof it was given.
    #[derive(Clone)]
    struct LyingRoll {
        real: String,
        client: reqwest::Client,
    }
    let roll = LyingRoll {
        real: cluster.er_base(),
        client: cluster.client.clone(),
    };
    let app = Router::new()
        .route(
            "/login",
            post(
                |State(roll): State<LyingRoll>, body: axum::body::Bytes| async move {
                    let mut answer: serde_json::Value = roll
                        .client
                        .post(format!("{}/login", roll.real))
                        .header("content-type", "application/json")
                        .body(body)
                        .send()
                        .await
                        .unwrap()
                        .json()
                        .await
                        .unwrap();
                    let vid = answer["vid"].as_u64().unwrap();
                    answer["vid"] = serde_json::json!(if vid == 1 { 2 } else { 1 });
                    Json(answer)
                },
            ),
        )
        .with_state(roll);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let lying_url = format!("http://{}/", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let voter_url = cluster.spawn_voter_with_er(&lying_url).await;
    let refused = cluster
        .client
        .post(format!("{voter_url}/api/login"))
        .json(&serde_json::json!({ "fiscal_id": "VOTER-001" }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        refused.status(),
        502,
        "an identifier that does not match the published commitment must be refused"
    );
    let body: serde_json::Value = refused.json().await.unwrap();
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("cannot prove that this pseudonymous identifier"),
        "{body}"
    );

    // The honest roll, over the same app, is accepted.
    let honest_url = cluster
        .spawn_voter_with_er(&format!("{}/", cluster.er_base()))
        .await;
    let accepted = cluster
        .client
        .post(format!("{honest_url}/api/login"))
        .json(&serde_json::json!({ "fiscal_id": "VOTER-002" }))
        .send()
        .await
        .unwrap();
    assert!(accepted.status().is_success(), "the honest roll proves it");
}

/// Thesis A9 ("at least one honest BB ... must not delete received ballots
/// while publishing their hash digest") and Sec. 3.9 step 3 ("the WBB publishes
/// each ballot B for which a digest H(B) has been published"): a ballot the
/// board counts is counted from ANY box's release. One box withholding it at
/// release changes nothing - the box is named by the audit. Only when EVERY
/// box withholds it is the ballot censored, and then the driver refuses to
/// tally before publishing anything.
#[tokio::test]
async fn a_ballot_one_box_withholds_is_still_counted() {
    use axum::{extract::State, routing::get, Router};

    let mut cluster = ElectionCluster::start(3, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    cluster.open_voting().await;
    // Voter 0 votes under coercion, then freely: only the LAST ballot counts.
    let pin0 = cluster.pin(0).await;
    cluster.vote_and_cast(0, "reject", pin0).await;
    let free = cluster.vote_and_cast(0, "approve", pin0).await;
    for (i, option) in [(1usize, "approve"), (2, "blank")] {
        let pin = cluster.pin(i).await;
        cluster.vote_and_cast(i, option, pin).await;
    }
    cluster.close_voting().await;
    let victim = free["digest"].as_str().unwrap().to_string();

    // A stand-in in front of a ballot box: it releases everything the real
    // box releases, except the voter's free ballot.
    #[derive(Clone)]
    struct Withholding {
        real: reqwest::Url,
        client: reqwest::Client,
        victim: String,
    }
    let spawn_withholding = |bb: usize| {
        let stand_in = Withholding {
            real: reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.bb[bb]))
                .unwrap(),
            client: cluster.client.clone(),
            victim: victim.clone(),
        };
        async move {
            let app = Router::new()
                .route(
                    "/ballots",
                    get(
                        |State(s): State<Withholding>, headers: axum::http::HeaderMap| async move {
                            let mut request = s.client.get(s.real.join("ballots").unwrap());
                            if let Some(auth) = headers.get("authorization") {
                                request = request.header("authorization", auth);
                            }
                            let mut records: Vec<serde_json::Value> =
                                request.send().await.unwrap().json().await.unwrap();
                            records.retain(|r| {
                                let ballot = r["ballot"].clone();
                                let digest = referendum_poc::protocol::voting::ballot_digest(
                                    &serde_json::from_value(ballot).unwrap(),
                                )
                                .unwrap();
                                digest.to_string() != s.victim
                            });
                            axum::Json(records)
                        },
                    ),
                )
                .with_state(stand_in);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = reqwest::Url::parse(&format!("http://{}/", listener.local_addr().unwrap()))
                .unwrap();
            tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            url
        }
    };

    // BB-2 withholds; BB-1 is honest. The free ballot is counted from BB-1.
    let honest_bb1 =
        reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.bb[0])).unwrap();
    let outcome = cluster
        .try_tally_with_boxes(vec![honest_bb1, spawn_withholding(1).await])
        .await
        .expect("the tally proceeds from the honest box's copy");
    assert_eq!(
        (outcome.counts.blank, outcome.counts.si, outcome.counts.no),
        (1, 2, 0),
        "the voter's LAST ballot counts, not the coerced one"
    );
    let report = cluster.audit().await;
    assert!(report.ok(), "audit:\n{}", report.render());
    let warned = report
        .warnings()
        .find(|s| s.name == "release_completeness")
        .unwrap_or_else(|| panic!("the withholding box must be named:\n{}", report.render()));
    assert!(warned.detail.contains("BB-2"), "{}", warned.detail);
}

/// When EVERY box withholds a ballot the board counts, no honest box is left
/// (A9 is violated) and the ballot is lost. The thesis does not stop the
/// tally for it: Sec. 3.9 step 4 names the boxes that published a digest
/// without releasing the ballot, and the count goes on without it. So does
/// the driver (a stop would hand a single box that fabricates a confirmation
/// for an unconfirmed ballot a veto over the whole election), and the audit
/// names both boxes.
#[tokio::test]
async fn a_ballot_every_box_withholds_is_not_counted_and_both_boxes_are_named() {
    use axum::{extract::State, routing::get, Router};

    let mut cluster = ElectionCluster::start(3, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    cluster.open_voting().await;
    let pin0 = cluster.pin(0).await;
    let free = cluster.vote_and_cast(0, "approve", pin0).await;
    for (i, option) in [(1usize, "approve"), (2, "blank")] {
        let pin = cluster.pin(i).await;
        cluster.vote_and_cast(i, option, pin).await;
    }
    cluster.close_voting().await;
    let victim = free["digest"].as_str().unwrap().to_string();

    #[derive(Clone)]
    struct Withholding {
        real: reqwest::Url,
        client: reqwest::Client,
        victim: String,
    }
    let mut stand_ins = Vec::new();
    for bb in 0..2 {
        let stand_in = Withholding {
            real: reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.bb[bb]))
                .unwrap(),
            client: cluster.client.clone(),
            victim: victim.clone(),
        };
        let app = Router::new()
            .route(
                "/ballots",
                get(
                    |State(s): State<Withholding>, headers: axum::http::HeaderMap| async move {
                        let mut request = s.client.get(s.real.join("ballots").unwrap());
                        if let Some(auth) = headers.get("authorization") {
                            request = request.header("authorization", auth);
                        }
                        let mut records: Vec<serde_json::Value> =
                            request.send().await.unwrap().json().await.unwrap();
                        records.retain(|r| {
                            let digest = referendum_poc::protocol::voting::ballot_digest(
                                &serde_json::from_value(r["ballot"].clone()).unwrap(),
                            )
                            .unwrap();
                            digest.to_string() != s.victim
                        });
                        axum::Json(records)
                    },
                ),
            )
            .with_state(stand_in);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        stand_ins.push(
            reqwest::Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap(),
        );
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    }

    let outcome = cluster
        .try_tally_with_boxes(stand_ins)
        .await
        .expect("the tally goes on without the withheld ballot");
    assert_eq!(
        (outcome.counts.blank, outcome.counts.si, outcome.counts.no),
        (1, 1, 0),
        "the withheld ballot is not counted; every other one is"
    );
    let report = cluster.audit().await;
    assert!(report.ok(), "audit:\n{}", report.render());
    let warned = report
        .warnings()
        .find(|s| s.name == "release_completeness")
        .unwrap_or_else(|| panic!("both boxes must be named:\n{}", report.render()));
    assert!(
        warned.detail.contains("released by NO box")
            && warned.detail.contains("BB-1")
            && warned.detail.contains("BB-2"),
        "{}",
        warned.detail
    );
}

/// The board is append-only and every tally artifact is once-only, so a
/// pipeline that fails after it has started publishing would strand the
/// election: the driver refuses to run twice and the board holds half a
/// tally. The driver therefore signs every artifact as it goes and submits
/// them only once the LAST step has succeeded. Here one teller fails at that
/// last step - the co-signature of the result - after every mix, proof and
/// decryption has been produced: nothing may have reached the board, and the
/// tally must run again once the teller is back.
#[tokio::test]
async fn a_tally_that_fails_part_way_leaves_the_board_untouched() {
    use axum::{body::Bytes, extract::State, http::StatusCode, Router};

    let mut cluster = ElectionCluster::start(3, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    cluster.open_voting().await;
    for (i, option) in ["approve", "approve", "blank"].iter().enumerate() {
        let pin = cluster.pin(i).await;
        cluster.vote_and_cast(i, option, pin).await;
    }
    cluster.close_voting().await;

    // A stand-in in front of TT-3: it forwards everything to the real teller
    // except the co-signature of the final result, which it refuses.
    #[derive(Clone)]
    struct FailsLast {
        real: reqwest::Url,
        client: reqwest::Client,
    }
    let stand_in = FailsLast {
        real: reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.tt[2])).unwrap(),
        client: cluster.client.clone(),
    };
    let app = Router::new()
        .fallback(
            |State(s): State<FailsLast>, request: axum::extract::Request| async move {
                let (parts, body) = request.into_parts();
                let body = axum::body::to_bytes(body, usize::MAX).await.unwrap();
                let path = parts.uri.path().trim_start_matches('/').to_string();
                if path == "sign" && String::from_utf8_lossy(&body).contains("tally_result") {
                    return (StatusCode::SERVICE_UNAVAILABLE, Bytes::new());
                }
                let mut forward = s
                    .client
                    .request(parts.method.clone(), s.real.join(&path).unwrap())
                    .body(body);
                for name in ["authorization", "content-type"] {
                    if let Some(value) = parts.headers.get(name) {
                        forward = forward.header(name, value);
                    }
                }
                let response = forward.send().await.unwrap();
                (response.status(), response.bytes().await.unwrap())
            },
        )
        .with_state(stand_in);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stand_in_url =
        reqwest::Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let url = |p: &u16| reqwest::Url::parse(&format!("https://127.0.0.1:{p}/")).unwrap();
    let before = cluster.wbb.client.entries().await.unwrap().entries.len();
    let failed = cluster
        .try_tally_with_tellers(vec![
            url(&cluster.ports.tt[0]),
            url(&cluster.ports.tt[1]),
            stand_in_url,
        ])
        .await
        .expect_err("a teller that will not sign the result stops the tally");
    assert!(
        failed.to_string().contains("TT co-signing failed"),
        "{failed}"
    );
    // Sec. 3.9 publishes as it goes - the control elements reach the WBB at
    // step 19 and the result only at step 30 - so the artifacts computed
    // before the failure are on the board. That is what lets the tellers
    // recompute what they decrypt instead of taking it from this driver.
    // What a failed tally must NOT leave is a result.
    let after = cluster.wbb.client.entries().await.unwrap().entries.len();
    assert!(
        after > before,
        "the pipeline's artifacts are published as it goes ({before} -> {after})"
    );
    assert_eq!(
        cluster.entry_type_count("tally_proof").await,
        0,
        "a tally that failed must publish no result"
    );
    assert_eq!(cluster.entry_type_count("tally_result").await, 0);
    // With the teller back the tally runs to the end, exactly once.
    let outcome = cluster.tally().await;
    assert_eq!(
        (outcome.counts.blank, outcome.counts.si, outcome.counts.no),
        (1, 2, 0)
    );
    let report = cluster.audit().await;
    assert!(report.ok(), "audit:\n{}", report.render());
}

/// A teller's co-signature is checked against the key pinned for it at the
/// ceremony when it is queued, not by the board at flush time: a teller
/// that returns a signature that does not verify is named at once, and
/// nothing reaches the board. (Left to the board, the flush would have
/// published every earlier artifact and the refusal of the last one would
/// have left the election behind the once-only guard.)
#[tokio::test]
async fn a_teller_whose_co_signature_does_not_verify_is_named_before_anything_is_published() {
    use super::helpers::{spawn_stand_in, Rewrite};
    use base64::Engine as _;

    let mut cluster = ElectionCluster::start(3, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    cluster.open_voting().await;
    for (i, option) in ["approve", "approve", "reject"].iter().enumerate() {
        let pin = cluster.pin(i).await;
        cluster.vote_and_cast(i, option, pin).await;
    }
    cluster.close_voting().await;

    // TT-3 signs the result with a signature that does not verify.
    let rewrite: Rewrite = std::sync::Arc::new(|path, request, status, body| {
        if path == "sign" && String::from_utf8_lossy(request).contains("tally_result") {
            let mut answer: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let mut signature = base64::engine::general_purpose::STANDARD
                .decode(answer["signature"].as_str().unwrap())
                .unwrap();
            signature[0] ^= 0x01;
            answer["signature"] = serde_json::Value::String(
                base64::engine::general_purpose::STANDARD.encode(signature),
            );
            return (
                status,
                axum::body::Bytes::from(serde_json::to_vec(&answer).unwrap()),
            );
        }
        (status, body)
    });
    let url = |p: &u16| reqwest::Url::parse(&format!("https://127.0.0.1:{p}/")).unwrap();
    let stand_in = spawn_stand_in(
        &url(&cluster.ports.tt[2]),
        cluster.client.clone(),
        rewrite,
        None,
    )
    .await;

    let before = cluster.wbb.client.entries().await.unwrap().entries.len();
    let failed = cluster
        .try_tally_with_tellers(vec![
            url(&cluster.ports.tt[0]),
            url(&cluster.ports.tt[1]),
            stand_in,
        ])
        .await
        .expect_err("a co-signature that does not verify stops the tally");
    assert!(
        failed
            .to_string()
            .contains("TT-3 returned an invalid co-signature"),
        "{failed}"
    );
    let after = cluster.wbb.client.entries().await.unwrap().entries.len();
    assert!(after > before, "{before} -> {after} entries");
    assert_eq!(
        cluster.entry_type_count("tally_proof").await,
        0,
        "a co-signature that does not verify must publish no result"
    );

    let outcome = cluster.tally().await;
    assert_eq!(
        (outcome.counts.blank, outcome.counts.si, outcome.counts.no),
        (0, 2, 1)
    );
    assert!(cluster.audit().await.ok());
}

/// The submission of the signed artifacts can be cut off part-way - here a
/// network fault loses one teller's partial of the result, twice, so the
/// result is never sequenced although everything before it is. The signed
/// outbox was saved before the first submission, so the next run finds the
/// board consistent with it and finishes the submission instead of refusing:
/// same artifacts, same result, no duplicate.
#[tokio::test]
async fn a_submission_cut_off_part_way_is_finished_by_the_next_run() {
    use super::helpers::{passthrough, spawn_stand_in, Intercept};
    use base64::Engine as _;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let mut cluster = ElectionCluster::start(3, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    cluster.open_voting().await;
    for (i, option) in ["approve", "approve", "reject"].iter().enumerate() {
        let pin = cluster.pin(i).await;
        cluster.vote_and_cast(i, option, pin).await;
    }
    cluster.close_voting().await;

    // TT-3's partial of the result never reaches the board (nor does the
    // driver's one retry of it).
    let dropped = std::sync::Arc::new(AtomicUsize::new(0));
    let counter = dropped.clone();
    let intercept: Intercept = std::sync::Arc::new(move |path, request| {
        if path == "wbb/submit" {
            let entry: serde_json::Value = serde_json::from_slice(request).unwrap();
            let data = base64::engine::general_purpose::STANDARD
                .decode(entry["data"].as_str().unwrap())
                .unwrap();
            if String::from_utf8_lossy(&data).contains(",tally_result,")
                && entry["entity_id"] == "TT-3"
                && counter.fetch_add(1, Ordering::SeqCst) < 2
            {
                return Some((
                    reqwest::StatusCode::BAD_GATEWAY,
                    axum::body::Bytes::from_static(b"dropped"),
                ));
            }
        }
        None
    });
    let real = reqwest::Url::parse(cluster.wbb_url.as_str().trim_end_matches("wbb/")).unwrap();
    let stand_in = spawn_stand_in(
        &real,
        cluster.client.clone(),
        passthrough(),
        Some(intercept),
    )
    .await;

    let failed = cluster
        .try_tally_with_board(stand_in.join("wbb/").unwrap())
        .await
        .expect_err("the lost partial aborts the submission");
    assert_eq!(dropped.load(Ordering::SeqCst), 2, "{failed}");
    assert_eq!(cluster.entry_type_count("tally_proof").await, 1);
    assert_eq!(cluster.entry_type_count("tally_result").await, 0);

    // The next run resumes the saved submission: the result appears once,
    // nothing else is published twice, and the audit passes.
    let releases_before = cluster.entry_type_count("encrypted_ballot").await;
    let outcome = cluster.tally().await;
    assert_eq!(
        (outcome.counts.blank, outcome.counts.si, outcome.counts.no),
        (0, 2, 1)
    );
    assert_eq!(cluster.entry_type_count("tally_result").await, 1);
    assert_eq!(cluster.entry_type_count("tally_proof").await, 1);
    assert_eq!(
        cluster.entry_type_count("encrypted_ballot").await,
        releases_before
    );
    let report = cluster.audit().await;
    assert!(report.ok(), "audit:\n{}", report.render());
    // And a third run is refused: the tally is complete.
    let refused = cluster.try_tally().await.expect_err("once-only guard");
    assert!(
        refused.to_string().contains("already been tallied"),
        "{refused}"
    );
}

/// A tabulation teller within the threshold answers a decryption request
/// with a partial computed under a key share of its own: its proof verifies
/// against the key it embeds. The driver holds every partial to the share
/// published for that teller at setup (Protocol 12 proves a share against
/// the shared key, not against a key the prover names), sets the teller
/// aside and finishes with the other two: the honest result is published,
/// the audit passes, and the teller's answer never reaches the board.
#[tokio::test]
async fn a_teller_decrypting_under_its_own_key_is_set_aside_and_the_honest_result_stands() {
    use super::helpers::{spawn_stand_in, Rewrite};
    use dlog_group::group::GroupScalar;
    use dlog_group::ristretto::RistrettoGroup as G;
    use evoting::api::prelude::{TTSecretKeyShare, VerifiablePartialDecryption};
    use rand::SeedableRng as _;
    use referendum_poc::protocol::tally::reconstruct_tt_teller;

    let mut cluster = ElectionCluster::start(3, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    cluster.open_voting().await;
    for (i, option) in ["approve", "approve", "reject"].iter().enumerate() {
        let pin = cluster.pin(i).await;
        cluster.vote_and_cast(i, option, pin).await;
    }
    cluster.close_voting().await;

    let ctx: evoting::api::server::bb::ElectionContext<G> = serde_json::from_slice(
        &std::fs::read(cluster.ceremony_dir().join("election_context.json")).unwrap(),
    )
    .unwrap();
    #[derive(serde::Deserialize)]
    #[serde(bound = "")]
    struct Request {
        blinded: Vec<dlog_sigma_primitives::elgamal::ciphertext::Ciphertext<G>>,
    }
    // TT-3's partial for the first shuffled vote is computed under a random
    // share of its own (with a proof that verifies against it).
    let rewrite: Rewrite = std::sync::Arc::new(move |path, request, status, body| {
        if path != "decrypt/acc-checks" || !status.is_success() {
            return (status, body);
        }
        let request: Request = serde_json::from_slice(request).expect("acc-checks request");
        let mut real: Vec<VerifiablePartialDecryption<G>> =
            serde_json::from_slice(&body).expect("real partials");
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([0x15; 32]);
        let fake = reconstruct_tt_teller(TTSecretKeyShare {
            id: 3,
            meg_sk1_share: G::scalar_random(&mut rng),
            meg_sk2_share: G::scalar_random(&mut rng),
        });
        let forged = fake.partial_gen_acc_checks(&ctx, &request.blinded[..1], &mut rng);
        real[0] = forged[0].clone();
        (
            status,
            axum::body::Bytes::from(serde_json::to_vec(&real).unwrap()),
        )
    });
    let url = |p: &u16| reqwest::Url::parse(&format!("https://127.0.0.1:{p}/")).unwrap();
    let stand_in = spawn_stand_in(
        &url(&cluster.ports.tt[2]),
        cluster.client.clone(),
        rewrite,
        None,
    )
    .await;

    let outcome = cluster
        .try_tally_with_tellers(vec![
            url(&cluster.ports.tt[0]),
            url(&cluster.ports.tt[1]),
            stand_in,
        ])
        .await
        .expect("two honest tellers suffice");
    assert_eq!(
        (outcome.counts.blank, outcome.counts.si, outcome.counts.no),
        (0, 2, 1),
        "the honest result, not the steered one"
    );
    assert_eq!(outcome.valid, outcome.deduped, "no vote dropped as invalid");
    let report = cluster.audit().await;
    assert!(report.ok(), "audit:\n{}", report.render());
}

/// An eID assertion is good ONCE (A5: assertions are accurate and audience
/// bound; an assertion observed on the wire must buy the observer nothing).
/// The same signed assertion presented a second time - to log in, or to
/// revoke - is refused by the roll.
#[tokio::test]
async fn a_replayed_eid_assertion_is_refused() {
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
    er.login(&auth.assertion, &auth.signature)
        .await
        .expect("a fresh assertion logs in");
    let replayed = er
        .login(&auth.assertion, &auth.signature)
        .await
        .expect_err("the same assertion a second time is refused");
    assert!(
        matches!(replayed, referendum_poc::clients::er::ErError::Http(status, _) if status == 401 || status == 403),
        "{replayed}"
    );
    let revoke = er
        .revoke(&auth.assertion, &auth.signature)
        .await
        .expect_err("nor does it revoke anything");
    assert!(
        matches!(revoke, referendum_poc::clients::er::ErError::Http(status, _) if status == 401 || status == 403),
        "{revoke}"
    );
    assert_eq!(cluster.entry_type_count("revocation_commitment").await, 0);
}

/// Sec. 3.7.4 step 7: a device already registered for an identifier keeps
/// its app key unless the new key is signed by the old one. Whoever holds a
/// registration token (a curious roll's log, a replayed request) cannot
/// rebind the voter's casting key and lock the voter out; the same key
/// registered again is fine.
#[tokio::test]
async fn a_device_cannot_be_rebound_without_the_old_key() {
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
    let login = er
        .login(&auth.assertion, &auth.signature)
        .await
        .expect("login");
    let other_key = "42".repeat(32);
    let refused = er
        .register_device(&login.registration_token, "", &other_key, None)
        .await
        .expect_err("a new app key without the old key's signature is refused");
    assert!(
        matches!(refused, referendum_poc::clients::er::ErError::Http(status, _) if status == 401),
        "{refused}"
    );
    // The voter's own device still works: its key is the registered one.
    let status = cluster
        .voter_post(
            0,
            "/api/status",
            serde_json::json!({ "passphrase": cluster.passphrases[0] }),
        )
        .await;
    assert_eq!(status["pin_set"], true, "{status}");
}

/// Sec. 3.6.1 step 11 / A2: one registration teller within the threshold
/// delivers a share that does not fit (a stand-in swaps two scalars of its
/// answer; the other two tellers are honest). The library carries no
/// per-share proof, so the app finds out when the finished credential fails
/// the PIN check - and then rebuilds it from every t_RT-subset of the tellers:
/// the voter gets their credential, and the teller left out is named.
#[tokio::test]
async fn one_corrupt_teller_share_does_not_deny_the_credential_and_is_named() {
    use super::helpers::{spawn_stand_in, Rewrite};

    let cluster = ElectionCluster::start(1, ElectionOpts::default()).await;
    // rt-3 answers the share delivery with x and sigma swapped: well-formed,
    // wrong.
    let rewrite: Rewrite = std::sync::Arc::new(|path, _, status, body| {
        if path == "credentials/deliver" && status.is_success() {
            let mut share: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let x = share["share"]["x_share"].clone();
            share["share"]["x_share"] = share["share"]["sigma_share"].clone();
            share["share"]["sigma_share"] = x;
            return (
                status,
                axum::body::Bytes::from(serde_json::to_vec(&share).unwrap()),
            );
        }
        (status, body)
    });
    let real_rt3 =
        reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.rt[2])).unwrap();
    let stand_in = spawn_stand_in(&real_rt3, cluster.client.clone(), rewrite, None).await;
    let voter = cluster
        .spawn_voter_with_peers(&[("rt-3", stand_in.to_string())])
        .await;

    let passphrase = super::helpers::enroll_on(&cluster.client, &voter, "VOTER-001").await;
    let status = super::helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/status"),
        serde_json::json!({ "passphrase": passphrase }),
    )
    .await;
    assert_eq!(status["pin_set"], true, "{status}");
    assert_eq!(
        status["rebuilt_without_rts"],
        serde_json::json!(["rt-3"]),
        "{status}"
    );
    // The credential is the real one: the PIN verifies.
    let pin = super::helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/pin"),
        serde_json::json!({ "passphrase": passphrase }),
    )
    .await["pin"]
        .as_u64()
        .unwrap();
    let verify = super::helpers::post_json(
        &cluster.client,
        &format!("{voter}/api/pin/verify"),
        serde_json::json!({ "passphrase": passphrase, "pin": pin }),
    )
    .await;
    assert_eq!(verify["valid"], true, "{verify}");
}

/// Sec. 3.7.3, A1: the cover story must survive a surveillance gap. A coercer
/// casts a ruse ballot, reads its control values and leaves without
/// confirming; the voter votes for real, casts and confirms; the coercer
/// returns and types the decoy they hold: the control-values screen shows the
/// same values as before, and the confirmation screen confirms the ruse
/// ballot as if nothing had happened in between. The PIN is what each screen
/// answers to (Sec. 3.7.1 step 3), so a PIN that built nothing reaches
/// nothing and the decoy reaches only the decoy's ballot.
#[tokio::test]
async fn the_control_values_and_confirmation_screens_keep_the_ruse_cover_story() {
    let mut cluster = ElectionCluster::start(3, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    cluster.open_voting().await;
    for (i, option) in [(1usize, "approve"), (2, "blank")] {
        let pin = cluster.pin(i).await;
        cluster.vote_and_cast(i, option, pin).await;
    }

    let real_pin = cluster.pin(0).await;
    let ruse_pin = cluster.ruse_pin(0, real_pin).await;
    // The coercer: vote with the ruse PIN, cast, look at the control values.
    let coerced = cluster
        .vote_and_cast_unconfirmed(0, "reject", ruse_pin)
        .await;
    let before = cluster
        .voter_post(
            0,
            "/api/cai/values",
            serde_json::json!({ "passphrase": cluster.passphrases[0], "pin": ruse_pin }),
        )
        .await;
    assert_eq!(before["digest"], coerced["digest"]);

    // The voter, alone: the real ballot, cast and left UNCONFIRMED for a
    // while (a board read that failed, a box that did not answer), then
    // confirmed. The coercer's screens must show none of it.
    let real = cluster
        .vote_and_cast_unconfirmed(0, "approve", real_pin)
        .await;
    let during = cluster
        .voter_post(
            0,
            "/api/cai/values",
            serde_json::json!({ "passphrase": cluster.passphrases[0], "pin": ruse_pin }),
        )
        .await;
    assert_eq!(
        during, before,
        "an unconfirmed REAL ballot must not reach the coercer's screen"
    );
    let confirm_real = cluster
        .voter_post(
            0,
            "/api/confirm",
            serde_json::json!({
                "passphrase": cluster.passphrases[0], "pin": real_pin,
                "digest": real["digest"], "l1": "code", "l2": "sum",
            }),
        )
        .await;
    assert_eq!(confirm_real["will_be_counted"], true, "{confirm_real}");

    // The coercer, back: same screen, same values; and the confirmation goes
    // through on the ruse ballot.
    let after = cluster
        .voter_post(
            0,
            "/api/cai/values",
            serde_json::json!({ "passphrase": cluster.passphrases[0], "pin": ruse_pin }),
        )
        .await;
    assert_eq!(after, before, "the control-values screen must not change");
    let confirm = cluster
        .voter_post(
            0,
            "/api/confirm",
            serde_json::json!({
                "passphrase": cluster.passphrases[0], "pin": ruse_pin,
                "digest": coerced["digest"], "l1": "code", "l2": "sum",
            }),
        )
        .await;
    assert_eq!(confirm["digest"], coerced["digest"], "{confirm}");
    assert_eq!(confirm["will_be_counted"], true, "{confirm}");
    let status = cluster
        .voter_post(
            0,
            "/api/ballot/status",
            serde_json::json!({ "passphrase": cluster.passphrases[0], "pin": ruse_pin }),
        )
        .await;
    assert_eq!(
        status["digest"], coerced["digest"],
        "the status screen tells the ruse story"
    );

    // The tally counts the real ballot; the ruse one has no valid credential.
    cluster.close_voting().await;
    let outcome = cluster.tally().await;
    assert_eq!(
        (outcome.counts.blank, outcome.counts.si, outcome.counts.no),
        (1, 2, 0)
    );
    assert!(cluster.audit().await.ok());
}

/// A curious electoral roll (Sec. 6.3.1: storage exfiltration, never a lie)
/// holds every voter's recovery blob. Its size must not sort voters into
/// "armed a ruse PIN" and "did not": the blob is padded to a fixed bucket.
#[tokio::test]
async fn the_recovery_blob_size_does_not_reveal_a_ruse() {
    use referendum_poc::clients::{dip::DipClient, er::ErClient};

    let mut cluster = ElectionCluster::start(2, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    let er = ErClient::new(
        cluster.client.clone(),
        reqwest::Url::parse(&cluster.er_base()).unwrap(),
    );
    let dip = DipClient::new(
        cluster.client.clone(),
        reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.dip)).unwrap(),
    );
    let blob_size = |fiscal_id: &'static str| {
        let er = er.clone();
        let dip = dip.clone();
        async move {
            let auth = dip.authenticate(fiscal_id).await.unwrap();
            er.recover_device(&auth.assertion, &auth.signature)
                .await
                .unwrap()
                .state_blob
                .len()
        }
    };
    let (v1_before, v2_before) = (blob_size("VOTER-001").await, blob_size("VOTER-002").await);
    assert_eq!(v1_before, v2_before);
    let real_pin = cluster.pin(0).await;
    cluster.ruse_pin(0, real_pin).await;
    let (v1_after, v2_after) = (blob_size("VOTER-001").await, blob_size("VOTER-002").await);
    assert_eq!(
        v1_after, v1_before,
        "arming a ruse must not change the blob's size"
    );
    assert_eq!(v2_after, v2_before);
}

/// A teller that answers a decryption request with the wrong NUMBER of
/// partials (one fewer here) would make the combination fail for everyone,
/// unattributed. The driver takes the shape the other tellers agree on, sets
/// the odd one aside naming it, and finishes with the rest.
#[tokio::test]
async fn a_teller_answering_with_the_wrong_shape_is_set_aside() {
    use super::helpers::{spawn_stand_in, Rewrite};

    let mut cluster = ElectionCluster::start(3, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    cluster.open_voting().await;
    for (i, option) in ["approve", "approve", "reject"].iter().enumerate() {
        let pin = cluster.pin(i).await;
        cluster.vote_and_cast(i, option, pin).await;
    }
    cluster.close_voting().await;

    let rewrite: Rewrite = std::sync::Arc::new(|path, _, status, body| {
        if path == "decrypt/acc-checks" && status.is_success() {
            let mut partials: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
            partials.pop();
            return (
                status,
                axum::body::Bytes::from(serde_json::to_vec(&partials).unwrap()),
            );
        }
        (status, body)
    });
    let url = |p: &u16| reqwest::Url::parse(&format!("https://127.0.0.1:{p}/")).unwrap();
    let stand_in = spawn_stand_in(
        &url(&cluster.ports.tt[2]),
        cluster.client.clone(),
        rewrite,
        None,
    )
    .await;
    let outcome = cluster
        .try_tally_with_tellers(vec![
            url(&cluster.ports.tt[0]),
            url(&cluster.ports.tt[1]),
            stand_in,
        ])
        .await
        .expect("two honest tellers suffice");
    assert_eq!(
        (outcome.counts.blank, outcome.counts.si, outcome.counts.no),
        (0, 2, 1)
    );
    assert!(cluster.audit().await.ok());
}

/// Sec. 3.8.4 step 15 / A9: a ballot box whose own `/cai` round trip fails
/// must still release a ballot the BOARD shows confirmed - otherwise the
/// honest box withholds the vote and is named for it. Here BB-2's `/cai` is
/// unreachable: BB-1 publishes a valid confirmation, and BB-2 releases the
/// ballot all the same because the board carries that confirmation.
#[tokio::test]
async fn a_box_releases_what_the_board_shows_confirmed_even_if_its_own_cai_failed() {
    use super::helpers::{passthrough, spawn_stand_in, Intercept};

    let mut cluster = ElectionCluster::start(3, ElectionOpts::default()).await;
    cluster.enroll(0).await;
    cluster.enroll(1).await;
    cluster.open_voting().await;
    for (i, option) in ["approve", "blank"].iter().enumerate() {
        let pin = cluster.pin(i).await;
        cluster.vote_and_cast(i, option, pin).await;
    }

    // The third voter's device reaches BB-2 through a stand-in that drops
    // `/cai` without forwarding it; BB-1 receives the disclosure and
    // publishes it.
    let drop_cai: Intercept = std::sync::Arc::new(|path, _| {
        (path == "cai").then(|| {
            (
                reqwest::StatusCode::SERVICE_UNAVAILABLE,
                axum::body::Bytes::from_static(b"{\"error\":\"down\"}"),
            )
        })
    });
    let real_bb2 =
        reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.bb[1])).unwrap();
    let stand_in = spawn_stand_in(
        &real_bb2,
        cluster.client.clone(),
        passthrough(),
        Some(drop_cai),
    )
    .await;
    let voter = cluster
        .spawn_voter_with_peers(&[("bb-2", stand_in.to_string())])
        .await;
    let passphrase = super::helpers::enroll_on(&cluster.client, &voter, "VOTER-003").await;
    let post = |path: &str, body: serde_json::Value| {
        let url = format!("{voter}{path}");
        let client = cluster.client.clone();
        async move { super::helpers::post_json(&client, &url, body).await }
    };
    let pin = post("/api/pin", serde_json::json!({ "passphrase": passphrase })).await["pin"]
        .as_u64()
        .unwrap();
    let vote = post(
        "/api/vote",
        serde_json::json!({ "passphrase": passphrase, "option": "reject", "pin": pin }),
    )
    .await;
    post(
        "/api/cast",
        serde_json::json!({ "passphrase": passphrase, "pin": pin }),
    )
    .await;
    let confirm = post(
        "/api/confirm",
        serde_json::json!({
            "passphrase": passphrase, "pin": pin, "digest": vote["digest"],
            "l1": "code", "l2": "sum",
        }),
    )
    .await;
    assert_eq!(confirm["will_be_counted"], true, "{confirm}");
    assert_eq!(confirm["silent_boxes"], serde_json::json!([2]), "{confirm}");

    // BOTH boxes release it: BB-2 from the board's confirmation.
    cluster.close_voting().await;
    let outcome = cluster.tally().await;
    assert_eq!(
        (outcome.counts.blank, outcome.counts.si, outcome.counts.no),
        (1, 1, 1)
    );
    let report = cluster.audit().await;
    assert!(report.ok(), "audit:\n{}", report.render());
    assert!(
        report
            .warnings()
            .all(|s| !s.detail.contains("did NOT release")),
        "no box may be named for withholding:\n{}",
        report.render()
    );
}

/// A ballot box may not be able to block the tally: `encrypted_ballot` is an
/// entry ANY box may write on its own (threshold 1), so the once-only guard
/// must not key on it. One box plants a release entry before the tally; the
/// tally runs, the audit names the box for a release nobody asked for, and
/// the result stands.
#[tokio::test]
async fn a_planted_release_entry_does_not_block_the_tally() {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD;

    let mut cluster = ElectionCluster::start(3, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    cluster.open_voting().await;
    for (i, option) in ["approve", "approve", "reject"].iter().enumerate() {
        let pin = cluster.pin(i).await;
        cluster.vote_and_cast(i, option, pin).await;
    }
    cluster.close_voting().await;

    // BB-1 writes a release entry of its own, under its real key, before the
    // driver runs. (Its payload is a genuine record of another ballot, so the
    // entry is well formed.)
    let entries = cluster.wbb.client.entries().await.unwrap();
    let genuine = entries
        .entries
        .iter()
        .find_map(|sequenced| {
            let data = b64.decode(sequenced.entry.get("data")?.as_str()?).ok()?;
            let parsed = referendum_poc::protocol::voting::parse_wbb_data(&data)?;
            (parsed.entry_type == "ballot_digest").then_some(parsed)
        })
        .expect("a digest entry");
    let data = format!("tallying,BB,encrypted_ballot,1,{}", genuine.content);
    let entry = referendum_poc::clients::wbb::sign_entry(
        data.as_bytes(),
        "BB-1",
        entries.entries.last().unwrap().timestamp + 1,
        &cluster.signing_key("bb-1"),
    );
    cluster
        .wbb
        .client
        .submit_and_wait(&entry, std::time::Duration::from_secs(20))
        .await
        .expect("the board accepts what a box may write");

    let outcome = cluster.tally().await;
    assert_eq!(
        (outcome.counts.blank, outcome.counts.si, outcome.counts.no),
        (0, 2, 1),
        "one box's entry must not change or block the tally"
    );
    let report = cluster.audit().await;
    assert!(report.ok(), "audit:\n{}", report.render());
    assert!(
        report.warnings().any(|s| s.name == "ballot_release"),
        "the box that wrote it must be named:\n{}",
        report.render()
    );
}

/// Sec. 3.7.3, A1: a decoy, the voter's real vote, then a SECOND decoy - all
/// across surveillance gaps. Every screen keeps telling one story: the PIN
/// shown is the newest decoy, only that decoy verifies, and the ballot the
/// coercer's screens work on is still the one cast under the first decoy
/// (the cast records show it either way, so dropping it would only make the
/// screens disagree - which is what a coercer reads). The tally counts the
/// voter's real ballot and neither decoy.
#[tokio::test]
async fn a_second_decoy_does_not_disturb_the_story_the_first_one_tells() {
    let mut cluster = ElectionCluster::start(3, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    cluster.open_voting().await;
    for (i, option) in [(1usize, "approve"), (2, "blank")] {
        let pin = cluster.pin(i).await;
        cluster.vote_and_cast(i, option, pin).await;
    }
    let real_pin = cluster.pin(0).await;
    let ruse1 = cluster.ruse_pin(0, real_pin).await;
    let body = serde_json::json!({ "passphrase": cluster.passphrases[0] });

    // The coercer casts under the first decoy and leaves it unconfirmed.
    let coerced = cluster.vote_and_cast_unconfirmed(0, "reject", ruse1).await;
    // The voter, alone.
    cluster.vote_and_cast(0, "approve", real_pin).await;

    // A coercer back, arming a decoy of their own.
    let ruse2 = cluster.ruse_pin(0, ruse1).await;
    assert_ne!(ruse1, ruse2);
    let shown = cluster.voter_post(0, "/api/pin", body.clone()).await;
    assert_eq!(shown["pin"].as_u64().unwrap(), ruse2);
    for (pin, expect) in [(ruse1, false), (ruse2, true), (real_pin, false)] {
        let verified = cluster
            .voter_post(
                0,
                "/api/pin/verify",
                serde_json::json!({ "passphrase": cluster.passphrases[0], "pin": pin }),
            )
            .await;
        assert_eq!(verified["valid"], expect, "pin {pin}: {verified}");
    }
    // The coercer types the decoy they were given, and it reaches the ballot
    // THAT decoy built and no other (Sec. 3.7.1 step 3, Sec. 3.7.3).
    let first_decoy = serde_json::json!({ "passphrase": cluster.passphrases[0], "pin": ruse1 });
    let values = cluster
        .voter_post(0, "/api/cai/values", first_decoy.clone())
        .await;
    let status = cluster
        .voter_post(0, "/api/ballot/status", first_decoy.clone())
        .await;
    assert_eq!(values["digest"], coerced["digest"], "{values}");
    assert_eq!(status["digest"], coerced["digest"], "{status}");
    let mut confirm_body = first_decoy.clone();
    confirm_body["digest"] = coerced["digest"].clone();
    confirm_body["l1"] = serde_json::json!("code");
    confirm_body["l2"] = serde_json::json!("sum");
    let confirm = cluster.voter_post(0, "/api/confirm", confirm_body).await;
    assert_eq!(confirm["digest"], coerced["digest"], "{confirm}");

    cluster.close_voting().await;
    let outcome = cluster.tally().await;
    assert_eq!(
        (outcome.counts.blank, outcome.counts.si, outcome.counts.no),
        (1, 2, 0),
        "the voter's real ballot counts, neither decoy does"
    );
    assert!(cluster.audit().await.ok());
}

/// Sec. 3.10 1(d): a ballot counts on a disclosure that OPENS on it, not on
/// the mere presence of a confirmation. One box publishes, for a ballot its
/// voter deliberately left unconfirmed, a confirmation carrying ANOTHER
/// ballot's disclosure. The device's own screen must not call that "counted",
/// no box must release the ballot on the strength of it, and the tally must
/// not count it.
#[tokio::test]
async fn a_planted_confirmation_does_not_make_a_ballot_counted() {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD;

    let mut cluster = ElectionCluster::start(3, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    cluster.open_voting().await;
    for (i, option) in ["approve", "reject"].iter().enumerate() {
        let pin = cluster.pin(i).await;
        cluster.vote_and_cast(i, option, pin).await;
    }
    let pin2 = cluster.pin(2).await;
    let unconfirmed = cluster.vote_and_cast_unconfirmed(2, "approve", pin2).await;
    let digest = unconfirmed["digest"].as_str().unwrap().to_string();

    // BB-2 publishes voter 0's disclosure under voter 2's digest, in its own
    // name and with its own key.
    let entries = cluster.wbb.client.entries().await.unwrap();
    let mut payload = entries
        .entries
        .iter()
        .find_map(|sequenced| {
            let data = b64.decode(sequenced.entry.get("data")?.as_str()?).ok()?;
            let parsed = referendum_poc::protocol::voting::parse_wbb_data(&data)?;
            if parsed.entry_type != "cast_intended_proof" {
                return None;
            }
            let payload = parsed.decode_payload::<serde_json::Value>().ok()?;
            (payload["bb_id"] == 2).then_some(payload)
        })
        .expect("a confirmation by BB-2");
    payload["digest"] = serde_json::json!(digest);
    let data = format!(
        "voting,BB,cast_intended_proof,1,{}",
        b64.encode(serde_json::to_string(&payload).unwrap())
    );
    let entry = referendum_poc::clients::wbb::sign_entry(
        data.as_bytes(),
        "BB-2",
        entries.entries.last().unwrap().timestamp + 1,
        &cluster.signing_key("bb-2"),
    );
    cluster
        .wbb
        .client
        .submit_and_wait(&entry, std::time::Duration::from_secs(20))
        .await
        .expect("the board takes what a box may write");

    // The device knows it never confirmed this ballot, and says so.
    let status = cluster
        .voter_post(
            2,
            "/api/ballot/status",
            serde_json::json!({ "passphrase": cluster.passphrases[2], "pin": pin2 }),
        )
        .await;
    assert_eq!(
        status["confirmed_bb_ids"],
        serde_json::json!([2]),
        "{status}"
    );
    assert_eq!(
        status["will_be_counted"], false,
        "a ballot this device never confirmed is never counted: {status}"
    );

    // No box releases it, so the tally never sees it.
    cluster.close_voting().await;
    let outcome = cluster.tally().await;
    assert_eq!(outcome.reconciled, 2, "only the two confirmed ballots");
    assert_eq!(
        (outcome.counts.blank, outcome.counts.si, outcome.counts.no),
        (0, 1, 1)
    );
    let report = cluster.audit().await;
    assert!(report.ok(), "audit:\n{}", report.render());
}

/// Sec. 3.9 step 1: the eligible list the credential mix is built from is the
/// electoral roll's. A roll that swaps one registered voter's identifier for
/// an unused spare keeps the list's shape - same length, no repeats, all in
/// range - and the whole tally stays self-consistent, yet that voter's ballot
/// is dropped at the last filter. What catches it is the commitment made at
/// setup, before anyone voted: the identifiers assigned to the registry. The
/// tally-time list may differ from it only by published revocations.
#[tokio::test]
async fn a_roll_cannot_swap_an_identifier_without_a_revocation() {
    use axum::{extract::State, routing::post, Json, Router};
    use base64::Engine as _;

    let mut cluster = ElectionCluster::start(3, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    cluster.open_voting().await;
    for (i, option) in ["approve", "approve", "reject"].iter().enumerate() {
        let pin = cluster.pin(i).await;
        cluster.vote_and_cast(i, option, pin).await;
    }
    cluster.close_voting().await;

    // The honest list, with the first voter's identifier swapped for a spare.
    let vids = super::helpers::vid_assignment(cluster.ceremony_dir(), cluster.base.election.n_acc);
    let n_v = cluster.base.election.n_voters;
    let mut lying: Vec<u64> = vids.iter().take(n_v).copied().collect();
    let victim = lying[0];
    lying[0] = *vids.last().expect("a spare");
    assert!(!lying.contains(&victim));

    // A stand-in roll that publishes that list - signed with the roll's REAL
    // key, in the right phase - and hands it to the tally driver.
    #[derive(Clone)]
    struct LyingRoll {
        wbb: referendum_poc::clients::wbb::WbbClient,
        key: ed25519_dalek::SigningKey,
        list: Vec<u64>,
        timestamp: i64,
    }
    let last = cluster.wbb.client.entries().await.unwrap();
    let roll = LyingRoll {
        wbb: cluster.wbb.client.clone(),
        key: cluster.signing_key("er"),
        list: lying.clone(),
        timestamp: last.entries.last().unwrap().timestamp + 1,
    };
    let app = Router::new()
        .route(
            "/admin/eligible-vids",
            post(|State(roll): State<LyingRoll>| async move {
                let data = format!(
                    "tallying,ER,eligible_vids,1,{}",
                    base64::engine::general_purpose::STANDARD
                        .encode(serde_json::to_string(&roll.list).unwrap())
                );
                let entry = referendum_poc::clients::wbb::sign_entry(
                    data.as_bytes(),
                    "ER-1",
                    roll.timestamp,
                    &roll.key,
                );
                roll.wbb
                    .submit_and_wait(&entry, std::time::Duration::from_secs(20))
                    .await
                    .expect("the board takes the roll's list");
                Json(serde_json::json!({ "vids": roll.list }))
            }),
        )
        .with_state(roll);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let lying_url =
        reqwest::Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    // The tally runs to the end on the lying list, and one approve is gone.
    let outcome = cluster
        .try_tally_with_roll(lying_url)
        .await
        .expect("the tally itself is self-consistent");
    assert_eq!(
        (outcome.counts.si, outcome.counts.no),
        (1, 1),
        "the victim's approve was dropped at the last filter"
    );

    // Everything about it is self-consistent - except the setup commitment.
    let report = cluster.audit().await;
    assert!(!report.ok(), "the swap must not pass the audit");
    let step = report.steps.iter().find(|s| !s.ok).expect("a failing step");
    assert_eq!(step.name, "eligible_identifiers", "{}", report.render());
    assert!(
        step.detail.contains("never assigned at setup"),
        "{}",
        step.detail
    );
}

/// After a revocation the voter holds a SPARE, whose committed holder is a
/// random string and not their registry id (Sec. 3.5.3). Logging in again -
/// the ordinary thing to do on a fresh device - must therefore work, and the
/// identifier must still be proved: a spare is a leaf of its own kind, so it
/// can never be passed off as another voter's identifier.
#[tokio::test]
async fn a_revoked_voter_can_log_in_again_on_the_spare() {
    let mut cluster = ElectionCluster::start(2, ElectionOpts::default()).await;
    cluster.enroll_all().await;

    let before = cluster
        .voter_post(
            0,
            "/api/status",
            serde_json::json!({ "passphrase": cluster.passphrases[0] }),
        )
        .await;
    let revoked = cluster
        .voter_post(
            0,
            "/api/revoke",
            serde_json::json!({ "passphrase": cluster.passphrases[0] }),
        )
        .await;
    assert_ne!(revoked["vid"], before["vid"], "a spare was handed out");

    // A fresh device, logging in from scratch.
    let fresh = cluster
        .spawn_voter_with_er(&format!("{}/", cluster.er_base()))
        .await;
    let login = cluster
        .client
        .post(format!("{fresh}/api/login"))
        .json(&serde_json::json!({ "fiscal_id": "VOTER-001" }))
        .send()
        .await
        .unwrap();
    assert!(
        login.status().is_success(),
        "a revoked voter must be able to log in on their spare: {}",
        login.text().await.unwrap_or_default()
    );
    let login: serde_json::Value = login.json().await.unwrap();
    assert_eq!(login["vid"], revoked["vid"]);
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
    // Identifiers are a private random assignment: ask the harness for it.
    let vids_of = cluster.vid_assignment();
    let (voter1, voter2, spare1, spare2) = (vids_of[0], vids_of[1], vids_of[8], vids_of[9]);
    let _ = (voter1, voter2, spare1, spare2);

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
    let auth = dip.authenticate("VOTER-001").await.expect("eID assertion");
    let login = er
        .login(&auth.assertion, &auth.signature)
        .await
        .expect("login");
    assert_eq!(
        login.vid.value(),
        voter1,
        "a failed revocation leaves the voter untouched"
    );

    // 2. The board recovers: the retry gets the FIRST spare id, so the failed
    //    attempt did not burn one.
    board.accept.store(true, Ordering::SeqCst);
    let auth = dip.authenticate("VOTER-001").await.expect("eID assertion");
    let revoked = er
        .revoke(&auth.assertion, &auth.signature)
        .await
        .expect("revocation");
    assert_eq!(revoked.vid.value(), spare1, "the first spare identifier");
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
    let auth = dip.authenticate("VOTER-001").await.expect("eID assertion");
    let adopted = reborn
        .revoke(&auth.assertion, &auth.signature)
        .await
        .expect("the published commitment is adopted");
    assert_eq!(adopted.vid.value(), spare1);
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
    let auth = dip.authenticate("VOTER-001").await.expect("eID assertion");
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
        .json(&serde_json::json!({ "passphrase": cluster.passphrases[0], "pin": pin0 }))
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
            serde_json::json!({ "passphrase": cluster.passphrases[0], "pin": pin0 }),
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
            serde_json::json!({
                "passphrase": cluster.passphrases[0], "pin": pin0,
                "digest": values["digest"], "l1": "sum", "l2": "code",
            }),
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

    // Sec. 3.8.5: the per-digest verification endpoint reports, for ANY
    // digest, what the bulletin board shows - here through voter 2's app,
    // which never saw this ballot.
    let verify_url = |digest: &str| format!("{}/api/verify/{digest}", cluster.voter_urls[1]);
    let verified = get_json(&cluster.client, &verify_url(&digest)).await;
    assert_eq!(verified["enough_ballot_boxes"], true);
    assert_eq!(verified["confirmed"], true);
    let bb_ids: Vec<u64> = verified["publications"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["bb_id"].as_u64().unwrap())
        .collect();
    assert_eq!(bb_ids, [1, 2]);
    assert!(!verified["publications"][0]["emoji"]
        .as_array()
        .unwrap()
        .is_empty());
    for confirmation in verified["confirmations"].as_array().unwrap() {
        assert_eq!(
            confirmation["opened"]["l1"],
            serde_json::json!({ "Sum": sum })
        );
    }
    assert_eq!(verified["confirmations"].as_array().unwrap().len(), 2);
    // A well-formed digest nobody published: a clean negative, not an error.
    let unknown = referendum_poc::domain::BallotDigest::from_bytes([0u8; 32]).to_string();
    let absent = get_json(&cluster.client, &verify_url(&unknown)).await;
    assert_eq!(absent["enough_ballot_boxes"], false);
    assert_eq!(absent["confirmed"], false);
    assert!(absent["publications"].as_array().unwrap().is_empty());
    assert!(absent["confirmations"].as_array().unwrap().is_empty());
    let malformed = cluster
        .client
        .get(verify_url("not-a-digest"))
        .send()
        .await
        .unwrap();
    assert_eq!(malformed.status(), 400);

    // An unknown slot name is rejected outright.
    let pin1 = cluster.pin(1).await;
    let cast = cluster.vote_and_cast_unconfirmed(1, "reject", pin1).await;
    let confirm_url = format!("{}/api/confirm", cluster.voter_urls[1]);
    let post = |mut body: serde_json::Value| {
        let client = cluster.client.clone();
        let url = confirm_url.clone();
        // Every request here is about the one cast ballot (Sec. 3.8.4
        // steps 9-11 name it).
        body["digest"] = cast["digest"].clone();
        async move { client.post(url).json(&body).send().await.unwrap() }
    };
    let bogus = post(
        serde_json::json!({ "passphrase": cluster.passphrases[1], "pin": pin1, "l1": "both" }),
    )
    .await;
    assert!(bogus.status().is_client_error(), "got {}", bogus.status());

    // Voter 2 chooses (code, code) but the window closes first: the BBs can
    // no longer publish, so the confirmation fails AFTER the choice was
    // pinned on the device.
    cluster.close_voting().await;
    let first = post(serde_json::json!({
        "passphrase": cluster.passphrases[1], "pin": pin1, "l1": "code", "l2": "code"
    }))
    .await;
    assert!(
        !first.status().is_success(),
        "confirmation after close must fail"
    );

    // Asking for the OTHER slot now is refused by the app itself...
    let other = post(serde_json::json!({
        "passphrase": cluster.passphrases[1], "pin": pin1, "l1": "sum", "l2": "code"
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
        "passphrase": cluster.passphrases[1], "pin": pin1, "l1": "code", "l2": "code"
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
    // Restating nothing repeats the pinned choice, and reaches the boxes
    // again rather than being refused on the pin.
    let toss = post(serde_json::json!({ "passphrase": cluster.passphrases[1], "pin": pin1 })).await;
    let toss_message = toss.json::<serde_json::Value>().await.unwrap()["error"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(!toss_message.contains("already chosen"), "{toss_message:?}");
}

/// Sec. 5.3.1.3-5 on the WALL clock: a teller announces itself and releases
/// its share only after the waiting period tau. An earlier delivery request
/// is refused WITHOUT spending the retrieval token, the very same token works
/// once tau is over and is then spent, the status flag follows, and a PIN
/// re-send (a new request with a new waiting period) still completes.
#[tokio::test]
async fn waiting_period_on_the_wall_clock() {
    use referendum_poc::clients::{dip::DipClient, er::ErClient, rt::RtClient, rt::RtError};
    use secrecy::SecretString;

    // tau in [3, 4) seconds: every teller waits exactly 3 s.
    let cluster = ElectionCluster::start(
        1,
        ElectionOpts {
            wall_clock_tau: Some((3, 4)),
            ..Default::default()
        },
    )
    .await;
    let voter = cluster.voter_urls[0].clone();
    let post = |path: &'static str, body: serde_json::Value| {
        let client = cluster.client.clone();
        let url = format!("{voter}{path}");
        async move { client.post(url).json(&body).send().await.unwrap() }
    };

    // Enrolling sends the PIN request: the waiting period starts during this
    // call, so the stopwatch starts before it (the tellers' gates can only
    // open LATER than `requested_at + 3 s`, never earlier).
    let requested_at = std::time::Instant::now();
    post(
        "/api/login",
        serde_json::json!({ "fiscal_id": "VOTER-001" }),
    )
    .await;
    let enrolled: serde_json::Value = post(
        "/api/enroll",
        serde_json::json!({ "fiscal_id": "VOTER-001" }),
    )
    .await
    .json()
    .await
    .unwrap();
    let passphrase = enrolled["passphrase"]
        .as_str()
        .unwrap_or_else(|| panic!("enrollment answered {enrolled}"))
        .to_string();
    let body = serde_json::json!({ "passphrase": passphrase });

    let status: serde_json::Value = post("/api/status", body.clone())
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(
        status["pin_ready"], false,
        "no teller has announced itself yet"
    );
    let early = post("/api/pin/retrieve", body.clone()).await;
    assert_eq!(
        early.status(),
        409,
        "the app refuses to retrieve before readiness"
    );

    // Go straight to a teller with a genuine retrieval token, before tau.
    let dip = DipClient::new(
        cluster.client.clone(),
        reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.dip)).unwrap(),
    );
    let er = ErClient::new(
        cluster.client.clone(),
        reqwest::Url::parse(&cluster.er_base()).unwrap(),
    );
    let auth = dip.authenticate("VOTER-001").await.unwrap();
    let login = er.login(&auth.assertion, &auth.signature).await.unwrap();
    // A second login for the retrieval tokens: an assertion is good once.
    let auth = dip.authenticate("VOTER-001").await.unwrap();
    let tokens = er
        .retrieval_tokens(&login.registration_token, &auth.assertion, &auth.signature)
        .await
        .unwrap()
        .retrieval_tokens;
    assert_eq!(
        tokens.len(),
        3,
        "a retrieval token for each teller (Sec. 5.3.1.4)"
    );
    let teller = RtClient::new(
        cluster.client.clone(),
        reqwest::Url::parse(&format!("https://127.0.0.1:{}/", cluster.ports.rt[0])).unwrap(),
        SecretString::new("not-a-service-call".into()),
    );
    let early = teller.credentials_deliver(&tokens[0]).await;
    // Judge earliness AFTER the call: only a call that certainly ended
    // before any gate could open must have been refused.
    if requested_at.elapsed() < Duration::from_millis(2800) {
        match early {
            Err(RtError::Http(status, _)) => assert_eq!(status, reqwest::StatusCode::TOO_EARLY),
            other => panic!("expected 425 before tau, got {other:?}"),
        }
    } else {
        eprintln!("machine too slow to test the early refusal: leg skipped");
    }

    // After tau: the SAME token was not spent by the refusal. The gate opens
    // tau after the teller RECEIVED the request, which is some time after
    // `requested_at` (the enrollment saves the session first), so the
    // delivery is asked again - each refusal spends nothing - until it opens.
    tokio::time::sleep(Duration::from_millis(3000).saturating_sub(requested_at.elapsed())).await;
    let deadline = std::time::Instant::now() + Duration::from_secs(8);
    loop {
        match teller.credentials_deliver(&tokens[0]).await {
            Ok(_) => break,
            Err(RtError::Http(status, _))
                if status == reqwest::StatusCode::TOO_EARLY
                    && std::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Err(e) => panic!("the token refused earlier still works after tau: {e:?}"),
        }
    }
    // ...and now it is.
    match teller.credentials_deliver(&tokens[0]).await {
        Err(RtError::Http(status, _)) => assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED),
        other => panic!("expected 401 for a spent token, got {other:?}"),
    }

    // The app sees readiness (two tellers' announcements land shortly after
    // their gates open) and retrieves at once.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let status: serde_json::Value = post("/api/status", body.clone())
            .await
            .json()
            .await
            .unwrap();
        if status["pin_ready"] == true {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "PIN never became ready"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let retrieved: serde_json::Value = post("/api/pin/retrieve", body.clone())
        .await
        .json()
        .await
        .unwrap();
    let pin = retrieved["pin"].as_u64().expect("PIN");

    // A re-send is a NEW request with its own waiting period: it must wait
    // for the tellers instead of failing, and deliver the same PIN.
    let resend_started = std::time::Instant::now();
    let resent = post("/api/pin/resend", body.clone()).await;
    assert!(
        resent.status().is_success(),
        "re-send on the wall clock: {}",
        resent.status()
    );
    let resent: serde_json::Value = resent.json().await.unwrap();
    assert_eq!(resent["pin"].as_u64().unwrap(), pin);
    assert!(
        resend_started.elapsed() >= Duration::from_millis(2900),
        "the re-send cannot complete before the new waiting period is over"
    );
}

/// The two PIN emoji (Sec. 3.6.3 step 5, Sec. 3.7.1, Sec. 3.8.2 step 14,
/// Sec. 3.8.4 step 2). The PRIVATE one depends only on the PIN typed: the
/// voter sees it when the PIN arrives and again whenever they type that PIN,
/// and a wrong or ruse PIN shows another one. The PUBLIC one belongs to the
/// ballot: the app shows it, both ballot boxes publish it, and they agree.
#[tokio::test]
async fn pin_emoji_private_and_public() {
    let mut cluster = ElectionCluster::start(1, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    cluster.open_voting().await;
    let body = serde_json::json!({ "passphrase": cluster.passphrases[0] });
    let emoji = |v: &serde_json::Value, key: &str| -> Vec<String> {
        serde_json::from_value(v[key].clone()).unwrap_or_default()
    };

    // When the PIN is shown, so is its emoji.
    let shown = cluster.voter_post(0, "/api/pin", body.clone()).await;
    let pin = shown["pin"].as_u64().unwrap();
    let mine = emoji(&shown, "private_pin_emoji");
    assert_eq!(mine.len(), 6);

    // Typing the PIN brings the same emoji back; another PIN does not.
    let right = cluster
        .voter_post(
            0,
            "/api/pin/verify",
            serde_json::json!({ "passphrase": cluster.passphrases[0], "pin": pin }),
        )
        .await;
    assert_eq!(right["valid"], true);
    assert_eq!(emoji(&right, "private_pin_emoji"), mine);
    let wrong_pin = (pin + 1) % 100_000;
    let wrong = cluster
        .voter_post(
            0,
            "/api/pin/verify",
            serde_json::json!({ "passphrase": cluster.passphrases[0], "pin": wrong_pin }),
        )
        .await;
    assert_eq!(wrong["valid"], false);
    assert_eq!(
        emoji(&wrong, "private_pin_emoji").len(),
        6,
        "an emoji is shown for any PIN"
    );
    assert_ne!(emoji(&wrong, "private_pin_emoji"), mine);

    // Voting with the PIN: same private emoji, plus the ballot's public one.
    let vote = cluster.vote(0, "approve", pin).await;
    assert_eq!(emoji(&vote, "private_pin_emoji"), mine);
    let public = emoji(&vote, "public_pin_emoji");
    assert_eq!(public.len(), 6);
    let digest = vote["digest"].as_str().unwrap().to_string();

    // After the cast both ballot boxes publish that same public emoji.
    cluster
        .voter_post(
            0,
            "/api/cast",
            serde_json::json!({ "passphrase": cluster.passphrases[0], "pin": pin }),
        )
        .await;
    let verified = get_json(
        &cluster.client,
        &format!("{}/api/verify/{digest}", cluster.voter_urls[0]),
    )
    .await;
    let publications = verified["publications"].as_array().unwrap();
    assert_eq!(publications.len(), 2);
    for publication in publications {
        assert_eq!(emoji(publication, "public_pin_emoji"), public);
    }

    // A ruse PIN has its own emoji, shown at issuance and again when typed,
    // so it looks exactly like a real PIN to whoever is watching.
    let ruse = cluster
        .voter_post(
            0,
            "/api/pin/ruse",
            serde_json::json!({ "passphrase": cluster.passphrases[0], "pin": pin }),
        )
        .await;
    let ruse_pin = ruse["ruse_pin"].as_u64().unwrap();
    let ruse_emoji = emoji(&ruse, "private_pin_emoji");
    assert_eq!(ruse_emoji.len(), 6);
    assert_ne!(ruse_emoji, mine);
    let coerced = cluster.vote(0, "reject", ruse_pin).await;
    assert_eq!(emoji(&coerced, "private_pin_emoji"), ruse_emoji);
    assert_ne!(
        emoji(&coerced, "public_pin_emoji"),
        public,
        "another ballot, another ciphertext"
    );
}

/// The verifiable mixes work from TWO ballots up (a shuffle of two elements
/// is the smallest that hides anything); one ballot is refused with a clear
/// message instead of failing inside the shuffle proof.
#[tokio::test]
async fn smallest_tally_has_two_ballots() {
    let mut cluster = ElectionCluster::start(2, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    cluster.open_voting().await;
    let pin0 = cluster.pin(0).await;
    cluster.vote_and_cast(0, "approve", pin0).await;
    let pin1 = cluster.pin(1).await;
    cluster.vote_and_cast(1, "reject", pin1).await;
    cluster.close_voting().await;

    let outcome = cluster.tally().await;
    assert_eq!(outcome.deduped, 2);
    assert_eq!(
        (outcome.counts.blank, outcome.counts.si, outcome.counts.no),
        (0, 1, 1)
    );
    let report = cluster.audit().await;
    assert!(report.ok(), "audit:\n{}", report.render());
}

#[tokio::test]
async fn single_ballot_tally_is_refused_clearly() {
    let mut cluster = ElectionCluster::start(1, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    cluster.open_voting().await;
    let pin0 = cluster.pin(0).await;
    // Two casts of ONE credential: two ballots released, one after the
    // re-vote filter - still nothing to mix it with.
    cluster.vote_and_cast(0, "approve", pin0).await;
    cluster.vote_and_cast(0, "reject", pin0).await;
    cluster.close_voting().await;

    let error = cluster
        .try_tally()
        .await
        .expect_err("one ballot cannot be mixed");
    let message = error.to_string();
    assert!(
        message.contains("at least 2 distinct confirmed ballots") && message.contains("found 1"),
        "{message}"
    );
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
    let first = cluster.cast(0, pin).await;
    let replay = cluster.cast(0, pin).await;
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
    // What a box published ABOUT a ballot is classified here too, from typed
    // content and the signer - the page never decides that itself.
    let metadata: Vec<&serde_json::Value> = rows
        .iter()
        .filter(|r| r["entry_type"] == "ballot_metadata")
        .collect();
    assert_eq!(metadata.len(), 2, "one per ballot box");
    for row in metadata {
        assert_eq!(row["ballot_box"]["status"], "valid", "{row}");
        assert_eq!(row["ballot_box"]["digest"], serde_json::json!(digest));
        assert_eq!(
            row["ballot_box"]["bb_id"],
            row["entity_ids"][0]
                .as_str()
                .unwrap()
                .trim_start_matches("BB-")
                .parse::<u64>()
                .unwrap()
        );
    }

    // What an entry COUNTS for is decided by the server, typed: the two
    // genuine publications count, one per ballot box.
    let counted = |rows: &[serde_json::Value]| -> Vec<u64> {
        let mut ids: Vec<u64> = rows
            .iter()
            .filter(|r| {
                r["entry_type"] == "ballot_digest"
                    && r["ballot_box"]["status"] == "valid"
                    && r["ballot_box"]["digest"] == serde_json::json!(digest)
            })
            .map(|r| r["ballot_box"]["bb_id"].as_u64().unwrap())
            .collect();
        ids.sort_unstable();
        ids
    };
    assert_eq!(counted(rows), [1, 2]);

    // A ballot box with its REAL key publishes, for the same digest, (1) its
    // own id as a string and (2) the other ballot box's id with markup in
    // the emoji. The board accepts both (payloads are opaque to it); the page
    // must count neither and must never run what they carry.
    {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD;
        let genuine = rows
            .iter()
            .find(|r| {
                r["entry_type"] == "ballot_digest"
                    && r["ballot_box"]["bb_id"] == 1
                    && r["payload"]["digest"] == serde_json::json!(digest)
            })
            .unwrap();
        let mut stringly = genuine["payload"].clone();
        stringly["receipt"]["bb_id"] = serde_json::json!("1");
        let mut for_another = genuine["payload"].clone();
        for_another["receipt"]["bb_id"] = serde_json::json!(2);
        for_another["emoji"][0] = serde_json::json!("<img src=x onerror=alert(1)>");
        let key = cluster.signing_key("bb-1");
        for (n, payload) in [stringly, for_another].into_iter().enumerate() {
            let data = format!(
                "voting,BB,ballot_digest,1,{}",
                b64.encode(serde_json::to_string(&payload).unwrap())
            );
            let entry = referendum_poc::clients::wbb::sign_entry(
                data.as_bytes(),
                "BB-1",
                genuine["timestamp"].as_i64().unwrap() + 1 + n as i64,
                &key,
            );
            cluster
                .wbb
                .client
                .submit_and_wait(&entry, std::time::Duration::from_secs(20))
                .await
                .expect("the board takes any payload from a ballot box");
        }
        let after = get_json(&cluster.client, &format!("{ui}/api/entries")).await;
        let after = after.as_array().unwrap();
        assert_eq!(after.len(), rows.len() + 2);
        assert_eq!(counted(after), [1, 2], "neither forgery counts");
        let reasons: Vec<&str> = after
            .iter()
            .filter(|r| r["ballot_box"]["status"] == "ignored")
            .map(|r| r["ballot_box"]["reason"].as_str().unwrap())
            .collect();
        assert_eq!(
            reasons,
            [
                "it cannot be read",
                "it names a ballot box that did not sign it"
            ]
        );
        assert!(after
            .iter()
            .filter(|r| r["ballot_box"]["status"] == "ignored")
            .all(|r| r["ballot_box"]["digest"] == serde_json::json!(digest)));
        // The voter app ignores them too.
        let verified = get_json(
            &cluster.client,
            &format!("{}/api/verify/{digest}", cluster.voter_urls[0]),
        )
        .await;
        assert_eq!(verified["publications"].as_array().unwrap().len(), 2);

        // The same two forgeries of a CONFIRMATION.
        let confirmation = after
            .iter()
            .find(|r| {
                r["entry_type"] == "cast_intended_proof"
                    && r["ballot_box"]["status"] == "valid"
                    && r["ballot_box"]["bb_id"] == 1
            })
            .expect("BB-1's confirmation");
        let mut stringly = confirmation["payload"].clone();
        stringly["bb_id"] = serde_json::json!("1");
        // A box that has not opened this ballot: the board refuses a SECOND
        // opening by a box that already made one (one opening per ballot per
        // box), so the forgery names a box with none - what is under test
        // here is that the PAGE counts an entry for nobody when the box it
        // names is not the box that signed it.
        let mut for_another = confirmation["payload"].clone();
        for_another["bb_id"] = serde_json::json!(3);
        for (n, payload) in [stringly, for_another].into_iter().enumerate() {
            let data = format!(
                "voting,BB,cast_intended_proof,1,{}",
                b64.encode(serde_json::to_string(&payload).unwrap())
            );
            let entry = referendum_poc::clients::wbb::sign_entry(
                data.as_bytes(),
                "BB-1",
                confirmation["timestamp"].as_i64().unwrap() + 10 + n as i64,
                &key,
            );
            cluster
                .wbb
                .client
                .submit_and_wait(&entry, std::time::Duration::from_secs(20))
                .await
                .expect("the board takes any payload from a ballot box");
        }
        let last = get_json(&cluster.client, &format!("{ui}/api/entries")).await;
        let last = last.as_array().unwrap();
        let confirmations = |status: &str| {
            last.iter()
                .filter(|r| {
                    r["entry_type"] == "cast_intended_proof" && r["ballot_box"]["status"] == status
                })
                .count()
        };
        assert_eq!(
            (confirmations("valid"), confirmations("ignored")),
            (2, 2),
            "forged confirmations count for nothing"
        );
        let verified = get_json(
            &cluster.client,
            &format!("{}/api/verify/{digest}", cluster.voter_urls[0]),
        )
        .await;
        assert_eq!(verified["confirmations"].as_array().unwrap().len(), 2);

        // A ballot box signing under `entity_id` while naming ANOTHER box in
        // an `entity_ids` list. The board refuses a single-signer submission
        // that carries multi-signer fields, so it never reaches the log - and
        // if a board ever served such an entry, the app and the page would
        // count it for nobody (unit-tested) and an audit would fail on it.
        let mut payload = genuine["payload"].clone();
        payload["receipt"]["bb_id"] = serde_json::json!(2);
        let data = format!(
            "voting,BB,ballot_digest,1,{}",
            b64.encode(serde_json::to_string(&payload).unwrap())
        );
        let timestamp = genuine["timestamp"].as_i64().unwrap() + 20;
        let signed =
            referendum_poc::clients::wbb::sign_entry(data.as_bytes(), "BB-1", timestamp, &key);
        let mut raw = serde_json::json!({
            "data": b64.encode(&signed.data),
            "timestamp": signed.timestamp,
            "entity_id": signed.entity_id,
            "signature": b64.encode(&signed.signature),
        });
        let submit_raw = |body: serde_json::Value| {
            let client = cluster.client.clone();
            let url = format!("{}submit", cluster.wbb.client.base_url());
            async move { client.post(url).json(&body).send().await.unwrap().status() }
        };
        // As it stands it is a plain (mislabelled) entry the board accepts.
        assert_eq!(submit_raw(raw.clone()).await, 200);
        raw["entity_ids"] = serde_json::json!(["BB-2"]);
        assert_eq!(
            submit_raw(raw.clone()).await,
            400,
            "a single-signer submission carrying multi-signer fields is refused"
        );
        // And the same entry replayed by ANYONE with an unverified field
        // added cannot become a second leaf either.
        let public = serde_json::json!({
            "data": b64.encode(&signed.data),
            "timestamp": signed.timestamp,
            "entity_id": signed.entity_id,
            "signature": b64.encode(&signed.signature),
            "sig_algorithm": "ed25519",
        });
        assert_eq!(submit_raw(public).await, 200, "a replay is deduplicated");
        let after_forgeries = loop {
            let rows = get_json(&cluster.client, &format!("{ui}/api/entries")).await;
            let rows = rows.as_array().unwrap().clone();
            if rows.len() > last.len() {
                break rows;
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        };
        assert_eq!(
            after_forgeries.len(),
            last.len() + 1,
            "only the mislabelled entry was logged"
        );
        let forged = after_forgeries.last().unwrap();
        assert_eq!(forged["entity_ids"], serde_json::json!(["BB-1"]));
        assert_eq!(forged["ballot_box"]["status"], "ignored");
        assert_eq!(counted(&after_forgeries), [1, 2], "it counts for nothing");
        let verified = get_json(
            &cluster.client,
            &format!("{}/api/verify/{digest}", cluster.voter_urls[0]),
        )
        .await;
        assert_eq!(verified["publications"].as_array().unwrap().len(), 2);
    }

    // Neither page may run inline or foreign script, whatever a payload says.
    for base in [ui.clone(), cluster.voter_urls[0].clone()] {
        let response = cluster.client.get(format!("{base}/")).send().await.unwrap();
        let csp = response.headers()["content-security-policy"]
            .to_str()
            .unwrap();
        assert!(csp.contains("default-src 'self'"), "{base}: {csp}");
    }
    let script = cluster
        .client
        .get(format!("{ui}/app.js"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(
        script.matches("innerHTML").count(),
        1,
        "the only innerHTML left empties the table"
    );
    assert!(script.contains("tbody.innerHTML = \"\";"));
    for sink in ["insertAdjacentHTML", "outerHTML", "document.write", "eval("] {
        assert!(
            !script.contains(sink),
            "{sink}: entry data is written as text only"
        );
    }

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
