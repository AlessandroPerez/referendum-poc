//! `referendum_happy_path`: V1-V15 for 8 voters over the full HTTPS
//! cluster - fixed vote matrix (1 blank, 1 re-vote, all options), exact
//! tally, complete WBB entry census, wbb-ui lookup, auditor all-OK.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use referendum_poc::protocol::tally::TallyCounts;
use referendum_poc::protocol::voting::parse_wbb_data;

use super::helpers::{get_json, ElectionCluster, ElectionOpts};

/// Fixed vote matrix: voter index -> (option, is the FINAL vote).
/// Voter 4 re-votes: reject first, then approve (last wins).
const MATRIX: [&str; 8] = [
    "approve", // v1: si
    "reject",  // v2: no
    "blank",   // v3: blank
    "approve", // v4: si (after a reject re-voted away)
    "reject",  // v5: no
    "approve", // v6: si
    "reject",  // v7: no
    "approve", // v8: si
];

#[tokio::test]
async fn referendum_happy_path() {
    let mut cluster = ElectionCluster::start(8, ElectionOpts::default()).await;

    // -- V1-V4: all 8 voters enroll and retrieve their PIN -----------------
    cluster.enroll_all().await;

    // -- V5: PIN verification succeeds with the real PIN -------------------
    let pin1 = cluster.pin(0).await;
    let verify = cluster
        .voter_post(
            0,
            "/api/pin/verify",
            serde_json::json!({ "passphrase": cluster.passphrases[0], "pin": pin1 }),
        )
        .await;
    assert_eq!(verify["valid"], true, "V5: real PIN verifies");

    // -- V10: voter 1 restricts to a trusted t_RT subset + both BBs --------
    let trusted = cluster
        .voter_post(
            0,
            "/api/settings/trusted",
            serde_json::json!({
                "passphrase": cluster.passphrases[0],
                "rts": ["rt-1", "rt-3"],
                "bbs": ["bb-1", "bb-2"]
            }),
        )
        .await;
    assert_eq!(trusted["rts"], serde_json::json!(["rt-1", "rt-3"]));

    // -- A4: PM opens the voting window ------------------------------------
    cluster.open_voting().await;

    // -- V11-V12: the fixed matrix (voter 4 re-votes: reject -> approve) ----
    let mut digests = Vec::new();
    for (i, option) in MATRIX.iter().enumerate() {
        let pin = cluster.pin(i).await;
        if i == 3 {
            cluster.vote_and_cast(i, "reject", pin).await;
        }
        let vote = cluster.vote_and_cast(i, option, pin).await;
        digests.push(vote["digest"].as_str().unwrap().to_string());
    }

    // -- V14: publication check - digest on >=2 BBs, no bot -------------------
    let status = cluster
        .voter_post(
            0,
            "/api/ballot/status",
            serde_json::json!({ "passphrase": cluster.passphrases[0] }),
        )
        .await;
    assert_eq!(status["no_bot"], true, "V14: no bot for voter 1");
    assert_eq!(status["published_bb_ids"], serde_json::json!([1, 2]));

    // -- V13: the CAI confirmation happened inside `vote_and_cast` (every
    //    cast is confirmed); a second confirmation has no held ballot ------
    let again = cluster
        .client
        .post(format!("{}/api/confirm", cluster.voter_urls[0]))
        .json(&serde_json::json!({ "passphrase": cluster.passphrases[0] }))
        .send()
        .await
        .unwrap();
    assert!(
        !again.status().is_success(),
        "V13: a confirmation is single-shot per cast (got {})",
        again.status()
    );

    // -- V14: manual verification on the public wbb-ui ---------------------
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
    assert!(page.contains("Public Bulletin Board"), "V14: page serves");
    let rows = get_json(&cluster.client, &format!("{ui}/api/entries")).await;
    assert!(
        rows.as_array()
            .unwrap()
            .iter()
            .any(|r| r["entry_type"] == "ballot_digest"
                && r["payload"]["digest"] == serde_json::json!(digests[0])),
        "V14: voter 1's digest is findable on the public page"
    );
    assert!(
        rows.as_array()
            .unwrap()
            .iter()
            .any(|r| r["entry_type"] == "cast_intended_proof"
                && r["payload"]["digest"] == serde_json::json!(digests[0])),
        "V13/V14: voter 1's cast-as-intended disclosure is on the public page"
    );

    // -- A5/A7: close voting, run the Sec. 3.9 tally ---------------------------
    cluster.close_voting().await;
    let outcome = cluster.tally().await;

    assert_eq!(outcome.released, 18, "9 casts x 2 BBs released");
    assert_eq!(outcome.reconciled, 9, "every ballot on >=2 BBs (no bot)");
    assert_eq!(outcome.deduped, 8, "voter 4's re-vote merges (last wins)");
    assert_eq!(outcome.valid, 8, "all real-PIN ballots pass the ACC check");
    assert_eq!(outcome.legitimate, 8, "all voters are eligible");
    assert_eq!(
        (outcome.counts.blank, outcome.counts.si, outcome.counts.no),
        (1, 4, 3),
        "fixed matrix tally"
    );

    // -- WBB entry census: every tallying artifact is on the log ----------------
    assert_eq!(cluster.entry_type_count("eligible_vids").await, 1);
    assert_eq!(
        cluster.entry_type_count("cast_intended_proof").await,
        18,
        "V13: every cast is confirmed on both BBs"
    );
    assert_eq!(cluster.entry_type_count("encrypted_ballot").await, 18);
    assert_eq!(cluster.entry_type_count("mixed_ballots").await, 2);
    assert_eq!(cluster.entry_type_count("re_encryption_proof").await, 4);
    assert_eq!(cluster.entry_type_count("tally_proof").await, 1);
    assert_eq!(cluster.entry_type_count("tally_result").await, 1);

    // -- V15: results viewing - decode the published tally_result ----------
    let entries = cluster.wbb.client.entries().await.expect("wbb entries");
    let published: TallyCounts = entries
        .entries
        .iter()
        .filter_map(|e| e.entry.get("data").and_then(|v| v.as_str()))
        .filter_map(|b64| BASE64.decode(b64).ok())
        .filter_map(|data| parse_wbb_data(&data))
        .find(|p| p.entry_type == "tally_result")
        .and_then(|p| BASE64.decode(p.content).ok())
        .and_then(|json| serde_json::from_slice(&json).ok())
        .expect("decodable tally_result entry");
    assert_eq!(
        (published.blank, published.si, published.no),
        (1, 4, 3),
        "V15: published result matches the driver outcome"
    );

    // V15 on the voter surface: `GET /api/results` returns the counts plus
    // links (leaf indexes) to the tally entries on the WBB.
    let results = get_json(
        &cluster.client,
        &format!("{}/api/results", cluster.voter_urls[0]),
    )
    .await;
    assert_eq!(results["phase"], "tallying");
    assert_eq!(results["counts"]["blank"], 1);
    assert_eq!(results["counts"]["si"], 4);
    assert_eq!(results["counts"]["no"], 3);
    assert_eq!(
        results["tally_entries"].as_array().unwrap().len(),
        2,
        "links to the tally_result and tally_proof entries"
    );

    // -- A6: Sec. 3.10 universal verification - every step OK ------------------
    let report = cluster.audit().await;
    assert!(report.ok(), "auditor found failures:\n{}", report.render());
    assert!(
        report.steps.len() >= 12,
        "audit must cover the whole pipeline, got:\n{}",
        report.render()
    );
}
