//! §13 `golden_determinism` (§9.6): the full 8-voter flow, driven with the
//! COMMITTED master seed, must reproduce `tests/e2e/golden/expected.json`
//! field-by-field — master seed, election-context hash, per-entry data
//! hashes, ballot emoji vectors, tally counts, WBB tree size and checkpoint
//! root.
//!
//! Regenerate with `GOLDEN_UPDATE=1 cargo test golden_determinism`.

use std::path::PathBuf;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use referendum_poc::protocol::voting::parse_wbb_data;
use sha2::{Digest, Sha256};

use super::helpers::{ElectionCluster, ElectionOpts};

/// Same fixed matrix as `referendum_happy_path` (voter 4 re-votes).
const MATRIX: [&str; 8] = [
    "approve", "reject", "blank", "approve", "reject", "approve", "reject", "approve",
];

fn golden_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("e2e")
        .join("golden")
        .join("expected.json")
}

#[tokio::test]
async fn golden_determinism() {
    // The COMMITTED §9.1 test master seed from configuration/base.yaml.
    let base = referendum_poc::configuration::get_configuration(&PathBuf::from(env!(
        "CARGO_MANIFEST_DIR"
    )))
    .expect("base settings");
    let seed_hex = {
        use secrecy::ExposeSecret as _;
        base.seeds.master_seed.expose_secret().clone()
    };
    let mut seed = [0u8; 32];
    hex::decode_to_slice(&seed_hex, &mut seed).expect("32-byte hex master seed");

    let mut cluster = ElectionCluster::start(
        8,
        ElectionOpts {
            master_seed: seed,
            ..Default::default()
        },
    )
    .await;

    // ── Drive the fixed flow ──────────────────────────────────────────────
    cluster.enroll_all().await;
    cluster.open_voting().await;
    let mut ballot_emoji: Vec<Vec<String>> = Vec::new();
    let mut record_emoji = |vote: &serde_json::Value| {
        ballot_emoji.push(
            vote["emoji"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| e.as_str().unwrap().to_string())
                .collect(),
        );
    };
    for (i, option) in MATRIX.iter().enumerate() {
        let pin = cluster.pin(i).await;
        if i == 3 {
            let vote = cluster.vote_and_cast(i, "reject", pin).await;
            record_emoji(&vote);
        }
        let vote = cluster.vote_and_cast(i, option, pin).await;
        record_emoji(&vote);
    }
    cluster.close_voting().await;
    let outcome = cluster.tally().await;

    // ── Collect the §9.6 golden fields ────────────────────────────────────
    let context_bytes =
        std::fs::read(cluster.ceremony_dir().join("election_context.json")).expect("context file");
    let entries = cluster.wbb.client.entries().await.expect("wbb entries");
    let entry_hashes: Vec<serde_json::Value> = entries
        .entries
        .iter()
        .map(|e| {
            let data = e
                .entry
                .get("data")
                .and_then(|v| v.as_str())
                .and_then(|b64| BASE64.decode(b64).ok())
                .expect("entry data");
            let parsed = parse_wbb_data(&data);
            serde_json::json!({
                "phase": parsed.as_ref().map(|p| p.phase.clone()).unwrap_or_default(),
                "entry_type": parsed.map(|p| p.entry_type).unwrap_or_default(),
                "data_sha256": hex::encode(Sha256::digest(&data)),
            })
        })
        .collect();

    let checkpoint = cluster.wbb.client.checkpoint().await.expect("checkpoint");
    let note = String::from_utf8_lossy(&checkpoint);
    let mut lines = note.lines();
    let _origin = lines.next().expect("checkpoint origin line");
    let tree_size: u64 = lines
        .next()
        .expect("checkpoint size line")
        .parse()
        .expect("numeric tree size");
    let checkpoint_root = lines.next().expect("checkpoint root line").to_string();

    let actual = serde_json::json!({
        "master_seed": seed_hex,
        "election_context_sha256": hex::encode(Sha256::digest(&context_bytes)),
        "ballot_emoji": ballot_emoji,
        "tally_counts": {
            "blank": outcome.counts.blank,
            "si": outcome.counts.si,
            "no": outcome.counts.no,
        },
        "wbb_tree_size": tree_size,
        "checkpoint_root": checkpoint_root,
        "entries": entry_hashes,
    });

    // ── Regenerate or compare ─────────────────────────────────────────────
    let path = golden_path();
    if std::env::var("GOLDEN_UPDATE").is_ok() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, serde_json::to_string_pretty(&actual).unwrap()).unwrap();
        eprintln!("golden: wrote {}", path.display());
        return;
    }

    let expected: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&path)
            .expect("tests/e2e/golden/expected.json missing - generate with GOLDEN_UPDATE=1"),
    )
    .expect("valid golden JSON");

    for field in [
        "master_seed",
        "election_context_sha256",
        "tally_counts",
        "ballot_emoji",
        "wbb_tree_size",
        "checkpoint_root",
    ] {
        assert_eq!(
            actual[field], expected[field],
            "golden field `{field}` diverged"
        );
    }
    let (act, exp) = (
        actual["entries"].as_array().unwrap(),
        expected["entries"].as_array().unwrap(),
    );
    assert_eq!(act.len(), exp.len(), "golden entry count diverged");
    for (i, (a, e)) in act.iter().zip(exp).enumerate() {
        assert_eq!(a, e, "golden entry {i} diverged");
    }
}
