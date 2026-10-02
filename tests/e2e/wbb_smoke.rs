//! WBB harness smoke tests: spawn the WBB over HTTPS and verify a threshold
//! entry is published with a deterministic checkpoint root hash, and that a
//! wall-clock WBB enforces its +/- 5 minute freshness window.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use referendum_poc::{
    clients::wbb::sign_entry,
    protocol::tls::{issue_service_cert, ClusterCa},
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::helpers;

const MASTER_SEED: [u8; 32] = [0xabu8; 32];

#[tokio::test]
async fn wbb_threshold_entry_and_deterministic_checkpoint() {
    helpers::init();
    // This test spawns WBB processes on bind-then-released ports twice, so it
    // participates in the same port race as the cluster tests - it must
    // hold the shared guard too (the likely cause of the
    // historical one-off suite flake).
    let _cluster = helpers::cluster_guard().await;
    let root1 = run_once().await;
    let root2 = run_once().await;
    assert_eq!(
        root1, root2,
        "checkpoint root hash must be byte-identical across two runs"
    );
}

/// On the wall clock the fork's freshness check is active: an entry stamped
/// with the current Unix time is accepted and sequenced with a real
/// timestamp, one stamped with a logical tick (far in the past) is refused.
#[tokio::test]
async fn wbb_wall_clock_enforces_freshness_window() {
    helpers::init();
    let _cluster = helpers::cluster_guard().await;
    let temp = tempfile::tempdir().expect("tempdir");
    let work_dir = temp.path();

    let ca = ClusterCa::from_seed(&MASTER_SEED).expect("cluster ca");
    let wbb_cert = issue_service_cert(&ca, "wbb", &[2u8; 32]).expect("wbb cert");
    let rt_keys: Vec<_> = (1..=3)
        .map(|i| helpers::entity_signing_key(&MASTER_SEED, &format!("RT-{i}")))
        .collect();
    let rt_key = &rt_keys[0];

    let port = helpers::free_port();
    let mut config = helpers::WbbSpawnConfig::new(port).with_timestamp_validation();
    for (i, key) in rt_keys.iter().enumerate() {
        config = config.with_entity(&format!("RT-{}", i + 1), key.verifying_key());
    }
    let wbb = helpers::WbbProcess::spawn(
        work_dir,
        &ca,
        wbb_cert.cert_pem(),
        wbb_cert.key_pem(),
        config,
    )
    .await
    .expect("spawn wbb");

    let started_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_millis() as i64;

    // Stale (logical-clock) timestamp: refused before sequencing.
    let stale = "setup,RT,acc_pub_key,2,stale-timestamp";
    let err = wbb
        .client
        .submit(&sign_entry(stale.as_bytes(), "RT-1", 1, rt_key))
        .await
        .expect_err("a logical tick is outside the freshness window");
    assert!(
        matches!(
            err,
            referendum_poc::clients::wbb::WbbError::Http(reqwest::StatusCode::BAD_REQUEST, _)
        ),
        "expected 400 for a stale timestamp, got {err:?}"
    );

    // Fresh wall-clock timestamps (threshold 2, three co-signers): accepted
    // and sequenced on real time.
    let fresh = "setup,RT,acc_pub_key,2,fresh-timestamp";
    for (i, key) in rt_keys.iter().enumerate() {
        let entity_id = format!("RT-{}", i + 1);
        let _ = wbb
            .client
            .submit(&sign_entry(fresh.as_bytes(), &entity_id, started_ms, key))
            .await
            .expect("fresh submission accepted");
    }
    let found = poll_for_entry(&wbb.client, fresh, Duration::from_secs(5))
        .await
        .expect("entry included");
    assert_eq!(found.leaf_index, 0, "the stale entry must not have landed");
    assert!(
        found.timestamp >= started_ms,
        "sequencing timestamp {} must be real time (>= {started_ms})",
        found.timestamp
    );
    assert!(
        found.timestamp - started_ms < 60_000,
        "sequencing timestamp {} must be current (test started at {started_ms})",
        found.timestamp
    );
}

async fn run_once() -> String {
    let temp = tempfile::tempdir().expect("tempdir");
    let work_dir = temp.path();

    let ca = ClusterCa::from_seed(&MASTER_SEED).expect("cluster ca");
    let wbb_cert = issue_service_cert(&ca, "wbb", &[1u8; 32]).expect("wbb cert");

    let rt_keys: Vec<_> = (1..=3)
        .map(|i| helpers::entity_signing_key(&MASTER_SEED, &format!("RT-{i}")))
        .collect();

    let port = helpers::free_port();
    let mut config = helpers::WbbSpawnConfig::new(port);
    for (i, key) in rt_keys.iter().enumerate() {
        config = config.with_entity(&format!("RT-{}", i + 1), key.verifying_key());
    }

    let wbb = helpers::WbbProcess::spawn(
        work_dir,
        &ca,
        wbb_cert.cert_pem(),
        wbb_cert.key_pem(),
        config,
    )
    .await
    .expect("spawn wbb");

    let wbb_data = "setup,RT,acc_pub_key,2,poc-test-key-material";
    let timestamp = 1;

    // Submit partial signatures from RT-1, RT-2 and RT-3; threshold is 2.
    for (i, key) in rt_keys.iter().enumerate() {
        let entity_id = format!("RT-{}", i + 1);
        let entry = sign_entry(wbb_data.as_bytes(), &entity_id, timestamp, key);
        let _ = wbb.client.submit(&entry).await.expect("submit partial");
    }

    // Poll until the entry is included.
    let found = poll_for_entry(&wbb.client, wbb_data, Duration::from_secs(5))
        .await
        .expect("entry included");
    assert_eq!(found.leaf_index, 0);

    // All 3 signers arrived before publication, so exactly one leaf must exist
    // (a late `ref:N` leaf would change the root hash and flake determinism).
    let entries = wbb.client.entries().await.expect("entries");
    assert_eq!(entries.entries.len(), 1, "expected a single published leaf");

    // Negative check: a client without the cluster CA must fail the TLS
    // handshake against the WBB.
    let untrusting = reqwest::Client::builder()
        .tls_built_in_root_certs(false)
        .timeout(Duration::from_secs(5))
        .build()
        .expect("plain client");
    let err = untrusting
        .get(format!("https://127.0.0.1:{port}/wbb/entries"))
        .send()
        .await
        .expect_err("handshake must fail without the cluster CA");
    assert!(err.is_connect() || err.is_request());

    // Fetch the signed checkpoint bytes.
    let checkpoint = wbb.client.checkpoint().await.expect("checkpoint");
    extract_root_hash(&checkpoint).expect("valid checkpoint root hash")
}

fn extract_root_hash(checkpoint: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(checkpoint).ok()?;
    let note = text.split('\u{2014}').next()?;
    note.lines().nth(2).map(|s| s.to_owned())
}

async fn poll_for_entry(
    client: &referendum_poc::clients::wbb::WbbClient,
    wbb_data: &str,
    deadline: Duration,
) -> Option<referendum_poc::clients::wbb::SequencedEntry> {
    let data_b64 = BASE64.encode(wbb_data.as_bytes());
    let end = tokio::time::Instant::now() + deadline;
    loop {
        if let Ok(entries) = client.entries().await {
            if let Some(found) = entries.entries.iter().find(|e| {
                e.entry
                    .get("data")
                    .and_then(|v| v.as_str())
                    .map(|s| s == data_b64)
                    .unwrap_or(false)
            }) {
                return Some(found.clone());
            }
        }
        if tokio::time::Instant::now() > end {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Validators' signatures are audited against keys pinned OUTSIDE the board.
/// Here the test plays two validators against the real board: the board (Go)
/// accepts the signatures this side (Rust) produces - the two BLS
/// implementations agree - and the auditor accepts genuine signatures,
/// reports partial coverage without failing, and fails on a forged signature
/// or on one attributed to a validator nobody pinned.
#[tokio::test]
async fn validator_signatures_are_audited_against_pinned_keys() {
    use referendum_poc::actors::auditor::{audit_log_and_validators, AuditConfig};
    use referendum_poc::protocol::{tlog, validators::ValidatorKey};

    helpers::init();
    let _cluster = helpers::cluster_guard().await;
    let temp = tempfile::tempdir().expect("tempdir");
    let work_dir = temp.path();
    let ca = ClusterCa::from_seed(&MASTER_SEED).expect("cluster ca");
    let wbb_cert = issue_service_cert(&ca, "wbb", &[3u8; 32]).expect("wbb cert");
    let rt_keys: Vec<_> = (1..=3)
        .map(|i| helpers::entity_signing_key(&MASTER_SEED, &format!("RT-{i}")))
        .collect();
    let validators = [
        ("V-1", ValidatorKey::from_seed(&[0x11; 32]).unwrap()),
        ("V-2", ValidatorKey::from_seed(&[0x22; 32]).unwrap()),
    ];

    let mut config = helpers::WbbSpawnConfig::new(helpers::free_port());
    for (i, key) in rt_keys.iter().enumerate() {
        config = config.with_entity(&format!("RT-{}", i + 1), key.verifying_key());
    }
    for (id, key) in &validators {
        config = config.with_validator(id, key.public_key());
    }
    let wbb = helpers::WbbProcess::spawn(
        work_dir,
        &ca,
        wbb_cert.cert_pem(),
        wbb_cert.key_pem(),
        config,
    )
    .await
    .expect("spawn wbb");

    // Two published entries.
    for content in ["first", "second"] {
        let data = format!("setup,RT,acc_pub_key,2,{content}");
        for (i, key) in rt_keys.iter().enumerate() {
            let entry = sign_entry(data.as_bytes(), &format!("RT-{}", i + 1), 1, key);
            wbb.client.submit(&entry).await.expect("submit");
        }
        poll_for_entry(&wbb.client, &data, Duration::from_secs(5))
            .await
            .expect("entry included");
    }

    let seed: [u8; 32] = std::fs::read(work_dir.join("wbb-log-seed.bin"))
        .unwrap()
        .try_into()
        .unwrap();
    let cfg = AuditConfig {
        wbb_url: wbb.client.base_url().clone(),
        ca_pem: ca.cert_pem().to_string(),
        log_origin: referendum_poc::protocol::tlog::log_origin_of(wbb.client.base_url()),
        log_key: tlog::derive_log_public_key(&seed).unwrap(),
        validator_keys: validators
            .iter()
            .map(|(id, key)| (id.to_string(), key.public_key()))
            .collect(),
        entity_keys: Vec::new(),
        n_tt: 3,
        t_tt: 2,
    };

    // Each validator signs what it verified: V-1 both leaves, V-2 only leaf 0.
    let head = tlog::verify_checkpoint(&wbb.client.checkpoint().await.unwrap(), &cfg.log_key)
        .expect("tree head signed by the pinned key");
    let served = wbb.client.entries_raw().await.unwrap().entries;
    for (id, key, leaves) in [
        ("V-1", &validators[0].1, vec![0usize, 1]),
        ("V-2", &validators[1].1, vec![0]),
    ] {
        for index in leaves {
            let entry = &served[index];
            let leaf = tlog::leaf_hash(entry.entry.get().as_bytes(), index as u64, entry.timestamp)
                .unwrap();
            let message = referendum_poc::protocol::validators::validation_message(
                &head.origin,
                index as u64,
                &leaf,
            );
            wbb.client
                .submit_validation(id, index as i64, &key.sign(&message))
                .await
                .expect("the board accepts a signature made on this side");
        }
    }

    let checkpoint = wbb.client.checkpoint().await.unwrap();
    let genuine = wbb.client.entries_raw().await.unwrap().entries;
    let (report, covered) = audit_log_and_validators(&cfg, &checkpoint, &genuine);
    assert_eq!(covered, Some(2), "{}", report.render());
    let step = report
        .steps
        .iter()
        .find(|s| s.name == "validator_signatures")
        .expect("step");
    assert!(step.ok, "{}", report.render());
    assert!(
        step.detail.contains("3 validator signatures") && step.detail.contains("1 of 2 entries"),
        "partial coverage is reported, not failed: {}",
        step.detail
    );

    // A signature swapped for another leaf's: it does not verify here.
    let mut forged = genuine.clone();
    forged[1].validations[0].signature = genuine[0].validations[0].signature.clone();
    let (report, covered) = audit_log_and_validators(&cfg, &checkpoint, &forged);
    assert_eq!(covered, None);
    let step = report
        .steps
        .iter()
        .find(|s| s.name == "validator_signatures")
        .unwrap();
    assert!(
        !step.ok && step.detail.contains("does not verify"),
        "{}",
        step.detail
    );

    // A genuine signature attributed to a validator nobody pinned.
    let mut misattributed = genuine.clone();
    misattributed[0].validations[0].validator_id = "V-9".to_string();
    let (report, _) = audit_log_and_validators(&cfg, &checkpoint, &misattributed);
    let step = report
        .steps
        .iter()
        .find(|s| s.name == "validator_signatures")
        .unwrap();
    assert!(
        !step.ok && step.detail.contains("unknown validator V-9"),
        "{}",
        step.detail
    );

    // A board that withholds every signature of one validator (or of all)
    // cannot be failed - validators are slow by design - but it is said out
    // loud, never reported as quiet success.
    let mut withheld = genuine.clone();
    for entry in &mut withheld {
        entry.validations.retain(|v| v.validator_id != "V-2");
    }
    let (report, _) = audit_log_and_validators(&cfg, &checkpoint, &withheld);
    let step = report
        .steps
        .iter()
        .find(|s| s.name == "validator_signatures")
        .unwrap();
    assert!(
        step.ok && step.detail.contains("no signature at all from V-2"),
        "{}",
        step.detail
    );
    for entry in &mut withheld {
        entry.validations.clear();
    }
    let (report, _) = audit_log_and_validators(&cfg, &checkpoint, &withheld);
    let step = report
        .steps
        .iter()
        .find(|s| s.name == "validator_signatures")
        .unwrap();
    assert!(
        step.detail.contains("0 validator signatures")
            && step.detail.contains("no signature at all from V-1, V-2"),
        "{}",
        step.detail
    );
    assert!(
        !report.render().is_empty() && !genuine[0].validations.is_empty(),
        "the genuine list did carry signatures"
    );

    // An auditor that pins no validators does not audit their signatures.
    let mut unpinned = cfg.clone();
    unpinned.validator_keys.clear();
    let (report, covered) = audit_log_and_validators(&unpinned, &checkpoint, &forged);
    assert_eq!(covered, Some(2));
    assert!(report
        .steps
        .iter()
        .all(|s| s.name != "validator_signatures"));
}
