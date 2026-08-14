//! M2 harness smoke test: spawn the WBB over HTTPS and verify a threshold
//! entry is published with a deterministic checkpoint root hash.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use referendum_poc::{
    clients::wbb::sign_entry,
    protocol::tls::{issue_service_cert, ClusterCa},
};
use std::time::Duration;

use super::helpers;

const MASTER_SEED: [u8; 32] = [0xabu8; 32];

#[tokio::test]
async fn wbb_threshold_entry_and_deterministic_checkpoint() {
    helpers::init();
    let root1 = run_once().await;
    let root2 = run_once().await;
    assert_eq!(
        root1, root2,
        "checkpoint root hash must be byte-identical across two runs"
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
