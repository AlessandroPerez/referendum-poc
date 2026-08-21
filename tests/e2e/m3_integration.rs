//! M3 integration test: ceremony → cluster boot → ER publishes 3 setup entries
//! to the WBB, visible via the read API.

use std::path::PathBuf;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::{SigningKey, Verifier};
use rand::SeedableRng;
use referendum_poc::actors::common::actor_signing_key;
use referendum_poc::actors::er;
use referendum_poc::configuration::get_configuration;
use referendum_poc::protocol::rng::MasterSeed;
use referendum_poc::protocol::setup::artifacts::write_artifacts;
use referendum_poc::protocol::setup::run_ceremony;
use referendum_poc::protocol::tls::{issue_service_cert, reqwest_client_trusting_ca, ClusterCa};
use reqwest::Url;
use secrecy::{ExposeSecret, SecretString};
use sha2::Digest;

use super::helpers;

const MASTER_SEED: [u8; 32] = [0xabu8; 32];

#[tokio::test]
async fn er_publishes_three_setup_entries_to_wbb() {
    helpers::init();

    // 1. Run ceremony in a temp directory.
    let temp = tempfile::tempdir().expect("tempdir");
    let ceremony_dir = temp.path();

    let base_settings = base_settings();
    let master_seed = MasterSeed::new(MASTER_SEED);
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(MASTER_SEED);
    let ceremony = run_ceremony(&base_settings.election, &mut rng).unwrap();
    let _paths = write_artifacts(
        ceremony_dir,
        &base_settings,
        &ceremony,
        &master_seed,
        &base_settings.dip,
    )
    .expect("write ceremony artifacts");

    // 2. Spawn the WBB with the generated sunlight.yaml.
    let ca = ClusterCa::from_seed(&MASTER_SEED).unwrap();
    let wbb_cert = issue_service_cert(&ca, "wbb", &MASTER_SEED).unwrap();
    let wbb_port = helpers::free_port();
    let er_key = actor_signing_key(&master_seed, "ER-1");
    let wbb_config =
        helpers::WbbSpawnConfig::new(wbb_port).with_entity("ER-1", er_key.verifying_key());

    let wbb = helpers::WbbProcess::spawn(
        ceremony_dir,
        &ca,
        wbb_cert.cert_pem(),
        wbb_cert.key_pem(),
        wbb_config,
    )
    .await
    .expect("spawn wbb");

    // 3. Spawn the ER server in-process, pointing at the WBB.
    let er_port = helpers::free_port();
    let er_settings = build_er_settings(ceremony_dir, er_port, wbb_port, &base_settings);
    let er_signing_key = load_er_signing_key(ceremony_dir);
    let er_admin_token = load_er_admin_token(ceremony_dir);
    let (er_addr, er_tls, er_state) =
        er::build_service(er_settings, er_signing_key, er_admin_token.clone())
            .await
            .expect("build er service");
    let er_handle = tokio::spawn(async move {
        referendum_poc::actors::common::serve_rustls(er::router(er_state), er_addr, er_tls)
            .await
            .expect("er server")
    });

    // Give the ER server a moment to bind before sending requests.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 4. Call ER /admin/setup with the deterministic admin token.
    let admin_token = er_admin_token.expose_secret().clone();
    let client = reqwest_client_trusting_ca(ca.cert_pem()).unwrap();
    let setup_url = Url::parse(&format!("https://127.0.0.1:{}/admin/setup", er_port)).unwrap();
    let response = client
        .post(setup_url)
        .header("authorization", format!("Bearer {admin_token}"))
        .send()
        .await
        .expect("setup request");
    assert!(
        response.status().is_success(),
        "setup failed: {:?}",
        response.text().await
    );

    // 5. Poll the WBB until all 3 setup entries appear.
    let entries = poll_for_setup_entries(&wbb.client, 3, Duration::from_secs(10))
        .await
        .expect("setup entries not published in time");
    assert_eq!(entries.len(), 3);

    // 6. Verify each entry is signed by ER-1 and has the expected type.
    let er_key = actor_signing_key(&master_seed, "ER-1");
    let mut seen_types = std::collections::HashSet::new();
    for entry in &entries {
        let data_b64 = entry
            .entry
            .get("data")
            .and_then(|v| v.as_str())
            .expect("data field");
        let data = BASE64.decode(data_b64).expect("valid base64");
        let data_str = String::from_utf8(data.clone()).expect("utf8");
        let parts: Vec<&str> = data_str.split(',').collect();
        assert_eq!(parts.len(), 5, "WBB entry must have 5 fields: {data_str}");
        assert_eq!(parts[0], "setup");
        assert_eq!(parts[1], "ER");
        seen_types.insert(parts[2].to_string());

        let entity_id = entry
            .entry
            .get("entity_id")
            .and_then(|v| v.as_str())
            .expect("entity_id field");
        let timestamp = entry
            .entry
            .get("timestamp")
            .and_then(|v| v.as_i64())
            .expect("timestamp field");

        let sig_b64 = entry
            .entry
            .get("signature")
            .and_then(|v| v.as_str())
            .expect("signature field");
        let sig = BASE64.decode(sig_b64).expect("valid signature base64");
        let sig_bytes: [u8; 64] = sig.try_into().expect("ed25519 signature length");
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

        let mut hasher = sha2::Sha256::new();
        hasher.update(&data);
        hasher.update(entity_id.as_bytes());
        hasher.update(format!("{timestamp}").as_bytes());
        let message = hasher.finalize();
        er_key
            .verifying_key()
            .verify(&message, &signature)
            .expect("ER-1 signature valid");
    }
    assert!(
        seen_types.contains("election_pub_key")
            && seen_types.contains("pseudonymous_id_count")
            && seen_types.contains("voter_id_merkle_root"),
        "missing setup entry types: {:?}",
        seen_types
    );

    er_handle.abort();
}

fn base_settings() -> referendum_poc::configuration::Settings {
    let base_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    get_configuration(&base_dir).expect("base settings")
}

fn build_er_settings(
    ceremony_dir: &std::path::Path,
    er_port: u16,
    wbb_port: u16,
    base: &referendum_poc::configuration::Settings,
) -> referendum_poc::configuration::Settings {
    use referendum_poc::configuration::*;

    Settings {
        service: ServiceSettings {
            name: "er".to_string(),
            host: "127.0.0.1".to_string(),
            port: er_port,
        },
        tls: TlsSettings {
            cert_pem: ceremony_dir.join("er.pem").display().to_string(),
            key_pem: ceremony_dir.join("er-key.pem").display().to_string(),
            ca_pem: ceremony_dir.join("ca.pem").display().to_string(),
        },
        seeds: base.seeds.clone(),
        clock: base.clock.clone(),
        wbb: WbbSettings {
            base_url: format!("https://127.0.0.1:{wbb_port}/wbb/"),
            request_timeout_ms: 10000,
        },
        peers: Vec::new(),
        er: Default::default(),
        ns: Default::default(),
        election: base.election.clone(),
        dip: base.dip.clone(),
        voter: Default::default(),
        wbb_ui: Default::default(),
        _ceremony: CeremonyPaths {
            seed_bin: ceremony_dir.join("seed.bin").display().to_string(),
            sunlight_yaml: ceremony_dir.join("sunlight.yaml").display().to_string(),
            election_context: ceremony_dir
                .join("election_context.json")
                .display()
                .to_string(),
        },
    }
}

fn load_er_signing_key(ceremony_dir: &std::path::Path) -> SigningKey {
    let bytes = std::fs::read(ceremony_dir.join("er-signing-key.bin")).expect("er signing key");
    let seed: [u8; 32] = bytes.try_into().expect("32-byte signing key seed");
    SigningKey::from_bytes(&seed)
}

fn load_er_admin_token(ceremony_dir: &std::path::Path) -> SecretString {
    SecretString::new(
        std::fs::read_to_string(ceremony_dir.join("er-admin-token.txt"))
            .expect("er admin token")
            .trim()
            .to_string(),
    )
}

async fn poll_for_setup_entries(
    client: &referendum_poc::clients::wbb::WbbClient,
    expected: usize,
    deadline: Duration,
) -> Option<Vec<referendum_poc::clients::wbb::SequencedEntry>> {
    let end = tokio::time::Instant::now() + deadline;
    loop {
        if let Ok(entries) = client.entries().await {
            let setup: Vec<_> = entries
                .entries
                .into_iter()
                .filter(|e| {
                    e.entry
                        .get("data")
                        .and_then(|v| v.as_str())
                        .map(|s| {
                            let decoded = BASE64.decode(s).unwrap_or_default();
                            String::from_utf8(decoded)
                                .map(|d| d.starts_with("setup,ER,"))
                                .unwrap_or(false)
                        })
                        .unwrap_or(false)
                })
                .collect();
            if setup.len() >= expected {
                return Some(setup);
            }
        }
        if tokio::time::Instant::now() > end {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
