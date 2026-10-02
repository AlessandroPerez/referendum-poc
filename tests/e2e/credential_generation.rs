//! Credential-generation integration test: ceremony -> election-admin generates 10 credentials,
//! co-signs `setup,RT,acc_pub_key,2,...` on the WBB, and writes enrollment
//! packages.

use std::path::PathBuf;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::SigningKey;
use rand::SeedableRng;
use referendum_poc::actors::admin::{gen_credentials, GenCredentialsConfig};
use referendum_poc::actors::common::serve_rustls;
use referendum_poc::actors::rt;
use referendum_poc::configuration::{
    get_configuration, CeremonyPaths, ServiceSettings, Settings, TlsSettings, WbbSettings,
};
use referendum_poc::protocol::clock::Clock;
use referendum_poc::protocol::rng::MasterSeed;
use referendum_poc::protocol::setup::artifacts::write_artifacts;
use referendum_poc::protocol::setup::run_ceremony;
use referendum_poc::protocol::tls::{issue_service_cert, reqwest_client_trusting_ca, ClusterCa};
use reqwest::Url;

use super::helpers;

const MASTER_SEED: [u8; 32] = [0xabu8; 32];

#[tokio::test]
async fn admin_generates_credentials_and_publishes_acc_pub_key() {
    helpers::init();
    let _cluster = helpers::cluster_guard().await;

    // 1. Run ceremony in a temp directory.
    let temp = tempfile::tempdir().expect("tempdir");
    let ceremony_dir = temp.path();

    let base_settings = base_settings();
    let master_seed = MasterSeed::new(MASTER_SEED);
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(MASTER_SEED);
    let ceremony = run_ceremony(&base_settings.election, &mut rng).unwrap();
    let _paths = write_artifacts(ceremony_dir, &base_settings, &ceremony, &master_seed)
        .expect("write ceremony artifacts");

    // 2. Spawn the WBB with the RT entity keys registered.
    let ca = ClusterCa::from_seed(&MASTER_SEED).unwrap();
    let wbb_cert = issue_service_cert(&ca, "wbb", &MASTER_SEED).unwrap();
    let wbb_port = helpers::free_port();

    let mut wbb_config = helpers::WbbSpawnConfig::new(wbb_port);
    for i in 1..=3 {
        let key = rt_signing_key(ceremony_dir, i);
        wbb_config = wbb_config.with_entity(&format!("RT-{i}"), key.verifying_key());
    }

    let wbb = helpers::WbbProcess::spawn(
        ceremony_dir,
        &ca,
        wbb_cert.cert_pem(),
        wbb_cert.key_pem(),
        wbb_config,
    )
    .await
    .expect("spawn wbb");

    // A leftover from the older layout, which held EVERY teller's shares:
    // credential generation must remove it.
    std::fs::create_dir_all(ceremony_dir.join("output")).unwrap();
    std::fs::write(
        ceremony_dir.join("output").join("enrollment_packages.json"),
        b"[\"stale all-shares file\"]",
    )
    .unwrap();

    // 3. Run the election-admin credential-generation driver (local RT signing).
    let wbb_url = Url::parse(&format!("https://127.0.0.1:{wbb_port}/wbb/")).unwrap();
    gen_credentials(GenCredentialsConfig {
        ceremony_dir: ceremony_dir.to_path_buf(),
        output_dir: ceremony_dir.join("output"),
        n_acc: base_settings.election.n_acc,
        t_rt: base_settings.election.t_rt,
        t_prime: base_settings.election.t_prime,
        wbb_url: wbb_url.clone(),
        rt_urls: None,
        rt_tokens: None,
        ca_pem: ca.cert_pem().to_string(),
        clock: Clock::from_settings(&base_settings.clock),
    })
    .await
    .expect("gen credentials");

    // A rerun - e.g. after a crash between publication and the writing of the
    // share files - is deterministic: it must ADOPT the entry already on the
    // board (not be refused as a duplicate, not publish it twice) and leave
    // the same files behind.
    let first_run = std::fs::read(
        ceremony_dir
            .join("output")
            .join("rt-1-credential_shares.json"),
    )
    .unwrap();
    std::fs::remove_file(
        ceremony_dir
            .join("output")
            .join("rt-1-credential_shares.json"),
    )
    .unwrap();
    gen_credentials(GenCredentialsConfig {
        ceremony_dir: ceremony_dir.to_path_buf(),
        output_dir: ceremony_dir.join("output"),
        n_acc: base_settings.election.n_acc,
        t_rt: base_settings.election.t_rt,
        t_prime: base_settings.election.t_prime,
        wbb_url: wbb_url.clone(),
        rt_urls: None,
        rt_tokens: None,
        ca_pem: ca.cert_pem().to_string(),
        clock: Clock::from_settings(&base_settings.clock),
    })
    .await
    .expect("a rerun adopts the published entry and rewrites the files");
    let second_run = std::fs::read(
        ceremony_dir
            .join("output")
            .join("rt-1-credential_shares.json"),
    )
    .unwrap();
    assert_eq!(
        first_run, second_run,
        "credential generation is deterministic"
    );

    // 4. Poll the WBB until the acc_pub_key entry appears.
    let entries = poll_for_rt_setup_entries(&wbb.client, 1, Duration::from_secs(15))
        .await
        .expect("RT setup entry not published in time");
    assert_eq!(entries.len(), 1);

    let entry = &entries[0];
    let data_b64 = entry
        .entry
        .get("data")
        .and_then(|v| v.as_str())
        .expect("data field");
    let data = BASE64.decode(data_b64).expect("valid base64");
    let data_str = String::from_utf8(data).expect("utf8");
    let parts: Vec<&str> = data_str.split(',').collect();
    assert_eq!(parts.len(), 5, "WBB entry must have 5 fields: {data_str}");
    assert_eq!(parts[0], "setup");
    assert_eq!(parts[1], "RT");
    assert_eq!(parts[2], "acc_pub_key");
    assert_eq!(parts[3], "2");

    // 5. Verify the entry is co-signed by RT-1, RT-2, RT-3.
    let entity_ids: Vec<String> = entry
        .entry
        .get("entity_ids")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .expect("entity_ids array");
    assert!(entity_ids.contains(&"RT-1".to_string()));
    assert!(entity_ids.contains(&"RT-2".to_string()));
    assert!(entity_ids.contains(&"RT-3".to_string()));

    let signatures = entry
        .entry
        .get("signatures")
        .and_then(|v| v.as_array())
        .expect("signatures array");
    assert_eq!(signatures.len(), 3);

    // 6. Credential material is split by recipient (Sec. 3.5.4): the ER file
    //    carries no teller share, each teller's file carries ONLY its own
    //    shares, and no file holds every teller's shares any more.
    let output = ceremony_dir.join("output");
    assert!(
        !output.join("enrollment_packages.json").exists(),
        "the all-shares file must not exist"
    );
    let er_json = tokio::fs::read_to_string(output.join("er_credential_packages.json"))
        .await
        .expect("read the ER credential file");
    let er_packages: Vec<serde_json::Value> = serde_json::from_str(&er_json).unwrap();
    assert_eq!(er_packages.len(), base_settings.election.n_acc);
    for package in &er_packages {
        let keys: Vec<&String> = package.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["a", "enc_a_ext"], "the ER sees A and E[A] only");
    }
    assert!(
        !er_json.contains("from_id"),
        "no teller share in the ER file"
    );
    for rt_id in 1..=base_settings.election.n_rt {
        let path = output.join(format!("rt-{rt_id}-credential_shares.json"));
        let shares: Vec<serde_json::Value> = serde_json::from_str(
            &tokio::fs::read_to_string(&path)
                .await
                .expect("RT share file"),
        )
        .unwrap();
        assert_eq!(shares.len(), base_settings.election.n_acc);
        for share in &shares {
            assert_eq!(
                share["share"]["from_id"].as_u64().unwrap() as usize,
                rt_id,
                "RT-{rt_id}'s file holds only its own shares"
            );
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "share files are owner-readable only");
        }
    }

    // A teller polices its file: it loads its own shares, and refuses a file
    // with another teller's share or with the wrong number of credentials.
    use referendum_poc::protocol::acc::parse_rt_credential_shares;
    let n_acc = base_settings.election.n_acc;
    let own = std::fs::read(output.join("rt-1-credential_shares.json")).unwrap();
    assert_eq!(
        parse_rt_credential_shares(&own, 1, n_acc).unwrap().len(),
        n_acc
    );
    let as_other = parse_rt_credential_shares(&own, 2, n_acc)
        .unwrap_err()
        .to_string();
    assert!(as_other.contains("another teller's share"), "{as_other}");
    // One foreign share smuggled into an otherwise valid file.
    let mut mixed: Vec<serde_json::Value> = serde_json::from_slice(&own).unwrap();
    let foreign: Vec<serde_json::Value> =
        serde_json::from_slice(&std::fs::read(output.join("rt-2-credential_shares.json")).unwrap())
            .unwrap();
    mixed[3] = foreign[3].clone();
    let smuggled = parse_rt_credential_shares(&serde_json::to_vec(&mixed).unwrap(), 1, n_acc)
        .unwrap_err()
        .to_string();
    assert!(smuggled.contains("share of RT-2"), "{smuggled}");
    let short = parse_rt_credential_shares(&own, 1, n_acc + 1)
        .unwrap_err()
        .to_string();
    assert!(short.contains("credentials"), "{short}");
}

#[tokio::test]
async fn rt_server_signs_with_its_service_token() {
    helpers::init();
    let _cluster = helpers::cluster_guard().await;

    let temp = tempfile::tempdir().expect("tempdir");
    let ceremony_dir = temp.path();

    let base_settings = base_settings();
    let master_seed = MasterSeed::new(MASTER_SEED);
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(MASTER_SEED);
    let ceremony = run_ceremony(&base_settings.election, &mut rng).unwrap();
    write_artifacts(ceremony_dir, &base_settings, &ceremony, &master_seed)
        .expect("write ceremony artifacts");

    let ca = ClusterCa::from_seed(&MASTER_SEED).unwrap();
    let port = helpers::free_port();
    let settings = build_rt_settings(ceremony_dir, 1, port, 0, &base_settings);
    let signing_key = rt_signing_key(ceremony_dir, 1);
    let token = rt_service_token(ceremony_dir, 1);
    let (addr, tls, state) = rt::build_service(settings, signing_key)
        .await
        .expect("build rt service");
    let handle = tokio::spawn(async move {
        serve_rustls(rt::router(state), addr, tls)
            .await
            .expect("rt server")
    });
    tokio::time::sleep(Duration::from_millis(200)).await;

    let client = reqwest_client_trusting_ca(ca.cert_pem()).unwrap();
    let base = Url::parse(&format!("https://127.0.0.1:{port}/")).unwrap();

    // /status is unauthenticated.
    let status: serde_json::Value = client
        .get(base.join("status").unwrap())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(status["entity_id"], "RT-1");

    // /sign without token is rejected.
    let unauthorized = client
        .post(base.join("sign").unwrap())
        .json(&serde_json::json!({ "data": "setup,RT,acc_pub_key,2,test" }))
        .send()
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), 401);

    // /sign with token succeeds.
    let data = "setup,RT,acc_pub_key,2,test";
    let sign_resp: serde_json::Value = client
        .post(base.join("sign").unwrap())
        .bearer_auth(&token)
        .json(&serde_json::json!({ "data": data }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(sign_resp["entity_id"], "RT-1");
    assert!(!sign_resp["signature"].as_str().unwrap().is_empty());
    assert_ne!(sign_resp["timestamp"].as_i64().unwrap(), 1);

    handle.abort();
}

fn base_settings() -> Settings {
    let base_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    get_configuration(&base_dir).expect("base settings")
}

fn build_rt_settings(
    ceremony_dir: &std::path::Path,
    idx: usize,
    port: u16,
    wbb_port: u16,
    base: &Settings,
) -> Settings {
    Settings {
        service: ServiceSettings {
            name: format!("rt-{idx}"),
            host: "127.0.0.1".to_string(),
            port,
        },
        tls: TlsSettings {
            cert_pem: ceremony_dir
                .join(format!("rt-{idx}.pem"))
                .display()
                .to_string(),
            key_pem: ceremony_dir
                .join(format!("rt-{idx}-key.pem"))
                .display()
                .to_string(),
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

fn rt_signing_key(ceremony_dir: &std::path::Path, idx: usize) -> SigningKey {
    let bytes = std::fs::read(ceremony_dir.join(format!("rt-{idx}-signing-key.bin")))
        .expect("rt signing key");
    let seed: [u8; 32] = bytes.try_into().expect("32-byte signing key seed");
    SigningKey::from_bytes(&seed)
}

fn rt_service_token(ceremony_dir: &std::path::Path, idx: usize) -> String {
    std::fs::read_to_string(ceremony_dir.join(format!("rt-{idx}-service-token.txt")))
        .expect("rt service token")
        .trim()
        .to_string()
}

async fn poll_for_rt_setup_entries(
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
                                .map(|d| d.starts_with("setup,RT,"))
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
