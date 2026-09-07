//! M5 integration test: full enrollment of one voter through the real HTTP
//! cluster (DIP, NS, ER, RT×3, voter-server) — login → enroll → NS readiness →
//! PIN retrieval (share delivery + threshold DVNIZKP) → local PIN verification.
//!
//! Exit gate (roadmap M5): the retrieved PIN is deterministic — asserted
//! against a committed expected value derived from the test master seed.

use std::path::PathBuf;
use std::time::Duration;

use claims::{assert_gt, assert_lt};
use ed25519_dalek::SigningKey;
use rand::SeedableRng;
use referendum_poc::actors::admin::{gen_credentials, GenCredentialsConfig};
use referendum_poc::actors::common::serve_rustls;
use referendum_poc::actors::{dip, er, ns, rt, voter};
use referendum_poc::configuration::{
    get_configuration, CeremonyPaths, DipSettings, ErClientSettings, NsClientSettings,
    PeerSettings, ServiceSettings, Settings, TlsSettings, VoterSettings, WbbSettings,
};
use referendum_poc::protocol::clock::LogicalClock;
use referendum_poc::protocol::rng::MasterSeed;
use referendum_poc::protocol::setup::artifacts::write_artifacts;
use referendum_poc::protocol::setup::run_ceremony;
use referendum_poc::protocol::tls::{issue_service_cert, reqwest_client_trusting_ca, ClusterCa};
use reqwest::Url;
use secrecy::SecretString;

use super::helpers;

const MASTER_SEED: [u8; 32] = [0xabu8; 32];

/// The deterministic 8-digit PIN for voter 1 under `MASTER_SEED` (D4/§9).
/// If this changes, the credential derivation pipeline changed — that is a
/// determinism regression, not a value to casually update.
const EXPECTED_PIN_VOTER_1: usize = 25149446;

#[tokio::test]
async fn voter_enrolls_and_verifies_deterministic_pin() {
    helpers::init();
    let _cluster = helpers::cluster_guard().await;

    // ── 1. Ceremony ────────────────────────────────────────────────────────
    let temp = tempfile::tempdir().expect("tempdir");
    let ceremony_dir = temp.path();
    let base = base_settings();
    let master_seed = MasterSeed::new(MASTER_SEED);
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(MASTER_SEED);
    let ceremony = run_ceremony(&base.election, &mut rng).unwrap();
    write_artifacts(ceremony_dir, &base, &ceremony, &master_seed, &base.dip)
        .expect("write ceremony artifacts");

    // ── 2. WBB (needed by gen-credentials for the acc_pub_key entry) ──────
    let ca = ClusterCa::from_seed(&MASTER_SEED).unwrap();
    let wbb_cert = issue_service_cert(&ca, "wbb", &MASTER_SEED).unwrap();
    let wbb_port = helpers::free_port();
    let mut wbb_config = helpers::WbbSpawnConfig::new(wbb_port);
    for i in 1..=3 {
        let key = signing_key(ceremony_dir, &format!("rt-{i}"));
        wbb_config = wbb_config.with_entity(&format!("RT-{i}"), key.verifying_key());
    }
    let _wbb = helpers::WbbProcess::spawn(
        ceremony_dir,
        &ca,
        wbb_cert.cert_pem(),
        wbb_cert.key_pem(),
        wbb_config,
    )
    .await
    .expect("spawn wbb");

    // ── 3. Credentials (enrollment packages) ──────────────────────────────
    let wbb_url = Url::parse(&format!("https://127.0.0.1:{wbb_port}/wbb/")).unwrap();
    gen_credentials(GenCredentialsConfig {
        ceremony_dir: ceremony_dir.to_path_buf(),
        output_dir: ceremony_dir.join("output"),
        n_acc: base.election.n_acc,
        t_rt: base.election.t_rt,
        t_prime: base.election.t_prime,
        wbb_url,
        rt_urls: None,
        rt_tokens: None,
        ca_pem: ca.cert_pem().to_string(),
        clock: LogicalClock::new(base.clock.base_ms, base.clock.tick_ms),
    })
    .await
    .expect("gen credentials");

    // ── 4. Boot the cluster: DIP, NS, ER, RT×3, voter-server ─────────────
    let dip_port = helpers::free_port();
    let ns_port = helpers::free_port();
    let er_port = helpers::free_port();
    let rt_ports: Vec<u16> = (0..3).map(|_| helpers::free_port()).collect();
    let voter_port = helpers::free_port();

    let mk = |name: &str, port: u16| {
        cluster_settings(
            ceremony_dir,
            name,
            port,
            wbb_port,
            dip_port,
            ns_port,
            er_port,
            &rt_ports,
            &base,
        )
    };

    tokio::spawn(dip::run(
        mk("dip", dip_port),
        signing_key(ceremony_dir, "dip"),
    ));
    tokio::spawn(ns::run(mk("ns", ns_port), signing_key(ceremony_dir, "ns")));

    let (er_addr, er_tls, er_state) = er::build_service(
        mk("er", er_port),
        signing_key(ceremony_dir, "er"),
        SecretString::new(admin_token(ceremony_dir)),
    )
    .await
    .expect("build er");
    tokio::spawn(async move {
        serve_rustls(er::router(er_state), er_addr, er_tls)
            .await
            .expect("er server")
    });

    for (i, port) in rt_ports.iter().enumerate() {
        let name = format!("rt-{}", i + 1);
        let (addr, tls, state) =
            rt::build_service(mk(&name, *port), signing_key(ceremony_dir, &name))
                .await
                .expect("build rt");
        tokio::spawn(async move {
            serve_rustls(rt::router(state), addr, tls)
                .await
                .expect("rt server")
        });
    }

    let mut voter_settings = mk("voter-1", voter_port);
    voter_settings.voter.state_dir = ceremony_dir.join("voter-state").display().to_string();
    voter_settings.voter.static_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("static")
        .display()
        .to_string();
    let (voter_addr, voter_tls, voter_state) = voter::build_service(voter_settings)
        .await
        .expect("build voter");
    tokio::spawn(async move {
        serve_rustls(voter::router(voter_state), voter_addr, voter_tls)
            .await
            .expect("voter server")
    });

    tokio::time::sleep(Duration::from_millis(300)).await;

    // ── 5. Drive the SPA API (V1–V5) ──────────────────────────────────────
    let client = reqwest_client_trusting_ca(ca.cert_pem()).unwrap();
    let base_url = format!("https://127.0.0.1:{voter_port}");

    // SPA smoke: static assets are served.
    let index = client
        .get(format!("{base_url}/"))
        .send()
        .await
        .expect("GET /")
        .text()
        .await
        .unwrap();
    assert!(index.contains("Vote App"), "SPA index must be served");

    // V1 login.
    let login: serde_json::Value = post_json(
        &client,
        &format!("{base_url}/api/login"),
        serde_json::json!({ "fiscal_id": "VOTER-001" }),
    )
    .await;
    assert_eq!(login["vid"], 1);

    // V2–V3 enroll (passphrase shown once).
    let enroll: serde_json::Value = post_json(
        &client,
        &format!("{base_url}/api/enroll"),
        serde_json::json!({ "fiscal_id": "VOTER-001" }),
    )
    .await;
    let passphrase = enroll["passphrase"]
        .as_str()
        .expect("passphrase")
        .to_string();
    assert_eq!(passphrase.split('-').count(), 6, "6-word passphrase (V2)");

    // Double enrollment is rejected.
    let relogin: serde_json::Value = post_json(
        &client,
        &format!("{base_url}/api/login"),
        serde_json::json!({ "fiscal_id": "VOTER-001" }),
    )
    .await;
    assert_eq!(relogin["vid"], 1, "re-login keeps the same vid");
    let dup = client
        .post(format!("{base_url}/api/enroll"))
        .json(&serde_json::json!({ "fiscal_id": "VOTER-001" }))
        .send()
        .await
        .unwrap();
    assert_eq!(dup.status(), 409, "second enrollment must conflict");

    // V4a status poll until the NS shows ≥ t_RT notifications.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let status: serde_json::Value = post_json(
            &client,
            &format!("{base_url}/api/status"),
            serde_json::json!({ "passphrase": passphrase }),
        )
        .await;
        assert_eq!(status["enrolled"], true);
        if status["pin_ready"] == true {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "PIN never became ready"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // V4b PIN retrieval: share delivery + threshold DVNIZKP.
    let pin_resp: serde_json::Value = post_json(
        &client,
        &format!("{base_url}/api/pin/retrieve"),
        serde_json::json!({ "passphrase": passphrase }),
    )
    .await;
    let pin = pin_resp["pin"].as_u64().expect("pin") as usize;
    assert_gt!(pin, 0);
    assert_lt!(pin, 100_000_000, "8-digit PIN (D14)");
    assert_eq!(
        pin, EXPECTED_PIN_VOTER_1,
        "PIN must be deterministic under the committed master seed (M5 exit gate)"
    );

    // Retrieval is idempotent.
    let again: serde_json::Value = post_json(
        &client,
        &format!("{base_url}/api/pin/retrieve"),
        serde_json::json!({ "passphrase": passphrase }),
    )
    .await;
    assert_eq!(again["pin"].as_u64().unwrap() as usize, pin);

    // /api/pin shows the stored PIN.
    let shown: serde_json::Value = post_json(
        &client,
        &format!("{base_url}/api/pin"),
        serde_json::json!({ "passphrase": passphrase }),
    )
    .await;
    assert_eq!(shown["pin"].as_u64().unwrap() as usize, pin);

    // V5 verify: correct PIN passes, wrong PIN fails (§3.7.1).
    let ok: serde_json::Value = post_json(
        &client,
        &format!("{base_url}/api/pin/verify"),
        serde_json::json!({ "passphrase": passphrase, "pin": pin }),
    )
    .await;
    assert_eq!(ok["valid"], true, "correct PIN must verify");

    let wrong_pin = (pin + 1) % 100_000_000;
    let bad: serde_json::Value = post_json(
        &client,
        &format!("{base_url}/api/pin/verify"),
        serde_json::json!({ "passphrase": passphrase, "pin": wrong_pin }),
    )
    .await;
    assert_eq!(bad["valid"], false, "wrong PIN must not verify");

    // Wrong passphrase is a generic 401 (anti-enumeration, §09).
    let unauthorized = client
        .post(format!("{base_url}/api/status"))
        .json(&serde_json::json!({ "passphrase": "wrong-wrong-wrong-wrong-wrong-wrong" }))
        .send()
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), 401);
}

async fn post_json(
    client: &reqwest::Client,
    url: &str,
    body: serde_json::Value,
) -> serde_json::Value {
    let response = client.post(url).json(&body).send().await.expect("request");
    let status = response.status();
    let text = response.text().await.expect("body");
    assert!(
        status.is_success(),
        "POST {url} failed with {status}: {text}"
    );
    serde_json::from_str(&text).expect("json body")
}

fn base_settings() -> Settings {
    let base_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    get_configuration(&base_dir).expect("base settings")
}

#[allow(clippy::too_many_arguments)]
fn cluster_settings(
    ceremony_dir: &std::path::Path,
    name: &str,
    port: u16,
    wbb_port: u16,
    dip_port: u16,
    ns_port: u16,
    er_port: u16,
    rt_ports: &[u16],
    base: &Settings,
) -> Settings {
    Settings {
        service: ServiceSettings {
            name: name.to_string(),
            host: "127.0.0.1".to_string(),
            port,
        },
        tls: TlsSettings {
            cert_pem: ceremony_dir
                .join(format!("{name}.pem"))
                .display()
                .to_string(),
            key_pem: ceremony_dir
                .join(format!("{name}-key.pem"))
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
        peers: {
            let mut peers: Vec<PeerSettings> = rt_ports
                .iter()
                .enumerate()
                .map(|(i, p)| PeerSettings {
                    name: format!("rt-{}", i + 1),
                    base_url: format!("https://127.0.0.1:{p}/"),
                })
                .collect();
            // The enrollment flow never contacts a BB, but the voter server
            // requires BB peers at boot (M6); point them at unused ports.
            for i in 1..=2 {
                peers.push(PeerSettings {
                    name: format!("bb-{i}"),
                    base_url: format!("https://127.0.0.1:{}/", 1024 + i),
                });
            }
            peers
        },
        er: ErClientSettings {
            base_url: format!("https://127.0.0.1:{er_port}/"),
        },
        ns: NsClientSettings {
            base_url: format!("https://127.0.0.1:{ns_port}/"),
        },
        election: base.election.clone(),
        dip: DipSettings {
            base_url: format!("https://127.0.0.1:{dip_port}/"),
            voters: base.dip.voters.clone(),
        },
        voter: VoterSettings::default(),
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

fn signing_key(ceremony_dir: &std::path::Path, name: &str) -> SigningKey {
    let bytes = std::fs::read(ceremony_dir.join(format!("{name}-signing-key.bin")))
        .expect("signing key file");
    let seed: [u8; 32] = bytes.try_into().expect("32-byte signing key seed");
    SigningKey::from_bytes(&seed)
}

fn admin_token(ceremony_dir: &std::path::Path) -> String {
    std::fs::read_to_string(ceremony_dir.join("er-admin-token.txt"))
        .expect("admin token")
        .trim()
        .to_string()
}
