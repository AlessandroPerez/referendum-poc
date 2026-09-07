//! M7 integration test: PIN management & lifecycle (roadmap M7) —
//! ruse PIN (coercion partial), PIN re-send, new-device recovery,
//! revocation + spare-vid re-issue, trusted-authority settings.

use std::path::PathBuf;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rand::SeedableRng;
use referendum_poc::actors::admin::{
    gen_credentials, transition_phase, GenCredentialsConfig, PhaseTransitionConfig,
};
use referendum_poc::actors::common::serve_rustls;
use referendum_poc::actors::{bb, dip, er, ns, rt, voter};
use referendum_poc::configuration::{
    get_configuration, CeremonyPaths, DipSettings, ErClientSettings, NsClientSettings,
    PeerSettings, ServiceSettings, Settings, TlsSettings, VoterSettings, WbbSettings,
    WbbUiSettings,
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

struct ClusterPorts {
    wbb: u16,
    dip: u16,
    ns: u16,
    er: u16,
    rt: Vec<u16>,
    bb: Vec<u16>,
}

#[tokio::test]
async fn pin_lifecycle_ruse_resend_recover_revoke_trusted() {
    helpers::init();
    let _cluster = helpers::cluster_guard().await;

    // ── 1. Ceremony + WBB (entities incl. ER for revocation entries) ──────
    let temp = tempfile::tempdir().expect("tempdir");
    let ceremony_dir = temp.path();
    let base = base_settings();
    let master_seed = MasterSeed::new(MASTER_SEED);
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(MASTER_SEED);
    let ceremony = run_ceremony(&base.election, &mut rng).unwrap();
    write_artifacts(ceremony_dir, &base, &ceremony, &master_seed, &base.dip)
        .expect("write ceremony artifacts");

    let ca = ClusterCa::from_seed(&MASTER_SEED).unwrap();
    let wbb_cert = issue_service_cert(&ca, "wbb", &MASTER_SEED).unwrap();
    let ports = ClusterPorts {
        wbb: helpers::free_port(),
        dip: helpers::free_port(),
        ns: helpers::free_port(),
        er: helpers::free_port(),
        rt: (0..3).map(|_| helpers::free_port()).collect(),
        bb: (0..2).map(|_| helpers::free_port()).collect(),
    };

    let pm_key = signing_key(ceremony_dir, "pm");
    let mut wbb_config = helpers::WbbSpawnConfig::new(ports.wbb)
        .with_entity("PM-1", pm_key.verifying_key())
        .with_entity("ER-1", signing_key(ceremony_dir, "er").verifying_key())
        .with_phase_manager(pm_key.verifying_key());
    for i in 1..=3 {
        let key = signing_key(ceremony_dir, &format!("rt-{i}"));
        wbb_config = wbb_config.with_entity(&format!("RT-{i}"), key.verifying_key());
    }
    for i in 1..=2 {
        let key = signing_key(ceremony_dir, &format!("bb-{i}"));
        wbb_config = wbb_config.with_entity(&format!("BB-{i}"), key.verifying_key());
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

    // ── 2. Credentials + cluster boot ─────────────────────────────────────
    let wbb_url = Url::parse(&format!("https://127.0.0.1:{}/wbb/", ports.wbb)).unwrap();
    gen_credentials(GenCredentialsConfig {
        ceremony_dir: ceremony_dir.to_path_buf(),
        output_dir: ceremony_dir.join("output"),
        n_acc: base.election.n_acc,
        t_rt: base.election.t_rt,
        t_prime: base.election.t_prime,
        wbb_url: wbb_url.clone(),
        rt_urls: None,
        rt_tokens: None,
        ca_pem: ca.cert_pem().to_string(),
        clock: LogicalClock::new(base.clock.base_ms, base.clock.tick_ms),
    })
    .await
    .expect("gen credentials");

    let mk = |name: &str, port: u16| cluster_settings(ceremony_dir, name, port, &ports, &base);

    tokio::spawn(dip::run(
        mk("dip", ports.dip),
        signing_key(ceremony_dir, "dip"),
    ));
    tokio::spawn(ns::run(mk("ns", ports.ns), signing_key(ceremony_dir, "ns")));

    let (er_addr, er_tls, er_state) = er::build_service(
        mk("er", ports.er),
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

    for (i, port) in ports.rt.iter().enumerate() {
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
    for (i, port) in ports.bb.iter().enumerate() {
        let name = format!("bb-{}", i + 1);
        let (addr, tls, state) =
            bb::build_service(mk(&name, *port), signing_key(ceremony_dir, &name))
                .await
                .expect("build bb");
        tokio::spawn(async move {
            serve_rustls(bb::router(state), addr, tls)
                .await
                .expect("bb server")
        });
    }

    // voter-1 and voter-2 are the primary devices; voter-3 acts as the
    // fresh "new device" for the V8 recovery flow.
    let mut voter_urls = Vec::new();
    for i in 1..=3u64 {
        let port = helpers::free_port();
        let mut settings = mk(&format!("voter-{i}"), port);
        settings.voter.state_dir = ceremony_dir
            .join(format!("voter-state-{i}"))
            .display()
            .to_string();
        settings.voter.static_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("static")
            .display()
            .to_string();
        let (addr, tls, state) = voter::build_service(settings).await.expect("build voter");
        tokio::spawn(async move {
            serve_rustls(voter::router(state), addr, tls)
                .await
                .expect("voter server")
        });
        voter_urls.push(format!("https://127.0.0.1:{port}"));
    }

    tokio::time::sleep(Duration::from_millis(300)).await;
    let client = reqwest_client_trusting_ca(ca.cert_pem()).unwrap();

    // ── 3. Enroll voters 1 and 2 (M5 flow, setup phase) ───────────────────
    let v1 = voter_urls[0].clone();
    let v2 = voter_urls[1].clone();
    let v3 = voter_urls[2].clone();
    let p1 = enroll_voter(&client, &v1, "VOTER-001").await;
    let p2 = enroll_voter(&client, &v2, "VOTER-002").await;
    let pin1 = pin_of(&client, &v1, &p1).await;
    let pin2 = pin_of(&client, &v2, &p2).await;

    // ── 4. V7 ruse PIN: verifies locally, distinct from the real PIN ──────
    let ruse: serde_json::Value = post_json(
        &client,
        &format!("{v1}/api/pin/ruse"),
        serde_json::json!({ "passphrase": p1 }),
    )
    .await;
    let ruse_pin = ruse["ruse_pin"].as_u64().expect("ruse pin");
    assert_ne!(ruse_pin, pin1, "ruse PIN must differ from the real PIN");

    for (pin, expected) in [
        (ruse_pin, true),
        (pin1, true),
        ((pin1 + 7) % 100_000_000, false),
    ] {
        let verify: serde_json::Value = post_json(
            &client,
            &format!("{v1}/api/pin/verify"),
            serde_json::json!({ "passphrase": p1, "pin": pin }),
        )
        .await;
        assert_eq!(verify["valid"], expected, "verify_pin({pin})");
    }

    // ── 5. Open voting; coercion partial: cast ruse then real ballot ──────
    transition_phase(
        PhaseTransitionConfig {
            ceremony_dir: ceremony_dir.to_path_buf(),
            wbb_url: wbb_url.clone(),
            ca_pem: ca.cert_pem().to_string(),
            clock: LogicalClock::new(base.clock.base_ms, base.clock.tick_ms),
        },
        "setup",
        "voting",
    )
    .await
    .expect("open voting");

    let ruse_vote: serde_json::Value = post_json(
        &client,
        &format!("{v1}/api/vote"),
        serde_json::json!({ "passphrase": p1, "option": "reject", "pin": ruse_pin }),
    )
    .await;
    let ruse_cast: serde_json::Value = post_json(
        &client,
        &format!("{v1}/api/cast"),
        serde_json::json!({ "passphrase": p1 }),
    )
    .await;
    assert_eq!(
        ruse_cast["receipts"].as_array().unwrap().len(),
        2,
        "the decoy ballot is indistinguishable at cast time (BBs accept it)"
    );

    let real_vote: serde_json::Value = post_json(
        &client,
        &format!("{v1}/api/vote"),
        serde_json::json!({ "passphrase": p1, "option": "approve", "pin": pin1 }),
    )
    .await;
    assert_ne!(ruse_vote["digest"], real_vote["digest"]);
    post_json(
        &client,
        &format!("{v1}/api/cast"),
        serde_json::json!({ "passphrase": p1 }),
    )
    .await;
    // Tally-side filtering of the ruse ballot is asserted in M8.

    // ── 6. V6 PIN re-send: fresh rid + retrieval, same PIN ────────────────
    let resend: serde_json::Value = post_json(
        &client,
        &format!("{v1}/api/pin/resend"),
        serde_json::json!({ "passphrase": p1 }),
    )
    .await;
    assert_eq!(
        resend["pin"].as_u64().unwrap(),
        pin1,
        "re-delivered PIN equals the original (§3.7.2)"
    );

    // ── 7. V8 new-device recovery on the fresh voter-3 server ─────────────
    let wrong = client
        .post(format!("{v3}/api/device/recover"))
        .json(&serde_json::json!({
            "fiscal_id": "VOTER-001",
            "passphrase": "wrong-wrong-wrong-wrong-wrong-wrong"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(wrong.status(), 401, "wrong passphrase must fail closed");

    let recovered: serde_json::Value = post_json(
        &client,
        &format!("{v3}/api/device/recover"),
        serde_json::json!({ "fiscal_id": "VOTER-001", "passphrase": p1 }),
    )
    .await;
    assert_eq!(recovered["vid"], 1);
    assert_eq!(recovered["pin_set"], true);
    // The blob was refreshed while a ruse was active, so the recovered
    // device DISPLAYS the ruse PIN (§3.7.3 cover story survives recovery) …
    assert_eq!(
        pin_of(&client, &v3, &p1).await,
        ruse_pin,
        "PIN display shows the active ruse PIN after recovery"
    );
    // … while the REAL credential is fully restored (§3.7.4).
    let verify: serde_json::Value = post_json(
        &client,
        &format!("{v3}/api/pin/verify"),
        serde_json::json!({ "passphrase": p1, "pin": pin1 }),
    )
    .await;
    assert_eq!(
        verify["valid"], true,
        "recovery restores the real credential on the new device"
    );

    // ── 8. V9 revocation: spare vid, WBB commitment, new PIN ──────────────
    let revoked: serde_json::Value = post_json(
        &client,
        &format!("{v2}/api/revoke"),
        serde_json::json!({ "passphrase": p2 }),
    )
    .await;
    let new_vid = revoked["vid"].as_u64().unwrap();
    assert_eq!(new_vid, 9, "first spare vid is n_voters + 1 (D12)");

    // The eligible list swaps old vid 2 for spare vid 9 (A7).
    let eligible: serde_json::Value = get_json(
        &client,
        &format!("https://127.0.0.1:{}/voters/eligible", ports.er),
    )
    .await;
    let vids: Vec<u64> = serde_json::from_value(eligible["vids"].clone()).unwrap();
    assert!(!vids.contains(&2), "revoked vid must not be eligible");
    assert!(vids.contains(&9), "spare vid must be eligible");
    assert_eq!(vids.len(), 8, "electorate size is unchanged");

    // Exactly one revocation_commitment entry on the WBB.
    let commitments = count_entries_of_type(&wbb.client, "revocation_commitment").await;
    assert_eq!(commitments, 1, "revocation commitment published (§3.7.5)");

    // The re-issued credential delivers a fresh PIN.
    wait_pin_ready(&client, &v2, &p2).await;
    let new_pin: serde_json::Value = post_json(
        &client,
        &format!("{v2}/api/pin/retrieve"),
        serde_json::json!({ "passphrase": p2 }),
    )
    .await;
    let new_pin = new_pin["pin"].as_u64().unwrap();
    assert_ne!(new_pin, pin2, "spare credential has a different PIN");
    let verify: serde_json::Value = post_json(
        &client,
        &format!("{v2}/api/pin/verify"),
        serde_json::json!({ "passphrase": p2, "pin": new_pin }),
    )
    .await;
    assert_eq!(verify["valid"], true);

    // ── 9. V10 trusted-authority settings ─────────────────────────────────
    for invalid in [
        serde_json::json!({ "passphrase": p1, "rts": ["rt-1"], "bbs": ["bb-1", "bb-2"] }),
        serde_json::json!({ "passphrase": p1, "rts": ["rt-1", "rt-2"], "bbs": ["bb-1"] }),
        serde_json::json!({ "passphrase": p1, "rts": ["rt-1", "rt-9"], "bbs": ["bb-1", "bb-2"] }),
    ] {
        let response = client
            .post(format!("{v1}/api/settings/trusted"))
            .json(&invalid)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 400, "invalid selection must be rejected");
    }

    let trusted: serde_json::Value = post_json(
        &client,
        &format!("{v1}/api/settings/trusted"),
        serde_json::json!({ "passphrase": p1, "rts": ["rt-1", "rt-3"], "bbs": ["bb-1", "bb-2"] }),
    )
    .await;
    assert_eq!(trusted["rts"], serde_json::json!(["rt-1", "rt-3"]));

    let shown: serde_json::Value = post_json(
        &client,
        &format!("{v1}/api/settings/trusted/show"),
        serde_json::json!({ "passphrase": p1 }),
    )
    .await;
    assert_eq!(shown["rts"], serde_json::json!(["rt-1", "rt-3"]));

    // The restricted teller set (t_RT of n_RT) still re-delivers the PIN.
    let resend2: serde_json::Value = post_json(
        &client,
        &format!("{v1}/api/pin/resend"),
        serde_json::json!({ "passphrase": p1 }),
    )
    .await;
    assert_eq!(
        resend2["pin"].as_u64().unwrap(),
        pin1,
        "re-send works with the trusted t_RT subset"
    );
}

// ── Helpers ────────────────────────────────────────────────────────────────

async fn count_entries_of_type(
    wbb_client: &referendum_poc::clients::wbb::WbbClient,
    entry_type: &str,
) -> usize {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    let entries = wbb_client.entries().await.expect("wbb entries");
    entries
        .entries
        .iter()
        .filter(|e| {
            e.entry
                .get("data")
                .and_then(|v| v.as_str())
                .and_then(|s| B64.decode(s).ok())
                .and_then(|d| referendum_poc::protocol::voting::parse_wbb_data(&d))
                .map(|p| p.entry_type == entry_type)
                .unwrap_or(false)
        })
        .count()
}

async fn wait_pin_ready(client: &reqwest::Client, base_url: &str, passphrase: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let status: serde_json::Value = post_json(
            client,
            &format!("{base_url}/api/status"),
            serde_json::json!({ "passphrase": passphrase }),
        )
        .await;
        if status["pin_ready"] == true {
            return;
        }
        assert!(tokio::time::Instant::now() < deadline, "PIN never ready");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn enroll_voter(client: &reqwest::Client, base_url: &str, fiscal_id: &str) -> String {
    let login: serde_json::Value = post_json(
        client,
        &format!("{base_url}/api/login"),
        serde_json::json!({ "fiscal_id": fiscal_id }),
    )
    .await;
    assert!(login["vid"].as_u64().unwrap() > 0);
    let enroll: serde_json::Value = post_json(
        client,
        &format!("{base_url}/api/enroll"),
        serde_json::json!({ "fiscal_id": fiscal_id }),
    )
    .await;
    let passphrase = enroll["passphrase"].as_str().unwrap().to_string();
    wait_pin_ready(client, base_url, &passphrase).await;
    let _pin: serde_json::Value = post_json(
        client,
        &format!("{base_url}/api/pin/retrieve"),
        serde_json::json!({ "passphrase": passphrase }),
    )
    .await;
    passphrase
}

async fn pin_of(client: &reqwest::Client, base_url: &str, passphrase: &str) -> u64 {
    let shown: serde_json::Value = post_json(
        client,
        &format!("{base_url}/api/pin"),
        serde_json::json!({ "passphrase": passphrase }),
    )
    .await;
    shown["pin"].as_u64().expect("pin")
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

async fn get_json(client: &reqwest::Client, url: &str) -> serde_json::Value {
    let response = client.get(url).send().await.expect("request");
    let status = response.status();
    let text = response.text().await.expect("body");
    assert!(
        status.is_success(),
        "GET {url} failed with {status}: {text}"
    );
    serde_json::from_str(&text).expect("json body")
}

fn base_settings() -> Settings {
    let base_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    get_configuration(&base_dir).expect("base settings")
}

fn cluster_settings(
    ceremony_dir: &std::path::Path,
    name: &str,
    port: u16,
    ports: &ClusterPorts,
    base: &Settings,
) -> Settings {
    let mut peers: Vec<PeerSettings> = ports
        .rt
        .iter()
        .enumerate()
        .map(|(i, p)| PeerSettings {
            name: format!("rt-{}", i + 1),
            base_url: format!("https://127.0.0.1:{p}/"),
        })
        .collect();
    peers.extend(ports.bb.iter().enumerate().map(|(i, p)| PeerSettings {
        name: format!("bb-{}", i + 1),
        base_url: format!("https://127.0.0.1:{p}/"),
    }));

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
            base_url: format!("https://127.0.0.1:{}/wbb/", ports.wbb),
            request_timeout_ms: 10000,
        },
        peers,
        er: ErClientSettings {
            base_url: format!("https://127.0.0.1:{}/", ports.er),
        },
        ns: NsClientSettings {
            base_url: format!("https://127.0.0.1:{}/", ports.ns),
        },
        election: base.election.clone(),
        dip: DipSettings {
            base_url: format!("https://127.0.0.1:{}/", ports.dip),
            voters: base.dip.voters.clone(),
        },
        voter: VoterSettings::default(),
        wbb_ui: WbbUiSettings::default(),
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
