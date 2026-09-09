//! M8 integration test: full election → §3.9 tally over HTTP → expected
//! counts → §3.10 auditor OK (roadmap M8.4).
//!
//! Covers the deferred M6/M7 tally assertions: the ruse-PIN and wrong-PIN
//! ballots are accepted by the BBs (indistinguishable at cast time) but
//! filtered by the ACC check, and a re-vote resolves last-wins via the ox
//! fingerprint dedup.

use std::path::PathBuf;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rand::SeedableRng;
use referendum_poc::actors::admin::{
    gen_credentials, run_tally, transition_phase, GenCredentialsConfig, PhaseTransitionConfig,
    TallyConfig,
};
use referendum_poc::actors::auditor::{run_audit, AuditConfig};
use referendum_poc::actors::common::serve_rustls;
use referendum_poc::actors::{bb, dip, er, ns, rt, tt, voter};
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
    tt: Vec<u16>,
}

#[tokio::test]
async fn full_election_tally_and_audit() {
    helpers::init();
    let _cluster = helpers::cluster_guard().await;

    // ── 1. Ceremony + WBB (all entities + the phase manager) ──────────────
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
        tt: (0..3).map(|_| helpers::free_port()).collect(),
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
    for i in 1..=3 {
        let key = signing_key(ceremony_dir, &format!("tt-{i}"));
        wbb_config = wbb_config.with_entity(&format!("TT-{i}"), key.verifying_key());
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

    // ── 2. Credentials (setup phase) ──────────────────────────────────────
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

    // ── 3. Boot the cluster (incl. the TT servers, first time in e2e) ─────
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

    for (i, port) in ports.tt.iter().enumerate() {
        let name = format!("tt-{}", i + 1);
        let (addr, tls, state) =
            tt::build_service(mk(&name, *port), signing_key(ceremony_dir, &name))
                .await
                .expect("build tt");
        tokio::spawn(async move {
            serve_rustls(tt::router(state), addr, tls)
                .await
                .expect("tt server")
        });
    }

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

    // ER publishes the setup entries (A2) — the auditor reads the election
    // context and n_acc from the log itself.
    let setup = client
        .post(format!("https://127.0.0.1:{}/admin/setup", ports.er))
        .header(
            "Authorization",
            format!("Bearer {}", admin_token(ceremony_dir)),
        )
        .send()
        .await
        .expect("admin setup");
    assert!(setup.status().is_success(), "ER setup publication");

    // ── 4. Enroll the three voters, open voting ───────────────────────────
    let mut passphrases = Vec::new();
    for (i, base_url) in voter_urls.iter().enumerate() {
        passphrases.push(enroll_voter(&client, base_url, &format!("VOTER-00{}", i + 1)).await);
    }
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

    // ── 5. Cast: v1 approve · v2 reject → blank (re-vote, last wins) ──────
    let (v1, p1) = (&voter_urls[0], &passphrases[0]);
    let pin1 = pin_of(&client, v1, p1).await;
    vote_and_cast(&client, v1, p1, "approve", pin1).await;

    let (v2, p2) = (&voter_urls[1], &passphrases[1]);
    let pin2 = pin_of(&client, v2, p2).await;
    vote_and_cast(&client, v2, p2, "reject", pin2).await;
    vote_and_cast(&client, v2, p2, "blank", pin2).await;

    // ── 6. v3: ruse-PIN and wrong-PIN ballots (accepted at cast, filtered
    //          at tally), then the real approve ────────────────────────────
    let (v3, p3) = (&voter_urls[2], &passphrases[2]);
    let pin3 = pin_of(&client, v3, p3).await;
    let ruse: serde_json::Value = post_json(
        &client,
        &format!("{v3}/api/pin/ruse"),
        serde_json::json!({ "passphrase": p3 }),
    )
    .await;
    let ruse_pin = ruse["ruse_pin"].as_u64().expect("ruse pin");
    assert_ne!(ruse_pin, pin3);
    vote_and_cast(&client, v3, p3, "reject", ruse_pin).await;

    let wrong_pin = {
        let mut candidate = (pin3 + 1) % 100_000_000;
        if candidate == ruse_pin {
            candidate = (candidate + 1) % 100_000_000;
        }
        candidate
    };
    vote_and_cast(&client, v3, p3, "reject", wrong_pin).await;
    vote_and_cast(&client, v3, p3, "approve", pin3).await;

    // ── 7. Close voting, run the §3.9 tally driver over HTTP ──────────────
    transition_phase(
        PhaseTransitionConfig {
            ceremony_dir: ceremony_dir.to_path_buf(),
            wbb_url: wbb_url.clone(),
            ca_pem: ca.cert_pem().to_string(),
            clock: LogicalClock::new(base.clock.base_ms, base.clock.tick_ms),
        },
        "voting",
        "tallying",
    )
    .await
    .expect("close voting");

    let outcome = run_tally(TallyConfig {
        ceremony_dir: ceremony_dir.to_path_buf(),
        wbb_url: wbb_url.clone(),
        er_url: Url::parse(&format!("https://127.0.0.1:{}/", ports.er)).unwrap(),
        bb_urls: ports
            .bb
            .iter()
            .map(|p| Url::parse(&format!("https://127.0.0.1:{p}/")).unwrap())
            .collect(),
        rt_urls: ports
            .rt
            .iter()
            .map(|p| Url::parse(&format!("https://127.0.0.1:{p}/")).unwrap())
            .collect(),
        tt_urls: ports
            .tt
            .iter()
            .map(|p| Url::parse(&format!("https://127.0.0.1:{p}/")).unwrap())
            .collect(),
        ca_pem: ca.cert_pem().to_string(),
        clock: LogicalClock::new(base.clock.base_ms, base.clock.tick_ms),
        n_acc: base.election.n_acc,
        t_tt: base.election.t_tt,
    })
    .await
    .expect("tally pipeline");

    // 6 cast ballots on both BBs; the re-vote merges in the ox dedup; the
    // ruse-PIN and wrong-PIN ballots die at the ACC check.
    assert_eq!(outcome.released, 12, "6 ballots × 2 BBs released");
    assert_eq!(outcome.reconciled, 6, "all ballots on ≥2 BBs (no ⊥)");
    assert_eq!(outcome.deduped, 5, "v2's re-vote merges (last wins)");
    assert_eq!(outcome.valid, 3, "ruse + wrong-PIN filtered by ACC check");
    assert_eq!(outcome.legitimate, 3, "all valid votes are eligible");
    assert_eq!(
        (outcome.counts.blank, outcome.counts.si, outcome.counts.no),
        (1, 2, 0),
        "blank=1 (v2 last vote), si=2 (v1 + v3 real), no=0"
    );

    // ── 8. All tally entries on the WBB (§4.4) ────────────────────────────
    let entries = wbb.client.entries().await.expect("wbb entries");
    let type_count = |wanted: &str| -> usize {
        use base64::Engine as _;
        entries
            .entries
            .iter()
            .filter_map(|e| e.entry.get("data").and_then(|v| v.as_str()))
            .filter_map(|b64| base64::engine::general_purpose::STANDARD.decode(b64).ok())
            .filter_map(|data| referendum_poc::protocol::voting::parse_wbb_data(&data))
            .filter(|p| p.entry_type == wanted)
            .count()
    };
    assert_eq!(type_count("eligible_vids"), 1);
    assert_eq!(
        type_count("cast_intended_proof"),
        12,
        "6 confirmations × 2 BBs"
    );
    assert_eq!(type_count("encrypted_ballot"), 12, "per-BB release");
    assert_eq!(type_count("mixed_ballots"), 2, "vote + credential mixes");
    assert_eq!(
        type_count("re_encryption_proof"),
        4,
        "ox, controls, acc_checks, credential fingerprints"
    );
    assert_eq!(type_count("tally_proof"), 1);
    assert_eq!(type_count("tally_result"), 1);

    // ── 9. §3.10 universal verification: every audit step passes ──────────
    let mut entity_keys = vec![
        ("PM-1".to_string(), pm_key.verifying_key()),
        (
            "ER-1".to_string(),
            signing_key(ceremony_dir, "er").verifying_key(),
        ),
    ];
    for i in 1..=3 {
        entity_keys.push((
            format!("RT-{i}"),
            signing_key(ceremony_dir, &format!("rt-{i}")).verifying_key(),
        ));
        entity_keys.push((
            format!("TT-{i}"),
            signing_key(ceremony_dir, &format!("tt-{i}")).verifying_key(),
        ));
    }
    for i in 1..=2 {
        entity_keys.push((
            format!("BB-{i}"),
            signing_key(ceremony_dir, &format!("bb-{i}")).verifying_key(),
        ));
    }
    let report = run_audit(AuditConfig {
        wbb_url,
        ca_pem: ca.cert_pem().to_string(),
        entity_keys,
        n_tt: base.election.n_tt,
        t_tt: base.election.t_tt,
    })
    .await
    .expect("audit run");
    assert!(report.ok(), "auditor found failures:\n{}", report.render());
    assert!(
        report.steps.len() >= 12,
        "audit must cover the whole pipeline, got:\n{}",
        report.render()
    );
}

// ── Helpers ────────────────────────────────────────────────────────────────

/// Vote (any PIN — ruse and wrong PINs included) and cast to both BBs.
async fn vote_and_cast(
    client: &reqwest::Client,
    base_url: &str,
    passphrase: &str,
    option: &str,
    pin: u64,
) {
    let vote: serde_json::Value = post_json(
        client,
        &format!("{base_url}/api/vote"),
        serde_json::json!({ "passphrase": passphrase, "option": option, "pin": pin }),
    )
    .await;
    assert!(!vote["emoji"].as_array().unwrap().is_empty());
    let cast: serde_json::Value = post_json(
        client,
        &format!("{base_url}/api/cast"),
        serde_json::json!({ "passphrase": passphrase }),
    )
    .await;
    assert_eq!(
        cast["receipts"].as_array().unwrap().len(),
        2,
        "both BBs accept the ballot"
    );
    // §3.8.4 steps 8–17: confirm the cast-as-intended disclosure — only
    // confirmed ballots are released at tally (§3.9 step 2).
    let confirm: serde_json::Value = post_json(
        client,
        &format!("{base_url}/api/confirm"),
        serde_json::json!({ "passphrase": passphrase }),
    )
    .await;
    assert!(confirm["confirmed_at_ms"].as_u64().unwrap() > 0);
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

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let status: serde_json::Value = post_json(
            client,
            &format!("{base_url}/api/status"),
            serde_json::json!({ "passphrase": passphrase }),
        )
        .await;
        if status["pin_ready"] == true {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "PIN never ready");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
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
    peers.extend(ports.tt.iter().enumerate().map(|(i, p)| PeerSettings {
        name: format!("tt-{}", i + 1),
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
