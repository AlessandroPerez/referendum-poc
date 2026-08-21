//! M6 integration tests: CAT casting + BB intake + CAI + wbb-ui (roadmap M6.5)
//! and WBB write-policy enforcement (§3.4.2).

use std::path::PathBuf;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rand::SeedableRng;
use referendum_poc::actors::admin::{
    gen_credentials, transition_phase, GenCredentialsConfig, PhaseTransitionConfig,
};
use referendum_poc::actors::common::serve_rustls;
use referendum_poc::actors::{bb, dip, er, ns, rt, voter, wbb_ui};
use referendum_poc::clients::wbb::{sign_entry, WbbError};
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
    wbb_ui: u16,
}

#[tokio::test]
async fn three_voters_cast_with_cat_and_cai() {
    helpers::init();

    // ── 1. Ceremony + WBB (entities incl. BBs and the phase manager) ──────
    let temp = tempfile::tempdir().expect("tempdir");
    let ceremony_dir = temp.path();
    let mut base = base_settings();
    // Tight CAT rate limit so the negative is reachable in-test.
    base.election.max_casts_per_voter = 3;

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
        wbb_ui: helpers::free_port(),
    };

    let pm_key = signing_key(ceremony_dir, "pm");
    let mut wbb_config = helpers::WbbSpawnConfig::new(ports.wbb)
        .with_entity("PM-1", pm_key.verifying_key())
        .with_phase_manager(pm_key.verifying_key());
    for i in 1..=3 {
        let key = signing_key(ceremony_dir, &format!("rt-{i}"));
        wbb_config = wbb_config.with_entity(&format!("RT-{i}"), key.verifying_key());
    }
    for i in 1..=2 {
        let key = signing_key(ceremony_dir, &format!("bb-{i}"));
        wbb_config = wbb_config.with_entity(&format!("BB-{i}"), key.verifying_key());
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

    // ── 3. Boot the cluster ───────────────────────────────────────────────
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

    let mut ui_settings = mk("wbb-ui", ports.wbb_ui);
    ui_settings.wbb_ui.static_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("static-wbb")
        .display()
        .to_string();
    let (ui_addr, ui_tls, ui_state) = wbb_ui::build_service(ui_settings)
        .await
        .expect("build wbb-ui");
    tokio::spawn(async move {
        serve_rustls(wbb_ui::router(ui_state), ui_addr, ui_tls)
            .await
            .expect("wbb-ui server")
    });

    tokio::time::sleep(Duration::from_millis(300)).await;
    let client = reqwest_client_trusting_ca(ca.cert_pem()).unwrap();

    // ── 4. Enroll the three voters (M5 flow) ──────────────────────────────
    let mut passphrases = Vec::new();
    for (i, base_url) in voter_urls.iter().enumerate() {
        passphrases.push(enroll_voter(&client, base_url, &format!("VOTER-00{}", i + 1)).await);
    }

    // ── 5. Open the voting phase (A4) ─────────────────────────────────────
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

    let ui_base = format!("https://127.0.0.1:{}", ports.wbb_ui);
    let phase: serde_json::Value = get_json(&client, &format!("{ui_base}/api/phase")).await;
    assert_eq!(phase["phase"], "voting");

    // ── 6. Voter 1: vote → cast → publication check → CAI confirm ─────────
    let v1 = &voter_urls[0];
    let p1 = &passphrases[0];
    let vote1: serde_json::Value = post_json(
        &client,
        &format!("{v1}/api/vote"),
        serde_json::json!({ "passphrase": p1, "option": "approve", "pin": pin_of(&client, v1, p1).await }),
    )
    .await;
    let digest1 = vote1["digest"].as_str().unwrap().to_string();
    assert!(!vote1["emoji"].as_array().unwrap().is_empty());

    let cast1: serde_json::Value = post_json(
        &client,
        &format!("{v1}/api/cast"),
        serde_json::json!({ "passphrase": p1 }),
    )
    .await;
    assert_eq!(cast1["receipts"].as_array().unwrap().len(), 2, "both BBs");

    let status1: serde_json::Value = post_json(
        &client,
        &format!("{v1}/api/ballot/status"),
        serde_json::json!({ "passphrase": p1 }),
    )
    .await;
    assert_eq!(status1["no_bot"], true, "digest published by ≥2 BBs (no ⊥)");
    assert_eq!(status1["published_bb_ids"], serde_json::json!([1, 2]));

    let confirm1: serde_json::Value = post_json(
        &client,
        &format!("{v1}/api/confirm"),
        serde_json::json!({ "passphrase": p1 }),
    )
    .await;
    assert!(confirm1["confirmed_at_ms"].as_u64().unwrap() > 0);

    // ── 7. Voter 2: cast, then re-vote (last-wins resolved at tally) ──────
    let v2 = &voter_urls[1];
    let p2 = &passphrases[1];
    let pin2 = pin_of(&client, v2, p2).await;
    let vote2a: serde_json::Value = post_json(
        &client,
        &format!("{v2}/api/vote"),
        serde_json::json!({ "passphrase": p2, "option": "reject", "pin": pin2 }),
    )
    .await;
    post_json(
        &client,
        &format!("{v2}/api/cast"),
        serde_json::json!({ "passphrase": p2 }),
    )
    .await;
    let vote2b: serde_json::Value = post_json(
        &client,
        &format!("{v2}/api/vote"),
        serde_json::json!({ "passphrase": p2, "option": "blank", "pin": pin2 }),
    )
    .await;
    assert_ne!(
        vote2a["digest"], vote2b["digest"],
        "re-vote is a new ballot"
    );
    let cast2b: serde_json::Value = post_json(
        &client,
        &format!("{v2}/api/cast"),
        serde_json::json!({ "passphrase": p2 }),
    )
    .await;

    // Idempotent casting (§12): re-casting the same held ballot replays the
    // stored receipts (a fresh CAT issuance, same BB state).
    let recast: serde_json::Value = post_json(
        &client,
        &format!("{v2}/api/cast"),
        serde_json::json!({ "passphrase": p2 }),
    )
    .await;
    assert_eq!(recast["receipts"], cast2b["receipts"], "idempotent replay");

    // CAT rate limit is over DISTINCT commitments: the idempotent re-cast
    // above did not burn budget, so a 3rd distinct ballot still passes and
    // the 4th is rejected (max_casts_per_voter = 3).
    post_json(
        &client,
        &format!("{v2}/api/vote"),
        serde_json::json!({ "passphrase": p2, "option": "approve", "pin": pin2 }),
    )
    .await;
    post_json(
        &client,
        &format!("{v2}/api/cast"),
        serde_json::json!({ "passphrase": p2 }),
    )
    .await;
    post_json(
        &client,
        &format!("{v2}/api/vote"),
        serde_json::json!({ "passphrase": p2, "option": "reject", "pin": pin2 }),
    )
    .await;
    let limited = client
        .post(format!("{v2}/api/cast"))
        .json(&serde_json::json!({ "passphrase": p2 }))
        .send()
        .await
        .unwrap();
    assert!(
        !limited.status().is_success(),
        "4th distinct ballot commitment must be rate-limited"
    );

    // ── 8. Voter 3: cast-before-vote is rejected, then a real cast ────────
    let v3 = &voter_urls[2];
    let p3 = &passphrases[2];
    let no_ballot = client
        .post(format!("{v3}/api/cast"))
        .json(&serde_json::json!({ "passphrase": p3 }))
        .send()
        .await
        .unwrap();
    assert_eq!(no_ballot.status(), 400, "cast before vote must fail");

    let pin3 = pin_of(&client, v3, p3).await;
    post_json(
        &client,
        &format!("{v3}/api/vote"),
        serde_json::json!({ "passphrase": p3, "option": "approve", "pin": pin3 }),
    )
    .await;
    let cast3: serde_json::Value = post_json(
        &client,
        &format!("{v3}/api/cast"),
        serde_json::json!({ "passphrase": p3 }),
    )
    .await;
    assert_eq!(cast3["receipts"].as_array().unwrap().len(), 2);

    // ── 9. wbb-ui: page + decoded entries (V14) ───────────────────────────
    let page = client
        .get(format!("{ui_base}/"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(page.contains("Public Bulletin Board"));

    let rows: serde_json::Value = get_json(&client, &format!("{ui_base}/api/entries")).await;
    let rows = rows.as_array().unwrap();
    let digest_rows: Vec<_> = rows
        .iter()
        .filter(|r| r["entry_type"] == "ballot_digest")
        .collect();
    // 5 cast ballots (voter1 ×1, voter2 ×3 incl. re-votes, voter3 ×1) ×2 BBs.
    assert_eq!(digest_rows.len(), 10, "expected 10 ballot_digest entries");
    assert!(
        digest_rows
            .iter()
            .any(|r| r["payload"]["digest"] == serde_json::json!(digest1)),
        "voter 1 digest must be on the WBB"
    );
    let cai_rows: Vec<_> = rows
        .iter()
        .filter(|r| r["entry_type"] == "cast_intended_proof")
        .collect();
    assert_eq!(cai_rows.len(), 2, "CAI proof published by both BBs");
    let metadata_rows = rows
        .iter()
        .filter(|r| r["entry_type"] == "ballot_metadata")
        .count();
    assert_eq!(metadata_rows, 10, "one metadata entry per digest entry");

    // ── 10. Negative: a CAI disclosure for the WRONG ballot is rejected ───
    // Scrape voter 1's published disclosure from the WBB and replay it
    // against voter 2's (different) ballot digest at BB-1.
    let disclosure = cai_rows[0]["payload"]["disclosure"].clone();
    let wrong_digest = vote2b["digest"].as_str().unwrap();
    let mismatched = client
        .post(format!("https://127.0.0.1:{}/cai", ports.bb[0]))
        .json(&serde_json::json!({ "digest": wrong_digest, "disclosure": disclosure }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        mismatched.status(),
        400,
        "disclosure for a different ballot must be rejected"
    );
}

#[tokio::test]
async fn wbb_policy_enforcement() {
    helpers::init();

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
    let port = helpers::free_port();
    let pm_key = signing_key(ceremony_dir, "pm");
    let bb1_key = signing_key(ceremony_dir, "bb-1");
    let tt1_key = signing_key(ceremony_dir, "tt-1");
    let config = helpers::WbbSpawnConfig::new(port)
        .with_entity("PM-1", pm_key.verifying_key())
        .with_entity("BB-1", bb1_key.verifying_key())
        .with_entity("TT-1", tt1_key.verifying_key())
        .with_phase_manager(pm_key.verifying_key());
    let wbb = helpers::WbbProcess::spawn(
        ceremony_dir,
        &ca,
        wbb_cert.cert_pem(),
        wbb_cert.key_pem(),
        config,
    )
    .await
    .expect("spawn wbb");

    let ts = 1_700_000_000_000i64;
    let submit = |data: String, key: SigningKey, entity: &'static str, ts: i64| {
        let client = wbb.client.clone();
        async move {
            let entry = sign_entry(data.as_bytes(), entity, ts, &key);
            client.submit(&entry).await
        }
    };
    let assert_403 = |result: Result<serde_json::Value, WbbError>, what: &str| match result {
        Err(WbbError::Http(status, _)) => {
            assert_eq!(status.as_u16(), 403, "{what}: expected 403, got {status}")
        }
        other => panic!("{what}: expected HTTP 403 rejection, got {other:?}"),
    };

    // (a) Entry type not allowed in its phase: ballot_digest during setup.
    assert_403(
        submit(
            "setup,BB,ballot_digest,1,x".into(),
            bb1_key.clone(),
            "BB-1",
            ts,
        )
        .await,
        "wrong-phase entry type",
    );

    // (b) Correct policy row but wrong server phase: voting entry while the
    // server is still in setup.
    assert_403(
        submit(
            "voting,BB,ballot_digest,1,x".into(),
            bb1_key.clone(),
            "BB-1",
            ts + 1,
        )
        .await,
        "phase mismatch",
    );

    // (c) Phase transition signed by a non-PM entity.
    assert_403(
        submit(
            "setup,PM,phase_transition,1,voting".into(),
            bb1_key.clone(),
            "BB-1",
            ts + 2,
        )
        .await,
        "non-PM phase transition",
    );

    // (d) Legitimate PM transition setup → voting succeeds.
    submit(
        "setup,PM,phase_transition,1,voting".into(),
        pm_key.clone(),
        "PM-1",
        ts + 3,
    )
    .await
    .expect("PM transition must be accepted");

    // (e) Setup-phase entry after the transition is rejected.
    assert_403(
        submit(
            "setup,RT,acc_pub_key,2,x".into(),
            bb1_key.clone(),
            "BB-1",
            ts + 4,
        )
        .await,
        "setup entry after transition",
    );

    // (f) Insufficient threshold: tally_result requires t ≥ 3.
    submit(
        "voting,PM,phase_transition,1,tallying".into(),
        pm_key.clone(),
        "PM-1",
        ts + 5,
    )
    .await
    .expect("PM transition to tallying must be accepted");
    assert_403(
        submit(
            "tallying,TT,tally_result,1,x".into(),
            tt1_key.clone(),
            "TT-1",
            ts + 6,
        )
        .await,
        "insufficient threshold",
    );

    // (g) Unknown entity signature.
    let rogue = SigningKey::from_bytes(&[9u8; 32]);
    let result = submit("tallying,TT,tally_result,3,x".into(), rogue, "TT-9", ts + 7).await;
    assert!(
        matches!(result, Err(WbbError::Http(status, _)) if !status.is_success()),
        "unknown entity must be rejected"
    );
}

// ── Helpers ────────────────────────────────────────────────────────────────

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
