//! The drivers' handling of a partial the board refuses
//! (admin.rs `gen_credentials`, `submit_cosigned_and_wait`) never treats an
//! entry as published unless the board published it under the signers its
//! threshold requires (Sec. 3.4.2: "tRT RTs which agree on the same data can
//! write the ACC generation public key pkACC and the list of nACC public
//! ACCs" / "the credential control elements"; Sec. 3.9 step 19).

use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::SigningKey;
use rand::SeedableRng;
use referendum_poc::actors::admin::{gen_credentials, GenCredentialsConfig};
use referendum_poc::clients::wbb::{sign_entry, WbbClient};
use referendum_poc::configuration::get_configuration;
use referendum_poc::protocol::clock::Clock;
use referendum_poc::protocol::rng::MasterSeed;
use referendum_poc::protocol::setup::artifacts::write_artifacts;
use referendum_poc::protocol::setup::run_ceremony;
use referendum_poc::protocol::tls::{issue_service_cert, ClusterCa};
use reqwest::Url;

use super::helpers::{self, ElectionCluster, ElectionOpts};

const MASTER_SEED: [u8; 32] = [0x47u8; 32];

fn rt_key(ceremony_dir: &std::path::Path, idx: usize) -> SigningKey {
    let bytes = std::fs::read(ceremony_dir.join(format!("rt-{idx}-signing-key.bin")))
        .expect("rt signing key");
    SigningKey::from_bytes(&bytes.try_into().expect("32-byte seed"))
}

/// `who` stages junk setup entries no other teller co-signs until the board
/// holds as many unpublished ones for it as it allows: its next partial is
/// refused (503).
async fn fill_allowance(client: &WbbClient, who: usize, key: &SigningKey, already: usize) {
    for i in already..64 {
        let entry = sign_entry(
            format!("setup,RT,acc_pub_key,2,junk-{who}-{i}").as_bytes(),
            &format!("RT-{who}"),
            1_700_000_000_000 + i as i64,
            key,
        );
        client.submit(&entry).await.expect("staged");
    }
}

struct Board {
    _temp: tempfile::TempDir,
    _guard: tokio::sync::SemaphorePermit<'static>,
    wbb: helpers::WbbProcess,
    cfg: GenCredentialsConfig,
    keys: Vec<SigningKey>,
}

async fn board() -> Board {
    helpers::init();
    let guard = helpers::cluster_guard().await;
    let temp = tempfile::tempdir().expect("tempdir");
    let ceremony_dir = temp.path().to_path_buf();
    let base_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let base = get_configuration(&base_dir).expect("base settings");
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(MASTER_SEED);
    let ceremony = run_ceremony(&base.election, &mut rng).unwrap();
    write_artifacts(
        &ceremony_dir,
        &base,
        &ceremony,
        &MasterSeed::new(MASTER_SEED),
    )
    .expect("ceremony artifacts");
    let ca = ClusterCa::from_seed(&MASTER_SEED).unwrap();
    let cert = issue_service_cert(&ca, "wbb", &MASTER_SEED).unwrap();
    let port = helpers::free_port();
    let keys: Vec<SigningKey> = (1..=3).map(|i| rt_key(&ceremony_dir, i)).collect();
    let mut config = helpers::WbbSpawnConfig::new(port);
    for (i, key) in keys.iter().enumerate() {
        config = config.with_entity(&format!("RT-{}", i + 1), key.verifying_key());
    }
    let wbb =
        helpers::WbbProcess::spawn(&ceremony_dir, &ca, cert.cert_pem(), cert.key_pem(), config)
            .await
            .expect("spawn wbb");
    let cfg = GenCredentialsConfig {
        ceremony_dir: ceremony_dir.clone(),
        output_dir: ceremony_dir.join("output"),
        n_acc: base.election.n_acc,
        t_rt: base.election.t_rt,
        t_prime: base.election.t_prime,
        wbb_url: Url::parse(&format!("https://127.0.0.1:{port}/wbb/")).unwrap(),
        rt_urls: None,
        rt_tokens: None,
        ca_pem: ca.cert_pem().to_string(),
        clock: Clock::from_settings(&base.clock),
    };
    Board {
        _temp: temp,
        _guard: guard,
        wbb,
        cfg,
        keys,
    }
}

/// The published `acc_pub_key` entries (not the junk, which is never
/// published) with their signers.
async fn published_acc_pub_keys(client: &WbbClient) -> Vec<Vec<String>> {
    client
        .entries()
        .await
        .expect("entries")
        .entries
        .iter()
        .filter(|e| {
            e.entry
                .get("data")
                .and_then(|v| v.as_str())
                .and_then(|s| BASE64.decode(s).ok())
                .is_some_and(|d| d.starts_with(b"setup,RT,acc_pub_key,2,"))
        })
        .map(|e| {
            serde_json::from_value(e.entry.get("entity_ids").cloned().unwrap_or_default())
                .unwrap_or_default()
        })
        .collect()
}

fn share_files(cfg: &GenCredentialsConfig) -> Vec<String> {
    std::fs::read_dir(&cfg.output_dir)
        .map(|dir| {
            dir.filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default()
}

/// One teller whose partial the board refuses does not stop credential
/// generation: the entry is published on the other two partials (t_RT = 2),
/// under those two signers, and the refused teller is not among them.
#[tokio::test(flavor = "multi_thread")]
async fn credential_generation_publishes_on_the_other_tellers_partials() {
    let b = board().await;
    fill_allowance(&b.wbb.client, 1, &b.keys[0], 0).await;
    gen_credentials(b.cfg.clone())
        .await
        .expect("one refused partial does not stop credential generation");
    let published = published_acc_pub_keys(&b.wbb.client).await;
    assert_eq!(published.len(), 1, "{published:?}");
    let mut signers = published[0].clone();
    signers.sort();
    assert_eq!(signers, ["RT-2", "RT-3"]);
    assert!(share_files(&b.cfg)
        .iter()
        .any(|f| f == "rt-1-credential_shares.json"));
}

/// Two tellers whose partials the board refuses leave ONE partial staged, below
/// t_RT: the driver must not take the entry as published - it fails, names
/// both refused tellers, and writes no share file (nothing usable without the
/// public ACCs on the board).
#[tokio::test(flavor = "multi_thread")]
async fn credential_generation_below_t_rt_partials_publishes_nothing() {
    let b = board().await;
    fill_allowance(&b.wbb.client, 1, &b.keys[0], 0).await;
    fill_allowance(&b.wbb.client, 2, &b.keys[1], 0).await;
    let err = gen_credentials(b.cfg.clone())
        .await
        .expect_err("one staged partial is below t_RT: nothing is published");
    let text = err.to_string();
    assert!(
        text.contains("RT-1") && text.contains("RT-2"),
        "the refused tellers are not named: {text}"
    );
    assert!(
        published_acc_pub_keys(&b.wbb.client).await.is_empty(),
        "an acc_pub_key entry was published below t_RT"
    );
    let files = share_files(&b.cfg);
    assert!(
        !files.iter().any(|f| f.ends_with("credential_shares.json")),
        "share files written although nothing was published: {files:?}"
    );

    // A rerun: RT-3's partial of the (deterministic) entry is still staged,
    // so the board answers 409 for it - delivered, not refused - and the
    // driver again waits for the board, which still holds one partial.
    let err = gen_credentials(b.cfg.clone())
        .await
        .expect_err("still one staged partial");
    assert!(err.to_string().contains("not included in time"), "{err}");
    assert!(published_acc_pub_keys(&b.wbb.client).await.is_empty());
}

/// Every partial refused: nothing can be published, and the driver says so
/// at once, naming every teller.
#[tokio::test(flavor = "multi_thread")]
async fn credential_generation_with_every_partial_refused_fails_at_once() {
    let b = board().await;
    for who in 1..=3 {
        fill_allowance(&b.wbb.client, who, &b.keys[who - 1], 0).await;
    }
    let started = std::time::Instant::now();
    let err = gen_credentials(b.cfg.clone())
        .await
        .expect_err("every partial refused");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "every partial refused, yet the driver waited for the deadline: {:?}",
        started.elapsed()
    );
    let text = err.to_string();
    assert!(
        (1..=3).all(|i| text.contains(&format!("RT-{i}"))),
        "not every refused teller is named: {text}"
    );
    assert!(published_acc_pub_keys(&b.wbb.client).await.is_empty());
    assert!(!share_files(&b.cfg)
        .iter()
        .any(|f| f.ends_with("credential_shares.json")));
}

/// The tally's co-signed `credential_control` (t_RT = 2): two registration
/// tellers whose partials the board refuses leave one staged partial. The
/// driver must not take the entry as published and go on to the TT
/// artifacts that depend on it: the tally fails naming both, and neither the
/// control elements nor a result reach the board.
#[tokio::test(flavor = "multi_thread")]
async fn a_tally_entry_below_its_threshold_is_never_taken_as_published() {
    let mut cluster = ElectionCluster::start(2, ElectionOpts::default()).await;
    cluster.enroll_all().await;
    let pins = [cluster.pin(0).await, cluster.pin(1).await];
    cluster.open_voting().await;
    cluster.vote_and_cast(0, "approve", pins[0]).await;
    cluster.vote_and_cast(1, "reject", pins[1]).await;
    cluster.close_voting().await;
    for who in ["rt-1", "rt-2"] {
        let key = cluster.signing_key(who);
        for i in 0..64 {
            let entry = sign_entry(
                format!("tallying,RT,credential_control,2,junk-{who}-{i}").as_bytes(),
                &who.to_uppercase(),
                1_700_000_000_000 + i,
                &key,
            );
            cluster.wbb.client.submit(&entry).await.expect("staged");
        }
    }
    let err = match cluster.try_tally().await {
        Ok(outcome) => panic!(
            "the tally completed with credential_control below t_RT: {:?}",
            (outcome.counts.si, outcome.counts.no)
        ),
        Err(e) => e.to_string(),
    };
    assert!(
        err.contains("RT-1") && err.contains("RT-2"),
        "the refused tellers are not named: {err}"
    );
    assert_eq!(cluster.entry_type_count("credential_control").await, 0);
    assert_eq!(cluster.entry_type_count("tally_result").await, 0);
}

/// A stand-in registration teller `/sign` endpoint (plain HTTP): `key` signs
/// as `RT-{id}` would; `None` refuses (403), as a teller that will not
/// co-sign does.
async fn stand_in_rt_sign(id: usize, key: Option<SigningKey>) -> Url {
    use axum::{http::StatusCode, routing::post, Json, Router};
    let app = Router::new().route(
        "/sign",
        post(move |Json(req): Json<serde_json::Value>| {
            let key = key.clone();
            async move {
                let Some(key) = key else {
                    return Err((StatusCode::FORBIDDEN, "RT stand-in: not co-signing"));
                };
                let data = req["data"].as_str().unwrap_or_default().to_string();
                let ts = req["timestamp"].as_i64().unwrap_or_default();
                let entity = format!("RT-{id}");
                let signed = sign_entry(data.as_bytes(), &entity, ts, &key);
                Ok(Json(serde_json::json!({
                    "entity_id": entity,
                    "timestamp": ts,
                    "signature": BASE64.encode(signed.signature),
                })))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", helpers::free_port()))
        .await
        .expect("bind stand-in");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Url::parse(&format!("http://{addr}/")).unwrap()
}

/// Sec. 3.4.2: "tRT RTs which agree on the same data can write the ACC
/// generation public key pkACC and the list of nACC public ACCs" (A2: at
/// n_RT = 3, t_RT = 2 one teller may be dishonest). With `--rt-urls` the
/// driver asks each teller to co-sign; one that refuses must not stop the
/// publication the other two agree on - as in the tally, where
/// `queue_rt_cosigned` goes on with any t_RT co-signatures (README row 21).
#[tokio::test(flavor = "multi_thread")]
async fn one_teller_refusing_to_co_sign_does_not_stop_credential_generation() {
    let b = board().await;
    let urls = vec![
        stand_in_rt_sign(1, None).await,
        stand_in_rt_sign(2, Some(b.keys[1].clone())).await,
        stand_in_rt_sign(3, Some(b.keys[2].clone())).await,
    ];
    let mut cfg = b.cfg.clone();
    cfg.rt_tokens = Some(
        (0..3)
            .map(|_| secrecy::SecretString::new("stand-in".into()))
            .collect(),
    );
    cfg.rt_urls = Some(urls);
    let outcome = gen_credentials(cfg).await;
    assert!(
        outcome.is_ok(),
        "one teller refusing /sign stopped credential generation: {outcome:?}"
    );
    let published = published_acc_pub_keys(&b.wbb.client).await;
    assert_eq!(published.len(), 1, "{published:?}");
}
