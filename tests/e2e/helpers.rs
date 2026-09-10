//! Shared e2e harness (spawn cluster, seeded determinism, WBB process).
//! Shared by every end-to-end test.

use std::{
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use referendum_poc::{
    actors::admin::{
        gen_credentials, run_tally, transition_phase, GenCredentialsConfig, PhaseTransitionConfig,
        TallyConfig, TallyOutcome,
    },
    actors::auditor::{run_audit, AuditConfig, AuditReport},
    actors::common::serve_rustls,
    actors::{bb, dip, er, ns, rt, tt, voter, wbb_ui},
    clients::wbb::WbbClient,
    configuration::{
        get_configuration, CeremonyPaths, DipSettings, ErClientSettings, NsClientSettings,
        PeerSettings, ServiceSettings, Settings, TlsSettings, VoterSettings, WbbSettings,
        WbbUiSettings,
    },
    protocol::clock::LogicalClock,
    protocol::rng::MasterSeed,
    protocol::setup::artifacts::write_artifacts,
    protocol::setup::run_ceremony,
    protocol::tls::{issue_service_cert, reqwest_client_trusting_ca, ClusterCa},
};
use reqwest::Url;
use secrecy::SecretString;
use tokio::time::interval;

pub fn init() {
    referendum_poc::telemetry::init_test_tracing();
}

/// Path to the compiled `sunlight` WBB binary. Builds once and caches under
/// `target/wbb-bin/`.
///
/// A file lock serializes concurrent builds across test processes so the cached
/// binary is never written by two builders at once.
pub fn build_wbb() -> PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let out_dir = Path::new(&manifest).join("target").join("wbb-bin");
    std::fs::create_dir_all(&out_dir).expect("create wbb-bin dir");
    let binary = out_dir.join("sunlight");

    if binary.exists() {
        return binary;
    }

    let lock_path = out_dir.join("build.lock");
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .expect("open build lock");
    fs2::FileExt::lock_exclusive(&lock).expect("lock wbb build");

    // Recheck under the lock: another test may have built it while we waited.
    if binary.exists() {
        return binary;
    }

    let wbb_src = Path::new(&manifest)
        .parent()
        .expect("manifest has parent")
        .join("resources")
        .join("sunlight_test");

    let tmp_binary = out_dir.join("sunlight.tmp");
    let status = Command::new("go")
        .arg("build")
        .arg("-o")
        .arg(&tmp_binary)
        .arg("./cmd/sunlight")
        .current_dir(&wbb_src)
        .env("CGO_CFLAGS", "-O2 -D__BLST_PORTABLE__")
        .status()
        .expect("spawn go build");

    if !status.success() {
        panic!("go build sunlight failed: {status}");
    }

    std::fs::rename(&tmp_binary, &binary).expect("atomically install sunlight binary");
    binary
}

/// Configuration for spawning a WBB instance.
pub struct WbbSpawnConfig {
    pub port: u16,
    pub entity_keys: Vec<(String, VerifyingKey)>,
    pub phase_manager_key: Option<VerifyingKey>,
    pub grace_period_ms: u64,
    pub max_submit_body_bytes: i64,
}

impl WbbSpawnConfig {
    pub fn new(port: u16) -> Self {
        Self {
            port,
            entity_keys: Vec::new(),
            phase_manager_key: None,
            grace_period_ms: 100,
            max_submit_body_bytes: 32 * 1024 * 1024,
        }
    }

    pub fn with_entity(mut self, id: &str, key: VerifyingKey) -> Self {
        self.entity_keys.push((id.to_string(), key));
        self
    }

    #[allow(dead_code)]
    pub fn with_phase_manager(mut self, key: VerifyingKey) -> Self {
        self.phase_manager_key = Some(key);
        self
    }
}

/// A running WBB process plus the client configured to talk to it.
pub struct WbbProcess {
    #[allow(dead_code)]
    child: Child,
    pub client: WbbClient,
    #[allow(dead_code)]
    pub base_url: reqwest::Url,
}

impl WbbProcess {
    #[allow(unused_assignments)]
    pub async fn spawn(
        work_dir: &Path,
        ca: &ClusterCa,
        service_cert_pem: &str,
        service_key_pem: &str,
        config: WbbSpawnConfig,
    ) -> anyhow::Result<Self> {
        let binary = build_wbb();
        let today = time::OffsetDateTime::now_utc().date().to_string();

        std::fs::write(work_dir.join("sunlight.pem"), service_cert_pem)?;
        std::fs::write(work_dir.join("sunlight-key.pem"), service_key_pem)?;

        let seed_path = work_dir.join("seed.bin");
        std::fs::write(&seed_path, [0u8; 32])?;

        let checkpoints = work_dir.join("checkpoints.db");
        init_checkpoints_db(&checkpoints)?;

        let yaml = build_sunlight_yaml(&today, &config, &seed_path, work_dir);
        std::fs::write(work_dir.join("sunlight.yaml"), yaml)?;

        let mut child = Command::new(&binary)
            .arg("-c")
            .arg("sunlight.yaml")
            .arg("-testcert")
            .current_dir(work_dir)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()?;

        let base_url = reqwest::Url::parse(&format!("https://127.0.0.1:{}/wbb/", config.port))?;
        let client = reqwest_client_trusting_ca(ca.cert_pem())?;
        let wbb_client = WbbClient::new(client, base_url.clone());

        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let mut last_error: Option<String> = None;
        let mut ticker = interval(Duration::from_millis(50));
        loop {
            ticker.tick().await;
            last_error = match wbb_client.health().await {
                Ok(true) => break,
                Ok(false) => Some("health returned non-success".to_string()),
                Err(e) => Some(format!("{e}")),
            };
            if tokio::time::Instant::now() > deadline {
                let _ = child.kill();
                return Err(anyhow::anyhow!(
                    "WBB did not become healthy in time: {:?}",
                    last_error
                ));
            }
        }

        Ok(Self {
            child,
            client: wbb_client,
            base_url,
        })
    }
}

fn build_sunlight_yaml(
    today: &str,
    config: &WbbSpawnConfig,
    seed_path: &Path,
    work_dir: &Path,
) -> String {
    let mut entity_keys_yaml = String::new();
    for (id, key) in &config.entity_keys {
        entity_keys_yaml.push_str(&format!("      {id}: {}\n", BASE64.encode(key.as_bytes())));
    }

    let pm_key_yaml = config
        .phase_manager_key
        .as_ref()
        .map(|k| format!("    phase_manager_key: {}", BASE64.encode(k.as_bytes())))
        .unwrap_or_default();

    let port = config.port;
    let host = "127.0.0.1";
    let mut yaml = String::new();
    yaml.push_str("listen:\n");
    yaml.push_str(&format!("  - \"{}:{}\"\n", host, port));
    yaml.push_str(&format!(
        "checkpoints: {}\n",
        work_dir.join("checkpoints.db").display()
    ));
    yaml.push_str("logs:\n");
    yaml.push_str("  - shortname: poc\n");
    yaml.push_str(&format!("    inception: \"{}\"\n", today));
    yaml.push_str("    period: 50\n");
    yaml.push_str(&format!("    httphost: {}\n", host));
    yaml.push_str("    httpprefix: /wbb\n");
    yaml.push_str(&format!(
        "    submissionprefix: https://{}:{}/wbb\n",
        host, port
    ));
    yaml.push_str(&format!(
        "    monitoringprefix: https://{}:{}/wbb\n",
        host, port
    ));
    yaml.push_str(&format!("    secret: {}\n", seed_path.display()));
    yaml.push_str("    poolsize: 1000\n");
    yaml.push_str(&format!(
        "    cache: {}\n",
        work_dir.join("cache.db").display()
    ));
    yaml.push_str(&format!(
        "    localdirectory: {}\n",
        work_dir.join("logdata").display()
    ));
    yaml.push_str("    entity_keys:\n");
    yaml.push_str(&entity_keys_yaml);
    if !pm_key_yaml.is_empty() {
        yaml.push_str(&pm_key_yaml);
        yaml.push('\n');
    }
    yaml.push_str("    disable_timestamp_validation: true\n");
    yaml.push_str(&format!(
        "    grace_period_ms: {}\n",
        config.grace_period_ms
    ));
    yaml.push_str(&format!(
        "    max_submit_body_bytes: {}\n",
        config.max_submit_body_bytes
    ));
    yaml
}

fn init_checkpoints_db(path: &Path) -> anyhow::Result<()> {
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    let status = Command::new("sqlite3")
        .arg(path)
        .arg("CREATE TABLE checkpoints (logID BLOB PRIMARY KEY, body BLOB NOT NULL) STRICT")
        .status()?;
    if !status.success() {
        anyhow::bail!("sqlite3 checkpoints init failed");
    }
    Ok(())
}

/// Serializes the full-cluster e2e tests.  Each spawns ~a dozen servers on
/// ports found by bind-then-release (`free_port`), and two clusters booting
/// concurrently in one process can steal each other's just-released ports
/// (the documented port race).  Holding this guard for the duration of a
/// cluster test removes the intra-process race entirely.
pub async fn cluster_guard() -> tokio::sync::MutexGuard<'static, ()> {
    static CLUSTER_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    CLUSTER_LOCK.lock().await
}

/// Allocate a port for a cluster service.
///
/// Ports are taken from a private range BELOW the kernel's ephemeral range
/// (Linux default 32768-60999): a `bind(0)`-then-release port can be grabbed
/// as the SOURCE port of any outgoing client connection before the server
/// binds it (the port race, observed as `Address already in use` flakes), but
/// ports outside the ephemeral range are never handed out that way.  The
/// counter makes successive allocations distinct within a process; each
/// candidate is still bind-probed so unrelated listeners are skipped.
pub fn free_port() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(20_000);
    loop {
        let candidate = NEXT.fetch_add(1, Ordering::SeqCst);
        if candidate >= 30_000 {
            NEXT.store(20_000, Ordering::SeqCst);
            continue;
        }
        if TcpListener::bind(("127.0.0.1", candidate)).is_ok() {
            return candidate;
        }
    }
}

pub fn entity_signing_key(master_seed: &[u8; 32], entity_id: &str) -> SigningKey {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(master_seed);
    hasher.update(entity_id.as_bytes());
    let seed: [u8; 32] = hasher.finalize().into();
    let mut rng = ChaCha20Rng::from_seed(seed);
    SigningKey::generate(&mut rng)
}

#[allow(dead_code)]
pub struct Cluster {
    pub wbb: WbbProcess,
}

impl Drop for WbbProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ===========================================================================
// Full-election harness (`spawn_cluster()`).
//
// Boots the whole system - ceremony, WBB, DIP/NS/ER, RTx3, BBx2, TTx3,
// wbb-ui, N voter-servers - and exposes the voter/admin actions the protocol
// tests drive. Holds the cluster guard for its lifetime, so tests using it
// are serialized automatically.
// ===========================================================================

/// Tunables for a harness cluster.
pub struct ElectionOpts {
    /// Master seed for the ceremony, entity keys, and TLS material.
    pub master_seed: [u8; 32],
    /// Override for the CAT rate limit (`rate_limit_and_cat`).
    pub max_casts_per_voter: Option<usize>,
}

impl Default for ElectionOpts {
    fn default() -> Self {
        Self {
            master_seed: [0xab; 32],
            max_casts_per_voter: None,
        }
    }
}

pub struct ElectionPorts {
    pub wbb: u16,
    pub dip: u16,
    pub ns: u16,
    pub er: u16,
    pub rt: Vec<u16>,
    pub bb: Vec<u16>,
    pub tt: Vec<u16>,
    pub wbb_ui: u16,
}

pub struct ElectionCluster {
    _guard: tokio::sync::MutexGuard<'static, ()>,
    temp: tempfile::TempDir,
    pub wbb: WbbProcess,
    pub wbb_url: Url,
    pub ca: ClusterCa,
    pub client: reqwest::Client,
    pub base: Settings,
    pub ports: ElectionPorts,
    pub voter_urls: Vec<String>,
    pub passphrases: Vec<String>,
    #[allow(dead_code)]
    pub master_seed: [u8; 32],
}

#[allow(dead_code)]
impl ElectionCluster {
    /// Ceremony + WBB + full service cluster + `n_voters` voter-servers,
    /// with the ER setup entries already published (A2).
    pub async fn start(n_voters: usize, opts: ElectionOpts) -> Self {
        init();
        let guard = cluster_guard().await;

        let temp = tempfile::tempdir().expect("tempdir");
        let ceremony_dir = temp.path().to_path_buf();
        let base_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let mut base = get_configuration(&base_dir).expect("base settings");
        if let Some(limit) = opts.max_casts_per_voter {
            base.election.max_casts_per_voter = limit;
        }

        let master_seed = opts.master_seed;
        let seed = MasterSeed::new(master_seed);
        let mut rng = ChaCha20Rng::from_seed(master_seed);
        let ceremony = run_ceremony(&base.election, &mut rng).expect("ceremony");
        write_artifacts(&ceremony_dir, &base, &ceremony, &seed, &base.dip)
            .expect("write ceremony artifacts");

        let ca = ClusterCa::from_seed(&master_seed).expect("cluster ca");
        let wbb_cert = issue_service_cert(&ca, "wbb", &master_seed).expect("wbb cert");
        let ports = ElectionPorts {
            wbb: free_port(),
            dip: free_port(),
            ns: free_port(),
            er: free_port(),
            rt: (0..3).map(|_| free_port()).collect(),
            bb: (0..2).map(|_| free_port()).collect(),
            tt: (0..3).map(|_| free_port()).collect(),
            wbb_ui: free_port(),
        };

        let key_of = |name: &str| ceremony_signing_key(&ceremony_dir, name);
        let pm_key = key_of("pm");
        let mut wbb_config = WbbSpawnConfig::new(ports.wbb)
            .with_entity("PM-1", pm_key.verifying_key())
            .with_entity("ER-1", key_of("er").verifying_key())
            .with_phase_manager(pm_key.verifying_key());
        for i in 1..=3 {
            wbb_config = wbb_config.with_entity(
                &format!("RT-{i}"),
                key_of(&format!("rt-{i}")).verifying_key(),
            );
            wbb_config = wbb_config.with_entity(
                &format!("TT-{i}"),
                key_of(&format!("tt-{i}")).verifying_key(),
            );
        }
        for i in 1..=2 {
            wbb_config = wbb_config.with_entity(
                &format!("BB-{i}"),
                key_of(&format!("bb-{i}")).verifying_key(),
            );
        }
        let wbb = WbbProcess::spawn(
            &ceremony_dir,
            &ca,
            wbb_cert.cert_pem(),
            wbb_cert.key_pem(),
            wbb_config,
        )
        .await
        .expect("spawn wbb");

        let wbb_url = Url::parse(&format!("https://127.0.0.1:{}/wbb/", ports.wbb)).unwrap();
        gen_credentials(GenCredentialsConfig {
            ceremony_dir: ceremony_dir.clone(),
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

        let mk =
            |name: &str, port: u16| election_settings(&ceremony_dir, name, port, &ports, &base);

        tokio::spawn(dip::run(mk("dip", ports.dip), key_of("dip")));
        tokio::spawn(ns::run(mk("ns", ports.ns), key_of("ns")));

        let admin_token = read_admin_token(&ceremony_dir);
        let (er_addr, er_tls, er_state) = er::build_service(
            mk("er", ports.er),
            key_of("er"),
            SecretString::new(admin_token.clone()),
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
            let (addr, tls, state) = rt::build_service(mk(&name, *port), key_of(&name))
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
            let (addr, tls, state) = bb::build_service(mk(&name, *port), key_of(&name))
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
            let (addr, tls, state) = tt::build_service(mk(&name, *port), key_of(&name))
                .await
                .expect("build tt");
            tokio::spawn(async move {
                serve_rustls(tt::router(state), addr, tls)
                    .await
                    .expect("tt server")
            });
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

        let client = reqwest_client_trusting_ca(ca.cert_pem()).expect("http client");
        let mut cluster = Self {
            _guard: guard,
            temp,
            wbb,
            wbb_url,
            ca,
            client,
            base,
            ports,
            voter_urls: Vec::new(),
            passphrases: Vec::new(),
            master_seed,
        };
        for i in 1..=n_voters {
            let name = format!("voter-{i}");
            let url = cluster.spawn_voter_server_as(&name, &name).await;
            cluster.voter_urls.push(url);
        }

        tokio::time::sleep(Duration::from_millis(300)).await;

        // ER publishes the setup entries (A2) - the auditor and tally read
        // the election context from the log itself.
        let setup = cluster
            .client
            .post(format!(
                "https://127.0.0.1:{}/admin/setup",
                cluster.ports.er
            ))
            .header("Authorization", format!("Bearer {admin_token}"))
            .send()
            .await
            .expect("admin setup");
        assert!(setup.status().is_success(), "ER setup publication");

        cluster
    }

    pub fn ceremony_dir(&self) -> &Path {
        self.temp.path()
    }

    /// Spawn a voter-server. `cert_name` must be a ceremony-provisioned TLS
    /// identity (`voter-1`..`voter-n`); a fresh-device server for `new_device`
    /// reuses a cert but gets its own state dir via `state_label`.
    pub async fn spawn_voter_server_as(&self, cert_name: &str, state_label: &str) -> String {
        let port = free_port();
        let mut settings =
            election_settings(self.temp.path(), cert_name, port, &self.ports, &self.base);
        settings.voter.state_dir = self
            .temp
            .path()
            .join(format!("{state_label}-state"))
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
        format!("https://127.0.0.1:{port}")
    }

    pub fn signing_key(&self, name: &str) -> SigningKey {
        ceremony_signing_key(self.temp.path(), name)
    }

    pub fn admin_token(&self) -> String {
        read_admin_token(self.temp.path())
    }

    /// Enroll voter `i` (0-based) through V1-V4 and store the passphrase.
    pub async fn enroll(&mut self, i: usize) -> String {
        let base_url = self.voter_urls[i].clone();
        let fiscal_id = format!("VOTER-{:03}", i + 1);
        let passphrase = enroll_on(&self.client, &base_url, &fiscal_id).await;
        if self.passphrases.len() <= i {
            self.passphrases.resize(i + 1, String::new());
        }
        self.passphrases[i] = passphrase.clone();
        passphrase
    }

    pub async fn enroll_all(&mut self) {
        for i in 0..self.voter_urls.len() {
            self.enroll(i).await;
        }
    }

    fn transition_config(&self) -> PhaseTransitionConfig {
        PhaseTransitionConfig {
            ceremony_dir: self.temp.path().to_path_buf(),
            wbb_url: self.wbb_url.clone(),
            ca_pem: self.ca.cert_pem().to_string(),
            clock: LogicalClock::new(self.base.clock.base_ms, self.base.clock.tick_ms),
        }
    }

    pub async fn open_voting(&self) {
        transition_phase(self.transition_config(), "setup", "voting")
            .await
            .expect("open voting");
    }

    pub async fn close_voting(&self) {
        transition_phase(self.transition_config(), "voting", "tallying")
            .await
            .expect("close voting");
    }

    pub async fn pin(&self, i: usize) -> u64 {
        let shown = self
            .voter_post(
                i,
                "/api/pin",
                serde_json::json!({ "passphrase": self.passphrases[i] }),
            )
            .await;
        shown["pin"].as_u64().expect("pin")
    }

    pub async fn ruse_pin(&self, i: usize) -> u64 {
        let ruse = self
            .voter_post(
                i,
                "/api/pin/ruse",
                serde_json::json!({ "passphrase": self.passphrases[i] }),
            )
            .await;
        ruse["ruse_pin"].as_u64().expect("ruse pin")
    }

    /// `POST /api/vote` - returns the full response (digest, emoji).
    pub async fn vote(&self, i: usize, option: &str, pin: u64) -> serde_json::Value {
        self.voter_post(
            i,
            "/api/vote",
            serde_json::json!({
                "passphrase": self.passphrases[i], "option": option, "pin": pin
            }),
        )
        .await
    }

    /// `POST /api/cast` - returns the full response (receipts).
    pub async fn cast(&self, i: usize) -> serde_json::Value {
        self.voter_post(
            i,
            "/api/cast",
            serde_json::json!({ "passphrase": self.passphrases[i] }),
        )
        .await
    }

    /// Vote, cast to both BBs (asserting 2 receipts) and CONFIRM the
    /// cast-as-intended disclosure (Sec. 3.8.4 steps 8-17) - the full voter
    /// flow; only confirmed ballots are released at tally (Sec. 3.9 step 2).
    /// Returns the vote response (digest, emoji).
    pub async fn vote_and_cast(&self, i: usize, option: &str, pin: u64) -> serde_json::Value {
        let vote = self.vote_and_cast_unconfirmed(i, option, pin).await;
        let confirm = self
            .voter_post(
                i,
                "/api/confirm",
                serde_json::json!({ "passphrase": self.passphrases[i] }),
            )
            .await;
        assert!(
            confirm["confirmed_at_ms"].as_u64().unwrap() > 0,
            "cast-as-intended confirmation published"
        );
        vote
    }

    /// Vote and cast WITHOUT the cast-as-intended confirmation - such a
    /// ballot is accepted by the BBs but must never be released or counted.
    pub async fn vote_and_cast_unconfirmed(
        &self,
        i: usize,
        option: &str,
        pin: u64,
    ) -> serde_json::Value {
        let vote = self.vote(i, option, pin).await;
        assert!(!vote["emoji"].as_array().unwrap().is_empty());
        let cast = self.cast(i).await;
        assert_eq!(
            cast["receipts"].as_array().unwrap().len(),
            2,
            "both BBs accept the ballot"
        );
        vote
    }

    pub async fn voter_post(
        &self,
        i: usize,
        path: &str,
        body: serde_json::Value,
    ) -> serde_json::Value {
        post_json(&self.client, &format!("{}{path}", self.voter_urls[i]), body).await
    }

    /// Run the full Sec. 3.9 tally driver over HTTPS.
    pub async fn tally(&self) -> TallyOutcome {
        let url = |p: &u16| Url::parse(&format!("https://127.0.0.1:{p}/")).unwrap();
        run_tally(TallyConfig {
            ceremony_dir: self.temp.path().to_path_buf(),
            wbb_url: self.wbb_url.clone(),
            er_url: url(&self.ports.er),
            bb_urls: self.ports.bb.iter().map(url).collect(),
            rt_urls: self.ports.rt.iter().map(url).collect(),
            tt_urls: self.ports.tt.iter().map(url).collect(),
            ca_pem: self.ca.cert_pem().to_string(),
            clock: LogicalClock::new(self.base.clock.base_ms, self.base.clock.tick_ms),
            n_acc: self.base.election.n_acc,
            t_tt: self.base.election.t_tt,
        })
        .await
        .expect("tally pipeline")
    }

    /// Entity verifying keys as the auditor CLI would load them.
    pub fn entity_keys(&self) -> Vec<(String, VerifyingKey)> {
        let mut keys = vec![
            ("PM-1".to_string(), self.signing_key("pm").verifying_key()),
            ("ER-1".to_string(), self.signing_key("er").verifying_key()),
        ];
        for i in 1..=3 {
            keys.push((
                format!("RT-{i}"),
                self.signing_key(&format!("rt-{i}")).verifying_key(),
            ));
            keys.push((
                format!("TT-{i}"),
                self.signing_key(&format!("tt-{i}")).verifying_key(),
            ));
        }
        for i in 1..=2 {
            keys.push((
                format!("BB-{i}"),
                self.signing_key(&format!("bb-{i}")).verifying_key(),
            ));
        }
        keys
    }

    pub fn audit_config(&self) -> AuditConfig {
        AuditConfig {
            wbb_url: self.wbb_url.clone(),
            ca_pem: self.ca.cert_pem().to_string(),
            entity_keys: self.entity_keys(),
            n_tt: self.base.election.n_tt,
            t_tt: self.base.election.t_tt,
        }
    }

    /// Sec. 3.10 universal verification from the log alone.
    pub async fn audit(&self) -> AuditReport {
        run_audit(self.audit_config()).await.expect("audit run")
    }

    /// Count WBB entries of one entry type.
    pub async fn entry_type_count(&self, wanted: &str) -> usize {
        let entries = self.wbb.client.entries().await.expect("wbb entries");
        entries
            .entries
            .iter()
            .filter_map(|e| e.entry.get("data").and_then(|v| v.as_str()))
            .filter_map(|b64| BASE64.decode(b64).ok())
            .filter_map(|data| referendum_poc::protocol::voting::parse_wbb_data(&data))
            .filter(|p| p.entry_type == wanted)
            .count()
    }

    pub fn er_base(&self) -> String {
        format!("https://127.0.0.1:{}", self.ports.er)
    }

    pub fn ui_base(&self) -> String {
        format!("https://127.0.0.1:{}", self.ports.wbb_ui)
    }
}

fn ceremony_signing_key(ceremony_dir: &Path, name: &str) -> SigningKey {
    let bytes = std::fs::read(ceremony_dir.join(format!("{name}-signing-key.bin")))
        .expect("signing key file");
    let seed: [u8; 32] = bytes.try_into().expect("32-byte signing key seed");
    SigningKey::from_bytes(&seed)
}

fn read_admin_token(ceremony_dir: &Path) -> String {
    std::fs::read_to_string(ceremony_dir.join("er-admin-token.txt"))
        .expect("admin token")
        .trim()
        .to_string()
}

/// V1-V4: login, enroll, wait for PIN readiness, retrieve the PIN.
async fn enroll_on(client: &reqwest::Client, base_url: &str, fiscal_id: &str) -> String {
    let login = post_json(
        client,
        &format!("{base_url}/api/login"),
        serde_json::json!({ "fiscal_id": fiscal_id }),
    )
    .await;
    assert!(login["vid"].as_u64().unwrap() > 0);

    let enroll = post_json(
        client,
        &format!("{base_url}/api/enroll"),
        serde_json::json!({ "fiscal_id": fiscal_id }),
    )
    .await;
    let passphrase = enroll["passphrase"].as_str().unwrap().to_string();

    wait_pin_ready(client, base_url, &passphrase).await;
    let _pin = post_json(
        client,
        &format!("{base_url}/api/pin/retrieve"),
        serde_json::json!({ "passphrase": passphrase }),
    )
    .await;
    passphrase
}

/// Poll `/api/status` until the NS reports >= t_RT shares ready.
pub async fn wait_pin_ready(client: &reqwest::Client, base_url: &str, passphrase: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let status = post_json(
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
}

pub async fn post_json(
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

pub async fn get_json(client: &reqwest::Client, url: &str) -> serde_json::Value {
    let response = client.get(url).send().await.expect("request");
    let status = response.status();
    let text = response.text().await.expect("body");
    assert!(
        status.is_success(),
        "GET {url} failed with {status}: {text}"
    );
    serde_json::from_str(&text).expect("json body")
}

/// Per-service settings pointing every client at the harness cluster.
fn election_settings(
    ceremony_dir: &Path,
    name: &str,
    port: u16,
    ports: &ElectionPorts,
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
