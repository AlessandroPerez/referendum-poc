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
    protocol::clock::Clock,
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

    let wbb_src = Path::new(&manifest)
        .parent()
        .expect("manifest has parent")
        .join("resources")
        .join("sunlight_test");
    // The cached binary is reused only while it is newer than every Go source
    // of the fork: a stale board silently runs old bulletin-board code.
    let fresh = |binary: &Path| -> bool {
        let Ok(built) = std::fs::metadata(binary).and_then(|m| m.modified()) else {
            return false;
        };
        newest_go_source(&wbb_src).is_none_or_older_than(built)
    };
    if fresh(&binary) {
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
    if fresh(&binary) {
        return binary;
    }

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

/// Modification time of the newest `.go` file under `dir` (skipping VCS and
/// vendored trees), if any.
fn newest_go_source(dir: &Path) -> NewestSource {
    fn walk(dir: &Path, newest: &mut Option<std::time::SystemTime>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            if path.is_dir() {
                if name != ".git" && name != "vendor" && name != "node_modules" {
                    walk(&path, newest);
                }
            } else if path.extension().is_some_and(|e| e == "go") {
                if let Ok(modified) = entry.metadata().and_then(|m| m.modified()) {
                    if newest.map_or(true, |n| modified > n) {
                        *newest = Some(modified);
                    }
                }
            }
        }
    }
    let mut newest = None;
    walk(dir, &mut newest);
    NewestSource(newest)
}

struct NewestSource(Option<std::time::SystemTime>);

impl NewestSource {
    fn is_none_or_older_than(&self, built: std::time::SystemTime) -> bool {
        self.0.map_or(true, |source| source < built)
    }
}

/// Configuration for spawning a WBB instance.
pub struct WbbSpawnConfig {
    pub port: u16,
    pub entity_keys: Vec<(String, VerifyingKey)>,
    pub phase_manager_key: Option<VerifyingKey>,
    pub grace_period_ms: u64,
    pub max_submit_body_bytes: i64,
    /// Validators registered with the board: id -> compressed BLS public key.
    pub validator_keys: Vec<(String, Vec<u8>)>,
    /// Enforce the WBB's +/- 5 minute freshness window (wall-clock runs).
    /// Off by default: the suite stamps entries with the logical clock.
    pub timestamp_validation: bool,
}

impl WbbSpawnConfig {
    pub fn new(port: u16) -> Self {
        Self {
            port,
            entity_keys: Vec::new(),
            phase_manager_key: None,
            grace_period_ms: 100,
            max_submit_body_bytes: 32 * 1024 * 1024,
            timestamp_validation: false,
            validator_keys: Vec::new(),
        }
    }

    #[allow(dead_code)]
    pub fn with_validator(mut self, id: &str, public_key: Vec<u8>) -> Self {
        self.validator_keys.push((id.to_string(), public_key));
        self
    }

    #[allow(dead_code)]
    pub fn with_timestamp_validation(mut self) -> Self {
        self.timestamp_validation = true;
        self
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

        let seed_path = work_dir.join("wbb-log-seed.bin");
        // A ceremony directory already holds the board's seed: run on it.
        if !seed_path.exists() {
            std::fs::write(&seed_path, [0u8; 32])?;
        }

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
    yaml.push_str(&format!(
        "    disable_timestamp_validation: {}\n",
        !config.timestamp_validation
    ));
    if !config.validator_keys.is_empty() {
        yaml.push_str("    validator_bls_keys:\n");
        for (id, key) in &config.validator_keys {
            yaml.push_str(&format!("      {id}: {}\n", BASE64.encode(key)));
        }
    }
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

/// Bounds how many full-cluster e2e tests run at once: `E2E_PARALLEL`
/// (default 1, i.e. one after another). Each cluster spawns ~a dozen servers;
/// their ports come from `free_port`'s per-process counter in a private range,
/// so concurrent clusters never get the same port. The bound is about CPU:
/// the tests time real protocol work, and too many clusters at once on a
/// small machine would only make them slow and their timing bounds noisy.
pub async fn cluster_guard() -> tokio::sync::SemaphorePermit<'static> {
    use std::sync::OnceLock;
    static CLUSTERS: OnceLock<tokio::sync::Semaphore> = OnceLock::new();
    CLUSTERS
        .get_or_init(|| {
            let parallel = std::env::var("E2E_PARALLEL")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .filter(|n| (1..=16).contains(n))
                .unwrap_or(1);
            tokio::sync::Semaphore::new(parallel)
        })
        .acquire()
        .await
        .expect("the cluster semaphore is never closed")
}

/// Allocate a port for a cluster service.
///
/// Ports are taken from a private range BELOW the kernel's ephemeral range
/// (Linux default 32768-60999): a `bind(0)`-then-release port can be grabbed
/// as the SOURCE port of any outgoing client connection before the server
/// binds it (the port race, observed as `Address already in use` flakes), but
/// ports outside the ephemeral range are never handed out that way.  The
/// counter makes successive allocations distinct within a process; each
/// candidate is still bind-probed so unrelated listeners are skipped. The
/// range starts at `E2E_PORT_BASE` (default 20000, at most 30000) and spans
/// 2000 ports, so several copies of the suite can run side by side.
pub fn free_port() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    use std::sync::OnceLock;
    static BASE: OnceLock<u16> = OnceLock::new();
    static NEXT: AtomicU16 = AtomicU16::new(0);
    let base = *BASE.get_or_init(|| {
        std::env::var("E2E_PORT_BASE")
            .ok()
            .and_then(|v| v.parse::<u16>().ok())
            .filter(|b| (1024..=30_000).contains(b))
            .unwrap_or(20_000)
    });
    loop {
        let offset = NEXT.fetch_add(1, Ordering::SeqCst);
        if offset >= 2_000 {
            NEXT.store(0, Ordering::SeqCst);
            continue;
        }
        let candidate = base + offset;
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
    /// Override for the casting tokens' validity, seconds.
    pub casting_token_ttl_s: Option<u64>,
    /// Override for the minimum time between two different ballots, seconds.
    pub min_cast_interval_s: Option<u64>,
    /// Run every service on the wall clock with this waiting-period range
    /// `(tau_min_s, tau_max_s)` instead of the reproducible logical clock.
    pub wall_clock_tau: Option<(u64, u64)>,
}

impl Default for ElectionOpts {
    fn default() -> Self {
        Self {
            master_seed: [0xab; 32],
            max_casts_per_voter: None,
            wall_clock_tau: None,
            casting_token_ttl_s: None,
            min_cast_interval_s: None,
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
    _guard: tokio::sync::SemaphorePermit<'static>,
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
        // The suite asks for the reproducible mode BY NAME; the shipped
        // configuration is the wall clock.
        base.clock.mode = referendum_poc::protocol::clock::ClockMode::Logical;
        if let Some(limit) = opts.max_casts_per_voter {
            base.election.max_casts_per_voter = limit;
        }

        if let Some(ttl) = opts.casting_token_ttl_s {
            base.election.casting_token_ttl_s = ttl;
        }
        if let Some(gap) = opts.min_cast_interval_s {
            base.election.min_cast_interval_s = gap;
        }
        if let Some((tau_min_s, tau_max_s)) = opts.wall_clock_tau {
            base.clock.mode = referendum_poc::protocol::clock::ClockMode::Wall;
            base.election.tau_min_s = tau_min_s;
            base.election.tau_max_s = tau_max_s;
        }
        let master_seed = opts.master_seed;
        let seed = MasterSeed::new(master_seed);
        let mut rng = ChaCha20Rng::from_seed(master_seed);
        let ceremony = run_ceremony(&base.election, &mut rng).expect("ceremony");
        write_artifacts(&ceremony_dir, &base, &ceremony, &seed).expect("write ceremony artifacts");

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
            clock: Clock::from_settings(&base.clock),
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

    /// The electoral roll's PRIVATE identifier assignment, recomputed from its
    /// seed: entry `i` is the vid of registry voter `i + 1`; from index
    /// `n_voters` on come the spare vids, in hand-out order.
    pub fn vid_assignment(&self) -> Vec<u64> {
        vid_assignment(self.temp.path(), self.base.election.n_acc)
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
            clock: Clock::from_settings(&self.base.clock),
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

    /// Arm a decoy, authorised with the PIN the app currently holds
    /// (Sec. 3.7.3 step 5 needs `PIN^valid` to build `x^ruse`).
    pub async fn ruse_pin(&self, i: usize, pin: u64) -> u64 {
        let ruse = self
            .voter_post(
                i,
                "/api/pin/ruse",
                serde_json::json!({ "passphrase": self.passphrases[i], "pin": pin }),
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

    /// `POST /api/cast` - returns the full response (receipts). The PIN says
    /// which held ballot to cast (Sec. 3.7.3: the ruse PIN has its own).
    pub async fn cast(&self, i: usize, pin: u64) -> serde_json::Value {
        self.voter_post(
            i,
            "/api/cast",
            serde_json::json!({ "passphrase": self.passphrases[i], "pin": pin }),
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
                // The post-cast choice of Sec. 3.8.4 steps 10-11, alternating
                // per voter so every slot combination is exercised.
                serde_json::json!({
                    "passphrase": self.passphrases[i],
                    "pin": pin,
                    // Sec. 3.8.4 steps 9-11: the confirmation names the
                    // ballot whose control values were checked.
                    "digest": vote["digest"],
                    "l1": if i % 2 == 0 { "code" } else { "sum" },
                    "l2": if (i / 2) % 2 == 0 { "sum" } else { "code" },
                }),
            )
            .await;
        assert!(
            confirm["confirmed_at_ms"].as_u64().unwrap() > 0,
            "cast-as-intended confirmation published"
        );
        assert_eq!(confirm["l1"], if i % 2 == 0 { "code" } else { "sum" });
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
        let cast = self.cast(i, pin).await;
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
        self.try_tally().await.expect("tally pipeline")
    }

    /// The tally pipeline, returning its error instead of panicking.
    pub async fn try_tally(
        &self,
    ) -> Result<TallyOutcome, referendum_poc::actors::admin::AdminError> {
        let er_url = Url::parse(&format!("https://127.0.0.1:{}/", self.ports.er)).unwrap();
        self.try_tally_with_roll(er_url).await
    }

    /// The tally, asking `er_url` for the eligible list (e.g. a stand-in
    /// electoral roll that lies about it).
    pub async fn try_tally_with_roll(
        &self,
        er_url: Url,
    ) -> Result<TallyOutcome, referendum_poc::actors::admin::AdminError> {
        let url = |p: &u16| Url::parse(&format!("https://127.0.0.1:{p}/")).unwrap();
        self.try_tally_with(er_url, self.ports.bb.iter().map(url).collect())
            .await
    }

    /// The tally, releasing ballots from `bb_urls` in place of the cluster's
    /// ballot boxes (e.g. stand-ins that withhold ballots).
    pub async fn try_tally_with_boxes(
        &self,
        bb_urls: Vec<Url>,
    ) -> Result<TallyOutcome, referendum_poc::actors::admin::AdminError> {
        let er_url = Url::parse(&format!("https://127.0.0.1:{}/", self.ports.er)).unwrap();
        self.try_tally_with(er_url, bb_urls).await
    }

    /// The tally over `bb_urls`, talking to the board through `wbb_url`.
    pub async fn try_tally_with_boxes_and_board(
        &self,
        bb_urls: Vec<Url>,
        wbb_url: Url,
    ) -> Result<TallyOutcome, referendum_poc::actors::admin::AdminError> {
        let url = |p: &u16| Url::parse(&format!("https://127.0.0.1:{p}/")).unwrap();
        self.try_tally_with_all(
            url(&self.ports.er),
            bb_urls,
            self.ports.tt.iter().map(url).collect(),
            wbb_url,
            Vec::new(),
        )
        .await
    }

    /// The tally over `bb_urls`, with the operator proceeding without the
    /// boxes in `proceed_without` should they give no release.
    pub async fn try_tally_with_boxes_without(
        &self,
        bb_urls: Vec<Url>,
        proceed_without: Vec<u64>,
    ) -> Result<TallyOutcome, referendum_poc::actors::admin::AdminError> {
        let url = |p: &u16| Url::parse(&format!("https://127.0.0.1:{p}/")).unwrap();
        self.try_tally_with_all(
            url(&self.ports.er),
            bb_urls,
            self.ports.tt.iter().map(url).collect(),
            self.wbb_url.clone(),
            proceed_without,
        )
        .await
    }

    /// The tally, driving `tt_urls` in place of the cluster's tabulation
    /// tellers (e.g. a stand-in that fails part-way through).
    pub async fn try_tally_with_tellers(
        &self,
        tt_urls: Vec<Url>,
    ) -> Result<TallyOutcome, referendum_poc::actors::admin::AdminError> {
        let url = |p: &u16| Url::parse(&format!("https://127.0.0.1:{p}/")).unwrap();
        let er_url = url(&self.ports.er);
        self.try_tally_with_all(
            er_url,
            self.ports.bb.iter().map(url).collect(),
            tt_urls,
            self.wbb_url.clone(),
            Vec::new(),
        )
        .await
    }

    /// The tally, driving `rt_urls` in place of the cluster's registration
    /// tellers (e.g. a stand-in that states the wrong control key share).
    pub async fn try_tally_with_rts(
        &self,
        rt_urls: Vec<Url>,
    ) -> Result<TallyOutcome, referendum_poc::actors::admin::AdminError> {
        let url = |p: &u16| Url::parse(&format!("https://127.0.0.1:{p}/")).unwrap();
        run_tally(TallyConfig {
            ceremony_dir: self.temp.path().to_path_buf(),
            er_url: url(&self.ports.er),
            bb_urls: self.ports.bb.iter().map(url).collect(),
            rt_urls,
            tt_urls: self.ports.tt.iter().map(url).collect(),
            wbb_url: self.wbb_url.clone(),
            ca_pem: self.ca.cert_pem().to_string(),
            clock: Clock::from_settings(&self.base.clock),
            n_acc: self.base.election.n_acc,
            t_tt: self.base.election.t_tt,
            t_rt: self.base.election.t_rt,
            proceed_without: Vec::new(),
        })
        .await
    }

    /// The tally, talking to the board through `wbb_url` (e.g. a stand-in
    /// that loses requests).
    pub async fn try_tally_with_board(
        &self,
        wbb_url: Url,
    ) -> Result<TallyOutcome, referendum_poc::actors::admin::AdminError> {
        let url = |p: &u16| Url::parse(&format!("https://127.0.0.1:{p}/")).unwrap();
        self.try_tally_with_all(
            url(&self.ports.er),
            self.ports.bb.iter().map(url).collect(),
            self.ports.tt.iter().map(url).collect(),
            wbb_url,
            Vec::new(),
        )
        .await
    }

    async fn try_tally_with(
        &self,
        er_url: Url,
        bb_urls: Vec<Url>,
    ) -> Result<TallyOutcome, referendum_poc::actors::admin::AdminError> {
        let url = |p: &u16| Url::parse(&format!("https://127.0.0.1:{p}/")).unwrap();
        self.try_tally_with_all(
            er_url,
            bb_urls,
            self.ports.tt.iter().map(url).collect(),
            self.wbb_url.clone(),
            Vec::new(),
        )
        .await
    }

    async fn try_tally_with_all(
        &self,
        er_url: Url,
        bb_urls: Vec<Url>,
        tt_urls: Vec<Url>,
        wbb_url: Url,
        proceed_without: Vec<u64>,
    ) -> Result<TallyOutcome, referendum_poc::actors::admin::AdminError> {
        let url = |p: &u16| Url::parse(&format!("https://127.0.0.1:{p}/")).unwrap();
        run_tally(TallyConfig {
            ceremony_dir: self.temp.path().to_path_buf(),
            wbb_url,
            er_url,
            bb_urls,
            rt_urls: self.ports.rt.iter().map(url).collect(),
            tt_urls,
            ca_pem: self.ca.cert_pem().to_string(),
            clock: Clock::from_settings(&self.base.clock),
            n_acc: self.base.election.n_acc,
            t_tt: self.base.election.t_tt,
            t_rt: self.base.election.t_rt,
            proceed_without,
        })
        .await
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
        // The harness board runs on the seed file in the cluster directory:
        // pin its log key from that seed, never from the board.
        let seed: [u8; 32] = std::fs::read(self.temp.path().join("wbb-log-seed.bin"))
            .expect("board seed")
            .try_into()
            .expect("32-byte board seed");
        AuditConfig {
            wbb_url: self.wbb_url.clone(),
            ca_pem: self.ca.cert_pem().to_string(),
            log_origin: referendum_poc::protocol::tlog::log_origin_of(&self.wbb_url),
            log_key: referendum_poc::protocol::tlog::derive_log_public_key(&seed).expect("log key"),
            validator_keys: Vec::new(),
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

    /// Boot a SECOND electoral roll, identical to the cluster's but talking
    /// to the bulletin board at `board_url` (e.g. a fault-injecting stand-in).
    /// Returns its base URL.
    pub async fn spawn_er_with_board(&self, board_url: &str) -> String {
        let ceremony_dir = self.temp.path().to_path_buf();
        let port = free_port();
        let mut settings = election_settings(&ceremony_dir, "er", port, &self.ports, &self.base);
        settings.wbb.base_url = board_url.to_string();
        let (addr, tls, state) = er::build_service(
            settings,
            ceremony_signing_key(&ceremony_dir, "er"),
            SecretString::new(read_admin_token(&ceremony_dir)),
        )
        .await
        .expect("build second er");
        tokio::spawn(async move {
            serve_rustls(er::router(state), addr, tls)
                .await
                .expect("second er server")
        });
        let base = format!("https://127.0.0.1:{port}");
        // Ready as soon as it answers anything over TLS.
        for _ in 0..200 {
            let ready = self.client.get(format!("{base}/health")).send().await;
            if ready.is_ok() {
                return base;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("the second electoral roll did not become ready on {base}")
    }

    /// Boot a SECOND copy of ballot box `name` (`bb-1`, ...), with the same
    /// key and identity, publishing to the bulletin board at `board_url`
    /// (e.g. a stand-in that refuses one kind of entry). Returns its base URL.
    pub async fn spawn_bb_with_board(&self, name: &str, board_url: &str) -> String {
        let ceremony_dir = self.temp.path().to_path_buf();
        let port = free_port();
        let mut settings = election_settings(&ceremony_dir, name, port, &self.ports, &self.base);
        settings.wbb.base_url = board_url.to_string();
        let (addr, tls, state) =
            bb::build_service(settings, ceremony_signing_key(&ceremony_dir, name))
                .await
                .expect("build second bb");
        tokio::spawn(async move {
            serve_rustls(bb::router(state), addr, tls)
                .await
                .expect("second bb server")
        });
        let base = format!("https://127.0.0.1:{port}");
        for _ in 0..200 {
            if self
                .client
                .get(format!("{base}/health"))
                .send()
                .await
                .is_ok()
            {
                return base;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("the second ballot box did not become ready on {base}")
    }

    /// The state directory of a voter server started by this cluster.
    pub fn voter_state_dir(&self, voter_base: &str) -> PathBuf {
        let port = voter_base.rsplit(':').next().expect("port");
        self.temp.path().join(format!("voter-state-{port}"))
    }

    /// Boot a SECOND voter server that talks to the electoral roll at
    /// `er_url` (e.g. a stand-in that lies about the identifier it assigns).
    pub async fn spawn_voter_with_er(&self, er_url: &str) -> String {
        self.spawn_voter_with(Some(er_url), None, &[]).await
    }

    /// A voter server whose notification service is `ns_url` (e.g. a stand-in
    /// that fails a registration).
    pub async fn spawn_voter_with_ns(&self, ns_url: &str) -> String {
        self.spawn_voter_with(None, Some(ns_url), &[]).await
    }

    /// A voter server whose peer `name` (`bb-1`, `rt-3`, ...) is reached
    /// through `url` instead of the cluster's service (e.g. a stand-in that
    /// lies).
    pub async fn spawn_voter_with_peers(&self, peers: &[(&str, String)]) -> String {
        self.spawn_voter_with(None, None, peers).await
    }

    pub async fn spawn_voter_with(
        &self,
        er_url: Option<&str>,
        ns_url: Option<&str>,
        peers: &[(&str, String)],
    ) -> String {
        self.spawn_voter_on_board(None, er_url, ns_url, peers).await
    }

    /// As `spawn_voter_with`, the app also reading the board at `wbb_url`
    /// (e.g. a stand-in that delays its answers).
    pub async fn spawn_voter_on_board(
        &self,
        wbb_url: Option<&str>,
        er_url: Option<&str>,
        ns_url: Option<&str>,
        peers: &[(&str, String)],
    ) -> String {
        let ceremony_dir = self.temp.path().to_path_buf();
        let port = free_port();
        let mut settings =
            election_settings(&ceremony_dir, "voter-1", port, &self.ports, &self.base);
        if let Some(wbb_url) = wbb_url {
            settings.wbb.base_url = wbb_url.to_string();
        }
        if let Some(er_url) = er_url {
            settings.er.base_url = er_url.to_string();
        }
        if let Some(ns_url) = ns_url {
            settings.ns.base_url = ns_url.to_string();
        }
        for (name, url) in peers {
            let peer = settings
                .peers
                .iter_mut()
                .find(|p| p.name == *name)
                .unwrap_or_else(|| panic!("no peer {name}"));
            peer.base_url = url.clone();
        }
        settings.voter.state_dir = ceremony_dir
            .join(format!("voter-state-{port}"))
            .display()
            .to_string();
        let (addr, tls, state) = voter::build_service(settings)
            .await
            .expect("build second voter server");
        tokio::spawn(async move {
            serve_rustls(voter::router(state), addr, tls)
                .await
                .expect("second voter server")
        });
        let base = format!("https://127.0.0.1:{port}");
        for _ in 0..200 {
            if self
                .client
                .get(format!("{base}/health"))
                .send()
                .await
                .is_ok()
            {
                return base;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("the second voter server did not become ready on {base}")
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
pub async fn enroll_on(client: &reqwest::Client, base_url: &str, fiscal_id: &str) -> String {
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

/// Wait until an enrollment's background step (device registration and PIN
/// request) has finished, successfully or not: the status screen then no
/// longer reports a PIN request in progress unless one is really open.
pub async fn wait_enrollment_settled(client: &reqwest::Client, base_url: &str, passphrase: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let status = post_json(
            client,
            &format!("{base_url}/api/status"),
            serde_json::json!({ "passphrase": passphrase }),
        )
        .await;
        if status["pin_request_open"] == false || status["pin_ready"] == true {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "enrollment never settled"
        );
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

/// GET with a bearer token (for endpoints the roll keeps private, such as
/// the live eligible list).
pub async fn get_json_with_token(
    client: &reqwest::Client,
    url: &str,
    token: &str,
) -> serde_json::Value {
    let response = client
        .get(url)
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("request");
    let status = response.status();
    let text = response.text().await.expect("body");
    assert!(
        status.is_success(),
        "GET {url} failed with {status}: {text}"
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

/// See [`ElectionCluster::vid_assignment`]; for tests that run their own ceremony.
#[allow(dead_code)]
pub fn vid_assignment(ceremony_dir: &Path, n_acc: usize) -> Vec<u64> {
    let seed: [u8; 32] = std::fs::read(ceremony_dir.join("er-seed.bin"))
        .expect("ER seed")
        .try_into()
        .expect("32-byte ER seed");
    referendum_poc::protocol::setup::assign_vids(
        &referendum_poc::protocol::rng::ActorSeed::from_bytes(seed),
        n_acc,
    )
}

/// What a stand-in does with a forwarded response:
/// `(path, request_body, status, response_body) -> what the caller sees`.
pub type Rewrite = std::sync::Arc<
    dyn Fn(
            &str,
            &[u8],
            reqwest::StatusCode,
            axum::body::Bytes,
        ) -> (reqwest::StatusCode, axum::body::Bytes)
        + Send
        + Sync,
>;
/// Decides BEFORE forwarding: `Some(response)` answers without forwarding
/// (a request lost on the wire), `None` forwards.
pub type Intercept = std::sync::Arc<
    dyn Fn(&str, &[u8]) -> Option<(reqwest::StatusCode, axum::body::Bytes)> + Send + Sync,
>;

/// A stand-in in front of a real service: forwards every request (method,
/// path, query, authorization and content type, body) and lets `intercept`
/// short-circuit a request or `rewrite` change what the caller sees.
#[derive(Clone)]
struct StandIn {
    real: Url,
    client: reqwest::Client,
    rewrite: Rewrite,
    intercept: Option<Intercept>,
}

pub fn passthrough() -> Rewrite {
    std::sync::Arc::new(|_, _, status, body| (status, body))
}

/// Spawn a stand-in in front of `real` and return its (plain HTTP) URL.
pub async fn spawn_stand_in(
    real: &Url,
    client: reqwest::Client,
    rewrite: Rewrite,
    intercept: Option<Intercept>,
) -> Url {
    use axum::{extract::State, Router};

    let stand_in = StandIn {
        real: real.clone(),
        client,
        rewrite,
        intercept,
    };
    let app = Router::new()
        .fallback(
            |State(s): State<StandIn>, request: axum::extract::Request| async move {
                let (parts, body) = request.into_parts();
                let body = axum::body::to_bytes(body, usize::MAX).await.unwrap();
                let path = parts.uri.path().trim_start_matches('/').to_string();
                if let Some(intercept) = &s.intercept {
                    if let Some(short) = intercept(&path, &body) {
                        return short;
                    }
                }
                let mut target = s.real.join(&path).unwrap();
                target.set_query(parts.uri.query());
                let mut forward = s
                    .client
                    .request(parts.method.clone(), target)
                    .body(body.clone());
                for name in ["authorization", "content-type"] {
                    if let Some(value) = parts.headers.get(name) {
                        forward = forward.header(name, value);
                    }
                }
                let response = forward.send().await.unwrap();
                let status = response.status();
                let bytes = response.bytes().await.unwrap();
                (s.rewrite)(&path, &body, status, bytes)
            },
        )
        .with_state(stand_in);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    url
}
