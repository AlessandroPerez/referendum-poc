//! Shared e2e harness (spawn cluster, seeded determinism, WBB process).
//! Grows per roadmap milestones M2+.

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
    clients::wbb::WbbClient,
    protocol::tls::{reqwest_client_trusting_ca, ClusterCa},
};
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

pub fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind free port");
    listener.local_addr().unwrap().port()
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
