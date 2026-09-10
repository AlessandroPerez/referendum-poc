//! File-system artifacts produced by the setup ceremony.
//!
//! Writes the election context, master seed, WBB configuration, TLS material,
//! per-service configs, and DKG share files into an output directory so that
//! every service can be started from the same deterministic state.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use curve25519_dalek::scalar::Scalar;
use secrecy::ExposeSecret;
use serde::de::Error as DeError;

use crate::actors::common::actor_signing_key;
use crate::configuration::{DipSettings, ElectionSettings, Settings};
use crate::protocol::merkle::voter_id_merkle_root;
use crate::protocol::rng::MasterSeed;
use crate::protocol::setup::CeremonyOutput;
use crate::protocol::tls::{issue_service_cert, ClusterCa};

/// All paths and bytes produced by the ceremony.
pub struct ArtifactPaths {
    pub output_dir: PathBuf,
    pub ca_pem: PathBuf,
    pub seed_bin: PathBuf,
    pub election_context_json: PathBuf,
    pub rt_public_key_json: PathBuf,
    pub tt_public_key_json: PathBuf,
    pub sunlight_yaml: PathBuf,
    pub checkpoints_db: PathBuf,
    pub service_configs: HashMap<String, PathBuf>,
    pub service_certs: HashMap<String, (PathBuf, PathBuf)>,
    pub service_signing_keys: HashMap<String, PathBuf>,
    pub er_admin_token: Option<PathBuf>,
    pub rt_share_files: Vec<PathBuf>,
    pub tt_share_files: Vec<PathBuf>,
}

/// Errors during artifact generation.
#[derive(Debug, thiserror::Error)]
pub enum ArtifactError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("YAML error: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("TLS error: {0}")]
    Tls(#[from] crate::protocol::tls::TlsError),
    #[error("sqlite3 init failed")]
    SqliteInit,
}

/// Write every artifact required to boot the cluster.
pub fn write_artifacts(
    output_dir: &Path,
    base_settings: &Settings,
    ceremony: &CeremonyOutput,
    master_seed: &MasterSeed,
    dip: &DipSettings,
) -> Result<ArtifactPaths, ArtifactError> {
    fs::create_dir_all(output_dir)?;

    // 1. Master seed.
    let seed_bin = output_dir.join("seed.bin");
    master_seed.expose(|seed| fs::write(&seed_bin, seed.as_slice()))?;

    // 2. Election context JSON + public keys needed by services.
    let election_context_json = output_dir.join("election_context.json");
    fs::write(
        &election_context_json,
        serde_json::to_string_pretty(&ceremony.election_context)?,
    )?;
    let rt_public_key_json = output_dir.join("rt_public_key.json");
    fs::write(
        &rt_public_key_json,
        serde_json::to_string_pretty(&ceremony.rt_pk)?,
    )?;
    let tt_public_key_json = output_dir.join("tt_public_key.json");
    fs::write(
        &tt_public_key_json,
        serde_json::to_string_pretty(&ceremony.master_tt_pk)?,
    )?;

    // 3. Cluster CA + service certs. The CA and every service key are
    //    deterministically derived from the master seed.
    let mut master_seed_bytes = [0u8; 32];
    master_seed.expose(|seed| master_seed_bytes.copy_from_slice(seed));
    let ca = ClusterCa::from_seed(&master_seed_bytes)?;
    let ca_pem = output_dir.join("ca.pem");
    fs::write(&ca_pem, ca.cert_pem())?;

    // The WBB serves TLS via sunlight's `-testcert` flag, which reads
    // `sunlight.pem`/`sunlight-key.pem` from its working directory.
    let wbb_cert = issue_service_cert(&ca, "wbb", &derive_service_seed(&master_seed_bytes, "wbb"))?;
    fs::write(output_dir.join("sunlight.pem"), wbb_cert.cert_pem())?;
    fs::write(output_dir.join("sunlight-key.pem"), wbb_cert.key_pem())?;

    // Generic admin identity backing the `cert.pem`/`key.pem` paths in the
    // self-contained base.yaml (the CLIs only need `ca.pem`; servers get
    // per-service certs via APP_TLS__* overrides).
    let admin_cert = issue_service_cert(
        &ca,
        "admin",
        &derive_service_seed(&master_seed_bytes, "admin"),
    )?;
    fs::write(output_dir.join("cert.pem"), admin_cert.cert_pem())?;
    fs::write(output_dir.join("key.pem"), admin_cert.key_pem())?;

    let mut service_certs = HashMap::new();
    let mut service_signing_keys = HashMap::new();
    let service_names = service_names(&base_settings.election);
    for (name, _) in &service_names {
        let service_seed = derive_service_seed(&master_seed_bytes, name);
        let cert = issue_service_cert(&ca, name, &service_seed)?;
        let cert_path = output_dir.join(format!("{name}.pem"));
        let key_path = output_dir.join(format!("{name}-key.pem"));
        fs::write(&cert_path, cert.cert_pem())?;
        fs::write(&key_path, cert.key_pem())?;
        service_certs.insert(name.clone(), (cert_path, key_path));

        // Per-service Ed25519 signing key for WBB entries (derived from master
        // seed, but each service config only sees its own key file, never the
        // master seed).
        let entity_id = service_entity_id(name);
        let signing_key = actor_signing_key(master_seed, &entity_id);
        let signing_key_path = output_dir.join(format!("{name}-signing-key.bin"));
        fs::write(&signing_key_path, signing_key.to_bytes())?;
        service_signing_keys.insert(name.clone(), signing_key_path);
        // Public counterpart for external verifiers (the auditor must not
        // need any secret material to check entry signatures).
        fs::write(
            output_dir.join(format!("{name}-verifying-key.bin")),
            signing_key.verifying_key().as_bytes(),
        )?;

        // Per-service bearer token for internal endpoint authentication.
        let service_token = derive_service_token(master_seed, name);
        let service_token_path = output_dir.join(format!("{name}-service-token.txt"));
        fs::write(&service_token_path, service_token.expose_secret())?;

        // Dedicated per-service operation seed so protocol RNGs are
        // not derived from the WBB entry-signing keys.
        let op_seed = master_seed.actor_seed(name);
        fs::write(output_dir.join(format!("{name}-seed.bin")), op_seed.bytes())?;
    }

    // ER admin token is a separate secret file.
    let admin_token = derive_admin_token(master_seed);
    let admin_token_path = output_dir.join("er-admin-token.txt");
    fs::write(&admin_token_path, admin_token.expose_secret())?;

    // Shared internal-API token authenticating service->service calls that are
    // not voter-facing (e.g. ER `/tokens/verify`).
    let internal_token = derive_service_token(master_seed, "internal-api");
    fs::write(
        output_dir.join("internal-api-token.txt"),
        internal_token.expose_secret(),
    )?;

    // Per-voter deterministic seeds + TLS certs .  Voter
    // servers are not WBB entities, so they get no entry in `sunlight.yaml`;
    // each instance only ever sees its own seed file.
    // `wbb-ui` (public read proxy) gets a TLS cert but is not a WBB entity.
    let mut non_entity_services: Vec<String> = (1..=base_settings.election.n_voters)
        .map(|i| format!("voter-{i}"))
        .collect();
    non_entity_services.push("wbb-ui".to_string());
    for name in non_entity_services {
        let actor_seed = master_seed.actor_seed(&name);
        fs::write(
            output_dir.join(format!("{name}-seed.bin")),
            actor_seed.bytes(),
        )?;
        let service_seed = derive_service_seed(&master_seed_bytes, &name);
        let cert = issue_service_cert(&ca, &name, &service_seed)?;
        fs::write(output_dir.join(format!("{name}.pem")), cert.cert_pem())?;
        fs::write(output_dir.join(format!("{name}-key.pem")), cert.key_pem())?;
    }

    // 4. WBB config and checkpoints DB.
    let sunlight_yaml = output_dir.join("sunlight.yaml");
    let checkpoints_db = output_dir.join("checkpoints.db");
    init_checkpoints_db(&checkpoints_db)?;

    let wbb_port = 8090u16;
    let host = "127.0.0.1";
    let yaml = build_sunlight_yaml(
        host,
        wbb_port,
        &seed_bin,
        &checkpoints_db,
        output_dir,
        base_settings,
        master_seed,
    );
    fs::write(&sunlight_yaml, yaml)?;

    // 5. Per-service configs.
    let mut service_configs = HashMap::new();
    for (name, _) in &service_names {
        let (cert, key) = service_certs.get(name).cloned().unwrap();
        let port = service_port(name);
        let cfg = build_service_config(
            name,
            host,
            port,
            &ca_pem,
            &cert,
            &key,
            &seed_bin,
            base_settings,
            &sunlight_yaml,
        );
        let path = output_dir.join(format!("{name}.yaml"));
        fs::write(&path, serde_yaml::to_string(&cfg)?)?;
        service_configs.insert(name.clone(), path);
    }

    // 5.5 Copy the base configuration into the ceremony directory with
    // absolute paths so that `election-admin -c <output_dir>` works without
    // further environment overrides.
    write_self_contained_base_config(output_dir, base_settings, host)?;

    // 6. DKG share files.
    let mut rt_share_files = Vec::new();
    for (i, rt) in ceremony.rt_tellers.iter().enumerate() {
        let path = output_dir.join(format!("rt-{}-share.json", i + 1));
        let file = RtShareFile {
            id: rt.share.id,
            secret_scalar_share: scalar_to_b64(&rt.share.secret_scalar_share),
            local_y_contrib: scalar_to_b64(&rt.share.local_y_contrib),
            meg_sk1_share: scalar_to_b64(&rt.share.meg_sk1_share),
            meg_sk2_share: scalar_to_b64(&rt.share.meg_sk2_share),
        };
        fs::write(&path, serde_json::to_string_pretty(&file)?)?;
        rt_share_files.push(path);
    }

    let mut tt_share_files = Vec::new();
    for (i, tt) in ceremony.tt_tellers.iter().enumerate() {
        let path = output_dir.join(format!("tt-{}-share.json", i + 1));
        let file = TtShareFile {
            id: tt.share.id,
            meg_sk1_share: scalar_to_b64(&tt.share.meg_sk1_share),
            meg_sk2_share: scalar_to_b64(&tt.share.meg_sk2_share),
        };
        fs::write(&path, serde_json::to_string_pretty(&file)?)?;
        tt_share_files.push(path);
    }

    // 7. Voter Merkle root (for inspection, not required by services).
    let vids = crate::protocol::setup::assign_vids(base_settings.election.n_voters);
    let voter_ids: Vec<_> = dip.voters.iter().map(|v| v.id.clone()).collect();
    let pairs = crate::protocol::setup::voter_pairs(&voter_ids, &vids);
    let root = voter_id_merkle_root(&pairs);
    fs::write(
        output_dir.join("voter_id_merkle_root.txt"),
        hex::encode(root),
    )?;

    restrict_secret_permissions(output_dir)?;

    Ok(ArtifactPaths {
        output_dir: output_dir.to_path_buf(),
        ca_pem,
        seed_bin,
        election_context_json,
        rt_public_key_json,
        tt_public_key_json,
        sunlight_yaml,
        checkpoints_db,
        service_configs,
        service_certs,
        service_signing_keys,
        er_admin_token: Some(admin_token_path),
        rt_share_files,
        tt_share_files,
    })
}

fn derive_service_seed(master_seed: &[u8; 32], service_name: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(master_seed);
    hasher.update(service_name.as_bytes());
    hasher.finalize().into()
}

/// Map a service file-name like "rt-1" or "bb-2" to its WBB entity id.
fn service_entity_id(name: &str) -> String {
    match name {
        "er" => "ER-1".to_string(),
        "dip" => "DIP-1".to_string(),
        "ns" => "NS-1".to_string(),
        "pm" => "PM-1".to_string(),
        other if other.starts_with("rt-") => other.to_uppercase(),
        other if other.starts_with("tt-") => other.to_uppercase(),
        other if other.starts_with("bb-") => other.to_uppercase(),
        other => other.to_uppercase(),
    }
}

/// Deterministic ER admin token derived from the master seed.
fn derive_admin_token(master_seed: &MasterSeed) -> secrecy::SecretString {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    master_seed.expose(|seed| hasher.update(seed));
    hasher.update(b"admin-token");
    secrecy::SecretString::new(hex::encode(hasher.finalize()))
}

/// Deterministic service bearer token derived from the master seed.
fn derive_service_token(master_seed: &MasterSeed, service_name: &str) -> secrecy::SecretString {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    master_seed.expose(|seed| hasher.update(seed));
    hasher.update(service_name.as_bytes());
    hasher.update(b"service-token");
    secrecy::SecretString::new(hex::encode(hasher.finalize()))
}

fn service_names(settings: &ElectionSettings) -> Vec<(String, String)> {
    let mut names = vec![("er".to_string(), "er".to_string())];
    names.push(("dip".to_string(), "dip".to_string()));
    names.push(("ns".to_string(), "ns".to_string()));
    for i in 1..=settings.n_rt {
        names.push((format!("rt-{i}"), format!("rt-{i}")));
    }
    for i in 1..=settings.n_tt {
        names.push((format!("tt-{i}"), format!("tt-{i}")));
    }
    for i in 1..=settings.n_bb {
        names.push((format!("bb-{i}"), format!("bb-{i}")));
    }
    names.push(("pm".to_string(), "pm".to_string()));
    names
}

fn service_port(name: &str) -> u16 {
    match name {
        "er" => 8001,
        "dip" => 8002,
        "ns" => 8003,
        "rt-1" => 8011,
        "rt-2" => 8012,
        "rt-3" => 8013,
        "tt-1" => 8021,
        "tt-2" => 8022,
        "tt-3" => 8023,
        "bb-1" => 8031,
        "bb-2" => 8032,
        "pm" => 8040,
        _ => 9000,
    }
}

/// Make every secret artifact owner-readable only (0600): seeds, signing
/// keys, TLS private keys, bearer tokens, and DKG share files.  Public
/// material (certificates, verifying keys, the election context, configs)
/// keeps the default mode.
fn restrict_secret_permissions(output_dir: &Path) -> Result<(), ArtifactError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let is_secret = |name: &str| {
            name == "seed.bin"
                || name == "key.pem"
                || name.ends_with("-key.pem")
                || name.ends_with("-signing-key.bin")
                || name.ends_with("-seed.bin")
                || name.ends_with("-token.txt")
                || name.ends_with("-share.json")
        };
        for entry in fs::read_dir(output_dir)? {
            let entry = entry?;
            let name = entry.file_name();
            if entry.file_type()?.is_file() && is_secret(&name.to_string_lossy()) {
                fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o600))?;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = output_dir;
    }
    Ok(())
}

/// Write a copy of `configuration/base.yaml` into `<output_dir>/configuration/`
/// with absolute TLS paths and a concrete WBB URL. This makes the ceremony
/// output self-contained: `election-admin -c <output_dir>` loads without
/// `APP_TLS__CA_PEM` overrides.
fn write_self_contained_base_config(
    output_dir: &Path,
    base_settings: &Settings,
    host: &str,
) -> Result<(), ArtifactError> {
    let config_dir = output_dir.join("configuration");
    fs::create_dir_all(&config_dir)?;

    let mut value: serde_yaml::Value =
        serde_yaml::from_slice(include_bytes!("../../../configuration/base.yaml"))?;
    let mapping = value
        .as_mapping_mut()
        .ok_or_else(|| ArtifactError::Yaml(DeError::custom("base.yaml root is not a mapping")))?;

    let make_absolute = |rel: &str| output_dir.join(rel).display().to_string();

    if let Some(tls) = mapping.get_mut(serde_yaml::Value::String("tls".to_string())) {
        if let Some(tls_map) = tls.as_mapping_mut() {
            tls_map.insert(
                serde_yaml::Value::String("cert_pem".to_string()),
                serde_yaml::Value::String(make_absolute("cert.pem")),
            );
            tls_map.insert(
                serde_yaml::Value::String("key_pem".to_string()),
                serde_yaml::Value::String(make_absolute("key.pem")),
            );
            tls_map.insert(
                serde_yaml::Value::String("ca_pem".to_string()),
                serde_yaml::Value::String(make_absolute("ca.pem")),
            );
        }
    }

    if let Some(wbb) = mapping.get_mut(serde_yaml::Value::String("wbb".to_string())) {
        if let Some(wbb_map) = wbb.as_mapping_mut() {
            wbb_map.insert(
                serde_yaml::Value::String("base_url".to_string()),
                serde_yaml::Value::String(format!("https://{host}:8090/wbb")),
            );
        }
    }

    // Ensure the election block contains the inner threshold. If the bundled
    // base.yaml already has it this is a no-op.
    if let Some(election) = mapping.get_mut(serde_yaml::Value::String("election".to_string())) {
        if let Some(election_map) = election.as_mapping_mut() {
            election_map.insert(
                serde_yaml::Value::String("t_prime".to_string()),
                serde_yaml::Value::Number(base_settings.election.t_prime.into()),
            );
        }
    }

    // Absolute ceremony paths so servers booted with this config resolve the
    // election context, seed, and share files without env overrides.
    mapping.insert(
        serde_yaml::Value::String("_ceremony".to_string()),
        serde_yaml::to_value(serde_yaml::Mapping::from_iter([
            (
                serde_yaml::Value::String("seed_bin".to_string()),
                serde_yaml::Value::String(make_absolute("seed.bin")),
            ),
            (
                serde_yaml::Value::String("sunlight_yaml".to_string()),
                serde_yaml::Value::String(make_absolute("sunlight.yaml")),
            ),
            (
                serde_yaml::Value::String("election_context".to_string()),
                serde_yaml::Value::String(make_absolute("election_context.json")),
            ),
        ]))?,
    );

    fs::write(config_dir.join("base.yaml"), serde_yaml::to_string(&value)?)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_service_config(
    name: &str,
    host: &str,
    port: u16,
    ca_pem: &Path,
    cert_pem: &Path,
    key_pem: &Path,
    seed_bin: &Path,
    settings: &Settings,
    sunlight_yaml: &Path,
) -> serde_yaml::Value {
    let mut map = serde_yaml::Mapping::new();
    map.insert(
        serde_yaml::Value::String("service".to_string()),
        serde_yaml::to_value(serde_yaml::Mapping::from_iter([
            (
                serde_yaml::Value::String("name".to_string()),
                serde_yaml::Value::String(name.to_string()),
            ),
            (
                serde_yaml::Value::String("host".to_string()),
                serde_yaml::Value::String(host.to_string()),
            ),
            (
                serde_yaml::Value::String("port".to_string()),
                serde_yaml::Value::Number(port.into()),
            ),
        ]))
        .unwrap(),
    );
    map.insert(
        serde_yaml::Value::String("tls".to_string()),
        serde_yaml::to_value(serde_yaml::Mapping::from_iter([
            (
                serde_yaml::Value::String("cert_pem".to_string()),
                serde_yaml::Value::String(cert_pem.display().to_string()),
            ),
            (
                serde_yaml::Value::String("key_pem".to_string()),
                serde_yaml::Value::String(key_pem.display().to_string()),
            ),
            (
                serde_yaml::Value::String("ca_pem".to_string()),
                serde_yaml::Value::String(ca_pem.display().to_string()),
            ),
        ]))
        .unwrap(),
    );
    map.insert(
        serde_yaml::Value::String("clock".to_string()),
        serde_yaml::to_value(&settings.clock).unwrap(),
    );
    map.insert(
        serde_yaml::Value::String("wbb".to_string()),
        serde_yaml::to_value(serde_yaml::Mapping::from_iter([
            (
                serde_yaml::Value::String("base_url".to_string()),
                serde_yaml::Value::String(format!("https://{host}:8090/wbb")),
            ),
            (
                serde_yaml::Value::String("request_timeout_ms".to_string()),
                serde_yaml::Value::Number(10000.into()),
            ),
        ]))
        .unwrap(),
    );
    map.insert(
        serde_yaml::Value::String("election".to_string()),
        serde_yaml::to_value(&settings.election).unwrap(),
    );
    map.insert(
        serde_yaml::Value::String("dip".to_string()),
        serde_yaml::to_value(&settings.dip).unwrap(),
    );
    map.insert(
        serde_yaml::Value::String("_ceremony".to_string()),
        serde_yaml::to_value(serde_yaml::Mapping::from_iter([
            (
                serde_yaml::Value::String("seed_bin".to_string()),
                serde_yaml::Value::String(seed_bin.display().to_string()),
            ),
            (
                serde_yaml::Value::String("sunlight_yaml".to_string()),
                serde_yaml::Value::String(sunlight_yaml.display().to_string()),
            ),
            (
                serde_yaml::Value::String("election_context".to_string()),
                serde_yaml::Value::String(
                    seed_bin
                        .parent()
                        .unwrap()
                        .join("election_context.json")
                        .display()
                        .to_string(),
                ),
            ),
        ]))
        .unwrap(),
    );
    serde_yaml::Value::Mapping(map)
}

fn build_sunlight_yaml(
    host: &str,
    port: u16,
    seed_bin: &Path,
    checkpoints_db: &Path,
    output_dir: &Path,
    settings: &Settings,
    master_seed: &MasterSeed,
) -> String {
    let today = time::OffsetDateTime::now_utc().date().to_string();

    let mut entity_keys = String::new();
    for i in 1..=settings.election.n_rt {
        let key = actor_signing_key(master_seed, &format!("RT-{i}"));
        entity_keys.push_str(&format!(
            "      RT-{i}: {}\n",
            BASE64.encode(key.verifying_key().as_bytes())
        ));
    }
    for i in 1..=settings.election.n_tt {
        let key = actor_signing_key(master_seed, &format!("TT-{i}"));
        entity_keys.push_str(&format!(
            "      TT-{i}: {}\n",
            BASE64.encode(key.verifying_key().as_bytes())
        ));
    }
    // ER is also an eligible signer for setup entries.
    let er_key_obj = actor_signing_key(master_seed, "ER-1");
    entity_keys.push_str(&format!(
        "      ER-1: {}\n",
        BASE64.encode(er_key_obj.verifying_key().as_bytes())
    ));
    for i in 1..=settings.election.n_bb {
        let key = actor_signing_key(master_seed, &format!("BB-{i}"));
        entity_keys.push_str(&format!(
            "      BB-{i}: {}\n",
            BASE64.encode(key.verifying_key().as_bytes())
        ));
    }
    let pm_key = actor_signing_key(master_seed, "PM-1");
    entity_keys.push_str(&format!(
        "      PM-1: {}\n",
        BASE64.encode(pm_key.verifying_key().as_bytes())
    ));

    let mut yaml = String::new();
    yaml.push_str("listen:\n");
    yaml.push_str(&format!("  - \"{}:{}\"\n", host, port));
    yaml.push_str(&format!("checkpoints: {}\n", checkpoints_db.display()));
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
    yaml.push_str(&format!("    secret: {}\n", seed_bin.display()));
    yaml.push_str("    poolsize: 1000\n");
    yaml.push_str(&format!(
        "    cache: {}\n",
        output_dir.join("cache.db").display()
    ));
    yaml.push_str(&format!(
        "    localdirectory: {}\n",
        output_dir.join("logdata").display()
    ));
    yaml.push_str("    entity_keys:\n");
    yaml.push_str(&entity_keys);
    yaml.push_str(&format!(
        "    phase_manager_key: {}\n",
        BASE64.encode(pm_key.verifying_key().as_bytes())
    ));
    yaml.push_str("    disable_timestamp_validation: true\n");
    yaml.push_str("    grace_period_ms: 100\n");
    yaml.push_str("    max_submit_body_bytes: 33554432\n");
    yaml
}

fn init_checkpoints_db(path: &Path) -> Result<(), ArtifactError> {
    if path.exists() {
        fs::remove_file(path)?;
    }
    let status = Command::new("sqlite3")
        .arg(path)
        .arg("CREATE TABLE checkpoints (logID BLOB PRIMARY KEY, body BLOB NOT NULL) STRICT")
        .status()?;
    if !status.success() {
        return Err(ArtifactError::SqliteInit);
    }
    Ok(())
}

/// On-disk representation of an RT key share.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct RtShareFile {
    pub id: usize,
    pub secret_scalar_share: String,
    pub local_y_contrib: String,
    pub meg_sk1_share: String,
    pub meg_sk2_share: String,
}

/// On-disk representation of a TT key share.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct TtShareFile {
    pub id: usize,
    pub meg_sk1_share: String,
    pub meg_sk2_share: String,
}

fn scalar_to_b64(scalar: &Scalar) -> String {
    BASE64.encode(scalar.to_bytes())
}
