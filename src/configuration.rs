//! Hierarchical configuration (style guide §07).
//!
//! Sources, in increasing priority: `configuration/base.yaml`,
//! `configuration/{environment}.yaml` (optional), `APP_*` environment
//! variables (double-underscore nesting, e.g. `APP_SERVICE__PORT=9000`).
//! No configuration value is hard-coded anywhere else.

use std::path::Path;

use secrecy::Secret;
use serde::{Deserialize, Serialize};
use serde_aux::field_attributes::deserialize_number_from_string;

/// Root settings, shared shape for every service (per-service extras are
/// added by later milestones as their actors land).
#[derive(Debug, Clone, Deserialize)]
pub struct Settings {
    pub service: ServiceSettings,
    pub tls: TlsSettings,
    pub seeds: SeedSettings,
    pub clock: ClockSettings,
    pub wbb: WbbSettings,
    #[serde(default)]
    pub peers: Vec<PeerSettings>,
    pub election: ElectionSettings,
    pub dip: DipSettings,
    #[serde(default)]
    pub _ceremony: CeremonyPaths,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CeremonyPaths {
    #[serde(default)]
    pub seed_bin: String,
    #[serde(default)]
    pub sunlight_yaml: String,
    #[serde(default)]
    pub election_context: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServiceSettings {
    pub name: String,
    pub host: String,
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub port: u16,
}

/// TLS material locations (D16: rustls everywhere, cluster test CA).
#[derive(Debug, Clone, Deserialize)]
pub struct TlsSettings {
    pub cert_pem: String,
    pub key_pem: String,
    pub ca_pem: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SeedSettings {
    /// Hex-encoded 32-byte master seed. The value committed in
    /// `configuration/base.yaml` is the public **test-only** seed (D4);
    /// real deployments override via `APP_SEEDS__MASTER_SEED`.
    pub master_seed: Secret<String>,
}

/// Deterministic logical clock (D4/§9). Timestamps in artifacts are
/// `base_ms + tick * tick_ms`; never wall-clock.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClockSettings {
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub base_ms: u64,
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub tick_ms: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WbbSettings {
    /// e.g. `https://localhost:8090/wbb` (the log's submission prefix).
    pub base_url: String,
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub request_timeout_ms: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PeerSettings {
    pub name: String,
    pub base_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DipSettings {
    pub voters: Vec<DipVoter>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DipVoter {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElectionSettings {
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub n_rt: usize,
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub t_rt: usize,
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub n_tt: usize,
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub t_tt: usize,
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub n_bb: usize,
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub n_voters: usize,
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub n_acc: usize,
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub max_casts_per_voter: usize,
}

/// Runtime environment selector (`APP_ENVIRONMENT`: `local` | `production`).
pub enum Environment {
    Local,
    Production,
}

impl Environment {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Production => "production",
        }
    }
}

impl TryFrom<String> for Environment {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.to_lowercase().as_str() {
            "local" => Ok(Self::Local),
            "production" => Ok(Self::Production),
            other => Err(format!(
                "{other:?} is not a supported environment, use `local` or `production`"
            )),
        }
    }
}

/// Load settings from `{base_dir}/configuration/` with env overrides.
pub fn get_configuration(base_dir: &Path) -> Result<Settings, config::ConfigError> {
    let environment: Environment = std::env::var("APP_ENVIRONMENT")
        .unwrap_or_else(|_| "local".into())
        .try_into()
        .map_err(config::ConfigError::Message)?;

    let config_dir = base_dir.join("configuration");
    config::Config::builder()
        .add_source(config::File::from(config_dir.join("base.yaml")))
        .add_source(config::File::from(config_dir.join(environment.as_str())).required(false))
        .add_source(
            config::Environment::with_prefix("APP")
                .prefix_separator("_")
                .separator("__"),
        )
        .build()?
        .try_deserialize()
}

/// Serializes every test that touches `get_configuration` — it reads
/// process env (`APP_ENVIRONMENT`), so parallel env-mutating tests would
/// otherwise race (§9: tests must be deterministic on repeated runs).
/// `pub(crate)` so every test in the crate that loads settings shares it.
#[cfg(test)]
pub(crate) static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;

    /// Panic-safe env cleanup: removes the variable even if the test panics.
    struct EnvVarGuard(&'static str);

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            std::env::remove_var(self.0);
        }
    }

    #[test]
    fn base_yaml_loads() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let base_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let settings = get_configuration(base_dir).expect("base.yaml must load");
        assert_eq!(settings.service.name, "referendum-poc");
        assert_eq!(settings.election.n_rt, 3);
        assert_eq!(settings.election.t_rt, 2);
        assert_eq!(settings.election.n_acc, 10);
    }

    #[test]
    fn environment_parsing() {
        assert!(matches!(
            Environment::try_from("local".to_string()),
            Ok(Environment::Local)
        ));
        assert!(matches!(
            Environment::try_from("PRODUCTION".to_string()),
            Ok(Environment::Production)
        ));
        assert!(Environment::try_from("staging".to_string()).is_err());
    }

    #[test]
    fn invalid_app_environment_is_an_error_not_a_panic() {
        let _lock = ENV_LOCK.lock().expect("env lock");
        std::env::set_var("APP_ENVIRONMENT", "staging");
        let _cleanup = EnvVarGuard("APP_ENVIRONMENT");
        let result = get_configuration(Path::new(env!("CARGO_MANIFEST_DIR")));
        assert!(result.is_err(), "bad APP_ENVIRONMENT must return Err");
    }
}
