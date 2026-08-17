//! Registration Teller (RT) server (M4).
//!
//! Implements the endpoints required for milestone M4:
//!   - `POST /sign`       — Ed25519-sign a WBB data string.
//!   - `POST /decoy`      — generate a decoy credential builder + ruse PIN.
//!   - `GET  /status`     — readiness + entity id.
//!
//! The service loads its DKG share and reconstructs its
//! `ThresholdRegistrationTeller` in memory; no network is needed for the
//! threshold math at this milestone.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use axum::{
    extract::Extension,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::Engine as _;
use dlog_group::ristretto::RistrettoGroup;
use ed25519_dalek::{Signer, SigningKey};
use evoting::api::server::bb::ElectionContext;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::actors::common::{health_router, serve_rustls, with_state};
use crate::configuration::Settings;
use crate::protocol::acc::{load_rt_share, reconstruct_rt_teller};
use crate::protocol::clock::LogicalClock;
use crate::protocol::tls::{reqwest_client_trusting_ca, rustls_config_for_service};

/// RT service state.
#[derive(Clone)]
pub struct RtState {
    entity_id: String,
    signing_key_seed: SecretString,
    service_token: SecretString,
    election_context: ElectionContext<RistrettoGroup>,
    rt_pk: evoting::api::prelude::RTPublicKey<RistrettoGroup>,
    share_path: std::path::PathBuf,
    clock: LogicalClock,
    decoy_counter: Arc<AtomicU64>,
}

impl std::fmt::Debug for RtState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RtState")
            .field("entity_id", &self.entity_id)
            .field("signing_key_seed", &"<redacted>")
            .field("service_token", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl RtState {
    pub fn new(
        entity_id: String,
        signing_key: SigningKey,
        service_token: SecretString,
        election_context: ElectionContext<RistrettoGroup>,
        rt_pk: evoting::api::prelude::RTPublicKey<RistrettoGroup>,
        share_path: std::path::PathBuf,
        clock: LogicalClock,
    ) -> Self {
        Self {
            entity_id,
            signing_key_seed: SecretString::new(hex::encode(signing_key.to_bytes())),
            service_token,
            election_context,
            rt_pk,
            share_path,
            clock,
            decoy_counter: Arc::new(AtomicU64::new(0)),
        }
    }

    fn signing_key(&self) -> SigningKey {
        let seed = hex::decode(self.signing_key_seed.expose_secret())
            .expect("valid hex seed")
            .try_into()
            .expect("seed length is 32");
        SigningKey::from_bytes(&seed)
    }

    fn next_decoy_rng(&self) -> ChaCha20Rng {
        let counter = self.decoy_counter.fetch_add(1, Ordering::SeqCst);
        let mut hasher = Sha256::new();
        hasher.update(self.signing_key_seed.expose_secret().as_bytes());
        hasher.update(b"decoy");
        hasher.update(counter.to_le_bytes());
        ChaCha20Rng::from_seed(hasher.finalize().into())
    }

    fn require_bearer(&self, headers: &HeaderMap) -> Result<(), RtError> {
        let expected = self.service_token.expose_secret();
        let header = headers
            .get("authorization")
            .ok_or(RtError::Unauthorized)?
            .to_str()
            .map_err(|_| RtError::Unauthorized)?;
        let Some(token) = header.strip_prefix("Bearer ") else {
            return Err(RtError::Unauthorized);
        };
        if !constant_time_eq::constant_time_eq(token.as_bytes(), expected.as_bytes()) {
            return Err(RtError::Unauthorized);
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignRequest {
    pub data: String,
    /// Optional logical timestamp in milliseconds. When omitted the server uses
    /// its own logical clock. The coordinator should supply this so that all
    /// co-signers share the same timestamp for a given artifact.
    #[serde(default)]
    pub timestamp: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct SignResponse {
    pub entity_id: String,
    pub timestamp: i64,
    pub signature: String,
}

async fn sign_handler(
    Extension(state): Extension<Arc<RtState>>,
    headers: HeaderMap,
    Json(req): Json<SignRequest>,
) -> Result<Json<SignResponse>, RtError> {
    state.require_bearer(&headers)?;
    let entity_id = state.entity_id.clone();
    let timestamp = req.timestamp.unwrap_or_else(|| state.clock.now_ms() as i64);
    let signing_key = state.signing_key();
    let data = req.data;

    let signature = tokio::task::spawn_blocking(move || {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        hasher.update(entity_id.as_bytes());
        hasher.update(format!("{timestamp}").as_bytes());
        let message = hasher.finalize();
        signing_key.sign(&message)
    })
    .await
    .map_err(|e| RtError::Internal(e.to_string()))?;

    Ok(Json(SignResponse {
        entity_id: state.entity_id.clone(),
        timestamp,
        signature: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
    }))
}

#[derive(Debug, Serialize)]
pub struct DecoyResponse {
    pub builder: evoting::api::prelude::VotingCredentialBuilder<RistrettoGroup>,
    pub pin: usize,
}

async fn decoy_handler(
    Extension(state): Extension<Arc<RtState>>,
    headers: HeaderMap,
) -> Result<Json<DecoyResponse>, RtError> {
    state.require_bearer(&headers)?;
    let mut rng = state.next_decoy_rng();
    let election_context = state.election_context.clone();
    let rt_pk = state.rt_pk.clone();
    let share_path = state.share_path.clone();

    let (builder, pin) = tokio::task::spawn_blocking(move || {
        let share = load_rt_share(&share_path).map_err(|e| RtError::Internal(e.to_string()))?;
        let teller = reconstruct_rt_teller(share, &election_context, &rt_pk);
        Ok::<_, RtError>(teller.gen_decoy_builder(&mut rng))
    })
    .await
    .map_err(|e| RtError::Internal(e.to_string()))??;

    Ok(Json(DecoyResponse { builder, pin }))
}

#[derive(Debug, Serialize)]
pub struct StatusResponse {
    pub entity_id: String,
    pub status: &'static str,
}

async fn status_handler(Extension(state): Extension<Arc<RtState>>) -> Json<StatusResponse> {
    Json(StatusResponse {
        entity_id: state.entity_id.clone(),
        status: "ok",
    })
}

#[derive(Debug, thiserror::Error)]
enum RtError {
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unauthorized")]
    Unauthorized,
    #[error("internal error: {0}")]
    Internal(String),
}

impl IntoResponse for RtError {
    fn into_response(self) -> Response {
        let status = match &self {
            Self::Json(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (
            status,
            Json(serde_json::json!({ "error": self.to_string() })),
        )
            .into_response()
    }
}

pub fn router(state: Arc<RtState>) -> Router {
    with_state(
        health_router()
            .route("/sign", post(sign_handler))
            .route("/decoy", post(decoy_handler))
            .route("/status", get(status_handler)),
        state,
    )
}

/// Run the RT service from settings and signing key.
pub async fn run(settings: Settings, signing_key: SigningKey) -> anyhow::Result<()> {
    let (addr, rustls_config, state) = build_service(settings, signing_key).await?;
    serve_rustls(router(state), addr, rustls_config).await
}

/// Build the RT service components without blocking on `serve_rustls`.
pub async fn build_service(
    settings: Settings,
    signing_key: SigningKey,
) -> anyhow::Result<(
    SocketAddr,
    axum_server::tls_rustls::RustlsConfig,
    Arc<RtState>,
)> {
    let election_context = load_election_context(&settings).await?;
    let rt_pk = load_rt_public_key(&settings).await?;
    let share_path = rt_share_path(&settings).await?;
    let service_token = load_service_token(&settings).await?;
    let clock = LogicalClock::new(settings.clock.base_ms, settings.clock.tick_ms);

    let entity_id = entity_id_from_name(&settings.service.name);
    let state = Arc::new(RtState::new(
        entity_id,
        signing_key,
        service_token,
        election_context,
        rt_pk,
        share_path,
        clock,
    ));

    let addr: SocketAddr = format!("{}:{}", settings.service.host, settings.service.port)
        .parse()
        .expect("valid service address");

    let cert_pem = tokio::fs::read_to_string(&settings.tls.cert_pem)
        .await
        .map_err(|e| anyhow::anyhow!("failed to read TLS cert: {e}"))?;
    let key_pem = tokio::fs::read_to_string(&settings.tls.key_pem)
        .await
        .map_err(|e| anyhow::anyhow!("failed to read TLS key: {e}"))?;
    let rustls_config = rustls_config_for_service(&cert_pem, &key_pem)
        .await
        .map_err(|e| anyhow::anyhow!("failed to load TLS config: {e}"))?;

    Ok((addr, rustls_config, state))
}

async fn load_election_context(
    settings: &Settings,
) -> anyhow::Result<ElectionContext<RistrettoGroup>> {
    let path = std::path::PathBuf::from(&settings._ceremony.election_context);
    let bytes = tokio::fs::read(&path)
        .await
        .map_err(|e| anyhow::anyhow!("failed to read {}: {}", path.display(), e))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| anyhow::anyhow!("failed to parse election context: {e}"))
}

async fn load_rt_public_key(
    settings: &Settings,
) -> anyhow::Result<evoting::api::prelude::RTPublicKey<RistrettoGroup>> {
    let context_path = std::path::PathBuf::from(&settings._ceremony.election_context);
    let path = context_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("rt_public_key.json");
    let bytes = tokio::fs::read(&path)
        .await
        .map_err(|e| anyhow::anyhow!("failed to read {}: {}", path.display(), e))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| anyhow::anyhow!("failed to parse RT public key: {e}"))
}

async fn rt_share_path(settings: &Settings) -> anyhow::Result<std::path::PathBuf> {
    let context_path = std::path::PathBuf::from(&settings._ceremony.election_context);
    let base_dir = context_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let idx = rt_index_from_name(&settings.service.name)?;
    Ok(base_dir.join(format!("rt-{idx}-share.json")))
}

async fn load_service_token(settings: &Settings) -> anyhow::Result<SecretString> {
    let context_path = std::path::PathBuf::from(&settings._ceremony.election_context);
    let base_dir = context_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let path = base_dir.join(format!("{}-service-token.txt", settings.service.name));
    let token = tokio::fs::read_to_string(&path)
        .await
        .map_err(|e| anyhow::anyhow!("failed to read service token {}: {}", path.display(), e))?
        .trim()
        .to_string();
    Ok(SecretString::new(token))
}

fn entity_id_from_name(name: &str) -> String {
    name.to_uppercase()
}

fn rt_index_from_name(name: &str) -> anyhow::Result<usize> {
    name.strip_prefix("rt-")
        .and_then(|s| s.parse::<usize>().ok())
        .ok_or_else(|| anyhow::anyhow!("RT service name must be 'rt-{{i}}', got {name}"))
}

/// Build a `reqwest::Client` trusting the cluster CA.  This is a thin wrapper
/// kept here for symmetry with the other actors; most callers use the shared
/// TLS helper directly.
#[allow(dead_code)]
pub async fn build_client(settings: &Settings) -> anyhow::Result<reqwest::Client> {
    let ca_pem = tokio::fs::read_to_string(&settings.tls.ca_pem)
        .await
        .map_err(|e| anyhow::anyhow!("failed to read CA cert: {e}"))?;
    reqwest_client_trusting_ca(&ca_pem).map_err(Into::into)
}
