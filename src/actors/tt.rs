//! Tabulation Teller (TT) server (M4).
//!
//! Implements the endpoints required for milestone M4:
//!   - `POST /sign`   — Ed25519-sign a WBB data string.
//!   - `GET  /status` — readiness + entity id.
//!
//! Full TT threshold tally endpoints (§6.3) are stubbed for later milestones.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::Extension,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::actors::common::{health_router, serve_rustls, with_state};
use crate::configuration::Settings;
use crate::protocol::clock::LogicalClock;
use crate::protocol::tls::rustls_config_for_service;

/// TT service state.
#[derive(Clone)]
pub struct TtState {
    entity_id: String,
    signing_key_seed: SecretString,
    service_token: SecretString,
    clock: LogicalClock,
}

impl std::fmt::Debug for TtState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TtState")
            .field("entity_id", &self.entity_id)
            .field("signing_key_seed", &"<redacted>")
            .field("service_token", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl TtState {
    pub fn new(
        entity_id: String,
        signing_key: SigningKey,
        service_token: SecretString,
        clock: LogicalClock,
    ) -> Self {
        Self {
            entity_id,
            signing_key_seed: SecretString::new(hex::encode(signing_key.to_bytes())),
            service_token,
            clock,
        }
    }

    fn require_bearer(&self, headers: &HeaderMap) -> Result<(), TtError> {
        let expected = self.service_token.expose_secret();
        let header = headers
            .get("authorization")
            .ok_or(TtError::Unauthorized)?
            .to_str()
            .map_err(|_| TtError::Unauthorized)?;
        let Some(token) = header.strip_prefix("Bearer ") else {
            return Err(TtError::Unauthorized);
        };
        if !constant_time_eq::constant_time_eq(token.as_bytes(), expected.as_bytes()) {
            return Err(TtError::Unauthorized);
        }
        Ok(())
    }

    fn signing_key(&self) -> SigningKey {
        let seed = hex::decode(self.signing_key_seed.expose_secret())
            .expect("valid hex seed")
            .try_into()
            .expect("seed length is 32");
        SigningKey::from_bytes(&seed)
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
    Extension(state): Extension<Arc<TtState>>,
    headers: HeaderMap,
    Json(req): Json<SignRequest>,
) -> Result<Json<SignResponse>, TtError> {
    state.require_bearer(&headers)?;
    let entity_id = state.entity_id.clone();
    let timestamp = req.timestamp.unwrap_or_else(|| state.clock.now_ms() as i64);
    let signing_key = state.signing_key();
    let data = req.data;

    let signature = tokio::task::spawn_blocking(move || {
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        hasher.update(entity_id.as_bytes());
        hasher.update(format!("{timestamp}").as_bytes());
        let message = hasher.finalize();
        signing_key.sign(&message)
    })
    .await
    .map_err(|e| TtError::Internal(e.to_string()))?;

    Ok(Json(SignResponse {
        entity_id: state.entity_id.clone(),
        timestamp,
        signature: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
    }))
}

#[derive(Debug, Serialize)]
pub struct StatusResponse {
    pub entity_id: String,
    pub status: &'static str,
}

async fn status_handler(Extension(state): Extension<Arc<TtState>>) -> Json<StatusResponse> {
    Json(StatusResponse {
        entity_id: state.entity_id.clone(),
        status: "ok",
    })
}

#[derive(Debug, thiserror::Error)]
enum TtError {
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unauthorized")]
    Unauthorized,
    #[error("internal error: {0}")]
    Internal(String),
}

impl IntoResponse for TtError {
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

pub fn router(state: Arc<TtState>) -> Router {
    with_state(
        health_router()
            .route("/sign", post(sign_handler))
            .route("/status", get(status_handler)),
        state,
    )
}

/// Run the TT service from settings and signing key.
pub async fn run(settings: Settings, signing_key: SigningKey) -> anyhow::Result<()> {
    let (addr, rustls_config, state) = build_service(settings, signing_key).await?;
    serve_rustls(router(state), addr, rustls_config).await
}

/// Build the TT service components without blocking on `serve_rustls`.
pub async fn build_service(
    settings: Settings,
    signing_key: SigningKey,
) -> anyhow::Result<(
    SocketAddr,
    axum_server::tls_rustls::RustlsConfig,
    Arc<TtState>,
)> {
    let entity_id = settings.service.name.to_uppercase();
    let service_token = load_service_token(&settings).await?;
    let clock = LogicalClock::new(settings.clock.base_ms, settings.clock.tick_ms);
    let state = Arc::new(TtState::new(entity_id, signing_key, service_token, clock));

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
