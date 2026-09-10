//! Digital Identity Provider (DIP) stub service.
//!
//! DIP authenticates voters and returns a signed assertion that the ER consumes
//! during login/device registration. The PoC uses a registry of 8 test voters
//! from configuration.

use std::net::SocketAddr;

use axum::{
    extract::Extension,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::actors::common::{health_router, serve_rustls, with_state};
use crate::configuration::{DipVoter, Settings};
use crate::protocol::tls::rustls_config_for_service;

/// DIP service state.
#[derive(Clone, Debug)]
pub struct DipState {
    signing_key_seed: SecretString,
    registry: Vec<DipVoter>,
}

impl DipState {
    pub fn new(signing_key: SigningKey, registry: Vec<DipVoter>) -> Self {
        Self {
            signing_key_seed: SecretString::new(hex::encode(signing_key.to_bytes())),
            registry,
        }
    }

    fn authenticate(&self, fiscal_id: &str) -> Option<DipAssertion> {
        let voter = self.registry.iter().find(|v| v.id == fiscal_id)?;
        Some(DipAssertion {
            fiscal_id: fiscal_id.to_string(),
            name: voter.name.clone(),
            assurance: "high".to_string(),
        })
    }

    fn signing_key(&self) -> SigningKey {
        let seed = hex::decode(self.signing_key_seed.expose_secret())
            .expect("valid hex seed")
            .try_into()
            .expect("seed length is 32");
        SigningKey::from_bytes(&seed)
    }

    fn sign_assertion(&self, assertion: &DipAssertion) -> Result<String, serde_json::Error> {
        let msg = serde_json::to_vec(assertion)?;
        let signature = self.signing_key().sign(&msg);
        Ok(BASE64.encode(signature.to_bytes()))
    }
}

/// Assertion returned to the voter client after DIP authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DipAssertion {
    pub fiscal_id: String,
    pub name: String,
    pub assurance: String,
}

/// Full DIP authentication response, including a base64 Ed25519 signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticateResponse {
    pub assertion: DipAssertion,
    pub signature: String,
    pub verifying_key: String,
}

#[derive(Debug, Deserialize)]
struct AuthenticateRequest {
    fiscal_id: String,
}

async fn authenticate_handler(
    Extension(state): Extension<Arc<DipState>>,
    Json(req): Json<AuthenticateRequest>,
) -> Result<Json<AuthenticateResponse>, DipError> {
    let assertion = state
        .authenticate(&req.fiscal_id)
        .ok_or(DipError::Unauthorized)?;
    let state_clone = state.clone();
    let assertion_clone = assertion.clone();
    let (signature, verifying_key) = tokio::task::spawn_blocking(move || {
        let signature = state_clone
            .sign_assertion(&assertion_clone)
            .map_err(DipError::Serialization)?;
        let verifying_key = BASE64.encode(state_clone.signing_key().verifying_key().as_bytes());
        Ok::<_, DipError>((signature, verifying_key))
    })
    .await
    .map_err(|e| DipError::Internal(e.to_string()))??;

    Ok(Json(AuthenticateResponse {
        assertion,
        signature,
        verifying_key,
    }))
}

#[derive(Debug, thiserror::Error)]
enum DipError {
    #[error("unauthorized")]
    Unauthorized,
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("internal error: {0}")]
    Internal(String),
}

impl IntoResponse for DipError {
    fn into_response(self) -> Response {
        let status = match &self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Serialization(_) | Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (
            status,
            Json(serde_json::json!({ "error": self.to_string() })),
        )
            .into_response()
    }
}

pub fn router(state: Arc<DipState>) -> Router {
    with_state(
        health_router().route("/authenticate", post(authenticate_handler)),
        state,
    )
}

/// Run the DIP service from settings and a signing key.
///
/// The service host/port come from `settings.service`; TLS material comes from
/// `settings.tls`. The signing key is loaded from the ceremony-generated key
/// file (e.g. `dip-signing-key.bin`).
pub async fn run(settings: Settings, signing_key: SigningKey) -> anyhow::Result<()> {
    let state = Arc::new(DipState::new(signing_key, settings.dip.voters));

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

    serve_rustls(router(state), addr, rustls_config).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn test_key() -> SigningKey {
        let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
        SigningKey::generate(&mut rng)
    }

    #[test]
    fn authenticate_known_voter() {
        let registry = vec![DipVoter {
            id: "VOTER-001".to_string(),
            name: "Alice".to_string(),
        }];
        let state = DipState::new(test_key(), registry);
        let assertion = state.authenticate("VOTER-001").unwrap();
        assert_eq!(assertion.name, "Alice");
        assert!(state.authenticate("UNKNOWN").is_none());
    }
}
