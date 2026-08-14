//! Electoral Roll (ER) server (M3.3).
//!
//! Handles voter login, device registration, token issuance/verification,
//! revocations, eligible-vid management, and admin publication of setup entries
//! to the WBB.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::Extension,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use dlog_group::ristretto::RistrettoGroup;
use ed25519_dalek::SigningKey;
use evoting::api::server::bb::ElectionContext;
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;

use crate::actors::common::{health_router, serve_rustls, with_state};
use crate::clients::wbb::{sign_entry, WbbClient};
use crate::configuration::{DipSettings, Settings};
use crate::protocol::merkle::voter_id_merkle_root;
use crate::protocol::rng::MasterSeed;
use crate::protocol::setup::{assign_vids, voter_pairs};
use crate::protocol::tls::{reqwest_client_trusting_ca, rustls_config_for_service};

/// ER service state.
#[derive(Clone, Debug)]
pub struct ErState {
    signing_key_seed: SecretString,
    admin_token: SecretString,
    election_context: ElectionContext<RistrettoGroup>,
    wbb_client: WbbClient,
    dip: DipSettings,
}

impl ErState {
    pub fn new(
        signing_key: SigningKey,
        admin_token: SecretString,
        election_context: ElectionContext<RistrettoGroup>,
        wbb_client: WbbClient,
        dip: DipSettings,
    ) -> Self {
        Self {
            signing_key_seed: SecretString::new(hex::encode(signing_key.to_bytes())),
            admin_token,
            election_context,
            wbb_client,
            dip,
        }
    }

    fn signing_key(&self) -> SigningKey {
        let seed = hex::decode(self.signing_key_seed.expose_secret())
            .expect("valid hex seed")
            .try_into()
            .expect("seed length is 32");
        SigningKey::from_bytes(&seed)
    }

    async fn publish_setup_entries(&self) -> Result<Vec<serde_json::Value>, ErError> {
        let ctx_json = serde_json::to_string(&self.election_context)?;
        let n_v = self.dip.voters.len();
        let n_acc = 10usize; // D12
        let count_json = serde_json::json!({ "n_v": n_v, "n_acc": n_acc }).to_string();

        let vids = assign_vids(n_v);
        let voter_ids: Vec<_> = self.dip.voters.iter().map(|v| v.id.clone()).collect();
        let pairs = voter_pairs(&voter_ids, &vids);
        let root = voter_id_merkle_root(&pairs);
        let root_b64 = BASE64.encode(root);

        // The WBB entry format requires exactly 5 comma-separated fields, so
        // JSON payloads (which contain commas) are base64-encoded in the 5th
        // field.
        let data_strings = vec![
            format!(
                "setup,ER,election_pub_key,1,{}",
                BASE64.encode(ctx_json.as_bytes())
            ),
            format!(
                "setup,ER,pseudonymous_id_count,1,{}",
                BASE64.encode(count_json.as_bytes())
            ),
            format!("setup,ER,voter_id_merkle_root,1,{}", root_b64),
        ];

        let entity_id = "ER-1".to_string();
        let timestamp = 1;
        let signing_key = self.signing_key();

        // Signing and serialization run in spawn_blocking per roadmap §6.
        let signed_entries = tokio::task::spawn_blocking(move || {
            data_strings
                .into_iter()
                .map(|data| sign_entry(data.as_bytes(), &entity_id, timestamp, &signing_key))
                .collect::<Vec<_>>()
        })
        .await
        .map_err(|e| ErError::Internal(e.to_string()))?;

        let mut results = Vec::new();
        for entry in signed_entries {
            let result = self.wbb_client.submit(&entry).await?;
            results.push(result);
        }
        Ok(results)
    }
}

fn check_admin_token(headers: &HeaderMaps, expected: &SecretString) -> Result<(), ErError> {
    let header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or(ErError::Unauthorized)?;
    let token = header.strip_prefix("Bearer ").unwrap_or(header);
    if token != expected.expose_secret() {
        return Err(ErError::Unauthorized);
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct SetupResponse {
    published: usize,
}

async fn setup_handler(
    Extension(state): Extension<Arc<ErState>>,
    headers: HeaderMaps,
) -> Result<Json<SetupResponse>, ErError> {
    check_admin_token(&headers, &state.admin_token)?;
    let results = state.publish_setup_entries().await?;
    Ok(Json(SetupResponse {
        published: results.len(),
    }))
}

#[derive(Debug, thiserror::Error)]
enum ErError {
    #[error("unauthorized")]
    Unauthorized,
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("wbb error: {0}")]
    Wbb(#[from] crate::clients::wbb::WbbError),
    #[error("internal error: {0}")]
    Internal(String),
}

impl IntoResponse for ErError {
    fn into_response(self) -> Response {
        let status = match &self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Json(_) | Self::Wbb(_) | Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (
            status,
            Json(serde_json::json!({ "error": self.to_string() })),
        )
            .into_response()
    }
}

pub fn router(state: Arc<ErState>) -> Router {
    with_state(
        health_router().route("/admin/setup", post(setup_handler)),
        state,
    )
}

/// Run the ER service from settings, signing key, and admin token.
pub async fn run(
    settings: Settings,
    signing_key: SigningKey,
    admin_token: SecretString,
) -> anyhow::Result<()> {
    let (addr, rustls_config, state) = build_service(settings, signing_key, admin_token).await?;
    serve_rustls(router(state), addr, rustls_config).await
}

/// Build the ER service components without blocking on `serve_rustls`. Useful
/// for integration tests that want to spawn the server in a background task.
pub async fn build_service(
    settings: Settings,
    signing_key: SigningKey,
    admin_token: SecretString,
) -> anyhow::Result<(
    SocketAddr,
    axum_server::tls_rustls::RustlsConfig,
    Arc<ErState>,
)> {
    let election_context = load_election_context(&settings).await?;

    let wbb_client = build_wbb_client(&settings).await?;

    let state = Arc::new(ErState::new(
        signing_key,
        admin_token,
        election_context,
        wbb_client,
        settings.dip.clone(),
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

async fn build_wbb_client(settings: &Settings) -> anyhow::Result<WbbClient> {
    let base_url = reqwest::Url::parse(&settings.wbb.base_url)?;
    let ca_pem = tokio::fs::read_to_string(&settings.tls.ca_pem)
        .await
        .map_err(|e| anyhow::anyhow!("failed to read CA cert: {e}"))?;
    let client = reqwest_client_trusting_ca(&ca_pem)?;
    Ok(WbbClient::new(client, base_url))
}

/// Derive the deterministic ER admin token from the master seed.
pub fn derive_admin_token(master_seed: &MasterSeed) -> SecretString {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    master_seed.expose(|seed| hasher.update(seed));
    hasher.update(b"admin-token");
    SecretString::new(hex::encode(hasher.finalize()))
}

// Axum's HeaderMap type is `HeaderMap`, not `HeaderMaps`. Fix accidental alias.
type HeaderMaps = axum::http::HeaderMap;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::rng::MasterSeed;
    use secrecy::ExposeSecret;

    #[test]
    fn admin_token_is_deterministic() {
        let seed = MasterSeed::new([3u8; 32]);
        let t1 = derive_admin_token(&seed);
        let t2 = derive_admin_token(&seed);
        assert_eq!(t1.expose_secret(), t2.expose_secret());
        assert_eq!(t1.expose_secret().len(), 64);
    }
}
