//! Shared actor service machinery: key derivation, TLS bind helpers, health.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use axum::{routing::get, Extension, Router};
use ed25519_dalek::SigningKey;

use crate::protocol::rng::MasterSeed;

/// Derive an Ed25519 signing key for an actor from the master seed.
///
/// Mirrors the deterministic derivation used by the WBB entity keys in the
/// e2e harness (`helpers::entity_signing_key`) but operates on the typed
/// `MasterSeed` from `protocol::rng`.
pub fn actor_signing_key(master_seed: &MasterSeed, actor_id: &str) -> SigningKey {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    master_seed.expose(|seed| hasher.update(seed));
    hasher.update(actor_id.as_bytes());
    let seed: [u8; 32] = hasher.finalize().into();
    let mut rng = ChaCha20Rng::from_seed(seed);
    SigningKey::generate(&mut rng)
}

/// Load an Ed25519 signing key from a raw 32-byte seed file.
///
/// The ceremony writes one file per service (`{name}-signing-key.bin`) so that
/// services never need the master seed in their config.
pub async fn load_signing_key(path: &Path) -> anyhow::Result<SigningKey> {
    let bytes = tokio::fs::read(path)
        .await
        .map_err(|e| anyhow::anyhow!("failed to read signing key from {path:?}: {e}"))?;
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("signing key file {path:?} must contain exactly 32 bytes"))?;
    Ok(SigningKey::from_bytes(&seed))
}

async fn health() -> &'static str {
    "ok"
}

/// Return a simple `GET /health` router. Services add their own routes on top.
pub fn health_router() -> Router {
    Router::new().route("/health", get(health))
}

/// Apply shared state to a stateless router via the `Extension` layer.
pub fn with_state<T: Clone + Send + Sync + 'static>(app: Router, state: Arc<T>) -> Router {
    app.layer(Extension(state))
}

/// Serve an axum `Router` over HTTPS with the supplied rustls config.
pub async fn serve_rustls(
    app: Router,
    addr: SocketAddr,
    config: axum_server::tls_rustls::RustlsConfig,
) -> anyhow::Result<()> {
    axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service())
        .await
        .map_err(Into::into)
}
