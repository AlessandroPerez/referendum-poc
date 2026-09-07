//! Tabulation Teller (TT) server (M4 signing + M8 threshold tally, §6.3).
//!
//! Endpoints:
//!   - `POST /sign`               — Ed25519-sign a WBB data string.
//!   - `GET  /status`             — readiness + entity id.
//!   - `POST /vss/zeta/round1`    — start a threshold ζ VSS session (§3.9).
//!   - `POST /vss/zeta/combine`   — combine ζ VSS broadcasts → sub-share.
//!   - `POST /decrypt/ox`         — partial ox-fingerprint decryptions.
//!   - `POST /decrypt/acc-checks` — partial ACC-check decryptions.
//!   - `POST /decrypt/fps`        — partial credential-fp decryptions.
//!   - `POST /decrypt/tally`      — partial tally decryptions.
//!
//! The service loads its DKG share (`tt-{i}-share.json`) per request (RT
//! precedent) and keeps the opaque ζ VSS state between round 1 and combine in
//! a session keyed by the driver-chosen label (design lock (e)).  All tally
//! endpoints require the service bearer token, and all crypto runs in
//! `tokio::task::spawn_blocking`.
//!
//! Trust assumption (§6.3, documented per M8 validation L5): the `/decrypt/*`
//! endpoints partially decrypt whatever ciphertexts the request carries — a
//! TT cannot distinguish pipeline ciphertexts from others, so a coordinator
//! holding ≥ t_TT service tokens is a decryption oracle for arbitrary
//! ciphertexts.  This matches the endpoint catalog and the library `partial_*`
//! API; the mitigations are the per-service bearer tokens and the public
//! audit trail (every decryption the tally *uses* must be published and is
//! master-key-bound by the auditor).

use std::collections::HashMap;
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
use dlog_group::group::GroupScalar;
use dlog_group::ristretto::RistrettoGroup;
use dlog_group::serde::ScalarHelper;
use ed25519_dalek::{Signer, SigningKey};
use evoting::api::prelude::{
    CredentialControlProof, EncrChoice, ThresholdTabulationTeller, VerifiableFingerprints,
    VerifiablePartialDecryption, Vote, ZetaVssBroadcast, ZetaVssState,
};
use evoting::api::server::bb::ElectionContext;
use rand_chacha::ChaCha20Rng;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use crate::actors::common::{health_router, serve_rustls, with_state};
use crate::configuration::Settings;
use crate::protocol::clock::LogicalClock;
use crate::protocol::rng::{operation_rng, ActorSeed};
use crate::protocol::tally::{load_tt_share, reconstruct_tt_teller};
use crate::protocol::tls::rustls_config_for_service;

type G = RistrettoGroup;

/// Upper bound on concurrently open ζ VSS sessions (the serial tally driver
/// needs 2; anything near this cap indicates driver misbehaviour).
const MAX_ZETA_SESSIONS: usize = 8;

/// TT service state.
#[derive(Clone)]
pub struct TtState {
    entity_id: String,
    signing_key_seed: SecretString,
    service_token: SecretString,
    clock: LogicalClock,
    /// Election context for context-bound tally operations (M8).
    election_context: ElectionContext<G>,
    /// Path to this party's `tt-{i}-share.json` DKG share.
    share_path: std::path::PathBuf,
    /// Dedicated operation seed (`tt-{i}-seed.bin`, §9.2) for proof nonces.
    actor_seed: ActorSeed,
    /// Number of TT parties / reconstruction threshold (from configuration).
    n_tt: usize,
    t_tt: usize,
    op_counter: Arc<AtomicU64>,
    /// Open ζ VSS sessions, keyed by the driver-chosen label (design lock (e)).
    zeta_sessions: Arc<Mutex<HashMap<String, ZetaVssState<G>>>>,
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

    fn build_teller(&self) -> Result<ThresholdTabulationTeller<G>, TtError> {
        let share =
            load_tt_share(&self.share_path).map_err(|e| TtError::Internal(e.to_string()))?;
        Ok(reconstruct_tt_teller(share))
    }

    fn next_op_rng(&self, purpose: &str) -> ChaCha20Rng {
        let counter = self.op_counter.fetch_add(1, Ordering::SeqCst);
        operation_rng(&self.actor_seed, purpose, counter)
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

// ── ζ VSS (§3.9 steps 6–7, design lock (e)) ─────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ZetaRound1Request {
    /// Driver-chosen session label (e.g. `ox` / `acc`); combine consumes it.
    pub session: String,
}

/// Start a ζ VSS session: Feldman-share a fresh local ζ_i over `g1`.
async fn zeta_round1_handler(
    Extension(state): Extension<Arc<TtState>>,
    headers: HeaderMap,
    Json(req): Json<ZetaRound1Request>,
) -> Result<Json<ZetaVssBroadcast<G>>, TtError> {
    state.require_bearer(&headers)?;
    let teller = state.build_teller()?;
    let n = state.n_tt;
    let t = state.t_tt;
    let base = state.election_context.pk.params.elgamal.g1;
    let mut rng = state.next_op_rng("zeta-vss");
    let (vss_state, broadcast) =
        tokio::task::spawn_blocking(move || teller.gen_zeta_vss_round1(n, t, base, &mut rng))
            .await
            .map_err(|e| TtError::Internal(e.to_string()))?;
    {
        // Bound the session map: abandoned round-1 sessions must not
        // accumulate without limit (a fresh round 1 on an existing label
        // replaces it and stays within the cap).
        let mut sessions = state.zeta_sessions.lock().await;
        if sessions.len() >= MAX_ZETA_SESSIONS && !sessions.contains_key(&req.session) {
            return Err(TtError::BadRequest(format!(
                "too many open ζ VSS sessions (max {MAX_ZETA_SESSIONS})"
            )));
        }
        sessions.insert(req.session, vss_state);
    }
    Ok(Json(broadcast))
}

#[derive(Debug, Deserialize)]
pub struct ZetaCombineRequest {
    pub session: String,
    pub broadcasts: Vec<ZetaVssBroadcast<G>>,
}

#[derive(Debug, Serialize)]
pub struct ZetaCombineResponse {
    pub id: usize,
    #[serde(with = "ScalarHelper::<G>")]
    pub sub_share: <G as GroupScalar>::Scalar,
}

/// Combine ζ VSS broadcasts into this party's sub-share; consumes the session.
async fn zeta_combine_handler(
    Extension(state): Extension<Arc<TtState>>,
    headers: HeaderMap,
    Json(req): Json<ZetaCombineRequest>,
) -> Result<Json<ZetaCombineResponse>, TtError> {
    state.require_bearer(&headers)?;
    // Shape validation before the library call: `combine_zeta_vss` indexes
    // `shares_for_others[id-1]` unchecked, so a short broadcast would panic
    // (→ 500) instead of failing the request.
    if req.broadcasts.is_empty() {
        return Err(TtError::BadRequest("ζ VSS broadcasts missing".into()));
    }
    for broadcast in &req.broadcasts {
        if broadcast.from_id == 0 || broadcast.from_id > state.n_tt {
            return Err(TtError::BadRequest(format!(
                "ζ VSS broadcast from_id {} out of range 1..={}",
                broadcast.from_id, state.n_tt
            )));
        }
        if broadcast.shares_for_others.len() != state.n_tt
            || broadcast.commitments.len() != state.t_tt
        {
            return Err(TtError::BadRequest(format!(
                "ζ VSS broadcast from party {} has wrong shape",
                broadcast.from_id
            )));
        }
    }
    let vss_state = state
        .zeta_sessions
        .lock()
        .await
        .remove(&req.session)
        .ok_or_else(|| TtError::BadRequest("unknown ζ VSS session".into()))?;
    let broadcasts = req.broadcasts;
    let (id, sub_share) = tokio::task::spawn_blocking(move || {
        ThresholdTabulationTeller::<G>::combine_zeta_vss(&vss_state, &broadcasts)
    })
    .await
    .map_err(|e| TtError::Internal(e.to_string()))?
    .map_err(|e| TtError::BadRequest(format!("ζ VSS combine failed: {e}")))?;
    Ok(Json(ZetaCombineResponse { id, sub_share }))
}

// ── Partial decryptions (§3.9, design lock (b)) ─────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(bound = "")]
pub struct DecryptOxRequest {
    pub fps: VerifiableFingerprints<G>,
}

/// Per-party ox-fingerprint decryptions (§3.9 steps 8–9).
async fn decrypt_ox_handler(
    Extension(state): Extension<Arc<TtState>>,
    headers: HeaderMap,
    Json(req): Json<DecryptOxRequest>,
) -> Result<Json<Vec<VerifiablePartialDecryption<G>>>, TtError> {
    state.require_bearer(&headers)?;
    let teller = state.build_teller()?;
    let ctx = state.election_context.clone();
    let mut rng = state.next_op_rng("decrypt-ox");
    let partials = tokio::task::spawn_blocking(move || {
        teller.partial_decrypt_ox_fps(&ctx, &req.fps, &mut rng)
    })
    .await
    .map_err(|e| TtError::Internal(e.to_string()))?
    .map_err(|e| TtError::BadRequest(format!("ox decryption rejected: {e}")))?;
    Ok(Json(partials))
}

#[derive(Debug, Deserialize)]
#[serde(bound = "")]
pub struct AccChecksRequest {
    pub votes: Vec<Vote<G>>,
    pub controls: Vec<CredentialControlProof<G>>,
    #[serde(with = "ScalarHelper::<G>")]
    pub zeta: <G as GroupScalar>::Scalar,
}

/// Per-party ACC-check decryptions over the shuffled votes (§3.9 steps 12–14).
async fn decrypt_acc_checks_handler(
    Extension(state): Extension<Arc<TtState>>,
    headers: HeaderMap,
    Json(req): Json<AccChecksRequest>,
) -> Result<Json<Vec<VerifiablePartialDecryption<G>>>, TtError> {
    state.require_bearer(&headers)?;
    let teller = state.build_teller()?;
    let ctx = state.election_context.clone();
    let mut rng = state.next_op_rng("decrypt-acc-checks");
    let partials = tokio::task::spawn_blocking(move || {
        teller.partial_gen_acc_checks(&ctx, &req.votes, &req.controls, req.zeta, &mut rng)
    })
    .await
    .map_err(|e| TtError::Internal(e.to_string()))?
    .map_err(|e| TtError::BadRequest(format!("acc-check decryption rejected: {e}")))?;
    Ok(Json(partials))
}

#[derive(Debug, Deserialize)]
#[serde(bound = "")]
pub struct DecryptFpsRequest {
    pub fps: VerifiableFingerprints<G>,
}

#[derive(Debug, Serialize)]
#[serde(bound = "")]
pub struct DecryptFpsResponse {
    pub pub_fps: Vec<VerifiablePartialDecryption<G>>,
    pub vote_fps: Vec<VerifiablePartialDecryption<G>>,
}

/// Per-party credential-fingerprint decryptions (§3.9 steps 20–24).
async fn decrypt_fps_handler(
    Extension(state): Extension<Arc<TtState>>,
    headers: HeaderMap,
    Json(req): Json<DecryptFpsRequest>,
) -> Result<Json<DecryptFpsResponse>, TtError> {
    state.require_bearer(&headers)?;
    let teller = state.build_teller()?;
    let ctx = state.election_context.clone();
    let mut rng = state.next_op_rng("decrypt-fps");
    let (pub_fps, vote_fps) =
        tokio::task::spawn_blocking(move || teller.partial_decrypt_fps(&ctx, &req.fps, &mut rng))
            .await
            .map_err(|e| TtError::Internal(e.to_string()))?
            .map_err(|e| TtError::BadRequest(format!("fp decryption rejected: {e}")))?;
    Ok(Json(DecryptFpsResponse { pub_fps, vote_fps }))
}

#[derive(Debug, Deserialize)]
#[serde(bound = "")]
pub struct DecryptTallyRequest {
    pub enc_tally: EncrChoice<G>,
}

#[derive(Debug, Serialize)]
#[serde(bound = "")]
pub struct DecryptTallyResponse {
    pub l1: Vec<VerifiablePartialDecryption<G>>,
    pub l2: Vec<Vec<VerifiablePartialDecryption<G>>>,
}

/// Per-party tally decryptions over the homomorphic sum (§3.9 steps 26–29).
async fn decrypt_tally_handler(
    Extension(state): Extension<Arc<TtState>>,
    headers: HeaderMap,
    Json(req): Json<DecryptTallyRequest>,
) -> Result<Json<DecryptTallyResponse>, TtError> {
    state.require_bearer(&headers)?;
    let teller = state.build_teller()?;
    let ctx = state.election_context.clone();
    let mut rng = state.next_op_rng("decrypt-tally");
    let (l1, l2) = tokio::task::spawn_blocking(move || {
        teller.partial_decrypt_tally(&ctx, &req.enc_tally, &mut rng)
    })
    .await
    .map_err(|e| TtError::Internal(e.to_string()))?;
    Ok(Json(DecryptTallyResponse { l1, l2 }))
}

#[derive(Debug, thiserror::Error)]
enum TtError {
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unauthorized")]
    Unauthorized,
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("internal error: {0}")]
    Internal(String),
}

impl IntoResponse for TtError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            Self::Json(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, self.to_string()),
            Self::BadRequest(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            // Internal failures are logged but not leaked (style guide §03).
            Self::Internal(_) => {
                tracing::error!(error = %self, "tt-server internal error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal error".to_string(),
                )
            }
        };
        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}

pub fn router(state: Arc<TtState>) -> Router {
    with_state(
        health_router()
            .route("/sign", post(sign_handler))
            .route("/status", get(status_handler))
            .route("/vss/zeta/round1", post(zeta_round1_handler))
            .route("/vss/zeta/combine", post(zeta_combine_handler))
            .route("/decrypt/ox", post(decrypt_ox_handler))
            .route("/decrypt/acc-checks", post(decrypt_acc_checks_handler))
            .route("/decrypt/fps", post(decrypt_fps_handler))
            .route("/decrypt/tally", post(decrypt_tally_handler)),
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
    let ceremony_dir = ceremony_dir(&settings);
    let service_token = load_service_token(&settings).await?;
    let clock = LogicalClock::new(settings.clock.base_ms, settings.clock.tick_ms);

    let election_context = load_election_context(&settings).await?;
    let tt_index = settings
        .service
        .name
        .strip_prefix("tt-")
        .and_then(|s| s.parse::<usize>().ok())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "TT service name must be 'tt-{{i}}', got {}",
                settings.service.name
            )
        })?;
    let share_path = ceremony_dir.join(format!("tt-{tt_index}-share.json"));
    let actor_seed = load_actor_seed(&settings).await?;

    let state = Arc::new(TtState {
        entity_id,
        signing_key_seed: SecretString::new(hex::encode(signing_key.to_bytes())),
        service_token,
        clock,
        election_context,
        share_path,
        actor_seed,
        n_tt: settings.election.n_tt,
        t_tt: settings.election.t_tt,
        op_counter: Arc::new(AtomicU64::new(0)),
        zeta_sessions: Arc::new(Mutex::new(HashMap::new())),
    });

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

fn ceremony_dir(settings: &Settings) -> std::path::PathBuf {
    std::path::PathBuf::from(&settings._ceremony.election_context)
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .to_path_buf()
}

async fn load_election_context(settings: &Settings) -> anyhow::Result<ElectionContext<G>> {
    let path = std::path::PathBuf::from(&settings._ceremony.election_context);
    let bytes = tokio::fs::read(&path)
        .await
        .map_err(|e| anyhow::anyhow!("failed to read {}: {}", path.display(), e))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| anyhow::anyhow!("failed to parse election context: {e}"))
}

/// Load this service's dedicated operation seed (`{name}-seed.bin`, §9.2).
async fn load_actor_seed(settings: &Settings) -> anyhow::Result<ActorSeed> {
    let path = ceremony_dir(settings).join(format!("{}-seed.bin", settings.service.name));
    let bytes = tokio::fs::read(&path)
        .await
        .map_err(|e| anyhow::anyhow!("failed to read actor seed {}: {}", path.display(), e))?;
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("actor seed file must contain exactly 32 bytes"))?;
    Ok(ActorSeed::from_bytes(seed))
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
