//! Registration Teller (RT) server.
//!
//! Implements:
//!   - `POST /sign`       - Ed25519-sign a WBB data string.
//!   - `POST /decoy`      - generate a decoy credential builder + ruse PIN.
//!   - `GET  /status`     - readiness + entity id.
//!
//! The service loads its DKG share and reconstructs its
//! `ThresholdRegistrationTeller` in memory; no network is needed for the
//! threshold math.

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
use dlog_group::group::{GroupPoint, GroupScalar};
use dlog_group::ristretto::RistrettoGroup;
use ed25519_dalek::{Signer, SigningKey};
use evoting::api::prelude::{ThresholdDvRound1Broadcast, ThresholdDvRound1State};
use evoting::api::server::bb::ElectionContext;
use evoting::api::server::rt::{AccShareBroadcast, ThresholdRegistrationTeller};
use rand_chacha::ChaCha20Rng;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::Mutex;

use crate::actors::common::{health_router, serve_rustls, with_state};
use crate::configuration::Settings;
use crate::domain::{TokenValue, Vid};
use crate::protocol::acc::{load_rt_share, reconstruct_rt_teller, EnrollmentPackage};
use crate::protocol::clock::LogicalClock;
use crate::protocol::rng::{operation_rng, ActorSeed};
use crate::protocol::tls::{reqwest_client_trusting_ca, rustls_config_for_service};

/// RT service state.
#[derive(Clone)]
pub struct RtState {
    entity_id: String,
    rt_id: usize,
    signing_key_seed: SecretString,
    service_token: SecretString,
    actor_seed: ActorSeed,
    election_context: ElectionContext<RistrettoGroup>,
    rt_pk: evoting::api::prelude::RTPublicKey<RistrettoGroup>,
    share_path: std::path::PathBuf,
    clock: LogicalClock,
    decoy_counter: Arc<AtomicU64>,
    dvnizkp_counter: Arc<AtomicU64>,
    tau_counter: Arc<AtomicU64>,
    controls_counter: Arc<AtomicU64>,
    enrollment_packages: Vec<EnrollmentPackage>,
    /// Clients to the ER (token verification) and NS (readiness notify);
    /// absent when the service is booted without those peers configured.
    er_client: Option<crate::clients::er::ErClient>,
    ns_client: Option<crate::clients::ns::NsClient>,
    /// Recorded PIN requests, keyed by vid (Sec. 5.3.1.3).
    pending: Arc<Mutex<HashMap<Vid, PendingCredentialRequest>>>,
    /// DVNIZKP sessions established at `/credentials/deliver`, keyed by the
    /// (already consumed) retrieval token.  Entries are removed when round 2
    /// completes.
    dv_sessions: Arc<Mutex<HashMap<TokenValue, Vid>>>,
    round1_sessions: Arc<Mutex<HashMap<TokenValue, Round1Session>>>,
    /// Shared internal-API token for the ER `/tokens/verify` call .
    internal_token: SecretString,
    /// Open credential-control session between `/controls/round1` and
    /// `/round2`; the serial tally driver runs one at a
    /// time, so a single slot suffices.
    controls_session: Arc<Mutex<Option<ControlsSession>>>,
}

/// Per-vote nonce state + the submitted votes, cached between control rounds
/// so round 2 provably operates on the same vote list as round 1.
struct ControlsSession {
    votes: Vec<evoting::api::prelude::Vote<RistrettoGroup>>,
    state: evoting::api::prelude::PartialControlState<RistrettoGroup>,
}

impl std::fmt::Debug for RtState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RtState")
            .field("entity_id", &self.entity_id)
            .field("rt_id", &self.rt_id)
            .field("signing_key_seed", &"<redacted>")
            .field("service_token", &"<redacted>")
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
struct PendingCredentialRequest {
    rid: String,
    /// tau delay in logical-clock ticks, sampled from {2..5} (Sec. 5.3.1.3).
    #[allow(dead_code)]
    tau_ticks: u64,
}

struct Round1Session {
    state: ThresholdDvRound1State<RistrettoGroup>,
}

impl RtState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        entity_id: String,
        rt_id: usize,
        signing_key: SigningKey,
        service_token: SecretString,
        actor_seed: ActorSeed,
        election_context: ElectionContext<RistrettoGroup>,
        rt_pk: evoting::api::prelude::RTPublicKey<RistrettoGroup>,
        share_path: std::path::PathBuf,
        clock: LogicalClock,
        enrollment_packages: Vec<EnrollmentPackage>,
        er_client: Option<crate::clients::er::ErClient>,
        ns_client: Option<crate::clients::ns::NsClient>,
        internal_token: SecretString,
    ) -> Self {
        Self {
            entity_id,
            rt_id,
            signing_key_seed: SecretString::new(hex::encode(signing_key.to_bytes())),
            service_token,
            actor_seed,
            election_context,
            rt_pk,
            share_path,
            clock,
            decoy_counter: Arc::new(AtomicU64::new(0)),
            dvnizkp_counter: Arc::new(AtomicU64::new(0)),
            tau_counter: Arc::new(AtomicU64::new(0)),
            controls_counter: Arc::new(AtomicU64::new(0)),
            enrollment_packages,
            er_client,
            ns_client,
            pending: Arc::new(Mutex::new(HashMap::new())),
            dv_sessions: Arc::new(Mutex::new(HashMap::new())),
            round1_sessions: Arc::new(Mutex::new(HashMap::new())),
            internal_token,
            controls_session: Arc::new(Mutex::new(None)),
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
        operation_rng(&self.actor_seed, "decoy", counter)
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

    fn next_dvnizkp_rng(&self) -> ChaCha20Rng {
        let counter = self.dvnizkp_counter.fetch_add(1, Ordering::SeqCst);
        operation_rng(&self.actor_seed, "dvnizkp", counter)
    }

    fn next_tau_rng(&self) -> ChaCha20Rng {
        let counter = self.tau_counter.fetch_add(1, Ordering::SeqCst);
        operation_rng(&self.actor_seed, "tau", counter)
    }

    fn next_controls_rng(&self) -> ChaCha20Rng {
        let counter = self.controls_counter.fetch_add(1, Ordering::SeqCst);
        operation_rng(&self.actor_seed, "controls", counter)
    }

    fn er_client(&self) -> Result<&crate::clients::er::ErClient, RtError> {
        self.er_client
            .as_ref()
            .ok_or_else(|| RtError::Internal("ER peer not configured".into()))
    }

    fn my_share_broadcast(
        &self,
        credential_index: usize,
    ) -> Result<AccShareBroadcast<RistrettoGroup>, RtError> {
        let pkg = self
            .enrollment_packages
            .get(credential_index)
            .ok_or_else(|| {
                RtError::Internal(format!("credential index {credential_index} out of range"))
            })?;
        pkg.share_broadcasts
            .iter()
            .find(|s| s.from_id == self.rt_id)
            .cloned()
            .ok_or_else(|| RtError::Internal("share broadcast for this RT not found".into()))
    }

    fn build_teller(&self) -> Result<ThresholdRegistrationTeller<RistrettoGroup>, RtError> {
        let share =
            load_rt_share(&self.share_path).map_err(|e| RtError::Internal(e.to_string()))?;
        Ok(reconstruct_rt_teller(
            share,
            &self.election_context,
            &self.rt_pk,
        ))
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

#[derive(Debug, Deserialize)]
struct CredentialsRequestReq {
    /// ER-issued single-use PIN-request token (Sec. 5.3.1.2).
    token: TokenValue,
    rid: String,
}

#[derive(Debug, Serialize)]
struct CredentialsRequestResp {
    /// Sampled tau delay in logical-clock ticks (Sec. 5.3.1.3).
    tau_ticks: u64,
}

/// `POST /credentials/request` - record a PIN request (Sec. 5.3.1.3).
///
/// The RT verifies and consumes the ER-issued PIN-request token, records the
/// `(vid, rid)` pair, samples tau in {2..5} ticks with its seeded RNG, and
/// notifies the NS on the logical clock (no wall-clock wait).
async fn credentials_request_handler(
    Extension(state): Extension<Arc<RtState>>,
    Json(req): Json<CredentialsRequestReq>,
) -> Result<Json<CredentialsRequestResp>, RtError> {
    let verification = state
        .er_client()?
        .verify_token(&req.token, Some("pinrequest"), true, &state.internal_token)
        .await
        .map_err(|e| RtError::Internal(format!("ER token verification failed: {e}")))?;
    if !verification.valid {
        return Err(RtError::Unauthorized);
    }
    let vid = verification.vid.ok_or(RtError::Unauthorized)?;
    if verification.rid.as_deref() != Some(req.rid.as_str()) {
        return Err(RtError::Unauthorized);
    }

    let mut tau_rng = state.next_tau_rng();
    let tau_ticks = state.clock.sample_tau(&mut tau_rng, 2, 5);

    state.pending.lock().await.insert(
        vid,
        PendingCredentialRequest {
            rid: req.rid.clone(),
            tau_ticks,
        },
    );

    if let Some(ns) = &state.ns_client {
        ns.notify(vid, &req.rid, &state.entity_id)
            .await
            .map_err(|e| RtError::Internal(format!("NS notify failed: {e}")))?;
    }

    Ok(Json(CredentialsRequestResp { tau_ticks }))
}

#[derive(Debug, Deserialize)]
struct CredentialsDeliverReq {
    /// ER-issued single-use retrieval token (Sec. 5.3.1.4).
    token: TokenValue,
}

/// `POST /credentials/deliver` - hand this RT's `AccShareBroadcast` to the
/// voter (Sec. 5.3.1.5, Sec. 3.6.3) and open a DVNIZKP session for the same token.
async fn credentials_deliver_handler(
    Extension(state): Extension<Arc<RtState>>,
    Json(req): Json<CredentialsDeliverReq>,
) -> Result<Json<AccShareBroadcast<RistrettoGroup>>, RtError> {
    let verification = state
        .er_client()?
        .verify_token(&req.token, Some("retrieval"), true, &state.internal_token)
        .await
        .map_err(|e| RtError::Internal(format!("ER token verification failed: {e}")))?;
    if !verification.valid {
        return Err(RtError::Unauthorized);
    }
    let vid = verification.vid.ok_or(RtError::Unauthorized)?;

    // A delivery without a recorded PIN request is a protocol violation.
    let pending = state.pending.lock().await;
    let request = pending.get(&vid).ok_or(RtError::Unauthorized)?;
    if verification.rid.as_deref() != Some(request.rid.as_str()) {
        return Err(RtError::Unauthorized);
    }
    drop(pending);

    // Credential index is fixed by the vid assignment (vid i <-> package i-1).
    let share = state.my_share_broadcast((vid.value() - 1) as usize)?;
    state.dv_sessions.lock().await.insert(req.token, vid);
    Ok(Json(share))
}

#[derive(Debug, Deserialize)]
struct DvnizkpRound1Req {
    token: TokenValue,
    #[serde(with = "dlog_group::serde::PointHelper::<RistrettoGroup>")]
    a: <RistrettoGroup as GroupPoint>::Point,
}

async fn dvnizkp_round1_handler(
    Extension(state): Extension<Arc<RtState>>,
    Json(req): Json<DvnizkpRound1Req>,
) -> Result<Json<ThresholdDvRound1Broadcast<RistrettoGroup>>, RtError> {
    // Authenticated by the DVNIZKP session opened at /credentials/deliver.
    let vid = *state
        .dv_sessions
        .lock()
        .await
        .get(&req.token)
        .ok_or(RtError::Unauthorized)?;

    // Bind the proof statement to this voter's credential: the point `a` must
    // be the credential point A of the vid's enrollment package.
    let expected_a = state
        .enrollment_packages
        .get((vid.value() - 1) as usize)
        .map(|p| p.a)
        .ok_or(RtError::Unauthorized)?;
    if req.a != expected_a {
        return Err(RtError::Unauthorized);
    }

    let mut rng = state.next_dvnizkp_rng();
    let teller = state.build_teller()?;
    let a = req.a;
    let token = req.token;
    let (st, bcast) = tokio::task::spawn_blocking(move || teller.gen_dvnizkp_round1(a, &mut rng))
        .await
        .map_err(|e| RtError::Internal(e.to_string()))?;
    state
        .round1_sessions
        .lock()
        .await
        .insert(token, Round1Session { state: st });
    Ok(Json(bcast))
}

#[derive(Debug, Deserialize)]
struct DvnizkpRound2Req {
    token: TokenValue,
    #[serde(with = "dlog_group::serde::ScalarHelper::<RistrettoGroup>")]
    c1: <RistrettoGroup as GroupScalar>::Scalar,
    all_ids: Vec<usize>,
}

#[derive(Debug, Serialize)]
struct DvnizkpRound2Resp {
    #[serde(with = "dlog_group::serde::ScalarHelper::<RistrettoGroup>")]
    z1: <RistrettoGroup as GroupScalar>::Scalar,
}

async fn dvnizkp_round2_handler(
    Extension(state): Extension<Arc<RtState>>,
    Json(req): Json<DvnizkpRound2Req>,
) -> Result<Json<DvnizkpRound2Resp>, RtError> {
    let session = state
        .round1_sessions
        .lock()
        .await
        .remove(&req.token)
        .ok_or(RtError::Unauthorized)?;
    // The DVNIZKP session is complete after round 2 - drop it so rounds
    // cannot be replayed with the consumed retrieval token.
    state.dv_sessions.lock().await.remove(&req.token);
    let teller = state.build_teller()?;
    let c1 = req.c1;
    let all_ids = req.all_ids;
    let z1 = tokio::task::spawn_blocking(move || {
        teller.gen_dvnizkp_round2(session.state, &c1, &all_ids)
    })
    .await
    .map_err(|e| RtError::Internal(e.to_string()))?;
    Ok(Json(DvnizkpRound2Resp { z1 }))
}

// -- Credential controls (Sec. 3.9 steps 14-19) ---------------------------

#[derive(Debug, Deserialize)]
#[serde(bound = "")]
pub struct ControlsRound1Request {
    pub votes: Vec<evoting::api::prelude::Vote<RistrettoGroup>>,
}

/// Round 1: sample per-vote nonces and broadcast commitments + partial Ay.
async fn controls_round1_handler(
    Extension(state): Extension<Arc<RtState>>,
    headers: HeaderMap,
    Json(req): Json<ControlsRound1Request>,
) -> Result<Json<evoting::api::prelude::PartialControlBroadcast<RistrettoGroup>>, RtError> {
    state.require_bearer(&headers)?;
    let teller = state.build_teller()?;
    let mut rng = state.next_controls_rng();
    let votes = req.votes;
    let (votes, control_state, broadcast) = tokio::task::spawn_blocking(move || {
        let (control_state, broadcast) = teller.gen_controls_round1(&votes, &mut rng);
        (votes, control_state, broadcast)
    })
    .await
    .map_err(|e| RtError::Internal(e.to_string()))?;
    *state.controls_session.lock().await = Some(ControlsSession {
        votes,
        state: control_state,
    });
    Ok(Json(broadcast))
}

#[derive(Debug, Deserialize)]
#[serde(bound = "")]
pub struct ControlsRound2Request {
    pub all_round1: Vec<evoting::api::prelude::PartialControlBroadcast<RistrettoGroup>>,
    pub all_ids: Vec<usize>,
}

/// Round 2: derive the Fiat-Shamir challenge and respond over the cached
/// round-1 vote list; consumes the session.
async fn controls_round2_handler(
    Extension(state): Extension<Arc<RtState>>,
    headers: HeaderMap,
    Json(req): Json<ControlsRound2Request>,
) -> Result<Json<evoting::api::prelude::PartialControlResponse<RistrettoGroup>>, RtError> {
    state.require_bearer(&headers)?;
    let session = state
        .controls_session
        .lock()
        .await
        .take()
        .ok_or_else(|| RtError::BadRequest("no open controls session".into()))?;
    let teller = state.build_teller()?;
    let response = tokio::task::spawn_blocking(move || {
        teller.gen_controls_round2(&session.votes, session.state, &req.all_round1, &req.all_ids)
    })
    .await
    .map_err(|e| RtError::Internal(e.to_string()))?;
    Ok(Json(response))
}

#[derive(Debug, thiserror::Error)]
enum RtError {
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unauthorized")]
    Unauthorized,
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("internal error: {0}")]
    Internal(String),
}

impl IntoResponse for RtError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            Self::Json(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, self.to_string()),
            Self::BadRequest(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            // Internal failures are logged but not leaked.
            Self::Internal(_) => {
                tracing::error!(error = %self, "rt-server internal error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal error".to_string(),
                )
            }
        };
        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}

pub fn router(state: Arc<RtState>) -> Router {
    with_state(
        health_router()
            .route("/sign", post(sign_handler))
            .route("/decoy", post(decoy_handler))
            .route("/status", get(status_handler))
            .route("/credentials/request", post(credentials_request_handler))
            .route("/credentials/deliver", post(credentials_deliver_handler))
            .route("/dvnizkp/round1", post(dvnizkp_round1_handler))
            .route("/dvnizkp/round2", post(dvnizkp_round2_handler))
            .route("/controls/round1", post(controls_round1_handler))
            .route("/controls/round2", post(controls_round2_handler)),
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
    let actor_seed = load_actor_seed(&settings).await?;
    let enrollment_packages = load_enrollment_packages(&settings)
        .await
        .unwrap_or_default();
    let clock = LogicalClock::new(settings.clock.base_ms, settings.clock.tick_ms);

    // Peer clients are optional: an RT booted without ER/NS peers (e.g. the
    // signing test) simply rejects credential-request traffic.
    let http_client = build_client(&settings).await?;
    let er_client = parse_peer_url(&settings.er.base_url)?
        .map(|url| crate::clients::er::ErClient::new(http_client.clone(), url));
    let ns_client = parse_peer_url(&settings.ns.base_url)?
        .map(|url| crate::clients::ns::NsClient::new(http_client.clone(), url));

    let entity_id = entity_id_from_name(&settings.service.name);
    let rt_id = {
        let share = load_rt_share(&share_path)?;
        share.id
    };
    let state = Arc::new(RtState::new(
        entity_id,
        rt_id,
        signing_key,
        service_token,
        actor_seed,
        election_context,
        rt_pk,
        share_path,
        clock,
        enrollment_packages,
        er_client,
        ns_client,
        crate::actors::common::load_internal_token(&settings).await?,
    ));

    let addr: SocketAddr = format!("{}:{}", settings.service.host, settings.service.port)
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid service address: {e}"))?;

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

async fn load_enrollment_packages(settings: &Settings) -> anyhow::Result<Vec<EnrollmentPackage>> {
    let context_path = std::path::PathBuf::from(&settings._ceremony.election_context);
    let base_dir = context_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let path = base_dir.join("output").join("enrollment_packages.json");
    let bytes = tokio::fs::read(&path).await.map_err(|e| {
        anyhow::anyhow!(
            "failed to read enrollment packages {}: {}",
            path.display(),
            e
        )
    })?;
    serde_json::from_slice(&bytes)
        .map_err(|e| anyhow::anyhow!("failed to parse enrollment packages: {e}"))
}

/// Load this service's dedicated operation seed (`{name}-seed.bin`).
async fn load_actor_seed(settings: &Settings) -> anyhow::Result<ActorSeed> {
    let context_path = std::path::PathBuf::from(&settings._ceremony.election_context);
    let base_dir = context_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let path = base_dir.join(format!("{}-seed.bin", settings.service.name));
    let bytes = tokio::fs::read(&path)
        .await
        .map_err(|e| anyhow::anyhow!("failed to read actor seed {}: {}", path.display(), e))?;
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("actor seed file must contain exactly 32 bytes"))?;
    Ok(ActorSeed::from_bytes(seed))
}

/// Parse an optional peer base URL; empty means "peer not configured".
fn parse_peer_url(base_url: &str) -> anyhow::Result<Option<reqwest::Url>> {
    if base_url.is_empty() {
        return Ok(None);
    }
    reqwest::Url::parse(base_url)
        .map(Some)
        .map_err(|e| anyhow::anyhow!("invalid peer URL {base_url}: {e}"))
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
