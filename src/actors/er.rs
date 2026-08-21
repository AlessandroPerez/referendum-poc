//! Electoral Roll (ER) server (M3.3 + M5 backend).
//!
//! Handles voter login, device registration, token issuance/verification,
//! revocations, eligible-vid management, and admin publication of setup entries
//! to the WBB.

use std::collections::{HashMap, HashSet};
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
use ed25519_dalek::{SigningKey, Verifier, VerifyingKey};
use evoting::api::server::bb::ElectionContext;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::sync::Mutex;

use crate::actors::common::{health_router, serve_rustls, with_state};
use crate::clients::dip::DipAssertion;
use crate::clients::wbb::{sign_entry, WbbClient};
use crate::configuration::{DipSettings, Settings};
use crate::domain::{TokenValue, Vid};
use crate::protocol::acc::{CredentialPackage, EnrollmentPackage};
use crate::protocol::clock::LogicalClock;
use crate::protocol::merkle::voter_id_merkle_root;
use crate::protocol::rng::{operation_rng, ActorSeed, MasterSeed};
use crate::protocol::setup::{assign_vids, voter_pairs};
use crate::protocol::tls::{reqwest_client_trusting_ca, rustls_config_for_service};

/// ER service state.
#[derive(Clone)]
pub struct ErState {
    signing_key_seed: SecretString,
    admin_token: SecretString,
    dip_verifying_key: VerifyingKey,
    election_context: ElectionContext<RistrettoGroup>,
    election: crate::configuration::ElectionSettings,
    wbb_client: WbbClient,
    dip: DipSettings,
    enrollment_packages: Vec<EnrollmentPackage>,
    enrolled_vids: Arc<Mutex<HashSet<Vid>>>,
    tokens: Arc<Mutex<HashMap<TokenValue, TokenMeta>>>,
    token_counter: Arc<Mutex<u64>>,
    /// Registered device records, keyed by vid.
    devices: Arc<Mutex<HashMap<Vid, DeviceRecord>>>,
    /// Latest PIN-request rid per vid (needed by retrieval-token issuance).
    last_rid: Arc<Mutex<HashMap<Vid, String>>>,
    /// Logical clock for WBB entry timestamps (§9.4).
    clock: Arc<Mutex<LogicalClock>>,
    /// Dedicated operation seed (`er-seed.bin`, §9.2) for token generation.
    token_seed: ActorSeed,
    /// Shared internal-API token authenticating service→service calls
    /// (`/tokens/verify`, roadmap §6.1).
    internal_token: SecretString,
}

/// A registered voter device (PoC: app public key + opaque state blob).
#[derive(Debug, Clone)]
struct DeviceRecord {
    #[allow(dead_code)]
    at_pk: String,
    #[allow(dead_code)]
    pk_dv: String,
}

impl std::fmt::Debug for ErState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ErState")
            .field("signing_key_seed", &"<redacted>")
            .field("admin_token", &"<redacted>")
            .field("dip_verifying_key", &self.dip_verifying_key)
            .field("election_context", &self.election_context)
            .field("dip", &self.dip)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
struct TokenMeta {
    token_type: TokenType,
    vid: Vid,
    rid: Option<String>,
    used: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenType {
    Registration,
    PinRequest,
    Retrieval,
    Ns,
}

impl ErState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        signing_key: SigningKey,
        admin_token: SecretString,
        dip_verifying_key: VerifyingKey,
        election_context: ElectionContext<RistrettoGroup>,
        election: crate::configuration::ElectionSettings,
        wbb_client: WbbClient,
        dip: DipSettings,
        enrollment_packages: Vec<EnrollmentPackage>,
        clock: LogicalClock,
        token_seed: ActorSeed,
        internal_token: SecretString,
    ) -> Self {
        Self {
            signing_key_seed: SecretString::new(hex::encode(signing_key.to_bytes())),
            admin_token,
            dip_verifying_key,
            election_context,
            election,
            wbb_client,
            dip,
            enrollment_packages,
            enrolled_vids: Arc::new(Mutex::new(HashSet::new())),
            tokens: Arc::new(Mutex::new(HashMap::new())),
            token_counter: Arc::new(Mutex::new(0)),
            devices: Arc::new(Mutex::new(HashMap::new())),
            last_rid: Arc::new(Mutex::new(HashMap::new())),
            clock: Arc::new(Mutex::new(clock)),
            token_seed,
            internal_token,
        }
    }

    fn signing_key(&self) -> SigningKey {
        let seed = hex::decode(self.signing_key_seed.expose_secret())
            .expect("valid hex seed")
            .try_into()
            .expect("seed length is 32");
        SigningKey::from_bytes(&seed)
    }

    /// Mint a fresh single-use token from the ER's dedicated operation seed
    /// (§9.2; deliberately decoupled from the WBB entry-signing key).
    async fn next_token(&self, token_type: TokenType, vid: Vid, rid: Option<String>) -> TokenValue {
        use rand::RngCore;
        let mut counter = self.token_counter.lock().await;
        *counter += 1;
        let mut rng = operation_rng(&self.token_seed, "er-token", *counter);
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let token = TokenValue::from_bytes(bytes);
        self.tokens.lock().await.insert(
            token.clone(),
            TokenMeta {
                token_type,
                vid,
                rid,
                used: false,
            },
        );
        token
    }

    /// Validate a token without consuming it (registration tokens act as the
    /// enrollment session credential and stay valid for the whole enrollment).
    async fn verify_token(
        &self,
        token: &TokenValue,
        expected_type: TokenType,
    ) -> Result<TokenMeta, ErError> {
        let map = self.tokens.lock().await;
        let meta = map.get(token).ok_or(ErError::Unauthorized)?.clone();
        if meta.token_type != expected_type || meta.used {
            return Err(ErError::Unauthorized);
        }
        Ok(meta)
    }

    fn verify_dip_assertion(
        &self,
        assertion: &DipAssertion,
        signature: &str,
    ) -> Result<(), ErError> {
        let signature_bytes = BASE64
            .decode(signature)
            .map_err(|_| ErError::Unauthorized)?;
        let signature = ed25519_dalek::Signature::from_bytes(
            signature_bytes
                .as_slice()
                .try_into()
                .map_err(|_| ErError::Unauthorized)?,
        );
        let msg = serde_json::to_vec(assertion).map_err(|_| ErError::Internal("json".into()))?;
        self.dip_verifying_key
            .verify(&msg, &signature)
            .map_err(|_| ErError::Unauthorized)
    }

    async fn publish_setup_entries(&self) -> Result<Vec<serde_json::Value>, ErError> {
        let ctx_json = serde_json::to_string(&self.election_context)?;
        let n_v = self.dip.voters.len();
        let n_acc = self.election.n_acc;
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
        let signing_key = self.signing_key();

        // One logical timestamp per artifact, advancing the clock in between
        // (roadmap §9.4).
        let timestamps: Vec<i64> = {
            let mut clock = self.clock.lock().await;
            data_strings
                .iter()
                .map(|_| {
                    let ts = clock.now_ms() as i64;
                    clock.advance();
                    ts
                })
                .collect()
        };

        // Signing and serialization run in spawn_blocking per roadmap §6.
        let signed_entries = tokio::task::spawn_blocking(move || {
            data_strings
                .into_iter()
                .zip(timestamps)
                .map(|(data, ts)| sign_entry(data.as_bytes(), &entity_id, ts, &signing_key))
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

#[derive(Debug, Serialize)]
struct SetupResponse {
    published: usize,
}

async fn setup_handler(
    Extension(state): Extension<Arc<ErState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<SetupResponse>, ErError> {
    check_admin_token(&headers, &state.admin_token)?;
    let results = state.publish_setup_entries().await?;
    Ok(Json(SetupResponse {
        published: results.len(),
    }))
}

#[derive(Debug, Deserialize)]
struct LoginRequest {
    assertion: DipAssertion,
    signature: String,
}

#[derive(Debug, Serialize)]
struct LoginResponse {
    vid: Vid,
    registration_token: TokenValue,
    credential_package: CredentialPackage,
}

async fn login_handler(
    Extension(state): Extension<Arc<ErState>>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, ErError> {
    state.verify_dip_assertion(&req.assertion, &req.signature)?;

    // Deterministic vid assignment: the i-th registry voter gets vid i (§3.5.3,
    // matches the ceremony's `assign_vids` ordering).  Re-login returns the
    // same vid with a fresh registration token.  Unknown ids get the same
    // generic 401 as a bad signature (anti-enumeration, style guide §09).
    let voter_index = state
        .dip
        .voters
        .iter()
        .position(|v| v.id == req.assertion.fiscal_id)
        .ok_or(ErError::Unauthorized)?;
    let vid = Vid::new((voter_index + 1) as u64)
        .map_err(|_| ErError::Internal("vid out of range".into()))?;

    let credential_package = state
        .enrollment_packages
        .get(voter_index)
        .map(EnrollmentPackage::credential_package)
        .ok_or_else(|| ErError::Internal("missing enrollment package".into()))?;

    let registration_token = state.next_token(TokenType::Registration, vid, None).await;
    state.enrolled_vids.lock().await.insert(vid);

    Ok(Json(LoginResponse {
        vid,
        registration_token,
        credential_package,
    }))
}

#[derive(Debug, Deserialize)]
struct DeviceRegisterRequest {
    registration_token: TokenValue,
    #[serde(default)]
    pk_dv: String,
    #[serde(default)]
    at_pk: String,
}

async fn device_register_handler(
    Extension(state): Extension<Arc<ErState>>,
    Json(req): Json<DeviceRegisterRequest>,
) -> Result<StatusCode, ErError> {
    let meta = state
        .verify_token(&req.registration_token, TokenType::Registration)
        .await?;
    state.devices.lock().await.insert(
        meta.vid,
        DeviceRecord {
            at_pk: req.at_pk,
            pk_dv: req.pk_dv,
        },
    );
    Ok(StatusCode::OK)
}

#[derive(Debug, Serialize)]
struct PinRequestTokensResponse {
    rid: String,
    rt_tokens: Vec<TokenValue>,
    ns_token: TokenValue,
}

async fn pin_request_tokens_handler(
    Extension(state): Extension<Arc<ErState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<PinRequestTokensResponse>, ErError> {
    let token = bearer_token(&headers)?;
    let meta = state.verify_token(&token, TokenType::Registration).await?;
    let rid = {
        let mut counter = state.token_counter.lock().await;
        *counter += 1;
        format!("rid-{}-{}", meta.vid.value(), *counter)
    };
    state.last_rid.lock().await.insert(meta.vid, rid.clone());

    let mut rt_tokens = Vec::with_capacity(state.election.n_rt);
    for _ in 0..state.election.n_rt {
        rt_tokens.push(
            state
                .next_token(TokenType::PinRequest, meta.vid, Some(rid.clone()))
                .await,
        );
    }
    let ns_token = state
        .next_token(TokenType::Ns, meta.vid, Some(rid.clone()))
        .await;

    Ok(Json(PinRequestTokensResponse {
        rid,
        rt_tokens,
        ns_token,
    }))
}

#[derive(Debug, Deserialize)]
struct RetrievalTokensRequest {
    assertion: DipAssertion,
    signature: String,
}

#[derive(Debug, Serialize)]
struct RetrievalTokensResponse {
    retrieval_tokens: Vec<TokenValue>,
}

async fn retrieval_tokens_handler(
    Extension(state): Extension<Arc<ErState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<RetrievalTokensRequest>,
) -> Result<Json<RetrievalTokensResponse>, ErError> {
    let token = bearer_token(&headers)?;
    let meta = state.verify_token(&token, TokenType::Registration).await?;
    state.verify_dip_assertion(&req.assertion, &req.signature)?;

    // Retrieval tokens are bound to the latest PIN-request rid for this vid;
    // a retrieval without a preceding PIN request is a protocol violation.
    let rid = state
        .last_rid
        .lock()
        .await
        .get(&meta.vid)
        .cloned()
        .ok_or(ErError::Unauthorized)?;
    let t_rt = state.election.t_rt;
    let mut retrieval_tokens = Vec::with_capacity(t_rt);
    for _ in 0..t_rt {
        retrieval_tokens.push(
            state
                .next_token(TokenType::Retrieval, meta.vid, Some(rid.clone()))
                .await,
        );
    }

    Ok(Json(RetrievalTokensResponse { retrieval_tokens }))
}

#[derive(Debug, Deserialize)]
struct VerifyTokenRequest {
    token: TokenValue,
    /// Expected token type (`registration`/`pinrequest`/`retrieval`/`ns`);
    /// verification fails if the token is of a different type.
    #[serde(default)]
    expected_type: Option<String>,
    /// When true, a valid single-use token is atomically marked consumed.
    #[serde(default)]
    consume: bool,
}

#[derive(Debug, Serialize)]
struct VerifyTokenResponse {
    valid: bool,
    token_type: Option<String>,
    vid: Option<Vid>,
    rid: Option<String>,
}

impl VerifyTokenResponse {
    fn invalid() -> Self {
        Self {
            valid: false,
            token_type: None,
            vid: None,
            rid: None,
        }
    }
}

/// Service-facing single-use token verification (§6.1).  Requires the shared
/// internal-API bearer token: voter clients never call this endpoint.
async fn verify_token_handler(
    Extension(state): Extension<Arc<ErState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<VerifyTokenRequest>,
) -> Result<Json<VerifyTokenResponse>, ErError> {
    check_admin_token(&headers, &state.internal_token)?;
    let mut map = state.tokens.lock().await;
    let Some(meta) = map.get_mut(&req.token) else {
        return Ok(Json(VerifyTokenResponse::invalid()));
    };
    let type_name = format!("{:?}", meta.token_type).to_lowercase();
    let type_matches = req
        .expected_type
        .as_deref()
        .map(|t| t == type_name)
        .unwrap_or(true);
    if meta.used || !type_matches {
        return Ok(Json(VerifyTokenResponse::invalid()));
    }
    if req.consume {
        meta.used = true;
    }
    Ok(Json(VerifyTokenResponse {
        valid: true,
        token_type: Some(type_name),
        vid: Some(meta.vid),
        rid: meta.rid.clone(),
    }))
}

fn check_admin_token(
    headers: &axum::http::HeaderMap,
    expected: &SecretString,
) -> Result<(), ErError> {
    let header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or(ErError::Unauthorized)?;
    let token = header
        .strip_prefix("Bearer ")
        .ok_or(ErError::Unauthorized)?;
    if !constant_time_eq::constant_time_eq(token.as_bytes(), expected.expose_secret().as_bytes()) {
        return Err(ErError::Unauthorized);
    }
    Ok(())
}

fn bearer_token(headers: &axum::http::HeaderMap) -> Result<TokenValue, ErError> {
    let header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or(ErError::Unauthorized)?;
    header
        .strip_prefix("Bearer ")
        .ok_or(ErError::Unauthorized)?
        .parse()
        .map_err(|_| ErError::Unauthorized)
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
        let (status, message) = match &self {
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, self.to_string()),
            // Internal failures are logged but not leaked (style guide §03).
            Self::Json(_) | Self::Wbb(_) | Self::Internal(_) => {
                tracing::error!(error = %self, "er-server internal error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal error".to_string(),
                )
            }
        };
        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}

pub fn router(state: Arc<ErState>) -> Router {
    with_state(
        health_router()
            .route("/admin/setup", post(setup_handler))
            .route("/login", post(login_handler))
            .route("/devices", post(device_register_handler))
            .route("/tokens/pin-request", post(pin_request_tokens_handler))
            .route("/tokens/retrieval", post(retrieval_tokens_handler))
            .route("/tokens/verify", post(verify_token_handler)),
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
    let dip_verifying_key = load_dip_verifying_key(&settings).await?;
    // Enrollment packages only exist once `election-admin gen-credentials` has
    // run; an ER booted before that (e.g. for setup publication) simply has no
    // voters to log in yet.
    let enrollment_packages = load_enrollment_packages(&settings)
        .await
        .unwrap_or_default();

    let wbb_client = build_wbb_client(&settings).await?;
    let token_seed = load_actor_seed(&settings).await?;
    let internal_token = crate::actors::common::load_internal_token(&settings).await?;

    let state = Arc::new(ErState::new(
        signing_key,
        admin_token,
        dip_verifying_key,
        election_context,
        settings.election.clone(),
        wbb_client,
        settings.dip.clone(),
        enrollment_packages,
        LogicalClock::new(settings.clock.base_ms, settings.clock.tick_ms),
        token_seed,
        internal_token,
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

/// Load the ER's dedicated operation seed (`er-seed.bin`, §9.2).
async fn load_actor_seed(settings: &Settings) -> anyhow::Result<ActorSeed> {
    let context_path = std::path::PathBuf::from(&settings._ceremony.election_context);
    let base_dir = context_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let path = base_dir.join("er-seed.bin");
    let bytes = tokio::fs::read(&path)
        .await
        .map_err(|e| anyhow::anyhow!("failed to read ER seed {}: {}", path.display(), e))?;
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("ER seed file must contain exactly 32 bytes"))?;
    Ok(ActorSeed::from_bytes(seed))
}

async fn load_dip_verifying_key(settings: &Settings) -> anyhow::Result<VerifyingKey> {
    let context_path = std::path::PathBuf::from(&settings._ceremony.election_context);
    let base_dir = context_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let path = base_dir.join("dip-signing-key.bin");
    let bytes = tokio::fs::read(&path)
        .await
        .map_err(|e| anyhow::anyhow!("failed to read DIP signing key {}: {}", path.display(), e))?;
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("DIP signing key file must contain exactly 32 bytes"))?;
    Ok(SigningKey::from_bytes(&seed).verifying_key())
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
    use sha2::Digest;
    let mut hasher = Sha256::new();
    master_seed.expose(|seed| hasher.update(seed));
    hasher.update(b"admin-token");
    SecretString::new(hex::encode(hasher.finalize()))
}

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
