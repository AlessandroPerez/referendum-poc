//! Ballot Box (BB) server (M6, §3.8.4 / roadmap §6.4).
//!
//! Endpoints:
//!   - `POST /ballots`          — CAT-authorized ballot intake: verifies the
//!     casting token with the ER (commB binding, single use), verifies the
//!     ballot proofs, stores it idempotently by digest, publishes
//!     `ballot_digest` + `ballot_metadata` to the WBB, returns a `Receipt`.
//!   - `POST /cai`              — CAI disclosure verification + publication.
//!   - `GET  /receipts/{digest}`— public receipt lookup.
//!   - `GET  /ballots`          — ballot release for the tally driver (M8).
//!
//! Receipts are minted on the logical clock (§9.4) — the library's
//! `InMemoryBB` uses wall-clock time, so the PoC keeps its own store built
//! from the library's public `BallotRecord`/`Receipt` types.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use axum::{
    extract::{Extension, Path},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use dlog_group::ristretto::RistrettoGroup;
use ed25519_dalek::SigningKey;
use evoting::api::client::Ballot;
use evoting::api::server::bb::{BallotRecord, ElectionContext, Receipt};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::actors::common::{health_router, serve_rustls, with_state};
use crate::clients::wbb::{sign_entry, WbbClient};
use crate::configuration::Settings;
use crate::domain::{BallotDigest, TokenValue};
use crate::protocol::clock::LogicalClock;
use crate::protocol::rng::{operation_rng, ActorSeed};
use crate::protocol::tls::{reqwest_client_trusting_ca, rustls_config_for_service};
use crate::protocol::voting::{
    ballot_digest, bb_id_encryption, comm_b, wbb_data_string, BallotDigestEntry,
    BallotMetadataEntry, CaiEntry,
};

type G = RistrettoGroup;

/// One stored ballot with its published artifacts.
struct StoredBallot {
    record: BallotRecord<G>,
    emoji: Vec<String>,
    cai: Option<CaiEntry>,
}

/// BB service state.
#[derive(Clone)]
pub struct BbState {
    entity_id: String,
    bb_id: u64,
    signing_key_seed: SecretString,
    service_token: SecretString,
    internal_token: SecretString,
    actor_seed: ActorSeed,
    election_context: ElectionContext<G>,
    wbb_client: WbbClient,
    er_client: crate::clients::er::ErClient,
    clock: Arc<Mutex<LogicalClock>>,
    enc_counter: Arc<AtomicU64>,
    next_seq: Arc<AtomicU64>,
    ballots: Arc<Mutex<HashMap<BallotDigest, StoredBallot>>>,
}

impl std::fmt::Debug for BbState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BbState")
            .field("entity_id", &self.entity_id)
            .field("bb_id", &self.bb_id)
            .field("signing_key_seed", &"<redacted>")
            .field("service_token", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl BbState {
    fn signing_key(&self) -> SigningKey {
        let seed = hex::decode(self.signing_key_seed.expose_secret())
            .expect("valid hex seed")
            .try_into()
            .expect("seed length is 32");
        SigningKey::from_bytes(&seed)
    }

    /// Sign and publish a WBB data string with a fresh logical timestamp.
    async fn publish(&self, data: &str) -> Result<(), BbError> {
        let timestamp = {
            let mut clock = self.clock.lock().await;
            let ts = clock.now_ms() as i64;
            clock.advance();
            ts
        };
        let signing_key = self.signing_key();
        let entity_id = self.entity_id.clone();
        let data_owned = data.to_string();
        let entry = tokio::task::spawn_blocking(move || {
            sign_entry(data_owned.as_bytes(), &entity_id, timestamp, &signing_key)
        })
        .await
        .map_err(|e| BbError::Internal(e.to_string()))?;
        self.wbb_client
            .submit_and_wait(&entry, std::time::Duration::from_secs(10))
            .await
            .map_err(|e| BbError::Internal(format!("WBB publication failed: {e}")))?;
        Ok(())
    }
}

// ── Handlers ────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct CastRequest {
    ballot: Ballot<G>,
    /// Hex-encoded 32-byte commitment randomness (§5.3.1.6).
    rndcomm: String,
    casting_token: TokenValue,
}

impl std::fmt::Debug for CastRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CastRequest")
            .field("rndcomm", &"<redacted>")
            .field("casting_token", &self.casting_token)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Serialize)]
struct CastResponse {
    digest: BallotDigest,
    receipt: Receipt,
    emoji: Vec<String>,
}

/// V12: ballot intake (§3.8.4, style guide §12 idempotency).
#[tracing::instrument(skip(state, req))]
async fn cast_handler(
    Extension(state): Extension<Arc<BbState>>,
    Json(req): Json<CastRequest>,
) -> Result<Json<CastResponse>, BbError> {
    let digest = ballot_digest(&req.ballot).map_err(|e| BbError::Internal(e.to_string()))?;

    // Idempotent replay: the same ballot (same digest) returns the stored
    // receipt without consuming another token (§12).
    if let Some(stored) = state.ballots.lock().await.get(&digest) {
        return Ok(Json(CastResponse {
            digest,
            receipt: stored.record.receipt,
            emoji: stored.emoji.clone(),
        }));
    }

    // Recompute commB from the submitted ballot + randomness and verify the
    // casting token with the ER (single use, commB binding, anonymous).
    let rndcomm: [u8; 32] = hex::decode(&req.rndcomm)
        .map_err(|_| BbError::BadRequest("rndcomm must be hex".into()))?
        .try_into()
        .map_err(|_| BbError::BadRequest("rndcomm must be 32 bytes".into()))?;
    let commitment = comm_b(&req.ballot, &rndcomm).map_err(|e| BbError::Internal(e.to_string()))?;
    let verification = state
        .er_client
        .verify_token_with_comm_b(
            &req.casting_token,
            Some("casting"),
            true,
            &commitment,
            &state.internal_token,
        )
        .await
        .map_err(|e| BbError::Internal(format!("ER token verification failed: {e}")))?;
    if !verification.valid {
        return Err(BbError::Unauthorized);
    }

    // Verify the ballot proofs against the election context (§3.8.4 step 5).
    let ctx = state.election_context.clone();
    let ballot = req.ballot.clone();
    tokio::task::spawn_blocking(move || ballot.verify(&ctx))
        .await
        .map_err(|e| BbError::Internal(e.to_string()))?
        .map_err(|_| BbError::BadRequest("ballot verification failed".into()))?;

    // Mint the receipt on the logical clock and store the ballot.
    let received_at_ms = {
        let mut clock = state.clock.lock().await;
        let ts = clock.now_ms();
        clock.advance();
        ts
    };
    let receipt = Receipt {
        seq_no: state.next_seq.fetch_add(1, Ordering::SeqCst),
        received_at_unix_ms: received_at_ms,
        bb_id: state.bb_id,
    };
    let emoji: Vec<String> = req
        .ballot
        .to_emoji()
        .iter()
        .map(|s| s.to_string())
        .collect();

    // E_pk_TT[g1^{2^bb_id}] (§3.8.4) with a seeded RNG (§9.2).
    let bb_id_enc = {
        let counter = state.enc_counter.fetch_add(1, Ordering::SeqCst);
        let mut rng = operation_rng(&state.actor_seed, "bb-id-enc", counter);
        bb_id_encryption(&state.election_context.pk, state.bb_id, &mut rng)
    };

    let record = BallotRecord {
        receipt,
        ballot: req.ballot,
        bb_id_enc: Some(bb_id_enc),
    };
    state.ballots.lock().await.insert(
        digest,
        StoredBallot {
            record,
            emoji: emoji.clone(),
            cai: None,
        },
    );

    // Publish digest + metadata to the WBB (roadmap §4.4).
    let digest_entry = BallotDigestEntry {
        digest,
        emoji: emoji.clone(),
        receipt,
    };
    let metadata_entry = BallotMetadataEntry {
        digest,
        bb_id: state.bb_id,
        bb_id_enc,
    };
    let digest_data = wbb_data_string("voting", "BB", "ballot_digest", 1, &digest_entry)
        .map_err(|e| BbError::Internal(e.to_string()))?;
    let metadata_data = wbb_data_string("voting", "BB", "ballot_metadata", 1, &metadata_entry)
        .map_err(|e| BbError::Internal(e.to_string()))?;
    state.publish(&digest_data).await?;
    state.publish(&metadata_data).await?;

    Ok(Json(CastResponse {
        digest,
        receipt,
        emoji,
    }))
}

#[derive(Debug, Deserialize)]
struct CaiRequest {
    digest: BallotDigest,
    disclosure: evoting::api::prelude::DiscloseCAI<G>,
}

#[derive(Debug, Serialize)]
struct CaiResponse {
    digest: BallotDigest,
    confirmed_at_ms: u64,
}

/// V13: CAI disclosure verification + `cast_intended_proof` publication
/// (§3.8.4 steps 11–16).
#[tracing::instrument(skip(state, req))]
async fn cai_handler(
    Extension(state): Extension<Arc<BbState>>,
    Json(req): Json<CaiRequest>,
) -> Result<Json<CaiResponse>, BbError> {
    // Idempotent replay of an already-confirmed disclosure.
    {
        let ballots = state.ballots.lock().await;
        let stored = ballots.get(&req.digest).ok_or(BbError::NotFound)?;
        if let Some(cai) = &stored.cai {
            return Ok(Json(CaiResponse {
                digest: req.digest,
                confirmed_at_ms: cai.confirmed_at_ms,
            }));
        }
        // Verify the disclosure against the stored ballot (drop the lock for
        // the crypto below by cloning what we need).
    }
    let ballot = {
        let ballots = state.ballots.lock().await;
        ballots
            .get(&req.digest)
            .ok_or(BbError::NotFound)?
            .record
            .ballot
            .clone()
    };
    let ctx = state.election_context.clone();
    let disclosure = req.disclosure.clone();
    let valid =
        tokio::task::spawn_blocking(move || ballot.verify_cai_disclosure(&disclosure, &ctx))
            .await
            .map_err(|e| BbError::Internal(e.to_string()))?;
    if !valid {
        return Err(BbError::BadRequest("CAI disclosure does not verify".into()));
    }

    let confirmed_at_ms = {
        let mut clock = state.clock.lock().await;
        let ts = clock.now_ms();
        clock.advance();
        ts
    };
    let entry = CaiEntry {
        digest: req.digest,
        bb_id: state.bb_id,
        disclosure: req.disclosure,
        confirmed_at_ms,
    };

    // Reserve the CAI slot under the lock BEFORE publishing so a concurrent
    // same-digest disclosure replays instead of double-publishing; roll the
    // reservation back if publication fails.
    {
        let mut ballots = state.ballots.lock().await;
        let stored = ballots.get_mut(&req.digest).ok_or(BbError::NotFound)?;
        if let Some(existing) = &stored.cai {
            return Ok(Json(CaiResponse {
                digest: req.digest,
                confirmed_at_ms: existing.confirmed_at_ms,
            }));
        }
        stored.cai = Some(entry.clone());
    }

    let data = wbb_data_string("voting", "BB", "cast_intended_proof", 1, &entry)
        .map_err(|e| BbError::Internal(e.to_string()))?;
    if let Err(e) = state.publish(&data).await {
        if let Some(stored) = state.ballots.lock().await.get_mut(&req.digest) {
            stored.cai = None;
        }
        return Err(e);
    }

    Ok(Json(CaiResponse {
        digest: req.digest,
        confirmed_at_ms,
    }))
}

#[derive(Debug, Serialize)]
struct ReceiptResponse {
    digest: BallotDigest,
    receipt: Receipt,
    emoji: Vec<String>,
    cai_confirmed: bool,
}

/// Public receipt lookup (V14 support).
async fn receipt_handler(
    Extension(state): Extension<Arc<BbState>>,
    Path(digest): Path<String>,
) -> Result<Json<ReceiptResponse>, BbError> {
    let digest: BallotDigest = digest
        .parse()
        .map_err(|_| BbError::BadRequest("invalid digest".into()))?;
    let ballots = state.ballots.lock().await;
    let stored = ballots.get(&digest).ok_or(BbError::NotFound)?;
    Ok(Json(ReceiptResponse {
        digest,
        receipt: stored.record.receipt,
        emoji: stored.emoji.clone(),
        cai_confirmed: stored.cai.is_some(),
    }))
}

/// Ballot release for the tally driver (§3.9 step 2; auth: service token).
async fn ballots_handler(
    Extension(state): Extension<Arc<BbState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<BallotRecord<G>>>, BbError> {
    require_bearer(&headers, &state.service_token)?;
    let ballots = state.ballots.lock().await;
    let mut records: Vec<BallotRecord<G>> = ballots.values().map(|s| s.record.clone()).collect();
    records.sort_by_key(|r| r.receipt.seq_no);
    Ok(Json(records))
}

fn require_bearer(headers: &HeaderMap, expected: &SecretString) -> Result<(), BbError> {
    let header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or(BbError::Unauthorized)?;
    let token = header
        .strip_prefix("Bearer ")
        .ok_or(BbError::Unauthorized)?;
    if !constant_time_eq::constant_time_eq(token.as_bytes(), expected.expose_secret().as_bytes()) {
        return Err(BbError::Unauthorized);
    }
    Ok(())
}

// ── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
enum BbError {
    #[error("unauthorized")]
    Unauthorized,
    #[error("not found")]
    NotFound,
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("internal error: {0}")]
    Internal(String),
}

impl IntoResponse for BbError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, self.to_string()),
            Self::NotFound => (StatusCode::NOT_FOUND, self.to_string()),
            Self::BadRequest(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            // Internal failures are logged but not leaked (style guide §03).
            Self::Internal(_) => {
                tracing::error!(error = %self, "bb-server internal error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal error".to_string(),
                )
            }
        };
        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}

// ── Router / startup ────────────────────────────────────────────────────────

pub fn router(state: Arc<BbState>) -> Router {
    with_state(
        health_router()
            .route("/ballots", post(cast_handler).get(ballots_handler))
            .route("/cai", post(cai_handler))
            .route("/receipts/:digest", get(receipt_handler)),
        state,
    )
}

/// Run the BB service from settings and signing key.
pub async fn run(settings: Settings, signing_key: SigningKey) -> anyhow::Result<()> {
    let (addr, rustls_config, state) = build_service(settings, signing_key).await?;
    serve_rustls(router(state), addr, rustls_config).await
}

/// Build the BB service components without blocking on `serve_rustls`.
pub async fn build_service(
    settings: Settings,
    signing_key: SigningKey,
) -> anyhow::Result<(
    SocketAddr,
    axum_server::tls_rustls::RustlsConfig,
    Arc<BbState>,
)> {
    let election_context = load_election_context(&settings).await?;
    let ceremony_dir = ceremony_dir(&settings);
    let service_token = load_secret_file(
        &ceremony_dir.join(format!("{}-service-token.txt", settings.service.name)),
    )
    .await?;
    let internal_token = crate::actors::common::load_internal_token(&settings).await?;
    let actor_seed = load_actor_seed(&settings).await?;

    let ca_pem = tokio::fs::read_to_string(&settings.tls.ca_pem)
        .await
        .map_err(|e| anyhow::anyhow!("failed to read CA cert: {e}"))?;
    let http_client = reqwest_client_trusting_ca(&ca_pem)?;
    let wbb_client = WbbClient::new(
        http_client.clone(),
        reqwest::Url::parse(&settings.wbb.base_url)
            .map_err(|e| anyhow::anyhow!("invalid WBB URL: {e}"))?,
    );
    let er_client = crate::clients::er::ErClient::new(
        http_client,
        reqwest::Url::parse(&settings.er.base_url)
            .map_err(|e| anyhow::anyhow!("invalid ER URL: {e}"))?,
    );

    let bb_id = bb_index_from_name(&settings.service.name)?;
    let state = Arc::new(BbState {
        entity_id: settings.service.name.to_uppercase(),
        bb_id,
        signing_key_seed: SecretString::new(hex::encode(signing_key.to_bytes())),
        service_token,
        internal_token,
        actor_seed,
        election_context,
        wbb_client,
        er_client,
        clock: Arc::new(Mutex::new(LogicalClock::new(
            settings.clock.base_ms,
            settings.clock.tick_ms,
        ))),
        enc_counter: Arc::new(AtomicU64::new(0)),
        next_seq: Arc::new(AtomicU64::new(0)),
        ballots: Arc::new(Mutex::new(HashMap::new())),
    });

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

fn ceremony_dir(settings: &Settings) -> std::path::PathBuf {
    std::path::PathBuf::from(&settings._ceremony.election_context)
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .to_path_buf()
}

fn bb_index_from_name(name: &str) -> anyhow::Result<u64> {
    name.strip_prefix("bb-")
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| anyhow::anyhow!("BB service name must be 'bb-{{i}}', got {name}"))
}

async fn load_election_context(settings: &Settings) -> anyhow::Result<ElectionContext<G>> {
    let path = std::path::PathBuf::from(&settings._ceremony.election_context);
    let bytes = tokio::fs::read(&path)
        .await
        .map_err(|e| anyhow::anyhow!("failed to read {}: {}", path.display(), e))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| anyhow::anyhow!("failed to parse election context: {e}"))
}

async fn load_secret_file(path: &std::path::Path) -> anyhow::Result<SecretString> {
    let token = tokio::fs::read_to_string(path)
        .await
        .map_err(|e| anyhow::anyhow!("failed to read secret {}: {}", path.display(), e))?
        .trim()
        .to_string();
    Ok(SecretString::new(token))
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
