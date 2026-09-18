//! Electoral Roll (ER) server.
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
use crate::domain::{CommB, TokenValue, Vid};
use crate::protocol::acc::CredentialPackage;
use crate::protocol::clock::Clock;
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
    /// `A` and `E[A]` per credential - the ER never holds a teller share.
    credential_packages: Vec<CredentialPackage>,
    enrolled_vids: Arc<Mutex<HashSet<Vid>>>,
    tokens: Arc<Mutex<HashMap<TokenValue, TokenMeta>>>,
    token_counter: Arc<Mutex<u64>>,
    /// Registered device records, keyed by vid.
    devices: Arc<Mutex<HashMap<Vid, DeviceRecord>>>,
    /// Latest PIN-request rid per vid (needed by retrieval-token issuance).
    last_rid: Arc<Mutex<HashMap<Vid, String>>>,
    /// Clock for WBB entry timestamps (logical in tests, wall in real runs).
    clock: Arc<Mutex<Clock>>,
    /// Revoked vids (V9); their credentials are excluded from the eligible
    /// list and filtered at tally.
    revoked_vids: Arc<Mutex<HashSet<Vid>>>,
    /// Post-revocation vid reassignments, keyed by fiscal id (V9).
    vid_overrides: Arc<Mutex<HashMap<String, Vid>>>,
    /// Next spare vid to hand out on revocation (n_voters+1 ..= n_acc).
    next_spare_vid: Arc<Mutex<u64>>,
    /// Casting tokens issued per vid, keyed by ballot commitment (CAT rate
    /// limit over DISTINCT commitments).  Re-requesting tokens for
    /// the SAME commitment returns the cached tokens instead of minting new
    /// ones, so idempotent re-casts neither burn budget nor grow the store.
    cast_commitments: Arc<Mutex<HashMap<Vid, CommitmentTokens>>>,
    /// Dedicated operation seed (`er-seed.bin`) for token generation.
    token_seed: ActorSeed,
    /// Shared internal-API token authenticating service->service calls
    /// (`/tokens/verify`).
    internal_token: SecretString,
}

/// Casting tokens issued for each of a voter's distinct ballot commitments.
type CommitmentTokens = HashMap<CommB, Vec<TokenValue>>;

/// A registered voter device (PoC: app public key + opaque state blob).
#[derive(Clone)]
struct DeviceRecord {
    at_pk: String,
    #[allow(dead_code)]
    pk_dv: String,
    /// Passphrase-encrypted voter state (Deviation 6): the ER cannot read it;
    /// it is returned verbatim on new-device recovery (V8).
    state_blob: Option<String>,
}

impl std::fmt::Debug for DeviceRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceRecord")
            .field("at_pk", &self.at_pk)
            .field("state_blob", &"<opaque>")
            .finish_non_exhaustive()
    }
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
    /// Casting tokens are bound to the ballot commitment `commB` (Sec. 5.3.1.6).
    comm_b: Option<CommB>,
    used: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenType {
    Registration,
    PinRequest,
    Retrieval,
    Ns,
    Casting,
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
        credential_packages: Vec<CredentialPackage>,
        clock: Clock,
        token_seed: ActorSeed,
        internal_token: SecretString,
    ) -> Self {
        let first_spare = election.n_voters as u64 + 1;
        Self {
            signing_key_seed: SecretString::new(hex::encode(signing_key.to_bytes())),
            admin_token,
            dip_verifying_key,
            election_context,
            election,
            wbb_client,
            dip,
            credential_packages,
            enrolled_vids: Arc::new(Mutex::new(HashSet::new())),
            tokens: Arc::new(Mutex::new(HashMap::new())),
            token_counter: Arc::new(Mutex::new(0)),
            devices: Arc::new(Mutex::new(HashMap::new())),
            last_rid: Arc::new(Mutex::new(HashMap::new())),
            clock: Arc::new(Mutex::new(clock)),
            revoked_vids: Arc::new(Mutex::new(HashSet::new())),
            vid_overrides: Arc::new(Mutex::new(HashMap::new())),
            next_spare_vid: Arc::new(Mutex::new(first_spare)),
            cast_commitments: Arc::new(Mutex::new(HashMap::new())),
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
    /// (deliberately decoupled from the WBB entry-signing key).
    async fn next_token(
        &self,
        token_type: TokenType,
        vid: Vid,
        rid: Option<String>,
        comm_b: Option<CommB>,
    ) -> TokenValue {
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
                comm_b,
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

    /// Resolve a fiscal id to its EFFECTIVE vid: the ceremony assignment
    /// (index+1, Sec. 3.5.3) unless a revocation reassigned it (V9).
    async fn effective_vid(&self, fiscal_id: &str) -> Result<Vid, ErError> {
        if let Some(vid) = self.vid_overrides.lock().await.get(fiscal_id) {
            return Ok(*vid);
        }
        let voter_index = self
            .dip
            .voters
            .iter()
            .position(|v| v.id == fiscal_id)
            .ok_or(ErError::Unauthorized)?;
        Vid::new((voter_index + 1) as u64).map_err(|_| ErError::Internal("vid out of range".into()))
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

        // One timestamp per artifact, advancing the clock in between
        // (a no-op on the wall clock).
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

        // Signing and serialization run in spawn_blocking.
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

    // Deterministic vid assignment: the i-th registry voter gets vid i (Sec. 3.5.3,
    // matches the ceremony's `assign_vids` ordering), unless a revocation
    // reassigned a spare vid (V9).  Re-login returns the same vid with a
    // fresh registration token.  Unknown ids get the same generic 401 as a
    // bad signature (anti-enumeration).
    let vid = state.effective_vid(&req.assertion.fiscal_id).await?;

    let credential_package = state
        .credential_packages
        .get((vid.value() - 1) as usize)
        .cloned()
        .ok_or_else(|| ErError::Internal("missing enrollment package".into()))?;

    let registration_token = state
        .next_token(TokenType::Registration, vid, None, None)
        .await;
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
    /// Passphrase-encrypted voter state blob (Deviation 6, base64).
    #[serde(default)]
    state_blob: Option<String>,
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
            state_blob: req.state_blob,
        },
    );
    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
struct DeviceBlobRequest {
    registration_token: TokenValue,
    /// Passphrase-encrypted voter state blob (base64).
    state_blob: String,
}

impl std::fmt::Debug for DeviceBlobRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceBlobRequest")
            .field("registration_token", &self.registration_token)
            .field("state_blob", &"<opaque>")
            .finish()
    }
}

/// Refresh the stored recovery blob (called after PIN retrieval, V8).
#[tracing::instrument(skip(state, req))]
async fn device_blob_handler(
    Extension(state): Extension<Arc<ErState>>,
    Json(req): Json<DeviceBlobRequest>,
) -> Result<StatusCode, ErError> {
    let meta = state
        .verify_token(&req.registration_token, TokenType::Registration)
        .await?;
    let mut devices = state.devices.lock().await;
    let record = devices.get_mut(&meta.vid).ok_or(ErError::Unauthorized)?;
    record.state_blob = Some(req.state_blob);
    Ok(StatusCode::OK)
}

#[derive(Debug, Deserialize)]
struct DeviceRecoverRequest {
    assertion: DipAssertion,
    signature: String,
}

#[derive(Serialize)]
struct DeviceRecoverResponse {
    vid: Vid,
    /// Passphrase-encrypted state blob - only the passphrase holder can
    /// decrypt it (Sec. 3.7.4 approximation, Deviation 6).
    state_blob: String,
}

impl std::fmt::Debug for DeviceRecoverResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceRecoverResponse")
            .field("vid", &self.vid)
            .field("state_blob", &"<opaque>")
            .finish()
    }
}

/// V8: new-device recovery - a fresh DIP login returns the encrypted state
/// blob; the passphrase check happens client-side by decryption (fails
/// closed on a wrong passphrase).
#[tracing::instrument(skip(state, req))]
async fn device_recover_handler(
    Extension(state): Extension<Arc<ErState>>,
    Json(req): Json<DeviceRecoverRequest>,
) -> Result<Json<DeviceRecoverResponse>, ErError> {
    state.verify_dip_assertion(&req.assertion, &req.signature)?;
    let vid = state.effective_vid(&req.assertion.fiscal_id).await?;
    let devices = state.devices.lock().await;
    let record = devices.get(&vid).ok_or(ErError::Unauthorized)?;
    let state_blob = record.state_blob.clone().ok_or(ErError::Unauthorized)?;
    Ok(Json(DeviceRecoverResponse { vid, state_blob }))
}

#[derive(Debug, Deserialize)]
struct RevocationRequest {
    assertion: DipAssertion,
    signature: String,
}

#[derive(Debug, Serialize)]
struct RevocationResponse {
    /// The freshly assigned spare vid (Sec. 3.7.5).
    vid: Vid,
    registration_token: TokenValue,
    credential_package: CredentialPackage,
}

/// V9: revoke the caller's credential and re-issue a spare vid (Sec. 3.7.5).
///
/// Publishes a salted-hash `{phase},ER,revocation_commitment,1,...` entry in
/// the board's current phase (setup during enrollment, or voting): the
/// commitment binds (old vid, new vid) without revealing the linkage. The
/// revocation takes effect only after the entry is published.
#[tracing::instrument(skip(state, req))]
async fn revocation_handler(
    Extension(state): Extension<Arc<ErState>>,
    Json(req): Json<RevocationRequest>,
) -> Result<Json<RevocationResponse>, ErError> {
    state.verify_dip_assertion(&req.assertion, &req.signature)?;

    // The spare-id counter stays locked for the whole operation, state
    // changes included: requests are fully serialised, so a second request of
    // the same voter sees the id the first one issued and revokes THAT.
    let mut next_spare = state.next_spare_vid.lock().await;
    let old_vid = state.effective_vid(&req.assertion.fiscal_id).await?;

    // A credential can be revoked from enrollment until the end of voting
    // (Sec. 3.7.5); enrollment happens in the board's setup window, so the
    // entry is stamped with the board's CURRENT phase.
    let phase = state.wbb_client.phase().await?;
    if phase != "setup" && phase != "voting" {
        return Err(ErError::RevocationClosed);
    }

    // The board, not this process's memory, is the record of which spare ids
    // are taken: every published commitment consumed exactly one.
    let published: HashSet<String> = state
        .wbb_client
        .entries()
        .await?
        .entries
        .iter()
        .filter_map(|e| e.entry.get("data").and_then(|v| v.as_str()))
        .filter_map(|b64| {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.decode(b64).ok()
        })
        .filter_map(|data| crate::protocol::voting::parse_wbb_data(&data))
        .filter(|parsed| parsed.entry_type == "revocation_commitment")
        .filter_map(|parsed| parsed.decode_payload::<serde_json::Value>().ok())
        .filter_map(|payload| payload["commitment"].as_str().map(str::to_owned))
        .collect();

    // Commitment to (old, new): SHA3-256(domain || salt || old || new); the
    // salt comes from the ER operation seed so the pair is not publicly
    // linkable, and the value is deterministic in (old, new).
    let commit = |new_vid: u64| {
        use rand::RngCore;
        use sha3::{Digest as _, Sha3_256};
        let mut salt_rng = operation_rng(&state.token_seed, "revocation-salt", old_vid.value());
        let mut salt = [0u8; 32];
        salt_rng.fill_bytes(&mut salt);
        let mut hasher = Sha3_256::new();
        hasher.update(b"referendum-poc-revocation");
        hasher.update(salt);
        hasher.update(old_vid.value().to_le_bytes());
        hasher.update(new_vid.to_le_bytes());
        hex::encode(hasher.finalize())
    };

    // An earlier attempt for this same vid may have reached the board without
    // this process recording it (a lost answer): adopt that spare id instead
    // of publishing a second commitment. Otherwise take the first id that
    // neither the board nor this process has handed out.
    let first_spare = state.election.n_voters as u64 + 1;
    let last_spare = state.election.n_acc as u64;
    let adopted = (first_spare..=last_spare).find(|k| published.contains(&commit(*k)));
    let already_published = adopted.is_some();
    let new_vid_value =
        adopted.unwrap_or_else(|| (*next_spare).max(first_spare + published.len() as u64));
    if new_vid_value > last_spare {
        return Err(ErError::SparesExhausted);
    }
    let new_vid =
        Vid::new(new_vid_value).map_err(|_| ErError::Internal("vid out of range".into()))?;
    let commitment = commit(new_vid_value);

    let payload = serde_json::json!({ "commitment": commitment });
    let data = crate::protocol::voting::wbb_data_string(
        &phase,
        "ER",
        "revocation_commitment",
        1,
        &payload,
    )
    .map_err(|e| ErError::Internal(e.to_string()))?;
    let timestamp = {
        let mut clock = state.clock.lock().await;
        let ts = clock.now_ms() as i64;
        clock.advance();
        ts
    };
    let signing_key = state.signing_key();
    let entry = tokio::task::spawn_blocking(move || {
        sign_entry(data.as_bytes(), "ER-1", timestamp, &signing_key)
    })
    .await
    .map_err(|e| ErError::Internal(e.to_string()))?;
    if !already_published {
        if let Err(e) = state
            .wbb_client
            .submit_and_wait(&entry, std::time::Duration::from_secs(10))
            .await
        {
            // An HTTP answer is a refusal: nothing was published, nothing is
            // consumed. Anything else (transport error, not sequenced in
            // time) leaves the outcome UNKNOWN - the commitment may still
            // land - so this id is set aside: the next voter must not get it.
            // The same voter's retry adopts it if it did land.
            if !matches!(e, crate::clients::wbb::WbbError::Http(..)) {
                *next_spare = (*next_spare).max(new_vid_value + 1);
            }
            return Err(ErError::Internal(format!("WBB publication failed: {e}")));
        }
    }

    // The commitment is public: only now does the revocation take effect.
    *next_spare = (*next_spare).max(new_vid_value + 1);
    state.revoked_vids.lock().await.insert(old_vid);
    state
        .vid_overrides
        .lock()
        .await
        .insert(req.assertion.fiscal_id.clone(), new_vid);
    // The new credential has no device/session state yet.
    state.devices.lock().await.remove(&old_vid);
    // Defense in depth: kill every outstanding token of the revoked vid so
    // its registration session cannot mint casting tokens any more (the
    // tally-side ACC filtering remains the protocol-level backstop).
    for meta in state.tokens.lock().await.values_mut() {
        if meta.vid == old_vid {
            meta.used = true;
        }
    }
    // Every state change is in place: let the next revocation in.
    drop(next_spare);

    let credential_package = state
        .credential_packages
        .get((new_vid.value() - 1) as usize)
        .cloned()
        .ok_or_else(|| ErError::Internal("missing spare enrollment package".into()))?;
    let registration_token = state
        .next_token(TokenType::Registration, new_vid, None, None)
        .await;
    state.enrolled_vids.lock().await.insert(new_vid);

    Ok(Json(RevocationResponse {
        vid: new_vid,
        registration_token,
        credential_package,
    }))
}

#[derive(Debug, Serialize)]
struct EligibleResponse {
    vids: Vec<Vid>,
}

impl ErState {
    /// The eligible vid list: assigned (with revocation overrides applied)
    /// minus revoked (A7).
    async fn eligible_vids(&self) -> Result<Vec<Vid>, ErError> {
        let overrides = self.vid_overrides.lock().await;
        let revoked = self.revoked_vids.lock().await;
        let mut vids = Vec::with_capacity(self.dip.voters.len());
        for (index, voter) in self.dip.voters.iter().enumerate() {
            let vid = match overrides.get(&voter.id) {
                Some(vid) => *vid,
                None => Vid::new((index + 1) as u64)
                    .map_err(|_| ErError::Internal("vid out of range".into()))?,
            };
            if !revoked.contains(&vid) {
                vids.push(vid);
            }
        }
        vids.sort_unstable();
        Ok(vids)
    }
}

/// A7 support: the eligible vid list (assigned minus revoked), also
/// published to the WBB at tally start.
async fn eligible_handler(
    Extension(state): Extension<Arc<ErState>>,
) -> Result<Json<EligibleResponse>, ErError> {
    let vids = state.eligible_vids().await?;
    Ok(Json(EligibleResponse { vids }))
}

#[derive(Debug, Serialize)]
struct PublishEligibleResponse {
    vids: Vec<Vid>,
}

/// A7: publish `tallying,ER,eligible_vids,1,...` at tally start, honoring
/// revocations (Sec. 3.9 step 1).
async fn publish_eligible_handler(
    Extension(state): Extension<Arc<ErState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<PublishEligibleResponse>, ErError> {
    check_admin_token(&headers, &state.admin_token)?;
    let vids = state.eligible_vids().await?;
    let data =
        crate::protocol::voting::wbb_data_string("tallying", "ER", "eligible_vids", 1, &vids)
            .map_err(|e| ErError::Internal(e.to_string()))?;
    let timestamp = {
        let mut clock = state.clock.lock().await;
        let ts = clock.now_ms() as i64;
        clock.advance();
        ts
    };
    let signing_key = state.signing_key();
    let entry = tokio::task::spawn_blocking(move || {
        sign_entry(data.as_bytes(), "ER-1", timestamp, &signing_key)
    })
    .await
    .map_err(|e| ErError::Internal(e.to_string()))?;
    state
        .wbb_client
        .submit_and_wait(&entry, std::time::Duration::from_secs(10))
        .await
        .map_err(|e| ErError::Internal(format!("WBB publication failed: {e}")))?;
    Ok(Json(PublishEligibleResponse { vids }))
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
                .next_token(TokenType::PinRequest, meta.vid, Some(rid.clone()), None)
                .await,
        );
    }
    let ns_token = state
        .next_token(TokenType::Ns, meta.vid, Some(rid.clone()), None)
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
                .next_token(TokenType::Retrieval, meta.vid, Some(rid.clone()), None)
                .await,
        );
    }

    Ok(Json(RetrievalTokensResponse { retrieval_tokens }))
}

#[derive(Deserialize)]
struct CastingTokensRequest {
    comm_b: CommB,
    /// Base64 EdDSA signature over the commB bytes, made with the voter's
    /// app secret key AtSK (Sec. 5.3.1.6, Sec. 3.13).
    signature: String,
}

impl std::fmt::Debug for CastingTokensRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CastingTokensRequest")
            .field("comm_b", &self.comm_b)
            .field("signature", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Serialize)]
struct CastingTokensResponse {
    /// One anonymous single-use token per ballot box, bound to `comm_b`.
    casting_tokens: Vec<TokenValue>,
}

/// V12: issue anonymous single-use casting tokens (Sec. 5.3.1.6).
///
/// The voter authenticates with the registration token and an EdDSA signature
/// over `comm_b` made with the registered app key; the ER rate-limits per vid
/// and binds each token to `comm_b` so the BB can check the commitment.
async fn casting_tokens_handler(
    Extension(state): Extension<Arc<ErState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<CastingTokensRequest>,
) -> Result<Json<CastingTokensResponse>, ErError> {
    let token = bearer_token(&headers)?;
    let meta = state.verify_token(&token, TokenType::Registration).await?;

    // Verify the AtSK signature against the device's registered app key.
    let at_pk = {
        let devices = state.devices.lock().await;
        let record = devices.get(&meta.vid).ok_or(ErError::Unauthorized)?;
        let bytes: [u8; 32] = hex::decode(&record.at_pk)
            .map_err(|_| ErError::Unauthorized)?
            .try_into()
            .map_err(|_| ErError::Unauthorized)?;
        VerifyingKey::from_bytes(&bytes).map_err(|_| ErError::Unauthorized)?
    };
    let signature_bytes: [u8; 64] = BASE64
        .decode(&req.signature)
        .map_err(|_| ErError::Unauthorized)?
        .try_into()
        .map_err(|_| ErError::Unauthorized)?;
    at_pk
        .verify(
            req.comm_b.as_bytes(),
            &ed25519_dalek::Signature::from_bytes(&signature_bytes),
        )
        .map_err(|_| ErError::Unauthorized)?;

    // CAT rate limit (max_casts_per_voter, Sec. 5.3.1.6) over DISTINCT ballot
    // commitments.  A re-request for an already-committed ballot replays the
    // cached tokens (idempotent: no budget burn, no token-store growth); the
    // reservation happens atomically under the lock, so the limit is
    // race-safe.
    {
        let mut commitments = state.cast_commitments.lock().await;
        let seen = commitments.entry(meta.vid).or_default();
        if let Some(cached) = seen.get(&req.comm_b) {
            if !cached.is_empty() {
                return Ok(Json(CastingTokensResponse {
                    casting_tokens: cached.clone(),
                }));
            }
        } else {
            if seen.len() >= state.election.max_casts_per_voter {
                return Err(ErError::RateLimited);
            }
            seen.insert(req.comm_b, Vec::new());
        }
    }

    let mut casting_tokens = Vec::with_capacity(state.election.n_bb);
    for _ in 0..state.election.n_bb {
        casting_tokens.push(
            state
                .next_token(TokenType::Casting, meta.vid, None, Some(req.comm_b))
                .await,
        );
    }
    if let Some(slot) = state
        .cast_commitments
        .lock()
        .await
        .entry(meta.vid)
        .or_default()
        .get_mut(&req.comm_b)
    {
        *slot = casting_tokens.clone();
    }
    Ok(Json(CastingTokensResponse { casting_tokens }))
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
    /// For casting tokens: the commitment the caller observed; must match the
    /// binding recorded at issuance (Sec. 5.3.1.6).
    #[serde(default)]
    comm_b: Option<CommB>,
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

/// Service-facing single-use token verification .  Requires the shared
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
    // Casting tokens are bound to commB: the caller must present the matching
    // commitment (Sec. 5.3.1.6).
    if let Some(bound) = &meta.comm_b {
        if req.comm_b.as_ref() != Some(bound) {
            return Ok(Json(VerifyTokenResponse::invalid()));
        }
    }
    if req.consume {
        meta.used = true;
    }
    // Casting tokens are anonymous towards the BB: no vid/rid in the response.
    let (vid, rid) = if meta.token_type == TokenType::Casting {
        (None, None)
    } else {
        (Some(meta.vid), meta.rid.clone())
    };
    Ok(Json(VerifyTokenResponse {
        valid: true,
        token_type: Some(type_name),
        vid,
        rid,
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
    #[error("casting rate limit exceeded")]
    RateLimited,
    #[error("credentials can no longer be revoked: the voting period is over")]
    RevocationClosed,
    #[error("no spare credential is left to re-issue")]
    SparesExhausted,
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
            Self::RateLimited => (StatusCode::TOO_MANY_REQUESTS, self.to_string()),
            Self::RevocationClosed => (StatusCode::CONFLICT, self.to_string()),
            Self::SparesExhausted => (StatusCode::CONFLICT, self.to_string()),
            // Internal failures are logged but not leaked.
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
            .route("/admin/eligible-vids", post(publish_eligible_handler))
            .route("/login", post(login_handler))
            .route("/devices", post(device_register_handler))
            .route("/devices/blob", post(device_blob_handler))
            .route("/devices/recover", post(device_recover_handler))
            .route("/revocations", post(revocation_handler))
            .route("/voters/eligible", axum::routing::get(eligible_handler))
            .route("/tokens/pin-request", post(pin_request_tokens_handler))
            .route("/tokens/retrieval", post(retrieval_tokens_handler))
            .route("/tokens/casting", post(casting_tokens_handler))
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
    // The credential file only exists once `election-admin gen-credentials`
    // has run; an ER booted before that (e.g. for setup publication) simply
    // has no voters to log in yet.
    let credential_packages = load_credential_packages(&settings).await?;

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
        credential_packages,
        Clock::from_settings(&settings.clock),
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

/// Load the ER's dedicated operation seed (`er-seed.bin`).
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

/// Load the ER's credential file: `A` and `E[A]` per credential. It holds no
/// registration-teller share, so the ER alone cannot rebuild a credential.
/// Absent before `gen-credentials` has run (the ER must then be restarted
/// once credentials exist).
async fn load_credential_packages(settings: &Settings) -> anyhow::Result<Vec<CredentialPackage>> {
    let context_path = std::path::PathBuf::from(&settings._ceremony.election_context);
    let base_dir = context_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let path = base_dir
        .join("output")
        .join(crate::protocol::acc::ER_CREDENTIALS_FILE);
    let bytes = match tokio::fs::read(&path).await {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => anyhow::bail!("failed to read credential packages {}: {e}", path.display()),
    };
    let packages: Vec<CredentialPackage> = serde_json::from_slice(&bytes)
        .map_err(|e| anyhow::anyhow!("failed to parse credential packages: {e}"))?;
    if packages.len() != settings.election.n_acc {
        anyhow::bail!(
            "{} holds {} credentials, the election has {}",
            path.display(),
            packages.len(),
            settings.election.n_acc
        );
    }
    Ok(packages)
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
