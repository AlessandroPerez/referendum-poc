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
use crate::protocol::cat::CastingToken;
use crate::protocol::clock::Clock;
use crate::protocol::merkle::voter_id_merkle_root;
use crate::protocol::rng::{operation_rng, ActorSeed, MasterSeed};
use crate::protocol::setup::{assign_vids, spare_holder_ids, voter_pairs};
use crate::protocol::tls::{reqwest_client_trusting_ca, rustls_config_for_service};

/// ER service state.
#[derive(Clone)]
pub struct ErState {
    signing_key_seed: SecretString,
    admin_token: SecretString,
    dip_verifying_key: VerifyingKey,
    election_context: ElectionContext<RistrettoGroup>,
    /// The tabulation tellers' public key shares from the ceremony, published
    /// at setup so every threshold decryption can be bound to its teller.
    teller_public_shares: Vec<crate::protocol::tally::TellerPublicShare>,
    election: crate::configuration::ElectionSettings,
    wbb_client: WbbClient,
    dip: DipSettings,
    /// `A` and `E[A]` per credential - the ER never holds a teller share.
    credential_packages: Vec<CredentialPackage>,
    enrolled_vids: Arc<Mutex<HashSet<Vid>>>,
    /// Nonces of the eID assertions already accepted (each is good once).
    used_assertions: Arc<Mutex<HashSet<String>>>,
    /// Serialises the once-only publication of the eligible list.
    publish_lock: Arc<Mutex<()>>,
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
    /// The request id of each voter's LAST completed revocation and the
    /// spare it issued. A device that never heard the answer sends the same
    /// id again and gets that spare back; any other request is a new
    /// revocation (an out-of-date second device included).
    revocation_requests: Arc<Mutex<HashMap<String, (String, Vid)>>>,
    /// Post-revocation vid reassignments, keyed by fiscal id (V9).
    vid_overrides: Arc<Mutex<HashMap<String, Vid>>>,
    /// The private random identifier assignment (Sec. 3.5.3): registry
    /// position -> vid, followed by the spare identifiers.
    vid_assignment: Arc<Vec<u64>>,
    /// Next spare SLOT to hand out on revocation (index into the spares).
    next_spare_vid: Arc<Mutex<u64>>,
    /// Casting tokens issued per vid, keyed by ballot commitment (CAT rate
    /// limit over DISTINCT commitments).  Re-requesting tokens for
    /// the SAME commitment returns the cached tokens instead of minting new
    /// ones, so idempotent re-casts neither burn budget nor grow the store.
    cast_commitments: Arc<Mutex<HashMap<Vid, CommitmentTokens>>>,
    /// When each vid last obtained tokens for a NEW ballot ("not too recently").
    last_cast_issue_ms: Arc<Mutex<HashMap<Vid, u64>>>,
    /// Dedicated operation seed (`er-seed.bin`) for token generation.
    token_seed: ActorSeed,
    /// Shared internal-API token authenticating service->service calls
    /// (`/tokens/verify`).
    internal_token: SecretString,
}

/// Casting tokens issued for each of a voter's distinct ballot commitments.
type CommitmentTokens = HashMap<CommB, Vec<CastingToken>>;

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
        teller_public_shares: Vec<crate::protocol::tally::TellerPublicShare>,
        election: crate::configuration::ElectionSettings,
        wbb_client: WbbClient,
        dip: DipSettings,
        credential_packages: Vec<CredentialPackage>,
        clock: Clock,
        token_seed: ActorSeed,
        internal_token: SecretString,
    ) -> Self {
        let vid_assignment = Arc::new(assign_vids(&token_seed, election.n_acc));
        Self {
            signing_key_seed: SecretString::new(hex::encode(signing_key.to_bytes())),
            admin_token,
            dip_verifying_key,
            election_context,
            teller_public_shares,
            election,
            wbb_client,
            dip,
            credential_packages,
            enrolled_vids: Arc::new(Mutex::new(HashSet::new())),
            used_assertions: Arc::new(Mutex::new(HashSet::new())),
            publish_lock: Arc::new(Mutex::new(())),
            tokens: Arc::new(Mutex::new(HashMap::new())),
            token_counter: Arc::new(Mutex::new(0)),
            devices: Arc::new(Mutex::new(HashMap::new())),
            last_rid: Arc::new(Mutex::new(HashMap::new())),
            clock: Arc::new(Mutex::new(clock)),
            revoked_vids: Arc::new(Mutex::new(HashSet::new())),
            revocation_requests: Arc::new(Mutex::new(HashMap::new())),
            vid_overrides: Arc::new(Mutex::new(HashMap::new())),
            vid_assignment,
            next_spare_vid: Arc::new(Mutex::new(0)),
            cast_commitments: Arc::new(Mutex::new(HashMap::new())),
            last_cast_issue_ms: Arc::new(Mutex::new(HashMap::new())),
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

    /// Mint a fresh opaque token from the ER's dedicated operation seed
    /// (deliberately decoupled from the WBB entry-signing key).
    async fn next_token(&self, token_type: TokenType, vid: Vid, rid: Option<String>) -> TokenValue {
        use rand::RngCore;
        let mut counter = self.token_counter.lock().await;
        *counter += 1;
        let mut bytes = [0u8; 32];
        // On a real run a token is fresh from the operating system: the
        // seed-and-counter stream is reproducible for the harness only, and
        // its counter is in memory - a restart would mint the same tokens
        // again.
        if self.clock.lock().await.mode() == crate::protocol::clock::ClockMode::Wall {
            rand::rngs::OsRng.fill_bytes(&mut bytes);
        } else {
            let mut rng = operation_rng(&self.token_seed, "er-token", *counter);
            rng.fill_bytes(&mut bytes);
        }
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

    /// Resolve a fiscal id to its EFFECTIVE vid: the private random
    /// assignment (Sec. 3.5.3) unless a revocation reassigned it (V9).
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
        self.assigned_vid(voter_index)
    }

    /// The identifier the private assignment gives to registry position `index`.
    fn assigned_vid(&self, index: usize) -> Result<Vid, ErError> {
        self.vid_assignment
            .get(index)
            .copied()
            .ok_or_else(|| ErError::Internal("registry larger than the credential pool".into()))
            .and_then(|vid| Vid::new(vid).map_err(|_| ErError::Internal("vid out of range".into())))
    }

    /// The spare identifiers, in the order they are handed out on revocation.
    fn spare_vids(&self) -> &[u64] {
        // Counted from the registry, like the published identifier tree: a
        // registered voter's identifier is never a spare.
        let first = self.dip.voters.len().min(self.vid_assignment.len());
        &self.vid_assignment[first..]
    }

    /// The identifiers assigned to the registry's voters, in increasing order
    /// (the order says nothing about who holds which).
    fn assigned_vids_sorted(&self) -> Vec<u64> {
        let mut assigned: Vec<u64> = self
            .vid_assignment
            .iter()
            .take(self.dip.voters.len())
            .copied()
            .collect();
        assigned.sort_unstable();
        assigned
    }

    /// The (holder, identifier) pairs this roll committed to at setup, in the
    /// same order the published Merkle root was computed over.
    fn committed_pairs(&self) -> Vec<(crate::protocol::merkle::LeafKind, String, u64)> {
        let n_v = self.dip.voters.len();
        let mut holder_ids: Vec<_> = self.dip.voters.iter().map(|v| v.id.clone()).collect();
        holder_ids.extend(spare_holder_ids(
            &self.token_seed,
            self.vid_assignment.len().saturating_sub(n_v),
        ));
        voter_pairs(&holder_ids, &self.vid_assignment, n_v)
    }

    /// The holder the identifier tree commits `vid` to: the voter's own
    /// registry id for an assigned identifier, a random string for a spare.
    fn committed_holder(&self, vid: Vid) -> Option<(crate::protocol::merkle::LeafKind, String)> {
        let index = self
            .vid_assignment
            .iter()
            .position(|assigned| *assigned == vid.value())?;
        use crate::protocol::merkle::LeafKind;
        let n_v = self.dip.voters.len();
        if index < n_v {
            return self
                .dip
                .voters
                .get(index)
                .map(|v| (LeafKind::Voter, v.id.clone()));
        }
        spare_holder_ids(&self.token_seed, self.vid_assignment.len() - n_v)
            .into_iter()
            .nth(index - n_v)
            .map(|holder| (LeafKind::Spare, holder))
    }

    /// The proof that `(holder, vid)` is a leaf of the published identifier
    /// tree (Sec. 3.5.3). Without it the identifier this roll hands out is
    /// its word alone, and it could quietly give a voter an identifier that
    /// belongs to nobody - whose ballot is then dropped by the last filter.
    fn vid_inclusion_proof(
        &self,
        kind: crate::protocol::merkle::LeafKind,
        holder: &str,
        vid: Vid,
    ) -> Result<Vec<crate::protocol::merkle::MerkleStep>, ErError> {
        crate::protocol::merkle::inclusion_proof(&self.committed_pairs(), kind, holder, vid.value())
            .ok_or_else(|| {
                ErError::Internal(
                    "the identifier assigned is not in the committed identifier tree".into(),
                )
            })
    }

    /// An eID login is accepted once, for this roll, and while fresh: an
    /// observed assertion must not be enough to log in, re-register a device
    /// or REVOKE a credential later on somebody else's behalf (thesis A5 and
    /// Sec. 3.7.5, whose revocation rests on the login alone).
    async fn verify_fresh_dip_assertion(
        &self,
        assertion: &DipAssertion,
        signature: &str,
    ) -> Result<(), ErError> {
        self.verify_dip_assertion(assertion, signature)?;
        if assertion.audience != crate::actors::dip::ASSERTION_AUDIENCE
            || assertion.nonce.is_empty()
        {
            return Err(ErError::Unauthorized);
        }
        {
            let clock = self.clock.lock().await;
            if clock.mode() == crate::protocol::clock::ClockMode::Wall {
                let now = clock.now_ms();
                const MAX_AGE_MS: u64 = 5 * 60 * 1000;
                if assertion.issued_at_ms + MAX_AGE_MS < now
                    || assertion.issued_at_ms > now + 60_000
                {
                    return Err(ErError::Unauthorized);
                }
            }
        }
        if !self
            .used_assertions
            .lock()
            .await
            .insert(assertion.nonce.clone())
        {
            return Err(ErError::Unauthorized);
        }
        Ok(())
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

    /// Which setup entry types this roll's board already carries.
    async fn published_setup_entry_types(
        &self,
    ) -> Result<std::collections::HashSet<String>, ErError> {
        Ok(self
            .wbb_client
            .board_entries()
            .await?
            .iter()
            .filter_map(|e| e.entry.get("data").and_then(|v| v.as_str()))
            .filter_map(|b64| BASE64.decode(b64).ok())
            .filter_map(|data| crate::protocol::voting::parse_wbb_data(&data))
            .filter(|parsed| parsed.phase == "setup" && parsed.role == "ER")
            .map(|parsed| parsed.entry_type)
            .collect())
    }

    async fn publish_setup_entries(&self) -> Result<usize, ErError> {
        let ctx_json = serde_json::to_string(&self.election_context)?;
        let n_v = self.dip.voters.len();
        let n_acc = self.election.n_acc;
        let count_json = serde_json::json!({ "n_v": n_v, "n_acc": n_acc }).to_string();

        // Leaves are the pairs (id, vid) for the voters AND for the spare
        // identifiers, whose holders are random strings (Sec. 3.5.3).
        let pairs = self.committed_pairs();
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
            // The identifiers assigned to the registered voters, sorted. The
            // electoral register is an INPUT of the setup, so the roll says
            // here - before anyone votes - which identifiers are in play; the
            // eligible list it publishes at tally is audited against this
            // one, and can differ from it only by revocations.
            format!(
                "setup,ER,assigned_vids,1,{}",
                BASE64.encode(serde_json::to_string(&self.assigned_vids_sorted())?.as_bytes())
            ),
            // The tabulation tellers' public key shares (Sec. 3.5.2): what a
            // threshold decryption's partials are held to, teller by teller.
            format!(
                "setup,ER,tt_public_shares,1,{}",
                BASE64.encode(serde_json::to_string(&self.teller_public_shares)?.as_bytes())
            ),
        ];

        // Published once per election, and only what is MISSING. The board is
        // append-only (Sec. 3.4.2, A3), the auditor requires exactly one of
        // each setup entry and the tally refuses two `tt_public_shares`, so a
        // second copy would make the election unauditable and stop the tally
        // for good. A run cut off part-way - a lost answer, a board that went
        // down between two of the five submissions - is finished by the next
        // call instead of duplicating what is already there.
        let already = self.published_setup_entry_types().await?;
        let data_strings: Vec<String> = data_strings
            .into_iter()
            .filter(|data| {
                crate::protocol::voting::parse_wbb_data(data.as_bytes())
                    .map_or(true, |parsed| !already.contains(&parsed.entry_type))
            })
            .collect();
        if data_strings.is_empty() {
            return Ok(0);
        }

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

        let mut published = 0usize;
        for entry in signed_entries {
            self.wbb_client.submit(&entry).await?;
            published += 1;
        }
        Ok(published)
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
    // One publication at a time, and only once per election: the board is
    // append-only and the auditor requires exactly one of each setup entry,
    // so a second call - an operator's retry, or a caller retrying after a
    // lost answer - would make the election unauditable for good and stop
    // the tally, which refuses a duplicate `tt_public_shares`. A repeat is
    // therefore adopted, not published again.
    let _publishing = state.publish_lock.lock().await;
    let published = state.publish_setup_entries().await?;
    Ok(Json(SetupResponse { published }))
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
    /// Who the published identifier tree commits this identifier to: the
    /// voter's own registry id, or - after a revocation - the random holder
    /// of the spare they were given.
    vid_holder: String,
    /// Whether that leaf is this voter's own identifier or a spare.
    vid_kind: crate::protocol::merkle::LeafKind,
    /// Proof that the leaf is in the tree published at setup: the app checks
    /// it against the root on the board.
    vid_proof: Vec<crate::protocol::merkle::MerkleStep>,
}

async fn login_handler(
    Extension(state): Extension<Arc<ErState>>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, ErError> {
    state
        .verify_fresh_dip_assertion(&req.assertion, &req.signature)
        .await?;

    // The voter's identifier comes from the ER's private random assignment
    // (Sec. 3.5.3), unless a revocation
    // reassigned a spare vid (V9).  Re-login returns the same vid with a
    // fresh registration token.  Unknown ids get the same generic 401 as a
    // bad signature (anti-enumeration).
    let vid = state.effective_vid(&req.assertion.fiscal_id).await?;

    let credential_package = state
        .credential_packages
        .get((vid.value() - 1) as usize)
        .cloned()
        .ok_or_else(|| ErError::Internal("missing enrollment package".into()))?;

    let registration_token = state.next_token(TokenType::Registration, vid, None).await;
    state.enrolled_vids.lock().await.insert(vid);

    // A revoked voter holds a spare, whose committed holder is a random
    // string rather than their fiscal id: the proof then names that holder,
    // and the app checks the pair as published.
    let (vid_kind, vid_holder) = state
        .committed_holder(vid)
        .ok_or_else(|| ErError::Internal("identifier outside the committed tree".into()))?;
    let vid_proof = state.vid_inclusion_proof(vid_kind, &vid_holder, vid)?;

    Ok(Json(LoginResponse {
        vid,
        registration_token,
        credential_package,
        vid_holder,
        vid_kind,
        vid_proof,
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
    /// When the app key changes for an identifier already registered: the
    /// new key, signed by the previous one (base64).
    #[serde(default)]
    rebind_signature: Option<String>,
}

async fn device_register_handler(
    Extension(state): Extension<Arc<ErState>>,
    Json(req): Json<DeviceRegisterRequest>,
) -> Result<StatusCode, ErError> {
    let meta = state
        .verify_token(&req.registration_token, TokenType::Registration)
        .await?;
    let mut devices = state.devices.lock().await;
    // Sec. 3.7.4 step 7: "the ER compares the received and stored values".
    // A device already registered for this identifier keeps its app key
    // unless the NEW key is signed by the OLD one - which only a device that
    // really recovered the voter's state can do. Otherwise anyone holding a
    // registration token could rebind the casting key and lock the voter out.
    if let Some(existing) = devices.get(&meta.vid) {
        if !existing.at_pk.is_empty() && existing.at_pk != req.at_pk {
            let old_key = hex::decode(&existing.at_pk)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .and_then(|b| ed25519_dalek::VerifyingKey::from_bytes(&b).ok())
                .ok_or(ErError::Unauthorized)?;
            let signature = req
                .rebind_signature
                .as_deref()
                .and_then(|s| BASE64.decode(s).ok())
                .and_then(|b| <[u8; 64]>::try_from(b).ok())
                .map(|bytes| ed25519_dalek::Signature::from_bytes(&bytes))
                .ok_or(ErError::Unauthorized)?;
            old_key
                .verify(req.at_pk.as_bytes(), &signature)
                .map_err(|_| ErError::Unauthorized)?;
        }
    }
    // A registration of the SAME key that carries no blob (a device
    // repairing a registration it could not confirm) keeps the blob already
    // stored: replacing it with nothing would leave the voter no recovery.
    let state_blob = match (req.state_blob, devices.get(&meta.vid)) {
        (Some(blob), _) => Some(blob),
        (None, Some(existing)) if existing.at_pk == req.at_pk => existing.state_blob.clone(),
        (None, _) => None,
    };
    devices.insert(
        meta.vid,
        DeviceRecord {
            at_pk: req.at_pk,
            pk_dv: req.pk_dv,
            state_blob,
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
    state
        .verify_fresh_dip_assertion(&req.assertion, &req.signature)
        .await?;
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
    /// A random id the device chose and saved BEFORE sending. The same id
    /// again is a RETRY of a revocation whose answer was lost; anything
    /// else is a new revocation.
    #[serde(default)]
    request_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct RevocationResponse {
    /// The freshly assigned spare vid (Sec. 3.7.5).
    vid: Vid,
    registration_token: TokenValue,
    credential_package: CredentialPackage,
    /// Who the published identifier tree commits that spare to (a random
    /// string, not the voter), and the proof of that pair: the app checks
    /// the spare really is one of the committed identifiers.
    vid_holder: String,
    vid_kind: crate::protocol::merkle::LeafKind,
    vid_proof: Vec<crate::protocol::merkle::MerkleStep>,
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
    state
        .verify_fresh_dip_assertion(&req.assertion, &req.signature)
        .await?;

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

    // Sec. 3.7.5: one request, one spare. The SAME request again - the id
    // the device saved before sending it - never heard its answer: it gets
    // that revocation's spare back (a fresh registration token for it) and
    // nothing else is revoked. Only the id decides: a device that is merely
    // out of date (a second device of the voter, still on a revoked
    // identifier) sends no matching id, and its revocation is a real one.
    if let Some(id) = req.request_id.as_deref() {
        let done = state
            .revocation_requests
            .lock()
            .await
            .get(&req.assertion.fiscal_id)
            .cloned();
        if let Some((done_id, issued)) = done {
            if done_id == id && issued == old_vid {
                drop(next_spare);
                tracing::info!(current = %old_vid, "revocation retried after a lost answer");
                return revocation_answer(&state, old_vid).await.map(Json);
            }
        }
    }

    // The board, not this process's memory, is the record of which spare ids
    // are taken: every published commitment consumed exactly one.
    let published: HashSet<String> = state
        .wbb_client
        .board_entries()
        .await?
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
    let spares = state.spare_vids();
    let adopted = spares
        .iter()
        .position(|vid| published.contains(&commit(*vid)));
    let already_published = adopted.is_some();
    // Every published commitment consumed one spare slot, in order.
    let slot = adopted.unwrap_or_else(|| (*next_spare as usize).max(published.len()));
    let Some(&new_vid_value) = spares.get(slot) else {
        return Err(ErError::SparesExhausted);
    };
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
                *next_spare = (*next_spare).max(slot as u64 + 1);
            }
            return Err(ErError::Internal(format!("WBB publication failed: {e}")));
        }
    }

    // The commitment is public: only now does the revocation take effect.
    *next_spare = (*next_spare).max(slot as u64 + 1);
    state.revoked_vids.lock().await.insert(old_vid);
    state
        .vid_overrides
        .lock()
        .await
        .insert(req.assertion.fiscal_id.clone(), new_vid);
    // The device's record moves onto the new identifier within the
    // revocation itself: the app key is kept, so the roll goes on issuing
    // this device its casting tokens, and the recovery blob is dropped, since
    // it describes the revoked credential. Were the record only removed, the
    // device would depend on a second request - its own re-registration - to
    // exist again, and that request lost would leave a voter revoked at the
    // roll and unable to retrieve, vote or cast, with no request that could
    // repair it (Sec. 3.7.5: the revocation is a fresh registration, and a
    // registration ends with a device the roll knows).
    {
        let mut devices = state.devices.lock().await;
        if let Some(mut record) = devices.remove(&old_vid) {
            record.state_blob = None;
            devices.insert(new_vid, record);
        }
    }
    // Defense in depth: kill every outstanding token of the revoked vid so
    // its registration session cannot mint casting tokens any more (the
    // tally-side ACC filtering remains the protocol-level backstop).
    for meta in state.tokens.lock().await.values_mut() {
        if meta.vid == old_vid {
            meta.used = true;
        }
    }
    if let Some(id) = req.request_id.clone() {
        state
            .revocation_requests
            .lock()
            .await
            .insert(req.assertion.fiscal_id.clone(), (id, new_vid));
    }
    // Every state change is in place: let the next revocation in.
    drop(next_spare);

    state.enrolled_vids.lock().await.insert(new_vid);
    revocation_answer(&state, new_vid).await.map(Json)
}

/// What a device needs to start over on the spare `new_vid`: its enrollment
/// package, a fresh registration token, and the proof that the spare is one
/// of the identifiers committed at setup.
async fn revocation_answer(state: &ErState, new_vid: Vid) -> Result<RevocationResponse, ErError> {
    let credential_package = state
        .credential_packages
        .get((new_vid.value() - 1) as usize)
        .cloned()
        .ok_or_else(|| ErError::Internal("missing spare enrollment package".into()))?;
    let registration_token = state
        .next_token(TokenType::Registration, new_vid, None)
        .await;
    let (vid_kind, vid_holder) = state
        .committed_holder(new_vid)
        .ok_or_else(|| ErError::Internal("spare outside the committed tree".into()))?;
    let vid_proof = state.vid_inclusion_proof(vid_kind, &vid_holder, new_vid)?;
    Ok(RevocationResponse {
        vid: new_vid,
        registration_token,
        credential_package,
        vid_holder,
        vid_kind,
        vid_proof,
    })
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
                None => self.assigned_vid(index)?,
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
/// The live eligible list. Not public: polled during voting it would show
/// each revocation's (old, new) pair as it happens - the linkage the salted
/// commitment of Sec. 3.7.5 exists to hide. The published list appears on the
/// board at tally, where the pairs are no longer distinguishable.
async fn eligible_handler(
    Extension(state): Extension<Arc<ErState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<EligibleResponse>, ErError> {
    check_admin_token(&headers, &state.admin_token)?;
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
    // One publication at a time: the check below and the publication that
    // follows it are a read-then-write, and two callers racing here would
    // put TWO lists on an append-only board - which no audit can forgive.
    let _publishing = state.publish_lock.lock().await;
    let vids = state.eligible_vids().await?;

    // The list is published once per election. A tally that failed after this
    // point and is run again must find it already there: a second entry would
    // make the election unauditable for good (the auditor requires exactly
    // one), and the board cannot take anything back.
    let published: Option<Vec<Vid>> = state
        .wbb_client
        .board_entries()
        .await?
        .iter()
        .filter_map(|e| e.entry.get("data").and_then(|v| v.as_str()))
        .filter_map(|b64| {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.decode(b64).ok()
        })
        .filter_map(|data| crate::protocol::voting::parse_wbb_data(&data))
        .filter(|parsed| parsed.entry_type == "eligible_vids")
        .find_map(|parsed| parsed.decode_payload::<Vec<Vid>>().ok());
    if let Some(published) = published {
        if published != vids {
            return Err(ErError::Internal(
                "a different eligible-vid list is already published for this election".into(),
            ));
        }
        return Ok(Json(PublishEligibleResponse { vids }));
    }

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
    state
        .verify_fresh_dip_assertion(&req.assertion, &req.signature)
        .await?;

    // Retrieval tokens are bound to the latest PIN-request rid for this vid;
    // a retrieval without a preceding PIN request is a protocol violation.
    let rid = state
        .last_rid
        .lock()
        .await
        .get(&meta.vid)
        .cloned()
        .ok_or(ErError::Unauthorized)?;
    // "A retrieval token for each RT" (Sec. 5.3.1.4 step 8(c)): the voter
    // needs t_RT shares, but which tellers are ready first is not known here.
    // A fresh set supersedes the vid's outstanding retrieval tokens: unused
    // ones (at least one per retrieval, since t_RT shares suffice) must not
    // pile up or stay valid.
    for outstanding in state.tokens.lock().await.values_mut() {
        if outstanding.vid == meta.vid && outstanding.token_type == TokenType::Retrieval {
            outstanding.used = true;
        }
    }
    let n_rt = state.election.n_rt;
    let mut retrieval_tokens = Vec::with_capacity(n_rt);
    for _ in 0..n_rt {
        retrieval_tokens.push(
            state
                .next_token(TokenType::Retrieval, meta.vid, Some(rid.clone()))
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
    /// One anonymous token per ballot box, bound to `comm_b`.
    casting_tokens: Vec<CastingToken>,
}

/// V12: issue anonymous casting tokens (Sec. 5.3.1.6).
///
/// The voter authenticates with the registration token and an EdDSA signature
/// over `comm_b` made with the registered app key; the ER applies the casting
/// policy per vid and SIGNS one token per ballot box, tied to `comm_b` and
/// valid for a limited time. The ballot boxes verify it without the ER.
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

    // Casting policy (Sec. 5.3.1.6 step 4) over DISTINCT ballot commitments:
    // not too frequently (`max_casts_per_voter`) and not too recently
    // (`min_cast_interval_s`). A re-request for an already-committed ballot
    // replays the cached tokens while they are valid and gets fresh ones once
    // they expired - neither burns budget. Everything happens under one lock,
    // so the policy is race-safe.
    let now_ms = state.clock.lock().await.now_ms();
    let mut commitments = state.cast_commitments.lock().await;
    let seen = commitments.entry(meta.vid).or_default();
    match seen.get(&req.comm_b) {
        Some(cached) if cached.iter().all(|t| t.expires_at_ms > now_ms) && !cached.is_empty() => {
            return Ok(Json(CastingTokensResponse {
                casting_tokens: cached.clone(),
            }));
        }
        Some(_) => {}
        None => {
            if seen.len() >= state.election.max_casts_per_voter {
                return Err(ErError::RateLimited);
            }
            let mut last_issue = state.last_cast_issue_ms.lock().await;
            let min_gap_ms = state.election.min_cast_interval_s.saturating_mul(1000);
            if let Some(last) = last_issue.get(&meta.vid) {
                if now_ms < last.saturating_add(min_gap_ms) {
                    return Err(ErError::CastTooSoon);
                }
            }
            last_issue.insert(meta.vid, now_ms);
        }
    }

    // One self-contained token per ballot box: the ER's signature over the
    // commitment. It names nobody, and the ER will never see it again - each
    // ballot box verifies it on its own (Sec. 5.2).
    let expires_at_ms =
        now_ms.saturating_add(state.election.casting_token_ttl_s.saturating_mul(1000));
    let signing_key = state.signing_key();
    let election = state.election_context.context_hash;
    let casting_tokens: Vec<CastingToken> = (1..=state.election.n_bb as u64)
        .map(|bb_id| CastingToken::issue(&signing_key, &election, bb_id, req.comm_b, expires_at_ms))
        .collect();
    seen.insert(req.comm_b, casting_tokens.clone());
    drop(commitments);
    Ok(Json(CastingTokensResponse { casting_tokens }))
}

#[derive(Debug, Deserialize)]
struct VerifyTokenRequest {
    token: TokenValue,
    /// Expected token type (`registration`/`pinrequest`/`retrieval`/`ns`;
    /// casting tokens are self-contained and never come back here);
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
    if req.consume {
        meta.used = true;
    }
    let (vid, rid) = (Some(meta.vid), meta.rid.clone());
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
    #[error("a ballot was cast too recently; try again shortly")]
    CastTooSoon,
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
            Self::RateLimited => (StatusCode::FORBIDDEN, self.to_string()),
            Self::CastTooSoon => (StatusCode::TOO_MANY_REQUESTS, self.to_string()),
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
    let teller_public_shares = load_teller_public_shares(&settings, &election_context).await?;
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
        teller_public_shares,
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

/// Load the tabulation tellers' public key shares (`tt-public-shares.json`,
/// next to the election context).
async fn load_teller_public_shares(
    settings: &Settings,
    election_context: &ElectionContext<RistrettoGroup>,
) -> anyhow::Result<Vec<crate::protocol::tally::TellerPublicShare>> {
    let context_path = std::path::PathBuf::from(&settings._ceremony.election_context);
    let base_dir = context_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let path = base_dir.join("tt-public-shares.json");
    let bytes = tokio::fs::read(&path)
        .await
        .map_err(|e| anyhow::anyhow!("failed to read {}: {}", path.display(), e))?;
    let shares: Vec<crate::protocol::tally::TellerPublicShare> = serde_json::from_slice(&bytes)
        .map_err(|e| anyhow::anyhow!("failed to parse teller public shares: {e}"))?;
    // This file is published verbatim at setup, onto a board nothing can
    // amend (Sec. 3.5.2, A3). A stale or empty one would boot the roll, reach
    // the board, and only be caught by the tally driver after the election -
    // so it is held to the master key here, before it can be published.
    crate::protocol::tally::teller_shares_bind_to_master(
        &shares,
        &election_context.pk.params.tally.h,
        settings.election.n_tt,
        settings.election.t_tt,
    )
    .map_err(|e| {
        anyhow::anyhow!(
            "{} does not fit this election's tabulation key: {e}",
            path.display()
        )
    })?;
    Ok(shares)
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
