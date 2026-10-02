//! Tabulation Teller (TT) server (Sec. 3.9 threshold tally).
//!
//! Endpoints:
//!   - `POST /sign`               - Ed25519-sign a WBB data string.
//!   - `GET  /status`             - readiness + entity id.
//!   - `POST /vss/zeta/round1`    - start a threshold zeta VSS session (Sec. 3.9).
//!   - `POST /vss/zeta/combine`   - combine zeta VSS broadcasts; the sub-share stays here.
//!   - `POST /blind`              - raise ciphertexts to this teller's zeta sub-share, with proof.
//!   - `POST /decrypt/ox`         - partial ox-fingerprint decryptions.
//!   - `POST /decrypt/acc-checks` - partial decryptions of the blinded ACC checks.
//!   - `POST /decrypt/fps`        - partial credential-fp decryptions.
//!   - `POST /decrypt/tally`      - partial tally decryptions.
//!
//! The service loads its DKG share (`tt-{i}-share.json`) per request (RT
//! precedent) and keeps the opaque zeta VSS state between round 1 and combine in
//! a session keyed by the driver-chosen label.  All tally
//! endpoints require the service bearer token, and all crypto runs in
//! `tokio::task::spawn_blocking`.
//!
//! Trust assumption (README deviation 14): the `/decrypt/*`
//! endpoints partially decrypt whatever ciphertexts the request carries - a
//! TT cannot distinguish pipeline ciphertexts from others, so a coordinator
//! holding >= t_TT service tokens is a decryption oracle for arbitrary
//! ciphertexts.  This matches the endpoint catalog and the library `partial_*`
//! API; the mitigations are the per-service bearer tokens and the public
//! audit trail (every decryption the tally *uses* must be published and is
//! master-key-bound by the auditor).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::Extension,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use dlog_group::group::GroupScalar;
use dlog_group::ristretto::RistrettoGroup;
use dlog_sigma_primitives::elgamal::ciphertext::Ciphertext;
use ed25519_dalek::{Signer, SigningKey};
use evoting::api::prelude::{
    BlindingShare, ThresholdFingerprints, ThresholdTabulationTeller, VerifiablePartialDecryption,
    ZetaCommitments, ZetaVssBroadcast, ZetaVssState,
};
use evoting::api::server::bb::ElectionContext;
use rand_chacha::ChaCha20Rng;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use crate::actors::common::{health_router, serve_rustls, with_state};
use crate::configuration::Settings;
use crate::protocol::clock::Clock;
use crate::protocol::rng::{operation_rng, ActorSeed};
use crate::protocol::tally::{
    encrypted_tally_from_entries, load_tt_share, reconstruct_tt_teller, zeta_broadcast_message,
    ReEncryptionProofEntry, SignedZetaVssBroadcast,
};
use crate::protocol::tls::rustls_config_for_service;

type G = RistrettoGroup;

/// Upper bound on concurrently open zeta VSS sessions (the serial tally driver
/// needs 2; anything near this cap indicates driver misbehaviour).
const MAX_ZETA_SESSIONS: usize = 8;

/// This teller's sub-share of one zeta VSS session, together with the
/// commitments that name that session.
type HeldZetaShare = (<G as GroupScalar>::Scalar, Vec<ZetaCommitments<G>>);

/// An open zeta VSS session: this party's VSS state and the broadcast it
/// dealt, kept so the copy relayed back can be compared with it.
type OpenZetaSession = (ZetaVssState<G>, ZetaVssBroadcast<G>);

/// TT service state.
#[derive(Clone)]
pub struct TtState {
    entity_id: String,
    signing_key_seed: SecretString,
    service_token: SecretString,
    clock: Clock,
    /// Election context for context-bound tally operations.
    election_context: ElectionContext<G>,
    /// Path to this party's `tt-{i}-share.json` DKG share.
    share_path: std::path::PathBuf,
    /// This teller's index `i` in `1..=n_tt`.
    tt_index: usize,
    /// Dedicated operation seed (`tt-{i}-seed.bin`) for proof nonces.
    actor_seed: ActorSeed,
    /// Read-only bulletin-board access: what this teller decrypts at the final
    /// step is recomputed from the board, never taken from its caller.
    wbb_client: crate::clients::wbb::WbbClient,
    /// Number of TT parties / reconstruction threshold (from configuration).
    n_tt: usize,
    t_tt: usize,
    /// Durable record of what this teller has already done: the proof-nonce
    /// counter, the zeta sessions whose sub-share is spent, and the blinding
    /// shares it produced. It survives a restart, so a restarted teller
    /// neither re-uses a nonce nor disowns its own work.
    ledger: Arc<Mutex<TtLedger>>,
    ledger_path: std::path::PathBuf,
    /// Verifying keys pinned at the ceremony for the other tellers, by index.
    /// A zeta VSS deal is only combined once every dealer has signed its own
    /// broadcast with the key it was given at the ceremony.
    peer_keys: HashMap<usize, ed25519_dalek::VerifyingKey>,
    /// Open zeta VSS sessions, keyed by the driver-chosen label: this party's
    /// VSS state together with the broadcast it dealt, kept so that the copy
    /// relayed back can be compared with it byte for byte.
    zeta_sessions: Arc<Mutex<HashMap<String, OpenZetaSession>>>,
    /// This teller's zeta sub-shares, one per completed session, keyed by
    /// the session label. They never leave this process: the teller applies
    /// them (`/blind`) and proves it (Sec. 3.9 steps 7, 20, 24).
    zeta_shares: Arc<Mutex<HashMap<String, HeldZetaShare>>>,
}

/// How many spent sessions and produced blindings a ledger keeps. A tally
/// run adds three of each, so this is some 1300 runs - far more than an
/// election needs, and it bounds a file that is rewritten on every request.
/// Far beyond any election this PoC runs; reaching it is a fault, not a
/// housekeeping event, and is refused rather than absorbed by forgetting.
const LEDGER_CAPACITY: usize = 1 << 20;

/// What a tabulation teller must not forget across a restart.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct TtLedger {
    /// Next proof-nonce counter. A nonce is `operation_rng(seed, purpose,
    /// counter)`, so a counter that restarted at zero would sign a DIFFERENT
    /// statement with the SAME nonce and any board reader could then solve
    /// for this teller's secret share.
    #[serde(default)]
    op_counter: u64,
    /// Zeta VSS sessions whose sub-share has been used. Never emptied: one
    /// exponent blinds one list (Sec. 3.9 draws a fresh zeta per step), so a
    /// replay of the same deal must not re-create the share.
    #[serde(default)]
    spent_sessions: Vec<String>,
    /// Digests of the blinding shares this teller produced, so `/sign`
    /// refuses an artifact carrying one it did not.
    #[serde(default)]
    blindings: Vec<String>,
}

impl TtLedger {
    /// Append `value`. NEVER evicts: a teller that forgot its own work would
    /// refuse to sign its own artifact, and one that forgot a spent session
    /// could be replayed - so a ledger that cannot grow stops the teller
    /// instead, loudly.
    fn remember(list: &mut Vec<String>, value: String) -> Result<(), TtError> {
        if list.contains(&value) {
            return Ok(());
        }
        if list.len() >= LEDGER_CAPACITY {
            return Err(TtError::Internal(
                "this teller's ledger is full - it must not forget what it has done".into(),
            ));
        }
        list.push(value);
        Ok(())
    }
}

/// A ledger on disk, under this teller's own MAC.
///
/// The key is derived from the teller's operation seed, which lives in the
/// same directory: the MAC catches a corrupted or edited ledger, not a
/// deletion, and it is not meant to. Anyone who can delete this file can read
/// `tt-{i}-seed.bin` and `tt-{i}-share.json` beside it, and so already holds
/// everything the ledger protects.
#[derive(Debug, Serialize, Deserialize)]
struct SealedLedger {
    ledger: TtLedger,
    mac: String,
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

    /// A fresh proof nonce. The counter is taken from the durable ledger and
    /// written back before the nonce is used.
    async fn next_op_rng(&self, purpose: &str) -> Result<ChaCha20Rng, TtError> {
        let counter = {
            let mut ledger = self.ledger.lock().await;
            let counter = ledger.op_counter;
            ledger.op_counter += 1;
            self.write_ledger(&ledger).await?;
            counter
        };
        let mut rng = operation_rng(&self.actor_seed, purpose, counter);
        // On a real run, fresh entropy as well (see `NonceLedger::salt`): a
        // ledger restored from an older backup must not replay a nonce.
        if matches!(self.clock.mode(), crate::protocol::clock::ClockMode::Wall) {
            use rand::{RngCore as _, SeedableRng as _};
            let mut salt = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut salt);
            let mut seed = [0u8; 32];
            rng.fill_bytes(&mut seed);
            for (byte, s) in seed.iter_mut().zip(&salt) {
                *byte ^= s;
            }
            rng = ChaCha20Rng::from_seed(seed);
        }
        Ok(rng)
    }

    async fn write_ledger(&self, ledger: &TtLedger) -> Result<(), TtError> {
        let sealed = SealedLedger {
            mac: ledger_mac(&self.actor_seed, ledger)
                .map_err(|e| TtError::Internal(e.to_string()))?,
            ledger: ledger.clone(),
        };
        let bytes = serde_json::to_vec(&sealed).map_err(|e| TtError::Internal(e.to_string()))?;
        let tmp = self.ledger_path.with_extension("json.tmp");
        // Written, FLUSHED, then renamed: a power loss can make the rename
        // durable before the data otherwise, and a truncated ledger nobody can
        // read is what it was written to prevent.
        {
            let mut file = tokio::fs::File::create(&tmp)
                .await
                .map_err(|e| TtError::Internal(format!("ledger write failed: {e}")))?;
            tokio::io::AsyncWriteExt::write_all(&mut file, &bytes)
                .await
                .map_err(|e| TtError::Internal(format!("ledger write failed: {e}")))?;
            file.sync_all()
                .await
                .map_err(|e| TtError::Internal(format!("ledger write failed: {e}")))?;
        }
        tokio::fs::rename(&tmp, &self.ledger_path)
            .await
            .map_err(|e| TtError::Internal(format!("ledger write failed: {e}")))?;
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignRequest {
    pub data: String,
    /// Optional timestamp in milliseconds. When omitted the server uses
    /// its own clock. The coordinator should supply this so that all
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
    // Sec. 3.4.2 has each teller write its own entries: a signature of this
    // teller must mean that what it signs is its own work. An artifact that
    // carries a blinding share in THIS teller's name must carry the share
    // this teller produced, unchanged - otherwise a coordinator could have
    // the tellers co-sign a blinding they never performed (and, with a
    // fabricated zeta, one that makes every credential check pass).
    state.refuse_foreign_blinding(&req.data).await?;
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

// -- zeta VSS (Sec. 3.9 steps 6-7) ---------------------------------

#[derive(Debug, Deserialize)]
pub struct ZetaRound1Request {
    /// Driver-chosen session label (e.g. `ox` / `acc`); combine consumes it.
    pub session: String,
}

/// Start a zeta VSS session: Feldman-share a fresh local zeta_i over `g1`.
///
/// The answer is the broadcast of Sec. 2.8 Protocol 2 step 4 - the
/// commitments in the clear, every evaluation share sealed to its recipient
/// (step 3) - under this teller's ceremony-pinned signature, so that a relay
/// can neither read a share nor pass a deal of its own off as the tellers'.
async fn zeta_round1_handler(
    Extension(state): Extension<Arc<TtState>>,
    headers: HeaderMap,
    Json(req): Json<ZetaRound1Request>,
) -> Result<Json<SignedZetaVssBroadcast<G>>, TtError> {
    state.require_bearer(&headers)?;
    let teller = state.build_teller()?;
    let n = state.n_tt;
    let t = state.t_tt;
    let base = state.election_context.pk.params.elgamal.g1;
    let mut rng = state.next_op_rng("zeta-vss").await?;
    let params = state.election_context.pk.params.clone();
    let session_bytes = req.session.clone().into_bytes();
    let (vss_state, broadcast) = tokio::task::spawn_blocking(move || {
        teller.gen_zeta_vss_round1(n, t, base, &params, &session_bytes, &mut rng)
    })
    .await
    .map_err(|e| TtError::Internal(e.to_string()))?
    .map_err(|e| TtError::Internal(format!("zeta VSS round 1 failed: {e:?}")))?;
    {
        // Bound the session map: abandoned round-1 sessions must not
        // accumulate without limit (a fresh round 1 on an existing label
        // replaces it and stays within the cap).
        let mut sessions = state.zeta_sessions.lock().await;
        if sessions.len() >= MAX_ZETA_SESSIONS && !sessions.contains_key(&req.session) {
            return Err(TtError::BadRequest(format!(
                "too many open zeta VSS sessions (max {MAX_ZETA_SESSIONS})"
            )));
        }
        sessions.insert(req.session.clone(), (vss_state, broadcast.clone()));
    }
    // Protocol 2 step 4 BROADCASTS the commitments: every recipient must be
    // able to tell that this deal is this dealer's. The relay holds no key
    // that produces this signature.
    let message = zeta_broadcast_message(
        &broadcast,
        &state.election_context.manifest.election_id,
        &req.session,
    )
    .map_err(|e| TtError::Internal(e.to_string()))?;
    let signature = BASE64.encode(state.signing_key().sign(&message).to_bytes());
    Ok(Json(SignedZetaVssBroadcast {
        broadcast,
        signature,
    }))
}

#[derive(Debug, Deserialize)]
pub struct ZetaCombineRequest {
    pub session: String,
    pub broadcasts: Vec<SignedZetaVssBroadcast<G>>,
}

#[derive(Debug, Serialize)]
pub struct ZetaCombineResponse {
    pub id: usize,
}

/// Combine zeta VSS broadcasts into this party's sub-share; consumes the
/// session. The sub-share is KEPT here (nobody reconstructs zeta): the driver
/// learns only that the session is ready for `/blind`.
async fn zeta_combine_handler(
    Extension(state): Extension<Arc<TtState>>,
    headers: HeaderMap,
    Json(req): Json<ZetaCombineRequest>,
) -> Result<Json<ZetaCombineResponse>, TtError> {
    state.require_bearer(&headers)?;
    // Shape validation before the library call, which indexes
    // `sealed_shares[id-1]` by this party's own id: a broadcast of the wrong
    // shape is refused here, with its dealer named.
    if req.broadcasts.is_empty() {
        return Err(TtError::BadRequest("zeta VSS broadcasts missing".into()));
    }
    for signed in &req.broadcasts {
        let broadcast = &signed.broadcast;
        if broadcast.from_id == 0 || broadcast.from_id > state.n_tt {
            return Err(TtError::BadRequest(format!(
                "zeta VSS broadcast from_id {} out of range 1..={}",
                broadcast.from_id, state.n_tt
            )));
        }
        if broadcast.sealed_shares.len() != state.n_tt || broadcast.commitments.len() != state.t_tt
        {
            return Err(TtError::BadRequest(format!(
                "zeta VSS broadcast from party {} has wrong shape",
                broadcast.from_id
            )));
        }
    }
    // Protocol 2 step 6 combines the sharings of ALL n dealers: exactly one
    // per party, none missing and none twice, or the joint secret is not the
    // one the tellers dealt.
    let mut seen: Vec<usize> = req.broadcasts.iter().map(|s| s.broadcast.from_id).collect();
    seen.sort_unstable();
    if seen != (1..=state.n_tt).collect::<Vec<_>>() {
        return Err(TtError::BadRequest(
            "the zeta VSS deal must carry exactly one broadcast from each teller".into(),
        ));
    }
    // The broadcast this party dealt for the session, read WITHOUT consuming
    // it: a deal refused below must leave the session open, or one bad
    // request would burn a teller's round.
    let own = state
        .zeta_sessions
        .lock()
        .await
        .get(&req.session)
        .map(|(_, broadcast)| broadcast.clone())
        .ok_or_else(|| TtError::BadRequest("unknown zeta VSS session".into()))?;
    // Every dealer's own signature, checked against the key pinned for it at
    // the ceremony. Without this the relay could throw the tellers' deal away
    // and substitute a sharing of its own - sealed to the tellers' PUBLISHED
    // key shares, so every teller would open, verify and blind with it, and
    // the relay would know zeta (Sec. 3.9 steps 6-7).
    for signed in &req.broadcasts {
        let id = signed.broadcast.from_id;
        let key = state
            .peer_keys
            .get(&id)
            .ok_or_else(|| TtError::BadRequest(format!("no pinned key for TT-{id}")))?;
        let raw = BASE64.decode(&signed.signature).map_err(|_| {
            TtError::BadRequest(format!("TT-{id} zeta VSS signature is not base64"))
        })?;
        let bytes: [u8; 64] = raw
            .try_into()
            .map_err(|_| TtError::BadRequest(format!("TT-{id} zeta VSS signature is malformed")))?;
        let message = zeta_broadcast_message(
            &signed.broadcast,
            &state.election_context.manifest.election_id,
            &req.session,
        )
        .map_err(|e| TtError::Internal(e.to_string()))?;
        key.verify_strict(&message, &ed25519_dalek::Signature::from_bytes(&bytes))
            .map_err(|_| {
                TtError::BadRequest(format!(
                    "TT-{id} did not sign this zeta VSS broadcast for session {}, as refused by                      TT-{}",
                    req.session, state.tt_index
                ))
            })?;
        // And this party's own deal must come back exactly as it was dealt:
        // a signature check alone would pass a broadcast of ours replayed
        // from an earlier session of the same election.
        if id == state.tt_index {
            let relayed = serde_json::to_vec(&signed.broadcast)
                .map_err(|e| TtError::Internal(e.to_string()))?;
            let dealt = serde_json::to_vec(&own).map_err(|e| TtError::Internal(e.to_string()))?;
            if relayed != dealt {
                return Err(TtError::BadRequest(
                    "the zeta VSS deal does not carry this teller's own broadcast".into(),
                ));
            }
        }
    }
    let broadcasts: Vec<ZetaVssBroadcast<G>> =
        req.broadcasts.into_iter().map(|s| s.broadcast).collect();
    // Only an accepted deal consumes the session.
    let (vss_state, _) = state
        .zeta_sessions
        .lock()
        .await
        .remove(&req.session)
        .ok_or_else(|| TtError::BadRequest("unknown zeta VSS session".into()))?;
    let teller = state.build_teller()?;
    let commitments: Vec<ZetaCommitments<G>> =
        broadcasts.iter().map(ZetaCommitments::from).collect();
    let election_params = state.election_context.pk.params.clone();
    let (id, sub_share) = tokio::task::spawn_blocking(move || {
        teller.combine_zeta_vss(&vss_state, &broadcasts, &election_params)
    })
    .await
    .map_err(|e| TtError::Internal(e.to_string()))?
    .map_err(|e| TtError::BadRequest(format!("zeta VSS combine failed: {e}")))?;
    {
        // The share is kept under the SESSION's own fingerprint - the
        // commitments it came from - not under a label the caller chose: a
        // caller that replays the same broadcasts under a new label finds the
        // share already spent, and cannot have two lists blinded with one
        // exponent (Sec. 3.9 draws a fresh zeta per step).
        let key = session_key::<G>(&commitments);
        if state.ledger.lock().await.spent_sessions.contains(&key) {
            return Err(TtError::BadRequest(
                "this zeta VSS session's sub-share has already been spent".into(),
            ));
        }
        let mut shares = state.zeta_shares.lock().await;
        if shares.len() >= MAX_ZETA_SESSIONS && !shares.contains_key(&key) {
            return Err(TtError::BadRequest(format!(
                "too many zeta shares held (max {MAX_ZETA_SESSIONS})"
            )));
        }
        shares.insert(key, (sub_share, commitments));
    }
    Ok(Json(ZetaCombineResponse { id }))
}

#[derive(Debug, Deserialize)]
#[serde(bound = "")]
pub struct BlindRequest {
    /// The zeta VSS session whose sub-share to apply, named by ITS OWN
    /// commitments (the caller cannot rename a session to spend a share
    /// twice); consumed.
    pub commitments: Vec<ZetaCommitments<G>>,
    pub ct_lists: Vec<Vec<Ciphertext<G>>>,
    /// Which step of the pipeline this blinding belongs to.
    pub transcript: BlindTranscript,
}

/// Which pipeline step the blinding belongs to: fixes the transcript the
/// share's proof is bound to.
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlindTranscript {
    Ox,
    Acc,
    CredentialFingerprints,
}

/// Raise every ciphertext to this teller's zeta sub-share and prove it (Sec.
/// 3.9 steps 7, 20, 24): the share never leaves; the blinded lists and the
/// proof do. Each sub-share is applied ONCE - a second blinding under the
/// same share would relate two lists through a common exponent.
async fn blind_handler(
    Extension(state): Extension<Arc<TtState>>,
    headers: HeaderMap,
    Json(req): Json<BlindRequest>,
) -> Result<Json<BlindingShare<G>>, TtError> {
    state.require_bearer(&headers)?;
    let key = session_key::<G>(&req.commitments);
    let (z_i, commitments) = state
        .zeta_shares
        .lock()
        .await
        .remove(&key)
        .ok_or_else(|| TtError::BadRequest("no zeta share for this session".into()))?;
    // Spent for good. Removing the share is not enough on its own: the same
    // broadcasts replayed through `/vss/zeta/combine` would re-create it, and
    // one exponent would blind two lists (Sec. 3.9 draws a fresh zeta at
    // steps 6, 20 and 24).
    {
        let mut ledger = state.ledger.lock().await;
        TtLedger::remember(&mut ledger.spent_sessions, key.clone())?;
        state.write_ledger(&ledger).await?;
    }
    if commitments != req.commitments {
        return Err(TtError::BadRequest(
            "the commitments do not name this teller's session".into(),
        ));
    }
    let pipeline = evoting::api::server::bb::PublicPipeline::new(
        evoting::api::server::bb::PublicElection::new(state.election_context.clone()),
    );
    let transcript = match req.transcript {
        BlindTranscript::Ox => pipeline.ox_transcript(),
        BlindTranscript::Acc => pipeline.acc_transcript(),
        BlindTranscript::CredentialFingerprints => pipeline.credential_fingerprint_transcript(),
    };
    let from_id = state.tt_index;
    let base = state.election_context.pk.params.elgamal.g1;
    let mut rng = state.next_op_rng("blind").await?;
    let share = tokio::task::spawn_blocking(move || {
        BlindingShare::new(
            from_id,
            req.ct_lists,
            z_i,
            base,
            &commitments,
            &mut rng,
            &transcript,
        )
    })
    .await
    .map_err(|e| TtError::Internal(e.to_string()))?;
    state.remember_blinding(&share).await?;
    Ok(Json(share))
}

// -- Partial decryptions (Sec. 3.9) -----------------------------

/// What a teller is asked to threshold-decrypt: the BLINDING ARTIFACT, and
/// the originals it was built over.
///
/// Sec. 3.9 step 22 decrypts `E^z`, never `E`. A teller that decrypted a list
/// its caller simply handed it would be an oracle, and the credential checks
/// are a public function of two board entries: whoever could call it would
/// skip the blinding altogether and read `g3^(PIN_used - PIN_real)` off every
/// discarded check - which is exactly the coercion resistance of Sec. 3.7
/// that the threshold blinding exists to protect. So a teller decrypts only
/// what ITS OWN fresh, unknown blinding exponent produced.
#[derive(Debug, Deserialize)]
#[serde(bound = "")]
pub struct BlindedDecryptionRequest {
    pub fps: ThresholdFingerprints<G>,
    /// The lists the blinding was performed over; the artifact is verified
    /// against them, so they cannot be restated.
    pub originals: Vec<Vec<Ciphertext<G>>>,
    pub transcript: BlindTranscript,
}

impl TtState {
    /// Hold a decryption request to a blinding this teller really performed.
    ///
    /// Two things are required, and neither can be forged by a caller: the
    /// artifact must verify against `originals` under the session's own VSS
    /// commitments, and it must carry a blinding share in THIS teller's name
    /// that this teller's ledger records having produced. A caller can still
    /// ask for a list of its choosing to be blinded and then decrypted - but
    /// what comes back is that list raised to an exponent nobody knows, which
    /// is the verdict Sec. 3.9 step 22 publishes anyway, not a plaintext.
    async fn require_own_blinding(&self, req: &BlindedDecryptionRequest) -> Result<(), TtError> {
        let pipeline = evoting::api::server::bb::PublicPipeline::new(
            evoting::api::server::bb::PublicElection::new(self.election_context.clone()),
        );
        let transcript = match req.transcript {
            BlindTranscript::Ox => pipeline.ox_transcript(),
            BlindTranscript::Acc => pipeline.acc_transcript(),
            BlindTranscript::CredentialFingerprints => pipeline.credential_fingerprint_transcript(),
        };
        let base = self.election_context.pk.params.elgamal.g1;
        req.fps
            .verify(&req.originals, &base, self.n_tt, self.t_tt, &transcript)
            .map_err(|e| TtError::BadRequest(format!("blinding artifact rejected: {e:?}")))?;

        let mine = self.ledger.lock().await;
        let ours = req
            .fps
            .shares
            .iter()
            .find(|share| share.from_id == self.tt_index)
            .ok_or_else(|| {
                TtError::BadRequest(
                    "this teller did not take part in the blinding of these values".into(),
                )
            })?;
        let bytes = serde_json::to_vec(ours).map_err(|e| TtError::Internal(e.to_string()))?;
        if !mine
            .blindings
            .iter()
            .any(|h| *h == hex::encode(Sha256::digest(&bytes)))
        {
            return Err(TtError::BadRequest(
                "the blinding share in this teller's name is not one this teller produced".into(),
            ));
        }
        Ok(())
    }
}

/// Per-party ox-fingerprint decryptions (Sec. 3.9 steps 8-9).
async fn decrypt_ox_handler(
    Extension(state): Extension<Arc<TtState>>,
    headers: HeaderMap,
    Json(req): Json<BlindedDecryptionRequest>,
) -> Result<Json<Vec<VerifiablePartialDecryption<G>>>, TtError> {
    state.require_bearer(&headers)?;
    state.require_own_blinding(&req).await?;
    let teller = state.build_teller()?;
    let ctx = state.election_context.clone();
    let mut rng = state.next_op_rng("decrypt-ox").await?;
    let partials = tokio::task::spawn_blocking(move || {
        teller.partial_decrypt_ox_fps(&ctx, &req.fps, &mut rng)
    })
    .await
    .map_err(|e| TtError::Internal(e.to_string()))?
    .map_err(|e| TtError::BadRequest(format!("ox decryption rejected: {e}")))?;
    Ok(Json(partials))
}

/// Per-party ACC-check decryptions over the BLINDED checks (Sec. 3.9 step 22).
/// The list decrypted is the artifact's own `fp_lists[0]`, never one the
/// caller states separately.
async fn decrypt_acc_checks_handler(
    Extension(state): Extension<Arc<TtState>>,
    headers: HeaderMap,
    Json(req): Json<BlindedDecryptionRequest>,
) -> Result<Json<Vec<VerifiablePartialDecryption<G>>>, TtError> {
    state.require_bearer(&headers)?;
    state.require_own_blinding(&req).await?;
    let blinded = req
        .fps
        .fp_lists
        .first()
        .cloned()
        .ok_or_else(|| TtError::BadRequest("the blinding carries no checks".into()))?;
    let teller = state.build_teller()?;
    let ctx = state.election_context.clone();
    let mut rng = state.next_op_rng("decrypt-acc-checks").await?;
    let partials = tokio::task::spawn_blocking(move || {
        teller.partial_gen_acc_checks(&ctx, &blinded, &mut rng)
    })
    .await
    .map_err(|e| TtError::Internal(e.to_string()))?;
    Ok(Json(partials))
}

#[derive(Debug, Serialize)]
#[serde(bound = "")]
pub struct DecryptFpsResponse {
    pub pub_fps: Vec<VerifiablePartialDecryption<G>>,
    pub vote_fps: Vec<VerifiablePartialDecryption<G>>,
}

/// Per-party credential-fingerprint decryptions (Sec. 3.9 steps 24-26).
async fn decrypt_fps_handler(
    Extension(state): Extension<Arc<TtState>>,
    headers: HeaderMap,
    Json(req): Json<BlindedDecryptionRequest>,
) -> Result<Json<DecryptFpsResponse>, TtError> {
    state.require_bearer(&headers)?;
    state.require_own_blinding(&req).await?;
    let teller = state.build_teller()?;
    let ctx = state.election_context.clone();
    let mut rng = state.next_op_rng("decrypt-fps").await?;
    let (pub_fps, vote_fps) =
        tokio::task::spawn_blocking(move || teller.partial_decrypt_fps(&ctx, &req.fps, &mut rng))
            .await
            .map_err(|e| TtError::Internal(e.to_string()))?
            .map_err(|e| TtError::BadRequest(format!("fp decryption rejected: {e}")))?;
    Ok(Json(DecryptFpsResponse { pub_fps, vote_fps }))
}

/// `/decrypt/tally` takes NOTHING from its caller.
///
/// Sec. 3.9 steps 28-29 decrypt the sum of the legitimate votes, and every
/// input to that sum is already on the board when this is called. So the
/// teller recomputes it and decrypts that, rather than whatever ciphertext it
/// was handed: the credential checks are a public function of two board
/// entries, and a teller that decrypted a caller-chosen list under the master
/// tally key would hand out `g3^(PIN_used - PIN_real)` for every discarded
/// check - with nothing published for a verifier to catch.
#[derive(Debug, Default, Deserialize)]
pub struct DecryptTallyRequest {}

#[derive(Debug, Serialize)]
#[serde(bound = "")]
pub struct DecryptTallyResponse {
    pub l1: Vec<VerifiablePartialDecryption<G>>,
    pub l2: Vec<Vec<VerifiablePartialDecryption<G>>>,
}

/// Per-party tally decryptions over the homomorphic sum (Sec. 3.9 step 29).
async fn decrypt_tally_handler(
    Extension(state): Extension<Arc<TtState>>,
    headers: HeaderMap,
    Json(req): Json<DecryptTallyRequest>,
) -> Result<Json<DecryptTallyResponse>, TtError> {
    state.require_bearer(&headers)?;
    let _ = req;
    let entries =
        state.wbb_client.entries().await.map_err(|e| {
            TtError::BadRequest(format!("the bulletin board could not be read: {e}"))
        })?;
    let ctx = state.election_context.clone();
    let board: Vec<serde_json::Value> = entries.entries.into_iter().map(|e| e.entry).collect();
    let enc_tally = {
        let ctx = ctx.clone();
        tokio::task::spawn_blocking(move || encrypted_tally_from_entries(&board, &ctx))
            .await
            .map_err(|e| TtError::Internal(e.to_string()))?
            .map_err(|e| TtError::BadRequest(format!("the published tally does not add up: {e}")))?
    };
    let teller = state.build_teller()?;
    let mut rng = state.next_op_rng("decrypt-tally").await?;
    let (l1, l2) = tokio::task::spawn_blocking(move || {
        teller.partial_decrypt_tally(&ctx, &enc_tally, &mut rng)
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
            // Internal failures are logged but not leaked.
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
            .route("/blind", post(blind_handler))
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
    let clock = Clock::from_settings(&settings.clock);

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
    let ledger_path = ceremony_dir.join(format!("tt-{tt_index}-ledger.json"));
    let actor_seed = load_actor_seed(&settings).await?;
    let ledger = load_ledger(&ledger_path, &actor_seed).await?;

    let state = Arc::new(TtState {
        entity_id,
        tt_index,
        signing_key_seed: SecretString::new(hex::encode(signing_key.to_bytes())),
        service_token,
        clock,
        election_context,
        share_path,
        actor_seed,
        wbb_client: crate::clients::wbb::WbbClient::new(
            crate::protocol::tls::reqwest_client_trusting_ca(
                &tokio::fs::read_to_string(&settings.tls.ca_pem)
                    .await
                    .map_err(|e| anyhow::anyhow!("failed to read CA cert: {e}"))?,
            )?,
            reqwest::Url::parse(&settings.wbb.base_url)
                .map_err(|e| anyhow::anyhow!("invalid WBB URL: {e}"))?,
        ),
        n_tt: settings.election.n_tt,
        t_tt: settings.election.t_tt,
        ledger: Arc::new(Mutex::new(ledger)),
        ledger_path,
        peer_keys: load_peer_keys(&ceremony_dir, settings.election.n_tt).await?,
        zeta_sessions: Arc::new(Mutex::new(HashMap::new())),
        zeta_shares: Arc::new(Mutex::new(HashMap::new())),
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

/// The verifying keys pinned at the ceremony for `TT-1..=TT-n`
/// (`tt-{i}-verifying-key.bin`), by index.
async fn load_peer_keys(
    ceremony_dir: &std::path::Path,
    n_tt: usize,
) -> anyhow::Result<HashMap<usize, ed25519_dalek::VerifyingKey>> {
    let mut keys = HashMap::with_capacity(n_tt);
    for i in 1..=n_tt {
        let path = ceremony_dir.join(format!("tt-{i}-verifying-key.bin"));
        let bytes = tokio::fs::read(&path)
            .await
            .map_err(|e| anyhow::anyhow!("failed to read {}: {e}", path.display()))?;
        let raw: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("{} must be 32 bytes", path.display()))?;
        keys.insert(i, ed25519_dalek::VerifyingKey::from_bytes(&raw)?);
    }
    Ok(keys)
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

/// Load this service's dedicated operation seed (`{name}-seed.bin`).
/// This teller's MAC over a ledger, keyed by its own operation seed.
fn ledger_mac(seed: &ActorSeed, ledger: &TtLedger) -> anyhow::Result<String> {
    let body = serde_json::to_vec(ledger)?;
    let mut hasher = Sha256::new();
    hasher.update(b"referendum-poc/tt-ledger/v1");
    hasher.update(seed.mac_key());
    hasher.update((body.len() as u64).to_le_bytes());
    hasher.update(&body);
    Ok(hex::encode(hasher.finalize()))
}

/// The empty, sealed ledger the CEREMONY writes beside a tabulation teller's
/// seed, so that a teller finding none later knows it was LOST - the
/// spent-session and blinding records in it are what keep a replayed deal
/// from re-creating a share and this teller from signing an artifact that is
/// not its own. Never over an existing one.
pub fn create_ledger_blocking(path: &std::path::Path, seed: &ActorSeed) -> anyhow::Result<()> {
    let ledger = TtLedger::default();
    let sealed = SealedLedger {
        mac: ledger_mac(seed, &ledger)?,
        ledger,
    };
    let bytes = serde_json::to_vec(&sealed)?;
    use std::io::Write as _;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?
        .write_all(&bytes)?;
    Ok(())
}

/// Read this teller's durable ledger. A ledger that is missing, unreadable or
/// does not carry this teller's MAC stops the teller: it would otherwise go on
/// with a record someone else wrote, or from nothing over a seed it has used.
async fn load_ledger(path: &std::path::Path, seed: &ActorSeed) -> anyhow::Result<TtLedger> {
    let bytes = match tokio::fs::read(path).await {
        Ok(bytes) => bytes,
        Err(e) => {
            return Err(anyhow::anyhow!(
                "failed to read {} ({e}): a missing ledger means this teller's record is LOST, \
                 and it must not start again from nothing over a seed it has used",
                path.display()
            ))
        }
    };
    let sealed: SealedLedger = serde_json::from_slice(&bytes)
        .map_err(|e| anyhow::anyhow!("{} is unreadable: {e}", path.display()))?;
    let expected = ledger_mac(seed, &sealed.ledger)?;
    if !constant_time_eq::constant_time_eq(expected.as_bytes(), sealed.mac.as_bytes()) {
        return Err(anyhow::anyhow!(
            "{} does not carry this teller's own MAC",
            path.display()
        ));
    }
    Ok(sealed.ledger)
}

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

impl TtState {
    /// Every blinding share this teller has produced, by its serialised form.
    /// Kept so the teller can recognise its own work in an artifact it is
    /// asked to sign.
    async fn remember_blinding(&self, share: &BlindingShare<G>) -> Result<(), TtError> {
        let bytes = serde_json::to_vec(share).map_err(|e| TtError::Internal(e.to_string()))?;
        let mut ledger = self.ledger.lock().await;
        // Never dropped, and never cleared: a teller that forgot its own work
        // would refuse to sign its own artifact, and one call from anyone
        // holding a service token could bring that about.
        TtLedger::remember(&mut ledger.blindings, hex::encode(Sha256::digest(&bytes)))?;
        self.write_ledger(&ledger).await
    }

    /// Refuse to sign a data string whose payload carries a blinding share in
    /// this teller's name that this teller did not produce.
    async fn refuse_foreign_blinding(&self, data: &str) -> Result<(), TtError> {
        let Some(parsed) = crate::protocol::voting::parse_wbb_data(data.as_bytes()) else {
            return Ok(());
        };
        let value: serde_json::Value = match parsed.decode_payload() {
            Ok(value) => value,
            Err(_) => return Ok(()),
        };
        let mine = self.ledger.lock().await;
        let mine = &mine.blindings;
        let mut ours = Vec::new();
        // The typed reading first - the one the auditor and the tally use -
        // so that a payload dressed up to look like something else is walked
        // as what it will actually be read as; then a sweep of the whole
        // decoded value, which recurses THROUGH an object that parses as a
        // share, so a genuine share merged into an artifact cannot hide the
        // forged ones beneath it.
        if let Ok(entry) = serde_json::from_value::<ReEncryptionProofEntry>(value.clone()) {
            typed_blinding_shares(&entry, self.tt_index, &mut ours);
        }
        collect_blinding_shares(&value, self.tt_index, &mut ours);
        for share in ours {
            let Ok(bytes) = serde_json::to_vec(&share) else {
                return Err(TtError::BadRequest(
                    "a blinding share in this teller's name cannot be read".into(),
                ));
            };
            if !mine
                .iter()
                .any(|h| *h == hex::encode(Sha256::digest(&bytes)))
            {
                return Err(TtError::BadRequest(
                    "this artifact carries a blinding share in this teller's name that this \
                     teller did not produce"
                        .into(),
                ));
            }
        }
        Ok(())
    }
}

/// The blinding shares of teller `id` in the fields the tally and the auditor
/// actually read - whatever else the payload carries beside them.
fn typed_blinding_shares(
    entry: &ReEncryptionProofEntry,
    id: usize,
    out: &mut Vec<BlindingShare<G>>,
) {
    let fps = match entry {
        ReEncryptionProofEntry::OxFingerprints { fps, .. }
        | ReEncryptionProofEntry::CredentialFingerprints { fps, .. } => fps,
        ReEncryptionProofEntry::AccChecks { blinding, .. } => blinding,
        ReEncryptionProofEntry::Controls { .. } => return,
    };
    out.extend(fps.shares.iter().filter(|s| s.from_id == id).cloned());
}

/// Every `BlindingShare` of teller `id` anywhere inside a decoded payload.
fn collect_blinding_shares(value: &serde_json::Value, id: usize, out: &mut Vec<BlindingShare<G>>) {
    match value {
        serde_json::Value::Object(map) => {
            if map.contains_key("from_id")
                && map.contains_key("pub_z")
                && map.contains_key("fp_lists")
            {
                if let Ok(share) = serde_json::from_value::<BlindingShare<G>>(value.clone()) {
                    if share.from_id == id {
                        out.push(share);
                    }
                }
            }
            for v in map.values() {
                collect_blinding_shares(v, id, out);
            }
        }
        serde_json::Value::Array(items) => {
            for v in items {
                collect_blinding_shares(v, id, out);
            }
        }
        _ => {}
    }
}

/// A zeta VSS session's own name: a digest of the dealers' commitments, which
/// no caller can choose. Keying the held sub-shares on it means a caller that
/// replays one session's broadcasts under another label finds the share
/// already spent.
fn session_key<G: dlog_group::group::Group>(commitments: &[ZetaCommitments<G>]) -> String {
    let mut hasher = Sha256::new();
    for dealer in commitments {
        hasher.update(dealer.from_id.to_le_bytes());
        for c in &dealer.commitments {
            let mut bytes = vec![0u8; G::POINT_SIZE];
            G::point_to_bytes(&mut bytes, c);
            hasher.update(&bytes);
        }
    }
    hex::encode(hasher.finalize())
}
