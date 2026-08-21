//! Voter-facing server (M5, roadmap §6.6 / §8.3).
//!
//! Serves the enrollment SPA from `static_dir` and exposes a JSON API gated by
//! the voter's generated passphrase (V2).  Per-voter state is persisted as one
//! ChaCha20-Poly1305-encrypted file per vid; the passphrase is the only way to
//! unlock it.
//!
//! Enrollment flow (V1–V5):
//! 1. `POST /api/login`    — DIP assertion → ER `/login` → vid + registration token
//! 2. `POST /api/enroll`   — passphrase + app key, device registration, PIN
//!    request tokens → RT `/credentials/request` (τ, NS notify), NS registration
//! 3. `POST /api/status`   — NS poll: PIN ready when ≥ t_RT notifications
//! 4. `POST /api/pin/retrieve` — re-login → retrieval tokens → RT share
//!    delivery → `voter_build_acc` → threshold DVNIZKP → `Voter` + PIN
//! 5. `POST /api/pin`, `POST /api/pin/verify` — display / local check (§3.7.1)

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::{
    extract::Extension,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use dlog_group::ristretto::RistrettoGroup;
use evoting::api::client::{Voter, VoterBuilder};
use evoting::api::prelude::{voter_build_acc, ThresholdRegistrationTeller};
use evoting::api::server::bb::ElectionContext;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use tokio::sync::Mutex;
use tower_http::services::ServeDir;

use crate::actors::common::serve_rustls;
use crate::clients::bb::BbClient;
use crate::clients::dip::DipClient;
use crate::clients::er::ErClient;
use crate::clients::ns::NsClient;
use crate::clients::rt::RtClient;
use crate::clients::wbb::WbbClient;
use crate::configuration::Settings;
use crate::domain::{BallotDigest, PinCode, ReferendumOption, TokenValue, Vid};
use crate::protocol::acc::CredentialPackage;
use crate::protocol::rng::{ActorRng, ActorSeed};
use crate::protocol::tls::{reqwest_client_trusting_ca, rustls_config_for_service};
use crate::protocol::voting::{self, ballot_digest, comm_b, referendum_choice, BallotDigestEntry};
use evoting::api::client::Ballot;
use evoting::api::prelude::{DiscloseCAI, Receipt};

type G = RistrettoGroup;

/// Voter-server runtime state.
pub struct VoterState {
    state_dir: PathBuf,
    static_dir: PathBuf,
    election_context: ElectionContext<G>,
    rt_pk: evoting::api::prelude::RTPublicKey<G>,
    t_rt: usize,
    dip_client: DipClient,
    er_client: ErClient,
    ns_client: NsClient,
    rt_clients: Vec<RtClient>,
    /// One client per trusted ballot box (V10 default: all configured BBs).
    bb_clients: Vec<BbClient>,
    /// Read-only WBB access for publication checks (V14).
    wbb_client: WbbClient,
    /// Deterministic per-voter operation RNG (§9.2); short critical sections
    /// only, so a sync mutex is fine.
    rng: std::sync::Mutex<ActorRng>,
    /// Login state awaiting `/api/enroll`, keyed by fiscal id.
    pending_logins: Mutex<HashMap<String, PendingLogin>>,
}

impl std::fmt::Debug for VoterState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VoterState")
            .field("state_dir", &self.state_dir)
            .field("static_dir", &self.static_dir)
            .field("t_rt", &self.t_rt)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
struct PendingLogin {
    vid: Vid,
    registration_token: TokenValue,
    credential_package: CredentialPackage,
}

/// Persisted per-voter state.  Never derives `Debug`: it contains the PIN,
/// the voting credential, and the voter key pair.
#[derive(Clone, Serialize, Deserialize)]
struct VoterSession {
    fiscal_id: String,
    vid: Vid,
    registration_token: TokenValue,
    credential_package: CredentialPackage,
    /// App-key (AtSK) seed, hex-encoded (used for CAT signing from M6 on).
    at_sk_seed: String,
    rid: Option<String>,
    ns_token: Option<TokenValue>,
    pin: Option<PinCode>,
    voter: Option<Voter<G>>,
    /// Ballot built by `/api/vote`, awaiting cast/confirmation (§3.8).
    held: Option<HeldVote>,
    /// Cast history (receipts per BB, confirmation state).
    casts: Vec<CastRecord>,
}

/// A built-but-not-yet-confirmed ballot with its CAI disclosure (§3.8.4).
/// Never derives `Debug`: the disclosure reveals the vote.
#[derive(Clone, Serialize, Deserialize)]
struct HeldVote {
    ballot: Ballot<G>,
    disclosure: DiscloseCAI<G>,
    digest: BallotDigest,
    /// Hex-encoded commitment randomness (§5.3.1.6).
    rndcomm: String,
    emoji: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
struct CastRecord {
    digest: BallotDigest,
    receipts: Vec<Receipt>,
    emoji: Vec<String>,
    confirmed_at_ms: Option<u64>,
}

impl VoterState {
    fn state_path(&self, vid: Vid) -> PathBuf {
        self.state_dir.join(format!("voter-{}.dat", vid.value()))
    }

    fn next_rng(&self, purpose: &str) -> rand_chacha::ChaCha20Rng {
        // Recover from a poisoned mutex rather than panicking in a handler:
        // the RNG registry has no invariant a panicked holder could break
        // (it is a seed plus a monotonic counter).
        self.rng
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .next(purpose)
    }

    /// Find and decrypt the session unlocked by `passphrase`.
    async fn load_session(&self, passphrase: &str) -> Result<Option<VoterSession>, VoterError> {
        let mut entries = match tokio::fs::read_dir(&self.state_dir).await {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(VoterError::Io(e)),
        };
        while let Some(entry) = entries.next_entry().await.map_err(VoterError::Io)? {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("dat") {
                continue;
            }
            let ciphertext = tokio::fs::read(&path).await.map_err(VoterError::Io)?;
            match decrypt_state(&ciphertext, passphrase) {
                Ok(plaintext) => {
                    let session: VoterSession =
                        serde_json::from_slice(&plaintext).map_err(VoterError::Json)?;
                    return Ok(Some(session));
                }
                Err(VoterError::Crypto(_)) => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(None)
    }

    async fn save_session(
        &self,
        passphrase: &str,
        session: &VoterSession,
    ) -> Result<(), VoterError> {
        tokio::fs::create_dir_all(&self.state_dir)
            .await
            .map_err(VoterError::Io)?;
        let plaintext = serde_json::to_vec(session).map_err(VoterError::Json)?;
        let ciphertext = encrypt_state(&plaintext, passphrase)?;
        tokio::fs::write(self.state_path(session.vid), ciphertext)
            .await
            .map_err(VoterError::Io)?;
        Ok(())
    }

    /// Resolve a passphrase to a session.  Always decrypts from disk, so the
    /// passphrase itself is what authenticates the caller.
    async fn session_for(&self, passphrase: &str) -> Result<VoterSession, VoterError> {
        self.load_session(passphrase)
            .await?
            .ok_or(VoterError::Unauthorized)
    }
}

// ── Handlers ────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct LoginRequest {
    fiscal_id: String,
}

#[derive(Debug, Serialize)]
struct LoginResponse {
    vid: Vid,
}

/// V1: eID login via DIP, then ER `/login` (§5.3.1.1).
#[tracing::instrument(skip(state, req))]
async fn login_handler(
    Extension(state): Extension<Arc<VoterState>>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, VoterError> {
    let auth = state
        .dip_client
        .authenticate(&req.fiscal_id)
        .await
        .map_err(|_| VoterError::Unauthorized)?;
    let login = state
        .er_client
        .login(&auth.assertion, &auth.signature)
        .await
        .map_err(|_| VoterError::Unauthorized)?;

    let vid = login.vid;
    state.pending_logins.lock().await.insert(
        req.fiscal_id,
        PendingLogin {
            vid,
            registration_token: login.registration_token,
            credential_package: login.credential_package,
        },
    );
    Ok(Json(LoginResponse { vid }))
}

#[derive(Debug, Deserialize)]
struct EnrollRequest {
    fiscal_id: String,
}

#[derive(Serialize)]
struct EnrollResponse {
    vid: Vid,
    /// Shown exactly once; unlocks every subsequent API call (V2).
    passphrase: String,
}

impl std::fmt::Debug for EnrollResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrollResponse")
            .field("vid", &self.vid)
            .field("passphrase", &"<redacted>")
            .finish()
    }
}

/// V2 + V3: passphrase & app key generation, device registration, PIN request
/// to all RTs, NS registration (§3.6.1, §5.3.1.2/.3).
#[tracing::instrument(skip(state, req))]
async fn enroll_handler(
    Extension(state): Extension<Arc<VoterState>>,
    Json(req): Json<EnrollRequest>,
) -> Result<Json<EnrollResponse>, VoterError> {
    let pending = state
        .pending_logins
        .lock()
        .await
        .remove(&req.fiscal_id)
        .ok_or(VoterError::NotLoggedIn)?;

    if tokio::fs::try_exists(state.state_path(pending.vid))
        .await
        .unwrap_or(false)
    {
        return Err(VoterError::AlreadyEnrolled);
    }

    // 6-word passphrase (V2) and the EdDSA app key (§3.13), both from the
    // deterministic per-voter RNG.
    let passphrase = {
        let mut rng = state.next_rng("passphrase");
        evoting::utils::generate_passphrase(&mut rng, 6)
    };
    let at_sk_seed: [u8; 32] = {
        let mut rng = state.next_rng("app-key");
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        seed
    };
    let at_pk = hex::encode(
        ed25519_dalek::SigningKey::from_bytes(&at_sk_seed)
            .verifying_key()
            .to_bytes(),
    );

    // Device registration (§8.3 step 2c).  pkDV does not exist yet — the DV
    // key pair is generated by `VoterBuilder::new` at PIN retrieval (§8.3
    // ordering note) — so the PoC registers the app key only.
    state
        .er_client
        .register_device(&pending.registration_token, "", &at_pk)
        .await?;

    // PIN request tokens (§5.3.1.2) + NS registration + RT PIN requests.
    let tokens = state
        .er_client
        .pin_request_tokens(&pending.registration_token)
        .await?;
    state.ns_client.register(pending.vid, &tokens.rid).await?;
    if tokens.rt_tokens.len() != state.rt_clients.len() {
        return Err(VoterError::Protocol(
            "ER issued an unexpected number of RT tokens".into(),
        ));
    }
    for (rt, token) in state.rt_clients.iter().zip(&tokens.rt_tokens) {
        rt.credentials_request(token, &tokens.rid).await?;
    }

    let session = VoterSession {
        fiscal_id: req.fiscal_id,
        vid: pending.vid,
        registration_token: pending.registration_token,
        credential_package: pending.credential_package,
        at_sk_seed: hex::encode(at_sk_seed),
        rid: Some(tokens.rid),
        ns_token: Some(tokens.ns_token),
        pin: None,
        voter: None,
        held: None,
        casts: Vec::new(),
    };
    state.save_session(&passphrase, &session).await?;

    Ok(Json(EnrollResponse {
        vid: session.vid,
        passphrase,
    }))
}

#[derive(Deserialize)]
struct PassphraseRequest {
    passphrase: String,
}

impl std::fmt::Debug for PassphraseRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PassphraseRequest")
            .field("passphrase", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Serialize)]
struct StatusResponse {
    vid: Vid,
    enrolled: bool,
    pin_ready: bool,
    pin_set: bool,
}

/// Poll enrollment status: the PIN is ready once ≥ t_RT notifications arrived
/// at the NS for the current rid (§5.3.1.4).
#[tracing::instrument(skip(state, req))]
async fn status_handler(
    Extension(state): Extension<Arc<VoterState>>,
    Json(req): Json<PassphraseRequest>,
) -> Result<Json<StatusResponse>, VoterError> {
    let session = state.session_for(&req.passphrase).await?;
    let pin_ready = match (&session.rid, session.pin) {
        (_, Some(_)) => true,
        (Some(rid), None) => {
            let list = state.ns_client.notifications(session.vid, rid).await?;
            list.notifications.len() >= state.t_rt
        }
        (None, None) => false,
    };
    Ok(Json(StatusResponse {
        vid: session.vid,
        enrolled: true,
        pin_ready,
        pin_set: session.pin.is_some(),
    }))
}

#[derive(Serialize)]
struct PinResponse {
    vid: Vid,
    pin: PinCode,
}

impl std::fmt::Debug for PinResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PinResponse")
            .field("vid", &self.vid)
            .field("pin", &"<redacted>")
            .finish()
    }
}

/// V4: PIN delivery (§5.3.1.4/.5, §3.6.3, §3.6.2).
///
/// Re-login → retrieval tokens → `AccShareBroadcast` delivery from t_RT RTs →
/// `voter_build_acc` → `VoterBuilder::new` (DV keys) → threshold DVNIZKP with
/// the same RTs → `build_with_dvnizkp` → `finalize` → `verify_pin`.
#[tracing::instrument(skip(state, req))]
async fn pin_retrieve_handler(
    Extension(state): Extension<Arc<VoterState>>,
    Json(req): Json<PassphraseRequest>,
) -> Result<Json<PinResponse>, VoterError> {
    let mut session = state.session_for(&req.passphrase).await?;

    // Idempotent: a second retrieval re-displays the stored PIN.
    if let Some(pin) = session.pin {
        return Ok(Json(PinResponse {
            vid: session.vid,
            pin,
        }));
    }

    let rid = session.rid.clone().ok_or(VoterError::PinNotReady)?;

    // Gate on NS readiness (≥ t_RT notifications, §5.3.1.4).
    let notifications = state.ns_client.notifications(session.vid, &rid).await?;
    if notifications.notifications.len() < state.t_rt {
        return Err(VoterError::PinNotReady);
    }

    // Re-login for retrieval tokens (§5.3.1.4).
    let auth = state
        .dip_client
        .authenticate(&session.fiscal_id)
        .await
        .map_err(|_| VoterError::Unauthorized)?;
    let retrieval = state
        .er_client
        .retrieval_tokens(
            &session.registration_token,
            &auth.assertion,
            &auth.signature,
        )
        .await?;
    if retrieval.retrieval_tokens.len() > state.rt_clients.len() {
        return Err(VoterError::Protocol(
            "more retrieval tokens than RTs".into(),
        ));
    }

    // Fetch this voter's AccShareBroadcast from t_RT tellers (§3.6.3,
    // Deviation 5: shares travel over HTTPS from the RTs, not from the ER).
    let delivery: Vec<(&RtClient, TokenValue)> = state
        .rt_clients
        .iter()
        .zip(retrieval.retrieval_tokens.iter().cloned())
        .collect();
    let mut share_broadcasts = Vec::with_capacity(delivery.len());
    for (rt, token) in &delivery {
        share_broadcasts.push(rt.credentials_deliver(token).await?);
    }

    // Rebuild the credential builder + PIN locally (§8.3 step 4-5).
    let election_context = state.election_context.clone();
    let rt_pk = state.rt_pk.clone();
    let package = session.credential_package.clone();
    let mut build_rng = state.next_rng("voter-build-acc");
    let mut voter_rng = state.next_rng("voter-builder");
    let (credential_builder, pin, voter_builder, p1a, a_point) =
        tokio::task::spawn_blocking(move || {
            let enc_a_ext = package.enc_a_ext.clone().into();
            let (builder, pin, _public_acc) = voter_build_acc(
                &election_context.pk,
                &rt_pk,
                package.a,
                enc_a_ext,
                &share_broadcasts,
                &mut build_rng,
            );
            let voter_builder =
                VoterBuilder::new(&election_context, builder.clone(), &mut voter_rng);
            let p1a =
                ThresholdRegistrationTeller::credential_p1a(&election_context.pk, &builder, pin);
            let a_point = builder.credential_point();
            (builder, pin, voter_builder, p1a, a_point)
        })
        .await
        .map_err(|e| VoterError::Protocol(e.to_string()))?;

    // DVNIZKP round 1 with the RTs holding our delivery sessions (§3.6.2).
    let mut round1 = Vec::with_capacity(delivery.len());
    for (rt, token) in &delivery {
        round1.push(rt.dvnizkp_round1(token, &a_point).await?);
    }
    let all_ids: Vec<usize> = round1.iter().map(|b| b.from_id).collect();

    // Combiner step: the voter derives the S1 challenge (§3.6.2).
    let dv_pk = voter_builder.voter_pk();
    let election_pk = state.election_context.pk.clone();
    let mut combine_rng = state.next_rng("dvnizkp-combine");
    let round1_for_combine = round1.clone();
    let (i0, c0, z0, c1) = tokio::task::spawn_blocking(move || {
        ThresholdRegistrationTeller::dvnizkp_combine_commitments(
            &election_pk,
            &dv_pk,
            a_point,
            p1a,
            &round1_for_combine,
            &mut combine_rng,
        )
    })
    .await
    .map_err(|e| VoterError::Protocol(e.to_string()))?;

    // Round 2: collect the z1 scalar shares.
    let mut z1_shares = Vec::with_capacity(delivery.len());
    for (rt, token) in &delivery {
        z1_shares.push(rt.dvnizkp_round2(token, &c1, &all_ids).await?);
    }

    // Assemble, finalize, and locally verify the PIN (§3.7.1).
    let voter = tokio::task::spawn_blocking(move || {
        let proof =
            ThresholdRegistrationTeller::dvnizkp_assemble(&round1, i0, c0, z0, c1, &z1_shares);
        let credential = credential_builder.build_with_dvnizkp(proof);
        let voter = voter_builder.finalize(credential);
        voter.verify_pin(pin).map(|_| voter)
    })
    .await
    .map_err(|e| VoterError::Protocol(e.to_string()))?
    .map_err(|e| VoterError::Protocol(format!("delivered credential failed PIN check: {e:?}")))?;

    let pin_code = PinCode::new(pin as u32)
        .map_err(|e| VoterError::Protocol(format!("library PIN out of range: {e}")))?;
    session.pin = Some(pin_code);
    session.voter = Some(voter);
    state.save_session(&req.passphrase, &session).await?;

    Ok(Json(PinResponse {
        vid: session.vid,
        pin: pin_code,
    }))
}

/// Show the stored PIN (post-retrieval display).
#[tracing::instrument(skip(state, req))]
async fn pin_show_handler(
    Extension(state): Extension<Arc<VoterState>>,
    Json(req): Json<PassphraseRequest>,
) -> Result<Json<PinResponse>, VoterError> {
    let session = state.session_for(&req.passphrase).await?;
    let pin = session.pin.ok_or(VoterError::PinNotRetrieved)?;
    Ok(Json(PinResponse {
        vid: session.vid,
        pin,
    }))
}

#[derive(Deserialize)]
struct VerifyPinRequest {
    passphrase: String,
    pin: PinCode,
}

impl std::fmt::Debug for VerifyPinRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifyPinRequest")
            .field("passphrase", &"<redacted>")
            .field("pin", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Serialize)]
struct VerifyPinResponse {
    valid: bool,
}

/// V5: local, unlimited PIN verification (§3.7.1) — no network round-trips.
#[tracing::instrument(skip(state, req))]
async fn pin_verify_handler(
    Extension(state): Extension<Arc<VoterState>>,
    Json(req): Json<VerifyPinRequest>,
) -> Result<Json<VerifyPinResponse>, VoterError> {
    let session = state.session_for(&req.passphrase).await?;
    let voter = session.voter.ok_or(VoterError::PinNotRetrieved)?;
    let pin = req.pin.value() as usize;
    let valid = tokio::task::spawn_blocking(move || voter.verify_pin(pin).is_ok())
        .await
        .map_err(|e| VoterError::Protocol(e.to_string()))?;
    Ok(Json(VerifyPinResponse { valid }))
}

#[derive(Debug, Serialize)]
struct ElectionResponse {
    phase: String,
    options: Vec<&'static str>,
}

/// Public election info for the SPA (V1/V11).
#[tracing::instrument(skip(state))]
async fn election_handler(
    Extension(state): Extension<Arc<VoterState>>,
) -> Result<Json<ElectionResponse>, VoterError> {
    let phase = state
        .wbb_client
        .phase()
        .await
        .map_err(|e| VoterError::Protocol(format!("WBB phase query failed: {e}")))?;
    Ok(Json(ElectionResponse {
        phase,
        options: vec!["blank", "approve", "reject"],
    }))
}

#[derive(Deserialize)]
struct VoteRequest {
    passphrase: String,
    option: ReferendumOption,
    /// The PIN the voter types.  Deliberately NOT checked against the stored
    /// credential here: a wrong (or ruse) PIN builds a ballot that verifies
    /// at the BB but is filtered at tally time (§3.8.2 coercion resistance).
    pin: PinCode,
}

impl std::fmt::Debug for VoteRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VoteRequest")
            .field("passphrase", &"<redacted>")
            .field("option", &"<redacted>")
            .field("pin", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Serialize)]
struct VoteResponse {
    digest: BallotDigest,
    emoji: Vec<String>,
}

/// V11: build the ballot + CAI disclosure and hold it for casting (§3.8.2).
#[tracing::instrument(skip(state, req))]
async fn vote_handler(
    Extension(state): Extension<Arc<VoterState>>,
    Json(req): Json<VoteRequest>,
) -> Result<Json<VoteResponse>, VoterError> {
    let mut session = state.session_for(&req.passphrase).await?;
    let voter = session.voter.clone().ok_or(VoterError::PinNotRetrieved)?;

    let params = state.election_context.choice.clone();
    let mut vote_rng = state.next_rng("vote");
    let pin = req.pin.value() as usize;
    let option = req.option;
    let (ballot, disclosure) = tokio::task::spawn_blocking(move || {
        let choice = referendum_choice(option, &params)?;
        let builder = evoting::api::client::BallotBuilder::new(choice);
        // D13: disclose the l1 code slot; l2 is trivial for a referendum.
        Ok::<_, crate::protocol::voting::VotingError>(voter.vote_with_disclosure(
            &builder,
            pin,
            true,
            false,
            &mut vote_rng,
        ))
    })
    .await
    .map_err(|e| VoterError::Protocol(e.to_string()))?
    .map_err(|e| VoterError::Protocol(e.to_string()))?;

    let digest = ballot_digest(&ballot).map_err(|e| VoterError::Protocol(e.to_string()))?;
    let emoji: Vec<String> = ballot.to_emoji().iter().map(|s| s.to_string()).collect();
    let rndcomm: [u8; 32] = {
        let mut rng = state.next_rng("rndcomm");
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        bytes
    };

    session.held = Some(HeldVote {
        ballot,
        disclosure,
        digest,
        rndcomm: hex::encode(rndcomm),
        emoji: emoji.clone(),
    });
    state.save_session(&req.passphrase, &session).await?;

    Ok(Json(VoteResponse { digest, emoji }))
}

#[derive(Debug, Serialize)]
struct CastResultResponse {
    digest: BallotDigest,
    receipts: Vec<Receipt>,
    emoji: Vec<String>,
}

/// V12: cast the held ballot with CAT tokens to every trusted BB (§5.3.1.6,
/// §3.8.4 steps 1–7).
#[tracing::instrument(skip(state, req))]
async fn cast_handler(
    Extension(state): Extension<Arc<VoterState>>,
    Json(req): Json<PassphraseRequest>,
) -> Result<Json<CastResultResponse>, VoterError> {
    let mut session = state.session_for(&req.passphrase).await?;
    let held = session.held.clone().ok_or(VoterError::NoHeldBallot)?;

    let rndcomm: [u8; 32] = hex::decode(&held.rndcomm)
        .map_err(|e| VoterError::Protocol(format!("stored rndcomm corrupt: {e}")))?
        .try_into()
        .map_err(|_| VoterError::Protocol("stored rndcomm corrupt".into()))?;
    let commitment =
        comm_b(&held.ballot, &rndcomm).map_err(|e| VoterError::Protocol(e.to_string()))?;

    // Sign commB with the app key (AtSK) and request casting tokens.
    let at_sk_seed: [u8; 32] = hex::decode(&session.at_sk_seed)
        .map_err(|e| VoterError::Protocol(format!("stored app key corrupt: {e}")))?
        .try_into()
        .map_err(|_| VoterError::Protocol("stored app key corrupt".into()))?;
    let at_sk = ed25519_dalek::SigningKey::from_bytes(&at_sk_seed);
    use base64::Engine as _;
    use ed25519_dalek::Signer as _;
    let signature = base64::engine::general_purpose::STANDARD
        .encode(at_sk.sign(commitment.as_bytes()).to_bytes());

    let tokens = state
        .er_client
        .casting_tokens(&session.registration_token, &commitment, &signature)
        .await?;
    if tokens.casting_tokens.len() != state.bb_clients.len() {
        return Err(VoterError::Protocol(
            "ER issued an unexpected number of casting tokens".into(),
        ));
    }

    // Cast to every trusted BB (V10 default: all).
    let mut receipts = Vec::with_capacity(state.bb_clients.len());
    for (bb, token) in state.bb_clients.iter().zip(&tokens.casting_tokens) {
        let response = bb.cast(&held.ballot, &rndcomm, token).await?;
        receipts.push(response.receipt);
    }

    session.casts.push(CastRecord {
        digest: held.digest,
        receipts: receipts.clone(),
        emoji: held.emoji.clone(),
        confirmed_at_ms: None,
    });
    state.save_session(&req.passphrase, &session).await?;

    Ok(Json(CastResultResponse {
        digest: held.digest,
        receipts,
        emoji: held.emoji,
    }))
}

#[derive(Debug, Serialize)]
struct BallotStatusResponse {
    digest: BallotDigest,
    /// BB ids whose `ballot_digest` entry is on the WBB.
    published_bb_ids: Vec<u64>,
    /// True when ≥ 2 BBs published the digest (no ⊥, §3.8.5).
    no_bot: bool,
    confirmed_at_ms: Option<u64>,
}

/// V12 step 7 / V14: check the WBB publication of the last cast ballot.
#[tracing::instrument(skip(state, req))]
async fn ballot_status_handler(
    Extension(state): Extension<Arc<VoterState>>,
    Json(req): Json<PassphraseRequest>,
) -> Result<Json<BallotStatusResponse>, VoterError> {
    let session = state.session_for(&req.passphrase).await?;
    let record = session.casts.last().ok_or(VoterError::NoHeldBallot)?;
    let published_bb_ids = wbb_digest_publications(&state, &record.digest).await?;
    Ok(Json(BallotStatusResponse {
        digest: record.digest,
        no_bot: published_bb_ids.len() >= voting::NO_BOT_MIN_BBS,
        published_bb_ids,
        confirmed_at_ms: record.confirmed_at_ms,
    }))
}

/// Collect the bb_ids whose `ballot_digest` WBB entry matches `digest`.
async fn wbb_digest_publications(
    state: &VoterState,
    digest: &BallotDigest,
) -> Result<Vec<u64>, VoterError> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    let entries = state
        .wbb_client
        .entries()
        .await
        .map_err(|e| VoterError::Protocol(format!("WBB read failed: {e}")))?;
    let mut bb_ids = Vec::new();
    for sequenced in &entries.entries {
        let Some(data_b64) = sequenced.entry.get("data").and_then(|v| v.as_str()) else {
            continue;
        };
        let Ok(data) = B64.decode(data_b64) else {
            continue;
        };
        let Some(parsed) = voting::parse_wbb_data(&data) else {
            continue;
        };
        if parsed.entry_type != "ballot_digest" {
            continue;
        }
        let Ok(payload) = parsed.decode_payload::<BallotDigestEntry>() else {
            continue;
        };
        if payload.digest == *digest {
            bb_ids.push(payload.receipt.bb_id);
        }
    }
    bb_ids.sort_unstable();
    bb_ids.dedup();
    Ok(bb_ids)
}

#[derive(Debug, Serialize)]
struct ConfirmResponse {
    digest: BallotDigest,
    confirmed_at_ms: u64,
}

/// V13: send the held CAI disclosure to the BBs (§3.8.4 steps 8–17).
#[tracing::instrument(skip(state, req))]
async fn confirm_handler(
    Extension(state): Extension<Arc<VoterState>>,
    Json(req): Json<PassphraseRequest>,
) -> Result<Json<ConfirmResponse>, VoterError> {
    let mut session = state.session_for(&req.passphrase).await?;
    let held = session.held.clone().ok_or(VoterError::NoHeldBallot)?;
    if !session.casts.iter().any(|c| c.digest == held.digest) {
        return Err(VoterError::Protocol(
            "ballot must be cast before confirmation".into(),
        ));
    }

    let mut confirmed_at_ms = 0u64;
    for bb in &state.bb_clients {
        let response = bb.cai(&held.digest, &held.disclosure).await?;
        confirmed_at_ms = response.confirmed_at_ms.max(confirmed_at_ms);
    }

    if let Some(record) = session.casts.iter_mut().find(|c| c.digest == held.digest) {
        record.confirmed_at_ms = Some(confirmed_at_ms);
    }
    // The disclosure has served its purpose; drop the held ballot.
    session.held = None;
    let digest = held.digest;
    state.save_session(&req.passphrase, &session).await?;

    Ok(Json(ConfirmResponse {
        digest,
        confirmed_at_ms,
    }))
}

// ── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
enum VoterError {
    #[error("unauthorized")]
    Unauthorized,
    #[error("login required before enrollment")]
    NotLoggedIn,
    #[error("already enrolled")]
    AlreadyEnrolled,
    #[error("PIN is not ready for retrieval yet")]
    PinNotReady,
    #[error("PIN has not been retrieved yet")]
    PinNotRetrieved,
    #[error("no ballot to operate on — vote (and cast) first")]
    NoHeldBallot,
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("ER error: {0}")]
    Er(#[from] crate::clients::er::ErError),
    #[error("NS error: {0}")]
    Ns(#[from] crate::clients::ns::NsError),
    #[error("RT error: {0}")]
    Rt(#[from] crate::clients::rt::RtError),
    #[error("BB error: {0}")]
    Bb(#[from] crate::clients::bb::BbError),
}

impl IntoResponse for VoterError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, self.to_string()),
            Self::NotLoggedIn => (StatusCode::BAD_REQUEST, self.to_string()),
            Self::AlreadyEnrolled => (StatusCode::CONFLICT, self.to_string()),
            Self::PinNotReady => (StatusCode::CONFLICT, self.to_string()),
            Self::PinNotRetrieved => (StatusCode::BAD_REQUEST, self.to_string()),
            Self::NoHeldBallot => (StatusCode::BAD_REQUEST, self.to_string()),
            // Internal failures are logged but not leaked (style guide §03).
            _ => {
                tracing::error!(error = %self, "voter-server internal error");
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

pub fn router(state: Arc<VoterState>) -> Router {
    Router::new()
        .route("/api/login", post(login_handler))
        .route("/api/enroll", post(enroll_handler))
        .route("/api/status", post(status_handler))
        .route("/api/pin/retrieve", post(pin_retrieve_handler))
        .route("/api/pin", post(pin_show_handler))
        .route("/api/pin/verify", post(pin_verify_handler))
        .route("/api/election", axum::routing::get(election_handler))
        .route("/api/vote", post(vote_handler))
        .route("/api/cast", post(cast_handler))
        .route("/api/ballot/status", post(ballot_status_handler))
        .route("/api/confirm", post(confirm_handler))
        .fallback_service(ServeDir::new(&state.static_dir).append_index_html_on_directories(true))
        .layer(Extension(state))
}

/// Run the voter server.
pub async fn run(settings: Settings) -> anyhow::Result<()> {
    let (addr, rustls_config, state) = build_service(settings).await?;
    serve_rustls(router(state), addr, rustls_config).await
}

pub async fn build_service(
    settings: Settings,
) -> anyhow::Result<(
    SocketAddr,
    axum_server::tls_rustls::RustlsConfig,
    Arc<VoterState>,
)> {
    let election_context = load_election_context(&settings).await?;
    let rt_pk = load_rt_public_key(&settings).await?;
    let actor_seed = load_actor_seed(&settings).await?;
    let ca_pem = tokio::fs::read_to_string(&settings.tls.ca_pem)
        .await
        .map_err(|e| anyhow::anyhow!("failed to read CA cert: {e}"))?;
    let client = reqwest_client_trusting_ca(&ca_pem)?;

    let parse = |url: &str, what: &str| {
        reqwest::Url::parse(url).map_err(|e| anyhow::anyhow!("invalid {what} URL {url}: {e}"))
    };
    let dip_client = DipClient::new(client.clone(), parse(&settings.dip.base_url, "DIP")?);
    let er_client = ErClient::new(client.clone(), parse(&settings.er.base_url, "ER")?);
    let ns_client = NsClient::new(client.clone(), parse(&settings.ns.base_url, "NS")?);
    let rt_clients = build_rt_clients(&settings, client.clone())?;
    if rt_clients.is_empty() {
        anyhow::bail!("no RT peers configured (peers named rt-* required)");
    }
    let bb_clients = build_bb_clients(&settings, client.clone())?;
    if bb_clients.is_empty() {
        anyhow::bail!("no BB peers configured (peers named bb-* required for casting)");
    }
    let wbb_client = WbbClient::new(client, parse(&settings.wbb.base_url, "WBB")?);

    let state = Arc::new(VoterState {
        state_dir: PathBuf::from(&settings.voter.state_dir),
        static_dir: PathBuf::from(&settings.voter.static_dir),
        election_context,
        rt_pk,
        t_rt: settings.election.t_rt,
        dip_client,
        er_client,
        ns_client,
        rt_clients,
        bb_clients,
        wbb_client,
        rng: std::sync::Mutex::new(actor_seed.into_rng()),
        pending_logins: Mutex::new(HashMap::new()),
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

fn build_bb_clients(settings: &Settings, client: reqwest::Client) -> anyhow::Result<Vec<BbClient>> {
    let mut clients = Vec::new();
    for peer in &settings.peers {
        if peer.name.starts_with("bb-") {
            let url = reqwest::Url::parse(&peer.base_url)
                .map_err(|e| anyhow::anyhow!("invalid BB peer URL {}: {}", peer.base_url, e))?;
            clients.push(BbClient::new(client.clone(), url));
        }
    }
    Ok(clients)
}

fn build_rt_clients(settings: &Settings, client: reqwest::Client) -> anyhow::Result<Vec<RtClient>> {
    let mut clients = Vec::new();
    for peer in &settings.peers {
        if peer.name.starts_with("rt-") {
            let url = reqwest::Url::parse(&peer.base_url)
                .map_err(|e| anyhow::anyhow!("invalid RT peer URL {}: {}", peer.base_url, e))?;
            clients.push(RtClient::new(
                client.clone(),
                url,
                secrecy::SecretString::new(String::new()),
            ));
        }
    }
    Ok(clients)
}

async fn load_election_context(settings: &Settings) -> anyhow::Result<ElectionContext<G>> {
    let path = PathBuf::from(&settings._ceremony.election_context);
    let bytes = tokio::fs::read(&path)
        .await
        .map_err(|e| anyhow::anyhow!("failed to read {}: {}", path.display(), e))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| anyhow::anyhow!("failed to parse election context: {e}"))
}

async fn load_rt_public_key(
    settings: &Settings,
) -> anyhow::Result<evoting::api::prelude::RTPublicKey<G>> {
    let context_path = PathBuf::from(&settings._ceremony.election_context);
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

/// Load this voter instance's dedicated operation seed (`voter-{i}-seed.bin`).
async fn load_actor_seed(settings: &Settings) -> anyhow::Result<ActorSeed> {
    let context_path = PathBuf::from(&settings._ceremony.election_context);
    let base_dir = context_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let path = base_dir.join(format!("{}-seed.bin", settings.service.name));
    let bytes = tokio::fs::read(&path)
        .await
        .map_err(|e| anyhow::anyhow!("failed to read voter seed {}: {}", path.display(), e))?;
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("voter seed file must contain exactly 32 bytes"))?;
    Ok(ActorSeed::from_bytes(seed))
}

// ── ChaCha20-Poly1305 encryption for persisted voter state ─────────────────

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const SALT_LEN: usize = 16;
const KEY_LEN: usize = 32;

fn derive_key(passphrase: &str, salt: &[u8]) -> [u8; KEY_LEN] {
    let mut hasher = Sha3_256::new();
    hasher.update(salt);
    hasher.update(passphrase.as_bytes());
    hasher.finalize().into()
}

fn encrypt_state(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>, VoterError> {
    use ring::aead::{Aad, BoundKey, Nonce, SealingKey, UnboundKey, CHACHA20_POLY1305};

    // SIV-style determinism: the salt is derived from the plaintext, so every
    // distinct plaintext gets a distinct key, making the fixed all-zero nonce
    // safe under nonce-uniqueness (one message per key).  Re-encrypting the
    // same state yields the identical ciphertext — no randomness, so a server
    // restart cannot cause key+nonce reuse across different plaintexts (§9).
    let mut salt_hasher = Sha3_256::new();
    salt_hasher.update(b"referendum-poc-state-salt");
    salt_hasher.update(plaintext);
    let salt_full: [u8; 32] = salt_hasher.finalize().into();
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&salt_full[..SALT_LEN]);
    let nonce = [0u8; NONCE_LEN];

    let key = derive_key(passphrase, &salt);
    let unbound = UnboundKey::new(&CHACHA20_POLY1305, &key)
        .map_err(|_| VoterError::Crypto("invalid key".into()))?;
    let mut sealing_key = SealingKey::new(
        unbound,
        OneNonceSequence::new(Nonce::assume_unique_for_key(nonce)),
    );

    let mut in_out = plaintext.to_vec();
    let tag = sealing_key
        .seal_in_place_separate_tag(Aad::empty(), &mut in_out)
        .map_err(|_| VoterError::Crypto("encryption failed".into()))?;
    in_out.extend_from_slice(tag.as_ref());

    let mut output = Vec::with_capacity(SALT_LEN + NONCE_LEN + in_out.len());
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&in_out);
    Ok(output)
}

fn decrypt_state(ciphertext: &[u8], passphrase: &str) -> Result<Vec<u8>, VoterError> {
    use ring::aead::{Aad, BoundKey, Nonce, OpeningKey, UnboundKey, CHACHA20_POLY1305};

    if ciphertext.len() < SALT_LEN + NONCE_LEN + TAG_LEN {
        return Err(VoterError::Crypto("ciphertext too short".into()));
    }
    let salt = &ciphertext[..SALT_LEN];
    let nonce = &ciphertext[SALT_LEN..SALT_LEN + NONCE_LEN];
    let sealed = &ciphertext[SALT_LEN + NONCE_LEN..];

    let key = derive_key(passphrase, salt);
    let unbound = UnboundKey::new(&CHACHA20_POLY1305, &key)
        .map_err(|_| VoterError::Crypto("invalid key".into()))?;
    let nonce_arr: [u8; NONCE_LEN] = nonce
        .try_into()
        .map_err(|_| VoterError::Crypto("bad nonce length".into()))?;
    let mut opening_key = OpeningKey::new(
        unbound,
        OneNonceSequence::new(Nonce::assume_unique_for_key(nonce_arr)),
    );

    let mut in_out = sealed.to_vec();
    let plaintext = opening_key
        .open_in_place(Aad::empty(), &mut in_out)
        .map_err(|_| VoterError::Crypto("decryption failed".into()))?;
    Ok(plaintext.to_vec())
}

struct OneNonceSequence(Option<ring::aead::Nonce>);

impl OneNonceSequence {
    fn new(nonce: ring::aead::Nonce) -> Self {
        Self(Some(nonce))
    }
}

impl ring::aead::NonceSequence for OneNonceSequence {
    fn advance(&mut self) -> Result<ring::aead::Nonce, ring::error::Unspecified> {
        self.0.take().ok_or(ring::error::Unspecified)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let plaintext = b"hello voter";
        let passphrase = "correct-horse-battery-staple-mule-crank";
        let ciphertext = encrypt_state(plaintext, passphrase).unwrap();
        let decrypted = decrypt_state(&ciphertext, passphrase).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);
        assert!(decrypt_state(&ciphertext, "wrong").is_err());
    }

    #[test]
    fn encryption_is_deterministic_and_plaintext_bound() {
        let passphrase = "correct-horse-battery-staple-mule-crank";
        // Same plaintext → identical ciphertext (restart-safe, §9).
        let c1 = encrypt_state(b"state-v1", passphrase).unwrap();
        let c2 = encrypt_state(b"state-v1", passphrase).unwrap();
        assert_eq!(c1, c2);
        // Different plaintext → different salt, hence a different key under
        // the fixed nonce (no key+nonce pair ever encrypts two plaintexts).
        let c3 = encrypt_state(b"state-v2", passphrase).unwrap();
        assert_ne!(&c1[..SALT_LEN], &c3[..SALT_LEN]);
    }
}
