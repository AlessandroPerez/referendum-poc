//! Voter-facing server (Sec. 3.6, 3.7, 3.8, 5.3.1).
//!
//! Serves the enrollment SPA from `static_dir` and exposes a JSON API gated by
//! the voter's generated passphrase (V2).  Per-voter state is persisted as one
//! ChaCha20-Poly1305-encrypted file per vid; the passphrase is the only way to
//! unlock it.
//!
//! Enrollment flow (V1-V5):
//! 1. `POST /api/login`    - DIP assertion -> ER `/login` -> vid + registration token
//! 2. `POST /api/enroll`   - passphrase + app key, device registration, PIN
//!    request tokens -> RT `/credentials/request` (tau, NS notify), NS registration
//! 3. `POST /api/status`   - NS poll: PIN ready when >= t_RT notifications
//! 4. `POST /api/pin/retrieve` - re-login -> retrieval tokens -> RT share
//!    delivery -> `voter_build_acc` -> threshold DVNIZKP -> `Voter` + PIN
//! 5. `POST /api/pin`, `POST /api/pin/verify` - display / local check (Sec. 3.7.1)

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
use evoting::api::server::rt::AccShareCommitments;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use tokio::sync::Mutex;
use tower_http::services::{ServeDir, ServeFile};

use crate::actors::common::serve_rustls;
use crate::actors::rt::DeliveredShare;
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
    /// Longest a re-send waits for the tellers' waiting periods to end.
    tau_wait: std::time::Duration,
    dip_client: DipClient,
    er_client: ErClient,
    ns_client: NsClient,
    rt_clients: Vec<RtClient>,
    /// Peer names aligned with `rt_clients` (for V10 trusted selection).
    rt_names: Vec<String>,
    /// One client per configured ballot box (V10 default: all trusted).
    bb_clients: Vec<BbClient>,
    /// Peer names aligned with `bb_clients`.
    bb_names: Vec<String>,
    /// Read-only WBB access for publication checks (V14).
    wbb_client: WbbClient,
    /// Deterministic per-voter operation RNG; short critical sections
    /// only, so a sync mutex is fine. Used only under the logical clock.
    rng: std::sync::Mutex<ActorRng>,
    /// Draw the voter's own secrets from the OS CSPRNG rather than from the
    /// ceremony-derived seed.
    ///
    /// Everything this app draws is a voter secret: the passphrase that is
    /// the only lock on the recovery blob the roll stores, the app key that
    /// signs `commB`, the ballot randomness, the decoy PIN. Sec. 3.6.1 has
    /// the app generate `psph` itself, as the voter's own secret, and
    /// Table 6.2 keeps the PIN's story away from the authorities - none of
    /// which holds if a holder of the ceremony master seed can recompute
    /// them. The seeded path stays for the reproducible test runs, and is
    /// selected by the same switch as the logical clock.
    secrets_from_os: bool,
    /// Login state awaiting `/api/enroll`, keyed by fiscal id.
    pending_logins: Mutex<HashMap<String, PendingLogin>>,
    /// The ballots this device holds, by identifier - IN MEMORY, never on
    /// disk.
    ///
    /// Sec. 3.6.1 lists what the app saves encrypted and no ballot,
    /// disclosure or receipt is among them. That is load-bearing: a ballot
    /// carries BOTH cast-as-intended values until one is pinned, so a copy of
    /// the stored state is a copy of both, and whoever takes it can confirm
    /// the other slot - or confirm first and leave the voter refused by every
    /// box. Keeping them here means the file holds the credential and nothing
    /// a thief can vote or disclose with.
    ballots: Mutex<HashMap<Vid, HeldBallots>>,
    /// One writer per device at a time. A handler reads the device's session,
    /// does seconds of network work (the roll, every box, the tellers'
    /// waiting period) and writes the session back; two of them interleaved
    /// each act on a copy the other has made stale, and every such race found
    /// so far ended with a ballot stranded, a revoked identifier resurrected,
    /// or a confirmation undone. So every handler that WRITES the session
    /// holds this lock from its first read to its last write. Handlers that
    /// only read do not take it: a stale read costs nothing.
    device_locks: Mutex<HashMap<[u8; 32], Arc<Mutex<()>>>>,
    /// Identifiers whose enrollment is still registering the device and
    /// sending the PIN request in the background (see `enroll_handler`):
    /// the status screen reports a request as open while it runs.
    enrolling: Mutex<std::collections::HashSet<Vid>>,
    /// What this app has made of the board so far (see [`BoardView`]).
    board_view: Mutex<BoardView>,
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
    /// App-key (AtSK) seed, hex-encoded (used for CAT signing).
    at_sk_seed: String,
    rid: Option<String>,
    ns_token: Option<TokenValue>,
    pin: Option<PinCode>,
    voter: Option<Voter<G>>,
    /// Ballot built by `/api/vote`, awaiting cast/confirmation (Sec. 3.8).
    held: Option<HeldVote>,
    /// Every held ballot, one per PIN that built one. The cover story of
    /// Sec. 3.7.3 must survive a surveillance gap: a coercer who comes back
    /// to the control-values or confirmation screen finds the ballot THEIR
    /// PIN built exactly where they left it, whatever the voter did in
    /// between - and a PIN that built nothing reaches nothing.
    #[serde(default)]
    held_by_pin: Vec<HeldVote>,
    /// Cast history (receipts per BB, confirmation state).
    casts: Vec<CastRecord>,
    /// Ruse PIN + simulated voter (V7, Sec. 3.7.3 / Deviation 4).
    #[serde(default)]
    ruse_pin: Option<PinCode>,
    /// Registration tellers left out of the credential.
    ///
    /// Normally these are NAMED by Sec. 3.6.1 step 11: their share did not fit
    /// the dealers' published commitments, which is that teller's own doing.
    /// The subset rebuild below can still add a teller on suspicion when a
    /// credential fails the PIN check despite every share verifying, which no
    /// longer has an in-protocol cause - so this field is read as a report,
    /// and nothing acts on it automatically.
    #[serde(default)]
    rebuilt_without_rts: Vec<String>,
    /// A fresh random value each time a PIN is delivered (retrieval, re-send,
    /// ruse, revocation). Every open screen of this app compares it with the
    /// one it last saw and, when it changed, forgets every PIN it shows:
    /// after a ruse no other tab may go on showing the valid PIN. Random, not
    /// a count, so it says nothing about how many deliveries there were.
    #[serde(default)]
    pin_epoch: String,
    #[serde(default)]
    ruse_voter: Option<Voter<G>>,
    /// The dealers' commitments for this credential, pinned the first time
    /// t_RT tellers agreed on them (Sec. 3.6.1 step 11).
    #[serde(default)]
    share_commitments: Option<AccShareCommitments<G>>,
    /// Trusted authority selection (V10, Sec. 3.12).  `None` = all configured.
    #[serde(default)]
    trusted: Option<TrustedSettings>,
    /// Bumped by every revocation. A crash between saving the new session and
    /// removing the old file leaves two files that decrypt under one
    /// passphrase; the HIGHER generation is the device's, whatever order the
    /// directory lists them in, and the other is removed on the next load.
    #[serde(default)]
    generation: u64,
    /// Whether the roll is known to hold this device's app key. An
    /// enrollment saves the session BEFORE it registers the device, so a
    /// lost answer from the roll leaves `false` here; the next PIN request
    /// registers the SAME key again, which the roll accepts (Sec. 3.7.4
    /// step 7 compares the stored and received values).
    #[serde(default = "registered_by_default")]
    device_registered: bool,
    /// The id of a revocation this device sent and has not heard the answer
    /// to. Saved BEFORE the request leaves; sent again on a retry, so the
    /// roll can tell a lost answer from a new revocation (Sec. 3.7.5: one
    /// request, one spare).
    #[serde(default)]
    pending_revocation: Option<String>,
    /// How many ballots this device has built. Each ballot carries its
    /// number (`HeldVote::built`): the voter's own order of intent, which
    /// never changes, whatever order the boxes publish them in.
    #[serde(default)]
    built: u64,
    /// The ballots `session_for` handed this handler, as they were then.
    /// Never stored: it is the base `save_session` applies this handler's
    /// difference against (see `HeldBallots::apply`).
    #[serde(skip)]
    ballots_base: Option<HeldBallots>,
}

fn registered_by_default() -> bool {
    true
}

/// What a device holds about ballots in flight: never written to disk.
///
/// This map, not the session a handler is holding, is the truth about
/// ballots: a handler reads a COPY of it and may take seconds over a network
/// round-trip, so writing its copy back wholesale would undo whatever else
/// happened meanwhile - including a confirmation, which would put both
/// unpinned openings of a confirmed ballot back within reach and let the
/// device send the OTHER one (Sec. 3.8.4 steps 10-14: the two together are
/// the vote). `save_session` therefore writes here only what its own handler
/// changed, and never brings back a ballot already confirmed.
#[derive(Default, Clone, Serialize)]
struct HeldBallots {
    held: Option<HeldVote>,
    held_by_pin: Vec<HeldVote>,
    casts: Vec<CastRecord>,
}

impl HeldBallots {
    fn of(session: &VoterSession) -> Self {
        Self {
            held: session.held.clone(),
            held_by_pin: session.held_by_pin.clone(),
            casts: session.casts.clone(),
        }
    }

    /// Apply to the live map the difference between what a handler was handed
    /// (`base`) and what it wrote back (`mine`).
    ///
    /// Never a whole-value overwrite: a handler holds its copy across a
    /// network round trip - `/api/cast` talks to the roll and to every box -
    /// and whatever else happened meanwhile is in the map, not in that copy.
    /// So a ballot the handler did not touch is left alone, one it dropped is
    /// dropped here, one it added is added, and a cast record it did not
    /// create keeps the confirmation state the map holds: a confirmation is
    /// the one thing that must never be undone, because undoing it puts both
    /// openings of a confirmed ballot back within reach (Sec. 3.8.4
    /// steps 10-14).
    fn apply(&mut self, base: &HeldBallots, mine: HeldBallots) {
        let key = |v: &HeldVote| (v.pin, v.digest);
        let had = |set: &[HeldVote], v: &HeldVote| set.iter().any(|o| key(o) == key(v));

        // Held ballots: the handler's additions, removals and in-place
        // changes, nothing else. The one in-place change that exists is the
        // confirmation PINNING its choice and destroying the unused openings
        // (Sec. 3.8.4 steps 10-11) before anything is sent - it must land
        // even when the sending then fails, or the retry could open the
        // other slot. A change to a ballot the map has meanwhile dropped is
        // not applied: dropped is final.
        let removed: Vec<(Option<PinCode>, BallotDigest)> = base
            .held_by_pin
            .iter()
            .filter(|v| !had(&mine.held_by_pin, v))
            .map(key)
            .collect();
        self.held_by_pin.retain(|v| !removed.contains(&key(v)));
        let same =
            |a: &HeldVote, b: &HeldVote| serde_json::to_vec(a).ok() == serde_json::to_vec(b).ok();
        for v in &mine.held_by_pin {
            match base.held_by_pin.iter().find(|b| key(b) == key(v)) {
                None => {
                    self.held_by_pin.retain(|o| key(o) != key(v));
                    self.held_by_pin.push(v.clone());
                }
                Some(before) if !same(before, v) => {
                    if let Some(live) = self.held_by_pin.iter_mut().find(|o| key(o) == key(v)) {
                        *live = v.clone();
                    }
                }
                Some(_) => {}
            }
        }
        if mine.held.as_ref().map(key) != base.held.as_ref().map(key) {
            self.held = mine.held;
        }
        if self
            .held
            .as_ref()
            .is_some_and(|h| removed.contains(&key(h)))
        {
            self.held = None;
        }

        // Cast records: the handler's version of a record wins, EXCEPT for
        // the confirmation, which only the confirming handler sets and which
        // no later writer may clear.
        for record in mine.casts {
            match self
                .casts
                .iter_mut()
                .find(|c| c.pin == record.pin && c.digest == record.digest)
            {
                Some(live) => {
                    let confirmed_at_ms = live.confirmed_at_ms.or(record.confirmed_at_ms);
                    let disclosed = live.disclosed.clone().or_else(|| record.disclosed.clone());
                    *live = record;
                    live.confirmed_at_ms = confirmed_at_ms;
                    live.disclosed = disclosed;
                }
                None => self.casts.push(record),
            }
        }
    }

    /// Drop every held ballot that a cast record here shows as CONFIRMED.
    /// One-way: no ordering of handlers can put one back.
    fn forget_confirmed(&mut self) {
        let confirmed: Vec<(Option<PinCode>, BallotDigest)> = self
            .casts
            .iter()
            .filter(|c| c.confirmed_at_ms.is_some())
            .map(|c| (c.pin, c.digest))
            .collect();
        let is_confirmed = |v: &HeldVote| {
            confirmed
                .iter()
                .any(|(pin, d)| *pin == v.pin && *d == v.digest)
        };
        self.held_by_pin.retain(|v| !is_confirmed(v));
        if self.held.as_ref().is_some_and(is_confirmed) {
            self.held = None;
        }
    }
}

/// Trusted RT/BB selection (V10).  Names are peer names (`rt-1`, `bb-2`).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TrustedSettings {
    rts: Vec<String>,
    bbs: Vec<String>,
}

/// Which cast-as-intended value of a level the voter asks to open
/// (Sec. 3.8.4 steps 10-11): the control code or the control sum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum CaiSlot {
    Code,
    Sum,
}

/// The cast-as-intended openings held for a built ballot.
///
/// The ballot always carries BOTH encrypted values of each level (code and
/// sum); which one is opened must be decided by the voter only AFTER the
/// ballot has been cast, otherwise a malicious device could alter the vote
/// and keep just the to-be-opened value consistent (Sec. 3.8.4, note on step
/// 9). So the app keeps the openings of both slots until the choice is made.
///
/// Opening both slots of a level would reveal the vote (sum - code = choice):
/// the first choice is therefore pinned, persisted BEFORE anything is sent,
/// and the unused openings are destroyed. A retry can only resend the same
/// disclosure. Never derives `Debug`: the openings reveal the vote.
#[derive(Clone, Serialize, Deserialize)]
enum HeldDisclosure {
    /// No choice made yet: the openings of every code slot and of every sum slot.
    Open {
        all_code: DiscloseCAI<G>,
        all_sum: DiscloseCAI<G>,
    },
    /// Choice made: only the chosen openings survive.
    Chosen {
        l1: CaiSlot,
        l2: CaiSlot,
        disclosure: DiscloseCAI<G>,
    },
}

impl HeldDisclosure {
    /// Pin the voter's choice (or return the already pinned disclosure when
    /// the same choice is repeated). A different choice after the first one
    /// is refused: it would open both slots.
    fn choose(&mut self, l1: CaiSlot, l2: CaiSlot) -> Result<DiscloseCAI<G>, VoterError> {
        match self {
            HeldDisclosure::Open { all_code, all_sum } => {
                let pick = |slot: CaiSlot| match slot {
                    CaiSlot::Code => &*all_code,
                    CaiSlot::Sum => &*all_sum,
                };
                let disclosure = DiscloseCAI {
                    l1: pick(l1).l1.clone(),
                    l2: pick(l2).l2.clone(),
                };
                *self = HeldDisclosure::Chosen {
                    l1,
                    l2,
                    disclosure: disclosure.clone(),
                };
                Ok(disclosure)
            }
            HeldDisclosure::Chosen {
                l1: pinned_l1,
                l2: pinned_l2,
                disclosure,
            } => {
                if (*pinned_l1, *pinned_l2) != (l1, l2) {
                    return Err(VoterError::CaiAlreadyChosen);
                }
                Ok(disclosure.clone())
            }
        }
    }

    /// The pinned choice, if any.
    fn chosen(&self) -> Option<(CaiSlot, CaiSlot)> {
        match self {
            HeldDisclosure::Open { .. } => None,
            HeldDisclosure::Chosen { l1, l2, .. } => Some((*l1, *l2)),
        }
    }
}

/// The decoy PIN in force, if any.
///
/// NOTHING in this app compares a decoy with the real PIN. `/api/pin/ruse`
/// neither refuses a choice, nor treats one differently, nor leaves a
/// different state behind: Sec. 6.3.2 p. 131 rests the whole PIN-leak
/// mitigation on the coercer being unable to test a PIN - "a ruse PIN is
/// always displayed exactly as the valid PIN, the attacker is not sure of
/// the validity of the PIN learned" - and Sec. 3.7.3 puts no limit on ruse
/// requests, so ANY difference, in the answer or in what the next screen
/// says, is an oracle that can be run to exhaustion.
///
/// The consequence is deliberate: a voter who types their OWN PIN into the
/// decoy box arms it as a decoy - but Sec. 3.7.3 step 5 builds the ruse
/// credential for `x + PIN^ruse - PIN^valid`, which for their own PIN IS the
/// valid credential, so ballots cast with it still count. A decoy the app
/// draws itself is uniform over every PIN, the real one included (see
/// `pin_ruse_handler`), and arming any other value makes that value the
/// decoy instead.
///
/// PrivatePINEmoji of `pin` (Sec. 3.6.3 step 5, 3.7.1, 3.8.2 step 14): the
/// visual digest of `H(o^x)` for the credential that PIN is used with - the
/// ruse credential for the ruse PIN, the real one for any other PIN, exactly
/// as the vote itself dispatches. `None` before the PIN has been retrieved.
fn private_pin_emoji(session: &VoterSession, pin: PinCode) -> Option<Vec<String>> {
    let voter = if session.ruse_pin == Some(pin) {
        session.ruse_voter.as_ref().or(session.voter.as_ref())
    } else {
        session.voter.as_ref()
    }?;
    Some(
        voter
            .private_pin_emoji(pin.value() as usize)
            .iter()
            .map(|s| s.to_string())
            .collect(),
    )
}

/// A built-but-not-yet-confirmed ballot with its CAI openings (Sec. 3.8.4).
/// Never derives `Debug`: the openings reveal the vote.
#[derive(Clone, Serialize, Deserialize)]
struct HeldVote {
    ballot: Ballot<G>,
    disclosure: HeldDisclosure,
    /// The plain control values sealed in the ballot (Sec. 3.8.4 step 9):
    /// shown to the voter only after the cast, never sent anywhere.
    control: evoting::api::prelude::CaiValues,
    digest: BallotDigest,
    /// Hex-encoded commitment randomness (Sec. 5.3.1.6).
    rndcomm: String,
    emoji: Vec<String>,
    /// What the ballot boxes must publish next to the digest, computed here
    /// (Sec. 3.8.4 step 2) so this app can check the board itself.
    #[serde(default)]
    public_pin_emoji: Vec<String>,
    /// True when this ballot was built with the ruse credential: the cover
    /// story (Sec. 3.7.3) has to hold for what the app SHOWS about it too.
    #[serde(default)]
    ruse: bool,
    /// The PIN that built this ballot. The screens that work on a held
    /// ballot answer about the ballot of the PIN they are given and no
    /// other: whoever types a PIN sees what THAT PIN did, which is what
    /// makes the decoy of Sec. 3.7.3 a complete story, and what stops a PIN
    /// nobody built a ballot with from reaching somebody else's.
    #[serde(default)]
    pin: Option<PinCode>,
    /// The order the voter built this ballot in (`VoterSession::built`).
    #[serde(default)]
    built: u64,
}

#[derive(Clone, Serialize, Deserialize)]
struct CastRecord {
    digest: BallotDigest,
    receipts: Vec<Receipt>,
    emoji: Vec<String>,
    confirmed_at_ms: Option<u64>,
    /// True for a ballot cast with the ruse credential.
    #[serde(default)]
    ruse: bool,
    /// The PIN that built this ballot: the status screen answers to that PIN
    /// and no other.
    #[serde(default)]
    pin: Option<PinCode>,
    /// The cast-as-intended disclosure this device actually sent, and the
    /// values it opens to. The status screen re-checks the board against
    /// them: a box may publish the right numbers next to ANOTHER ballot's
    /// disclosure, which the tally discards (Sec. 3.10 1(d)), and the voter
    /// must not be told "counted" for it.
    #[serde(default)]
    disclosed: Option<Disclosed>,
    /// The order the voter built this ballot in (`VoterSession::built`).
    #[serde(default)]
    built: u64,
}

/// What this device sealed when it confirmed a ballot.
#[derive(Clone, Serialize, Deserialize)]
struct Disclosed {
    disclosure: DiscloseCAI<G>,
    opened: evoting::api::prelude::OpenedCai,
}

impl std::fmt::Debug for Disclosed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Disclosed").finish_non_exhaustive()
    }
}

impl VoterState {
    fn state_path(&self, vid: Vid) -> PathBuf {
        self.state_dir.join(format!("voter-{}.dat", vid.value()))
    }

    fn next_rng(&self, purpose: &str) -> rand_chacha::ChaCha20Rng {
        if self.secrets_from_os {
            use rand::SeedableRng as _;
            return rand_chacha::ChaCha20Rng::from_entropy();
        }
        // Recover from a poisoned mutex rather than panicking in a handler:
        // the RNG registry has no invariant a panicked holder could break
        // (it is a seed plus a monotonic counter).
        self.rng
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .next(purpose)
    }

    /// Find and decrypt the session unlocked by `passphrase`.
    ///
    /// Decrypting and parsing run on a blocking thread: the key derivation is
    /// CPU work that must not stall the runtime, and the session is a large
    /// value that, parsed in the handler's own frame, would deepen every
    /// handler's stack by the whole deserializer. It comes back boxed for the
    /// same reason.
    async fn load_session(
        &self,
        passphrase: &str,
    ) -> Result<Option<Box<VoterSession>>, VoterError> {
        let mut entries = match tokio::fs::read_dir(&self.state_dir).await {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(VoterError::Io(e)),
        };
        // Every file that decrypts under this passphrase is this device's; the
        // one with the highest generation is current (a crash between saving
        // a revoked-onto session and removing the old file leaves two), and
        // any other is a leftover, removed here so the directory's order never
        // decides which credential the voter is on.
        let mut found: Vec<(std::path::PathBuf, Box<VoterSession>)> = Vec::new();
        while let Some(entry) = entries.next_entry().await.map_err(VoterError::Io)? {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("dat") {
                continue;
            }
            // A superseded file can be removed by another reader between the
            // listing and this read: it is gone, not an error.
            let ciphertext = match tokio::fs::read(&path).await {
                Ok(bytes) => bytes,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(VoterError::Io(e)),
            };
            let passphrase = passphrase.to_owned();
            let parsed =
                tokio::task::spawn_blocking(move || decrypt_session(&ciphertext, &passphrase))
                    .await
                    .map_err(|e| VoterError::Io(std::io::Error::other(e)))??;
            if let Some(session) = parsed {
                found.push((path, session));
            }
        }
        let Some(newest) = found.iter().map(|(_, s)| s.generation).max() else {
            return Ok(None);
        };
        let mut current = None;
        for (path, session) in found {
            if session.generation == newest && current.is_none() {
                current = Some(session);
            } else {
                tracing::warn!(path = %path.display(), "removing a superseded session file");
                let _ = tokio::fs::remove_file(&path).await;
            }
        }
        Ok(current)
    }

    async fn save_session(
        &self,
        passphrase: &str,
        session: &VoterSession,
    ) -> Result<(), VoterError> {
        tokio::fs::create_dir_all(&self.state_dir)
            .await
            .map_err(VoterError::Io)?;
        let mine = HeldBallots::of(session);
        {
            let mut ballots = self.ballots.lock().await;
            let live = ballots.entry(session.vid).or_default();
            // A handler holds its copy across seconds of network work, so
            // what it wrote back can never simply replace what the map holds
            // now: it would undo whatever else happened meanwhile, and a
            // confirmation undone is both openings of a confirmed ballot back
            // within reach (Sec. 3.8.4 steps 10-14). Only the DIFFERENCE this
            // handler made is applied, against the base it was handed. A
            // session that never read the ballots at all - a recovery, or the
            // enrollment that creates the device - made no difference and
            // writes nothing.
            if let Some(base) = &session.ballots_base {
                live.apply(base, mine);
            }
            live.forget_confirmed();
        }
        let mut stored = Box::new(session.clone());
        stored.held = None;
        stored.held_by_pin.clear();
        stored.casts.clear();
        let passphrase_owned = passphrase.to_owned();
        let ciphertext = tokio::task::spawn_blocking(move || {
            let plaintext = serde_json::to_vec(&stored).map_err(VoterError::Json)?;
            encrypt_state(&plaintext, &passphrase_owned)
        })
        .await
        .map_err(|e| VoterError::Io(std::io::Error::other(e)))??;
        // Through a temporary file and a rename: a reader in the middle of an
        // in-place rewrite would find a file that decrypts under no passphrase
        // and answer "unauthorized" to the right one, and a crash in it would
        // lose the credential file.
        let path = self.state_path(session.vid);
        let tmp = path.with_extension("dat.tmp");
        tokio::fs::write(&tmp, ciphertext)
            .await
            .map_err(VoterError::Io)?;
        tokio::fs::rename(&tmp, &path)
            .await
            .map_err(VoterError::Io)?;
        Ok(())
    }

    /// Register this device's app key with the roll if the enrollment could
    /// not confirm it did (see `VoterSession::device_registered`).
    async fn ensure_device_registered(&self, session: &mut VoterSession) -> Result<(), VoterError> {
        if session.device_registered {
            return Ok(());
        }
        let seed: [u8; 32] = hex::decode(&session.at_sk_seed)
            .map_err(|e| VoterError::Protocol(format!("stored app key corrupt: {e}")))?
            .try_into()
            .map_err(|_| VoterError::Protocol("stored app key corrupt".into()))?;
        let at_pk = hex::encode(
            ed25519_dalek::SigningKey::from_bytes(&seed)
                .verifying_key()
                .to_bytes(),
        );
        self.er_client
            .register_device(&session.registration_token, "", &at_pk, None)
            .await?;
        session.device_registered = true;
        Ok(())
    }

    /// The write lock of the device `passphrase` unlocks (see `device_locks`).
    ///
    /// The passphrase is resolved to a session FIRST - so a caller that is not
    /// this device's holder gets `Unauthorized` and allocates nothing, and the
    /// map is bounded by the devices this server really holds, not by strings
    /// an unauthenticated caller chooses. The lock itself is keyed by the
    /// passphrase (see `device_lock_unchecked`). The caller re-reads the
    /// session under the lock.
    async fn device_lock(
        &self,
        passphrase: &str,
    ) -> Result<tokio::sync::OwnedMutexGuard<()>, VoterError> {
        // Authenticate first: a passphrase that unlocks nothing allocates
        // nothing, so the map is bounded by the devices this server holds.
        self.load_session(passphrase)
            .await?
            .ok_or(VoterError::Unauthorized)?;
        Ok(self.device_lock_unchecked(passphrase).await)
    }

    /// The lock itself, keyed by the PASSPHRASE (hashed) and not by the
    /// identifier: a revocation changes the identifier in the middle of a
    /// handler, and a lock keyed by it let a writer queued behind the
    /// revocation hold the old key while a writer arriving after it took the
    /// new one - two writers on one device. The passphrase is what stays the
    /// same across everything a device can do. Callers authenticate first
    /// (`device_lock`) or have just decrypted this device's recovery blob.
    async fn device_lock_unchecked(&self, passphrase: &str) -> tokio::sync::OwnedMutexGuard<()> {
        use sha3::Digest as _;
        let key: [u8; 32] = sha3::Sha3_256::digest(passphrase.as_bytes()).into();
        let lock = self
            .device_locks
            .lock()
            .await
            .entry(key)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone();
        lock.lock_owned().await
    }

    /// Resolve a passphrase to a session.  Always decrypts from disk, so the
    /// passphrase itself is what authenticates the caller.
    async fn session_for(&self, passphrase: &str) -> Result<VoterSession, VoterError> {
        let mut session = *self
            .load_session(passphrase)
            .await?
            .ok_or(VoterError::Unauthorized)?;
        let held = self
            .ballots
            .lock()
            .await
            .get(&session.vid)
            .cloned()
            .unwrap_or_default();
        session.held = held.held.clone();
        session.held_by_pin = held.held_by_pin.clone();
        session.casts = held.casts.clone();
        session.ballots_base = Some(held);
        Ok(session)
    }

    /// The tellers that have announced, through the notification service,
    /// that their waiting period for this request is over. EVERY teller
    /// counts, trusted or not: Sec. 3.6.3 has each RT_i send its shares and
    /// the app interpolate any t_RT of them; the trusted selection of
    /// Sec. 3.12 only decides which tellers can tell a ruse from a re-send,
    /// and the ruse is made on the device here. Narrowing retrieval to the
    /// trusted tellers would let one of them deny the voter a credential.
    fn ready_rts<'a>(
        &'a self,
        _session: &VoterSession,
        notifications: &crate::clients::ns::NotificationList,
    ) -> Vec<(&'a str, &'a RtClient)> {
        let announced: std::collections::HashSet<String> = notifications
            .notifications
            .iter()
            .map(|n| n.rt_id.to_lowercase())
            .collect();
        self.rt_names
            .iter()
            .zip(&self.rt_clients)
            .filter(|(name, _)| announced.contains(&name.to_lowercase()))
            .map(|(name, c)| (name.as_str(), c))
            .collect()
    }

    /// The trusted ballot boxes with their ids (`bb-2` is ballot box 2).
    fn trusted_bbs_with_ids<'a>(&'a self, session: &VoterSession) -> Vec<(u64, &'a BbClient)> {
        self.bb_names
            .iter()
            .zip(&self.bb_clients)
            .filter(|(name, _)| match &session.trusted {
                Some(t) => t.bbs.contains(name),
                None => true,
            })
            .filter_map(|(name, client)| {
                let id = name.rsplit('-').next()?.parse().ok()?;
                Some((id, client))
            })
            .collect()
    }

    /// V3: request PIN delivery - fresh pin-request tokens under a new rid,
    /// NS registration, and RT `/credentials/request` on every teller
    /// (Sec. 5.3.1.2/.3, Sec. 3.6.3).  Updates `session.rid`/`ns_token`.
    async fn run_pin_request(&self, session: &mut VoterSession) -> Result<(), VoterError> {
        self.ensure_device_registered(session).await?;
        let tokens = self
            .er_client
            .pin_request_tokens(&session.registration_token)
            .await?;
        self.ns_client.register(session.vid, &tokens.rid).await?;
        if tokens.rt_tokens.len() < self.rt_clients.len() {
            return Err(VoterError::Protocol(
                "ER issued fewer RT tokens than there are tellers".into(),
            ));
        }
        // A teller that refuses or errors is dropped, not fatal: the
        // credential needs t_RT of them (A2, Sec. 3.6.3), so one teller must
        // not be able to deny a voter their enrollment. The request is made
        // to every teller and counted.
        let mut asked = 0usize;
        let mut refused = Vec::new();
        for (rt, token) in self.rt_clients.iter().zip(&tokens.rt_tokens) {
            match rt.credentials_request(token, &tokens.rid).await {
                Ok(_) => asked += 1,
                Err(e) => refused.push(e.to_string()),
            }
        }
        if asked < self.t_rt {
            tracing::warn!(
                "only {asked} of the registration tellers accepted the credential \
                 request, {} are needed: {}",
                self.t_rt,
                refused.join("; ")
            );
            return Err(VoterError::TooFewTellersForRequest {
                asked,
                needed: self.t_rt,
            });
        }
        for reason in &refused {
            tracing::warn!("a registration teller refused the credential request: {reason}");
        }
        session.rid = Some(tokens.rid);
        session.ns_token = Some(tokens.ns_token);
        Ok(())
    }

    /// V4: retrieval-token share delivery + threshold DVNIZKP against the
    /// tellers that have announced themselves - every teller, trusted or not
    /// (Sec. 3.6.3) - finalizing the `Voter` (Sec. 5.3.1.4/.5, Sec. 3.6.2/.3).
    ///
    /// EVERY path that rebuilds a credential goes through here, retrieval and
    /// re-send alike. A revocation clears any decoy first (Sec. 3.7.5: a new
    /// registration shows PIN^valid), so none is carried over.
    async fn run_retrieval(&self, session: &mut VoterSession) -> Result<PinCode, VoterError> {
        let pin = self.rebuild_credential(session).await?;
        Ok(pin)
    }

    /// Sec. 3.6.1 step 11 has the app check each teller's share proof and
    /// interpolate the good ones; the library's `AccShareBroadcast` carries no
    /// proof, so a bad share is only found when the finished credential
    /// fails the PIN check. The app then retries with every `t_rt`-subset of
    /// the ready tellers: the subset that yields a credential names the
    /// teller(s) left out of it, and the voter is not denied a credential by
    /// one dishonest teller within the threshold (A2). A teller that drops
    /// out of the DVNIZKP rounds is retried the same way.
    async fn rebuild_credential(&self, session: &mut VoterSession) -> Result<PinCode, VoterError> {
        match self.run_retrieval_with(session, None).await {
            Err(VoterError::CredentialFailedPinCheck) | Err(VoterError::CredentialRoundRefused) => {
            }
            other => return other,
        }
        let rid = session.rid.clone().ok_or(VoterError::PinNotReady)?;
        let notifications = self.ns_client.notifications(session.vid, &rid).await?;
        let ready: Vec<String> = self
            .ready_rts(session, &notifications)
            .into_iter()
            .map(|(name, _)| name.to_string())
            .collect();
        // One bad share must not cost C(n,t) full retrievals: each attempt is
        // a fresh eID assertion, fresh retrieval tokens, share deliveries and
        // two DVNIZKP rounds, and the count is combinatorial. A teller that
        // sometimes returns a bad share would otherwise impose that on the
        // roll, the DIP and every honest teller with no cap.
        const MAX_SUBSET_ATTEMPTS: usize = 8;
        for subset in t_subsets(&ready, self.t_rt)
            .into_iter()
            .take(MAX_SUBSET_ATTEMPTS)
        {
            match self.run_retrieval_with(session, Some(&subset)).await {
                Ok(pin) => {
                    let excluded: Vec<&String> =
                        ready.iter().filter(|n| !subset.contains(n)).collect();
                    tracing::warn!(
                        ?excluded,
                        "credential rebuilt without these tellers: one of their shares did not \
                         fit, which of them cannot be told without a per-share proof"
                    );
                    session.rebuilt_without_rts = excluded.into_iter().cloned().collect();
                    return Ok(pin);
                }
                // A teller in this subset that refuses to deliver now (it
                // delivered before, or the subset would not be ready) is one
                // more teller to leave out, not a reason to stop: otherwise
                // one dishonest teller holds every retry (A2).
                Err(VoterError::CredentialFailedPinCheck)
                | Err(VoterError::CredentialRoundRefused)
                | Err(VoterError::TellersStillWaiting) => continue,
                Err(e) => return Err(e),
            }
        }
        Err(VoterError::CredentialFailedPinCheck)
    }

    async fn run_retrieval_with(
        &self,
        session: &mut VoterSession,
        only: Option<&[String]>,
    ) -> Result<PinCode, VoterError> {
        let rid = session.rid.clone().ok_or(VoterError::PinNotReady)?;

        // Gate on NS readiness (Sec. 5.3.1.4): each teller announces itself
        // only once ITS waiting period is over, and the periods differ. Ask
        // only the tellers that have announced - asking a slower one
        // would just be refused - and go ahead as soon as t_RT of them have.
        let notifications = self.ns_client.notifications(session.vid, &rid).await?;
        let ready: Vec<(&str, &RtClient)> = self
            .ready_rts(session, &notifications)
            .into_iter()
            .filter(|(name, _)| only.map_or(true, |names| names.iter().any(|n| n == name)))
            .collect();
        if ready.len() < self.t_rt {
            return Err(VoterError::PinNotReady);
        }

        // Re-login for retrieval tokens (Sec. 5.3.1.4).
        let auth = self
            .dip_client
            .authenticate(&session.fiscal_id)
            .await
            .map_err(|_| VoterError::Unauthorized)?;
        let retrieval = self
            .er_client
            .retrieval_tokens(
                &session.registration_token,
                &auth.assertion,
                &auth.signature,
            )
            .await?;
        // Fetch this voter's AccShareBroadcast from the ready tellers
        // (Sec. 3.6.3, Deviation 5: shares travel over HTTPS from the RTs,
        // not the ER). The roll mints "a retrieval token for each RT"
        // (Sec. 5.3.1.4 step 8(c)), so each teller is handed one of its own
        // and it is never offered to another: whether the teller delivers,
        // refuses or answers "too early", only it can say whether the token
        // was spent, and a spent token given to the next teller would be
        // refused by the roll - one teller could strand the voter and an
        // honest teller would take the blame (Sec. 3.12, A2).
        let mut tokens = retrieval.retrieval_tokens.iter().cloned();
        let mut delivery: Vec<(&str, &RtClient, TokenValue)> = Vec::with_capacity(ready.len());
        let mut share_broadcasts = Vec::with_capacity(ready.len());
        let mut refused_shares: Vec<String> = Vec::new();
        let params = &self.election_context.pk.params;
        let mut delivered_shares: Vec<(&str, &RtClient, TokenValue, DeliveredShare)> =
            Vec::with_capacity(ready.len());
        for (name, rt) in ready {
            let Some(token) = tokens.next() else {
                break;
            };
            match rt.credentials_deliver(&token).await {
                Ok(delivered) => {
                    delivered_shares.push((name, rt, token, delivered));
                }
                Err(e) => {
                    // A teller that refuses, errors, or says its waiting
                    // period is not over delivers nothing: it is dropped, by
                    // name, and the retrieval goes on with the others
                    // (Sec. 3.12, A2). One teller must not be able to deny a
                    // voter their credential.
                    tracing::warn!("registration teller {name} did not deliver its share: {e}");
                }
            }
        }
        // Sec. 3.6.1 step 11: the app checks EACH share before it interpolates
        // anything. The commitments come from the tellers themselves, one set
        // each, so the app takes the set they AGREE on - under A2 at least
        // n_RT - t_RT + 1 of them are honest, which is a strict majority, and
        // a teller alone in its answer is in the minority by construction.
        // A share that does not fit is that teller's, and only that teller's:
        // it is dropped by NAME, where the subset search below could only say
        // that one of several tellers was wrong.
        // A set already established for this credential is the one that
        // counts: a later retrieval cannot be talked into another.
        let agreed = match session.share_commitments.clone() {
            Some(pinned) => Some(pinned),
            None => agreed_commitments(&delivered_shares, self.t_rt),
        };
        let Some(agreed) = agreed else {
            // No t_RT of them state the same thing. Refusing is the only
            // honest answer - going on unchecked would put the whole point of
            // Sec. 3.6.1 step 11 at the mercy of one dropped packet - and the
            // disagreement is reported by name.
            let who: Vec<&str> = delivered_shares.iter().map(|(name, ..)| *name).collect();
            tracing::warn!(
                "the registration tellers do not agree on this credential's commitments: {}",
                who.join(", ")
            );
            session.rebuilt_without_rts = who.iter().map(|n| n.to_string()).collect();
            return Err(VoterError::CommitmentsDisagree);
        };
        if session.share_commitments.is_none() {
            session.share_commitments = Some(agreed.clone());
        }
        for (name, rt, token, delivered) in delivered_shares {
            let fits = if delivered.share_commitments != agreed {
                Err("delivered commitments the other tellers do not share".to_string())
            } else {
                delivered
                    .share
                    .verify(&agreed, params)
                    .map_err(|e| e.to_string())
            };
            match fits {
                Ok(()) => {
                    share_broadcasts.push(delivered.share);
                    delivery.push((name, rt, token));
                }
                Err(e) => {
                    tracing::warn!("registration teller {name} delivered a bad share: {e}");
                    refused_shares.push(name.to_string());
                }
            }
        }
        if !refused_shares.is_empty() {
            // Named, not guessed: this is the accusation the subset rebuild
            // could never make.
            session.rebuilt_without_rts = refused_shares;
        }
        if delivery.len() < self.t_rt {
            // Announced but still refusing: tokens were minted for nothing.
            return Err(VoterError::TellersStillWaiting);
        }

        // Rebuild the credential builder + PIN locally (Sec. 3.6.3).
        let election_context = self.election_context.clone();
        let rt_pk = self.rt_pk.clone();
        let package = session.credential_package.clone();
        let mut build_rng = self.next_rng("voter-build-acc");
        let mut voter_rng = self.next_rng("voter-builder");
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
                let p1a = ThresholdRegistrationTeller::credential_p1a(
                    &election_context.pk,
                    &builder,
                    pin,
                );
                let a_point = builder.credential_point();
                (builder, pin, voter_builder, p1a, a_point)
            })
            .await
            .map_err(|e| VoterError::Protocol(e.to_string()))?;

        // DVNIZKP round 1 with the RTs holding our delivery sessions
        // (Sec. 3.6.2). The two rounds run over the SAME set of tellers as
        // the shares, so one that drops out here cannot simply be skipped:
        // the attempt is abandoned and the caller retries over a subset
        // without it, which is what keeps one teller from denying a voter
        // their credential (Sec. 6.3.1 A2).
        let mut round1 = Vec::with_capacity(delivery.len());
        for (name, rt, token) in &delivery {
            match rt.dvnizkp_round1(token, &a_point).await {
                Ok(broadcast) => round1.push(broadcast),
                Err(e) => {
                    tracing::warn!("registration teller {name} refused DVNIZKP round 1: {e}");
                    return Err(VoterError::CredentialRoundRefused);
                }
            }
        }
        let all_ids: Vec<usize> = round1.iter().map(|b| b.from_id).collect();

        // Combiner step: the voter derives the S1 challenge (Sec. 3.6.2).
        let dv_pk = voter_builder.voter_pk();
        let election_pk = self.election_context.pk.clone();
        let mut combine_rng = self.next_rng("dvnizkp-combine");
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
        for (name, rt, token) in &delivery {
            match rt.dvnizkp_round2(token, &c1, &all_ids).await {
                Ok(share) => z1_shares.push(share),
                Err(e) => {
                    tracing::warn!("registration teller {name} refused DVNIZKP round 2: {e}");
                    return Err(VoterError::CredentialRoundRefused);
                }
            }
        }

        // Assemble, finalize, and locally verify the PIN (Sec. 3.7.1).
        let voter = tokio::task::spawn_blocking(move || {
            let proof =
                ThresholdRegistrationTeller::dvnizkp_assemble(&round1, i0, c0, z0, c1, &z1_shares);
            let credential = credential_builder.build_with_dvnizkp(proof);
            let voter = voter_builder.finalize(credential);
            voter.verify_pin(pin).map(|_| voter)
        })
        .await
        .map_err(|e| VoterError::Protocol(e.to_string()))?
        .map_err(|e| {
            tracing::warn!("delivered credential failed the PIN check: {e:?}");
            VoterError::CredentialFailedPinCheck
        })?;

        let pin_code = PinCode::new(pin as u32)
            .map_err(|e| VoterError::Protocol(format!("library PIN out of range: {e}")))?;
        session.pin = Some(pin_code);
        session.voter = Some(voter);
        Ok(pin_code)
    }

    /// The passphrase-encrypted state blob for ER-side recovery (V8,
    /// Deviation 6).  The SIV encryption is deterministic, so the blob
    /// matches the on-disk state file byte-for-byte.
    /// The blob the roll keeps so a voter can set a new device up (V8,
    /// Deviation 6).
    ///
    /// It carries the CREDENTIAL, and no ballots. Sec. 3.6.1 lists exactly
    /// what the app stores encrypted - the keys, the public ACC, the masked
    /// private ACC, the passphrase - and no ballot, disclosure or receipt is
    /// among them; Sec. 3.7.4 step 8 has a new device "proceed as in the PIN
    /// re-sending procedure", inheriting nothing else.
    ///
    /// That is load-bearing, not housekeeping. A ballot carries BOTH
    /// cast-as-intended values and the device that built it pins ONE of each
    /// pair before anything leaves (Sec. 3.8.4 steps 10-11). Only that device
    /// holds the randomness that opens them, so only it can disclose, and it
    /// can disclose only what it pinned. Copy a held ballot to a second device
    /// and two devices can open the two different slots of one ballot -
    /// `sum - code`, the vote - each of them honestly, on a board that cannot
    /// take a leaf back.
    ///
    /// A device recovered after a cast therefore cannot confirm that ballot.
    /// That is the thesis's behaviour: the ballot was never confirmed, so it
    /// is never counted (Sec. 3.9 step 2), and the voter casts again.
    fn recovery_blob(
        &self,
        passphrase: &str,
        session: &VoterSession,
    ) -> Result<String, VoterError> {
        use base64::Engine as _;
        // The session handed in carries the ballots this device holds in
        // memory, so they are stripped here as well as from the state file:
        // nothing that leaves the device may carry a ballot.
        let mut portable = session.clone();
        portable.held = None;
        portable.held_by_pin.clear();
        portable.casts.clear();
        // A pending revocation id belongs to THIS device's request: a device
        // recovered from the blob that inherited it would have its own later
        // revocation taken for a retry of this one, and revoke nothing.
        portable.pending_revocation = None;
        let plaintext = serde_json::to_vec(&portable).map_err(VoterError::Json)?;
        let ciphertext = encrypt_state(&plaintext, passphrase)?;
        Ok(base64::engine::general_purpose::STANDARD.encode(ciphertext))
    }

    /// Upload the recovery blob for an already-registered device.
    async fn upload_recovery_blob(
        &self,
        passphrase: &str,
        session: &VoterSession,
    ) -> Result<(), VoterError> {
        let blob = self.recovery_blob(passphrase, session)?;
        self.er_client
            .upload_device_blob(&session.registration_token, &blob)
            .await?;
        Ok(())
    }

    /// Refresh the recovery blob after something that already succeeded.
    ///
    /// A device recovered from a stale blob knows nothing of a ballot this
    /// one cast: it could neither confirm it (Sec. 3.9 step 2 releases only
    /// confirmed ballots) nor show the voter the digest Sec. 3.8.5 item 1
    /// has them look up - and it would contradict, on the same account, what
    /// a coercer watched happen (Sec. 3.7.3). The upload cannot be allowed to
    /// undo the cast, so a roll that does not answer is reported and the
    /// answer to the voter stands.
    async fn refresh_recovery_blob(&self, passphrase: &str, session: &VoterSession) {
        if let Err(e) = self.upload_recovery_blob(passphrase, session).await {
            tracing::warn!("the recovery blob could not be refreshed: {e}");
        }
    }
}

// -- Handlers ----------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct LoginRequest {
    fiscal_id: String,
}

#[derive(Debug, Serialize)]
struct LoginResponse {
    vid: Vid,
}

/// The identifiers the electoral roll assigned to the registered voters, as
/// committed on the board at setup (`setup,ER,assigned_vids`).
async fn published_assigned_vids(state: &VoterState) -> Result<Vec<u64>, VoterError> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    let entries = state
        .wbb_client
        .board_entries()
        .await
        .map_err(|e| VoterError::Protocol(format!("WBB read failed: {e}")))?;
    entries
        .iter()
        .filter_map(|sequenced| {
            let data = B64.decode(sequenced.entry.get("data")?.as_str()?).ok()?;
            let parsed = voting::parse_wbb_data(&data)?;
            (parsed.entry_type == "assigned_vids")
                .then(|| parsed.decode_payload::<Vec<u64>>().ok())
                .flatten()
        })
        .next()
        .ok_or(VoterError::NoPublishedIdentifierRoot)
}

/// An identifier handed out as a voter's OWN must be one the roll assigned
/// at setup; one handed out as a SPARE must not be - otherwise it is another
/// voter's identifier under a different label.
fn identifier_matches_its_kind(
    kind: crate::protocol::merkle::LeafKind,
    vid: Vid,
    assigned: &[u64],
) -> bool {
    let is_assigned = assigned.contains(&vid.value());
    match kind {
        crate::protocol::merkle::LeafKind::Voter => is_assigned,
        crate::protocol::merkle::LeafKind::Spare => !is_assigned,
    }
}

/// The eligible identifiers the electoral roll published for the tally, if
/// it has published them yet.
async fn published_eligible_list(state: &VoterState) -> Result<Option<Vec<Vid>>, VoterError> {
    Ok(read_board_view(state).await?.eligible_list.clone())
}

/// The root of the identifier tree, as published on the bulletin board at
/// setup (`setup,ER,voter_id_merkle_root`).
async fn published_vid_root(state: &VoterState) -> Result<[u8; 32], VoterError> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    let entries = state
        .wbb_client
        .board_entries()
        .await
        .map_err(|e| VoterError::Protocol(format!("WBB read failed: {e}")))?;
    let root = entries
        .iter()
        .filter_map(|sequenced| {
            let data = B64.decode(sequenced.entry.get("data")?.as_str()?).ok()?;
            let parsed = voting::parse_wbb_data(&data)?;
            (parsed.entry_type == "voter_id_merkle_root").then_some(parsed.content)
        })
        .next()
        .ok_or(VoterError::NoPublishedIdentifierRoot)?;
    B64.decode(root)
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or(VoterError::NoPublishedIdentifierRoot)
}

/// V1: eID login via DIP, then ER `/login` (Sec. 5.3.1.1).
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
    // The identifier is the electoral roll's private assignment (Sec. 3.5.3),
    // so this app does not take it on the roll's word: it must be the one the
    // roll COMMITTED to for this voter, in the tree whose root is on the
    // board. Otherwise the roll could hand out an identifier nobody holds -
    // the ballot would be cast, confirmed and shown as counted, and then
    // dropped by the last filter with nothing to see.
    let root = published_vid_root(&state).await?;
    let assigned = published_assigned_vids(&state).await?;
    if !identifier_matches_its_kind(login.vid_kind, vid, &assigned) {
        return Err(VoterError::UnprovenIdentifier);
    }
    let holder = if login.vid_holder.is_empty() {
        req.fiscal_id.clone()
    } else {
        login.vid_holder.clone()
    };
    // Either the identifier committed for THIS voter, or - after a
    // revocation - a spare, whose committed holder is a random string. The
    // kind is part of the leaf, so one cannot be passed off as the other.
    let own_identifier =
        login.vid_kind == crate::protocol::merkle::LeafKind::Voter && holder == req.fiscal_id;
    let proved_spare = login.vid_kind == crate::protocol::merkle::LeafKind::Spare;
    if !(own_identifier || proved_spare)
        || !crate::protocol::merkle::verify_inclusion(
            &root,
            login.vid_kind,
            &holder,
            vid.value(),
            &login.vid_proof,
        )
    {
        return Err(VoterError::UnprovenIdentifier);
    }
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
    /// Set when the enrollment completed but its PIN request did not: the
    /// voter keeps the passphrase and asks again with a re-send.
    #[serde(skip_serializing_if = "Option::is_none")]
    warning: Option<String>,
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
/// to all RTs, NS registration (Sec. 3.6.1, Sec. 5.3.1.2/.3).
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

    // 6-word passphrase (V2) and the EdDSA app key (Sec. 3.13), both from the
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
    let mut session = VoterSession {
        fiscal_id: req.fiscal_id,
        vid: pending.vid,
        registration_token: pending.registration_token,
        credential_package: pending.credential_package,
        at_sk_seed: hex::encode(at_sk_seed),
        rid: None,
        ns_token: None,
        pin: None,
        voter: None,
        held: None,
        held_by_pin: Vec::new(),
        casts: Vec::new(),
        ruse_pin: None,
        share_commitments: None,
        rebuilt_without_rts: Vec::new(),
        pin_epoch: String::new(),
        ruse_voter: None,
        trusted: None,
        generation: 0,
        device_registered: false,
        pending_revocation: None,
        built: 0,
        ballots_base: None,
    };
    // The session is SAVED before anything leaves the device. Once the roll
    // holds the app key only this session can sign a rebind of it (Sec.
    // 3.7.4 step 7), so the key and the passphrase must already be the
    // voter's when the registration is sent: a lost ANSWER to it must not
    // leave a key at the roll that no device has. From here the passphrase
    // is SHOWN whatever happens next - a lost registration, PIN request or
    // blob upload costs the voter a retry, never the election (Sec. 3.6.1
    // steps 5-9 are one procedure, and Sec. 3.7.4 step 5's remedy for a
    // voter without the passphrase, a revocation, needs it on this device).
    state.save_session(&passphrase, &session).await?;
    // The passphrase is handed over NOW, before anything goes on the
    // network: a voter whose request is slow and who gives up waiting must
    // not leave behind a session under a passphrase they never saw. The
    // rest of the enrollment - the device registration (Sec. 5.3.1.1, run
    // first inside the PIN request, and again with the same key in any later
    // one until the roll has confirmed it) and the PIN request (Sec.
    // 5.3.1.2-3) - runs in the background under the device lock, so a
    // re-send waits for it. pkDV does not exist yet - the DV key pair is
    // generated by `VoterBuilder::new` at PIN retrieval (Sec. 3.6.1 ordering
    // note) - so the PoC registers the app key only. A request that fails
    // leaves none open, which the status screen names ("use Re-send"); a
    // blob the roll did not take is seeded by the next refresh.
    let vid = session.vid;
    state.enrolling.lock().await.insert(vid);
    {
        let state = state.clone();
        let passphrase = passphrase.clone();
        tokio::spawn(async move {
            let _device = state.device_lock_unchecked(&passphrase).await;
            if let Err(e) = state.run_pin_request(&mut session).await {
                tracing::warn!("enrolled, but the PIN request failed: {e}");
            }
            if let Err(e) = state.save_session(&passphrase, &session).await {
                tracing::error!("enrolled, but the session could not be saved: {e}");
            }
            state.refresh_recovery_blob(&passphrase, &session).await;
            state.enrolling.lock().await.remove(&session.vid);
        });
    }

    Ok(Json(EnrollResponse {
        vid,
        passphrase,
        warning: None,
    }))
}

#[derive(Deserialize)]
struct PassphraseRequest {
    passphrase: String,
}

/// A request about the ballot a PIN holds (Sec. 3.7.3: the ruse PIN has its
/// own). Without a PIN the cover story answers - see [`operative_held`].
#[derive(Deserialize)]
struct HeldBallotRequest {
    passphrase: String,
    #[serde(default)]
    pin: Option<PinCode>,
    /// Which of this PIN's ballots the screen is about. Omitted means the
    /// newest one awaiting confirmation.
    #[serde(default)]
    digest: Option<BallotDigest>,
}

impl std::fmt::Debug for HeldBallotRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeldBallotRequest")
            .field("passphrase", &"<redacted>")
            .field("pin", &"<redacted>")
            .finish()
    }
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
    /// Whether a PIN request is outstanding. False with no PIN set means the
    /// request has to be made again (a re-send), not waited for.
    pin_request_open: bool,
    /// Tellers left out of the subset the credential was rebuilt from
    /// (Sec. 3.6.1 step 11) - a retry took place, not proof of who was
    /// wrong: see the register.
    rebuilt_without_rts: Vec<String>,
    /// See `VoterSession::pin_epoch`.
    pin_epoch: String,
}

/// Poll enrollment status: the PIN is ready once >= t_RT notifications arrived
/// at the NS for the current rid (Sec. 5.3.1.4).
#[tracing::instrument(skip(state, req))]
async fn status_handler(
    Extension(state): Extension<Arc<VoterState>>,
    Json(req): Json<PassphraseRequest>,
) -> Result<Json<StatusResponse>, VoterError> {
    let session = state.session_for(&req.passphrase).await?;
    let pin_ready = match (&session.rid, session.pin) {
        (_, Some(_)) => true,
        (Some(rid), None) => {
            // Same rule as the retrieval itself: t_RT of the tellers this
            // voter's app asks have announced that their waiting period is over.
            let list = state.ns_client.notifications(session.vid, rid).await?;
            state.ready_rts(&session, &list).len() >= state.t_rt
        }
        (None, None) => false,
    };
    Ok(Json(StatusResponse {
        vid: session.vid,
        enrolled: true,
        pin_ready,
        pin_set: session.pin.is_some(),
        pin_request_open: session.rid.is_some()
            || state.enrolling.lock().await.contains(&session.vid),
        rebuilt_without_rts: session.rebuilt_without_rts.clone(),
        pin_epoch: session.pin_epoch.clone(),
    }))
}

#[derive(Serialize)]
struct PinResponse {
    vid: Vid,
    pin: PinCode,
    /// PrivatePINEmoji of the PIN shown: the voter memorises it and expects
    /// to see it again whenever they type this PIN.
    private_pin_emoji: Vec<String>,
}

impl std::fmt::Debug for PinResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PinResponse")
            .field("vid", &self.vid)
            .field("pin", &"<redacted>")
            .finish()
    }
}

/// V4: PIN delivery (Sec. 5.3.1.4/.5, Sec. 3.6.3, Sec. 3.6.2).
///
/// Re-login -> retrieval tokens -> `AccShareBroadcast` delivery from t_RT RTs ->
/// `voter_build_acc` -> `VoterBuilder::new` (DV keys) -> threshold DVNIZKP with
/// the same RTs -> `build_with_dvnizkp` -> `finalize` -> `verify_pin`.
#[tracing::instrument(skip(state, req))]
async fn pin_retrieve_handler(
    Extension(state): Extension<Arc<VoterState>>,
    Json(req): Json<PassphraseRequest>,
) -> Result<Json<PinResponse>, VoterError> {
    // One writer per device: see `VoterState::device_locks`.
    let _device = state.device_lock(&req.passphrase).await?;
    let mut session = state.session_for(&req.passphrase).await?;

    // Idempotent: a second retrieval re-displays the stored PIN - or the
    // ruse PIN while one is active (Sec. 3.7.3 cover story, see pin_show).
    if let Some(pin) = session.pin {
        let shown = session.ruse_pin.unwrap_or(pin);
        return Ok(Json(PinResponse {
            vid: session.vid,
            pin: shown,
            private_pin_emoji: private_pin_emoji(&session, shown).unwrap_or_default(),
        }));
    }

    let pin = state.run_retrieval(&mut session).await?;
    session.pin_epoch = new_pin_epoch(&state);
    state.save_session(&req.passphrase, &session).await?;
    // Refresh the recovery blob now that the credential exists (V8). The PIN
    // is on the device whatever the roll answers, so the answer says so.
    state.refresh_recovery_blob(&req.passphrase, &session).await;

    // The PIN this credential was delivered with (Sec. 3.6.3 step 5,
    // footnote 9: the first retrieval of a credential shows PIN^valid).
    Ok(Json(PinResponse {
        vid: session.vid,
        pin,
        private_pin_emoji: private_pin_emoji(&session, pin).unwrap_or_default(),
    }))
}

/// Show the stored PIN (post-retrieval display).
///
/// While a ruse PIN is active it is shown INSTEAD of the real one (Sec. 3.7.3
/// cover story): a coercer inspecting the device sees only the decoy; the
/// real PIN lives in the voter's memory and stays fully usable.
#[tracing::instrument(skip(state, req))]
async fn pin_show_handler(
    Extension(state): Extension<Arc<VoterState>>,
    Json(req): Json<PassphraseRequest>,
) -> Result<Json<PinResponse>, VoterError> {
    let session = state.session_for(&req.passphrase).await?;
    let pin = session
        .ruse_pin
        .or(session.pin)
        .ok_or(VoterError::PinNotRetrieved)?;
    Ok(Json(PinResponse {
        vid: session.vid,
        pin,
        private_pin_emoji: private_pin_emoji(&session, pin).unwrap_or_default(),
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
    /// PrivatePINEmoji of the PIN just typed (Sec. 3.7.1).
    private_pin_emoji: Vec<String>,
}

/// Whether `pin` is the one this app currently accepts (Sec. 3.7.1 steps
/// 3-5). Sec. 3.7.3 has a ruse request SUBSTITUTE the DVNIZKP, so after one
/// the decoy is the PIN in force and the valid PIN is not - which is the
/// cover story working, not a fault.
async fn pin_in_force(session: &VoterSession, pin: PinCode) -> Result<bool, VoterError> {
    let voter = session.voter.clone().ok_or(VoterError::PinNotRetrieved)?;
    let ruse = session.ruse_voter.clone();
    let pin = pin.value() as usize;
    tokio::task::spawn_blocking(move || match ruse {
        Some(ruse) => ruse.verify_pin(pin).is_ok(),
        None => voter.verify_pin(pin).is_ok(),
    })
    .await
    .map_err(|e| VoterError::Protocol(e.to_string()))
}

/// V5: local, unlimited PIN verification (Sec. 3.7.1) - no network round-trips.
#[tracing::instrument(skip(state, req))]
async fn pin_verify_handler(
    Extension(state): Extension<Arc<VoterState>>,
    Json(req): Json<VerifyPinRequest>,
) -> Result<Json<VerifyPinResponse>, VoterError> {
    let session = state.session_for(&req.passphrase).await?;
    // Shown whatever the outcome: it tells the voter WHICH PIN the device
    // processed, not whether that PIN is the valid one.
    let emoji = private_pin_emoji(&session, req.pin).unwrap_or_default();
    // Sec. 3.7.3: a ruse request SUBSTITUTES the DVNIZKP, so once a ruse PIN is
    // active only the ruse PIN verifies locally - "PIN^valid will no longer
    // verify ... Vote App will consider PIN^ruse as correct".  The valid PIN
    // keeps its ability to cast a counted vote (`vote_handler` dispatch).
    let valid = pin_in_force(&session, req.pin).await?;
    Ok(Json(VerifyPinResponse {
        valid,
        private_pin_emoji: emoji,
    }))
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

#[derive(Debug, Serialize)]
struct ResultsResponse {
    phase: String,
    /// Final counts, present once a `tally_result` entry is published.
    counts: Option<crate::protocol::tally::TallyCounts>,
    /// WBB leaf indexes of the `tally_result`/`tally_proof` entries (V15
    /// links: the voter can inspect them on the public bulletin board).
    tally_entries: Vec<i64>,
}

/// V15: results viewing - final counts + links to the WBB tally entries.
/// Results are public, so no passphrase is required.
#[tracing::instrument(skip(state))]
async fn results_handler(
    Extension(state): Extension<Arc<VoterState>>,
) -> Result<Json<ResultsResponse>, VoterError> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;

    let phase = state
        .wbb_client
        .phase()
        .await
        .map_err(|e| VoterError::Protocol(format!("WBB phase query failed: {e}")))?;
    let entries = state
        .wbb_client
        .board_entries()
        .await
        .map_err(|e| VoterError::Protocol(format!("WBB entries query failed: {e}")))?;

    let mut counts = None;
    let mut tally_entries = Vec::new();
    for sequenced in entries.iter() {
        let Some(parsed) = sequenced
            .entry
            .get("data")
            .and_then(|v| v.as_str())
            .and_then(|b64| B64.decode(b64).ok())
            .and_then(|data| voting::parse_wbb_data(&data))
        else {
            continue;
        };
        match parsed.entry_type.as_str() {
            "tally_result" => {
                if !voting::signed_by_tellers(&sequenced.entry, voting::RESULT_SIGNERS) {
                    continue;
                }
                tally_entries.push(sequenced.leaf_index);
                let published: Option<crate::protocol::tally::TallyCounts> = B64
                    .decode(parsed.content)
                    .ok()
                    .and_then(|json| serde_json::from_slice(&json).ok());
                match (&counts, published) {
                    (None, published) => counts = published,
                    // Two different results signed by the tellers: this app
                    // shows neither rather than picking one.
                    (Some(first), Some(second)) if *first != second => {
                        return Err(VoterError::ConflictingResults)
                    }
                    _ => {}
                }
            }
            "tally_proof" => tally_entries.push(sequenced.leaf_index),
            _ => {}
        }
    }
    Ok(Json(ResultsResponse {
        phase,
        counts,
        tally_entries,
    }))
}

#[derive(Deserialize)]
struct VoteRequest {
    passphrase: String,
    option: ReferendumOption,
    /// The PIN the voter types.  Deliberately NOT checked against the stored
    /// credential here: a wrong (or ruse) PIN builds a ballot that verifies
    /// at the BB but is filtered at tally time (Sec. 3.8.2 coercion resistance).
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
    /// A ballot of this PIN that is CAST and still unconfirmed, if any.
    /// Sec. 3.8.4 steps 7-17 are a sequence: this new ballot does not replace
    /// that one, which still has to be confirmed or it is dropped at
    /// Sec. 3.9 step 2, and the confirmation screens go on answering for it.
    #[serde(skip_serializing_if = "Option::is_none")]
    awaiting_confirmation: Option<BallotDigest>,
    emoji: Vec<String>,
    /// PrivatePINEmoji of the PIN typed for this ballot (Sec. 3.8.2 step 14).
    private_pin_emoji: Vec<String>,
    /// PublicPINEmoji of this ballot: the ballot boxes publish the same one.
    public_pin_emoji: Vec<String>,
}

/// V11: build the ballot + CAI disclosure and hold it for casting (Sec. 3.8.2).
#[tracing::instrument(skip(state, req))]
async fn vote_handler(
    Extension(state): Extension<Arc<VoterState>>,
    Json(req): Json<VoteRequest>,
) -> Result<Json<VoteResponse>, VoterError> {
    // One writer per device: see `VoterState::device_locks`.
    let _device = state.device_lock(&req.passphrase).await?;
    let mut session = state.session_for(&req.passphrase).await?;
    // V7 dispatch: the ruse PIN routes to the simulated voter whose forged DV
    // proof verifies locally but whose ballots are filtered at tally
    // (Sec. 3.7.3).  Any other PIN uses the real credential.
    let with_ruse = session.ruse_pin == Some(req.pin);
    let voter = if with_ruse {
        session
            .ruse_voter
            .clone()
            .ok_or(VoterError::PinNotRetrieved)?
    } else {
        session.voter.clone().ok_or(VoterError::PinNotRetrieved)?
    };

    let params = state.election_context.choice.clone();
    let mut vote_rng = state.next_rng("vote");
    let pin = req.pin.value() as usize;
    let option = req.option;
    let (ballot, disclosure, control) = tokio::task::spawn_blocking(move || {
        let choice = referendum_choice(option, &params)?;
        let builder = evoting::api::client::BallotBuilder::new(choice);
        // The slot flags only select which opening the library hands back:
        // the ballot holds both encrypted values of each level either way.
        // Building twice from the same RNG state yields the SAME ballot with
        // the openings of all code slots, then of all sum slots, so the
        // voter can choose after casting (Sec. 3.8.4 steps 9-11).
        let mut replay_rng = vote_rng.clone();
        let (ballot, all_code, control) =
            voter.vote_with_cai_values(&builder, pin, true, true, &mut vote_rng);
        let (replayed, all_sum) =
            voter.vote_with_disclosure(&builder, pin, false, false, &mut replay_rng);
        // Guard the assumption: if the library ever made the ballot depend
        // on the flags, the second set of openings would not fit the ballot.
        if ballot_digest(&ballot)? != ballot_digest(&replayed)? {
            return Err(crate::protocol::voting::VotingError::Crypto(
                "ballot depends on the cast-as-intended slot flags".into(),
            ));
        }
        Ok::<_, crate::protocol::voting::VotingError>((
            ballot,
            HeldDisclosure::Open { all_code, all_sum },
            control,
        ))
    })
    .await
    .map_err(|e| VoterError::Protocol(e.to_string()))?
    .map_err(|e| VoterError::Protocol(e.to_string()))?;

    let digest = ballot_digest(&ballot).map_err(|e| VoterError::Protocol(e.to_string()))?;
    let emoji: Vec<String> = ballot.to_emoji().iter().map(|s| s.to_string()).collect();
    let public_pin_emoji: Vec<String> = ballot
        .public_pin_emoji()
        .iter()
        .map(|s| s.to_string())
        .collect();
    let typed_pin_emoji = private_pin_emoji(&session, req.pin).unwrap_or_default();
    let rndcomm: [u8; 32] = {
        let mut rng = state.next_rng("rndcomm");
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        bytes
    };

    // Each PIN has its own held ballot: a ruse one built under the ruse PIN
    // stays exactly where the coercer left it, whatever the voter does with
    // their real PIN in between (Sec. 3.7.3 across a surveillance gap).
    let vote = HeldVote {
        ballot,
        disclosure,
        control,
        digest,
        rndcomm: hex::encode(rndcomm),
        emoji: emoji.clone(),
        public_pin_emoji: public_pin_emoji.clone(),
        ruse: with_ruse,
        pin: Some(req.pin),
        built: {
            session.built += 1;
            session.built
        },
    };
    // A ballot replaces only the one the SAME PIN built, and only while that
    // one is still unsent: a vote under one PIN never disturbs what another
    // PIN holds, so nobody can wipe a voter's cast-and-unconfirmed ballot by
    // voting with a PIN of their own - and a ballot already CAST survives
    // this too. Sec. 3.8.4 steps 7-17 are a sequence the voter is in the
    // middle of once the board carries the digest: dropping its openings here
    // would strand it, unconfirmable for ever, and Sec. 3.9 step 2 would
    // discard it with nothing on the board to tell that apart from a voter
    // who chose not to confirm.
    let awaiting: Vec<BallotDigest> = session
        .held_by_pin
        .iter()
        .filter(|v| {
            v.pin == Some(req.pin)
                && session
                    .casts
                    .iter()
                    .any(|c| c.digest == v.digest && c.pin == v.pin && c.confirmed_at_ms.is_none())
        })
        .map(|v| v.digest)
        .collect();
    session
        .held_by_pin
        .retain(|v| v.pin != Some(req.pin) || awaiting.contains(&v.digest));
    session.held_by_pin.push(vote.clone());
    // Kept for the screens that know only one ballot (and for state written
    // by an older build): the most recent ballot of the voter's own PIN.
    if !with_ruse {
        session.held = Some(vote);
    }
    state.save_session(&req.passphrase, &session).await?;

    Ok(Json(VoteResponse {
        digest,
        awaiting_confirmation: awaiting.last().copied(),
        emoji,
        private_pin_emoji: typed_pin_emoji,
        public_pin_emoji,
    }))
}

#[derive(Debug, Serialize)]
struct CastResultResponse {
    digest: BallotDigest,
    receipts: Vec<Receipt>,
    /// Trusted boxes that did not accept the ballot (refused, lied or did
    /// not answer). The cast stands on the others; what counts is decided
    /// from the board.
    refused_bb_ids: Vec<u64>,
    emoji: Vec<String>,
}

/// V12: cast the held ballot with CAT tokens to every trusted BB (Sec. 5.3.1.6,
/// Sec. 3.8.4 steps 1-7).
#[tracing::instrument(skip(state, req))]
async fn cast_handler(
    Extension(state): Extension<Arc<VoterState>>,
    Json(req): Json<HeldBallotRequest>,
) -> Result<Json<CastResultResponse>, VoterError> {
    // One writer per device: see `VoterState::device_locks`.
    let _device = state.device_lock(&req.passphrase).await?;
    let mut session = state.session_for(&req.passphrase).await?;
    let pin = req.pin.ok_or(VoterError::PinRequired)?;
    // The ballot the screen shows, when the screen names it: a cast must
    // never send another ballot than the one the voter is looking at.
    let held = match req.digest {
        Some(wanted) => session
            .held_by_pin
            .iter()
            .find(|v| v.pin == Some(pin) && v.digest == wanted)
            .cloned()
            .ok_or(VoterError::NoHeldBallot)?,
        None => operative_held(&session, pin)
            .cloned()
            .ok_or(VoterError::NoHeldBallot)?,
    };

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
        .await
        .map_err(|e| match e {
            crate::clients::er::ErError::Http(StatusCode::TOO_MANY_REQUESTS, _) => {
                VoterError::CastTooSoon
            }
            crate::clients::er::ErError::Http(StatusCode::FORBIDDEN, _) => {
                VoterError::CastLimitReached
            }
            other => VoterError::Er(other),
        })?;
    // Cast to every trusted BB (V10 default: all), each with the token the ER
    // issued FOR THAT ballot box (Sec. 5.3.1.6 steps 4-5).
    // EVERY trusted box is asked, whatever the others answer: one box that
    // refuses, lies or stalls must not keep the ballot from the honest one
    // (Sec. 5.3.1.6 step 5 sends to each trusted box; A9 relies on one). A
    // box that did not accept is named in the answer; the cast fails only
    // when NO box accepted.
    let trusted = state.trusted_bbs_with_ids(&session);
    let mut receipts = Vec::with_capacity(trusted.len());
    let mut refusals: Vec<(u64, VoterError)> = Vec::new();
    for (bb_id, bb) in trusted {
        let Some(token) = tokens.casting_tokens.iter().find(|t| t.bb_id == bb_id) else {
            refusals.push((
                bb_id,
                VoterError::Protocol(format!("the ER issued no casting token for BB {bb_id}")),
            ));
            continue;
        };
        match bb.cast(&held.ballot, &rndcomm, token).await {
            Ok(response) => receipts.push(response.receipt),
            Err(crate::clients::bb::BbError::Http(StatusCode::UNAUTHORIZED, _)) => {
                refusals.push((bb_id, VoterError::CastingTokenRefused));
            }
            Err(other) => refusals.push((bb_id, VoterError::Bb(other))),
        }
    }
    if receipts.is_empty() {
        return Err(refusals
            .into_iter()
            .next()
            .map(|(_, e)| e)
            .unwrap_or(VoterError::BallotBoxSilent));
    }
    let refused_bb_ids: Vec<u64> = refusals.iter().map(|(bb, _)| *bb).collect();
    for (bb_id, e) in &refusals {
        tracing::warn!(bb_id, "ballot box did not accept the cast: {e}");
    }

    // The same ballot cast again (a lost answer) is one cast, not two -
    // wherever its record sits. Comparing only with the most recent one would
    // leave two records for one ballot as soon as another PIN cast something
    // in between, and the screens would then disagree: confirmation marks the
    // first record, the status screen reads the last (Sec. 3.8.5 item 1 has
    // them tell the voter one thing). The receipts of the retry are kept: a
    // box that answered this time and not the last is in them.
    match session
        .casts
        .iter_mut()
        .rev()
        .find(|c| c.digest == held.digest && c.pin == held.pin)
    {
        Some(existing) => {
            for receipt in &receipts {
                if !existing.receipts.iter().any(|r| r == receipt) {
                    existing.receipts.push(*receipt);
                }
            }
        }
        None => session.casts.push(CastRecord {
            digest: held.digest,
            receipts: receipts.clone(),
            emoji: held.emoji.clone(),
            confirmed_at_ms: None,
            ruse: held.ruse,
            pin: held.pin,
            disclosed: None,
            built: held.built,
        }),
    }
    state.save_session(&req.passphrase, &session).await?;
    state.refresh_recovery_blob(&req.passphrase, &session).await;

    Ok(Json(CastResultResponse {
        digest: held.digest,
        receipts,
        refused_bb_ids,
        emoji: held.emoji,
    }))
}

#[derive(Debug, Serialize)]
struct BallotStatusResponse {
    digest: BallotDigest,
    /// BB ids whose `ballot_digest` entry is on the WBB.
    published_bb_ids: Vec<u64>,
    /// True when >= 2 BBs published the digest (no bot, Sec. 3.8.5).
    no_bot: bool,
    /// BB ids whose confirmation of this ballot is on the WBB.
    confirmed_bb_ids: Vec<u64>,
    /// Those that published BOTH the digest and a confirmation.
    counting_bb_ids: Vec<u64>,
    /// True when at least one box published the digest and at least one a
    /// confirmation - what the tally counts on (Sec. 3.10 1(c)-(d)). Read
    /// from the board.
    will_be_counted: bool,
    /// Whether the electoral roll's published eligible list names this
    /// voter's identifier; `None` while no list is published (it appears at
    /// tally). The credential mix is built from that list, so an identifier
    /// left out of it loses its holder's vote at the very last filter with
    /// nothing else to see - this is the one place a voter can notice.
    on_eligible_list: Option<bool>,
    confirmed_at_ms: Option<u64>,
}

/// V12 step 7 / V14: check the WBB publication of the last cast ballot.
#[tracing::instrument(skip(state, req))]
async fn ballot_status_handler(
    Extension(state): Extension<Arc<VoterState>>,
    Json(req): Json<HeldBallotRequest>,
) -> Result<Json<BallotStatusResponse>, VoterError> {
    let session = state.session_for(&req.passphrase).await?;
    // A PIN answers for its own casts and for no others: whoever types a PIN
    // sees the last ballot THAT PIN cast. The PIN is required here for the
    // same reason as on every other ballot screen (`operative_held`): the
    // passphrase alone must not tell a coercer that a ballot was cast, nor
    // show them its place on the board.
    let pin = req.pin.ok_or(VoterError::PinRequired)?;
    let record = session
        .casts
        .iter()
        .rev()
        .find(|c| c.pin == Some(pin))
        .ok_or(VoterError::NoHeldBallot)?;
    let board = digest_on_board(&state, record.digest).await?;
    let on_eligible_list = published_eligible_list(&state)
        .await?
        .map(|list| list.contains(&session.vid));
    let mut published_bb_ids: Vec<u64> = board.publications.iter().map(|p| p.bb_id).collect();
    published_bb_ids.dedup();
    let mut confirmed_bb_ids: Vec<u64> = board.confirmations.iter().map(|c| c.bb_id).collect();
    confirmed_bb_ids.dedup();
    // A ballot counts on a disclosure that OPENS on it (Sec. 3.10 1(d)), and
    // the only disclosure this voter made is the one this device sealed. A
    // ballot the device never confirmed is never "counted", whatever the
    // board carries for it - a box may publish a confirmation of its own - and
    // a confirmed one counts only while the board shows THAT disclosure.
    let will_be_counted = match (&record.confirmed_at_ms, &record.disclosed) {
        (Some(_), Some(sealed)) => {
            !published_bb_ids.is_empty()
                && board.confirmations.iter().any(|c| {
                    c.opened == sealed.opened && c.disclosure.as_ref() == Some(&sealed.disclosure)
                })
        }
        _ => false,
    };
    Ok(Json(BallotStatusResponse {
        digest: record.digest,
        no_bot: published_bb_ids.len() >= voting::NO_BOT_MIN_BBS,
        counting_bb_ids: board.counting_bb_ids,
        published_bb_ids,
        confirmed_bb_ids,
        will_be_counted,
        on_eligible_list,
        confirmed_at_ms: record.confirmed_at_ms,
    }))
}

/// One ballot box's publication of a digest, as found on the bulletin board.
#[derive(Debug, Clone, Serialize)]
struct DigestPublication {
    bb_id: u64,
    leaf_index: i64,
    /// When the bulletin board sequenced the entry.
    board_timestamp: i64,
    /// When the ballot box says it received the ballot.
    received_at_unix_ms: u64,
    emoji: Vec<String>,
    public_pin_emoji: Vec<String>,
}

/// One ballot box's published cast-as-intended proof for a digest.
#[derive(Debug, Clone, Serialize)]
struct DigestConfirmation {
    bb_id: u64,
    leaf_index: i64,
    confirmed_at_ms: u64,
    opened: evoting::api::prelude::OpenedCai,
    /// The disclosure the box published. A box can publish the values this
    /// app expects next to SOMEBODY ELSE'S disclosure: the values would look
    /// right here and the tally would discard the ballot (it re-opens the
    /// disclosure on the released ballot). The app compares the disclosure
    /// too, so the voter learns it at once.
    #[serde(skip)]
    disclosure: Option<evoting::api::prelude::DiscloseCAI<G>>,
}

#[derive(Debug, Serialize)]
struct VerifyResponse {
    digest: BallotDigest,
    publications: Vec<DigestPublication>,
    /// True when at least 2 ballot boxes published the digest.
    enough_ballot_boxes: bool,
    confirmations: Vec<DigestConfirmation>,
    /// The ballot boxes that published BOTH the digest and a confirmation.
    counting_bb_ids: Vec<u64>,
    /// True when at least one box published the digest and at least one a
    /// confirmation: what the tally counts on (Sec. 3.10 1(c)-(d)), the
    /// disclosure's validity being checked at tally against the released
    /// ballot.
    confirmed: bool,
}

/// V14 (Sec. 3.8.5): everything the bulletin board shows about ANY ballot
/// digest - who published it and when, the emoji receipt, and the opened
/// cast-as-intended values. Public information: no passphrase, and it works
/// for a digest this device never produced (e.g. copied from another device).
#[tracing::instrument(skip(state))]
async fn verify_digest_handler(
    Extension(state): Extension<Arc<VoterState>>,
    axum::extract::Path(digest): axum::extract::Path<String>,
) -> Result<Json<VerifyResponse>, VoterError> {
    let digest: BallotDigest = digest.parse().map_err(|_| VoterError::BadDigest)?;
    Ok(Json(digest_on_board(&state, digest).await?))
}

/// Everything the bulletin board holds about one digest. What counts is
/// decided from the board alone - never from a ballot box's HTTP answer.
async fn digest_on_board(
    state: &VoterState,
    digest: BallotDigest,
) -> Result<VerifyResponse, VoterError> {
    let (mut publications, mut confirmations) = {
        let view = read_board_view(state).await?;
        view.by_digest
            .get(&digest)
            .map(|on_board| {
                (
                    on_board.publications.clone(),
                    on_board.confirmations.clone(),
                )
            })
            .unwrap_or_default()
    };
    publications.sort_by_key(|p| p.bb_id);
    confirmations.sort_by_key(|c| c.bb_id);
    let distinct: std::collections::BTreeSet<u64> = publications.iter().map(|p| p.bb_id).collect();
    let counting_bb_ids = voting::counting_ballot_boxes(
        &publications.iter().map(|p| p.bb_id).collect::<Vec<_>>(),
        &confirmations.iter().map(|c| c.bb_id).collect::<Vec<_>>(),
    );
    Ok(VerifyResponse {
        digest,
        enough_ballot_boxes: distinct.len() >= voting::NO_BOT_MIN_BBS,
        // One box publishing the digest and one publishing a confirmation
        // is what the tally counts on (Sec. 3.10 1(c)-(d); one honest box,
        // A9). Fewer than two publishers is the bottom symbol: a warning.
        confirmed: !publications.is_empty() && !confirmations.is_empty(),
        counting_bb_ids,
        publications,
        confirmations,
    })
}

/// What one digest has on the board: each box's publication of it and each
/// box's cast-as-intended proof for it, under that box's own signature, in
/// board order.
#[derive(Default)]
struct DigestOnBoard {
    publications: Vec<DigestPublication>,
    confirmations: Vec<DigestConfirmation>,
}

/// The board as the voting path reads it, kept up to date entry by entry:
/// each reading parses only what was written since the last one (Table 6.1,
/// A9: one box flooding the board must not make every check of every voter
/// as slow as the board is long). Folded in board order, it answers what a
/// parse of a whole reading answers.
#[derive(Default)]
struct BoardView {
    /// Leaves below this one are folded in.
    next_leaf: i64,
    /// The ballot entries, by the tally's own rule (`board_ballots`).
    ballots: crate::protocol::tally::BoardBallotsFold,
    by_digest: HashMap<BallotDigest, DigestOnBoard>,
    /// The first `eligible_vids` list the roll published, once it has.
    eligible_list: Option<Vec<Vid>>,
}

impl BoardView {
    fn add(&mut self, sequenced: &crate::clients::wbb::SequencedEntry) {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine as _;
        self.ballots.add(&sequenced.entry);
        let Some(parsed) = sequenced
            .entry
            .get("data")
            .and_then(|v| v.as_str())
            .and_then(|b64| B64.decode(b64).ok())
            .and_then(|data| voting::parse_wbb_data(&data))
        else {
            return;
        };
        match parsed.entry_type.as_str() {
            "ballot_digest" => {
                if let Ok(entry) = parsed.decode_payload::<BallotDigestEntry>() {
                    if voting::signed_by_ballot_box(&sequenced.entry, entry.receipt.bb_id) {
                        self.by_digest
                            .entry(entry.digest)
                            .or_default()
                            .publications
                            .push(DigestPublication {
                                bb_id: entry.receipt.bb_id,
                                leaf_index: sequenced.leaf_index,
                                board_timestamp: sequenced.timestamp,
                                received_at_unix_ms: entry.receipt.received_at_unix_ms,
                                emoji: entry.emoji,
                                public_pin_emoji: entry.public_pin_emoji,
                            });
                    }
                }
            }
            "cast_intended_proof" => {
                if let Ok(entry) = parsed.decode_payload::<voting::CaiEntry>() {
                    if voting::signed_by_ballot_box(&sequenced.entry, entry.bb_id) {
                        self.by_digest
                            .entry(entry.digest)
                            .or_default()
                            .confirmations
                            .push(DigestConfirmation {
                                bb_id: entry.bb_id,
                                leaf_index: sequenced.leaf_index,
                                confirmed_at_ms: entry.confirmed_at_ms,
                                opened: entry.opened,
                                disclosure: Some(entry.disclosure),
                            });
                    }
                }
            }
            "eligible_vids" if self.eligible_list.is_none() => {
                self.eligible_list = parsed.decode_payload::<Vec<Vid>>().ok();
            }
            _ => {}
        }
    }
}

/// ONE reading of the board: the entries written since the last reading,
/// folded into the view. A failed read is an error, never an empty answer.
async fn read_board_view(
    state: &VoterState,
) -> Result<tokio::sync::MutexGuard<'_, BoardView>, VoterError> {
    let mut view = state.board_view.lock().await;
    let written_since = state
        .wbb_client
        .board_entries_from(view.next_leaf)
        .await
        .map_err(|e| VoterError::Protocol(format!("WBB read failed: {e}")))?;
    for sequenced in &written_since {
        view.add(sequenced);
    }
    if let Some(last) = written_since.last() {
        view.next_leaf = last.leaf_index + 1;
    }
    Ok(view)
}

/// The control values of the held ballot. No `Debug`: they reveal the vote.
#[derive(Serialize)]
struct ControlValuesResponse {
    digest: BallotDigest,
    /// Every ballot of this PIN that is cast and still awaiting confirmation,
    /// oldest first. More than one is ordinary, and each still has to be
    /// confirmed or Sec. 3.9 step 2 drops it, so none is hidden.
    awaiting_confirmation: Vec<BallotDigest>,
    /// List level: control code and control sum (= code + chosen index, mod 100).
    l1_code: u32,
    l1_sum: u32,
    /// Candidate level (trivial in a referendum).
    l2_code: u32,
    l2_sum: u32,
}

/// Sec. 3.8.4 step 9: show the voter the control code and sum of each level.
/// Refused until the ballot has been cast: showing them earlier would let a
/// malicious device learn nothing new, but the protocol order is what makes
/// the later comparison meaningful, so the app enforces it.
#[tracing::instrument(skip(state, req))]
async fn control_values_handler(
    Extension(state): Extension<Arc<VoterState>>,
    Json(req): Json<HeldBallotRequest>,
) -> Result<Json<ControlValuesResponse>, VoterError> {
    let session = state.session_for(&req.passphrase).await?;
    let pin = req.pin.ok_or(VoterError::PinRequired)?;
    // The same ballot the confirmation will act on, so the values the voter
    // checks at Sec. 3.8.4 step 9 belong to the ballot opened at step 11.
    let held = match held_to_confirm(&session, pin, req.digest) {
        Some(held) => held,
        None => {
            return Err(match req.digest {
                Some(digest) => cannot_confirm(&session, pin, digest),
                None => nothing_to_confirm(&session, pin),
            })
        }
    };
    let awaiting: Vec<BallotDigest> = session
        .awaiting_confirmation(pin)
        .map(|held| held.digest)
        .collect();
    Ok(Json(ControlValuesResponse {
        digest: held.digest,
        awaiting_confirmation: awaiting,
        l1_code: held.control.l1_code,
        l1_sum: held.control.l1_sum,
        l2_code: held.control.l2_code,
        l2_sum: held.control.l2_sum,
    }))
}

#[derive(Deserialize)]
struct ConfirmRequest {
    passphrase: String,
    /// Which held ballot to confirm (Sec. 3.7.3). Required: see
    /// `operative_held`.
    #[serde(default)]
    pin: Option<PinCode>,
    /// The ballot the screen showed the control values of (Sec. 3.8.4 steps
    /// 9-11). REQUIRED, and it says WHICH ballot is confirmed: the voter
    /// checks the sums of one ballot and then chooses which of its values is
    /// opened, so a confirmation that does not name a ballot could open a
    /// value of one nobody looked at - and a PIN may hold more than one
    /// ballot awaiting confirmation.
    digest: BallotDigest,
    /// The voter's post-cast choice for the list-level value (Sec. 3.8.4
    /// steps 10-11). Required: step 10 has V "perform the two random
    /// selections, preferably tossing a coin twice", and step 11 calls
    /// `b_Ls`, `b_Ca` "the random choices made by V". A choice this device
    /// made would be one it could have worked around when it sealed the
    /// ballot. It may be omitted only to REPEAT a choice already pinned to
    /// this ballot, which is the retry path.
    #[serde(default)]
    l1: Option<CaiSlot>,
    /// The candidate-level value. In a REFERENDUM this choice protects
    /// nothing: every option has exactly one candidate (Sec. 3.11), so
    /// `Ca = 0` for every ballot ever built here and both candidate values
    /// are the same number - opening either, or both, tells a reader what
    /// they already knew. So the voter is asked for ONE selection, as in the
    /// referendum variant of Sec. 3.11, and this level opens a fixed, public
    /// slot unless the caller states one. A device cannot exploit knowing it:
    /// the check that slot performs is `s_Ca + Ca = s_Ca`, which every honest
    /// referendum ballot satisfies identically.
    #[serde(default)]
    l2: Option<CaiSlot>,
}

/// The candidate-level slot a referendum opens when the voter is not asked
/// (see `ConfirmRequest::l2`).
const REFERENDUM_L2: CaiSlot = CaiSlot::Code;

impl std::fmt::Debug for ConfirmRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfirmRequest")
            .field("passphrase", &"<redacted>")
            .field("l1", &self.l1)
            .field("l2", &self.l2)
            .finish()
    }
}

#[derive(Debug, Serialize)]
struct ConfirmResponse {
    digest: BallotDigest,
    confirmed_at_ms: u64,
    /// Which value was opened for each level.
    l1: CaiSlot,
    l2: CaiSlot,
    /// The opened values as published by the ballot boxes - checked by the
    /// app against its own control values before answering.
    l1_value: u32,
    l2_value: u32,
    /// Read back from the BOARD after the ballot boxes answered: the boxes
    /// whose digest entry and confirmation are both published, and whether
    /// they are enough for the ballot to be counted.
    counting_bb_ids: Vec<u64>,
    will_be_counted: bool,
    /// Boxes that published, or answered with, values for this ballot other
    /// than the ones this app sealed. Another box published the right ones,
    /// so the ballot stands - but these boxes lied, and the board carries
    /// the evidence.
    lying_boxes: Vec<u64>,
    /// Boxes that did not answer the confirmation at all.
    silent_boxes: Vec<u64>,
    /// Boxes that REFUSED the confirmation, with what they said. A refusal is
    /// not silence - no retry changes it - and it is not a lie about the
    /// values either, so it is reported on its own. One box refusing while
    /// another publishes is exactly what A9 allows, and the voter is the only
    /// party who can act on it in time (Sec. 3.8.4 step 17).
    refused_boxes: Vec<RefusedBox>,
}

/// How many times a box that answers "confirmation in progress" (409) is
/// asked again, half a second apart, before it is counted as silent.
const CAI_IN_PROGRESS_RETRIES: usize = 6;

#[derive(Debug, Serialize)]
struct RefusedBox {
    bb_id: u64,
    reason: String,
}

/// V13: the voter chooses, AFTER casting, which cast-as-intended value to
/// open; the app sends only that opening to the BBs (Sec. 3.8.4 steps 8-17).
#[tracing::instrument(skip(state, req))]
async fn confirm_handler(
    Extension(state): Extension<Arc<VoterState>>,
    Json(req): Json<ConfirmRequest>,
) -> Result<Json<ConfirmResponse>, VoterError> {
    // One writer per device: see `VoterState::device_locks`. Pinning the
    // cast-as-intended choice is a read-then-write over the stored session
    // (Sec. 3.8.4 steps 10-11); two confirmations racing it would each pin a
    // different slot and send their own disclosure - the two together being
    // the vote. The DEVICE's lock makes the second see the first's pin and be
    // refused by `choose`. Nothing wider is taken: a box that stalls one
    // voter's confirmation must not hold any other voter's (A9).
    let _device = state.device_lock(&req.passphrase).await?;
    let mut session = state.session_for(&req.passphrase).await?;
    let pin = req.pin.ok_or(VoterError::PinRequired)?;
    let held = match held_to_confirm(&session, pin, Some(req.digest)) {
        Some(held) => held,
        None => return Err(cannot_confirm(&session, pin, req.digest)),
    };
    let mut held = held.clone();

    // Both choices are the VOTER's (Sec. 3.8.4 steps 10-11). A choice
    // already pinned to this ballot wins - that is the retry path, and it can
    // only ever resend the same disclosure - but nothing here invents one.
    let pinned = held.disclosure.chosen();
    let (l1, l2) = match (pinned, req.l1, req.l2) {
        // A retry that restates no choice repeats the pinned one.
        (Some((l1, l2)), None, None) => (l1, l2),
        // A restated choice is checked against the pin by `choose` below,
        // which refuses a DIFFERENT one: both slots together are the vote.
        (_, Some(l1), l2) => (l1, l2.unwrap_or(REFERENDUM_L2)),
        _ => return Err(VoterError::CaiChoiceMissing),
    };

    // Sec. 3.9 step 10 counts the voter's most recent ballot, and the tally
    // reads "most recent" from the BOARD: the ballot first published last.
    // The voter's intent is the order they BUILT their ballots in. The two
    // must agree for the ballot counted to be the one the voter meant, so a
    // ballot is never confirmed once a NEWER ballot of the same PIN is on the
    // board: it is superseded, and a box that held it back could otherwise
    // publish it after the newer one and have the older choice counted.
    // Read from one reading of the board, by the tally's own rule - and
    // the same reading must show THIS ballot published: read apart, a box
    // could publish the newer ballot and then this one in between, and the
    // older choice would be confirmed as the most recent.
    {
        let view = read_board_view(&state).await?;
        let on_board = view.ballots.publishers();
        let newer_on_board = session
            .held_by_pin
            .iter()
            .filter(|v| v.pin == Some(pin) && v.built > held.built)
            .map(|v| v.digest)
            .chain(
                session
                    .casts
                    .iter()
                    .filter(|c| c.pin == Some(pin) && c.built > held.built)
                    .map(|c| c.digest),
            )
            .any(|digest| on_board.contains_key(&digest));
        if newer_on_board {
            return Err(VoterError::SupersededBallot);
        }
        // Sec. 3.8.4 steps 6-8: the app checks that the ballot is PUBLISHED
        // on the board before the voter goes on to the confirmation. Its
        // "first received" moment is then fixed BEFORE any disclosure exists:
        // a box holding a ballot no box has published could otherwise publish
        // it later - after a re-vote - with the voter's own disclosure, and
        // the board's order would make it the one counted (Sec. 3.9 step 10).
        // Done before the choice is pinned, so a refusal here costs nothing.
        if !on_board.contains_key(&held.digest) {
            return Err(VoterError::NotYetPublished);
        }
    }

    // Pin the choice and destroy the unused openings on disk BEFORE anything
    // leaves the device: a retry after a partial failure can then only
    // resend this same disclosure, never the other slot.
    let disclosure = held.disclosure.choose(l1, l2)?;
    put_held(&mut session, held.clone());
    state.save_session(&req.passphrase, &session).await?;

    // What an honest ballot box must open for this choice.
    use evoting::api::prelude::{OpenedCai, OpenedCaiValue};
    let expect = |slot: CaiSlot, code: u32, sum: u32| match slot {
        CaiSlot::Code => OpenedCaiValue::Code(code),
        CaiSlot::Sum => OpenedCaiValue::Sum(sum),
    };
    let expected = OpenedCai {
        l1: expect(l1, held.control.l1_code, held.control.l1_sum),
        l2: expect(l2, held.control.l2_code, held.control.l2_sum),
    };

    // The disclosure goes to EVERY trusted box (Sec. 3.8.4 step 11): a box
    // that does not answer, or answers with values other than the sealed
    // ones, must not keep the disclosure from the honest box. Its answer is
    // recorded against it; the verdict comes from the board below.
    let mut silent_boxes: Vec<u64> = Vec::new();
    let mut lying_in_answer: Vec<u64> = Vec::new();
    let mut answered = 0usize;
    let mut refused_by: Vec<(u64, String)> = Vec::new();
    for (bb_id, bb) in state.trusted_bbs_with_ids(&session) {
        // 409 is a box saying "a confirmation of this ballot is in progress
        // here" - another request with the same disclosure (a retry, a second
        // device, or a dishonest box forwarding the voter's disclosure to
        // it). That is not a refusal: the box answers the replay once the
        // first one completes, so it is asked again a few times, and counted
        // as silent - not as refusing - if it still has not finished.
        let mut answer = bb.cai(&held.digest, &disclosure).await;
        for _ in 0..CAI_IN_PROGRESS_RETRIES {
            match &answer {
                Err(crate::clients::bb::BbError::Http(status, _))
                    if *status == reqwest::StatusCode::CONFLICT =>
                {
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    answer = bb.cai(&held.digest, &disclosure).await;
                }
                _ => break,
            }
        }
        match answer {
            Ok(response) => {
                answered += 1;
                if response.opened != expected {
                    lying_in_answer.push(bb_id);
                }
            }
            Err(e) => {
                // A REFUSAL is not silence: no retry changes it, and telling
                // the voter to confirm again would send them round a loop.
                if let crate::clients::bb::BbError::Http(status, body) = &e {
                    if status.is_client_error() && *status != reqwest::StatusCode::CONFLICT {
                        tracing::warn!(bb_id, "ballot box refused the confirmation: {body}");
                        refused_by.push((bb_id, body.clone()));
                        continue;
                    }
                }
                tracing::warn!(bb_id, "ballot box did not answer the confirmation: {e}");
                silent_boxes.push(bb_id);
            }
        }
    }
    if answered == 0 {
        if let Some((bb_id, why)) = refused_by.into_iter().next() {
            // A refusal is final, but a SILENT box beside it is not: say so,
            // or a voter takes one box's refusal as the last word while the
            // honest box merely did not answer this time.
            let silent = if silent_boxes.is_empty() {
                String::new()
            } else {
                format!(
                    " (ballot box(es) {silent_boxes:?} did not answer - confirm again to reach them)"
                )
            };
            return Err(VoterError::BallotBoxRefused(format!(
                "BB-{bb_id}: {why}{silent}"
            )));
        }
        return Err(VoterError::BallotBoxSilent);
    }
    let refused_boxes: Vec<RefusedBox> = refused_by
        .into_iter()
        .map(|(bb_id, reason)| RefusedBox { bb_id, reason })
        .collect();
    // The confirmation time is the DEVICE's (Sec. 3.8.4 step 12: a time that
    // does not match the real one is a symptom that something is wrong with
    // the device) - never a box's claim.
    let confirmed_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let value_of = |opened: OpenedCaiValue| match opened {
        OpenedCaiValue::Code(v) | OpenedCaiValue::Sum(v) => v,
    };

    if let Some(record) = session
        .casts
        .iter_mut()
        .rev()
        .find(|c| c.digest == held.digest && c.pin == held.pin)
    {
        record.confirmed_at_ms = Some(confirmed_at_ms);
        record.disclosed = Some(Disclosed {
            disclosure: disclosure.clone(),
            opened: expected,
        });
    }
    let digest = held.digest;

    // A ballot box answering "confirmed" proves nothing: only what is on the
    // board makes the ballot count. The read happens BEFORE the disclosure is
    // dropped, so a board that is briefly unreachable leaves the voter able to
    // confirm again rather than with a confirmed ballot and an error.
    let board = digest_on_board(&state, digest).await?;

    // And what the board shows must be what this app sealed: the app holds
    // both halves of the comparison the voter is told to make (Sec. 3.8.5),
    // so it makes it here instead of claiming "published" on trust. One box
    // publishing something else is that box's lie (Sec. 3.8.4 step 15 makes
    // it visible, not fatal): the confirmation stands when enough boxes
    // published the right values, and the liar is named.
    // What a box published must be the voter's OWN disclosure opening to the
    // sealed values - not merely the right numbers next to another ballot's
    // disclosure, which the tally would discard (Sec. 3.10 1(d)).
    let is_this_ballots =
        |c: &DigestConfirmation| c.opened == expected && c.disclosure.as_ref() == Some(&disclosure);
    let matching_confirmations: std::collections::BTreeSet<u64> = board
        .confirmations
        .iter()
        .filter(|c| is_this_ballots(c))
        .map(|c| c.bb_id)
        .collect();
    let matching_publications: std::collections::BTreeSet<u64> = board
        .publications
        .iter()
        .filter(|p| p.emoji == held.emoji && p.public_pin_emoji == held.public_pin_emoji)
        .map(|p| p.bb_id)
        .collect();
    let lying_boxes: Vec<u64> = board
        .confirmations
        .iter()
        .filter(|c| !is_this_ballots(c))
        .map(|c| c.bb_id)
        .chain(
            board
                .publications
                .iter()
                .filter(|p| p.emoji != held.emoji || p.public_pin_emoji != held.public_pin_emoji)
                .map(|p| p.bb_id),
        )
        .chain(lying_in_answer.iter().copied())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    // One box publishing the sealed values is what the ballot counts on
    // (Sec. 3.10 1(d)); a box that published OTHER values is a liar, a box
    // that published nothing is silent - two different reports.
    if matching_confirmations.is_empty() || matching_publications.is_empty() {
        return Err(if lying_boxes.is_empty() {
            VoterError::BoardMissingConfirmation {
                silent: silent_boxes.clone(),
                refused: refused_boxes
                    .iter()
                    .map(|r| format!("BB-{}: {}", r.bb_id, r.reason))
                    .collect(),
            }
        } else {
            VoterError::BoardMismatch {
                lying: lying_boxes.clone(),
                refused: refused_boxes
                    .iter()
                    .map(|r| format!("BB-{}: {}", r.bb_id, r.reason))
                    .collect(),
            }
        });
    }

    // The disclosure has served its purpose; drop the held ballot.
    // Every ballot of this PIN BUILT before this one is superseded by this
    // confirmation (Sec. 3.9 step 10): forgotten with it, so no later tap can
    // cast or confirm one of them in its place. Newer ones stay.
    let older: Vec<BallotDigest> = session
        .held_by_pin
        .iter()
        .filter(|v| v.pin == held.pin && v.built < held.built)
        .map(|v| v.digest)
        .collect();
    for digest in older {
        drop_held(&mut session, held.pin, digest);
    }
    drop_held(&mut session, held.pin, held.digest);
    state.save_session(&req.passphrase, &session).await?;
    state.refresh_recovery_blob(&req.passphrase, &session).await;

    Ok(Json(ConfirmResponse {
        counting_bb_ids: board.counting_bb_ids,
        will_be_counted: board.confirmed,
        lying_boxes,
        silent_boxes,
        refused_boxes,
        digest,
        confirmed_at_ms,
        l1,
        l2,
        l1_value: value_of(expected.l1),
        l2_value: value_of(expected.l2),
    }))
}

#[derive(Serialize)]
struct RusePinResponse {
    ruse_pin: PinCode,
    /// PrivatePINEmoji of the ruse PIN: it has one like any PIN.
    private_pin_emoji: Vec<String>,
}

impl std::fmt::Debug for RusePinResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RusePinResponse")
            .field("ruse_pin", &"<redacted>")
            .finish()
    }
}

#[derive(Deserialize)]
struct RusePinRequest {
    passphrase: String,
    /// The PIN in force, typed by the voter. Sec. 3.7.3 step 5 builds the
    /// decoy credential for `x^ruse = x + PIN^ruse - PIN^valid`, and
    /// Sec. 3.7.1 step 3 has Vote App recover `x` only "after V has typed in
    /// PIN": the app cannot arm a decoy for someone who does not know the PIN
    /// it holds. Checked exactly as `/api/pin/verify` checks it - and that
    /// screen is unlimited by Sec. 3.7.1, so this check is no oracle the
    /// coercer did not already have.
    pin: PinCode,
    /// The decoy the VOTER chooses (Sec. 3.7.3 step 3). NEVER compared with
    /// the PIN above: see `private_pin_emoji` for why any difference here
    /// would be an oracle.
    #[serde(default)]
    ruse_pin: Option<PinCode>,
}

impl std::fmt::Debug for RusePinRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RusePinRequest")
            .field("passphrase", &"<redacted>")
            .field("pin", &"<redacted>")
            .field("ruse_pin", &"<redacted>")
            .finish()
    }
}

/// V7: obtain a ruse PIN (Sec. 3.7.3, Deviation 4).  Unlimited; each call
/// replaces the previous ruse credential.
#[tracing::instrument(skip(state, req))]
async fn pin_ruse_handler(
    Extension(state): Extension<Arc<VoterState>>,
    Json(req): Json<RusePinRequest>,
) -> Result<Json<RusePinResponse>, VoterError> {
    // One writer per device: see `VoterState::device_locks`.
    let _device = state.device_lock(&req.passphrase).await?;
    let mut session = state.session_for(&req.passphrase).await?;
    session.voter.as_ref().ok_or(VoterError::PinNotRetrieved)?;
    session.pin.ok_or(VoterError::PinNotRetrieved)?;

    // Arming a decoy is an act of the voter, not of whoever holds the device:
    // without this, a coercer with the passphrase alone arms one, the voter's
    // own PIN then stops verifying (Sec. 3.7.3: "PIN^valid will no longer
    // verify the DVNIZKP") and every ballot the voter casts afterwards is
    // discarded at tally - silently, with nothing on any screen to show it.
    // The PIN in force, or the valid PIN. The valid PIN is accepted as well
    // because refusing it protected nothing: whoever holds the passphrase can
    // ask for a re-send and be handed PIN^valid (footnote 9), so "is this the
    // valid PIN?" is answered elsewhere already. What the gate still does is
    // keep the passphrase ALONE from arming a decoy (Sec. 3.7.3 step 5 needs
    // a PIN to build one from).
    let is_valid_pin = session.pin == Some(req.pin);
    if !is_valid_pin && !pin_in_force(&session, req.pin).await? {
        return Err(VoterError::WrongPin);
    }

    // Sec. 3.7.3 step 3: the VOTER chooses the decoy ("V ... inserts a ruse
    // PIN"), so that a decoy already given to a coercer can be armed again -
    // after a revocation, or on another device. The app draws one only when
    // the voter does not supply it.
    let ruse_pin = match req.ruse_pin {
        // A choice is never refused, never treated differently and never
        // compared with the real PIN, whatever it is: see `private_pin_emoji`
        // for why any difference here is an oracle.
        Some(chosen) => chosen,
        None => {
            // UNIFORM over the whole range, the real PIN included. Drawing
            // "away from" it makes the value a collector never sees the real
            // one: with five digits (Sec. 5.2) that is about 1.15 million
            // draws, not the 1.8 billion it was at eight. A decoy that lands
            // on the real PIN costs the voter nothing - Sec. 3.7.3 step 5
            // builds it for `x^ruse = x + PIN^ruse - PIN^valid`, which is `x`.
            let mut rng = state.next_rng("ruse-pin");
            let candidate = rng.next_u32() % PinCode::MAX;
            PinCode::new(candidate).map_err(|e| VoterError::Protocol(format!("ruse pin: {e}")))?
        }
    };

    // Sec. 3.7.3 steps 7-8: a ruse is a PIN request like a re-send - the
    // tellers answer it after their waiting period, and those not trusted
    // return the valid shares. So it IS one here: the same request, the same
    // wait and the same traffic, and the decoy is then armed on this device
    // over the credential just delivered (README row 3). A screen that
    // finished sooner, or a request that looked different on the wire, would
    // tell a ruse from a re-send.
    redeliver_pin(&state, &mut session, &req.passphrase, false).await?;
    let voter = session.voter.clone().ok_or(VoterError::PinNotRetrieved)?;

    // Simulate over the REAL credential builder: the forged DV proof makes
    // local verification of the ruse PIN succeed, while ballots built with it
    // unmask a wrong x and are filtered by the tally ACC check.
    let mut sim_rng = state.next_rng("ruse-simulate");
    let pin = ruse_pin.value() as usize;
    let ruse_voter =
        tokio::task::spawn_blocking(move || voter.to_builder().simulate(pin, &mut sim_rng))
            .await
            .map_err(|e| VoterError::Protocol(e.to_string()))?
            .map_err(|e| VoterError::Protocol(format!("ruse simulation failed: {e:?}")))?;

    session.ruse_pin = Some(ruse_pin);
    session.ruse_voter = Some(ruse_voter);
    // The ballot held under a previous decoy stays: every screen must keep
    // telling ONE story (Sec. 3.7.3). The cast records already show it, so
    // dropping it here would only make the screens disagree - which is what
    // a coercer reads.

    state.save_session(&req.passphrase, &session).await?;
    // The blob the electoral roll keeps for device recovery has to tell the
    // same story as this device: otherwise a coercer who recovers the account
    // elsewhere is handed the REAL PIN (Sec. 3.7.3). But the decoy IS armed
    // now, whatever the roll answers: a failed upload is logged and retried
    // by the next writer, never reported as "the ruse failed" over a device
    // whose PIN in force has already changed.
    state.refresh_recovery_blob(&req.passphrase, &session).await;

    let private_pin_emoji = private_pin_emoji(&session, ruse_pin).unwrap_or_default();
    Ok(Json(RusePinResponse {
        ruse_pin,
        private_pin_emoji,
    }))
}

/// A new `VoterSession::pin_epoch`.
fn new_pin_epoch(state: &VoterState) -> String {
    let mut rng = state.next_rng("pin-epoch");
    format!("{:016x}", rng.next_u64())
}

/// Sec. 3.7.2: a fresh rid', the PIN request to every teller, and the
/// retrieval once t_RT of them have announced themselves; the stored
/// credential is replaced by the valid one the tellers deliver, and any
/// decoy goes with it. Shared by the re-send and the ruse, which in the
/// thesis is a PIN request too (Sec. 3.7.3 steps 7-8): the two then take
/// the same time and look the same on the wire.
async fn redeliver_pin(
    state: &VoterState,
    session: &mut VoterSession,
    passphrase: &str,
    commit: bool,
) -> Result<PinCode, VoterError> {
    let stored_pin = session.pin;

    state.run_pin_request(session).await?;
    // The new request id must survive a timeout: another re-send then
    // starts from a consistent session (the stored PIN is untouched).
    state.save_session(passphrase, session).await?;
    // Each teller answers only after its waiting period tau (Sec. 5.3.1.4):
    // wait for t_RT of them to announce themselves, for at most the longest
    // possible tau plus a margin. On the logical clock they already have.
    // Polling the notification service is cheap; an attempt that got as far
    // as the tellers minted retrieval tokens, so that case is retried once
    // per second at most (it only happens on forged or stale announcements).
    let deadline = tokio::time::Instant::now() + state.tau_wait;
    let pin = loop {
        let pause = match state.run_retrieval(session).await {
            Err(VoterError::PinNotReady) => std::time::Duration::from_millis(250),
            Err(VoterError::TellersStillWaiting) => std::time::Duration::from_secs(1),
            other => break other?,
        };
        if tokio::time::Instant::now() + pause > deadline {
            return Err(VoterError::PinNotReady);
        }
        tokio::time::sleep(pause).await;
    };
    if let Some(stored) = stored_pin {
        if stored != pin {
            return Err(VoterError::Protocol(
                "re-delivered PIN does not match the original".into(),
            ));
        }
    }
    // Sec. 3.7.2 step 3: the re-send REPLACES the stored credential - the mask
    // and the DVNIZKP go back to placeholders and are rebuilt from what the
    // tellers deliver, which is the valid credential (footnote 9). So the
    // decoy is gone: the PIN this screen hands back is the one that verifies
    // and the one `/api/pin` shows. Anything else leaves the voter with a
    // PIN the app calls invalid and a decoy - possibly a coercer's - that it
    // calls valid. A voter who wants a decoy arms one again afterwards.
    session.ruse_pin = None;
    session.ruse_voter = None;
    session.pin_epoch = new_pin_epoch(state);
    // Committed: the answer below describes the device as it now is, and a
    // blob upload the roll refuses is logged, not turned into "failed". A
    // ruse commits once, after arming its decoy - one save and one upload
    // either way, and no moment where the valid credential is saved with no
    // decoy armed.
    if commit {
        state.save_session(passphrase, session).await?;
        state.refresh_recovery_blob(passphrase, session).await;
    }
    Ok(pin)
}

/// V6: PIN re-sending (Sec. 3.7.2) - a fresh rid' + RT requests + retrieval.
/// The re-derived PIN must equal the stored one.
#[tracing::instrument(skip(state, req))]
async fn pin_resend_handler(
    Extension(state): Extension<Arc<VoterState>>,
    Json(req): Json<PassphraseRequest>,
) -> Result<Json<PinResponse>, VoterError> {
    // One writer per device: see `VoterState::device_locks`.
    let _device = state.device_lock(&req.passphrase).await?;
    let mut session = state.session_for(&req.passphrase).await?;
    let pin = redeliver_pin(&state, &mut session, &req.passphrase, true).await?;

    // A RE-SEND delivers the valid PIN. Sec. 3.6.3 footnote 9 is explicit:
    // "PIN = PIN^ruse if this originates from a ruse PIN request ..., or
    // PIN = PIN^valid if this originates from a pin re-sending request".
    // Showing the decoy here instead would leave a voter whose decoy was
    // armed by somebody else with no way back to their own PIN - and the
    // cover story does not need it: a voter under coercion asks for a RUSE
    // PIN, which Sec. 3.7.3 step 7 (footnote 13) pads to look exactly like
    // this request on the wire, and that screen shows the decoy.
    Ok(Json(PinResponse {
        vid: session.vid,
        pin,
        private_pin_emoji: private_pin_emoji(&session, pin).unwrap_or_default(),
    }))
}

#[derive(Deserialize)]
struct RecoverRequest {
    fiscal_id: String,
    passphrase: String,
}

impl std::fmt::Debug for RecoverRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoverRequest")
            .field("fiscal_id", &self.fiscal_id)
            .field("passphrase", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Serialize)]
struct RecoverResponse {
    vid: Vid,
    pin_set: bool,
}

/// V8: new-device recovery (Sec. 3.7.4, Deviation 6).  A fresh DIP login fetches
/// the encrypted blob; only the correct passphrase decrypts it.
#[tracing::instrument(skip(state, req))]
async fn device_recover_handler(
    Extension(state): Extension<Arc<VoterState>>,
    Json(req): Json<RecoverRequest>,
) -> Result<Json<RecoverResponse>, VoterError> {
    use base64::Engine as _;
    // On a device that already holds a session under this passphrase the
    // passphrase is authenticated now, and the lock is taken BEFORE the blob
    // is fetched: a writer finishing in between would otherwise be undone by
    // a blob read before it (a decoy just armed, a revocation just made).
    let early_lock = match state.load_session(&req.passphrase).await? {
        Some(_) => Some(state.device_lock_unchecked(&req.passphrase).await),
        None => None,
    };
    let auth = state
        .dip_client
        .authenticate(&req.fiscal_id)
        .await
        .map_err(|_| VoterError::Unauthorized)?;
    let recovered = state
        .er_client
        .recover_device(&auth.assertion, &auth.signature)
        .await
        .map_err(|_| VoterError::Unauthorized)?;

    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(&recovered.state_blob)
        .map_err(|_| VoterError::Unauthorized)?;
    // The passphrase check IS the decryption (fails closed, generic 401).
    let passphrase = req.passphrase.clone();
    let session = tokio::task::spawn_blocking(move || decrypt_session(&ciphertext, &passphrase))
        .await
        .map_err(|e| VoterError::Io(std::io::Error::other(e)))??
        .ok_or(VoterError::Unauthorized)?;

    // The blob decrypted: this is the device's holder. One writer at a time
    // from here, like every other handler that writes the session.
    let _device = match early_lock {
        Some(guard) => guard,
        None => state.device_lock_unchecked(&req.passphrase).await,
    };
    // A pending revocation id is the sending device's alone (blobs written
    // before it was stripped from them may still carry one).
    let mut session = session;
    session.pending_revocation = None;
    // A session of a LATER generation already on this device is the newer
    // state (a revocation the blob predates): it is kept, never overwritten.
    if let Some(local) = state.load_session(&req.passphrase).await? {
        if local.generation > session.generation {
            return Ok(Json(RecoverResponse {
                vid: local.vid,
                pin_set: local.pin.is_some(),
            }));
        }
    }
    state.save_session(&req.passphrase, &session).await?;
    Ok(Json(RecoverResponse {
        vid: session.vid,
        pin_set: session.pin.is_some(),
    }))
}

#[derive(Debug, Serialize)]
struct RevokeResponse {
    /// The freshly assigned spare vid (Sec. 3.7.5).
    vid: Vid,
}

/// V9: revoke the credential and start over on a spare vid (Sec. 3.7.5).
#[tracing::instrument(skip(state, req))]
async fn revoke_handler(
    Extension(state): Extension<Arc<VoterState>>,
    Json(req): Json<PassphraseRequest>,
) -> Result<Json<RevokeResponse>, VoterError> {
    // One writer per device: see `VoterState::device_locks`.
    let _device = state.device_lock(&req.passphrase).await?;
    let mut session = state.session_for(&req.passphrase).await?;
    let auth = state
        .dip_client
        .authenticate(&session.fiscal_id)
        .await
        .map_err(|_| VoterError::Unauthorized)?;
    // The root is read BEFORE anything irreversible: a revocation cannot be
    // taken back, so a board that is briefly unreachable must stop the
    // request here rather than leave the voter with a revoked credential and
    // an error (Sec. 3.7.5).
    let root = published_vid_root(&state).await?;
    let assigned = published_assigned_vids(&state).await?;
    // The request id is saved before the request leaves: if its answer is
    // lost, the retry sends the same id and gets the same spare.
    let request_id = match session.pending_revocation.clone() {
        Some(id) => id,
        None => {
            let mut bytes = [0u8; 16];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
            let id = hex::encode(bytes);
            session.pending_revocation = Some(id.clone());
            state.save_session(&req.passphrase, &session).await?;
            id
        }
    };
    let revocation = state
        .er_client
        .revoke_from(&auth.assertion, &auth.signature, Some(&request_id))
        .await
        .map_err(|e| match e {
            // The roll REFUSED (no spare identifier left, or revocations are
            // closed): a retry cannot succeed, so the voter is not told to
            // try again (Sec. 3.7.5: n_ACC - n_V revocations in all).
            crate::clients::er::ErError::Http(status, body)
                if status == reqwest::StatusCode::CONFLICT =>
            {
                let reason = serde_json::from_str::<serde_json::Value>(&body)
                    .ok()
                    .and_then(|v| v["error"].as_str().map(str::to_owned))
                    .unwrap_or(body);
                VoterError::RevocationRefused(reason)
            }
            e => VoterError::Er(e),
        })?;
    // A revocation hands out a SPARE - a leaf of the other kind would be
    // another voter's identifier, which two voters would then share - and it
    // must be one of the identifiers committed at setup (Sec. 3.5.3).
    let proved = revocation.vid_kind == crate::protocol::merkle::LeafKind::Spare
        && identifier_matches_its_kind(revocation.vid_kind, revocation.vid, &assigned)
        && crate::protocol::merkle::verify_inclusion(
            &root,
            revocation.vid_kind,
            &revocation.vid_holder,
            revocation.vid.value(),
            &revocation.vid_proof,
        );

    // Reset the credential state onto the spare vid. The new session is
    // SAVED BEFORE anything else can fail: the revocation has already taken
    // effect at the roll, so a device left without state here would hold a
    // revoked credential, no state file and no recovery blob - unable even to
    // ask for a PIN again. (A voter reaches this step precisely when they are
    // being coerced, so it must not be the step that disenfranchises them.)
    let old_path = state.state_path(session.vid);
    // The ballots of the revoked identifier go with it, out of memory as well
    // as out of the session: a ballot cast under a revoked credential is not
    // counted (Sec. 3.7.5), so nothing may keep holding its openings.
    state.ballots.lock().await.remove(&session.vid);
    session.vid = revocation.vid;
    session.generation += 1;
    session.pending_revocation = None;
    session.registration_token = revocation.registration_token;
    session.credential_package = revocation.credential_package;
    session.pin = None;
    session.voter = None;
    // A revocation is a NEW registration (Sec. 3.7.5 step 3, "as in Section
    // 3.6.1"), and the first retrieval of a new credential shows PIN^valid
    // (Sec. 3.6.3 footnote 9). No decoy is carried over: an earlier build
    // re-armed the old decoy here so that a returning coercer saw a PIN they
    // knew, and the cost fell on the voter - the PIN screen showed the decoy,
    // the verify screen called the new PIN invalid, and a ballot cast on what
    // the screens called valid was discarded. A voter who wants the decoy
    // again arms it again, by typing it.
    session.share_commitments = None;
    session.ruse_pin = None;
    session.ruse_voter = None;
    session.held = None;
    session.held_by_pin.clear();
    // The receipts belong to the revoked identifier: a ballot cast under it
    // is not counted (Sec. 3.7.5), so a status screen must not go on
    // answering about it.
    session.casts.clear();
    session.rebuilt_without_rts.clear();
    session.rid = None;
    session.ns_token = None;
    session.pin_epoch = new_pin_epoch(&state);
    state.save_session(&req.passphrase, &session).await?;
    // Only now is the old file dropped, so the passphrase resolves to one
    // session; and only then is the PIN requested, which the voter can retry.
    if state.state_path(session.vid) != old_path {
        let _ = tokio::fs::remove_file(&old_path).await;
    }
    if !proved {
        // The old credential is gone either way: the session keeps the new
        // identifier so the voter is not stranded, but this app will not
        // pretend the roll proved it.
        return Err(VoterError::UnprovenIdentifier);
    }

    // The roll moved this device's record onto the spare identifier within
    // the revocation (key kept, old blob dropped), so the device already
    // exists there. This re-registration only seeds the new recovery blob:
    // lost, it costs the voter a blob until the next refresh, never the
    // credential - which is why it is a warning here and not a failure.
    let at_pk = {
        let seed: [u8; 32] = hex::decode(&session.at_sk_seed)
            .map_err(|e| VoterError::Protocol(format!("stored app key corrupt: {e}")))?
            .try_into()
            .map_err(|_| VoterError::Protocol("stored app key corrupt".into()))?;
        hex::encode(
            ed25519_dalek::SigningKey::from_bytes(&seed)
                .verifying_key()
                .to_bytes(),
        )
    };
    let blob = state.recovery_blob(&req.passphrase, &session)?;
    if let Err(e) = state
        .er_client
        .register_device(&session.registration_token, "", &at_pk, Some(blob))
        .await
    {
        tracing::warn!("the recovery blob could not be seeded after the revocation: {e}");
    }

    // The revocation has taken effect and the device is registered. If the
    // PIN request fails from here, the voter is told exactly that: revoked,
    // ask for the PIN again - not "revocation failed", whose only retry
    // would burn another spare (Sec. 3.7.5: n_ACC - n_V of them).
    if let Err(e) = state.run_pin_request(&mut session).await {
        state.save_session(&req.passphrase, &session).await?;
        return Err(VoterError::RevokedPinRequestFailed(e.to_string()));
    }
    state.save_session(&req.passphrase, &session).await?;
    state.refresh_recovery_blob(&req.passphrase, &session).await;

    Ok(Json(RevokeResponse { vid: session.vid }))
}

#[derive(Debug, Serialize)]
struct TrustedResponse {
    rts: Vec<String>,
    bbs: Vec<String>,
}

/// V10: read the trusted authority selection (Sec. 3.12).
#[tracing::instrument(skip(state, req))]
async fn trusted_get_handler(
    Extension(state): Extension<Arc<VoterState>>,
    Json(req): Json<PassphraseRequest>,
) -> Result<Json<TrustedResponse>, VoterError> {
    let session = state.session_for(&req.passphrase).await?;
    let (rts, bbs) = match session.trusted {
        Some(t) => (t.rts, t.bbs),
        None => (state.rt_names.clone(), state.bb_names.clone()),
    };
    Ok(Json(TrustedResponse { rts, bbs }))
}

#[derive(Deserialize)]
struct TrustedPutRequest {
    passphrase: String,
    rts: Vec<String>,
    bbs: Vec<String>,
}

impl std::fmt::Debug for TrustedPutRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustedPutRequest")
            .field("passphrase", &"<redacted>")
            .field("rts", &self.rts)
            .field("bbs", &self.bbs)
            .finish()
    }
}

/// V10: update the trusted authority selection (Sec. 3.12).  Bounds: at least
/// t_RT registration tellers and at least NO_BOT_MIN_BBS ballot boxes.
#[tracing::instrument(skip(state, req))]
async fn trusted_put_handler(
    Extension(state): Extension<Arc<VoterState>>,
    Json(req): Json<TrustedPutRequest>,
) -> Result<Json<TrustedResponse>, VoterError> {
    // One writer per device: see `VoterState::device_locks`.
    let _device = state.device_lock(&req.passphrase).await?;
    let mut session = state.session_for(&req.passphrase).await?;

    if req.rts.iter().any(|n| !state.rt_names.contains(n))
        || req.bbs.iter().any(|n| !state.bb_names.contains(n))
    {
        return Err(VoterError::BadSelection("unknown authority name".into()));
    }
    // Count DISTINCT authorities: duplicates must not satisfy the thresholds.
    let mut req = req;
    req.rts.sort_unstable();
    req.rts.dedup();
    req.bbs.sort_unstable();
    req.bbs.dedup();
    if req.rts.len() < state.t_rt {
        return Err(VoterError::BadSelection(format!(
            "at least {} registration tellers required",
            state.t_rt
        )));
    }
    if req.bbs.len() < voting::NO_BOT_MIN_BBS {
        return Err(VoterError::BadSelection(format!(
            "at least {} ballot boxes required",
            voting::NO_BOT_MIN_BBS
        )));
    }

    // The ballot boxes chosen here are the ones ballots and disclosures go
    // to (Sec. 3.8). The registration tellers are recorded and shown: in the
    // thesis they decide which tellers can tell a ruse from a re-send (Sec.
    // 3.12), and the ruse is made on this device (README row 3), so the PIN
    // request still goes to every teller (Sec. 3.6.3).
    session.trusted = Some(TrustedSettings {
        rts: req.rts.clone(),
        bbs: req.bbs.clone(),
    });
    state.save_session(&req.passphrase, &session).await?;
    // A recovered device must trust what this one trusts (Sec. 3.12): the
    // tellers a voter excluded are the ones that would otherwise see a ruse.
    state.refresh_recovery_blob(&req.passphrase, &session).await;
    Ok(Json(TrustedResponse {
        rts: req.rts,
        bbs: req.bbs,
    }))
}

// -- Errors ------------------------------------------------------------------

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
    /// Tellers announced themselves but still refuse to deliver (their
    /// waiting period is not over by their own clock). Same answer to the
    /// voter as `PinNotReady`; callers must not retry this one in a tight
    /// loop, since every attempt mints fresh retrieval tokens.
    #[error("PIN is not ready for retrieval yet")]
    TellersStillWaiting,
    #[error("PIN has not been retrieved yet")]
    PinNotRetrieved,
    #[error("no ballot to operate on - vote (and cast) first")]
    NoHeldBallot,
    #[error(
        "a cast-as-intended value was already chosen for this ballot - \
         opening the other one would reveal the vote"
    )]
    CaiAlreadyChosen,
    /// Sec. 3.7.1 step 3: the credential is recovered only "after V has typed
    /// in PIN". The passphrase unlocks the app; it does not answer for a
    /// ballot.
    #[error("type your PIN to work on a ballot")]
    PinRequired,
    /// The roll HAS revoked and this device is registered on the new
    /// identifier; only the PIN request after it failed. Said plainly, because
    /// the wrong retry - another revocation - spends a spare (Sec. 3.7.5).
    #[error(
        "your credential was revoked and this device is on the new identifier, but the PIN \
         request failed ({0}) - do NOT revoke again; use \"Re-send my PIN\""
    )]
    RevokedPinRequestFailed(String),
    #[error(
        "the electoral roll refused the revocation ({0}); your credential was NOT revoked \
         and trying again will not help - contact the electoral authority"
    )]
    RevocationRefused(String),
    #[error(
        "this ballot is not on the bulletin board: no ballot box has published it, so it \
         cannot be confirmed - cast it again, then confirm"
    )]
    NotYetPublished,
    #[error(
        "a newer ballot of yours is already on the bulletin board: this older one is \
         superseded and cannot be confirmed - confirm the newer one (if this app says it \
         has not been cast yet, cast it again first, then confirm it)"
    )]
    SupersededBallot,
    /// The PIN typed is not the one this app holds. Sec. 3.7.1 lets the voter
    /// find that out as often as they like, so saying it plainly gives away
    /// nothing `/api/pin/verify` does not.
    #[error("that is not the PIN this app holds")]
    WrongPin,
    /// Sec. 3.8.4 steps 9-11: the checked ballot and the confirmed ballot are
    /// the same ballot.
    #[error("that is not the ballot whose control values were shown - check them again")]
    ConfirmsAnotherBallot,
    #[error(
        "the electoral roll refuses a new ballot so soon after the previous one - try again later"
    )]
    CastTooSoon,
    #[error(
        "a ballot box refused the casting token (expired or not for this ballot) - cast again"
    )]
    CastingTokenRefused,
    #[error("the electoral roll issues no more casting tokens to this voter: the limit of different ballots is reached")]
    CastLimitReached,
    #[error("a ballot box did not answer - confirm again; nothing is lost")]
    BallotBoxSilent,
    /// A ballot box REFUSED the disclosure, which no retry changes.
    #[error("a ballot box refused this confirmation: {0}")]
    BallotBoxRefused(String),
    /// A legitimate state, not a failure of this server: the ballot this PIN
    /// holds has not been cast (Sec. 3.8.4 confirms what was cast).
    #[error("ballot {0} has not been cast yet - cast it, then confirm")]
    BallotNotCast(BallotDigest),
    /// The voter has not made both cast-as-intended selections. This app
    /// does not make them (Sec. 3.8.4 steps 10-11: they are the voter's, and
    /// a device that chose could have worked around its own choice).
    #[error("choose which control value to open for each level - the app cannot choose for you")]
    CaiChoiceMissing,
    /// Fewer than t_RT tellers accepted the PIN request. Not this server's
    /// failure, and the voter can act on it: try again, and report it.
    #[error(
        "only {asked} of the registration tellers accepted the request and {needed} are \
         needed - try again, and report it if it persists"
    )]
    TooFewTellersForRequest { asked: usize, needed: usize },
    /// The delivering registration tellers do not agree on the dealers'
    /// commitments, so no share can be checked (Sec. 3.6.1 step 11).
    #[error(
        "the registration tellers disagree about this credential - try again, and report it \
         if it persists"
    )]
    CommitmentsDisagree,
    /// A teller dropped out of one of the two DVNIZKP rounds. Retryable over
    /// a subset without it (Sec. 3.6.2, Sec. 6.3.1 A2).
    #[error("a registration teller did not finish the credential proof")]
    CredentialRoundRefused,
    #[error(
        "the credential built from the tellers' shares failed the PIN check with every \
         combination of tellers - report it; nothing is lost"
    )]
    CredentialFailedPinCheck,
    #[error(
        "ballot box(es) {lying:?} published values for this ballot other than the ones this \
         app sealed, and no box published the right ones - do not trust this confirmation, \
         and report it (refused: {refused:?})"
    )]
    BoardMismatch {
        lying: Vec<u64>,
        /// A box that REFUSED the disclosure, with what it said: a refusal
        /// is neither silence nor a lie about the values, and it reaches the
        /// voter on the error paths too (Sec. 3.8.4 steps 15 and 17), not only
        /// when the confirmation succeeds.
        refused: Vec<String>,
    },
    #[error(
        "no ballot box has published your confirmation on the bulletin board yet (silent \
         boxes: {silent:?}; refused: {refused:?}) - confirm again; if it persists, report it"
    )]
    BoardMissingConfirmation {
        silent: Vec<u64>,
        refused: Vec<String>,
    },
    #[error(
        "the bulletin board carries two different results signed by the tellers - this app \
         shows neither; report it"
    )]
    ConflictingResults,
    #[error(
        "the electoral roll cannot prove that this pseudonymous identifier is the one it \
         committed to for you - do not enroll, and report it"
    )]
    UnprovenIdentifier,
    #[error(
        "the bulletin board is not showing the electoral roll's published identifier \
         commitment yet - wait and try again; if it persists, report it"
    )]
    NoPublishedIdentifierRoot,
    #[error("not a ballot digest")]
    BadDigest,
    #[error("invalid trusted-authority selection: {0}")]
    BadSelection(String),
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
            Self::TellersStillWaiting => (StatusCode::CONFLICT, self.to_string()),
            Self::PinNotRetrieved => (StatusCode::BAD_REQUEST, self.to_string()),
            Self::NoHeldBallot => (StatusCode::BAD_REQUEST, self.to_string()),
            Self::PinRequired => (StatusCode::BAD_REQUEST, self.to_string()),
            Self::RevokedPinRequestFailed(_) => (StatusCode::BAD_GATEWAY, self.to_string()),
            Self::RevocationRefused(_) => (StatusCode::CONFLICT, self.to_string()),
            Self::NotYetPublished => (StatusCode::CONFLICT, self.to_string()),
            Self::SupersededBallot => (StatusCode::CONFLICT, self.to_string()),
            Self::WrongPin => (StatusCode::BAD_REQUEST, self.to_string()),
            Self::ConfirmsAnotherBallot => (StatusCode::BAD_REQUEST, self.to_string()),
            Self::CaiAlreadyChosen => (StatusCode::CONFLICT, self.to_string()),
            Self::CastTooSoon => (StatusCode::TOO_MANY_REQUESTS, self.to_string()),
            Self::CastLimitReached => (StatusCode::FORBIDDEN, self.to_string()),
            Self::CastingTokenRefused => (StatusCode::BAD_GATEWAY, self.to_string()),
            Self::BallotBoxSilent => (StatusCode::BAD_GATEWAY, self.to_string()),
            Self::BallotBoxRefused(_) => (StatusCode::CONFLICT, self.to_string()),
            Self::BallotNotCast(_) => (StatusCode::CONFLICT, self.to_string()),
            Self::CredentialFailedPinCheck => (StatusCode::BAD_GATEWAY, self.to_string()),
            Self::CredentialRoundRefused => (StatusCode::BAD_GATEWAY, self.to_string()),
            Self::CommitmentsDisagree => (StatusCode::BAD_GATEWAY, self.to_string()),
            Self::TooFewTellersForRequest { .. } => (StatusCode::BAD_GATEWAY, self.to_string()),
            Self::CaiChoiceMissing => (StatusCode::BAD_REQUEST, self.to_string()),
            // An authority refused or did not answer: the voter can act on
            // that (try again, or report it), so it is not hidden behind a
            // generic internal error.
            Self::Er(_) | Self::Bb(_) | Self::Rt(_) | Self::Ns(_) => (
                StatusCode::BAD_GATEWAY,
                "an election authority refused or did not answer this request - try again, \
                 and report it if it persists"
                    .to_string(),
            ),
            Self::BoardMismatch { .. }
            | Self::BoardMissingConfirmation { .. }
            | Self::ConflictingResults => (StatusCode::BAD_GATEWAY, self.to_string()),
            Self::UnprovenIdentifier => (StatusCode::BAD_GATEWAY, self.to_string()),
            Self::NoPublishedIdentifierRoot => (StatusCode::SERVICE_UNAVAILABLE, self.to_string()),
            Self::BadDigest => (StatusCode::BAD_REQUEST, self.to_string()),
            Self::BadSelection(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            // Internal failures are logged but not leaked.
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

// -- Router / startup --------------------------------------------------------

/// The app's script and markup change with the PoC and its API answers are
/// live: never let the browser serve a stale copy of either.
async fn no_cache(mut response: Response) -> Response {
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-cache, no-store, must-revalidate"),
    );
    // The app shows text read from the bulletin board: no inline or foreign
    // script may ever run in it.
    response.headers_mut().insert(
        axum::http::header::CONTENT_SECURITY_POLICY,
        axum::http::HeaderValue::from_static("default-src 'self'; frame-ancestors 'none'"),
    );
    response
}

/// Client-side routes of the Vote App: each serves the same single page,
/// which shows the matching section (`/menagement` is a tolerated alias).
const APP_ROUTES: [&str; 4] = ["/enrollment", "/voting", "/management", "/menagement"];

pub fn router(state: Arc<VoterState>) -> Router {
    let index = state.static_dir.join("index.html");
    let mut app = Router::new();
    for route in APP_ROUTES {
        app = app.route_service(route, ServeFile::new(&index));
    }
    app.route("/api/login", post(login_handler))
        .route("/api/enroll", post(enroll_handler))
        .route("/api/status", post(status_handler))
        .route("/api/pin/retrieve", post(pin_retrieve_handler))
        .route("/api/pin", post(pin_show_handler))
        .route("/api/pin/verify", post(pin_verify_handler))
        .route("/api/pin/ruse", post(pin_ruse_handler))
        .route("/api/pin/resend", post(pin_resend_handler))
        .route("/api/device/recover", post(device_recover_handler))
        .route("/api/revoke", post(revoke_handler))
        .route(
            "/api/settings/trusted",
            post(trusted_put_handler).put(trusted_put_handler),
        )
        .route("/api/settings/trusted/show", post(trusted_get_handler))
        .route("/api/election", axum::routing::get(election_handler))
        .route("/api/results", axum::routing::get(results_handler))
        .route("/api/vote", post(vote_handler))
        .route("/api/cast", post(cast_handler))
        .route("/api/ballot/status", post(ballot_status_handler))
        .route(
            "/api/verify/:digest",
            axum::routing::get(verify_digest_handler),
        )
        .route("/api/cai/values", post(control_values_handler))
        .route("/api/confirm", post(confirm_handler))
        .fallback_service(ServeDir::new(&state.static_dir).append_index_html_on_directories(true))
        .layer(axum::middleware::map_response(no_cache))
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
    let (rt_names, rt_clients) = build_rt_clients(&settings, client.clone())?;
    // A PIN re-send holds its request open for the longest waiting period
    // plus a margin: bound it, so a misconfiguration cannot pin connections.
    let (_, tau_max_s) = settings
        .election
        .tau_range()
        .map_err(|e| anyhow::anyhow!(e))?;
    if tau_max_s > 60 {
        anyhow::bail!("election.tau_max_s ({tau_max_s}) must not exceed 60 seconds");
    }
    let tau_wait = std::time::Duration::from_secs(tau_max_s + 3);
    if rt_clients.is_empty() {
        anyhow::bail!("no RT peers configured (peers named rt-* required)");
    }
    let (bb_names, bb_clients) = build_bb_clients(&settings, client.clone())?;
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
        tau_wait,
        dip_client,
        er_client,
        ns_client,
        rt_clients,
        rt_names,
        bb_clients,
        bb_names,
        wbb_client,
        rng: std::sync::Mutex::new(actor_seed.into_rng()),
        secrets_from_os: matches!(
            crate::protocol::clock::Clock::from_settings(&settings.clock).mode(),
            crate::protocol::clock::ClockMode::Wall
        ),
        pending_logins: Mutex::new(HashMap::new()),
        ballots: Mutex::new(HashMap::new()),
        device_locks: Mutex::new(HashMap::new()),
        enrolling: Mutex::new(std::collections::HashSet::new()),
        board_view: Mutex::new(BoardView::default()),
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

fn build_bb_clients(
    settings: &Settings,
    client: reqwest::Client,
) -> anyhow::Result<(Vec<String>, Vec<BbClient>)> {
    let mut names = Vec::new();
    let mut clients = Vec::new();
    for peer in &settings.peers {
        if peer.name.starts_with("bb-") {
            let url = reqwest::Url::parse(&peer.base_url)
                .map_err(|e| anyhow::anyhow!("invalid BB peer URL {}: {}", peer.base_url, e))?;
            names.push(peer.name.clone());
            clients.push(BbClient::new(client.clone(), url));
        }
    }
    Ok((names, clients))
}

fn build_rt_clients(
    settings: &Settings,
    client: reqwest::Client,
) -> anyhow::Result<(Vec<String>, Vec<RtClient>)> {
    let mut names = Vec::new();
    let mut clients = Vec::new();
    for peer in &settings.peers {
        if peer.name.starts_with("rt-") {
            let url = reqwest::Url::parse(&peer.base_url)
                .map_err(|e| anyhow::anyhow!("invalid RT peer URL {}: {}", peer.base_url, e))?;
            names.push(peer.name.clone());
            clients.push(RtClient::new(
                client.clone(),
                url,
                secrecy::SecretString::new(String::new()),
            ));
        }
    }
    Ok((names, clients))
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

// -- ChaCha20-Poly1305 encryption for persisted voter state -----------------

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

/// Every encrypted state is padded to a multiple of this many bytes, so its
/// size says nothing about what it holds: whether a ruse PIN was armed, how
/// many ballots were cast, whether a device was recovered, whether a ruse
/// ballot is held next to a real one. One bucket covers every state this PoC
/// produces (a full session with both held ballots and every cast is a few
/// tens of kilobytes); the ladder only ever shows how much a voter did if a
/// state crosses it, which is why the bucket is far larger than needed. The electoral roll
/// stores the very same bytes as the recovery blob (V8) and a curious roll
/// could otherwise sort voters by it (Sec. 3.7.3; Table 6.2 keeps the PIN's
/// whole story from the roll).
const STATE_PAD_TO: usize = 64 * 1024;

/// Frame `plaintext` as a 4-byte big-endian length followed by the bytes and
/// zero padding up to a multiple of [`STATE_PAD_TO`].
fn pad_state(plaintext: &[u8]) -> Vec<u8> {
    let framed_len = 4 + plaintext.len();
    let padded_len = framed_len.div_ceil(STATE_PAD_TO) * STATE_PAD_TO;
    let mut out = Vec::with_capacity(padded_len);
    out.extend_from_slice(&(plaintext.len() as u32).to_be_bytes());
    out.extend_from_slice(plaintext);
    out.resize(padded_len, 0);
    out
}

fn unpad_state(framed: &[u8]) -> Result<Vec<u8>, VoterError> {
    let len = framed
        .get(..4)
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map(u32::from_be_bytes)
        .ok_or_else(|| VoterError::Crypto("state frame too short".into()))? as usize;
    framed
        .get(4..4 + len)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| VoterError::Crypto("state frame length out of range".into()))
}

fn encrypt_state(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>, VoterError> {
    use ring::aead::{Aad, BoundKey, Nonce, SealingKey, UnboundKey, CHACHA20_POLY1305};
    let padded = pad_state(plaintext);
    let plaintext = padded.as_slice();

    // SIV-style determinism: the salt is derived from the plaintext, so every
    // distinct plaintext gets a distinct key, making the fixed all-zero nonce
    // safe under nonce-uniqueness (one message per key).  Re-encrypting the
    // same state yields the identical ciphertext - no randomness, so a server
    // restart cannot cause key+nonce reuse across different plaintexts.
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

/// Decrypt and parse one session file. `Ok(None)` when the passphrase is not
/// this file's; any other failure is an error.
fn decrypt_session(
    ciphertext: &[u8],
    passphrase: &str,
) -> Result<Option<Box<VoterSession>>, VoterError> {
    match decrypt_state(ciphertext, passphrase) {
        Ok(plaintext) => {
            let session: Box<VoterSession> =
                serde_json::from_slice(&plaintext).map_err(VoterError::Json)?;
            Ok(Some(session))
        }
        Err(VoterError::Crypto(_)) => Ok(None),
        Err(e) => Err(e),
    }
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
    unpad_state(plaintext)
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

/// The ballot the control-values and confirmation screens operate on: the
/// newest one the given PIN built.
///
/// A PIN is REQUIRED. Sec. 3.7.1 step 3 has Vote App recover the credential
/// only "after V has typed in PIN", and every screen that acts on a ballot is
/// downstream of that: the passphrase alone unlocks the app, it does not
/// stand in for the PIN. Without this the coercer of Sec. 6.3.2, who by A1
/// may hold the passphrase, reads the vote of a voter who has not armed a
/// decoy - `sum - code` is the choice - and can confirm the ballot in the
/// voter's place.
fn operative_held(session: &VoterSession, pin: PinCode) -> Option<&HeldVote> {
    // The PIN decides which ballot a screen works on, exactly as it decides
    // which one `/api/vote` builds: the ballot THAT PIN built, and no other.
    // A PIN that built nothing reaches nothing - a coercer who tries a PIN of
    // their own learns only that it holds no ballot, which is what a voter
    // who never used that PIN would show them anyway (Sec. 3.7.3, A1).
    // The NEWEST ballot of that PIN: `put_held` appends, so anything else
    // would make two screens disagree about the same PIN (Sec. 3.8.5 item 1).
    session
        .held_by_pin
        .iter()
        .rev()
        .find(|v| v.pin == Some(pin))
}

/// Why there is nothing to confirm under `pin` - naming the ballot whenever
/// there is one to name, because "no ballot" about a ballot the voter is
/// holding the digest of tells them nothing (Sec. 3.8.5 1(a)).
fn nothing_to_confirm(session: &VoterSession, pin: PinCode) -> VoterError {
    match operative_held(session, pin) {
        Some(built) => VoterError::BallotNotCast(built.digest),
        None => VoterError::NoHeldBallot,
    }
}

/// Why the ballot `digest` is not one this PIN can confirm.
fn cannot_confirm(session: &VoterSession, pin: PinCode, digest: BallotDigest) -> VoterError {
    // A ballot this PIN built and never cast: say so, by name.
    if session
        .held_by_pin
        .iter()
        .any(|v| v.pin == Some(pin) && v.digest == digest)
    {
        return VoterError::BallotNotCast(digest);
    }
    // Not this PIN's ballot at all, while another one IS waiting.
    if session.awaiting_confirmation(pin).next().is_some() {
        return VoterError::ConfirmsAnotherBallot;
    }
    nothing_to_confirm(session, pin)
}

/// The ballot the CONFIRMATION screens operate on: the newest ballot of that
/// PIN that has been CAST and not yet confirmed.
///
/// Not simply the newest one built. Sec. 3.8.4 steps 7-17 are a sequence the
/// voter is in the middle of once a ballot is cast: the board carries its
/// digest, Sec. 3.8.5 has the voter look it up, and Sec. 3.9 step 2 drops it
/// unless a disclosure arrives. A second `/api/vote` before the confirmation
/// must therefore not take the screens away from it - that would strand a
/// ballot the board already shows as cast, with no way back to it and nothing
/// on the board to distinguish the loss from a voter who chose not to
/// confirm.
fn held_to_confirm(
    session: &VoterSession,
    pin: PinCode,
    digest: Option<BallotDigest>,
) -> Option<&HeldVote> {
    session
        .awaiting_confirmation(pin)
        .rev()
        .find(|held| digest.map_or(true, |wanted| held.digest == wanted))
}

impl VoterSession {
    /// Every ballot this PIN has CAST and not yet confirmed, oldest first.
    ///
    /// More than one is ordinary, because the voter may cast again before
    /// confirming, and each of them is a ballot the board already carries and
    /// that Sec. 3.9 step 2 will drop unless a disclosure arrives. So none of
    /// them may become unreachable.
    fn awaiting_confirmation(&self, pin: PinCode) -> impl DoubleEndedIterator<Item = &HeldVote> {
        self.held_by_pin.iter().filter(move |held| {
            held.pin == Some(pin)
                && self.casts.iter().any(|c| {
                    c.digest == held.digest && c.pin == held.pin && c.confirmed_at_ms.is_none()
                })
        })
    }
}

/// The commitment set at least `t_rt` of the delivering tellers agree on.
///
/// NOT a majority of whoever happened to answer: a majority rule switches
/// itself off exactly when it is needed, since one dishonest teller plus one
/// delivery lost on the wire leaves two answers that disagree and no majority
/// at all. Sec. 6.3.1 A2 guarantees `n_RT - t_RT + 1` honest tellers, so any
/// set `t_rt` of them state is the tellers' own.
fn agreed_commitments(
    delivered: &[(&str, &RtClient, TokenValue, DeliveredShare)],
    t_rt: usize,
) -> Option<AccShareCommitments<G>> {
    delivered
        .iter()
        .map(|(_, _, _, one)| &one.share_commitments)
        .filter(|c| !c.x.is_empty())
        .find(|candidate| {
            delivered
                .iter()
                .filter(|(_, _, _, other)| other.share_commitments == **candidate)
                .count()
                >= t_rt
        })
        .cloned()
}

/// Store a held ballot back under its own PIN.
fn put_held(session: &mut VoterSession, held: HeldVote) {
    if !held.ruse {
        session.held = Some(held.clone());
    }
    // In place: the list's order is the order the ballots were built in,
    // and storing one back must not make it look newer than it is.
    match session
        .held_by_pin
        .iter_mut()
        .find(|v| v.pin == held.pin && v.digest == held.digest)
    {
        Some(slot) => *slot = held,
        None => session.held_by_pin.push(held),
    }
}

/// Forget the held ballot a PIN built, once its disclosure has been made.
fn drop_held(session: &mut VoterSession, pin: Option<PinCode>, digest: BallotDigest) {
    session
        .held_by_pin
        .retain(|v| !(v.pin == pin && v.digest == digest));
    if session.held.as_ref().is_some_and(|h| h.digest == digest) {
        session.held = None;
    }
}

/// Every `t`-element subset of `names`, in order.
fn t_subsets(names: &[String], t: usize) -> Vec<Vec<String>> {
    fn go(
        start: usize,
        names: &[String],
        t: usize,
        current: &mut Vec<String>,
        out: &mut Vec<Vec<String>>,
    ) {
        if current.len() == t {
            out.push(current.clone());
            return;
        }
        for i in start..names.len() {
            current.push(names[i].clone());
            go(i + 1, names, t, current, out);
            current.pop();
        }
    }
    let mut out = Vec::new();
    go(0, names, t, &mut Vec::with_capacity(t), &mut out);
    out
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
        // Same plaintext -> identical ciphertext (restart-safe, deterministic).
        let c1 = encrypt_state(b"state-v1", passphrase).unwrap();
        let c2 = encrypt_state(b"state-v1", passphrase).unwrap();
        assert_eq!(c1, c2);
        // Different plaintext -> different salt, hence a different key under
        // the fixed nonce (no key+nonce pair ever encrypts two plaintexts).
        let c3 = encrypt_state(b"state-v2", passphrase).unwrap();
        assert_ne!(&c1[..SALT_LEN], &c3[..SALT_LEN]);
    }

    /// The size of an encrypted state says nothing about its contents: a
    /// state a few kilobytes larger (a ruse credential, more casts) encrypts
    /// to exactly as many bytes, and a state the size of a nonsense of zeros
    /// comes back intact.
    #[test]
    fn the_size_of_an_encrypted_state_hides_what_it_holds() {
        let passphrase = "correct-horse-battery-staple-mule-crank";
        let small = vec![b'a'; 3_100];
        let with_ruse = vec![b'b'; 5_300];
        let c_small = encrypt_state(&small, passphrase).unwrap();
        let c_ruse = encrypt_state(&with_ruse, passphrase).unwrap();
        assert_eq!(c_small.len(), c_ruse.len());
        assert_eq!(decrypt_state(&c_ruse, passphrase).unwrap(), with_ruse);
        let zeros = vec![0u8; 100];
        let c_zeros = encrypt_state(&zeros, passphrase).unwrap();
        assert_eq!(decrypt_state(&c_zeros, passphrase).unwrap(), zeros);
        // A state beyond one bucket still round-trips (and grows by whole buckets).
        let big = vec![b'c'; STATE_PAD_TO + 10];
        let c_big = encrypt_state(&big, passphrase).unwrap();
        assert_eq!(decrypt_state(&c_big, passphrase).unwrap(), big);
        assert_eq!(c_big.len() - c_small.len(), STATE_PAD_TO);
    }
}
