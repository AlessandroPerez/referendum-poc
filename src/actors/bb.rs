//! Ballot Box (BB) server (Sec. 3.8.4).
//!
//! Endpoints:
//!   - `POST /ballots`          - CAT-authorized ballot intake: verifies the
//!     casting token BY ITSELF (ER signature, this ballot box, validity,
//!     commB binding - no call to the ER), verifies the ballot proofs,
//!     stores it idempotently by digest, publishes `ballot_digest` +
//!     `ballot_metadata` to the WBB, returns a `Receipt`.
//!   - `POST /cai`              - CAI disclosure verification + publication.
//!   - `GET  /receipts/{digest}`- public receipt lookup.
//!   - `GET  /ballots`          - ballot release for the tally driver.
//!
//! Receipts are minted on the configured clock (logical in the test suite,
//! wall clock in real runs) - the library's `InMemoryBB` always uses
//! wall-clock time, so the PoC keeps its own store built
//! from the library's public `BallotRecord`/`Receipt` types.

use std::collections::{HashMap, HashSet};
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
use crate::clients::wbb::{sign_entry, SignedEntry, WbbClient};
use crate::configuration::Settings;
use crate::domain::BallotDigest;
use crate::protocol::cat::CastingToken;
use crate::protocol::clock::Clock;
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
    cai: Option<HeldCai>,
    /// While the board has not been SEEN to hold this ballot's digest: the
    /// signed digest entry and the metadata entry, kept so a later attempt
    /// sends THE SAME BYTES (the board keeps one leaf for them). Sec. 3.8.4
    /// step 6: a box confirms a registration only once it can confirm the
    /// publication - a re-cast, a confirmation and the release all publish
    /// it first.
    unpublished: Option<UnpublishedDigest>,
}

#[derive(Clone)]
struct UnpublishedDigest {
    digest: SignedEntry,
    metadata: String,
}

impl BbState {
    /// Put a stored ballot's digest on the board if it is not yet seen there
    /// (see `StoredBallot::unpublished`). `Ok` once it is.
    async fn publish_pending_digest(&self, digest: &BallotDigest) -> Result<(), BbError> {
        // Serialised, and the pending entry read only once the turn comes: a
        // caller that waited finds it already published (or re-signed).
        let turn = self
            .pending_publish
            .lock()
            .await
            .entry(*digest)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone();
        let _turn = turn.lock_owned().await;
        let pending = {
            let ballots = self.ballots.lock().await;
            match ballots.get(digest) {
                Some(stored) => stored.unpublished.clone(),
                None => return Err(BbError::NotFound),
            }
        };
        let Some(pending) = pending else {
            return Ok(());
        };
        match self.submit_signed(&pending.digest).await {
            Ok(()) => {}
            Err(BbError::Internal(refused)) => {
                // Refused AND not on the board (`submit_signed` asked it): no
                // copy of these bytes was ever accepted, so a fresh signature
                // can take no second leaf. Signed again once - a board on the
                // wall clock refuses a timestamp older than its window, which
                // the first signature may now be. Still refused (the voting
                // window is closed) = the ballot was never published.
                tracing::warn!(%digest, "pending digest refused ({refused}); signing it afresh");
                let data = String::from_utf8_lossy(&pending.digest.data).to_string();
                let fresh = self.sign_for_board(&data).await?;
                // The fresh signature replaces the stale one before it is
                // sent: any later attempt sends THESE bytes.
                if let Some(stored) = self.ballots.lock().await.get_mut(digest) {
                    if let Some(held) = stored.unpublished.as_mut() {
                        held.digest = fresh.clone();
                    }
                }
                self.submit_signed(&fresh).await?;
            }
            Err(e) => return Err(e),
        }
        // Only the request that clears the mark publishes the metadata: two
        // concurrent re-casts would otherwise each sign a fresh metadata
        // entry for one ballot.
        let first = match self.ballots.lock().await.get_mut(digest) {
            Some(stored) => stored.unpublished.take().is_some(),
            None => false,
        };
        if first {
            if let Err(e) = self.publish(&pending.metadata).await {
                tracing::warn!(%digest, "ballot accepted, but its metadata entry was not published: {e}");
            }
        }
        Ok(())
    }
}

/// A cast-as-intended disclosure this box opened, and whether its publication
/// was CONFIRMED on the board. Sec. 3.8.4 step 16 lets a box tell the app the
/// data is published only "once a trusted BB can confirm that the data has
/// been published": one it could not confirm is kept (the entry may well be
/// there) but marked, so a later attempt publishes it again instead of
/// replaying a success the board may never have seen.
#[derive(Clone)]
struct HeldCai {
    entry: CaiEntry,
    /// The signed entry this box submitted for `entry`, kept verbatim so a
    /// retry resubmits THE SAME BYTES. `publish` stamps a fresh timestamp
    /// each time it signs, so re-deriving the entry would take a second leaf
    /// on an append-only board and make an honest box look like it published
    /// two confirmations.
    submitted: SignedEntry,
    published: bool,
}

/// BB service state.
#[derive(Clone)]
pub struct BbState {
    entity_id: String,
    bb_id: u64,
    signing_key_seed: SecretString,
    service_token: SecretString,
    actor_seed: ActorSeed,
    election_context: ElectionContext<G>,
    wbb_client: WbbClient,
    /// The electoral roll's public key: casting tokens are checked locally.
    er_verifying_key: ed25519_dalek::VerifyingKey,
    clock: Arc<Mutex<Clock>>,
    enc_counter: Arc<AtomicU64>,
    next_seq: Arc<AtomicU64>,
    ballots: Arc<Mutex<HashMap<BallotDigest, StoredBallot>>>,
    /// Digests whose intake is in progress (reserved before token
    /// verification, released on every exit path) so two concurrent casts of
    /// the same ballot cannot both publish it.
    in_flight: Arc<Mutex<HashSet<BallotDigest>>>,
    /// Digests whose CONFIRMATION is in progress. The slot a box opens is
    /// taken here, before the (slow) disclosure verification, so that two
    /// confirmations of one ballot arriving together cannot both find the
    /// slot free: the two openings of one ballot are `sum - code`, the vote
    /// (Sec. 3.8.4 steps 10-14). Two devices at once is ordinary - Sec. 3.7.4
    /// allows it - so the loser is told to retry, not refused.
    confirming: Arc<Mutex<HashSet<BallotDigest>>>,
    /// Which of THIS box's ballots each published disclosure opens, by the
    /// disclosure's bytes - computed once per distinct disclosure, ever. The
    /// conflict check of Sec. 3.8.4 steps 13-16 must look at every published
    /// disclosure whatever digest it states, and without this a box paid
    /// (published entries x its ballots) group operations on EVERY
    /// confirmation, a price any publisher on the board could set.
    opened_disclosures: Arc<Mutex<OpenedDisclosures>>,
    /// One pending-digest publication at a time PER BALLOT: concurrent
    /// callers would each sign a stale digest afresh, and an append-only
    /// board would then carry two acceptances of one ballot by this box.
    /// Per ballot, so casts of different ballots never wait for each other.
    pending_publish: Arc<Mutex<HashMap<BallotDigest, Arc<Mutex<()>>>>>,
    /// The release once voting has closed: computed ONCE, in the background,
    /// and kept (the voting-phase entries it is computed from are final).
    /// Junk on the board can make it slow; it can no longer make a request
    /// time out and be taken for an empty release.
    release: Arc<Mutex<ReleaseState>>,
}

/// Which of this box's ballots each published disclosure (by its bytes) opens.
type OpenedDisclosures = HashMap<Vec<u8>, Option<(BallotDigest, evoting::api::prelude::OpenedCai)>>;

/// Where the post-voting release stands (see `BbState::release`).
enum ReleaseState {
    NotStarted,
    Preparing,
    Ready(Vec<BallotRecord<G>>),
    /// The last attempt failed (its board reading did); the next request
    /// starts a new one.
    Failed(String),
}

/// Drops the in-flight reservation for a digest on every exit path.
struct InFlightGuard {
    set: Arc<Mutex<HashSet<BallotDigest>>>,
    digest: BallotDigest,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        let digest = self.digest;
        // `Drop` cannot await; the tokio mutex offers a non-blocking path and
        // a spawned task covers the (rare) contended case.
        let released = match self.set.try_lock() {
            Ok(mut guard) => {
                guard.remove(&digest);
                true
            }
            Err(_) => false,
        };
        if !released {
            let set = self.set.clone();
            tokio::spawn(async move {
                set.lock().await.remove(&digest);
            });
        }
    }
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

    /// Sign and publish a WBB data string with a fresh timestamp.
    /// Sign `data` as this box, stamping the clock once.
    async fn sign_for_board(&self, data: &str) -> Result<SignedEntry, BbError> {
        let timestamp = {
            let mut clock = self.clock.lock().await;
            let ts = clock.now_ms() as i64;
            clock.advance();
            ts
        };
        let signing_key = self.signing_key();
        let entity_id = self.entity_id.clone();
        let data_owned = data.to_string();
        tokio::task::spawn_blocking(move || {
            sign_entry(data_owned.as_bytes(), &entity_id, timestamp, &signing_key)
        })
        .await
        .map_err(|e| BbError::Internal(e.to_string()))
    }

    async fn publish(&self, data: &str) -> Result<(), BbError> {
        let entry = self.sign_for_board(data).await?;
        self.submit_signed(&entry).await
    }

    /// Submit an entry this box has already signed. A retry sends THESE
    /// bytes, which the board keeps one leaf for however often they arrive.
    async fn submit_signed(&self, entry: &SignedEntry) -> Result<(), BbError> {
        let data = String::from_utf8_lossy(&entry.data).to_string();
        let data = data.as_str();
        match self
            .wbb_client
            .submit_and_wait(entry, std::time::Duration::from_secs(10))
            .await
        {
            Ok(_) => Ok(()),
            // The board REFUSED the entry (wrong phase, write policy, a stale
            // timestamp). That is a refusal of THIS submission, not proof that
            // the entry is absent: an earlier copy of the same bytes may be on
            // the board already, its answer lost. The board decides - and a
            // board this box cannot read leaves the question open.
            Err(crate::clients::wbb::WbbError::Http(status, body)) if status.is_client_error() => {
                match self.is_published(data).await {
                    Ok(true) => Ok(()),
                    Ok(false) => Err(BbError::Internal(format!(
                        "WBB refused the entry ({status}): {body}"
                    ))),
                    Err(_) => Err(BbError::PublicationUnconfirmed),
                }
            }
            // The submission was sent and the answer did not come back, or
            // did not come back in time. That is NOT a refusal: the entry may
            // well be on the board, and a box that then forgot the ballot
            // would be unable to release what the board shows it accepted -
            // and would be blamed for it. The same signed bytes are sent
            // again (the board keeps one leaf per entry) and the board is
            // read once more; if it still cannot be seen there, the caller is
            // told the publication is UNCONFIRMED and the ballot is kept.
            Err(e) => {
                tracing::warn!("WBB publication not confirmed ({e}); retrying");
                match self
                    .wbb_client
                    .submit_and_wait(entry, std::time::Duration::from_secs(10))
                    .await
                {
                    Ok(_) => Ok(()),
                    // A board this box cannot READ is not a board without the
                    // entry: `is_published` says so, and an unreadable one
                    // leaves the publication unconfirmed, to be retried.
                    Err(_) => match self.is_published(data).await {
                        Ok(true) => Ok(()),
                        Ok(false) | Err(_) => Err(BbError::PublicationUnconfirmed),
                    },
                }
            }
        }
    }

    /// Whether the board already carries this exact data string.
    /// Publish `data` unless the board already carries it.
    ///
    /// [`Self::publish`] stamps a FRESH timestamp each time it is called, so
    /// the same payload submitted twice is two different entries and would
    /// take two leaves on an append-only board. A retry therefore looks
    /// first: what is already there is adopted, not published again.
    /// Is this exact data already on the board, over this box's signature?
    ///
    /// A board this box cannot read answers `Err`, never "no": treating an
    /// unreadable board as an absent entry is how one publication becomes
    /// two (Sec. 3.4.2: the board is append-only, nothing takes a leaf back).
    async fn is_published(&self, data: &str) -> Result<bool, BbError> {
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        let wanted = B64.encode(data.as_bytes());
        let entries = self
            .wbb_client
            .entries()
            .await
            .map_err(|e| BbError::BoardUnreachable(e.to_string()))?;
        Ok(entries.entries.iter().any(|e| {
            e.entry
                .get("data")
                .and_then(|v| v.as_str())
                .is_some_and(|s| s == wanted)
                && crate::protocol::voting::signed_by_ballot_box(&e.entry, self.bb_id)
        }))
    }

    /// Every cast-as-intended disclosure on the board, signed by the box it
    /// names (Sec. 3.8.4 step 15 publishes every box's), read by the tally's
    /// own rule (`board_ballots`). Used by the confirmation's check for a
    /// second opening: not indexed by the digest an entry states, since the
    /// ballot is identified FROM the disclosure (Sec. 3.8.4 step 13), and
    /// each distinct disclosure is opened once and remembered there
    /// (`opened_disclosures`). A failing read is an error, never an empty
    /// answer.
    async fn confirmed_on_board(&self) -> Result<Vec<CaiEntry>, BbError> {
        Ok(self.board_reading().await?.confirmations)
    }

    /// ONE reading of the board, parsed by the rule the tally driver and the
    /// auditor use (`board_ballots`). A failed read is an error, never an
    /// empty answer.
    async fn board_reading(&self) -> Result<crate::protocol::tally::BoardBallots, BbError> {
        let entries = self
            .wbb_client
            .entries()
            .await
            .map_err(|e| BbError::BoardUnreachable(e.to_string()))?;
        let entries: Vec<(i64, serde_json::Value)> = entries
            .entries
            .into_iter()
            .map(|sequenced| (sequenced.leaf_index, sequenced.entry))
            .collect();
        Ok(crate::protocol::tally::board_ballots(&entries))
    }
}

// -- Handlers ----------------------------------------------------------------

#[derive(Deserialize)]
struct CastRequest {
    ballot: Ballot<G>,
    /// Hex-encoded 32-byte commitment randomness (Sec. 5.3.1.6).
    rndcomm: String,
    casting_token: CastingToken,
}

impl std::fmt::Debug for CastRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CastRequest")
            .field("rndcomm", &"<redacted>")
            .field("casting_token", &"<redacted>")
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Serialize)]
struct CastResponse {
    digest: BallotDigest,
    receipt: Receipt,
    emoji: Vec<String>,
}

/// V12: ballot intake (Sec. 3.8.4, idempotent intake).
#[tracing::instrument(skip(state, req))]
async fn cast_handler(
    Extension(state): Extension<Arc<BbState>>,
    Json(req): Json<CastRequest>,
) -> Result<Json<CastResponse>, BbError> {
    let digest = ballot_digest(&req.ballot).map_err(|e| BbError::Internal(e.to_string()))?;

    // Idempotent replay: the same ballot (same digest) returns the stored
    // receipt. The in-flight reservation is taken under the same lock so a
    // concurrent duplicate cannot slip past the lookup and publish twice.
    let _in_flight = {
        let ballots = state.ballots.lock().await;
        if let Some(stored) = ballots.get(&digest) {
            let response = CastResponse {
                digest,
                receipt: stored.record.receipt,
                emoji: stored.emoji.clone(),
            };
            let pending = stored.unpublished.is_some();
            drop(ballots);
            // A ballot whose digest this box never saw on the board: the
            // voter was told to cast again, and casting again must PUBLISH
            // it, not replay a receipt for data the board does not hold.
            if pending {
                state.publish_pending_digest(&digest).await?;
            }
            return Ok(Json(response));
        }
        let mut in_flight = state.in_flight.lock().await;
        if !in_flight.insert(digest) {
            return Err(BbError::Conflict);
        }
        InFlightGuard {
            set: state.in_flight.clone(),
            digest,
        }
    };

    // Recompute commB from the submitted ballot + randomness: the casting
    // token must be tied to exactly this commitment.
    let rndcomm: [u8; 32] = hex::decode(&req.rndcomm)
        .map_err(|_| BbError::BadRequest("rndcomm must be hex".into()))?
        .try_into()
        .map_err(|_| BbError::BadRequest("rndcomm must be 32 bytes".into()))?;
    let commitment = comm_b(&req.ballot, &rndcomm).map_err(|e| BbError::Internal(e.to_string()))?;
    // Sec. 5.3.1.6 step 6, all checked HERE with no call to the ER (which
    // therefore never learns that, or when, this ballot is cast): the token
    // is signed by the ER, is for this ballot box, has not expired, is tied
    // to the commitment just recomputed. "Not already used" (step 6) holds by
    // construction: the token is bound to ONE ballot through commB, and the
    // same ballot arriving again is the idempotent replay handled above, so
    // a token can never admit a second, different ballot.
    // Expiry compares the issuer's clock with this one's, which only means
    // something when both are the wall clock: on the logical clock every
    // service counts its own ticks, so there the validity is not enforced.
    let now_ms = {
        let clock = state.clock.lock().await;
        match clock.mode() {
            crate::protocol::clock::ClockMode::Wall => clock.now_ms(),
            crate::protocol::clock::ClockMode::Logical => 0,
        }
    };
    req.casting_token
        .verify(
            &state.er_verifying_key,
            &state.election_context.context_hash,
            state.bb_id,
            &commitment,
            now_ms,
        )
        .map_err(|e| {
            tracing::info!(reason = %e, "casting token refused");
            BbError::Unauthorized
        })?;
    // Verify the ballot proofs against the election context (Sec. 3.8.4 step 5).
    let ctx = state.election_context.clone();
    let ballot = req.ballot.clone();
    tokio::task::spawn_blocking(move || ballot.verify(&ctx))
        .await
        .map_err(|e| BbError::Internal(e.to_string()))?
        .map_err(|_| BbError::BadRequest("ballot verification failed".into()))?;

    // Mint the receipt on the configured clock and store the ballot.
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
    let public_pin_emoji: Vec<String> = req
        .ballot
        .public_pin_emoji()
        .iter()
        .map(|s| s.to_string())
        .collect();

    // E_pk_TT[g1^{2^bb_id}] (Sec. 3.8.4) with a seeded RNG.
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

    // Publish digest + metadata to the WBB (Sec. 3.4.2 write policy).
    let digest_entry = BallotDigestEntry {
        digest,
        emoji: emoji.clone(),
        public_pin_emoji,
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
    // The digest entry is signed ONCE and stored with the ballot until the
    // board is seen to hold it (see `StoredBallot::unpublished`): every later
    // attempt sends these same bytes.
    let signed_digest = state.sign_for_board(&digest_data).await?;
    state.ballots.lock().await.insert(
        digest,
        StoredBallot {
            record,
            emoji: emoji.clone(),
            cai: None,
            unpublished: Some(UnpublishedDigest {
                digest: signed_digest,
                metadata: metadata_data,
            }),
        },
    );
    // A ballot is accepted only if its digest is published (Sec. 3.8.4 steps
    // 2-6): if the WBB REFUSES the DIGEST - the voting window is closed, or
    // the policy rejects it - the stored ballot is rolled back so nothing
    // unpublished can ever be released at tally. A publication this box could
    // not CONFIRM is another matter: the entry is most likely on the board,
    // and deleting the ballot would leave this box unable to release a ballot
    // the board shows it accepted - the blame for that would land on this
    // box. The ballot is kept, still marked unpublished; the voter is told to
    // check the board and cast again, which publishes it. Once the digest is
    // on the board the metadata entry follows; a refused metadata entry does
    // not undo the acceptance (Sec. 3.8.5 1(d): the box holds the ballot the
    // board shows it accepted).
    match state.publish_pending_digest(&digest).await {
        Ok(()) => {}
        Err(BbError::PublicationUnconfirmed) => {
            tracing::warn!(%digest, "digest published but its inclusion could not be confirmed");
            return Err(BbError::PublicationUnconfirmed);
        }
        Err(e) => {
            // A REFUSAL: nothing was accepted, so nothing is kept.
            state.ballots.lock().await.remove(&digest);
            return Err(BbError::NotAccepted(format!(
                "digest publication refused by the WBB ({e})"
            )));
        }
    }

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
    /// The values this ballot box opened and published for the ballot. On a
    /// replay these are the FIRST disclosure's values: a ballot box never
    /// opens a second slot, which would reveal the vote.
    opened: evoting::api::prelude::OpenedCai,
}

/// Which of each pair an opening selected, e.g. `Code/Sum`.
fn opened_slots(opened: &evoting::api::prelude::OpenedCai) -> String {
    use evoting::api::prelude::OpenedCaiValue;
    let name = |value: &OpenedCaiValue| match value {
        OpenedCaiValue::Code(_) => "Code",
        OpenedCaiValue::Sum(_) => "Sum",
    };
    format!("{}/{}", name(&opened.l1), name(&opened.l2))
}

/// V13: CAI disclosure verification + `cast_intended_proof` publication
/// (Sec. 3.8.4 steps 11-16).
#[tracing::instrument(skip(state, req))]
async fn cai_handler(
    Extension(state): Extension<Arc<BbState>>,
    Json(req): Json<CaiRequest>,
) -> Result<Json<CaiResponse>, BbError> {
    // THE SLOT IS TAKEN FIRST, in one critical section, before the (slow)
    // disclosure verification. Two confirmations of one ballot arriving
    // together must not both find the slot free: the two openings of one
    // ballot are `sum - code`, the vote (Sec. 3.8.4 steps 10-14, footnote 23
    // p. 82), and a board is append-only, so both would stand for good. Two
    // devices confirming at once is ordinary - Sec. 3.7.4 allows a voter more
    // than one - so the loser is told to retry and then takes the replay path
    // below, which answers with the slot the winner opened.
    // A disclosure that does not open THIS ballot never takes the slot: the
    // endpoint is anonymous and every disclosure is public on the board, so
    // a flood of copied ones would otherwise keep the slot busy and turn the
    // voter's own confirmation away. The check is done first, outside the
    // slot; one that does not open is refused before anything is held.
    let pre_opened = {
        let (ballot, held) = {
            let ballots = state.ballots.lock().await;
            let stored = ballots.get(&req.digest).ok_or(BbError::NotFound)?;
            (stored.record.ballot.clone(), stored.cai.is_some())
        };
        if held {
            None
        } else {
            let ctx = state.election_context.clone();
            let disclosure = req.disclosure.clone();
            let opened =
                tokio::task::spawn_blocking(move || ballot.open_cai_disclosure(&disclosure, &ctx))
                    .await
                    .map_err(|e| BbError::Internal(e.to_string()))?
                    .ok_or_else(|| BbError::BadRequest("CAI disclosure does not verify".into()))?;
            Some(opened)
        }
    };
    let (held, _confirming) = {
        let ballots = state.ballots.lock().await;
        let stored = ballots.get(&req.digest).ok_or(BbError::NotFound)?;
        let held = stored.cai.clone();
        let guard = if held.is_none() {
            let mut confirming = state.confirming.lock().await;
            if !confirming.insert(req.digest) {
                return Err(BbError::Conflict);
            }
            Some(InFlightGuard {
                set: state.confirming.clone(),
                digest: req.digest,
            })
        } else {
            None
        };
        (held, guard)
    };

    // Idempotent replay: this box opened this ballot once and will not open
    // it again, so the caller's disclosure is not even looked at - whether or
    // not the first publication was confirmed.
    if let Some(cai) = held {
        if !cai.published {
            // Confirmed here but never seen on the board: submit THE SAME
            // SIGNED BYTES again. The board keeps one leaf for them however
            // often they arrive, where a re-signed copy would take a second.
            state.submit_signed(&cai.submitted).await?;
            if let Some(stored) = state.ballots.lock().await.get_mut(&req.digest) {
                if let Some(held) = stored.cai.as_mut() {
                    held.published = true;
                }
            }
        }
        return Ok(Json(CaiResponse {
            digest: req.digest,
            confirmed_at_ms: cai.entry.confirmed_at_ms,
            opened: cai.entry.opened,
        }));
    }
    // A ballot whose digest this box has not seen on the board is not
    // confirmed: publish it first, or refuse (Sec. 3.8.4 step 6 - and a
    // confirmation for a digest no entry of this box carries reads as a box
    // that held a ballot and did not publish it).
    state.publish_pending_digest(&req.digest).await?;
    let ballot = {
        let ballots = state.ballots.lock().await;
        ballots
            .get(&req.digest)
            .ok_or(BbError::NotFound)?
            .record
            .ballot
            .clone()
    };
    let ballot_for_check = ballot.clone();
    // The disclosure was verified, and its values decoded, before the slot
    // was taken (steps 13-14).
    let opened = pre_opened.ok_or_else(|| {
        BbError::Internal("a confirmation reached the slot without its opening".into())
    })?;

    // Sec. 3.8.4 step 15 has the WBB PUBLISH divergent data, not suppress it,
    // so the board cannot refuse a second opening: whichever box wrote first
    // would then hold a veto over every other box's confirmation, and one
    // dishonest box (A9 allows one) could make any ballot disappear by
    // planting a bogus disclosure before the voter confirms.
    //
    // A BOX can tell the difference, because it holds the ballot. So it opens
    // every disclosure already published for this ballot against its own copy,
    // and refuses only when one VALIDLY opens the other slots - a plant that
    // does not open is ignored, and vetoes nothing.
    {
        let published = state.confirmed_on_board().await?;
        let ctx = state.election_context.clone();
        // EVERY published disclosure, whatever digest it states: the digest is
        // the publisher's to choose, so keying this check on it would let a
        // second opening be parked under another ballot's label and never
        // weighed against ours (Sec. 3.8.4 step 13 identifies the ballot from
        // the disclosure itself).
        let conflict = {
            let mut cache = state.opened_disclosures.lock().await;
            let mut conflict = None;
            for entry in &published {
                let Ok(key) = serde_json::to_vec(&entry.disclosure) else {
                    continue;
                };
                let opens = match cache.get(&key) {
                    Some(known) => *known,
                    None => {
                        // A disclosure seen for the first time: which of the
                        // ballots this box holds does it open? Once, then
                        // remembered.
                        let found = state.ballots.lock().await.iter().find_map(|(d, s)| {
                            s.record
                                .ballot
                                .open_cai_disclosure(&entry.disclosure, &ctx)
                                .map(|theirs| (*d, theirs))
                        });
                        cache.insert(key, found);
                        found
                    }
                };
                if let Some((digest, theirs)) = opens {
                    if digest == req.digest
                        && crate::protocol::tally::openings_reveal(&theirs, &opened)
                    {
                        conflict = Some(theirs);
                        break;
                    }
                }
            }
            let _ = &ballot_for_check;
            conflict
        };
        if let Some(theirs) = conflict {
            tracing::warn!(
                digest = %req.digest,
                already = %opened_slots(&theirs),
                "refusing to open a second slot of a ballot already opened on another"
            );
            return Err(BbError::BadRequest(
                concat!(
                    "this ballot is already opened on the other cast-as-intended values: ",
                    "opening both would reveal the vote"
                )
                .into(),
            ));
        }
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
        opened,
        confirmed_at_ms,
    };

    // Sign now, so the bytes that go on the board are the bytes this box
    // keeps: a retry resubmits exactly them.
    let data = wbb_data_string("voting", "BB", "cast_intended_proof", 1, &entry)
        .map_err(|e| BbError::Internal(e.to_string()))?;
    let submitted = state.sign_for_board(&data).await?;

    // Record the slot. An EXISTING record is never overwritten, whatever its
    // publication state: it is the opening this box already stands behind,
    // and the answer is that one.
    {
        let mut ballots = state.ballots.lock().await;
        let stored = ballots.get_mut(&req.digest).ok_or(BbError::NotFound)?;
        if let Some(existing) = &stored.cai {
            return Ok(Json(CaiResponse {
                digest: req.digest,
                confirmed_at_ms: existing.entry.confirmed_at_ms,
                opened: existing.entry.opened,
            }));
        }
        stored.cai = Some(HeldCai {
            entry: entry.clone(),
            submitted: submitted.clone(),
            published: false,
        });
    }

    match state.submit_signed(&submitted).await {
        Ok(()) => {
            if let Some(stored) = state.ballots.lock().await.get_mut(&req.digest) {
                if let Some(cai) = stored.cai.as_mut() {
                    cai.published = true;
                }
            }
        }
        // Sent but not confirmed: the disclosure may well be on the board, so
        // the record stays (a box that forgot it would not release the ballot
        // and would be named for withholding it) - marked unpublished, so a
        // later attempt tries again. The voter is told.
        Err(BbError::PublicationUnconfirmed) => {
            tracing::warn!(digest = %req.digest, "confirmation published but not confirmed");
            return Err(BbError::PublicationUnconfirmed);
        }
        Err(e) => {
            // A refusal is only a refusal if the entry is NOT on the board.
            // An answer of 4xx to a submission the board did in fact publish
            // would otherwise make this box forget an opening it had already
            // made public - and then open the OTHER slot on the next attempt,
            // which together with the first is the vote (Sec. 3.8.4 steps
            // 10-14). So the board is asked before the record is dropped, and
            // a board that cannot be read keeps it.
            let published = state.is_published(&data).await.unwrap_or_else(|_| {
                tracing::warn!(
                    "the board could not be read after a refused confirmation: keeping it"
                );
                true
            });
            if !published {
                if let Some(stored) = state.ballots.lock().await.get_mut(&req.digest) {
                    stored.cai = None;
                }
                return Err(e);
            }
            tracing::warn!(
                digest = %req.digest,
                "the board refused this confirmation but already carries it: keeping the record"
            );
            if let Some(stored) = state.ballots.lock().await.get_mut(&req.digest) {
                if let Some(cai) = stored.cai.as_mut() {
                    cai.published = true;
                }
            }
        }
    }

    Ok(Json(CaiResponse {
        digest: req.digest,
        confirmed_at_ms,
        opened,
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
        cai_confirmed: stored.cai.as_ref().is_some_and(|c| c.published),
    }))
}

/// Ballot release for the tally driver (Sec. 3.9 step 2; auth: service token).
///
/// Per Sec. 3.9 step 2 the BB "discards all the ballots for which no valid
/// cast-as-intended disclosure has been received": only ballots that a
/// disclosure on the board opens are released, whichever box published it.
async fn ballots_handler(
    Extension(state): Extension<Arc<BbState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<BallotRecord<G>>>, BbError> {
    require_bearer(&headers, &state.service_token)?;
    // THE RELEASE RULE (`crate::protocol::tally::release_set`, Sec. 3.9 steps
    // 2-3): a held ballot is released if and only if the board COUNTS its
    // digest and a disclosure on the board opens it to the values published -
    // the very rule the tally driver and the auditor apply, so a box releases
    // exactly its share of what will be counted. It is decided from ONE
    // reading of the board. The tally driver asks only once voting has closed,
    // when the voting-phase entries are final; asked earlier, the same rule
    // gives a partial answer, never a wrong one. Nothing is resubmitted and
    // nothing this box remembers having done enters. A reading that fails
    // fails the release: a shorter list would look exactly like an honest one.
    let phase = state
        .wbb_client
        .phase()
        .await
        .map_err(|e| BbError::BoardUnreachable(e.to_string()))?;
    if phase == "setup" || phase == "voting" {
        // Asked before the close: a partial answer, computed now, never kept.
        return compute_release(&state).await.map(Json);
    }
    // After the close: computed once, in the background, and kept. The
    // caller is told to ask again while it is being prepared - never handed
    // a shorter list, never left to time out.
    {
        let mut release = state.release.lock().await;
        match &*release {
            ReleaseState::Ready(records) => return Ok(Json(records.clone())),
            ReleaseState::Preparing => {}
            ReleaseState::NotStarted | ReleaseState::Failed(_) => {
                *release = ReleaseState::Preparing;
                let state = state.clone();
                tokio::spawn(async move {
                    let outcome = compute_release(&state).await;
                    let mut release = state.release.lock().await;
                    *release = match outcome {
                        Ok(records) => ReleaseState::Ready(records),
                        Err(e) => {
                            tracing::warn!("the release could not be prepared: {e}");
                            ReleaseState::Failed(e.to_string())
                        }
                    };
                });
            }
        }
    }
    // A release that is quick to prepare is answered in the same request.
    for _ in 0..20 {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        match &*state.release.lock().await {
            ReleaseState::Ready(records) => return Ok(Json(records.clone())),
            // A failed reading fails this request: never a shorter list.
            ReleaseState::Failed(why) => return Err(BbError::BoardUnreachable(why.clone())),
            _ => {}
        }
    }
    Err(BbError::ReleasePreparing)
}

/// One reading of the board, the release rule applied to it (see
/// `ballots_handler`).
async fn compute_release(state: &Arc<BbState>) -> Result<Vec<BallotRecord<G>>, BbError> {
    let board = state.board_reading().await?;
    let held: HashMap<BallotDigest, Ballot<G>> = state
        .ballots
        .lock()
        .await
        .iter()
        .map(|(digest, stored)| (*digest, stored.record.ballot.clone()))
        .collect();
    let ctx = state.election_context.clone();
    let released = tokio::task::spawn_blocking(move || {
        crate::protocol::tally::release_set(&held, &board, &ctx)
    })
    .await
    .map_err(|e| BbError::Internal(e.to_string()))?;
    let mut records: Vec<BallotRecord<G>> = state
        .ballots
        .lock()
        .await
        .iter()
        .filter(|(digest, _)| released.contains(*digest))
        .map(|(_, stored)| stored.record.clone())
        .collect();
    records.sort_by_key(|r| r.receipt.seq_no);
    Ok(records)
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

// -- Errors ------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
enum BbError {
    #[error("unauthorized")]
    Unauthorized,
    /// The post-voting release is still being computed: ask again.
    #[error("release in preparation - ask again shortly")]
    ReleasePreparing,
    #[error("not found")]
    NotFound,
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error(
        "the ballot was accepted and sent to the bulletin board, but this ballot box could \
         not confirm its publication in time - check the board, and cast again if it is not there"
    )]
    PublicationUnconfirmed,
    /// A cast of the same ballot is already in progress; retry to get the
    /// idempotent replay once it completes.
    #[error("cast in progress for this ballot, retry")]
    Conflict,
    /// The ballot could not be accepted because its digest could not be
    /// published on the WBB (e.g. the voting window is closed); nothing was
    /// stored.
    #[error("ballot not accepted: {0}")]
    NotAccepted(String),
    /// The board could not be read. Not this box's failure, and not silence
    /// either: the caller is told so, with the reason, so that a channel that
    /// an attacker is holding down is not read as a box withholding ballots
    /// (Sec. 3.9 step 2).
    #[error("the bulletin board could not be read from this ballot box: {0}")]
    BoardUnreachable(String),
    #[error("internal error: {0}")]
    Internal(String),
}

impl IntoResponse for BbError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, self.to_string()),
            Self::NotFound => (StatusCode::NOT_FOUND, self.to_string()),
            Self::BadRequest(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            Self::Conflict => (StatusCode::CONFLICT, self.to_string()),
            Self::NotAccepted(_) => (StatusCode::FORBIDDEN, self.to_string()),
            Self::PublicationUnconfirmed => (StatusCode::SERVICE_UNAVAILABLE, self.to_string()),
            Self::BoardUnreachable(_) => (StatusCode::SERVICE_UNAVAILABLE, self.to_string()),
            Self::ReleasePreparing => (StatusCode::ACCEPTED, self.to_string()),
            // Internal failures are logged but not leaked.
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

// -- Router / startup --------------------------------------------------------

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
    let actor_seed = load_actor_seed(&settings).await?;

    let ca_pem = tokio::fs::read_to_string(&settings.tls.ca_pem)
        .await
        .map_err(|e| anyhow::anyhow!("failed to read CA cert: {e}"))?;
    let http_client = reqwest_client_trusting_ca(&ca_pem)?;
    let wbb_client = WbbClient::new(
        http_client,
        reqwest::Url::parse(&settings.wbb.base_url)
            .map_err(|e| anyhow::anyhow!("invalid WBB URL: {e}"))?,
    );
    let er_key_path = ceremony_dir.join("er-verifying-key.bin");
    let er_verifying_key = tokio::fs::read(&er_key_path)
        .await
        .map_err(|e| anyhow::anyhow!("failed to read {}: {e}", er_key_path.display()))
        .and_then(|bytes| {
            let bytes: [u8; 32] = bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("the ER verifying key must be 32 bytes"))?;
            ed25519_dalek::VerifyingKey::from_bytes(&bytes)
                .map_err(|e| anyhow::anyhow!("invalid ER verifying key: {e}"))
        })?;

    let bb_id = bb_index_from_name(&settings.service.name)?;
    let state = Arc::new(BbState {
        entity_id: settings.service.name.to_uppercase(),
        bb_id,
        signing_key_seed: SecretString::new(hex::encode(signing_key.to_bytes())),
        service_token,
        actor_seed,
        election_context,
        wbb_client,
        er_verifying_key,
        clock: Arc::new(Mutex::new(Clock::from_settings(&settings.clock))),
        enc_counter: Arc::new(AtomicU64::new(0)),
        next_seq: Arc::new(AtomicU64::new(0)),
        ballots: Arc::new(Mutex::new(HashMap::new())),
        in_flight: Arc::new(Mutex::new(HashSet::new())),
        confirming: Arc::new(Mutex::new(HashSet::new())),
        opened_disclosures: Arc::new(Mutex::new(HashMap::new())),
        pending_publish: Arc::new(Mutex::new(HashMap::new())),
        release: Arc::new(Mutex::new(ReleaseState::NotStarted)),
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

/// Load this service's dedicated operation seed (`{name}-seed.bin`).
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
