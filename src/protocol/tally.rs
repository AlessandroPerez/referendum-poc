//! Tally pipeline primitives (Sec. 3.9).
//!
//! Framework-free helpers shared by the `election-admin tally` driver, the
//! TT server, and the `referendum-auditor`: TT share loading, ballot-release
//! reconciliation (the Sec. 3.8.5 bot filter), the WBB entry payloads of the
//! tallying phase, and counts extraction from the decrypted tally via the
//! D-mandated serde round-trip.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use dlog_group::group::{GroupPoint, GroupScalar};
use dlog_group::ristretto::RistrettoGroup;
use evoting::api::prelude::{
    CredentialControlProof, DecryptedFingerprintsBundle, DecryptedTally, EncrChoice, Receipt,
    TTSecretKeyShare, ThresholdDecOk, ThresholdFingerprints, ThresholdTabulationTeller,
    VerifiablePartialDecryption,
};
use evoting::api::server::bb::{BallotRecord, CredMixArtifact, VoteMixArtifact};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};

use crate::domain::BallotDigest;
use crate::protocol::voting::{ballot_digest, VotingError};

/// Convenience alias for the concrete group used throughout the PoC.
type G = RistrettoGroup;

/// Errors from the tally helpers.
#[derive(Debug, thiserror::Error)]
pub enum TallyError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("base64 error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("invalid scalar bytes in share file")]
    InvalidScalar,
    #[error("voting helper error: {0}")]
    Voting(#[from] VotingError),
    #[error("tally shape error: {0}")]
    Shape(String),
}

/// On-disk representation of a TT key share (matches the ceremony output).
#[derive(Debug, serde::Deserialize)]
struct TtShareFile {
    id: usize,
    meg_sk1_share: String,
    meg_sk2_share: String,
}

/// Load a single TT share from the JSON file written by the setup ceremony.
pub fn load_tt_share(path: &Path) -> Result<TTSecretKeyShare<G>, TallyError> {
    let bytes = std::fs::read(path)?;
    let file: TtShareFile = serde_json::from_slice(&bytes)?;

    let decode_scalar = |s: &str| -> Result<<G as GroupScalar>::Scalar, TallyError> {
        let bytes = BASE64.decode(s)?;
        <G as GroupScalar>::scalar_from_bytes(&bytes).ok_or(TallyError::InvalidScalar)
    };

    Ok(TTSecretKeyShare {
        id: file.id,
        meg_sk1_share: decode_scalar(&file.meg_sk1_share)?,
        meg_sk2_share: decode_scalar(&file.meg_sk2_share)?,
    })
}

/// Reconstruct an in-process `ThresholdTabulationTeller` from a saved share.
///
/// The TT secret stays distributed: each party only ever reconstructs its own
/// share inside its own process.
pub fn reconstruct_tt_teller(share: TTSecretKeyShare<G>) -> ThresholdTabulationTeller<G> {
    ThresholdTabulationTeller {
        id: share.id,
        share,
    }
}

/// Re-key the released records with the order the BULLETIN BOARD recorded:
/// the leaf index of the first `ballot_digest` entry for each ballot.
///
/// The `seq_no` a ballot box mints is its own unconstrained number, yet it
/// decides which of a voter's ballots the re-vote filter keeps (Sec. 3.9
/// step 3) and the order of the canonical copies. A single box could
/// therefore number its ballots backwards and silently make every voter's
/// FIRST ballot win - disabling re-voting, which is what carries coercion
/// resistance (Sec. 3.7). The board's own order is append-only, signed and
/// no single box's to choose, so the tally and the auditor both use it.
///
/// Records whose ballot no box published a digest entry for are dropped:
/// nothing on the board orders them (the auditor fails such a release).
/// The board's cast order: for each ballot, the LOWEST leaf index among the
/// acceptances published for it. `accepted` carries one `(leaf, digest)` pair
/// per `ballot_digest` entry the caller has already judged valid (signed by
/// the ballot box it names).
///
/// Taking the minimum is what makes a ballot box powerless here: it can only
/// ever publish an acceptance LATER, never earlier than an honest box.
pub fn board_cast_order(
    accepted: impl IntoIterator<Item = (u64, BallotDigest)>,
) -> HashMap<BallotDigest, u64> {
    let mut order: HashMap<BallotDigest, u64> = HashMap::new();
    for (leaf, digest) in accepted {
        order
            .entry(digest)
            .and_modify(|first| *first = (*first).min(leaf))
            .or_insert(leaf);
    }
    order
}

pub fn order_by_board(
    records: Vec<BallotRecord<G>>,
    board_order: &HashMap<BallotDigest, u64>,
) -> Result<Vec<BallotRecord<G>>, TallyError> {
    let mut ordered = Vec::with_capacity(records.len());
    for mut record in records {
        let digest = ballot_digest(&record.ballot)?;
        if let Some(position) = board_order.get(&digest) {
            record.receipt.seq_no = *position;
            ordered.push(record);
        }
    }
    Ok(ordered)
}

/// Reconcile the per-BB ballot releases into the canonical tally input
/// (Sec. 3.9 step 3, Sec. 3.8.5).
///
/// Callers must first re-key the records with [`order_by_board`]: the
/// `seq_no` field then holds the board's position, not a ballot box's own
/// number.
///
/// `counted` is the set of digests the BOARD says count: accepted and
/// confirmed by at least [`NO_BOT_MIN_BBS`] ballot boxes (the voter's "no bot"
/// rule of Sec. 3.8.5, decided from published entries, never from what a box
/// releases). A ballot in that set is counted as soon as ANY box releases it:
/// "the WBB publishes each ballot B for which a digest H(B) has been
/// published" (step 3). Requiring two RELEASED copies would let a single box
/// delete a ballot by withholding it, which is exactly what the thesis's A9
/// (at least one honest box) says the protocol must survive. The canonical
/// copy is the one released by the lowest-numbered box.
pub fn reconcile_ballots(
    per_bb: &[Vec<BallotRecord<G>>],
    counted: &HashSet<BallotDigest>,
) -> Result<Vec<BallotRecord<G>>, TallyError> {
    let mut digest_lists = Vec::with_capacity(per_bb.len());
    for list in per_bb {
        let mut digests = Vec::with_capacity(list.len());
        for record in list {
            digests.push((ballot_digest(&record.ballot)?, record.receipt));
        }
        digest_lists.push(digests);
    }
    Ok(reconcile_indices(&digest_lists, counted)
        .into_iter()
        .map(|(list, idx)| per_bb[list][idx].clone())
        .collect())
}

/// Digest-level reconciliation core (unit-testable without real ballots).
///
/// Returns `(bb_list_index, item_index)` of the canonical copy of every
/// digest in `counted` that at least one box released, in board order.
fn reconcile_indices(
    per_bb: &[Vec<(BallotDigest, Receipt)>],
    counted: &HashSet<BallotDigest>,
) -> Vec<(usize, usize)> {
    let mut by_digest: HashMap<BallotDigest, Vec<(usize, usize, Receipt)>> = HashMap::new();
    for (list_idx, list) in per_bb.iter().enumerate() {
        for (item_idx, (digest, receipt)) in list.iter().enumerate() {
            by_digest
                .entry(*digest)
                .or_default()
                .push((list_idx, item_idx, *receipt));
        }
    }

    let mut chosen = Vec::new();
    for (digest, copies) in by_digest {
        if !counted.contains(&digest) {
            // Not accepted and confirmed by enough boxes ON THE BOARD (a bot,
            // or never confirmed): a release alone does not make it count.
            continue;
        }
        let canonical = copies
            .into_iter()
            .min_by_key(|(_, _, r)| r.bb_id)
            .expect("non-empty copy list");
        chosen.push(canonical);
    }

    // Total order even when canonical copies come from different BBs (only
    // possible with n_BB > NO_BOT_MIN_BBS): the board order is unique per
    // ballot, so (position, bb_id) is a strict key.
    chosen.sort_by_key(|(_, _, r)| (r.seq_no, r.bb_id));
    chosen.into_iter().map(|(l, i, _)| (l, i)).collect()
}

// -- WBB entry payloads (tallying phase, Sec. 3.4.2 write policy) -----

/// Content of a `tallying,BB,encrypted_ballot,1,...` entry: one released
/// ballot with its receipt and `bb_id_enc` (full record).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct EncryptedBallotEntry {
    pub record: BallotRecord<G>,
}

/// A release a ballot box wrote to the board itself (Sec. 3.9 step 2: each
/// BB "sends to the WBB the remaining ballots"): its leaf, the box, the
/// record and the entry's `data` field as published.
pub struct BoardRelease {
    pub leaf: i64,
    pub bb_id: u64,
    pub record: BallotRecord<G>,
    pub data: String,
}

/// The identifier of one release entry in the tally's input: the SHA-256
/// (hex) of the entry's decoded `data`.
pub fn release_input_id(data: &[u8]) -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(data))
}

/// Every readable `encrypted_ballot` entry on the board signed by the box
/// its receipt names, in board order. A record a box signs for ANOTHER box
/// is nobody's release and is left out (the auditor names it).
pub fn board_releases(entries: &[(i64, serde_json::Value)]) -> Vec<BoardRelease> {
    use crate::protocol::voting::{parse_wbb_data, signed_by_ballot_box};
    let mut releases = Vec::new();
    for (leaf, entry) in entries {
        let Some(data) = entry.get("data").and_then(|d| d.as_str()) else {
            continue;
        };
        let Some(parsed) = BASE64
            .decode(data)
            .ok()
            .and_then(|bytes| parse_wbb_data(&bytes))
        else {
            continue;
        };
        if parsed.entry_type != "encrypted_ballot" {
            continue;
        }
        let Ok(release) = parsed.decode_payload::<EncryptedBallotEntry>() else {
            continue;
        };
        let bb_id = release.record.receipt.bb_id;
        if !signed_by_ballot_box(entry, bb_id) {
            continue;
        }
        releases.push(BoardRelease {
            leaf: *leaf,
            bb_id,
            record: release.record,
            data: data.to_string(),
        });
    }
    releases.sort_by_key(|r| r.leaf);
    releases
}

/// Content of a `tallying,TT,mixed_ballots,3,...` entry (one per mix).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", bound = "")]
pub enum MixedBallotsEntry {
    /// The Sec. 3.9 vote mix over the deduped verified votes.
    Votes { artifact: Box<VoteMixArtifact<G>> },
    /// The Sec. 3.9 credential mix over the eligible public credentials.
    Credentials { artifact: Box<CredMixArtifact<G>> },
}

/// Content of a `tallying,TT,re_encryption_proof,3,...` entry: the public
/// verification artifacts of one pipeline stage.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", bound = "")]
pub enum ReEncryptionProofEntry {
    /// Sec. 3.9 steps 5-10: the tellers' threshold blinding of the re-vote
    /// handles (shares, VSS commitments, interpolated fingerprints) + the
    /// threshold decryptions.
    OxFingerprints {
        fps: ThresholdFingerprints<G>,
        decryptions: Vec<ThresholdDecOk<G>>,
        /// The tally's input, fixed by its first artifact: `release_input_id`
        /// of every release entry the tally took in. A release any box writes
        /// later - or in the moment before this entry - is not part of it,
        /// and the auditor names it (Sec. 3.9 steps 2-3, Sec. 3.10 1(b)).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        inputs: Vec<String>,
    },
    /// Sec. 3.9 step 19: RT credential control proofs over the shuffled votes.
    /// Published by the registration tellers themselves, in a
    /// `tallying,RT,credential_control,2,...` entry (Sec. 3.4.2) - not under
    /// the tabulation tellers' `re_encryption_proof`.
    Controls {
        controls: Vec<CredentialControlProof<G>>,
    },
    /// Sec. 3.9 steps 20-22: the tellers' threshold blinding of the
    /// credential checks and the decryptions of the blinded checks. No
    /// scalar: the blinding exists only as the tellers' shares.
    AccChecks {
        acc_checks: Vec<ThresholdDecOk<G>>,
        blinding: ThresholdFingerprints<G>,
    },
    /// Sec. 3.9 steps 24-26: credential fingerprints (threshold blinding) +
    /// decryption bundle.
    CredentialFingerprints {
        fps: ThresholdFingerprints<G>,
        bundle: DecryptedFingerprintsBundle<G>,
    },
}

/// Content of a `tallying,TT,tally_result,3,...` entry - and the driver/auditor
/// counts type (Sec. 3.11: 0 = blank, 1 = Si, 2 = No).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TallyCounts {
    pub blank: u64,
    pub si: u64,
    pub no: u64,
}

/// Content of a `tallying,TT,tally_proof,3,...` entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct TallyProofEntry {
    pub enc_tally: EncrChoice<G>,
    pub decrypted: DecryptedTally<G>,
}

// -- Counts extraction (serde round-trip) -------------------------------

/// Extract the referendum counts from a `DecryptedTally` via the serde
/// round-trip: the first-level counters
/// `tally.l1[0..3]` are the per-option totals.
pub fn extract_counts(decrypted: &DecryptedTally<G>) -> Result<TallyCounts, TallyError> {
    counts_from_value(&serde_json::to_value(decrypted)?)
}

/// Counts extraction core over the serialized tally (unit-testable).
fn counts_from_value(value: &serde_json::Value) -> Result<TallyCounts, TallyError> {
    let l1 = value
        .get("tally")
        .and_then(|t| t.get("l1"))
        .and_then(|l| l.as_array())
        .ok_or_else(|| TallyError::Shape("decrypted tally has no tally.l1 array".into()))?;
    if l1.len() != 3 {
        return Err(TallyError::Shape(format!(
            "expected 3 first-level counters, got {}",
            l1.len()
        )));
    }
    let counter = |i: usize| -> Result<u64, TallyError> {
        l1[i]
            .as_u64()
            .ok_or_else(|| TallyError::Shape(format!("tally.l1[{i}] is not a u64")))
    };
    Ok(TallyCounts {
        blank: counter(0)?,
        si: counter(1)?,
        no: counter(2)?,
    })
}

/// Derive the deterministic tally-driver RNG (mixes, fingerprint blinding)
/// from the TT operation seeds (`tt-{i}-seed.bin`) - the
/// `acc_rng_from_seeds` precedent, decoupled from WBB signing keys.
pub fn tally_rng_from_seeds(seeds: &[[u8; 32]]) -> ChaCha20Rng {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for seed in seeds {
        hasher.update(seed);
    }
    hasher.update(b"tally-driver");
    ChaCha20Rng::from_seed(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(tag: u8) -> BallotDigest {
        BallotDigest::from_bytes([tag; 32])
    }

    /// A ballot and both genuine disclosures of it - the two the voter's app
    /// holds between casting and confirming (Sec. 3.8.4 steps 9-11), before
    /// it pins one and destroys the other. Built exactly as the app builds
    /// them: twice from the same RNG state, so the ballot is the same and the
    /// openings are of the code slots and then of the sum slots.
    /// One election, and for each option a ballot with BOTH genuine
    /// disclosures of it - the two the voter's app holds between casting and
    /// confirming (Sec. 3.8.4 steps 9-11), before it pins one and destroys
    /// the other. Built exactly as the app builds them: twice from the same
    /// RNG state, so the ballot is the same and the openings are of the code
    /// slots and then of the sum slots.
    type BallotWithBothDisclosures = (
        evoting::api::prelude::Ballot<G>,
        evoting::api::prelude::DiscloseCAI<G>,
        evoting::api::prelude::DiscloseCAI<G>,
    );

    fn ballots_with_both_disclosures(
        options: &[crate::domain::ReferendumOption],
    ) -> (
        evoting::api::server::bb::ElectionContext<G>,
        Vec<BallotWithBothDisclosures>,
    ) {
        use crate::configuration::ElectionSettings;
        use crate::protocol::acc::generate_credentials;
        use crate::protocol::setup::run_ceremony;
        use rand::SeedableRng as _;

        let settings = ElectionSettings {
            n_rt: 3,
            t_rt: 2,
            n_tt: 3,
            t_tt: 2,
            n_bb: 2,
            n_voters: 2,
            n_acc: 2,
            t_prime: 2,
            max_casts_per_voter: 10,
            casting_token_ttl_s: 600,
            min_cast_interval_s: 0,
            tau_min_s: 2,
            tau_max_s: 5,
        };
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([0x5a; 32]);
        let ceremony = run_ceremony(&settings, &mut rng).expect("ceremony");
        let context = ceremony.election_context.clone();
        let mut tellers = ceremony.rt_tellers;
        let (packages, _) = generate_credentials(
            settings.n_acc,
            settings.t_rt,
            settings.t_prime,
            &mut tellers,
            &context,
            &ceremony.rt_pk,
            &mut rng,
        )
        .expect("credentials");

        let package = packages.into_iter().next().expect("one package");
        let (builder, pin, _public) = evoting::api::prelude::voter_build_acc(
            &context.pk,
            &ceremony.rt_pk,
            package.a,
            package.enc_a_ext.clone().into(),
            &package.share_broadcasts,
            &mut rng,
        );
        // A simulated credential builds a real ballot with real
        // cast-as-intended values; only the tally filters it.
        let voter = evoting::api::client::VoterBuilder::new(&context, builder, &mut rng)
            .simulate(pin, &mut rng)
            .expect("voter");

        let mut out = Vec::with_capacity(options.len());
        for option in options {
            let choice = crate::protocol::voting::referendum_choice(*option, &context.choice)
                .expect("choice");
            let ballot_builder = evoting::api::client::BallotBuilder::new(choice);
            let mut replay_rng = rng.clone();
            let (ballot, all_code, _control) =
                voter.vote_with_cai_values(&ballot_builder, pin, true, true, &mut rng);
            let (_replayed, all_sum) =
                voter.vote_with_disclosure(&ballot_builder, pin, false, false, &mut replay_rng);
            out.push((ballot, all_code, all_sum));
        }
        (context, out)
    }

    /// Sec. 3.8.4 steps 10-14: the two slots of the option level together are
    /// `sum - code`, the vote. A ballot box holds the ballot, so it can weigh
    /// a disclosure it is offered against the ones already published - and it
    /// must do so by what they OPEN, not by the digest their publisher chose
    /// to state beside them.
    #[test]
    fn a_box_refuses_the_opening_that_completes_a_published_one() {
        use crate::domain::ReferendumOption;
        let (context, ballots) =
            ballots_with_both_disclosures(&[ReferendumOption::Reject, ReferendumOption::Approve]);
        let (ballot, all_code, all_sum) = &ballots[0];
        let (_other, other_code, _) = &ballots[1];
        let code = ballot
            .open_cai_disclosure(all_code, &context)
            .expect("the code disclosure opens its own ballot");
        let sum = ballot
            .open_cai_disclosure(all_sum, &context)
            .expect("the sum disclosure opens its own ballot");
        assert_ne!(code, sum);

        // The second opening of the same ballot is refused ...
        assert!(
            opening_would_reveal(ballot, &sum, [all_code], &context).is_some(),
            "a box published the code slot and must refuse the sum slot"
        );
        // ... and the SAME one is not: a retry is not a second opening.
        assert!(
            opening_would_reveal(ballot, &code, [all_code], &context).is_none(),
            "a box must not refuse the disclosure it already published"
        );
        // A disclosure that does not open this ballot vetoes nothing
        // (Sec. 3.8.4 step 15 publishes divergent data, it does not suppress).
        assert!(
            opening_would_reveal(ballot, &sum, [other_code], &context).is_none(),
            "a plant that opens nothing here must not veto an honest confirmation"
        );
    }

    fn slot_value_of(value: &evoting::api::prelude::OpenedCaiValue) -> u32 {
        match value {
            evoting::api::prelude::OpenedCaiValue::Code(v)
            | evoting::api::prelude::OpenedCaiValue::Sum(v) => *v,
        }
    }

    /// Sec. 3.9 step 5 discards a released record whose proofs do not verify,
    /// and Sec. 3.10 1(d) re-opens disclosures "against the released
    /// BALLOTS". A dishonest box (A9 allows one) that releases a record of its
    /// own making whose two option ciphertexts are EQUAL, and publishes one
    /// disclosure under both tags, has produced two "openings" of a thing that
    /// is not a ballot: nothing is revealed and the election's audit must not
    /// fail over it. The box is named instead.
    #[test]
    fn a_record_that_is_not_a_ballot_cannot_be_revealed() {
        use crate::domain::ReferendumOption;
        use crate::protocol::voting::CaiEntry;

        let (context, ballots) = ballots_with_both_disclosures(&[ReferendumOption::Reject]);
        let (ballot, all_code, _all_sum) = ballots[0].clone();

        // The record: the real ballot with its l1 SUM ciphertext replaced by
        // its l1 CODE ciphertext, built through the serialized form because
        // that is what a box publishes.
        fn equalise_l1(value: &mut serde_json::Value) {
            match value {
                serde_json::Value::Object(map) => {
                    if map.contains_key("l1_code_enc") && map.contains_key("l1_sum_enc") {
                        let code = map["l1_code_enc"].clone();
                        map.insert("l1_sum_enc".to_string(), code);
                    }
                    for v in map.values_mut() {
                        equalise_l1(v);
                    }
                }
                serde_json::Value::Array(items) => items.iter_mut().for_each(equalise_l1),
                _ => {}
            }
        }
        let mut record_json = serde_json::to_value(&ballot).expect("ballot json");
        equalise_l1(&mut record_json);
        let record: evoting::api::prelude::Ballot<G> =
            serde_json::from_value(record_json).expect("record");
        assert!(
            record.verify(&context).is_err(),
            "the manufactured record must not verify as a ballot"
        );
        let digest = crate::protocol::voting::ballot_digest(&record).expect("digest");

        // The same disclosure twice: once as it is (Code), once retagged Sum.
        let mut retagged = serde_json::to_value(&all_code).expect("disclosure json");
        let l1 = retagged["l1"].take();
        retagged["l1"] = serde_json::json!({ "Sum": l1["Code"].clone() });
        let as_sum: evoting::api::prelude::DiscloseCAI<G> =
            serde_json::from_value(retagged).expect("retagged disclosure");
        let opened_code = record
            .open_cai_disclosure(&all_code, &context)
            .expect("the record opens under the Code tag");
        let opened_sum = record
            .open_cai_disclosure(&as_sum, &context)
            .expect("and under the Sum tag, because the two ciphertexts are equal");

        let released: HashMap<_, _> = [(digest, record)].into_iter().collect();
        let entry = |disclosure, opened| CaiEntry {
            digest,
            bb_id: 2,
            disclosure,
            opened,
            confirmed_at_ms: 1,
        };
        let check = valid_disclosures(
            &released,
            &[entry(all_code, opened_code), entry(as_sum, opened_sum)],
            &context,
        );
        assert!(
            check.revealed.is_empty(),
            "a record that is not a ballot must not fail the audit as a revealed vote: {check:?}"
        );
        assert_eq!(check.not_ballots, vec![digest], "{check:?}");
        assert!(check.valid.is_empty(), "{check:?}");
    }

    /// A released record that shares a real ballot's cast-as-intended
    /// ciphertexts but is not a ballot (here: the ballot with its election
    /// context hash flipped) OPENS under the ballot's own disclosures. A box
    /// that releases such a record and states ITS digest on a second genuine
    /// opening of the ballot must not have parked that opening out of reach:
    /// the disclosure is identified among the BALLOTS, the reveal is found,
    /// and the junk record is named.
    #[test]
    fn a_second_opening_parked_under_a_junk_record_is_still_found() {
        use crate::domain::ReferendumOption;
        use crate::protocol::voting::CaiEntry;

        let (context, ballots) = ballots_with_both_disclosures(&[ReferendumOption::Reject]);
        let (ballot, all_code, all_sum) = ballots[0].clone();
        let digest = crate::protocol::voting::ballot_digest(&ballot).expect("digest");

        let mut junk_json = serde_json::to_value(&ballot).expect("json");
        let first = junk_json["election_ctx"][0].as_u64().expect("ctx byte");
        junk_json["election_ctx"][0] = serde_json::json!((first + 1) % 256);
        let junk: evoting::api::prelude::Ballot<G> =
            serde_json::from_value(junk_json).expect("junk record");
        assert!(
            junk.verify(&context).is_err(),
            "the junk must not be a ballot"
        );
        let junk_digest = crate::protocol::voting::ballot_digest(&junk).expect("digest");
        assert_ne!(junk_digest, digest);
        let sum_opened = junk
            .open_cai_disclosure(&all_sum, &context)
            .expect("the ballot's disclosures open the junk too");

        let released: HashMap<_, _> = [(digest, ballot.clone()), (junk_digest, junk)]
            .into_iter()
            .collect();
        let honest = CaiEntry {
            digest,
            bb_id: 1,
            disclosure: all_code.clone(),
            opened: ballot
                .open_cai_disclosure(&all_code, &context)
                .expect("opens"),
            confirmed_at_ms: 1,
        };
        let parked = CaiEntry {
            digest: junk_digest,
            bb_id: 2,
            disclosure: all_sum,
            opened: sum_opened,
            confirmed_at_ms: 2,
        };
        let check = valid_disclosures(&released, &[honest, parked], &context);
        assert_eq!(
            check.revealed.len(),
            1,
            "the second opening of the real ballot must be weighed against it: {check:?}"
        );
        assert_eq!(check.not_ballots, vec![junk_digest], "{check:?}");
    }

    /// `sum - code = 0` is the BLANK ballot, one of the three results this
    /// election publishes, so two openings of the option level give the vote
    /// away even when the two numbers are equal.
    #[test]
    fn both_openings_of_a_blank_ballot_reveal_it_too() {
        let (context, ballots) =
            ballots_with_both_disclosures(&[crate::domain::ReferendumOption::Blank]);
        let (ballot, all_code, all_sum) = &ballots[0];
        let code = ballot
            .open_cai_disclosure(all_code, &context)
            .expect("code opens");
        let sum = ballot
            .open_cai_disclosure(all_sum, &context)
            .expect("sum opens");
        assert_eq!(
            slot_value_of(&code.l1),
            slot_value_of(&sum.l1),
            "a blank ballot opens both option slots to the same number"
        );
        assert!(
            opening_would_reveal(ballot, &sum, [all_code], &context).is_some(),
            "the difference is zero, and zero is the blank vote"
        );
    }

    /// Sec. 3.8.4 step 13 identifies the ballot FROM the disclosure: "each
    /// trusted BB uses the first three values of the tuple to compute idB and
    /// identify the pertinent ballot", and step 14 DERIVES the published
    /// `H(B)` from the ballot found. So a box that parks a second genuine
    /// opening under ANOTHER released ballot's digest hides nothing: the
    /// verifier still weighs it against the ballot it really opens, and a
    /// ballot whose secrecy is gone FAILS the audit.
    /// The release rule (`release_set`, Sec. 3.9 steps 2-3), case by case:
    /// a held ballot is released iff the board counts its digest (from
    /// whichever box) and a published disclosure opens it to the values
    /// published with it.
    #[test]
    fn the_release_rule_follows_the_board_and_nothing_else() {
        use crate::domain::ReferendumOption;
        use crate::protocol::voting::CaiEntry;
        let (context, ballots) =
            ballots_with_both_disclosures(&[ReferendumOption::Reject, ReferendumOption::Approve]);
        let (ballot, code, _) = ballots[0].clone();
        let (other, other_code, _) = ballots[1].clone();
        let digest = crate::protocol::voting::ballot_digest(&ballot).expect("digest");
        let other_digest = crate::protocol::voting::ballot_digest(&other).expect("digest");
        let held: HashMap<_, _> = [(digest, ballot.clone()), (other_digest, other.clone())]
            .into_iter()
            .collect();
        let confirmation = |bb_id: u64, stated: BallotDigest| CaiEntry {
            digest: stated,
            bb_id,
            disclosure: code.clone(),
            opened: ballot.open_cai_disclosure(&code, &context).expect("opens"),
            confirmed_at_ms: 1,
        };
        let board = |counted: &[BallotDigest], confirmations: Vec<CaiEntry>| BoardBallots {
            counted: counted.iter().copied().collect(),
            publishers: counted.iter().map(|d| (*d, vec![2])).collect(),
            confirmations,
        };
        let released = |b: &BoardBallots| release_set(&held, b, &context);

        // Counted on the board - digest and confirmation by ANOTHER box: released.
        assert_eq!(
            released(&board(&[digest], vec![confirmation(2, digest)])),
            [digest].into_iter().collect(),
            "a counted ballot is released whichever box published it"
        );
        // The confirmation filed under another digest still opens THIS ballot.
        assert_eq!(
            released(&board(&[digest], vec![confirmation(2, other_digest)])),
            [digest].into_iter().collect(),
            "the ballot is identified from the disclosure"
        );
        // Not counted on the board: never released, whatever is held.
        assert!(released(&board(&[], vec![confirmation(2, digest)])).is_empty());
        // Values that are not what the disclosure opens: not released.
        let mut wrong = confirmation(2, digest);
        wrong.opened = other
            .open_cai_disclosure(&other_code, &context)
            .expect("opens");
        assert!(
            released(&board(&[digest], vec![wrong])).is_empty(),
            "published values the ballot does not open release nothing"
        );
        // Another ballot's disclosure opens only that ballot.
        let theirs = CaiEntry {
            digest,
            bb_id: 2,
            disclosure: other_code.clone(),
            opened: other
                .open_cai_disclosure(&other_code, &context)
                .expect("opens"),
            confirmed_at_ms: 1,
        };
        assert_eq!(
            released(&board(&[digest, other_digest], vec![theirs])),
            [other_digest].into_iter().collect(),
            "a disclosure releases the ballot it opens, not the one it names"
        );
    }

    #[test]
    fn a_second_opening_is_found_under_whatever_digest_it_is_parked() {
        use crate::protocol::voting::CaiEntry;

        use crate::domain::ReferendumOption;
        let (context, ballots) =
            ballots_with_both_disclosures(&[ReferendumOption::Reject, ReferendumOption::Approve]);
        let (ballot, all_code, all_sum) = ballots[0].clone();
        let (other, other_code, _) = ballots[1].clone();
        let digest = crate::protocol::voting::ballot_digest(&ballot).expect("digest");
        let other_digest = crate::protocol::voting::ballot_digest(&other).expect("digest");
        let released: HashMap<_, _> = [(digest, ballot.clone()), (other_digest, other.clone())]
            .into_iter()
            .collect();
        let entry = |bb_id: u64,
                     stated: BallotDigest,
                     disclosure: &evoting::api::prelude::DiscloseCAI<G>,
                     on: &evoting::api::prelude::Ballot<G>| CaiEntry {
            digest: stated,
            bb_id,
            disclosure: disclosure.clone(),
            opened: on
                .open_cai_disclosure(disclosure, &context)
                .expect("opens its own ballot"),
            confirmed_at_ms: 1,
        };

        // The honest confirmation, plus the SAME ballot's other opening
        // published by a second box under the OTHER released ballot's digest.
        let honest = entry(1, digest, &all_code, &ballot);
        let parked = CaiEntry {
            digest: other_digest,
            ..entry(2, digest, &all_sum, &ballot)
        };
        let check = valid_disclosures(&released, &[honest.clone(), parked], &context);
        assert_eq!(
            check.revealed.len(),
            1,
            "the two openings of one ballot must be weighed against each other, \
             whatever digest the second states: {check:?}"
        );
        assert!(
            check
                .misconduct
                .iter()
                .any(|note| note.contains("under another digest")),
            "and the box that parked it must be named: {check:?}"
        );

        // A control: the honest confirmation alone leaves the ballot valid and
        // accuses nobody. The other box's own ballot is released too.
        let clean = valid_disclosures(
            &released,
            &[honest, entry(2, other_digest, &other_code, &other)],
            &context,
        );
        assert!(clean.revealed.is_empty(), "{clean:?}");
        assert!(clean.misconduct.is_empty(), "{clean:?}");
        assert_eq!(clean.valid.len(), 2);
    }

    #[test]
    fn the_board_order_is_the_first_acceptance_of_each_ballot() {
        // Two boxes accept two ballots; box 2 is slow on the first and
        // publishes an extra, later entry for the second.
        let order = board_cast_order([
            (7, digest(1)),
            (9, digest(2)),
            (11, digest(1)),
            (12, digest(2)),
            (13, digest(2)),
        ]);
        assert_eq!(order[&digest(1)], 7);
        assert_eq!(order[&digest(2)], 9);
        assert!(board_cast_order([]).is_empty());
    }

    fn receipt(seq_no: u64, bb_id: u64) -> Receipt {
        Receipt {
            seq_no,
            received_at_unix_ms: 1_700_000_000_000 + seq_no,
            bb_id,
        }
    }

    fn counted(tags: &[u8]) -> HashSet<BallotDigest> {
        tags.iter().map(|t| digest(*t)).collect()
    }

    #[test]
    fn reconcile_keeps_only_what_the_board_counts() {
        // Digest 1 counts on the board; digest 2 was released by BB-2 but the
        // board never saw it accepted and confirmed by enough boxes.
        let bb1 = vec![(digest(1), receipt(0, 1))];
        let bb2 = vec![(digest(1), receipt(0, 2)), (digest(2), receipt(1, 2))];
        let chosen = reconcile_indices(&[bb1, bb2], &counted(&[1]));
        assert_eq!(
            chosen,
            vec![(0, 0)],
            "a release alone does not make a ballot count"
        );
    }

    #[test]
    fn reconcile_counts_a_ballot_one_box_withheld() {
        // Both ballots count on the board. BB-2 released only the second one:
        // the first is counted from BB-1's copy (Sec. 3.9 step 3; A9).
        let bb1 = vec![(digest(1), receipt(0, 1)), (digest(2), receipt(1, 1))];
        let bb2 = vec![(digest(2), receipt(1, 2))];
        let chosen = reconcile_indices(&[bb1, bb2], &counted(&[1, 2]));
        assert_eq!(chosen, vec![(0, 0), (0, 1)]);
        // And the other way round: the ballot BB-1 withheld comes from BB-2.
        let bb1 = vec![(digest(2), receipt(1, 1))];
        let bb2 = vec![(digest(1), receipt(0, 2)), (digest(2), receipt(1, 2))];
        let chosen = reconcile_indices(&[bb1, bb2], &counted(&[1, 2]));
        assert_eq!(chosen, vec![(1, 0), (0, 0)]);
    }

    #[test]
    fn reconcile_prefers_lowest_bb_and_orders_by_the_board() {
        // Two counted ballots; BB-2 saw them in a different order.
        let bb1 = vec![(digest(1), receipt(0, 1)), (digest(2), receipt(1, 1))];
        let bb2 = vec![(digest(2), receipt(0, 2)), (digest(1), receipt(1, 2))];
        let chosen = reconcile_indices(&[bb1, bb2], &counted(&[1, 2]));
        // Canonical copies come from BB-1 (list 0), in board order.
        assert_eq!(chosen, vec![(0, 0), (0, 1)]);
    }

    #[test]
    fn reconcile_ignores_what_no_box_released() {
        // Counted on the board, released by nobody: nothing to reconcile
        // (the callers refuse to tally in that case).
        let bb1: Vec<(BallotDigest, Receipt)> = Vec::new();
        let bb2: Vec<(BallotDigest, Receipt)> = Vec::new();
        assert!(reconcile_indices(&[bb1, bb2], &counted(&[1])).is_empty());
    }

    #[test]
    fn counts_extraction_reads_first_level_totals() {
        let value = serde_json::json!({
            "tally": { "l1": [1, 4, 2], "l2": [[1], [4], [2]] },
            "l1_d": [],
            "l2_d": [],
        });
        let counts = counts_from_value(&value).unwrap();
        assert_eq!(
            counts,
            TallyCounts {
                blank: 1,
                si: 4,
                no: 2
            }
        );
    }

    #[test]
    fn counts_extraction_rejects_wrong_shape() {
        let value = serde_json::json!({ "tally": { "l1": [1, 4] } });
        assert!(counts_from_value(&value).is_err());
    }
}

// ---------------------------------------------------------------------------
// Tabulation tellers' public key shares (Sec. 3.5.2, Protocol 12).
// ---------------------------------------------------------------------------

/// One tabulation teller's public key share H_i = sk1_i G1 + sk2_i G2, a
/// public output of the key generation. Published at setup so that every
/// threshold decryption can be bound to the teller that produced it, not to
/// a key the partial itself declares.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TellerPublicShare {
    pub id: usize,
    #[serde(with = "dlog_group::serde::PointHelper::<RistrettoGroup>")]
    pub h: <RistrettoGroup as GroupPoint>::Point,
}

/// Lagrange basis coefficient lambda_i(0) over `participants` in the scalar field.
pub fn lagrange_basis_at_zero(
    i: usize,
    participants: &[usize],
) -> <RistrettoGroup as GroupScalar>::Scalar {
    let mut num = <RistrettoGroup as GroupScalar>::Scalar::from(1u64);
    let mut den = <RistrettoGroup as GroupScalar>::Scalar::from(1u64);
    let i_scalar = <RistrettoGroup as GroupScalar>::Scalar::from(i as u64);
    for &j in participants {
        if j != i {
            let j_scalar = <RistrettoGroup as GroupScalar>::Scalar::from(j as u64);
            num *= j_scalar;
            den *= j_scalar - i_scalar;
        }
    }
    num * RistrettoGroup::scalar_inv(den)
}

/// The published shares are the tellers' iff there is exactly one per
/// teller `1..=n` and EVERY `t`-subset of them interpolates at 0 to the
/// election master key: a list that merely has some t shares summing right
/// could hide a wrong share among the others.
pub fn teller_shares_bind_to_master(
    shares: &[TellerPublicShare],
    master_h: &<RistrettoGroup as GroupPoint>::Point,
    n: usize,
    t: usize,
) -> Result<(), String> {
    let ids: Vec<usize> = shares.iter().map(|share| share.id).collect();
    let distinct: HashSet<usize> = ids.iter().copied().collect();
    if ids.len() != n || distinct.len() != n || ids.iter().any(|&id| id == 0 || id > n) {
        return Err(format!(
            "expected one public share per teller 1..={n}, got ids {ids:?}"
        ));
    }
    if t == 0 || t > n {
        return Err(format!("threshold {t} out of range for {n} tellers"));
    }
    for subset in t_subsets(n, t) {
        let mut sum = RistrettoGroup::identity();
        for &id in &subset {
            let share = shares
                .iter()
                .find(|share| share.id == id)
                .expect("id present");
            sum += share.h * lagrange_basis_at_zero(id, &subset);
        }
        if sum != *master_h {
            return Err(format!(
                "the public shares of tellers {subset:?} do not interpolate to the election key"
            ));
        }
    }
    Ok(())
}

/// Every `t`-element subset of `1..=n`, in lexicographic order.
pub fn t_subsets(n: usize, t: usize) -> Vec<Vec<usize>> {
    let mut out = Vec::new();
    let mut current = Vec::with_capacity(t);
    fn go(start: usize, n: usize, t: usize, current: &mut Vec<usize>, out: &mut Vec<Vec<usize>>) {
        if current.len() == t {
            out.push(current.clone());
            return;
        }
        for id in start..=n {
            current.push(id);
            go(id + 1, n, t, current, out);
            current.pop();
        }
    }
    go(1, n, t, &mut current, &mut out);
    out
}

/// Bind one teller's partial decryptions to the ciphertexts they answer and
/// to the teller's published share: one partial per ciphertext, every one
/// from `expected_id`, each verifying on its own (key share, proof, and the
/// share the proof covers - `VerifiablePartialDecryption::verify`). The
/// error names the teller.
pub fn partials_are_the_tellers(
    expected_id: usize,
    partials: &[VerifiablePartialDecryption<G>],
    ciphertexts: &[dlog_sigma_primitives::elgamal::ciphertext::Ciphertext<G>],
    params: &evoting::api::prelude::ElectionParams<G>,
) -> Result<(), String> {
    if partials.len() != ciphertexts.len() {
        return Err(format!(
            "TT-{expected_id} returned {} partial decryptions for {} ciphertexts",
            partials.len(),
            ciphertexts.len()
        ));
    }
    for (i, (partial, ct)) in partials.iter().zip(ciphertexts).enumerate() {
        if partial.from_id != expected_id {
            return Err(format!(
                "TT-{expected_id} returned partial decryption {i} in the name of TT-{}",
                partial.from_id
            ));
        }
        partial.verify(params, ct).map_err(|_| {
            format!(
                "TT-{expected_id} returned partial decryption {i} that does not verify: not \
                 under its published share, a proof that fails, or a share the proof does not cover"
            )
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod teller_share_tests {
    use super::*;

    fn shares_for(secrets: &[(usize, u64)]) -> Vec<TellerPublicShare> {
        secrets
            .iter()
            .map(|&(id, x)| TellerPublicShare {
                id,
                h: RistrettoGroup::generator() * <RistrettoGroup as GroupScalar>::Scalar::from(x),
            })
            .collect()
    }

    /// Shares of the polynomial f(x) = 7 + 5x: f(1)=12, f(2)=17, f(3)=22,
    /// master f(0) = 7.
    #[test]
    fn shares_on_one_polynomial_bind_to_the_master_key() {
        let shares = shares_for(&[(1, 12), (2, 17), (3, 22)]);
        let master =
            RistrettoGroup::generator() * <RistrettoGroup as GroupScalar>::Scalar::from(7u64);
        assert!(teller_shares_bind_to_master(&shares, &master, 3, 2).is_ok());
    }

    #[test]
    fn one_wrong_share_is_refused_even_when_some_pair_still_interpolates() {
        // Tellers 1 and 2 interpolate to 7; teller 3 is off the polynomial.
        let shares = shares_for(&[(1, 12), (2, 17), (3, 23)]);
        let master =
            RistrettoGroup::generator() * <RistrettoGroup as GroupScalar>::Scalar::from(7u64);
        let err = teller_shares_bind_to_master(&shares, &master, 3, 2).unwrap_err();
        assert!(err.contains("[1, 3]") || err.contains("[2, 3]"), "{err}");
        // A missing or repeated teller is refused too.
        let two = shares_for(&[(1, 12), (2, 17)]);
        assert!(teller_shares_bind_to_master(&two, &master, 3, 2).is_err());
        let twice = shares_for(&[(1, 12), (2, 17), (2, 17)]);
        assert!(teller_shares_bind_to_master(&twice, &master, 3, 2).is_err());
    }
}

// ---------------------------------------------------------------------------
// Cast-as-intended disclosures at tally (Sec. 3.9 step 5, Sec. 3.10 1(d)).
// ---------------------------------------------------------------------------

/// Which released ballots carry a VALID published disclosure, and what the
/// boxes did wrong along the way.
#[derive(Debug, Default)]
pub struct DisclosureCheck {
    /// Digests for which at least one published disclosure opens on the
    /// released ballot to the very values the box published.
    pub valid: HashSet<BallotDigest>,
    /// Attributed misconduct: a box whose published disclosure does not
    /// verify, or shows values the ballot does not open to.
    pub misconduct: Vec<String>,
    /// Two DIFFERENT cast-as-intended slots opened for one ballot, by
    /// whichever boxes. The two together are `sum - code`, the vote, and a
    /// leaf cannot be taken back: this is not one box's word against another
    /// but a ballot whose secrecy is gone, so it FAILS the audit rather than
    /// warning (Sec. 3.8.4 steps 10-14).
    pub revealed: Vec<String>,
    /// Released records that are NOT ballots: their Sec. 3.8.2 proofs do not
    /// verify. Sec. 3.8.4 step 13 identifies "the pertinent BALLOT" and
    /// Sec. 3.10 1(d) re-opens disclosures "against the released ballots", so
    /// such a record can neither count nor be REVEALED - a box could
    /// otherwise release a record of its own making whose two option
    /// ciphertexts are equal, publish one disclosure under both tags, and
    /// have a clean election's audit FAIL over a ballot that never existed
    /// (A9 gives one box no such veto). The callers name the box that
    /// released each of these.
    pub not_ballots: Vec<BallotDigest>,
    /// Confirmations for a ballot NO box released. Nothing can be checked
    /// against them, so they are not misconduct: a box whose board channel
    /// failed leaves exactly this trace. But they are not silence either -
    /// a box can manufacture a public "this ballot was confirmed" for a
    /// ballot that does not exist, and the record must show it
    /// (Sec. 3.10 1(c)-(d)).
    pub unaccounted: Vec<String>,
}

/// Re-open every published disclosure on its released ballot. A ballot
/// counts on ONE valid disclosure, whichever box published it (Sec. 3.8.4
/// step 15 publishes what every box sends; Sec. 3.10 1(d) discards only
/// ballots with no valid disclosure). A box publishing an invalid one is
/// named, and changes nothing for a ballot another box vouches for.
pub fn valid_disclosures(
    released: &HashMap<BallotDigest, evoting::api::prelude::Ballot<G>>,
    confirmations: &[crate::protocol::voting::CaiEntry],
    context: &evoting::api::server::bb::ElectionContext<G>,
) -> DisclosureCheck {
    let mut check = DisclosureCheck::default();
    // Only records that ARE ballots take part (see `not_ballots`) - but a
    // record is asked to be one LAZILY, when a disclosure actually opens it.
    // The check is the whole ballot proof, and a box may release as many
    // junk records as it likes: a record no disclosure refers to costs the
    // verifier nothing, and one that some disclosure opens is verified once.
    let released: HashMap<BallotDigest, &evoting::api::prelude::Ballot<G>> =
        released.iter().map(|(d, b)| (*d, b)).collect();
    // Whether each released record IS a ballot, asked once and only for a
    // record some disclosure opens. A record that opens but is not a ballot
    // is set aside (`not_ballots`) and the disclosure goes on to be
    // identified among the BALLOTS - it must never be a place where a second
    // opening of a real ballot can be parked.
    let mut verified: HashMap<BallotDigest, bool> = HashMap::new();
    let mut not_ballots: Vec<BallotDigest> = Vec::new();
    let mut is_ballot = |digest: &BallotDigest, ballot: &evoting::api::prelude::Ballot<G>| {
        let ok = *verified
            .entry(*digest)
            .or_insert_with(|| ballot.verify(context).is_ok());
        if !ok && !not_ballots.contains(digest) {
            not_ballots.push(*digest);
        }
        ok
    };
    // What each box opened, so that a box opening a ballot TWICE is caught.
    // The two openings of one ballot are `sum - code` - the vote - and they
    // stand on the board for good; a verifier that only asked "is there a
    // valid one?" would certify that election clean (Sec. 3.8.4 steps 10-14).
    let mut opened_by: HashMap<(BallotDigest, u64), evoting::api::prelude::OpenedCai> =
        HashMap::new();
    // Which slots each ballot has been opened on, by ANY box.
    let mut slots_of: HashMap<BallotDigest, (evoting::api::prelude::OpenedCai, u64)> =
        HashMap::new();
    // Which ballot each distinct disclosure was found to open, once.
    let mut scanned: HashMap<Vec<u8>, Option<(BallotDigest, evoting::api::prelude::OpenedCai)>> =
        HashMap::new();
    for cai in confirmations {
        // Sec. 3.8.4 step 13 identifies the ballot FROM the disclosure, ALWAYS:
        // "each trusted BB uses the first three values of the tuple to compute
        // idB and identify the pertinent ballot". The digest beside it is the
        // publisher's to choose and is never more than a hint - step 14 has
        // the box DERIVE H(B) from the ballot it found. So the stated digest
        // is tried first, because it is right whenever the publisher is
        // honest and costs one opening, and a disclosure it does not open is
        // looked for among the released ballots like any other. Without the
        // fall-through, stating ANOTHER released ballot's digest hid a second
        // genuine opening from the check below - and two openings of one
        // ballot are `sum - code`, the vote.
        let stated_is_released = released.contains_key(&cai.digest);
        let opened_here = |ballot: &evoting::api::prelude::Ballot<G>| {
            ballot.open_cai_disclosure(&cai.disclosure, context)
        };
        let (digest, really_opens) = match released.get(&cai.digest).and_then(|ballot| {
            opened_here(ballot)
                .filter(|_| is_ballot(&cai.digest, ballot))
                .map(|opened| (cai.digest, Some(opened)))
        }) {
            Some(found) => found,
            // The scan is what an entry whose stated digest does not open
            // costs, and the publisher chooses how many of those to write. It
            // is done once per DISTINCT disclosure, so repeating one is free.
            None => match found_by_scan(&mut scanned, &cai.disclosure, |disclosure| {
                released.iter().find_map(|(real, ballot)| {
                    ballot
                        .open_cai_disclosure(disclosure, context)
                        .filter(|_| is_ballot(real, ballot))
                        .map(|opened| (*real, opened))
                })
            }) {
                Some((real, opened)) => {
                    check.misconduct.push(format!(
                        "digest {}: BB-{} published a disclosure that opens the ballot of digest \
                         {real} under another digest",
                        cai.digest, cai.bb_id
                    ));
                    (real, Some(opened))
                }
                // Opens nothing anyone released. When the digest it states is
                // one a box DID release, that is a broken entry about a real
                // ballot and it is named as such below; when it is not, there
                // is nothing on the board to check it against and nobody to
                // accuse - but it is recorded.
                None if stated_is_released => (cai.digest, None),
                None => {
                    check.unaccounted.push(format!(
                        "digest {}: BB-{} published a confirmation for a ballot no ballot box released - nothing on the board can check it",
                        cai.digest, cai.bb_id
                    ));
                    continue;
                }
            },
        };
        // WHAT THE DISCLOSURE REALLY OPENS decides whether a ballot's secrecy
        // is gone - not the values the box states beside it. A box that
        // publishes one voter's disclosure while STATING the slots another box
        // already used would otherwise slip past: its claim agrees, and the
        // two disclosures on the board still open `sum` and `code`
        // (Sec. 3.8.4 step 14 publishes the randomness; step 15 compares the
        // data).
        if let Some(opened) = &really_opens {
            match slots_of.entry(digest) {
                std::collections::hash_map::Entry::Vacant(slot) => {
                    slot.insert((*opened, cai.bb_id));
                }
                std::collections::hash_map::Entry::Occupied(first) => {
                    let (first_opened, first_box) = first.get();
                    if openings_reveal(first_opened, opened) {
                        check.revealed.push(format!(
                            "digest {digest}: BB-{first_box} published a disclosure opening {} \
                             and BB-{} one opening {} - the two together are the vote, and both \
                             are on the board for good",
                            opened_slots(first_opened),
                            cai.bb_id,
                            opened_slots(opened)
                        ));
                    }
                }
            }
        }
        match really_opens {
            Some(opened) if opened == cai.opened => {
                check.valid.insert(digest);
                match opened_by.entry((digest, cai.bb_id)) {
                    std::collections::hash_map::Entry::Vacant(slot) => {
                        slot.insert(opened);
                    }
                    std::collections::hash_map::Entry::Occupied(first) => {
                        if *first.get() != opened {
                            check.misconduct.push(format!(
                                "digest {}: BB-{} published a SECOND, different cast-as-intended opening of the same ballot - together the two open the vote, and both are on the board for good",
                                cai.digest, cai.bb_id
                            ));
                        }
                    }
                }
            }
            Some(opened) => check.misconduct.push(format!(
                "digest {}: BB-{} published opened values {:?} but the released ballot \
                 opens to {opened:?}",
                cai.digest, cai.bb_id, cai.opened
            )),
            None => check.misconduct.push(format!(
                "digest {}: cast-as-intended disclosure published by BB-{} does not \
                 verify against the released ballot",
                cai.digest, cai.bb_id
            )),
        }
    }
    check.not_ballots = not_ballots;
    check
}

// ---------------------------------------------------------------------------
// What the board counts, and what a ballot box releases (Sec. 3.9 steps 2-5).
// ---------------------------------------------------------------------------

/// The digests the board says count: accepted and confirmed by enough boxes,
/// each statement signed by the box it names (Sec. 3.8.5).
/// What the board says about the ballots: the digests it counts (published
/// and confirmed, each by at least one box under its own signature), which
/// boxes published each digest, and every signed confirmation (to be checked
/// against the released ballots).
pub struct BoardBallots {
    pub counted: std::collections::HashSet<crate::domain::BallotDigest>,
    pub publishers: std::collections::HashMap<crate::domain::BallotDigest, Vec<u64>>,
    pub confirmations: Vec<crate::protocol::voting::CaiEntry>,
}

pub fn board_ballots(entries: &[(i64, serde_json::Value)]) -> BoardBallots {
    use crate::protocol::voting::{
        parse_wbb_data, signed_by_ballot_box, BallotDigestEntry, CaiEntry,
    };
    use base64::Engine as _;
    let mut publications = Vec::new();
    let mut confirmations = Vec::new();
    let mut publishers: std::collections::HashMap<crate::domain::BallotDigest, Vec<u64>> =
        std::collections::HashMap::new();
    for (_, entry) in entries {
        let Some(parsed) = entry
            .get("data")
            .and_then(|v| v.as_str())
            .and_then(|b64| base64::engine::general_purpose::STANDARD.decode(b64).ok())
            .and_then(|data| parse_wbb_data(&data))
        else {
            continue;
        };
        match parsed.entry_type.as_str() {
            "ballot_digest" => {
                if let Ok(p) = parsed.decode_payload::<BallotDigestEntry>() {
                    if signed_by_ballot_box(entry, p.receipt.bb_id) {
                        publications.push((p.digest, p.receipt.bb_id));
                        let boxes = publishers.entry(p.digest).or_default();
                        if !boxes.contains(&p.receipt.bb_id) {
                            boxes.push(p.receipt.bb_id);
                        }
                    }
                }
            }
            "cast_intended_proof" => {
                if let Ok(p) = parsed.decode_payload::<CaiEntry>() {
                    if signed_by_ballot_box(entry, p.bb_id) {
                        confirmations.push(p);
                    }
                }
            }
            _ => {}
        }
    }
    let counted = crate::protocol::voting::counted_digests(
        publications,
        confirmations.iter().map(|c| (c.digest, c.bb_id)),
    );
    BoardBallots {
        counted,
        publishers,
        confirmations,
    }
}

/// THE RELEASE RULE (Sec. 3.9 steps 2-3): of the ballots a box `held`, the
/// ones it releases.
///
/// A ballot is released if and only if the board COUNTS its digest - the
/// digest was published during voting by some box, under that box's own
/// signature, and confirmed (`board.counted`, the rule the tally driver and
/// the auditor use) - and a disclosure published on the board OPENS this very
/// ballot to the values published with it (`valid_disclosures`, again the
/// driver's and the auditor's own check). Nothing else enters: not which box
/// published the digest (Sec. 3.9 step 3 asks only that it was published),
/// not what this box remembers having done, not what it could not confirm.
///
/// So a box releases exactly its share of what the tally will count: every
/// honest box releases every counted ballot it holds, and the board alone
/// decides. The caller passes ONE reading of the board, taken after voting
/// closed - the voting-phase entries are then final, and two readings give
/// the same answer.
pub fn release_set(
    held: &HashMap<BallotDigest, evoting::api::prelude::Ballot<G>>,
    board: &BoardBallots,
    context: &evoting::api::server::bb::ElectionContext<G>,
) -> HashSet<BallotDigest> {
    let candidates: HashMap<BallotDigest, evoting::api::prelude::Ballot<G>> = held
        .iter()
        .filter(|(digest, _)| board.counted.contains(*digest))
        .map(|(digest, ballot)| (*digest, ballot.clone()))
        .collect();
    let check = valid_disclosures(&candidates, &board.confirmations, context);
    candidates
        .into_keys()
        .filter(|digest| check.valid.contains(digest))
        .collect()
}

/// A zeta VSS broadcast under its dealer's ceremony-pinned signature
/// (Sec. 2.8 Protocol 2 step 4: the commitments are BROADCAST, and every
/// party must know they come from the dealer they name).
///
/// The tally driver only relays these (deviation 25): it holds no key that
/// can produce one, so it can neither deal a sharing of its own in the
/// tellers' names nor alter a byte of theirs without being caught by every
/// recipient.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct SignedZetaVssBroadcast<Grp: dlog_group::group::Group = G> {
    pub broadcast: evoting::api::prelude::ZetaVssBroadcast<Grp>,
    /// Ed25519 over [`zeta_broadcast_message`], by `TT-{from_id}`. The
    /// message binds the election AND the session, so a dealer's broadcast
    /// cannot be lifted from one deal into another and mixed with peers'
    /// broadcasts of a different one.
    pub signature: String,
}

/// The bytes a dealer signs for its zeta VSS broadcast: the broadcast itself,
/// under a domain separator and bound to the election, so a broadcast cannot
/// be replayed into another election or read as anything else.
pub fn zeta_broadcast_message<Grp: dlog_group::group::Group>(
    broadcast: &evoting::api::prelude::ZetaVssBroadcast<Grp>,
    election_id: &str,
    session: &str,
) -> Result<Vec<u8>, TallyError> {
    use sha2::{Digest, Sha256};
    let body = serde_json::to_vec(broadcast).map_err(|e| TallyError::Shape(e.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(b"referendum-poc/zeta-vss-broadcast/v2");
    for field in [election_id.as_bytes(), session.as_bytes(), &body[..]] {
        hasher.update((field.len() as u64).to_le_bytes());
        hasher.update(field);
    }
    Ok(hasher.finalize().to_vec())
}

// ---------------------------------------------------------------------------
// The encrypted tally, recomputed from the board (Sec. 3.9 steps 28-29).
// ---------------------------------------------------------------------------

/// Recompute the homomorphic sum the tally decrypts, from PUBLISHED artifacts
/// alone.
///
/// A tabulation teller uses this so that what it threshold-decrypts is not a
/// ciphertext its caller chose but a deterministic function of what the board
/// already carries - the vote and credential mixes, the control elements, the
/// ACC checks and the credential fingerprints, each co-signed by the tellers
/// and each re-checked by universal verification (Sec. 3.10). Without it, a
/// caller holding the service tokens can have ANY ciphertext decrypted under
/// the master tally key, the credential checks included, and nothing it did is
/// published for a verifier to catch.
pub fn encrypted_tally_from_entries(
    entries: &[serde_json::Value],
    context: &evoting::api::server::bb::ElectionContext<G>,
) -> Result<EncrChoice<G>, TallyError> {
    use evoting::api::server::bb::{PublicElection, PublicPipeline};

    let mut vote_art = None;
    let mut cred_art = None;
    let mut controls = None;
    let mut acc = None;
    let mut fps = None;

    for entry in entries {
        let Some(parsed) = entry
            .get("data")
            .and_then(|v| v.as_str())
            .and_then(|b64| BASE64.decode(b64).ok())
            .and_then(|raw| crate::protocol::voting::parse_wbb_data(&raw))
        else {
            continue;
        };
        match parsed.entry_type.as_str() {
            "mixed_ballots" if parsed.role == "TT" && parsed.threshold >= 3 => {
                match parsed.decode_payload::<MixedBallotsEntry>() {
                    Ok(MixedBallotsEntry::Votes { artifact }) => {
                        set_once(&mut vote_art, *artifact)?
                    }
                    Ok(MixedBallotsEntry::Credentials { artifact }) => {
                        set_once(&mut cred_art, *artifact)?
                    }
                    Err(_) => continue,
                }
            }
            // Authorship matters: the registration tellers write
            // `credential_control` at threshold 2 and the tabulation tellers
            // write `re_encryption_proof` at threshold 3 (Sec. 3.4.2). Reading
            // one as the other lets an entry written under the wrong authority
            // stand in for the tellers' own artifact - which the auditor
            // refuses, so the teller must refuse it too.
            "credential_control" if parsed.role == "RT" && parsed.threshold >= 2 => {
                match parsed.decode_payload::<ReEncryptionProofEntry>() {
                    Ok(ReEncryptionProofEntry::Controls { controls: c }) => {
                        set_once(&mut controls, c)?
                    }
                    _ => continue,
                }
            }
            "re_encryption_proof" if parsed.role == "TT" && parsed.threshold >= 3 => {
                match parsed.decode_payload::<ReEncryptionProofEntry>() {
                    Ok(ReEncryptionProofEntry::AccChecks {
                        acc_checks,
                        blinding,
                    }) => set_once(&mut acc, (acc_checks, blinding))?,
                    Ok(ReEncryptionProofEntry::CredentialFingerprints { fps: f, bundle }) => {
                        set_once(&mut fps, (f, bundle))?
                    }
                    _ => continue,
                }
            }
            _ => {}
        }
    }

    let missing = |what: &str| TallyError::Shape(format!("the board carries no {what} yet"));
    let vote_art = vote_art.ok_or_else(|| missing("shuffled votes"))?;
    let cred_art = cred_art.ok_or_else(|| missing("shuffled credentials"))?;
    let controls = controls.ok_or_else(|| missing("credential control elements"))?;
    let (acc_checks, blinding) = acc.ok_or_else(|| missing("ACC checks"))?;
    let (fps, bundle) = fps.ok_or_else(|| missing("credential fingerprints"))?;

    let pipeline = PublicPipeline::new(PublicElection::new(context.clone()));
    let shape = |e: evoting::error::Error| TallyError::Shape(format!("{e:?}"));
    let valid = pipeline
        .filter_invalid(&vote_art.shuffled, &controls, &acc_checks, &blinding)
        .map_err(shape)?;
    let legitimate = pipeline
        .filter_illicit(
            &valid,
            &cred_art,
            &fps,
            &bundle.dec_pub_fps,
            &bundle.dec_votes_fps,
        )
        .map_err(shape)?;
    Ok(pipeline.homomorphic_sum(legitimate))
}

/// Which of each pair an opening selected, e.g. `Code/Sum`.
fn opened_slots(opened: &evoting::api::prelude::OpenedCai) -> String {
    format!("{}/{}", slot_name(&opened.l1), slot_name(&opened.l2))
}

fn slot_name(value: &evoting::api::prelude::OpenedCaiValue) -> &'static str {
    match value {
        evoting::api::prelude::OpenedCaiValue::Code(_) => "Code",
        evoting::api::prelude::OpenedCaiValue::Sum(_) => "Sum",
    }
}

/// Do two openings of one ballot together give away a choice?
///
/// A level gives one away as soon as BOTH of its slots are opened: `sum -
/// code` is the index chosen there, and a difference of zero is an index of
/// zero - which at the option level is the BLANK ballot, one of the three
/// results this election publishes. Whether the two numbers happen to be
/// equal therefore settles nothing; what settles it is whether the
/// difference could have been anything else.
///
/// At the CANDIDATE level of a referendum it could not. Every option has one
/// candidate (Sec. 3.11), so `Ca` is zero for every ballot ever built here,
/// `s_Ca + Ca = s_Ca`, and the difference is zero by construction - the same
/// constant for every voter, known before any disclosure is read. Opening
/// both of those slots tells a reader what they already knew.
/// The identification scan, done once per DISTINCT disclosure and remembered:
/// repeating one is free. A disclosure that does not even serialise gets no
/// memo entry, so two such can never share one.
fn found_by_scan(
    scanned: &mut HashMap<Vec<u8>, Option<(BallotDigest, evoting::api::prelude::OpenedCai)>>,
    disclosure: &evoting::api::prelude::DiscloseCAI<G>,
    mut scan: impl FnMut(
        &evoting::api::prelude::DiscloseCAI<G>,
    ) -> Option<(BallotDigest, evoting::api::prelude::OpenedCai)>,
) -> Option<(BallotDigest, evoting::api::prelude::OpenedCai)> {
    match serde_json::to_vec(disclosure) {
        Ok(key) => *scanned.entry(key).or_insert_with(|| scan(disclosure)),
        Err(_) => scan(disclosure),
    }
}

/// Would opening `ours` on `ballot` give the vote away, given the
/// disclosures already published?
///
/// A ballot box holds the ballot, so it can answer this from its own copy:
/// every published disclosure is opened against THIS ballot and the ones that
/// open it are weighed against `ours`. The digest an entry states is not
/// consulted - Sec. 3.8.4 step 13 identifies the ballot from the disclosure,
/// and a publisher that could hide a second opening behind a digest of its
/// own choosing would make this check decorative. A disclosure that does not
/// open this ballot is somebody else's business, and vetoes nothing here
/// (Sec. 3.8.4 step 15 has divergent data PUBLISHED, not suppressed).
pub fn opening_would_reveal<'a, I>(
    ballot: &evoting::api::prelude::Ballot<G>,
    ours: &evoting::api::prelude::OpenedCai,
    published: I,
    context: &evoting::api::server::bb::ElectionContext<G>,
) -> Option<evoting::api::prelude::OpenedCai>
where
    I: IntoIterator<Item = &'a evoting::api::prelude::DiscloseCAI<G>>,
{
    published
        .into_iter()
        .filter_map(|disclosure| ballot.open_cai_disclosure(disclosure, context))
        .find(|theirs| openings_reveal(theirs, ours))
}

pub fn openings_reveal(
    first: &evoting::api::prelude::OpenedCai,
    second: &evoting::api::prelude::OpenedCai,
) -> bool {
    let both_slots = |a: &evoting::api::prelude::OpenedCaiValue,
                      b: &evoting::api::prelude::OpenedCaiValue| {
        slot_name(a) != slot_name(b)
    };
    // Only the OPTION level carries a choice in this election.
    both_slots(&first.l1, &second.l1)
}

/// Exactly one of each artifact: the board is append-only and the audit
/// requires one, so a second copy is an error rather than a choice to make.
fn set_once<T>(slot: &mut Option<T>, value: T) -> Result<(), TallyError> {
    if slot.is_some() {
        return Err(TallyError::Shape(
            "the board carries two copies of a tally artifact".into(),
        ));
    }
    *slot = Some(value);
    Ok(())
}
