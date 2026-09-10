//! Tally pipeline primitives (Sec. 3.9).
//!
//! Framework-free helpers shared by the `election-admin tally` driver, the
//! TT server, and the `referendum-auditor`: TT share loading, ballot-release
//! reconciliation (the Sec. 3.8.5 bot filter), the WBB entry payloads of the
//! tallying phase, and counts extraction from the decrypted tally via the
//! D-mandated serde round-trip.

use std::collections::HashMap;
use std::path::Path;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use dlog_group::group::GroupScalar;
use dlog_group::ristretto::RistrettoGroup;
use dlog_group::serde::ScalarHelper;
use evoting::api::prelude::{
    CredentialControlProof, DecryptedFingerprintsBundle, DecryptedTally, EncrChoice, Receipt,
    TTSecretKeyShare, ThresholdDecOk, ThresholdTabulationTeller, VerifiableFingerprints,
};
use evoting::api::server::bb::{BallotRecord, CredMixArtifact, VoteMixArtifact};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};

use crate::domain::BallotDigest;
use crate::protocol::voting::{ballot_digest, VotingError, NO_BOT_MIN_BBS};

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

/// Reconcile the per-BB ballot releases into the canonical tally input
/// (Sec. 3.8.5).
///
/// A ballot digest counts as accepted only when it appears on at least
/// [`NO_BOT_MIN_BBS`] distinct BBs (by `receipt.bb_id`); anything else is the
/// bot case and is excluded. The canonical copy of each accepted ballot is the
/// one released by the lowest-numbered BB, and the output is ordered by that
/// BB's `seq_no` - the global cast order used for last-vote-wins dedup.
pub fn reconcile_ballots(
    per_bb: &[Vec<BallotRecord<G>>],
) -> Result<Vec<BallotRecord<G>>, TallyError> {
    let mut digest_lists = Vec::with_capacity(per_bb.len());
    for list in per_bb {
        let mut digests = Vec::with_capacity(list.len());
        for record in list {
            digests.push((ballot_digest(&record.ballot)?, record.receipt));
        }
        digest_lists.push(digests);
    }
    Ok(reconcile_indices(&digest_lists)
        .into_iter()
        .map(|(list, idx)| per_bb[list][idx].clone())
        .collect())
}

/// Digest-level reconciliation core (unit-testable without real ballots).
///
/// Returns `(bb_list_index, item_index)` of the canonical copy of every
/// digest present on >= [`NO_BOT_MIN_BBS`] distinct BBs, in canonical
/// `seq_no` order.
fn reconcile_indices(per_bb: &[Vec<(BallotDigest, Receipt)>]) -> Vec<(usize, usize)> {
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
    for copies in by_digest.into_values() {
        let mut bb_ids: Vec<u64> = copies.iter().map(|(_, _, r)| r.bb_id).collect();
        bb_ids.sort_unstable();
        bb_ids.dedup();
        if bb_ids.len() < NO_BOT_MIN_BBS {
            // bot: accepted by too few BBs (Sec. 3.8.5).
            continue;
        }
        let canonical = copies
            .into_iter()
            .min_by_key(|(_, _, r)| r.bb_id)
            .expect("non-empty copy list");
        chosen.push(canonical);
    }

    // Total order even when canonical copies come from different BBs (only
    // possible with n_BB > NO_BOT_MIN_BBS): per-BB seq_no uniqueness makes
    // (seq_no, bb_id) a strict key.
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
    /// Sec. 3.9 steps 5-10: ox fingerprint proof + threshold decryptions.
    OxFingerprints {
        fps: VerifiableFingerprints<G>,
        decryptions: Vec<ThresholdDecOk<G>>,
    },
    /// Sec. 3.9 step 11: RT credential control proofs over the shuffled votes.
    Controls {
        controls: Vec<CredentialControlProof<G>>,
    },
    /// Sec. 3.9 steps 12-14: ACC checks (zeta is a public verification input of
    /// `verify_acc_checks` / `filter_invalid`).
    AccChecks {
        acc_checks: Vec<ThresholdDecOk<G>>,
        #[serde(with = "ScalarHelper::<G>")]
        zeta: <G as GroupScalar>::Scalar,
    },
    /// Sec. 3.9 steps 20-24: credential fingerprints + decryption bundle.
    CredentialFingerprints {
        fps: VerifiableFingerprints<G>,
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

    fn receipt(seq_no: u64, bb_id: u64) -> Receipt {
        Receipt {
            seq_no,
            received_at_unix_ms: 1_700_000_000_000 + seq_no,
            bb_id,
        }
    }

    #[test]
    fn reconcile_excludes_single_bb_ballots() {
        // Digest 1 on both BBs, digest 2 only on BB-2 (bot, Sec. 3.8.5).
        let bb1 = vec![(digest(1), receipt(0, 1))];
        let bb2 = vec![(digest(1), receipt(0, 2)), (digest(2), receipt(1, 2))];
        let chosen = reconcile_indices(&[bb1, bb2]);
        assert_eq!(chosen, vec![(0, 0)], "only the 2-BB digest survives");
    }

    #[test]
    fn reconcile_prefers_lowest_bb_and_orders_by_its_seq() {
        // Two accepted ballots; BB-2 saw them in a different order.
        let bb1 = vec![(digest(1), receipt(0, 1)), (digest(2), receipt(1, 1))];
        let bb2 = vec![(digest(2), receipt(0, 2)), (digest(1), receipt(1, 2))];
        let chosen = reconcile_indices(&[bb1, bb2]);
        // Canonical copies come from BB-1 (list 0), ordered by BB-1 seq_no.
        assert_eq!(chosen, vec![(0, 0), (0, 1)]);
    }

    #[test]
    fn reconcile_ignores_duplicate_receipts_from_one_bb() {
        // The same digest twice on ONE BB does not clear the bot threshold.
        let bb1 = vec![(digest(1), receipt(0, 1)), (digest(1), receipt(1, 1))];
        let bb2: Vec<(BallotDigest, Receipt)> = Vec::new();
        assert!(reconcile_indices(&[bb1, bb2]).is_empty());
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
