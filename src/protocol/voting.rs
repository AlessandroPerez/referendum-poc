//! Ballot casting primitives (Sec. 3.8, 5.3.1.6, 3.11).
//!
//! Framework-free helpers shared by the voter server and the ballot boxes:
//! ballot digests, casting-token commitments, the Sec. 3.8.4 `bb_id` encryption,
//! and the WBB entry payloads of the voting phase.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use dlog_group::group::GroupScalar;
use dlog_group::ristretto::RistrettoGroup;
use dlog_sigma_primitives::elgamal::ciphertext::Ciphertext;
use evoting::api::client::Ballot;
use evoting::api::prelude::{
    Choice, ChoiceParameters, DiscloseCAI, ElectionPublicKey, OpenedCai, Receipt,
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

use crate::domain::{BallotDigest, CommB, ReferendumOption};

type G = RistrettoGroup;

/// The number of distinct ballot boxes that must publish a ballot digest for
/// the voter to be spared the bottom symbol of Sec. 3.8.4 step 5 ("at least
/// one BB has failed"; Sec. 3.8.5 1(d)). A signal to the voter, who may cast
/// again - not a counting condition (see [`counted_digests`]).
pub const NO_BOT_MIN_BBS: usize = 2;

/// Errors from the voting helpers.
#[derive(Debug, thiserror::Error)]
pub enum VotingError {
    #[error("CBOR serialization error: {0}")]
    Cbor(#[from] serde_cbor::Error),
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("crypto error: {0}")]
    Crypto(String),
}

impl From<evoting::error::Error> for VotingError {
    fn from(e: evoting::error::Error) -> Self {
        Self::Crypto(format!("{e:?}"))
    }
}

fn shake256_32(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Shake256::default();
    for part in parts {
        Update::update(&mut hasher, part);
    }
    let mut reader = hasher.finalize_xof();
    let mut out = [0u8; 32];
    XofReader::read(&mut reader, &mut out);
    out
}

/// Ballot digest `H(B)`: SHAKE256 over the CBOR encoding (Sec. 3.8.4).
pub fn ballot_digest(ballot: &Ballot<G>) -> Result<BallotDigest, VotingError> {
    let bytes = serde_cbor::to_vec(ballot)?;
    Ok(BallotDigest::from_bytes(shake256_32(&[
        b"referendum-poc-ballot-digest",
        &bytes,
    ])))
}

/// Casting-token commitment `commB = H(B || rndcomm)` (Sec. 5.3.1.6).
pub fn comm_b(ballot: &Ballot<G>, rndcomm: &[u8; 32]) -> Result<CommB, VotingError> {
    let bytes = serde_cbor::to_vec(ballot)?;
    Ok(CommB::from_bytes(shake256_32(&[
        b"referendum-poc-comm-b",
        &bytes,
        rndcomm,
    ])))
}

/// Build the referendum `Choice` for an option (Sec. 3.11: 3 first-level options,
/// one candidate slot each; `Choice::new(i, vec![0], params)`).
pub fn referendum_choice(
    option: ReferendumOption,
    params: &ChoiceParameters,
) -> Result<Choice, VotingError> {
    Ok(Choice::new(option.index(), vec![0], params)?)
}

/// `E_pk_TT[g1^{2^bb_id}]` (Sec. 3.8.4): the tally later multiplies these
/// homomorphically to detect ballots accepted by fewer than 2 BBs (bot check).
pub fn bb_id_encryption<R: RngCore + CryptoRng>(
    election_pk: &ElectionPublicKey<G>,
    bb_id: u64,
    rng: &mut R,
) -> Ciphertext<G> {
    let exponent = <G as GroupScalar>::Scalar::from(1u64 << bb_id);
    let value = election_pk.params.elgamal.g1 * exponent;
    Ciphertext::new(
        &election_pk.params.tally,
        &election_pk.params.elgamal,
        value,
        rng,
    )
}

// -- WBB entry payloads (voting phase, Sec. 3.4.2 write policy) ------------------------

/// Content of a `voting,BB,ballot_digest,1,...` entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BallotDigestEntry {
    pub digest: BallotDigest,
    /// User-facing emoji receipt (`Ballot::to_emoji`, Deviation 2).
    pub emoji: Vec<String>,
    /// PublicPINEmoji: visual digest of `H(E[o^x])` of the received ballot
    /// (Sec. 3.8.4 step 2), for the voter to compare with their app's.
    pub public_pin_emoji: Vec<String>,
    pub receipt: Receipt,
}

/// Content of a `voting,BB,ballot_metadata,1,...` entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct BallotMetadataEntry {
    pub digest: BallotDigest,
    pub bb_id: u64,
    /// `E_pk_TT[g1^{2^bb_id}]` (Sec. 3.8.4).
    pub bb_id_enc: Ciphertext<G>,
}

/// Content of a `voting,BB,cast_intended_proof,1,...` entry (Sec. 3.8.4 steps 11-16).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct CaiEntry {
    pub digest: BallotDigest,
    pub bb_id: u64,
    pub disclosure: DiscloseCAI<G>,
    /// The values the disclosure opens in the ballot, as decoded by the
    /// ballot box (Sec. 3.8.4 steps 13-14). The voter compares them with the
    /// control values the app showed after casting; the auditor re-derives
    /// them from the released ballot.
    pub opened: OpenedCai,
    /// Logical confirmation time (Sec. 3.8.4 step 17).
    pub confirmed_at_ms: u64,
}

/// Serialize a payload as the base64 content field of a 5-field WBB data
/// string (`{phase},{role},{type},{threshold},{base64}`).
pub fn wbb_data_string<T: Serialize>(
    phase: &str,
    role: &str,
    entry_type: &str,
    threshold: usize,
    payload: &T,
) -> Result<String, VotingError> {
    let json = serde_json::to_string(payload)?;
    Ok(format!(
        "{phase},{role},{entry_type},{threshold},{}",
        BASE64.encode(json.as_bytes())
    ))
}

/// A parsed 5-field WBB data string.
#[derive(Debug, Clone)]
pub struct ParsedWbbData {
    pub phase: String,
    pub role: String,
    pub entry_type: String,
    pub threshold: usize,
    /// Raw content field (base64 JSON for PoC payloads; raw text for
    /// phase transitions).
    pub content: String,
}

/// The entity ids that signed a bulletin-board entry (`entity_id` on a
/// single-signer entry, `entity_ids` on a co-signed one).
pub fn entry_signer_ids(entry: &serde_json::Value) -> Vec<String> {
    // An honest entry carries ONE form. The board verifies one of them and
    // logs whatever else the submitter sent along, so an entry carrying both
    // is ambiguous on purpose: it counts as signed by nobody - here, in the
    // auditor and in both UIs alike.
    let single = entry.get("entity_id").and_then(|v| v.as_str());
    let co_signers: Vec<String> = entry
        .get("entity_ids")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    match (single, co_signers.is_empty()) {
        (Some(id), true) => vec![id.to_string()],
        (None, false) => co_signers,
        _ => Vec::new(),
    }
}

/// The ballot boxes that published BOTH a ballot's digest and a confirmation
/// of it - the boxes that vouch for it completely. Shown to the voter; the
/// count of them is NOT what decides whether the ballot counts (see
/// [`counted_digests`]).
pub fn counting_ballot_boxes(published: &[u64], confirmed: &[u64]) -> Vec<u64> {
    let mut both: Vec<u64> = published
        .iter()
        .copied()
        .filter(|bb| confirmed.contains(bb))
        .collect();
    both.sort_unstable();
    both.dedup();
    both
}

/// The digests the board says COUNT (Sec. 3.9 steps 3 and 5, Sec. 3.10
/// 1(c)-(d)): a `ballot_digest` entry published during voting by at least
/// ONE ballot box, and a `cast_intended_proof` entry published by at least
/// ONE ballot box - each entry signed by the box it names, not necessarily
/// the same box. One honest box is what the thesis relies on (A9): a rule
/// that needed two would hand any single dishonest box a veto over any
/// ballot, with nothing on the board to tell it from a voter who never
/// confirmed. Whether a published disclosure is VALID can only be checked
/// against the released ballot, at tally (`tally::valid_disclosures`); the
/// bottom symbol of Sec. 3.8.4 step 5 - fewer than [`NO_BOT_MIN_BBS`]
/// boxes published the digest - is a warning to the voter, not a discard.
/// `publications` and `confirmations` carry one `(digest, bb_id)` per such
/// entry. Used by the voter app, the tally driver and the auditor alike.
pub fn counted_digests(
    publications: impl IntoIterator<Item = (BallotDigest, u64)>,
    confirmations: impl IntoIterator<Item = (BallotDigest, u64)>,
) -> std::collections::HashSet<BallotDigest> {
    let published: std::collections::HashSet<BallotDigest> =
        publications.into_iter().map(|(digest, _)| digest).collect();
    let confirmed: std::collections::HashSet<BallotDigest> = confirmations
        .into_iter()
        .map(|(digest, _)| digest)
        .collect();
    published.intersection(&confirmed).copied().collect()
}

/// True when `entry` is a result the tabulation tellers really co-signed:
/// the published counts of an election are only what `t_TT` of them put their
/// name to (Sec. 3.4.2 write policy), so neither app shows a `tally_result`
/// entry on the board's word alone.
/// Tabulation tellers that must co-sign a published result: the fixed
/// Sec. 3.4.2 write policy, not a configurable threshold.
pub const RESULT_SIGNERS: usize = 3;

pub fn signed_by_tellers(entry: &serde_json::Value, t_tt: usize) -> bool {
    let signers: std::collections::BTreeSet<String> = entry_signer_ids(entry)
        .into_iter()
        .filter(|id| id.starts_with("TT-"))
        .collect();
    signers.len() >= t_tt
}

/// True when `entry` is signed by ballot box `bb_id` itself. What a ballot
/// box says in a payload counts - for the auditor, the voter app and the
/// public board page alike - only under that ballot box's own signature:
/// a payload naming ANOTHER ballot box is nobody's statement.
pub fn signed_by_ballot_box(entry: &serde_json::Value, bb_id: u64) -> bool {
    let expected = format!("BB-{bb_id}");
    entry_signer_ids(entry).contains(&expected)
}

/// Parse the decoded `data` bytes of a WBB entry into its 5 CSV fields.
pub fn parse_wbb_data(data: &[u8]) -> Option<ParsedWbbData> {
    let text = std::str::from_utf8(data).ok()?;
    let mut parts = text.splitn(5, ',');
    let phase = parts.next()?.to_string();
    let role = parts.next()?.to_string();
    let entry_type = parts.next()?.to_string();
    let threshold = parts.next()?.parse().ok()?;
    let content = parts.next()?.to_string();
    Some(ParsedWbbData {
        phase,
        role,
        entry_type,
        threshold,
        content,
    })
}

impl ParsedWbbData {
    /// Decode the base64-JSON content field into a payload type.
    pub fn decode_payload<T: serde::de::DeserializeOwned>(&self) -> Result<T, VotingError> {
        let bytes = BASE64
            .decode(&self.content)
            .map_err(|e| VotingError::Crypto(format!("invalid base64 content: {e}")))?;
        Ok(serde_json::from_slice(&bytes)?)
    }
}

/// Data string for a PM phase transition: `{from},PM,phase_transition,1,{to}`.
///
/// The content field is the RAW next-phase name (the WBB compares it
/// directly, no base64) and the entry's phase field must equal the server's
/// current phase (Sec. 3.4.2, fork `http.go`).
pub fn phase_transition_data_string(from: &str, to: &str) -> String {
    format!("{from},PM,phase_transition,1,{to}")
}

#[cfg(test)]
mod signer_rule_tests {
    use super::*;

    #[test]
    fn an_entry_with_both_signer_forms_is_signed_by_nobody() {
        let single = serde_json::json!({ "entity_id": "BB-1" });
        let co = serde_json::json!({ "entity_ids": ["RT-1", "RT-2"] });
        let shadowed = serde_json::json!({ "entity_id": "BB-1", "entity_ids": ["BB-2"] });
        assert_eq!(entry_signer_ids(&single), ["BB-1"]);
        assert_eq!(entry_signer_ids(&co), ["RT-1", "RT-2"]);
        assert!(entry_signer_ids(&shadowed).is_empty());
        assert!(signed_by_ballot_box(&single, 1));
        assert!(!signed_by_ballot_box(&shadowed, 1) && !signed_by_ballot_box(&shadowed, 2));
        // An empty list next to a single signer is not a second form.
        let padded = serde_json::json!({ "entity_id": "BB-1", "entity_ids": [] });
        assert_eq!(entry_signer_ids(&padded), ["BB-1"]);
    }

    #[test]
    fn a_ballot_counts_with_boxes_that_published_and_confirmed() {
        assert_eq!(counting_ballot_boxes(&[1, 2], &[2, 1, 1]), [1, 2]);
        assert_eq!(counting_ballot_boxes(&[1, 2], &[2]), [2]);
        assert_eq!(counting_ballot_boxes(&[1], &[2]), Vec::<u64>::new());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase_transition_format_is_raw() {
        assert_eq!(
            phase_transition_data_string("setup", "voting"),
            "setup,PM,phase_transition,1,voting"
        );
    }

    #[test]
    fn wbb_data_string_has_five_fields_and_no_extra_commas() {
        #[derive(Serialize)]
        struct P {
            a: String,
        }
        let s = wbb_data_string(
            "voting",
            "BB",
            "ballot_digest",
            1,
            &P {
                a: "x,y".to_string(),
            },
        )
        .unwrap();
        assert_eq!(s.split(',').count(), 5);
    }

    #[test]
    fn shake_domain_separation() {
        // Same bytes under different domains must differ.
        let a = shake256_32(&[b"domain-a", b"payload"]);
        let b = shake256_32(&[b"domain-b", b"payload"]);
        assert_ne!(a, b);
    }
}
