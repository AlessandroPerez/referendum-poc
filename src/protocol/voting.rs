//! Ballot casting primitives (M6, §3.8 / §5.3.1.6 / §3.11).
//!
//! Framework-free helpers shared by the voter server and the ballot boxes:
//! ballot digests, casting-token commitments, the §3.8.4 `bb_id` encryption,
//! and the WBB entry payloads of the voting phase.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use dlog_group::group::GroupScalar;
use dlog_group::ristretto::RistrettoGroup;
use dlog_sigma_primitives::elgamal::ciphertext::Ciphertext;
use evoting::api::client::Ballot;
use evoting::api::prelude::{Choice, ChoiceParameters, DiscloseCAI, ElectionPublicKey, Receipt};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

use crate::domain::{BallotDigest, CommB, ReferendumOption};

type G = RistrettoGroup;

/// Minimum number of distinct BBs that must publish a ballot digest for the
/// ballot to count as accepted without ⊥ (§3.8.5).  A protocol constant, not
/// a deployment knob: the ⊥ check is defined as "at least two".
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

/// Ballot digest `H(B)`: SHAKE256 over the CBOR encoding (§3.8.4, roadmap §8.4).
pub fn ballot_digest(ballot: &Ballot<G>) -> Result<BallotDigest, VotingError> {
    let bytes = serde_cbor::to_vec(ballot)?;
    Ok(BallotDigest::from_bytes(shake256_32(&[
        b"referendum-poc-ballot-digest",
        &bytes,
    ])))
}

/// Casting-token commitment `commB = H(B ‖ rndcomm)` (§5.3.1.6).
pub fn comm_b(ballot: &Ballot<G>, rndcomm: &[u8; 32]) -> Result<CommB, VotingError> {
    let bytes = serde_cbor::to_vec(ballot)?;
    Ok(CommB::from_bytes(shake256_32(&[
        b"referendum-poc-comm-b",
        &bytes,
        rndcomm,
    ])))
}

/// Build the referendum `Choice` for an option (§3.11: 3 first-level options,
/// one candidate slot each; `Choice::new(i, vec![0], params)`).
pub fn referendum_choice(
    option: ReferendumOption,
    params: &ChoiceParameters,
) -> Result<Choice, VotingError> {
    Ok(Choice::new(option.index(), vec![0], params)?)
}

/// `E_pk_TT[g1^{2^bb_id}]` (§3.8.4): the tally later multiplies these
/// homomorphically to detect ballots accepted by fewer than 2 BBs (⊥ check).
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

// ── WBB entry payloads (voting phase, roadmap §4.4) ────────────────────────

/// Content of a `voting,BB,ballot_digest,1,…` entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BallotDigestEntry {
    pub digest: BallotDigest,
    /// User-facing emoji receipt (`Ballot::to_emoji`, Deviation 2).
    pub emoji: Vec<String>,
    pub receipt: Receipt,
}

/// Content of a `voting,BB,ballot_metadata,1,…` entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct BallotMetadataEntry {
    pub digest: BallotDigest,
    pub bb_id: u64,
    /// `E_pk_TT[g1^{2^bb_id}]` (§3.8.4).
    pub bb_id_enc: Ciphertext<G>,
}

/// Content of a `voting,BB,cast_intended_proof,1,…` entry (§3.8.4 steps 11–16).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct CaiEntry {
    pub digest: BallotDigest,
    pub bb_id: u64,
    pub disclosure: DiscloseCAI<G>,
    /// Logical confirmation time (§3.8.4 step 17).
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
/// current phase (§3.4.2, fork `http.go`).
pub fn phase_transition_data_string(from: &str, to: &str) -> String {
    format!("{from},PM,phase_transition,1,{to}")
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
