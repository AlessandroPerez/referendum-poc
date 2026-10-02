//! Commitment Access Tokens for ballot casting (Sec. 5.2, Sec. 5.3.1.6).
//!
//! A casting token is the electoral roll's signature over the ballot
//! commitment `commB = H(B, rnd_comm)`. It is issued for ONE ballot box and
//! for a limited time. The ballot box checks it by itself - signature,
//! audience, expiry, and that the commitment opens to the ballot it received -
//! so the electoral roll never learns when, or whether, a token is redeemed,
//! and the ballot box never learns who the voter is: the token names no one.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::domain::CommB;

/// Separates casting-token signatures from every other signature of the
/// electoral roll's key.
const DOMAIN: &[u8] = b"referendum-poc/casting-token/v1";

/// An anonymous, self-contained casting token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CastingToken {
    /// The ballot box this token is valid at (Sec. 5.3.1.6 step 4: one per BB).
    pub bb_id: u64,
    /// The ballot commitment the token is tied to.
    pub comm_b: CommB,
    /// End of validity, Unix milliseconds on the issuer's clock.
    pub expires_at_ms: u64,
    /// Base64 Ed25519 signature of the electoral roll.
    pub signature: String,
}

/// Why a ballot box refuses a casting token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CatError {
    #[error("casting token was issued for another ballot box")]
    WrongAudience,
    #[error("casting token has expired")]
    Expired,
    #[error("casting token is tied to another ballot")]
    WrongCommitment,
    #[error("casting token is not signed by the electoral roll")]
    BadSignature,
}

fn signed_bytes(election: &[u8; 32], bb_id: u64, comm_b: &CommB, expires_at_ms: u64) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(DOMAIN.len() + 32 + 8 + 32 + 8);
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(election);
    bytes.extend_from_slice(&bb_id.to_le_bytes());
    bytes.extend_from_slice(comm_b.as_bytes());
    bytes.extend_from_slice(&expires_at_ms.to_le_bytes());
    bytes
}

impl CastingToken {
    /// Issue a token (electoral roll side). `election` is the election
    /// context hash: a token of one election is worthless in another.
    pub fn issue(
        key: &SigningKey,
        election: &[u8; 32],
        bb_id: u64,
        comm_b: CommB,
        expires_at_ms: u64,
    ) -> Self {
        let signature = key.sign(&signed_bytes(election, bb_id, &comm_b, expires_at_ms));
        Self {
            bb_id,
            comm_b,
            expires_at_ms,
            signature: BASE64.encode(signature.to_bytes()),
        }
    }

    /// Check a token (ballot box side, Sec. 5.3.1.6 step 6), with no call to
    /// the issuer: it must be for this ballot box, still valid at `now_ms`,
    /// tied to the commitment recomputed from the received ballot, and signed
    /// by the electoral roll. A token admits exactly one ballot: the one its
    /// commitment opens to.
    pub fn verify(
        &self,
        er_key: &VerifyingKey,
        election: &[u8; 32],
        bb_id: u64,
        comm_b: &CommB,
        now_ms: u64,
    ) -> Result<(), CatError> {
        if self.bb_id != bb_id {
            return Err(CatError::WrongAudience);
        }
        if now_ms >= self.expires_at_ms {
            return Err(CatError::Expired);
        }
        if self.comm_b != *comm_b {
            return Err(CatError::WrongCommitment);
        }
        let signature: [u8; 64] = BASE64
            .decode(&self.signature)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(CatError::BadSignature)?;
        er_key
            .verify(
                &signed_bytes(election, self.bb_id, &self.comm_b, self.expires_at_ms),
                &Signature::from_bytes(&signature),
            )
            .map_err(|_| CatError::BadSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (SigningKey, [u8; 32], CommB) {
        (
            SigningKey::from_bytes(&[7u8; 32]),
            [1u8; 32],
            CommB::from_bytes([2u8; 32]),
        )
    }

    #[test]
    fn a_token_is_accepted_only_where_and_while_it_is_valid() {
        let (er, election, comm_b) = fixture();
        let token = CastingToken::issue(&er, &election, 2, comm_b, 10_000);
        let key = er.verifying_key();

        assert_eq!(token.verify(&key, &election, 2, &comm_b, 9_999), Ok(()));
        assert_eq!(
            token.verify(&key, &election, 1, &comm_b, 9_999),
            Err(CatError::WrongAudience)
        );
        assert_eq!(
            token.verify(&key, &election, 2, &comm_b, 10_000),
            Err(CatError::Expired)
        );
        assert_eq!(
            token.verify(&key, &election, 2, &CommB::from_bytes([3u8; 32]), 9_999),
            Err(CatError::WrongCommitment)
        );
        assert_eq!(
            token.verify(&key, &[9u8; 32], 2, &comm_b, 9_999),
            Err(CatError::BadSignature),
            "another election"
        );
        let stranger = SigningKey::from_bytes(&[8u8; 32]).verifying_key();
        assert_eq!(
            token.verify(&stranger, &election, 2, &comm_b, 9_999),
            Err(CatError::BadSignature)
        );
    }

    #[test]
    fn no_field_can_be_changed_after_issuance() {
        let (er, election, comm_b) = fixture();
        let key = er.verifying_key();
        let token = CastingToken::issue(&er, &election, 1, comm_b, 10_000);

        // Re-targeting it to another ballot box, stretching its validity or
        // re-tying it to another ballot all break the signature.
        let mut moved = token.clone();
        moved.bb_id = 2;
        assert_eq!(
            moved.verify(&key, &election, 2, &comm_b, 1),
            Err(CatError::BadSignature)
        );
        let mut extended = token.clone();
        extended.expires_at_ms = u64::MAX;
        assert_eq!(
            extended.verify(&key, &election, 1, &comm_b, 1),
            Err(CatError::BadSignature)
        );
        let other = CommB::from_bytes([5u8; 32]);
        let mut retied = token.clone();
        retied.comm_b = other;
        assert_eq!(
            retied.verify(&key, &election, 1, &other, 1),
            Err(CatError::BadSignature)
        );
        let mut garbled = token;
        garbled.signature = "not base64".into();
        assert_eq!(
            garbled.verify(&key, &election, 1, &comm_b, 1),
            Err(CatError::BadSignature)
        );
    }

    #[test]
    fn a_token_names_nobody() {
        let (er, election, comm_b) = fixture();
        let json =
            serde_json::to_string(&CastingToken::issue(&er, &election, 1, comm_b, 5)).unwrap();
        for field in ["vid", "rid", "fiscal", "voter"] {
            assert!(!json.contains(field), "{json}");
        }
    }
}
