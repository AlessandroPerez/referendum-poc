//! Verification of the bulletin-board validators' signatures.
//!
//! A validator is an independent party that rebuilds the board's Merkle tree,
//! checks it against the signed tree head, and BLS-signs every leaf it has
//! verified. The board only collects and serves those signatures: whether
//! they are genuine is for the auditor to decide, against validator public
//! keys the auditor PINS itself (the CLI reads them from the election
//! operator's local board configuration, never from the running board).
//!
//! Scheme: BLS12-381, public keys in G1 (48 bytes compressed), signatures in
//! G2 (96 bytes compressed), hash-to-curve with the domain separation tag the
//! validators use.

use blst::min_pk::{PublicKey, SecretKey, Signature};
use blst::BLST_ERROR;

/// Domain separation tag shared with the validators.
pub const DST: &[u8] = b"SUNLIGHT_BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

/// The exact byte string a validator signs for one leaf: a protocol tag, the
/// log origin, the leaf index and the leaf's Merkle hash.
pub fn validation_message(origin: &str, leaf_index: u64, leaf_hash: &[u8; 32]) -> Vec<u8> {
    format!(
        "wbb-validation/v1\n{origin}\n{leaf_index}\n{}\n",
        hex::encode(leaf_hash)
    )
    .into_bytes()
}

/// Whether `signature` is `public_key`'s signature over `message`. Malformed
/// keys or signatures are simply invalid.
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let (Ok(public_key), Ok(signature)) = (
        PublicKey::from_bytes(public_key),
        Signature::from_bytes(signature),
    ) else {
        return false;
    };
    signature.verify(true, message, DST, &[], &public_key, true) == BLST_ERROR::BLST_SUCCESS
}

/// Read `validator_bls_keys` (id -> base64 compressed BLS key) of every log
/// in a board configuration (YAML text). None configured: no validators.
pub fn pinned_keys_from_board_config(yaml: &str) -> Result<Vec<(String, Vec<u8>)>, String> {
    use base64::Engine as _;
    let config: serde_yaml::Value = serde_yaml::from_str(yaml).map_err(|e| e.to_string())?;
    let mut keys = Vec::new();
    for log in config["logs"].as_sequence().into_iter().flatten() {
        let Some(map) = log["validator_bls_keys"].as_mapping() else {
            continue;
        };
        for (id, key) in map {
            let (Some(id), Some(key)) = (id.as_str(), key.as_str()) else {
                return Err("malformed validator_bls_keys".to_string());
            };
            let key = base64::engine::general_purpose::STANDARD
                .decode(key)
                .map_err(|e| format!("validator {id}: {e}"))?;
            if blst::min_pk::PublicKey::from_bytes(&key).is_err() {
                return Err(format!("validator {id}: not a BLS public key"));
            }
            keys.push((id.to_string(), key));
        }
    }
    keys.sort();
    Ok(keys)
}

/// A validator's signing key, derived from a 32-byte seed the way the
/// validator process derives it. Used by tests standing in for a validator.
pub struct ValidatorKey(SecretKey);

impl ValidatorKey {
    pub fn from_seed(seed: &[u8; 32]) -> Option<Self> {
        SecretKey::key_gen(seed, &[]).ok().map(Self)
    }

    /// Compressed public key, as registered with the board and pinned.
    pub fn public_key(&self) -> Vec<u8> {
        self.0.sk_to_pk().compress().to_vec()
    }

    /// Compressed signature over `message`.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.0.sign(message, DST, &[]).compress().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_verify_only_for_their_key_and_message() {
        let key = ValidatorKey::from_seed(&[0x11; 32]).unwrap();
        let other = ValidatorKey::from_seed(&[0x22; 32]).unwrap();
        let message = validation_message("127.0.0.1/wbb", 7, &[5u8; 32]);
        let signature = key.sign(&message);
        assert_eq!(key.public_key().len(), 48);
        assert_eq!(signature.len(), 96);
        assert!(verify(&key.public_key(), &message, &signature));
        assert!(!verify(&other.public_key(), &message, &signature));
        let elsewhere = validation_message("127.0.0.1/wbb", 8, &[5u8; 32]);
        assert!(!verify(&key.public_key(), &elsewhere, &signature));
        assert!(!verify(b"junk", &message, &signature));
        assert!(!verify(&key.public_key(), &message, b"junk"));
    }

    #[test]
    fn validator_keys_are_pinned_from_a_board_config() {
        use base64::Engine as _;
        let b64 =
            |k: &ValidatorKey| base64::engine::general_purpose::STANDARD.encode(k.public_key());
        let (v1, v2) = (
            ValidatorKey::from_seed(&[1; 32]).unwrap(),
            ValidatorKey::from_seed(&[2; 32]).unwrap(),
        );
        let yaml = format!(
            "listen: x\nlogs:\n  - shortname: poc\n    validator_bls_keys:\n      V-2: {}\n      V-1: {}\n",
            b64(&v2),
            b64(&v1)
        );
        let keys = pinned_keys_from_board_config(&yaml).unwrap();
        assert_eq!(
            keys,
            vec![
                ("V-1".to_string(), v1.public_key()),
                ("V-2".to_string(), v2.public_key())
            ]
        );
        // No validators configured, or no logs at all: nothing pinned.
        assert!(pinned_keys_from_board_config("logs:\n  - shortname: poc\n")
            .unwrap()
            .is_empty());
        assert!(pinned_keys_from_board_config("listen: x\n")
            .unwrap()
            .is_empty());
        // A key that is not a BLS key is refused, not silently pinned.
        let bad = "logs:\n  - validator_bls_keys:\n      V-1: AAAA\n";
        assert!(pinned_keys_from_board_config(bad).is_err());
    }

    #[test]
    fn message_binds_origin_index_and_hash() {
        let base = validation_message("a/wbb", 1, &[0u8; 32]);
        assert!(base.starts_with(b"wbb-validation/v1\n"));
        assert_ne!(base, validation_message("b/wbb", 1, &[0u8; 32]));
        assert_ne!(base, validation_message("a/wbb", 2, &[0u8; 32]));
        assert_ne!(base, validation_message("a/wbb", 1, &[1u8; 32]));
    }
}
