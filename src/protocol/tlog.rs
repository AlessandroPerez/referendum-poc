//! Verification of the bulletin board as a transparency log (Sec. 3.4: the
//! board is insert-only and inconsistent views are detectable).
//!
//! An auditor must not take the board's entry list on trust. This module
//! gives it everything needed to check that list against the board's own
//! signed tree head, using only public data and a log key PINNED at the
//! setup ceremony:
//!   - the log's public key, derived from the ceremony seed exactly as the
//!     board derives its signing key (so it can be pinned without asking the
//!     board);
//!   - the Merkle leaf hash of a sequenced entry, byte for byte as the board
//!     builds it;
//!   - the Merkle tree hash of RFC 6962 over a list of leaf hashes;
//!   - parsing and signature verification of a signed checkpoint note.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use hmac::{Hmac, Mac};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::EncodePublicKey;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// A SHA-256 Merkle hash.
pub type Hash = [u8; 32];

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TlogError {
    #[error("malformed checkpoint: {0}")]
    MalformedCheckpoint(String),
    #[error("checkpoint is not signed by the pinned log key")]
    BadSignature,
    #[error("log key derivation failed")]
    KeyDerivation,
    #[error("entry data longer than the leaf format allows")]
    LeafTooLarge,
}

fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

/// The board's log key, derived from the ceremony's 32-byte seed the way the
/// board does it: HKDF-SHA256(seed, salt "sunlight", info "ECDSA P-256 log
/// key") feeds a deterministic key generation (HMAC_DRBG with a fixed
/// personalization string, candidates rejected until one is a valid scalar).
pub fn derive_log_public_key(seed: &[u8; 32]) -> Result<VerifyingKey, TlogError> {
    // HKDF extract-then-expand, first output block.
    let prk = hmac_sha256(b"sunlight", &[seed]);
    let secret = hmac_sha256(&prk, &[b"ECDSA P-256 log key", &[0x01]]);

    // HMAC_DRBG instantiate.
    let personalization: &[u8] = b"det ECDSA key gen P-256";
    let mut v = [0x01u8; 32];
    let mut k = [0x00u8; 32];
    k = hmac_sha256(&k, &[&v, &[0x00], &secret, personalization]);
    v = hmac_sha256(&k, &[&v]);

    // Two candidates at most, as in the reference implementation.
    for attempt in 0..2 {
        k = if attempt == 0 {
            hmac_sha256(&k, &[&v, &[0x01], &secret, personalization])
        } else {
            hmac_sha256(&k, &[&v, &[0x00]])
        };
        v = hmac_sha256(&k, &[&v]);
        v = hmac_sha256(&k, &[&v]);
        if let Ok(secret_key) = p256::SecretKey::from_slice(&v) {
            return Ok(VerifyingKey::from(secret_key.public_key()));
        }
    }
    Err(TlogError::KeyDerivation)
}

/// Merkle leaf hash of one sequenced entry: `SHA-256(0x00 || leaf)` where
/// `leaf` is the board's timestamped-entry structure over the entry's exact
/// bytes, its sequencing timestamp and its index.
pub fn leaf_hash(data: &[u8], leaf_index: u64, timestamp_ms: i64) -> Result<Hash, TlogError> {
    if data.len() >= 1 << 24 || leaf_index >= 1 << 40 {
        return Err(TlogError::LeafTooLarge);
    }
    let mut hasher = Sha256::new();
    hasher.update([0x00]); // RFC 6962 leaf prefix
    hasher.update([0x00, 0x00]); // version v1, leaf type timestamped_entry
    hasher.update((timestamp_ms as u64).to_be_bytes());
    hasher.update([0x00, 0x00]); // entry type: generic blob
    hasher.update(&(data.len() as u32).to_be_bytes()[1..]); // u24 length
    hasher.update(data);
    // extensions: u16 length, then one leaf_index extension
    // (type 0, u16 length 5, 40-bit index).
    hasher.update([0x00, 0x08, 0x00, 0x00, 0x05]);
    hasher.update(&leaf_index.to_be_bytes()[3..]);
    Ok(hasher.finalize().into())
}

/// RFC 6962 Merkle tree hash of `leaves` (already leaf-hashed). `None` for an
/// empty list: the board never signs an empty tree into a checkpoint we audit.
pub fn tree_root(leaves: &[Hash]) -> Option<Hash> {
    match leaves.len() {
        0 => None,
        1 => Some(leaves[0]),
        n => {
            // Split at the largest power of two strictly smaller than n.
            let split = 1usize << (usize::BITS - 1 - (n - 1).leading_zeros());
            let left = tree_root(&leaves[..split])?;
            let right = tree_root(&leaves[split..])?;
            let mut hasher = Sha256::new();
            hasher.update([0x01]);
            hasher.update(left);
            hasher.update(right);
            Some(hasher.finalize().into())
        }
    }
}

/// A verified tree head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    pub origin: String,
    pub size: u64,
    pub root: Hash,
}

/// Parse a signed checkpoint note and verify the log's signature on it with
/// the PINNED key. The note is `origin\nsize\nbase64(root)\n\n` followed by
/// signature lines `-- name base64(keyhash4 || timestamp8 || r32 || s32)`
/// (the dash is U+2014); the signature is ECDSA P-256 over SHA-256 of the
/// text part.
pub fn verify_checkpoint(note: &[u8], log_key: &VerifyingKey) -> Result<Checkpoint, TlogError> {
    let malformed = |what: &str| TlogError::MalformedCheckpoint(what.to_string());
    let note = std::str::from_utf8(note).map_err(|_| malformed("not UTF-8"))?;
    let (text, signatures) = note
        .split_once("\n\n")
        .ok_or_else(|| malformed("no signature block"))?;
    let text = format!("{text}\n");

    let mut lines = text.lines();
    let origin = lines
        .next()
        .ok_or_else(|| malformed("no origin"))?
        .to_string();
    let size: u64 = lines
        .next()
        .and_then(|l| l.parse().ok())
        .ok_or_else(|| malformed("no tree size"))?;
    let root: Hash = lines
        .next()
        .and_then(|l| BASE64.decode(l).ok())
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| malformed("no root hash"))?;
    if lines.next().is_some() {
        return Err(malformed("unexpected extension lines"));
    }

    // The key hash binds the signature line to (origin, key): first four
    // bytes of SHA-256(origin || "\n" || 0x03 || PKIX(key)).
    let pkix = log_key
        .to_public_key_der()
        .map_err(|_| TlogError::KeyDerivation)?;
    let mut hasher = Sha256::new();
    hasher.update(origin.as_bytes());
    hasher.update(b"\n");
    hasher.update([0x03]);
    hasher.update(pkix.as_bytes());
    let expected_key_hash: [u8; 4] = hasher.finalize()[..4].try_into().expect("4 bytes");

    let digest = Sha256::digest(text.as_bytes());
    let dash = "\u{2014} ";
    for line in signatures.lines() {
        let Some(rest) = line.strip_prefix(dash) else {
            continue;
        };
        let Some((name, sig_b64)) = rest.rsplit_once(' ') else {
            continue;
        };
        let Ok(sig) = BASE64.decode(sig_b64) else {
            continue;
        };
        if name != origin || sig.len() != 4 + 8 + 64 || sig[..4] != expected_key_hash {
            continue;
        }
        let Ok(signature) = Signature::from_slice(&sig[12..]) else {
            continue;
        };
        if log_key.verify_prehash(&digest, &signature).is_ok() {
            return Ok(Checkpoint { origin, size, root });
        }
    }
    Err(TlogError::BadSignature)
}

/// The name a board signs its tree heads under: its host and path, without
/// scheme, port or trailing slash (`https://127.0.0.1:8443/wbb/` ->
/// `127.0.0.1/wbb`).
pub fn log_origin_of(board_url: &url::Url) -> String {
    format!(
        "{}{}",
        board_url.host_str().unwrap_or_default(),
        board_url.path().trim_end_matches('/')
    )
}

/// PKIX (SubjectPublicKeyInfo) DER of a log key, base64: the form the board
/// publishes in its metadata and the ceremony pins.
pub fn log_key_to_base64(key: &VerifyingKey) -> Result<String, TlogError> {
    key.to_public_key_der()
        .map(|der| BASE64.encode(der.as_bytes()))
        .map_err(|_| TlogError::KeyDerivation)
}

/// Inverse of [`log_key_to_base64`].
pub fn log_key_from_base64(text: &str) -> Result<VerifyingKey, TlogError> {
    use p256::pkcs8::DecodePublicKey;
    let der = BASE64
        .decode(text.trim())
        .map_err(|_| TlogError::KeyDerivation)?;
    VerifyingKey::from_public_key_der(&der).map_err(|_| TlogError::KeyDerivation)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Reference values produced by the board's own Go code (HKDF + keygen,
    // `LogEntry.MerkleTreeLeaf`, `tlog.TreeHash`) for seed 01..20 and five
    // entries `{"n":i}` at index i, timestamp 1_700_000_000_000 + i.
    const GO_PKIX_B64: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8/AqAGHLJBTYEoX5abmY0+HAKSkaI1+Lw1yX6F92Hd1VSf+onQGN67Rt9GiOpwvGmw5/ab0L3ZM1+psrdmGRtA==";
    const GO_LEAVES: [&str; 5] = [
        "7104a73a5f1722d64242f2e4abf13300c9e6d28043640feac8af77dfb5cc25a1",
        "1df3fb17dcdc2540a1b146e54b87806750d354a781c2b098aa12bffc0cfc20ba",
        "940b715a8ed6f4d11d1eae14d8998710c784c8f872a8d1cb1a2fa98c7ab7b547",
        "6d4e682d2393e423b46f2557324d852ea15c75c79162737e3fba388de9a38221",
        "1fed129a9c59a9c6d1ba6b7a72d6125310a3179025276f1da750da815720d4f4",
    ];
    const GO_ROOTS: [&str; 5] = [
        "7104a73a5f1722d64242f2e4abf13300c9e6d28043640feac8af77dfb5cc25a1",
        "c14be4d7e669fea7c464c5fa5499563a4a7dff96390140bdf5df5d07e7cfa968",
        "84d56b79b58abfb5a8f85804b52be0bf46d50342de173a571af9e9c7e980e6de",
        "88ff521f44d56b03aa83ef8a01ea0db8a82c17dc7d8c762b5e07a57746aa4524",
        "f449f38ff909e635f6b83f85b4ecad6b3e401c9fef63b8cfe3d018329206aac0",
    ];

    fn seed() -> [u8; 32] {
        let mut seed = [0u8; 32];
        for (i, byte) in seed.iter_mut().enumerate() {
            *byte = i as u8 + 1;
        }
        seed
    }

    #[test]
    fn log_key_matches_the_boards_derivation() {
        let key = derive_log_public_key(&seed()).unwrap();
        assert_eq!(log_key_to_base64(&key).unwrap(), GO_PKIX_B64);
        assert_eq!(log_key_from_base64(GO_PKIX_B64).unwrap(), key);
    }

    #[test]
    fn leaf_hashes_and_roots_match_the_board() {
        let leaves: Vec<Hash> = (0..5u64)
            .map(|i| {
                leaf_hash(
                    format!("{{\"n\":{i}}}").as_bytes(),
                    i,
                    1_700_000_000_000 + i as i64,
                )
                .unwrap()
            })
            .collect();
        for (leaf, expected) in leaves.iter().zip(GO_LEAVES) {
            assert_eq!(hex::encode(leaf), expected);
        }
        for (n, expected) in GO_ROOTS.iter().enumerate() {
            assert_eq!(hex::encode(tree_root(&leaves[..=n]).unwrap()), *expected);
        }
        assert_eq!(tree_root(&[]), None);
    }

    #[test]
    fn every_field_changes_the_leaf_hash() {
        let base = leaf_hash(b"data", 1, 2).unwrap();
        assert_ne!(leaf_hash(b"datA", 1, 2).unwrap(), base);
        assert_ne!(leaf_hash(b"data", 2, 2).unwrap(), base);
        assert_ne!(leaf_hash(b"data", 1, 3).unwrap(), base);
    }

    /// A tree head signed by the Go board itself (5 entries), with the key
    /// that board ran on.
    const BOARD_KEY: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElGmx+uJkF6EGUD7BOK0/tpr24EvouYOP1FXJk49BzijIDSxnPj9ePLdGvmtcwP2f1YuWjmlVopfwWMh9lV6s5g==";
    const BOARD_NOTE: &str = "127.0.0.1/wbb\n5\nN/5JiQ20MTtw4g9KtG2gLglYfVjbkhXXjlJs+FwfbhM=\n\n\u{2014} 127.0.0.1/wbb UAvrKQAAAaC/YXHFnsoXEXspA1u+YzTJ+PoHvQ7MS1Za3dNUy4xr9U5J/qZO9KoWSV6dDQpF7htO8d3S24YIg3cr2W0lEKUlYtmKfg==\n";

    #[test]
    fn a_tree_head_signed_by_the_board_verifies() {
        let key = log_key_from_base64(BOARD_KEY).unwrap();
        let head = verify_checkpoint(BOARD_NOTE.as_bytes(), &key).unwrap();
        assert_eq!(head.origin, "127.0.0.1/wbb");
        assert_eq!(head.size, 5);
        assert_eq!(hex::encode(&head.root[..8]), "37fe49890db4313b");

        // Any edit of the signed text, or another key, and it no longer does.
        for edited in [
            BOARD_NOTE.replacen("\n5\n", "\n4\n", 1),
            BOARD_NOTE.replacen("N/5J", "N/5K", 1),
            BOARD_NOTE.replacen("127.0.0.1/wbb\n", "127.0.0.2/wbb\n", 1),
        ] {
            assert!(matches!(
                verify_checkpoint(edited.as_bytes(), &key),
                Err(TlogError::BadSignature)
            ));
        }
        let other = derive_log_public_key(&seed()).unwrap();
        assert!(matches!(
            verify_checkpoint(BOARD_NOTE.as_bytes(), &other),
            Err(TlogError::BadSignature)
        ));
    }

    #[test]
    fn malformed_checkpoints_are_rejected() {
        let key = derive_log_public_key(&seed()).unwrap();
        for note in [
            "",
            "origin\n1\n",
            "origin\nx\nAAAA\n\n",
            "o\n1\n!!!\n\n\u{2014} o AAAA\n",
        ] {
            assert!(matches!(
                verify_checkpoint(note.as_bytes(), &key),
                Err(TlogError::MalformedCheckpoint(_))
            ));
        }
        // Well formed, but no signature by the pinned key.
        let root = BASE64.encode([7u8; 32]);
        let unsigned = format!(
            "origin\n3\n{root}\n\n\u{2014} origin {}\n",
            BASE64.encode([0u8; 76])
        );
        assert_eq!(
            verify_checkpoint(unsigned.as_bytes(), &key),
            Err(TlogError::BadSignature)
        );
    }
}
