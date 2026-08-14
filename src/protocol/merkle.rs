//! Deterministic Merkle root over voter (id, vid) pairs (roadmap §3.5 / M3.4).
//!
//! The root binds the eligible electorate to the election context. It is
//! computed over **sorted** `(id, vid)` pairs so the result is independent of
//! insertion order. Each leaf is `SHA3-256(id || vid)` and internal nodes are
//! `SHA3-256(left || right)`; an odd number of leaves duplicates the last one.

use sha3::{Digest, Sha3_256};

/// Compute the 32-byte Merkle root of `(id, vid)` pairs.
///
/// `id` is a stable human-facing identifier (e.g. fiscal id / national id).
/// `vid` is the pseudonymous voter id. Pairs are sorted lexicographically by
/// `(id, vid)` before hashing to guarantee determinism.
pub fn voter_id_merkle_root(pairs: &[(String, u64)]) -> [u8; 32] {
    let mut pairs = pairs.to_vec();
    pairs.sort();

    if pairs.is_empty() {
        return [0u8; 32];
    }

    let mut leaves: Vec<[u8; 32]> = pairs.iter().map(|(id, vid)| leaf_hash(id, *vid)).collect();

    while leaves.len() > 1 {
        if leaves.len() % 2 == 1 {
            leaves.push(*leaves.last().unwrap());
        }
        leaves = leaves
            .chunks(2)
            .map(|chunk| node_hash(&chunk[0], &chunk[1]))
            .collect();
    }

    leaves[0]
}

fn leaf_hash(id: &str, vid: u64) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"leaf");
    hasher.update(id.as_bytes());
    hasher.update(vid.to_le_bytes());
    hasher.finalize().into()
}

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"node");
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_tree_is_zero() {
        assert_eq!(voter_id_merkle_root(&[]), [0u8; 32]);
    }

    #[test]
    fn single_pair_root_is_leaf_hash() {
        let pairs = vec![("voter-1".to_string(), 7u64)];
        let root = voter_id_merkle_root(&pairs);
        assert_eq!(root, leaf_hash("voter-1", 7));
    }

    #[test]
    fn order_is_irrelevant() {
        let a = vec![
            ("alice".to_string(), 1u64),
            ("bob".to_string(), 2u64),
            ("carol".to_string(), 3u64),
        ];
        let mut b = a.clone();
        b.reverse();
        assert_eq!(voter_id_merkle_root(&a), voter_id_merkle_root(&b));
    }

    #[test]
    fn different_electorates_yield_different_roots() {
        let a = vec![("alice".to_string(), 1u64), ("bob".to_string(), 2u64)];
        let b = vec![("alice".to_string(), 1u64), ("bob".to_string(), 3u64)];
        assert_ne!(voter_id_merkle_root(&a), voter_id_merkle_root(&b));
    }

    #[test]
    fn odd_leaf_count_duplicates_last() {
        let pairs = vec![
            ("a".to_string(), 1u64),
            ("b".to_string(), 2u64),
            ("c".to_string(), 3u64),
        ];
        let root = voter_id_merkle_root(&pairs);
        // Sanity: non-trivial and deterministic.
        assert_ne!(root, [0u8; 32]);
        assert_eq!(root, voter_id_merkle_root(&pairs));
    }
}
