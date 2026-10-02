//! Deterministic Merkle root over the (holder, identifier) pairs of an
//! election (Sec. 3.5).
//!
//! The root binds the eligible electorate to the election context. It is
//! computed over **sorted** `(id, vid)` pairs so the result is independent of
//! insertion order. Each leaf is `SHA3-256(id || vid)` and internal nodes are
//! `SHA3-256(left || right)`; an odd number of leaves duplicates the last one.

use sha3::{Digest, Sha3_256};

/// What a leaf commits to: an identifier ASSIGNED to a registered voter, or
/// a SPARE held by nobody until a revocation hands it out (Sec. 3.5.3).
///
/// The kind is part of the leaf, so a proof for a spare can never be passed
/// off as the proof of a voter's own identifier, or the other way round.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum LeafKind {
    Voter,
    Spare,
}

impl LeafKind {
    fn tag(self) -> &'static [u8] {
        match self {
            Self::Voter => b"voter",
            Self::Spare => b"spare",
        }
    }
}

/// Compute the 32-byte Merkle root of `(kind, id, vid)` leaves.
///
/// `id` is a stable human-facing identifier (e.g. fiscal id / national id).
/// `vid` is the pseudonymous voter id. Pairs are sorted lexicographically by
/// `(id, vid)` before hashing to guarantee determinism.
pub fn voter_id_merkle_root(pairs: &[(LeafKind, String, u64)]) -> [u8; 32] {
    let mut pairs = pairs.to_vec();
    pairs.sort();

    if pairs.is_empty() {
        return [0u8; 32];
    }

    let mut leaves: Vec<[u8; 32]> = pairs
        .iter()
        .map(|(kind, id, vid)| leaf_hash(*kind, id, *vid))
        .collect();

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

/// One step of an inclusion proof: the sibling hash and which side it is on.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MerkleStep {
    /// Hex-encoded sibling hash.
    pub sibling: String,
    /// True when the sibling sits on the left of the node being hashed.
    pub sibling_on_left: bool,
}

/// The path proving that `(id, vid)` is one of the pairs behind the root.
///
/// The identifier a voter is handed is otherwise the electoral roll's word
/// alone: with this, the voter checks it against the tree the roll committed
/// to at setup and published on the board (Sec. 3.5.3).
pub fn inclusion_proof(
    pairs: &[(LeafKind, String, u64)],
    kind: LeafKind,
    id: &str,
    vid: u64,
) -> Option<Vec<MerkleStep>> {
    let mut pairs = pairs.to_vec();
    pairs.sort();
    let target = leaf_hash(kind, id, vid);
    let mut index = pairs
        .iter()
        .position(|(k, i, v)| *k == kind && *i == id && *v == vid)?;
    let mut level: Vec<[u8; 32]> = pairs
        .iter()
        .map(|(kind, id, vid)| leaf_hash(*kind, id, *vid))
        .collect();
    debug_assert_eq!(level[index], target);

    let mut path = Vec::new();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last().unwrap());
        }
        let sibling_on_left = index % 2 == 1;
        let sibling = if sibling_on_left {
            level[index - 1]
        } else {
            level[index + 1]
        };
        path.push(MerkleStep {
            sibling: hex::encode(sibling),
            sibling_on_left,
        });
        level = level
            .chunks(2)
            .map(|chunk| node_hash(&chunk[0], &chunk[1]))
            .collect();
        index /= 2;
    }
    Some(path)
}

/// Re-walk an inclusion proof: does `(id, vid)` hash up to `root`?
pub fn verify_inclusion(
    root: &[u8; 32],
    kind: LeafKind,
    id: &str,
    vid: u64,
    path: &[MerkleStep],
) -> bool {
    let mut node = leaf_hash(kind, id, vid);
    for step in path {
        let Ok(sibling) = hex::decode(&step.sibling) else {
            return false;
        };
        let Ok(sibling): Result<[u8; 32], _> = sibling.try_into() else {
            return false;
        };
        node = if step.sibling_on_left {
            node_hash(&sibling, &node)
        } else {
            node_hash(&node, &sibling)
        };
    }
    node == *root
}

fn leaf_hash(kind: LeafKind, id: &str, vid: u64) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"leaf");
    hasher.update(kind.tag());
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

    fn voter(id: &str, vid: u64) -> (LeafKind, String, u64) {
        (LeafKind::Voter, id.to_string(), vid)
    }

    fn spare(id: &str, vid: u64) -> (LeafKind, String, u64) {
        (LeafKind::Spare, id.to_string(), vid)
    }

    #[test]
    fn a_leaf_proves_its_place_in_the_tree_and_nothing_else() {
        let mut pairs: Vec<(LeafKind, String, u64)> = (1..=6u64)
            .map(|i| voter(&format!("VOTER-{i:03}"), 100 + i))
            .collect();
        pairs.push(spare("spare-aaaa", 200));
        let root = voter_id_merkle_root(&pairs);

        for (kind, id, vid) in &pairs {
            let path = inclusion_proof(&pairs, *kind, id, *vid).expect("a leaf of the tree");
            assert!(verify_inclusion(&root, *kind, id, *vid, &path));
            // The same path proves nothing for another holder, another
            // identifier, another tree - or the other kind of leaf.
            assert!(!verify_inclusion(&root, *kind, "VOTER-999", *vid, &path));
            assert!(!verify_inclusion(&root, *kind, id, vid + 1, &path));
            assert!(!verify_inclusion(&[9u8; 32], *kind, id, *vid, &path));
            let other = match kind {
                LeafKind::Voter => LeafKind::Spare,
                LeafKind::Spare => LeafKind::Voter,
            };
            assert!(
                !verify_inclusion(&root, other, id, *vid, &path),
                "a spare must not pass as a voter's own identifier, or the reverse"
            );
        }
        assert!(inclusion_proof(&pairs, LeafKind::Voter, "VOTER-999", 1).is_none());
        assert!(inclusion_proof(&pairs, LeafKind::Voter, "spare-aaaa", 200).is_none());
    }

    #[test]
    fn empty_tree_is_zero() {
        assert_eq!(voter_id_merkle_root(&[]), [0u8; 32]);
    }

    #[test]
    fn single_pair_root_is_leaf_hash() {
        let pairs = vec![voter("voter-1", 7)];
        let root = voter_id_merkle_root(&pairs);
        assert_eq!(root, leaf_hash(LeafKind::Voter, "voter-1", 7));
    }

    #[test]
    fn order_is_irrelevant() {
        let a = vec![voter("alice", 1), voter("bob", 2), voter("carol", 3)];
        let mut b = a.clone();
        b.reverse();
        assert_eq!(voter_id_merkle_root(&a), voter_id_merkle_root(&b));
    }

    #[test]
    fn different_electorates_yield_different_roots() {
        let a = vec![voter("alice", 1), voter("bob", 2)];
        let b = vec![voter("alice", 1), voter("bob", 3)];
        assert_ne!(voter_id_merkle_root(&a), voter_id_merkle_root(&b));
    }

    #[test]
    fn odd_leaf_count_duplicates_last() {
        let pairs = vec![voter("a", 1), voter("b", 2), voter("c", 3)];
        let root = voter_id_merkle_root(&pairs);
        // Sanity: non-trivial and deterministic.
        assert_ne!(root, [0u8; 32]);
        assert_eq!(root, voter_id_merkle_root(&pairs));
    }
}
