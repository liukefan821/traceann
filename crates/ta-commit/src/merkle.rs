//! Padded binary Merkle tree over blake3 with domain separation.
//!
//! # FORMAT-CRITICAL
//!
//! * Leaf hash = `blake3(0x00 ‖ payload)`; inner node =
//!   `blake3(0x01 ‖ L ‖ R)`. The prefix bytes put leaves and inner
//!   nodes in different hash domains, blocking the classic
//!   second-preimage attack where an inner node value is replayed as a
//!   leaf (or a 64-byte leaf as an inner node).
//! * Leaves are padded to the next power of two with
//!   `EMPTY = blake3(0x02 ‖ "traceann/empty-leaf/v1")`: uniform proof
//!   depth `ceil(log2 n)` and trivial index arithmetic
//!   (sibling = `i ^ 1`, parent = `i >> 1`). The *real* leaf count `n`
//!   is bound inside the digest δ, and [`verify`] derives the expected
//!   depth from `n` — so padding can never be confused with data and a
//!   proof for a different tree shape is rejected outright.
//! * Changing any prefix or the padding rule changes every root: all of
//!   this is proof format, not implementation detail.

pub type Hash = [u8; 32];

const LEAF_PREFIX: u8 = 0x00;
const NODE_PREFIX: u8 = 0x01;
const EMPTY_PREFIX: u8 = 0x02;

pub fn leaf_hash(payload: &[u8]) -> Hash {
    let mut h = blake3::Hasher::new();
    h.update(&[LEAF_PREFIX]);
    h.update(payload);
    *h.finalize().as_bytes()
}

pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut h = blake3::Hasher::new();
    h.update(&[NODE_PREFIX]);
    h.update(left);
    h.update(right);
    *h.finalize().as_bytes()
}

/// Padding leaf for indices beyond the real leaf count.
pub fn empty_leaf() -> Hash {
    let mut h = blake3::Hasher::new();
    h.update(&[EMPTY_PREFIX]);
    h.update(b"traceann/empty-leaf/v1");
    *h.finalize().as_bytes()
}

/// Uniform proof depth for `n` real leaves (0 for n <= 1).
pub fn depth_for(n: usize) -> u32 {
    n.max(1).next_power_of_two().trailing_zeros()
}

pub struct MerkleTree {
    /// `levels[0]` = padded leaf hashes; `levels[depth]` = `[root]`.
    levels: Vec<Vec<Hash>>,
    n_leaves: usize,
}

impl MerkleTree {
    pub fn from_leaf_hashes(mut leaves: Vec<Hash>) -> MerkleTree {
        let n_leaves = leaves.len();
        let padded = n_leaves.max(1).next_power_of_two();
        leaves.resize(padded, empty_leaf());
        let mut levels = vec![leaves];
        while levels.last().unwrap().len() > 1 {
            let next: Vec<Hash> = levels
                .last()
                .unwrap()
                .chunks_exact(2)
                .map(|p| node_hash(&p[0], &p[1]))
                .collect();
            levels.push(next);
        }
        MerkleTree { levels, n_leaves }
    }

    pub fn root(&self) -> Hash {
        self.levels.last().unwrap()[0]
    }

    /// Real (unpadded) leaf count.
    pub fn len(&self) -> usize {
        self.n_leaves
    }

    pub fn is_empty(&self) -> bool {
        self.n_leaves == 0
    }

    pub fn depth(&self) -> u32 {
        (self.levels.len() - 1) as u32
    }

    /// Bottom-up sibling path for a real leaf; `None` if out of range.
    pub fn prove(&self, index: usize) -> Option<MerkleProof> {
        if index >= self.n_leaves {
            return None;
        }
        let mut siblings = Vec::with_capacity(self.depth() as usize);
        let mut i = index;
        for lvl in 0..self.depth() as usize {
            siblings.push(self.levels[lvl][i ^ 1]);
            i >>= 1;
        }
        Some(MerkleProof {
            index: index as u64,
            siblings,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleProof {
    pub index: u64,
    /// Sibling hashes, leaf level first.
    pub siblings: Vec<Hash>,
}

/// Verify that `payload` is the content of leaf `proof.index` in the
/// tree with `root` over `n_leaves` real leaves. The expected depth is
/// derived from `n_leaves`, so proofs for a different tree shape fail.
pub fn verify(root: &Hash, n_leaves: u64, proof: &MerkleProof, payload: &[u8]) -> bool {
    if proof.index >= n_leaves {
        return false;
    }
    if proof.siblings.len() as u32 != depth_for(n_leaves as usize) {
        return false;
    }
    let mut acc = leaf_hash(payload);
    let mut i = proof.index;
    for s in &proof.siblings {
        acc = if i & 1 == 0 {
            node_hash(&acc, s)
        } else {
            node_hash(s, &acc)
        };
        i >>= 1;
    }
    acc == *root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lh(b: u8) -> Hash {
        leaf_hash(&[b])
    }

    #[test]
    fn domain_separation_blocks_node_as_leaf() {
        let a = lh(1);
        let b = lh(2);
        let inner = node_hash(&a, &b);
        let mut cat = Vec::new();
        cat.extend_from_slice(&a);
        cat.extend_from_slice(&b);
        // Without the 0x00/0x01 prefixes these two would collide — the
        // textbook Merkle second-preimage attack.
        assert_ne!(inner, leaf_hash(&cat));
    }

    #[test]
    fn small_tree_roots_match_manual_construction() {
        let t1 = MerkleTree::from_leaf_hashes(vec![lh(1)]);
        assert_eq!(t1.root(), lh(1));
        assert_eq!(t1.depth(), 0);

        let t2 = MerkleTree::from_leaf_hashes(vec![lh(1), lh(2)]);
        assert_eq!(t2.root(), node_hash(&lh(1), &lh(2)));

        // 3 leaves pad to 4 with EMPTY.
        let t3 = MerkleTree::from_leaf_hashes(vec![lh(1), lh(2), lh(3)]);
        let expect = node_hash(
            &node_hash(&lh(1), &lh(2)),
            &node_hash(&lh(3), &empty_leaf()),
        );
        assert_eq!(t3.root(), expect);
        assert_eq!(t3.depth(), 2);
    }

    #[test]
    fn prove_verify_roundtrip_all_indices() {
        let payloads: Vec<Vec<u8>> = (0u8..5).map(|i| vec![i, i + 10]).collect();
        let leaves: Vec<Hash> = payloads.iter().map(|p| leaf_hash(p)).collect();
        let t = MerkleTree::from_leaf_hashes(leaves);
        let root = t.root();
        for (i, p) in payloads.iter().enumerate() {
            let proof = t.prove(i).unwrap();
            assert!(verify(&root, 5, &proof, p));
            assert!(!verify(&root, 5, &proof, b"wrong payload"));
        }
        assert!(t.prove(5).is_none());
    }

    #[test]
    fn verify_rejects_wrong_shape_index_and_truncation() {
        let leaves: Vec<Hash> = (0u8..4).map(|i| leaf_hash(&[i])).collect();
        let t = MerkleTree::from_leaf_hashes(leaves);
        let root = t.root();
        let proof = t.prove(2).unwrap();
        assert!(verify(&root, 4, &proof, &[2]));
        // Wrong claimed n => wrong expected depth => reject.
        assert!(!verify(&root, 8, &proof, &[2]));
        // Index beyond claimed n => reject.
        let mut bad = proof.clone();
        bad.index = 7;
        assert!(!verify(&root, 4, &bad, &[2]));
        // Truncated sibling path => reject.
        let mut short = proof.clone();
        short.siblings.pop();
        assert!(!verify(&root, 4, &short, &[2]));
    }
}
