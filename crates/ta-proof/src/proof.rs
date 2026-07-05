//! The Tier-1 (Merkle-replay) query proof format.

use ta_commit::merkle::MultiProof;
use ta_core::graph::NodeId;

/// Proof that a claimed top-k result is exactly the output of the
/// deterministic search on the committed index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryProof {
    /// Claimed top-k, ascending by `(dist, id)` — the exact order the
    /// engine returns.
    pub result: Vec<(i64, NodeId)>,
    /// Leaf payloads; `payloads[j]` opens leaf `multi.indices[j]`.
    pub payloads: Vec<Vec<u8>>,
    /// Batch Merkle opening binding every payload to δ.root.
    pub multi: MultiProof,
}

impl QueryProof {
    /// Wire-size estimate in bytes, for VO measurements:
    /// payload bytes + 32 per sibling hash + 8 per opened index +
    /// 12 per result entry (i64 dist + u32 id).
    pub fn size_bytes(&self) -> usize {
        let payload: usize = self.payloads.iter().map(|p| p.len()).sum();
        payload
            + 32 * self.multi.siblings.len()
            + 8 * self.multi.indices.len()
            + 12 * self.result.len()
    }

    /// Number of opened leaves (= touched-set size for honest proofs).
    pub fn opened(&self) -> usize {
        self.multi.indices.len()
    }
}
