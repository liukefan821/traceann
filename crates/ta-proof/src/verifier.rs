//! Client side: verify openings against δ, rebuild a partial view,
//! replay the SAME engine, and bind the claimed result bit-for-bit.

use std::collections::{BTreeMap, BTreeSet};

use ta_commit::commit::{decode_leaf_payload, DecodedNode, Digest};
use ta_commit::merkle::verify_multi;
use ta_core::fixed::QVector;
use ta_core::graph::NodeId;
use ta_core::search::search_with_view;
use ta_core::view::{IndexView, RecordingView, ViewError};

use crate::proof::QueryProof;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyError {
    DimMismatch { expected: u32, got: u32 },
    /// δ commits an empty index; only the empty result is acceptable.
    EmptyIndexNonEmptyResult,
    /// The Merkle multiproof failed against δ.root / δ.n.
    BadOpening,
    /// A payload failed strict decoding.
    MalformedPayload { position: usize },
    /// Opened position and decoded identity disagree.
    IdMismatch { claimed: u64, decoded: NodeId },
    /// The replay needed a node that was not opened — the signature of
    /// a lazy or path-forging server.
    MissingNode(NodeId),
    /// Node opened, but the replay asked for a layer it doesn't carry.
    LayerOutOfRange { node: NodeId, layer: u8 },
    /// The replayed top-k contradicts the claimed result.
    ResultMismatch,
    /// Openings the replay never used — padded proof.
    UnusedOpenings,
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for VerifyError {}

/// Partial view rebuilt from verified openings. Any access outside the
/// opened set is a [`ViewError::Missing`], mapped to rejection.
struct LocalView {
    /// Committed id space (δ.n) — NOT the number of openings; the
    /// visited bitmap in the engine is sized by this.
    n: usize,
    nodes: BTreeMap<NodeId, DecodedNode>,
}

impl IndexView for LocalView {
    fn len(&self) -> usize {
        self.n
    }

    fn level(&self, id: NodeId) -> Result<u8, ViewError> {
        self.nodes
            .get(&id)
            .map(|n| n.level)
            .ok_or(ViewError::Missing(id))
    }

    fn neighbors(&self, id: NodeId, layer: u8) -> Result<&[NodeId], ViewError> {
        let n = self.nodes.get(&id).ok_or(ViewError::Missing(id))?;
        n.neighbors
            .get(layer as usize)
            .map(|v| v.as_slice())
            .ok_or(ViewError::LayerOutOfRange { node: id, layer })
    }

    fn vector(&self, id: NodeId) -> Result<&QVector, ViewError> {
        self.nodes
            .get(&id)
            .map(|n| &n.vector)
            .ok_or(ViewError::Missing(id))
    }
}

/// The six-stage verification pipeline. See the crate docs for the
/// soundness statement this implements.
pub fn verify_query(
    digest: &Digest,
    q: &QVector,
    k: usize,
    ef: usize,
    proof: &QueryProof,
) -> Result<(), VerifyError> {
    // 1. Dimension binding + empty-index convention.
    if q.dim() as u32 != digest.dim {
        return Err(VerifyError::DimMismatch {
            expected: digest.dim,
            got: q.dim() as u32,
        });
    }
    let Some(entry) = digest.entry else {
        return if proof.result.is_empty()
            && proof.payloads.is_empty()
            && proof.multi.indices.is_empty()
        {
            Ok(())
        } else {
            Err(VerifyError::EmptyIndexNonEmptyResult)
        };
    };
    // 2. Structural binding: every payload opens against δ.root / δ.n.
    if !verify_multi(&digest.root, digest.n, &proof.multi, &proof.payloads) {
        return Err(VerifyError::BadOpening);
    }
    // 3. Strict decode + position↔identity binding.
    let mut nodes: BTreeMap<NodeId, DecodedNode> = BTreeMap::new();
    for (j, (payload, &pos)) in proof
        .payloads
        .iter()
        .zip(&proof.multi.indices)
        .enumerate()
    {
        let node = decode_leaf_payload(payload, digest.dim as usize)
            .ok_or(VerifyError::MalformedPayload { position: j })?;
        if node.id as u64 != pos {
            return Err(VerifyError::IdMismatch {
                claimed: pos,
                decoded: node.id,
            });
        }
        nodes.insert(node.id, node);
    }
    let opened: BTreeSet<NodeId> = nodes.keys().copied().collect();
    // 4. Replay with the SAME engine over the partial view.
    let local = LocalView {
        n: digest.n as usize,
        nodes,
    };
    let rec = RecordingView::new(&local);
    let replayed = search_with_view(&rec, digest.metric, entry, digest.max_level, q, k, ef)
        .map_err(|e| match e {
            ViewError::Missing(id) => VerifyError::MissingNode(id),
            ViewError::LayerOutOfRange { node, layer } => {
                VerifyError::LayerOutOfRange { node, layer }
            }
        })?;
    // 5. Exact result binding: distances and ids, order and all.
    if replayed != proof.result {
        return Err(VerifyError::ResultMismatch);
    }
    // 6. Tightness: accepted proofs are exactly the touched set.
    if rec.into_touched() != opened {
        return Err(VerifyError::UnusedOpenings);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover::{prove_query, ProveError};
    use ta_commit::commit::{commit_index, leaf_payload, IndexCommitment};
    use ta_core::build::{splitmix64, BuildParams, HnswIndex};
    use ta_core::fixed::Metric;

    fn hv(seed: u64, i: u64, d: usize) -> QVector {
        let mut s = splitmix64(seed ^ i.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        let mut v = Vec::with_capacity(d);
        for _ in 0..d {
            s = splitmix64(s);
            v.push((s & 0xFF) as u8 as i8);
        }
        QVector(v)
    }

    fn make(n: usize, dim: usize, seed: u64) -> (HnswIndex, IndexCommitment) {
        let mut idx = HnswIndex::new(
            dim,
            Metric::L2Sq,
            BuildParams {
                m: 8,
                ef_construction: 64,
                seed,
            },
        );
        for i in 0..n {
            idx.insert(hv(0xDA7A, i as u64, dim)).unwrap();
        }
        let com = commit_index(&idx);
        (idx, com)
    }

    #[test]
    fn honest_proofs_verify_and_match_direct_search() {
        let (idx, com) = make(300, 16, 7);
        let d = com.digest();
        for qi in 0..10u64 {
            let q = hv(0xBEEF, qi, 16);
            let proof = prove_query(&idx, &com, &q, 10, 16).unwrap();
            assert_eq!(proof.result, idx.search(&q, 10, 16).unwrap());
            verify_query(d, &q, 10, 16, &proof).unwrap();
            // VO is sublinear in n even at toy scale: far fewer leaves
            // opened than the index holds.
            assert!(proof.opened() < 300 / 2, "opened = {}", proof.opened());
        }
    }

    #[test]
    fn lazy_server_lower_ef_is_caught() {
        let (idx, com) = make(300, 16, 7);
        let d = com.digest();
        let q = hv(0xBEEF, 3, 16);
        // The server actually searched with ef = 8 ...
        let cheap = prove_query(&idx, &com, &q, 10, 8).unwrap();
        // ... but the client demanded ef = 32. The replay at ef = 32
        // walks past the opened frontier: caught red-handed. (The only
        // other reachable outcome, ResultMismatch, rejects equally; and
        // if neither fired, the cheap answer WAS the honest ef=32
        // answer — no cheating occurred, by definition.)
        let err = verify_query(d, &q, 10, 32, &cheap).unwrap_err();
        assert!(matches!(err, VerifyError::MissingNode(_)), "got {err:?}");
    }

    #[test]
    fn tampered_result_is_caught() {
        let (idx, com) = make(200, 16, 5);
        let d = com.digest();
        let q = hv(0xF00D, 1, 16);
        let mut proof = prove_query(&idx, &com, &q, 5, 16).unwrap();
        proof.result.swap(0, 1);
        assert_eq!(
            verify_query(d, &q, 5, 16, &proof),
            Err(VerifyError::ResultMismatch)
        );
    }

    #[test]
    fn tampered_payload_is_caught() {
        let (idx, com) = make(200, 16, 5);
        let d = com.digest();
        let q = hv(0xF00D, 2, 16);
        let mut proof = prove_query(&idx, &com, &q, 5, 16).unwrap();
        proof.payloads[0][0] ^= 1;
        assert_eq!(
            verify_query(d, &q, 5, 16, &proof),
            Err(VerifyError::BadOpening)
        );
    }

    #[test]
    fn proof_from_a_different_index_is_rejected() {
        let (idx_a, com_a) = make(200, 16, 5);
        let (_idx_b, com_b) = make(200, 16, 999);
        let q = hv(0xF00D, 3, 16);
        let proof = prove_query(&idx_a, &com_a, &q, 5, 16).unwrap();
        assert_eq!(
            verify_query(com_b.digest(), &q, 5, 16, &proof),
            Err(VerifyError::BadOpening)
        );
    }

    #[test]
    fn padded_proof_is_rejected() {
        let (idx, com) = make(200, 16, 5);
        let d = com.digest();
        let q = hv(0xF00D, 4, 16);
        let honest = prove_query(&idx, &com, &q, 5, 16).unwrap();
        let touched: BTreeSet<u64> = honest.multi.indices.iter().copied().collect();
        // Open one extra, untouched node on top of the honest set.
        let extra = (0..d.n).find(|i| !touched.contains(i)).unwrap();
        let mut ids: Vec<NodeId> = honest.multi.indices.iter().map(|&i| i as NodeId).collect();
        ids.push(extra as NodeId);
        ids.sort_unstable();
        let payloads: Vec<Vec<u8>> = ids
            .iter()
            .map(|&id| leaf_payload(&idx, id).unwrap())
            .collect();
        let multi = com.prove_nodes(&ids).unwrap();
        let padded = QueryProof {
            result: honest.result.clone(),
            payloads,
            multi,
        };
        assert_eq!(
            verify_query(d, &q, 5, 16, &padded),
            Err(VerifyError::UnusedOpenings)
        );
    }

    #[test]
    fn truncated_openings_are_rejected() {
        let (idx, com) = make(200, 16, 5);
        let d = com.digest();
        let q = hv(0xF00D, 5, 16);
        let mut proof = prove_query(&idx, &com, &q, 5, 16).unwrap();
        proof.payloads.pop();
        proof.multi.indices.pop();
        assert_eq!(
            verify_query(d, &q, 5, 16, &proof),
            Err(VerifyError::BadOpening)
        );
    }

    #[test]
    fn empty_index_conventions() {
        let idx = HnswIndex::new(
            4,
            Metric::L2Sq,
            BuildParams {
                m: 2,
                ef_construction: 4,
                seed: 0,
            },
        );
        let com = commit_index(&idx);
        let q = QVector(vec![0, 0, 0, 0]);
        assert_eq!(
            prove_query(&idx, &com, &q, 3, 8),
            Err(ProveError::EmptyIndex)
        );
        let empty = QueryProof {
            result: vec![],
            payloads: vec![],
            multi: ta_commit::merkle::MultiProof {
                indices: vec![],
                siblings: vec![],
            },
        };
        verify_query(com.digest(), &q, 3, 8, &empty).unwrap();
        let mut nonempty = empty.clone();
        nonempty.result.push((0, 0));
        assert_eq!(
            verify_query(com.digest(), &q, 3, 8, &nonempty),
            Err(VerifyError::EmptyIndexNonEmptyResult)
        );
    }
}
