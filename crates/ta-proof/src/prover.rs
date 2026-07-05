//! Server side: run the recorded search and open exactly what it touched.

use ta_commit::commit::{leaf_payload, IndexCommitment};
use ta_core::build::HnswIndex;
use ta_core::fixed::QVector;
use ta_core::graph::NodeId;
use ta_core::search::search_with_view;
use ta_core::view::RecordingView;

use crate::proof::QueryProof;

#[derive(Debug, PartialEq, Eq)]
pub enum ProveError {
    DimMismatch { expected: usize, got: usize },
    /// Nothing to prove: the committed index is empty.
    EmptyIndex,
    /// Invariant violation — the full view can never miss.
    Internal(&'static str),
}

impl std::fmt::Display for ProveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ProveError {}

/// Run the query over the full index while recording the touched set,
/// then open exactly those leaves. The proof is minimal by
/// construction: the verifier's `UnusedOpenings` check would reject
/// anything looser.
pub fn prove_query(
    idx: &HnswIndex,
    com: &IndexCommitment,
    q: &QVector,
    k: usize,
    ef: usize,
) -> Result<QueryProof, ProveError> {
    if q.dim() != idx.dim() {
        return Err(ProveError::DimMismatch {
            expected: idx.dim(),
            got: q.dim(),
        });
    }
    let Some(entry) = idx.graph().entry() else {
        return Err(ProveError::EmptyIndex);
    };
    let max = idx.graph().max_level().expect("entry implies max_level");

    let base = idx.view();
    let rec = RecordingView::new(&base);
    let result = search_with_view(&rec, idx.metric(), entry, max, q, k, ef)
        .map_err(|_| ProveError::Internal("full view cannot miss"))?;
    let touched = rec.into_touched(); // ascending BTreeSet<NodeId>

    let ids: Vec<NodeId> = touched.iter().copied().collect();
    let payloads: Vec<Vec<u8>> = ids
        .iter()
        .map(|&id| leaf_payload(idx, id).expect("touched id exists"))
        .collect();
    let multi = com
        .prove_nodes(&ids)
        .ok_or(ProveError::Internal("touched ids must be provable"))?;

    let proof = QueryProof {
        result,
        payloads,
        multi,
    };
    // Debug-build self-check: the prover verifies its own proof, so any
    // prover/verifier drift explodes immediately in tests instead of
    // surfacing as a mystery rejection later.
    debug_assert!(
        crate::verifier::verify_query(com.digest(), q, k, ef, &proof).is_ok(),
        "prover self-check failed: prover/verifier drift"
    );
    Ok(proof)
}
