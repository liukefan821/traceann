//! Layer search primitives — ONE engine, generic over [`IndexView`].
//!
//! # REPLAY-CRITICAL
//!
//! The procedures in this module define, step by step, the exact
//! traversal that the verifier re-executes from a proof. Every rule
//! below is part of the proof format; changing any of them is a
//! breaking change:
//!
//! 1. All orderings are on the tuple `(dist, id)` — smaller wins.
//!    Distance ties are broken toward the smaller node id, everywhere.
//! 2. Neighbors of a popped node are scanned in canonical (ascending
//!    id) order, i.e. exactly the committed adjacency order.
//! 3. A node is marked visited the moment it is *scanned*, whether or
//!    not it is admitted to the result set.
//! 4. `search_layer` admission: when the result set is full (`ef`
//!    entries), a scanned node is admitted iff its `(dist, id)` tuple
//!    is strictly smaller than the current worst tuple; the worst is
//!    then evicted.
//! 5. `search_layer` termination: pop the best candidate `c`; if the
//!    result set is full and `dist(c) > dist(worst)` (pure distance,
//!    ties continue), stop.
//! 6. `greedy_search` move rule: among the current node's neighbors,
//!    let `best` be the minimum by `(dist, id)`; move iff
//!    `(dist_best, best) < (dist_cur, cur)`, else stop.
//! 7. `search_with_view` runs greedy descent on layers
//!    `max_level..=1`, then `search_layer` at layer 0 with beam
//!    `ef.max(k).max(1)`, truncated to `k`. The same normalization is
//!    applied by prover and verifier.
//!
//! Any node the engine cannot obtain from the view aborts the search
//! with [`ViewError`] — on the verifier side that means the proof is
//! incomplete and must be rejected.

use std::cmp::Reverse;
use std::collections::BinaryHeap;

use crate::fixed::{dist, Metric, QVector};
use crate::graph::NodeId;
use crate::view::{IndexView, ViewError};

/// Greedy descent used on layers above the query's target layer.
/// Returns the local minimum reached from `ep` at `layer`.
pub fn greedy_search<V: IndexView>(
    view: &V,
    metric: Metric,
    q: &QVector,
    ep: NodeId,
    layer: u8,
) -> Result<NodeId, ViewError> {
    let mut cur = ep;
    let mut d_cur = dist(metric, q, view.vector(cur)?);
    loop {
        let mut best = cur;
        let mut d_best = d_cur;
        for &nb in view.neighbors(cur, layer)? {
            let d_nb = dist(metric, q, view.vector(nb)?);
            if (d_nb, nb) < (d_best, best) {
                best = nb;
                d_best = d_nb;
            }
        }
        if (d_best, best) < (d_cur, cur) {
            cur = best;
            d_cur = d_best;
        } else {
            return Ok(cur);
        }
    }
}

/// Best-first search at a single layer (HNSW Algorithm 2), fully
/// deterministic. Returns up to `ef` results sorted ascending by
/// `(dist, id)`.
pub fn search_layer<V: IndexView>(
    view: &V,
    metric: Metric,
    q: &QVector,
    ep: NodeId,
    ef: usize,
    layer: u8,
) -> Result<Vec<(i64, NodeId)>, ViewError> {
    assert!(ef >= 1, "ef must be >= 1");
    let mut visited = vec![false; view.len()];
    if ep as usize >= visited.len() {
        return Err(ViewError::Missing(ep));
    }
    visited[ep as usize] = true;

    let d_ep = dist(metric, q, view.vector(ep)?);
    // Min-heap of candidates to expand, keyed by (dist, id).
    let mut cand: BinaryHeap<Reverse<(i64, NodeId)>> = BinaryHeap::new();
    cand.push(Reverse((d_ep, ep)));
    // Max-heap of current results: peek() is the worst kept entry.
    let mut results: BinaryHeap<(i64, NodeId)> = BinaryHeap::new();
    results.push((d_ep, ep));

    while let Some(Reverse((d_c, c))) = cand.pop() {
        let &(d_worst, _) = results.peek().expect("results never empty");
        // Rule 5: pure-distance stop condition (ties continue).
        if results.len() == ef && d_c > d_worst {
            break;
        }
        // Rule 2: canonical ascending scan order.
        for &nb in view.neighbors(c, layer)? {
            if (nb as usize) >= visited.len() {
                // A committed edge pointing outside the id space can
                // only come from a malformed index; never panic on it.
                return Err(ViewError::Missing(nb));
            }
            if visited[nb as usize] {
                continue;
            }
            // Rule 3: visited on scan.
            visited[nb as usize] = true;
            let d_nb = dist(metric, q, view.vector(nb)?);
            let worst = *results.peek().expect("results never empty");
            if results.len() < ef {
                cand.push(Reverse((d_nb, nb)));
                results.push((d_nb, nb));
            } else if (d_nb, nb) < worst {
                // Rule 4: strict tuple admission + eviction.
                cand.push(Reverse((d_nb, nb)));
                results.push((d_nb, nb));
                results.pop();
            }
        }
    }

    let mut out: Vec<(i64, NodeId)> = results.into_vec();
    out.sort_unstable();
    Ok(out)
}

/// Full deterministic query (rule 7). REPLAY-CRITICAL: both the prover
/// and the verifier call exactly this function — the prover over the
/// full index, the verifier over the partial view opened from a proof.
pub fn search_with_view<V: IndexView>(
    view: &V,
    metric: Metric,
    entry: NodeId,
    max_level: u8,
    q: &QVector,
    k: usize,
    ef: usize,
) -> Result<Vec<(i64, NodeId)>, ViewError> {
    let mut ep = entry;
    for lc in (1..=max_level).rev() {
        ep = greedy_search(view, metric, q, ep, lc)?;
    }
    let mut w = search_layer(view, metric, q, ep, ef.max(k).max(1), 0)?;
    w.truncate(k);
    Ok(w)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{Graph, HnswParams};
    use crate::view::{RecordingView, SliceView};
    use std::collections::BTreeSet;

    /// 1-D chain: ids 0..7 at x = 0,2,4,6,8,10,12, edges i <-> i+1.
    fn chain() -> (Graph, Vec<QVector>) {
        let mut g = Graph::new(HnswParams { m: 2, m0: 3 });
        let xs: Vec<i8> = vec![0, 2, 4, 6, 8, 10, 12];
        let mut vs = Vec::new();
        for &x in &xs {
            g.add_node(0);
            vs.push(QVector(vec![x]));
        }
        for i in 0..(xs.len() - 1) as NodeId {
            g.add_edge(i, i + 1, 0).unwrap();
            g.add_edge(i + 1, i, 0).unwrap();
        }
        (g, vs)
    }

    #[test]
    fn greedy_walks_to_local_minimum() {
        let (g, vs) = chain();
        let v = SliceView { graph: &g, vectors: &vs };
        let q = QVector(vec![12]);
        assert_eq!(greedy_search(&v, Metric::L2Sq, &q, 0, 0).unwrap(), 6);
        let q = QVector(vec![5]);
        // x=5 is equidistant to x=4 (id 2) and x=6 (id 3): tie broken
        // toward the smaller id by rule 6.
        assert_eq!(greedy_search(&v, Metric::L2Sq, &q, 0, 0).unwrap(), 2);
    }

    #[test]
    fn search_layer_orders_by_dist_then_id() {
        let (g, vs) = chain();
        let v = SliceView { graph: &g, vectors: &vs };
        let q = QVector(vec![5]);
        let w = search_layer(&v, Metric::L2Sq, &q, 0, 3, 0).unwrap();
        // dists to x=5: id2 -> 1, id3 -> 1, id1 -> 9. Ties by id.
        assert_eq!(w, vec![(1, 2), (1, 3), (9, 1)]);
    }

    #[test]
    fn search_layer_respects_ef() {
        let (g, vs) = chain();
        let v = SliceView { graph: &g, vectors: &vs };
        let q = QVector(vec![0]);
        let w = search_layer(&v, Metric::L2Sq, &q, 6, 2, 0).unwrap();
        assert_eq!(w.len(), 2);
        assert_eq!(w[0], (0, 0));
    }

    #[test]
    fn recording_view_captures_exact_touched_set() {
        let (g, vs) = chain();
        let base = SliceView { graph: &g, vectors: &vs };
        let rec = RecordingView::new(&base);
        let q = QVector(vec![5]);
        let w = search_layer(&rec, Metric::L2Sq, &q, 0, 3, 0).unwrap();
        assert_eq!(w.len(), 3);
        // The search from id 0 scans vectors of {0,1,2,3,4} and expands
        // neighbors of {0,1,2,3}; ids 5 and 6 are never touched — the
        // proof for this query would open exactly these five leaves.
        let touched = rec.into_touched();
        let expect: BTreeSet<NodeId> = [0, 1, 2, 3, 4].into_iter().collect();
        assert_eq!(touched, expect);
    }
}
