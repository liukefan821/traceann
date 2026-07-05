//! Layer search primitives.
//!
//! # REPLAY-CRITICAL
//!
//! The two procedures in this module define, step by step, the exact
//! traversal that the verifier will later re-execute from a proof.
//! Every rule below is part of the proof format; changing any of them
//! is a breaking change:
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

use std::cmp::Reverse;
use std::collections::BinaryHeap;

use crate::fixed::{dist, Metric, QVector};
use crate::graph::{Graph, NodeId};

/// Greedy descent used on layers above the query's target layer.
/// Returns the local minimum reached from `ep` at `layer`.
pub fn greedy_search(
    graph: &Graph,
    vectors: &[QVector],
    metric: Metric,
    q: &QVector,
    ep: NodeId,
    layer: u8,
) -> NodeId {
    let mut cur = ep;
    let mut d_cur = dist(metric, q, &vectors[cur as usize]);
    loop {
        let mut best = cur;
        let mut d_best = d_cur;
        for &nb in graph
            .neighbors(cur, layer)
            .expect("greedy_search: invariant violation — cur must exist at layer")
        {
            let d_nb = dist(metric, q, &vectors[nb as usize]);
            if (d_nb, nb) < (d_best, best) {
                best = nb;
                d_best = d_nb;
            }
        }
        if (d_best, best) < (d_cur, cur) {
            cur = best;
            d_cur = d_best;
        } else {
            return cur;
        }
    }
}

/// Best-first search at a single layer (HNSW Algorithm 2), fully
/// deterministic. Returns up to `ef` results sorted ascending by
/// `(dist, id)`.
pub fn search_layer(
    graph: &Graph,
    vectors: &[QVector],
    metric: Metric,
    q: &QVector,
    ep: NodeId,
    ef: usize,
    layer: u8,
) -> Vec<(i64, NodeId)> {
    assert!(ef >= 1, "ef must be >= 1");
    let mut visited = vec![false; graph.len()];
    visited[ep as usize] = true;

    let d_ep = dist(metric, q, &vectors[ep as usize]);
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
        for &nb in graph
            .neighbors(c, layer)
            .expect("search_layer: invariant violation — popped node must exist at layer")
        {
            if visited[nb as usize] {
                continue;
            }
            // Rule 3: visited on scan.
            visited[nb as usize] = true;
            let d_nb = dist(metric, q, &vectors[nb as usize]);
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
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::HnswParams;

    /// 1-D chain: ids 0..6 at x = 0,2,4,6,8,10,12, edges i <-> i+1.
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
        let q = QVector(vec![12]);
        assert_eq!(greedy_search(&g, &vs, Metric::L2Sq, &q, 0, 0), 6);
        let q = QVector(vec![5]);
        // x=5 is equidistant to x=4 (id 2) and x=6 (id 3): tie broken
        // toward the smaller id by rule 6.
        assert_eq!(greedy_search(&g, &vs, Metric::L2Sq, &q, 0, 0), 2);
    }

    #[test]
    fn search_layer_orders_by_dist_then_id() {
        let (g, vs) = chain();
        let q = QVector(vec![5]);
        let w = search_layer(&g, &vs, Metric::L2Sq, &q, 0, 3, 0);
        // dists to x=5: id2 -> 1, id3 -> 1, id1 -> 9. Ties by id.
        assert_eq!(w, vec![(1, 2), (1, 3), (9, 1)]);
    }

    #[test]
    fn search_layer_respects_ef() {
        let (g, vs) = chain();
        let q = QVector(vec![0]);
        let w = search_layer(&g, &vs, Metric::L2Sq, &q, 6, 2, 0);
        assert_eq!(w.len(), 2);
        assert_eq!(w[0], (0, 0));
    }
}
