//! HNSW index construction.
//!
//! Determinism decisions baked into this module:
//!
//! * **Level assignment without floats.** Standard HNSW draws
//!   `level = floor(-ln(u) * mL)` with `mL = 1/ln(M)`, which is exactly
//!   the geometric distribution `P(level >= l) = M^(-l)`. We realize
//!   the same distribution with an integer Bernoulli chain over a
//!   splitmix64 stream seeded by `(seed, id)` — no `f64::ln`, whose
//!   bit-level output depends on the platform's libm. Same data + same
//!   seed therefore rebuilds a bit-identical graph on x86-64 and
//!   aarch64 alike.
//! * **Old entry first.** `insert` captures the previous entry point
//!   and max level *before* `add_node`: a record-breaking new node
//!   becomes the entry immediately, but it has no edges yet — descending
//!   from it would strand the search and self-select. The new node has
//!   no in-edges during its own insertion, so it is structurally
//!   unreachable and self-loops cannot occur.
//! * **Heuristic selection (HNSW Algorithm 4).** Candidates are scanned
//!   in ascending `(dist, id)` order; `e` is kept iff it is *strictly*
//!   closer to the base point than to every already-kept neighbor.
//!   Overfull reverse lists are re-selected with the same rule and
//!   written back through `Graph::replace_neighbors`, which re-checks
//!   canonical form.

use crate::fixed::{dist, Metric, QVector};
use crate::graph::{Graph, GraphError, HnswParams, NodeId};
use crate::search;
use crate::view::SliceView;

/// Hard cap on layer indices (P(level >= 30) = M^-30 ~ never).
pub const MAX_LEVEL: u8 = 30;

/// Public-domain splitmix64 mixer. Not cryptographic — used only for
/// level assignment and test-data generation, where we need a
/// deterministic, well-mixed integer stream.
#[inline]
pub fn splitmix64(x: u64) -> u64 {
    let mut z = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Deterministic level for node `id`: count consecutive successes of a
/// Bernoulli(~1/m) trial over a splitmix64 chain seeded by (seed, id).
/// `P(level >= l) = m^(-l)` up to a floor bias of ~2^-60 — the same
/// distribution as the textbook `floor(-ln(u) * mL)` with `mL = 1/ln(m)`.
pub fn assign_level(seed: u64, id: NodeId, m: usize) -> u8 {
    debug_assert!(m >= 2);
    let mut s = splitmix64(seed ^ (id as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
    let threshold = u64::MAX / m as u64;
    let mut level = 0u8;
    while level < MAX_LEVEL {
        s = splitmix64(s);
        if s < threshold {
            level += 1;
        } else {
            break;
        }
    }
    level
}

#[derive(Clone, Copy, Debug)]
pub struct BuildParams {
    /// Out-degree target on layers >= 1 (layer-0 cap is `2 * m`).
    pub m: usize,
    /// Beam width used during construction.
    pub ef_construction: usize,
    /// Seed for deterministic level assignment.
    pub seed: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum BuildError {
    DimMismatch { expected: usize, got: usize },
    Graph(GraphError),
}

impl From<GraphError> for BuildError {
    fn from(e: GraphError) -> Self {
        BuildError::Graph(e)
    }
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for BuildError {}

/// An in-memory HNSW index: committed-to-be graph + quantized vectors.
pub struct HnswIndex {
    graph: Graph,
    vectors: Vec<QVector>,
    dim: usize,
    metric: Metric,
    ef_construction: usize,
    seed: u64,
}

impl HnswIndex {
    pub fn new(dim: usize, metric: Metric, p: BuildParams) -> Self {
        assert!(dim >= 1, "dim must be >= 1");
        assert!(p.m >= 2, "m must be >= 2");
        assert!(p.ef_construction >= 1, "ef_construction must be >= 1");
        HnswIndex {
            graph: Graph::new(HnswParams { m: p.m, m0: 2 * p.m }),
            vectors: Vec::new(),
            dim,
            metric,
            ef_construction: p.ef_construction,
            seed: p.seed,
        }
    }

    pub fn len(&self) -> usize {
        self.vectors.len()
    }

    pub fn is_empty(&self) -> bool {
        self.vectors.is_empty()
    }

    pub fn dim(&self) -> usize {
        self.dim
    }

    pub fn metric(&self) -> Metric {
        self.metric
    }

    pub fn seed(&self) -> u64 {
        self.seed
    }

    pub fn graph(&self) -> &Graph {
        &self.graph
    }

    /// Full read-only view over this index (the prover's view).
    pub fn view(&self) -> SliceView<'_> {
        SliceView {
            graph: &self.graph,
            vectors: &self.vectors,
        }
    }

    pub fn vector(&self, id: NodeId) -> Option<&QVector> {
        self.vectors.get(id as usize)
    }

    /// Insert one quantized vector (HNSW Algorithm 1). Node ids are
    /// assigned densely in insertion order.
    pub fn insert(&mut self, v: QVector) -> Result<NodeId, BuildError> {
        if v.dim() != self.dim {
            return Err(BuildError::DimMismatch {
                expected: self.dim,
                got: v.dim(),
            });
        }
        // Capture the pre-insert entry BEFORE add_node (see module doc).
        let old_entry = self.graph.entry();
        let old_max = self.graph.max_level();

        let next = self.graph.len() as NodeId;
        let lvl = assign_level(self.seed, next, self.graph.params().m);
        let id = self.graph.add_node(lvl);
        debug_assert_eq!(id, next);
        self.vectors.push(v);

        let Some(mut ep) = old_entry else {
            return Ok(id); // first node: nothing to connect
        };
        let old_max = old_max.expect("entry implies max_level");
        // Clone q (and neighbor base vectors below) to sidestep split
        // borrows; build-time cost is negligible next to search.
        let q = self.vectors[id as usize].clone();

        // Phase 1: greedy descent on layers above lvl.
        let mut lc = old_max;
        while lc > lvl {
            ep = search::greedy_search(
                &SliceView { graph: &self.graph, vectors: &self.vectors },
                self.metric,
                &q,
                ep,
                lc,
            )
            .expect("full view cannot miss");
            lc -= 1;
        }

        // Phase 2: connect on layers min(lvl, old_max)..=0.
        let m = self.graph.params().m;
        for layer in (0..=lvl.min(old_max)).rev() {
            let w = search::search_layer(
                &SliceView { graph: &self.graph, vectors: &self.vectors },
                self.metric,
                &q,
                ep,
                self.ef_construction,
                layer,
            )
            .expect("full view cannot miss");
            let selected = select_neighbors_heuristic(&self.vectors, self.metric, &w, m);
            for &(_, n) in &selected {
                self.graph.add_edge(id, n, layer)?;
            }
            for &(_, n) in &selected {
                let cap = self.graph.params().cap(layer);
                if self.graph.neighbors(n, layer)?.len() < cap {
                    self.graph.add_edge(n, id, layer)?;
                } else {
                    // Reverse list overfull: re-select from old ∪ {id}
                    // with respect to n's own vector.
                    let nv = self.vectors[n as usize].clone();
                    let mut pool: Vec<(i64, NodeId)> = self
                        .graph
                        .neighbors(n, layer)?
                        .iter()
                        .map(|&x| (dist(self.metric, &nv, &self.vectors[x as usize]), x))
                        .collect();
                    pool.push((dist(self.metric, &nv, &self.vectors[id as usize]), id));
                    pool.sort_unstable();
                    let keep =
                        select_neighbors_heuristic(&self.vectors, self.metric, &pool, cap);
                    let mut ids: Vec<NodeId> = keep.iter().map(|&(_, x)| x).collect();
                    ids.sort_unstable();
                    self.graph.replace_neighbors(n, layer, ids)?;
                }
            }
            ep = w[0].1; // best of W seeds the next lower layer
        }
        Ok(id)
    }

    /// Query: delegates to the single shared engine
    /// (`search::search_with_view`) over the full view — the same
    /// function the verifier replays over a partial view.
    pub fn search(&self, q: &QVector, k: usize, ef: usize) -> Result<Vec<(i64, NodeId)>, BuildError> {
        if q.dim() != self.dim {
            return Err(BuildError::DimMismatch {
                expected: self.dim,
                got: q.dim(),
            });
        }
        let Some(entry) = self.graph.entry() else {
            return Ok(Vec::new());
        };
        let max = self.graph.max_level().expect("entry implies max_level");
        Ok(
            search::search_with_view(&self.view(), self.metric, entry, max, q, k, ef)
                .expect("full view cannot miss"),
        )
    }
}

/// HNSW Algorithm 4 (simplified: no extendCandidates /
/// keepPrunedConnections). `cands` must be sorted ascending by
/// `(dist, id)`, where dist is measured to a common base point; returns
/// at most `m` kept entries in scan order. Keep rule: `e` survives iff
/// `dist(e, base) < dist(e, r)` for every already-kept `r` — and since
/// `dist(e, base)` is exactly the `d_e` stored in `cands`, the base
/// vector itself is never needed here.
pub(crate) fn select_neighbors_heuristic(
    vectors: &[QVector],
    metric: Metric,
    cands: &[(i64, NodeId)],
    m: usize,
) -> Vec<(i64, NodeId)> {
    let mut kept: Vec<(i64, NodeId)> = Vec::new();
    for &(d_e, e) in cands {
        if kept.len() >= m {
            break;
        }
        let diverse = kept
            .iter()
            .all(|&(_, r)| dist(metric, &vectors[e as usize], &vectors[r as usize]) > d_e);
        if diverse {
            kept.push((d_e, e));
        }
    }
    kept
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixed::{dist, Metric, QVector};
    use crate::graph::NodeId;

    /// Deterministic pseudo-random i8 vector from (seed, i).
    fn hv(seed: u64, i: u64, d: usize) -> QVector {
        let mut s = splitmix64(seed ^ i.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        let mut v = Vec::with_capacity(d);
        for _ in 0..d {
            s = splitmix64(s);
            v.push((s & 0xFF) as u8 as i8);
        }
        QVector(v)
    }

    fn build(n: usize, d: usize, seed: u64) -> HnswIndex {
        let mut idx = HnswIndex::new(
            d,
            Metric::L2Sq,
            BuildParams {
                m: 8,
                ef_construction: 64,
                seed,
            },
        );
        for i in 0..n {
            idx.insert(hv(0xDA7A, i as u64, d)).unwrap();
        }
        idx
    }

    #[test]
    fn level_distribution_is_geometric() {
        let m = 16usize;
        let n = 100_000u32;
        let ge1 = (0..n).filter(|&i| assign_level(42, i, m) >= 1).count() as f64 / n as f64;
        // P(level >= 1) = 1/16 = 0.0625; deterministic, wide-margin check.
        assert!(ge1 > 0.055 && ge1 < 0.070, "P(level>=1) = {ge1}");
        let max = (0..n).map(|i| assign_level(42, i, m)).max().unwrap();
        assert!(max <= MAX_LEVEL);
        assert!(max >= 2, "with 1e5 samples some node should reach level 2+");
    }

    #[test]
    fn rebuild_is_bit_identical() {
        let a = build(300, 8, 7);
        let b = build(300, 8, 7);
        assert_eq!(a.graph().entry(), b.graph().entry());
        for id in 0..300u32 {
            assert_eq!(
                a.graph().adjacency_bytes(id).unwrap(),
                b.graph().adjacency_bytes(id).unwrap()
            );
        }
    }

    #[test]
    fn self_query_returns_self_top1() {
        let idx = build(200, 16, 3);
        for id in 0..200u32 {
            let q = idx.vector(id).unwrap().clone();
            let w = idx.search(&q, 1, 64).unwrap();
            assert_eq!(w[0].0, 0, "self distance must be 0");
            assert_eq!(w[0].1, id);
        }
    }

    #[test]
    fn recall_at_10_beats_090_on_small_set() {
        let n = 400usize;
        let d = 16usize;
        let idx = build(n, d, 11);
        let queries = 50usize;
        let mut total = 0usize;
        for qi in 0..queries {
            let q = hv(0xBEEF, qi as u64, d);
            let mut exact: Vec<(i64, NodeId)> = (0..n as u32)
                .map(|id| (dist(Metric::L2Sq, &q, idx.vector(id).unwrap()), id))
                .collect();
            exact.sort_unstable();
            let truth: std::collections::HashSet<NodeId> =
                exact[..10].iter().map(|&(_, id)| id).collect();
            let w = idx.search(&q, 10, 64).unwrap();
            total += w.iter().filter(|&&(_, id)| truth.contains(&id)).count();
        }
        let recall = total as f64 / (10 * queries) as f64;
        assert!(recall >= 0.90, "recall@10 = {recall}");
    }

    #[test]
    fn dim_mismatch_is_rejected() {
        let mut idx = HnswIndex::new(
            4,
            Metric::L2Sq,
            BuildParams {
                m: 4,
                ef_construction: 8,
                seed: 0,
            },
        );
        assert_eq!(
            idx.insert(QVector(vec![1, 2, 3])),
            Err(BuildError::DimMismatch {
                expected: 4,
                got: 3
            })
        );
    }
}
