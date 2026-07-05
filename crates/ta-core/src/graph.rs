//! HNSW layered graph structure with canonical adjacency.
//!
//! This module owns the *logical* index structure that the commitment
//! layer (ta-commit) will bind to. Two properties are load-bearing:
//!
//! 1. **Canonical form.** Every adjacency list is kept sorted strictly
//!    ascending by node id — no duplicates, no self-loops — and
//!    [`Graph::adjacency_bytes`] defines the one and only byte encoding
//!    of a node's structural content. The Merkle leaf for node `i` will
//!    be `H(adjacency_bytes(i) ‖ C_i)`. If the same logical graph could
//!    be encoded in two ways, an honest server and verifier could
//!    disagree on the root — or a malicious server could shop between
//!    encodings.
//!
//! 2. **Replay-safe invariants.** Edges at layer `l` may only point to
//!    nodes that exist at layer `l`, and per-layer out-degree is
//!    hard-capped by the committed parameters (`m0` at layer 0, `m`
//!    above). The verifier's greedy replay and the VO-size bounds both
//!    rely on these invariants holding for *any* graph that hashes to
//!    the digest δ.
//!
//! Memory layout is deliberately simple (`Vec` of per-layer `Vec`s).
//! The commitment binds logical content, not memory layout, so a flat
//! arena can replace this later without changing any Merkle root.

/// Node identifier. Dense, assigned in insertion order starting at 0.
pub type NodeId = u32;

/// Structural parameters of the graph. Both values are bound into the
/// committed digest δ, so a server cannot silently use an over-provisioned
/// graph to inflate proofs or reshape search paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HnswParams {
    /// Maximum out-degree on layers >= 1.
    pub m: usize,
    /// Maximum out-degree on layer 0 (conventionally `2 * m`).
    pub m0: usize,
}

impl HnswParams {
    /// Degree cap at a given layer.
    pub fn cap(&self, layer: u8) -> usize {
        if layer == 0 {
            self.m0
        } else {
            self.m
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum GraphError {
    NodeMissing(NodeId),
    LayerOutOfRange { node: NodeId, layer: u8 },
    SelfLoop(NodeId),
    DuplicateEdge { from: NodeId, to: NodeId, layer: u8 },
    CapacityExceeded { node: NodeId, layer: u8, cap: usize },
    /// A neighbor list handed to [`Graph::replace_neighbors`] was not
    /// strictly ascending (canonical form violation).
    NotCanonical,
}

impl std::fmt::Display for GraphError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for GraphError {}

#[derive(Clone, Debug)]
struct Node {
    /// Top layer index this node exists on (a node lives on layers
    /// `0..=level`).
    level: u8,
    /// `neighbors[l]` = adjacency at layer `l`, sorted strictly
    /// ascending. Length is `level + 1`.
    neighbors: Vec<Vec<NodeId>>,
}

#[derive(Clone, Debug)]
pub struct Graph {
    params: HnswParams,
    nodes: Vec<Node>,
    entry: Option<NodeId>,
}

impl Graph {
    pub fn new(params: HnswParams) -> Self {
        assert!(
            params.m >= 1 && params.m0 >= params.m,
            "invalid HnswParams: require m >= 1 and m0 >= m"
        );
        Graph {
            params,
            nodes: Vec::new(),
            entry: None,
        }
    }

    pub fn params(&self) -> HnswParams {
        self.params
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Deterministic entry point: the node with the highest level, ties
    /// broken toward the smallest id (implemented by replacing the entry
    /// only on a *strictly* greater level). Replay starts here.
    pub fn entry(&self) -> Option<NodeId> {
        self.entry
    }

    pub fn max_level(&self) -> Option<u8> {
        self.entry.map(|e| self.nodes[e as usize].level)
    }

    pub fn level(&self, id: NodeId) -> Result<u8, GraphError> {
        Ok(self.node(id)?.level)
    }

    fn node(&self, id: NodeId) -> Result<&Node, GraphError> {
        self.nodes
            .get(id as usize)
            .ok_or(GraphError::NodeMissing(id))
    }

    /// Append a node existing on layers `0..=level`. Returns its id.
    pub fn add_node(&mut self, level: u8) -> NodeId {
        let id = self.nodes.len() as NodeId;
        self.nodes.push(Node {
            level,
            neighbors: vec![Vec::new(); level as usize + 1],
        });
        let higher = match self.entry {
            None => true,
            Some(e) => level > self.nodes[e as usize].level,
        };
        if higher {
            self.entry = Some(id);
        }
        id
    }

    /// Sorted out-neighbors of `id` at `layer`.
    pub fn neighbors(&self, id: NodeId, layer: u8) -> Result<&[NodeId], GraphError> {
        let n = self.node(id)?;
        if layer > n.level {
            return Err(GraphError::LayerOutOfRange { node: id, layer });
        }
        Ok(&n.neighbors[layer as usize])
    }

    /// Insert the directed edge `from -> to` at `layer`, keeping the
    /// list sorted. Both endpoints must exist at `layer`; the degree
    /// cap is enforced.
    pub fn add_edge(&mut self, from: NodeId, to: NodeId, layer: u8) -> Result<(), GraphError> {
        if from == to {
            return Err(GraphError::SelfLoop(from));
        }
        let from_level = self.level(from)?;
        let to_level = self.level(to)?;
        if layer > from_level {
            return Err(GraphError::LayerOutOfRange { node: from, layer });
        }
        if layer > to_level {
            return Err(GraphError::LayerOutOfRange { node: to, layer });
        }
        let cap = self.params.cap(layer);
        let list = &mut self.nodes[from as usize].neighbors[layer as usize];
        match list.binary_search(&to) {
            Ok(_) => Err(GraphError::DuplicateEdge { from, to, layer }),
            Err(pos) => {
                if list.len() >= cap {
                    return Err(GraphError::CapacityExceeded {
                        node: from,
                        layer,
                        cap,
                    });
                }
                list.insert(pos, to);
                Ok(())
            }
        }
    }

    /// Wholesale replacement of an adjacency list — used by the
    /// build-time pruning heuristic. `list` must already be canonical:
    /// strictly ascending, self-free, within the degree cap, and every
    /// target must exist at `layer`.
    pub fn replace_neighbors(
        &mut self,
        from: NodeId,
        layer: u8,
        list: Vec<NodeId>,
    ) -> Result<(), GraphError> {
        let from_level = self.level(from)?;
        if layer > from_level {
            return Err(GraphError::LayerOutOfRange { node: from, layer });
        }
        let cap = self.params.cap(layer);
        if list.len() > cap {
            return Err(GraphError::CapacityExceeded {
                node: from,
                layer,
                cap,
            });
        }
        if !list.windows(2).all(|w| w[0] < w[1]) {
            return Err(GraphError::NotCanonical);
        }
        for &t in &list {
            if t == from {
                return Err(GraphError::SelfLoop(from));
            }
            let t_level = self.level(t)?;
            if layer > t_level {
                return Err(GraphError::LayerOutOfRange { node: t, layer });
            }
        }
        self.nodes[from as usize].neighbors[layer as usize] = list;
        Ok(())
    }

    /// Canonical structural encoding of node `id`. This is the exact
    /// byte string the commitment layer hashes (with the vector
    /// commitment `C_i` appended). Layout, all little-endian:
    ///
    /// `id: u32 | level: u8 | for each layer 0..=level: (count: u16, count × neighbor id: u32)`
    ///
    /// Any change here is a breaking change to the proof format.
    pub fn adjacency_bytes(&self, id: NodeId) -> Result<Vec<u8>, GraphError> {
        let n = self.node(id)?;
        let mut out = Vec::with_capacity(
            4 + 1 + n.neighbors.iter().map(|l| 2 + 4 * l.len()).sum::<usize>(),
        );
        out.extend_from_slice(&id.to_le_bytes());
        out.push(n.level);
        for list in &n.neighbors {
            debug_assert!(list.len() <= u16::MAX as usize);
            out.extend_from_slice(&(list.len() as u16).to_le_bytes());
            for &nb in list {
                out.extend_from_slice(&nb.to_le_bytes());
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> HnswParams {
        HnswParams { m: 2, m0: 3 }
    }

    #[test]
    fn entry_tracks_highest_level_smallest_id() {
        let mut g = Graph::new(params());
        assert_eq!(g.entry(), None);
        let a = g.add_node(0);
        assert_eq!(g.entry(), Some(a));
        let b = g.add_node(2);
        assert_eq!(g.entry(), Some(b));
        let _c = g.add_node(2); // tie: entry must stay with b (smaller id)
        assert_eq!(g.entry(), Some(b));
        assert_eq!(g.max_level(), Some(2));
    }

    #[test]
    fn add_edge_keeps_sorted_order() {
        let mut g = Graph::new(params());
        let a = g.add_node(0);
        let b = g.add_node(0);
        let c = g.add_node(0);
        let d = g.add_node(0);
        g.add_edge(a, d, 0).unwrap();
        g.add_edge(a, b, 0).unwrap();
        g.add_edge(a, c, 0).unwrap();
        assert_eq!(g.neighbors(a, 0).unwrap(), &[b, c, d]);
    }

    #[test]
    fn rejects_self_loop_duplicate_and_missing() {
        let mut g = Graph::new(params());
        let a = g.add_node(0);
        let b = g.add_node(0);
        assert_eq!(g.add_edge(a, a, 0), Err(GraphError::SelfLoop(a)));
        g.add_edge(a, b, 0).unwrap();
        assert_eq!(
            g.add_edge(a, b, 0),
            Err(GraphError::DuplicateEdge {
                from: a,
                to: b,
                layer: 0
            })
        );
        assert_eq!(g.add_edge(a, 99, 0), Err(GraphError::NodeMissing(99)));
    }

    #[test]
    fn edge_targets_must_exist_at_layer() {
        let mut g = Graph::new(params());
        let a = g.add_node(1);
        let b = g.add_node(0); // b does not exist on layer 1
        assert_eq!(
            g.add_edge(a, b, 1),
            Err(GraphError::LayerOutOfRange { node: b, layer: 1 })
        );
    }

    #[test]
    fn capacity_is_enforced() {
        let mut g = Graph::new(params()); // m0 = 3 at layer 0
        let a = g.add_node(0);
        for _ in 0..3 {
            let x = g.add_node(0);
            g.add_edge(a, x, 0).unwrap();
        }
        let y = g.add_node(0);
        assert_eq!(
            g.add_edge(a, y, 0),
            Err(GraphError::CapacityExceeded {
                node: a,
                layer: 0,
                cap: 3
            })
        );
    }

    #[test]
    fn replace_neighbors_validates_canonical_form() {
        let mut g = Graph::new(params());
        let a = g.add_node(0);
        let b = g.add_node(0);
        let c = g.add_node(0);
        assert_eq!(
            g.replace_neighbors(a, 0, vec![c, b]),
            Err(GraphError::NotCanonical)
        );
        assert_eq!(
            g.replace_neighbors(a, 0, vec![b, b]),
            Err(GraphError::NotCanonical)
        );
        g.replace_neighbors(a, 0, vec![b, c]).unwrap();
        assert_eq!(g.neighbors(a, 0).unwrap(), &[b, c]);
    }

    #[test]
    fn adjacency_bytes_golden() {
        let mut g = Graph::new(params());
        let a = g.add_node(1); // id 0, level 1
        let b = g.add_node(0); // id 1
        let c = g.add_node(1); // id 2, level 1
        g.add_edge(a, b, 0).unwrap();
        g.add_edge(a, c, 0).unwrap();
        g.add_edge(a, c, 1).unwrap();
        let bytes = g.adjacency_bytes(a).unwrap();
        #[rustfmt::skip]
        let expect: Vec<u8> = vec![
            0, 0, 0, 0, // id = 0 (u32 LE)
            1,          // level = 1
            2, 0,       // layer-0 count = 2 (u16 LE)
            1, 0, 0, 0, // neighbor 1
            2, 0, 0, 0, // neighbor 2
            1, 0,       // layer-1 count = 1
            2, 0, 0, 0, // neighbor 2
        ];
        assert_eq!(bytes, expect);
    }

    #[test]
    fn same_logical_graph_same_bytes() {
        // Edge insertion order must not affect the canonical bytes.
        let build = |order: &[(NodeId, NodeId)]| {
            let mut g = Graph::new(params());
            for _ in 0..4 {
                g.add_node(0);
            }
            for &(f, t) in order {
                g.add_edge(f, t, 0).unwrap();
            }
            g.adjacency_bytes(0).unwrap()
        };
        let x = build(&[(0, 1), (0, 2), (0, 3)]);
        let y = build(&[(0, 3), (0, 1), (0, 2)]);
        assert_eq!(x, y);
    }
}
