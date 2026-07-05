//! Abstract read-only views of an index, and a recording wrapper.
//!
//! # Why a trait (SOUNDNESS-CRITICAL)
//!
//! The verifier must replay the search over *partial* data opened from
//! a proof, rejecting the moment anything it needs is missing. If the
//! prover and the verifier had separate search implementations, every
//! divergence — one tie-break, one stop rule — would be a soundness
//! bug waiting for an adversarial input. Instead TraceANN has ONE
//! search engine (`crate::search`), generic over [`IndexView`]:
//!
//! * the server runs it over [`SliceView`] (full index; a miss is a bug),
//! * the verifier runs it over a partial view built from verified
//!   openings (a miss means the proof is incomplete → reject).
//!
//! Behavioral equality between prover and verifier is therefore
//! structural, not aspirational.
//!
//! [`RecordingView`] wraps any view and records every id whose data is
//! served. Used on both sides: the server extracts the exact touched
//! set (= which leaves to open in the proof); the verifier extracts the
//! used set and checks it equals the opened set, so accepted proofs are
//! *exactly* the touched set — no padding, no omissions.

use std::cell::RefCell;
use std::collections::BTreeSet;

use crate::fixed::QVector;
use crate::graph::{Graph, GraphError, NodeId};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ViewError {
    /// The view has no data for this node (verifier: incomplete proof).
    Missing(NodeId),
    /// The node exists but not on the requested layer.
    LayerOutOfRange { node: NodeId, layer: u8 },
}

impl std::fmt::Display for ViewError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ViewError {}

/// Read-only access to (a subset of) an index. Ids live in `0..len()`.
pub trait IndexView {
    /// Total id space of the committed index (δ.n on the verifier side).
    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn level(&self, id: NodeId) -> Result<u8, ViewError>;

    fn neighbors(&self, id: NodeId, layer: u8) -> Result<&[NodeId], ViewError>;

    fn vector(&self, id: NodeId) -> Result<&QVector, ViewError>;
}

/// Full view over a graph + vector slice (server / build side).
/// Errors from this view indicate internal invariant violations.
pub struct SliceView<'a> {
    pub graph: &'a Graph,
    pub vectors: &'a [QVector],
}

impl IndexView for SliceView<'_> {
    fn len(&self) -> usize {
        self.graph.len()
    }

    fn level(&self, id: NodeId) -> Result<u8, ViewError> {
        self.graph.level(id).map_err(|_| ViewError::Missing(id))
    }

    fn neighbors(&self, id: NodeId, layer: u8) -> Result<&[NodeId], ViewError> {
        self.graph.neighbors(id, layer).map_err(|e| match e {
            GraphError::LayerOutOfRange { node, layer } => {
                ViewError::LayerOutOfRange { node, layer }
            }
            _ => ViewError::Missing(id),
        })
    }

    fn vector(&self, id: NodeId) -> Result<&QVector, ViewError> {
        self.vectors
            .get(id as usize)
            .ok_or(ViewError::Missing(id))
    }
}

/// Wraps any view and records every id whose data is served.
pub struct RecordingView<'a, V: IndexView> {
    inner: &'a V,
    touched: RefCell<BTreeSet<NodeId>>,
}

impl<'a, V: IndexView> RecordingView<'a, V> {
    pub fn new(inner: &'a V) -> Self {
        RecordingView {
            inner,
            touched: RefCell::new(BTreeSet::new()),
        }
    }

    /// The set of ids touched so far, in ascending order.
    pub fn into_touched(self) -> BTreeSet<NodeId> {
        self.touched.into_inner()
    }
}

impl<V: IndexView> IndexView for RecordingView<'_, V> {
    fn len(&self) -> usize {
        self.inner.len()
    }

    fn level(&self, id: NodeId) -> Result<u8, ViewError> {
        self.touched.borrow_mut().insert(id);
        self.inner.level(id)
    }

    fn neighbors(&self, id: NodeId, layer: u8) -> Result<&[NodeId], ViewError> {
        self.touched.borrow_mut().insert(id);
        self.inner.neighbors(id, layer)
    }

    fn vector(&self, id: NodeId) -> Result<&QVector, ViewError> {
        self.touched.borrow_mut().insert(id);
        self.inner.vector(id)
    }
}
