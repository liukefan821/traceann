//! Binding a built HNSW index to a digest δ.
//!
//! # FORMAT-CRITICAL
//!
//! Leaf payload for node `i` (Tier-1 / Merkle-replay format):
//!
//! ```text
//! adjacency_bytes(i) ‖ raw quantized vector (dim bytes, i8 as u8)
//! ```
//!
//! `adjacency_bytes` is self-delimiting and `dim` is bound in δ, so the
//! concatenation is unambiguous. In the later succinct tier the raw
//! vector is replaced by a 32-byte Pedersen commitment — the Merkle
//! machinery above stays byte-for-byte identical.
//!
//! δ binds *everything the verifier's replay depends on*: root, real
//! leaf count `n`, entry point, max level, degree caps `m`/`m0`, `dim`
//! and the metric. Omitting any of these would let a malicious server
//! answer queries against a different index shape than the one the
//! client pinned.

use ta_core::build::HnswIndex;
use ta_core::fixed::Metric;
use ta_core::graph::NodeId;

use crate::merkle::{leaf_hash, Hash, MerkleProof, MerkleTree, MultiProof};

/// Version-bearing domain string; bump on any format change.
pub const DIGEST_DOMAIN: &[u8] = b"traceann/digest/v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Digest {
    pub root: Hash,
    /// Real (unpadded) leaf count.
    pub n: u64,
    pub entry: Option<NodeId>,
    pub max_level: u8,
    pub m: u32,
    pub m0: u32,
    pub dim: u32,
    pub metric: Metric,
}

impl Digest {
    /// Canonical little-endian encoding (format-critical).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(DIGEST_DOMAIN.len() + 64);
        out.extend_from_slice(DIGEST_DOMAIN);
        out.extend_from_slice(&self.root);
        out.extend_from_slice(&self.n.to_le_bytes());
        match self.entry {
            None => out.push(0),
            Some(e) => {
                out.push(1);
                out.extend_from_slice(&e.to_le_bytes());
            }
        }
        out.push(self.max_level);
        out.extend_from_slice(&self.m.to_le_bytes());
        out.extend_from_slice(&self.m0.to_le_bytes());
        out.extend_from_slice(&self.dim.to_le_bytes());
        out.push(match self.metric {
            Metric::L2Sq => 0,
            Metric::InnerProduct => 1,
        });
        out
    }

    /// 32-byte checksum a client can pin instead of the full struct.
    pub fn checksum(&self) -> Hash {
        *blake3::hash(&self.to_bytes()).as_bytes()
    }
}

/// Server-side handle: the digest plus the Merkle tree used to open
/// individual nodes.
pub struct IndexCommitment {
    digest: Digest,
    tree: MerkleTree,
}

impl IndexCommitment {
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    /// Opening for node `id` against `digest().root`.
    pub fn prove_node(&self, id: NodeId) -> Option<MerkleProof> {
        self.tree.prove(id as usize)
    }

    /// Batch opening for an ascending set of node ids (the prover's
    /// touched set, as yielded by `RecordingView::into_touched`).
    pub fn prove_nodes(&self, ids: &[NodeId]) -> Option<MultiProof> {
        let idx: Vec<usize> = ids.iter().map(|&i| i as usize).collect();
        self.tree.prove_multi(&idx)
    }
}

/// Canonical leaf payload of node `id` (server side). Note the id is
/// embedded via `adjacency_bytes`, so two nodes with identical vectors
/// still have distinct payloads — a proof for node `i` can never verify
/// against node `j`'s content.
pub fn leaf_payload(idx: &HnswIndex, id: NodeId) -> Option<Vec<u8>> {
    let adj = idx.graph().adjacency_bytes(id).ok()?;
    let v = idx.vector(id)?;
    let mut out = adj;
    out.reserve(v.0.len());
    out.extend(v.0.iter().map(|&x| x as u8));
    Some(out)
}

/// A leaf payload parsed back into structured form (verifier side).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedNode {
    pub id: NodeId,
    pub level: u8,
    /// `neighbors[l]` = adjacency at layer `l`, exactly as committed.
    pub neighbors: Vec<Vec<NodeId>>,
    pub vector: ta_core::fixed::QVector,
}

/// Strict inverse of [`leaf_payload`]. Consumes the byte string
/// exactly — any missing or trailing byte yields `None` — so a payload
/// has one and only one parse (non-malleable).
pub fn decode_leaf_payload(payload: &[u8], dim: usize) -> Option<DecodedNode> {
    fn take<'a>(p: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
        if p.len() < n {
            return None;
        }
        let (a, b) = p.split_at(n);
        *p = b;
        Some(a)
    }
    let mut p = payload;
    let id = u32::from_le_bytes(take(&mut p, 4)?.try_into().ok()?);
    let level = take(&mut p, 1)?[0];
    let mut neighbors = Vec::with_capacity(level as usize + 1);
    for _ in 0..=level {
        let cnt = u16::from_le_bytes(take(&mut p, 2)?.try_into().ok()?) as usize;
        let mut list = Vec::with_capacity(cnt);
        for _ in 0..cnt {
            list.push(u32::from_le_bytes(take(&mut p, 4)?.try_into().ok()?));
        }
        neighbors.push(list);
    }
    let vec_bytes = take(&mut p, dim)?;
    if !p.is_empty() {
        return None;
    }
    let vector = ta_core::fixed::QVector(vec_bytes.iter().map(|&b| b as i8).collect());
    Some(DecodedNode {
        id,
        level,
        neighbors,
        vector,
    })
}

/// Commit a built index: hash every node's canonical payload into a
/// Merkle tree and bind all replay-relevant parameters into δ.
pub fn commit_index(idx: &HnswIndex) -> IndexCommitment {
    let n = idx.len();
    let leaves: Vec<Hash> = (0..n as NodeId)
        .map(|id| leaf_hash(&leaf_payload(idx, id).expect("id < n")))
        .collect();
    let tree = MerkleTree::from_leaf_hashes(leaves);
    let p = idx.graph().params();
    let digest = Digest {
        root: tree.root(),
        n: n as u64,
        entry: idx.graph().entry(),
        max_level: idx.graph().max_level().unwrap_or(0),
        m: p.m as u32,
        m0: p.m0 as u32,
        dim: idx.dim() as u32,
        metric: idx.metric(),
    };
    IndexCommitment { digest, tree }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::verify;
    use ta_core::build::{BuildParams, HnswIndex};
    use ta_core::fixed::{Metric, QVector};

    fn tiny(seed: u64) -> HnswIndex {
        let mut idx = HnswIndex::new(
            2,
            Metric::L2Sq,
            BuildParams {
                m: 2,
                ef_construction: 8,
                seed,
            },
        );
        for v in [[1, 2], [3, 4], [5, 6], [7, 8]] {
            idx.insert(QVector(v.to_vec())).unwrap();
        }
        idx
    }

    #[test]
    fn leaf_payload_decodes_back_exactly() {
        let idx = tiny(5);
        for id in 0..idx.len() as u32 {
            let payload = leaf_payload(&idx, id).unwrap();
            let node = decode_leaf_payload(&payload, idx.dim()).unwrap();
            assert_eq!(node.id, id);
            assert_eq!(node.level, idx.graph().level(id).unwrap());
            for l in 0..=node.level {
                assert_eq!(
                    node.neighbors[l as usize].as_slice(),
                    idx.graph().neighbors(id, l).unwrap()
                );
            }
            assert_eq!(&node.vector, idx.vector(id).unwrap());
            // Strict length: trailing or missing bytes kill the parse.
            let mut long = payload.clone();
            long.push(0);
            assert!(decode_leaf_payload(&long, idx.dim()).is_none());
            assert!(decode_leaf_payload(&payload[..payload.len() - 1], idx.dim()).is_none());
        }
    }

    #[test]
    fn commit_is_deterministic() {
        assert_eq!(
            commit_index(&tiny(1)).digest(),
            commit_index(&tiny(1)).digest()
        );
    }

    #[test]
    fn commit_binds_every_vector_byte() {
        let a = commit_index(&tiny(1)).digest().root;
        let mut idx = HnswIndex::new(
            2,
            Metric::L2Sq,
            BuildParams {
                m: 2,
                ef_construction: 8,
                seed: 1,
            },
        );
        for v in [[1, 2], [3, 4], [5, 7], [7, 8]] {
            // one byte differs   ^
            idx.insert(QVector(v.to_vec())).unwrap();
        }
        assert_ne!(a, commit_index(&idx).digest().root);
    }

    #[test]
    fn node_proofs_verify_against_root_and_bind_identity() {
        let idx = tiny(9);
        let c = commit_index(&idx);
        let d = c.digest();
        for id in 0..idx.len() as u32 {
            let proof = c.prove_node(id).unwrap();
            let payload = leaf_payload(&idx, id).unwrap();
            assert!(verify(&d.root, d.n, &proof, &payload));
            // Another node's payload must fail under this proof — the
            // id inside adjacency_bytes binds identity.
            let other = leaf_payload(&idx, (id + 1) % d.n as u32).unwrap();
            assert!(!verify(&d.root, d.n, &proof, &other));
        }
    }

    #[test]
    fn digest_checksum_golden_cross_platform() {
        // This exact hex must reproduce on x86-64 Linux and aarch64
        // macOS alike — integer-only build + canonical encodings +
        // blake3. If this test ever diverges across machines, the
        // reproducible-commitment story is broken and we stop the line.
        let hex = hex32(&commit_index(&tiny(1)).digest().checksum());
        assert_eq!(
            hex,
            "1035b4b4de5a174aa30177ca52fd0a3bd98f4a12b1be8364c4d2841862a332a1"
        );
    }

    fn hex32(h: &Hash) -> String {
        h.iter().map(|b| format!("{b:02x}")).collect()
    }
}
