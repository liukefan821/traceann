//! ta-proof: Tier-1 (Merkle-replay) query proofs for TraceANN.
//!
//! # Protocol
//!
//! * The client pins a digest δ = (root, n, entry, max_level, m, m0,
//!   dim, metric) of the server's committed index.
//! * For a query (q, k, ef) the server returns the top-k result plus a
//!   [`proof::QueryProof`]: Merkle openings of **exactly** the leaves
//!   its deterministic search touched.
//! * The verifier checks the openings against δ.root, strictly decodes
//!   them, and re-executes the *same* search engine
//!   (`ta_core::search::search_with_view`) over the partial view.
//!
//! # Soundness (informal Theorem 1)
//!
//! If `verifier::verify_query(δ, q, k, ef, π)` accepts, then
//! `π.result` equals the output of the deterministic HNSW search with
//! parameters (q, k, ef) on the index committed by δ — unless the
//! adversary produced a blake3 collision (Merkle binding) . A server
//! that skimps on work (smaller ef, wrong path, stale index) either
//! fails an opening, leaves the replay starving for an unopened node
//! (`MissingNode`), or produces a result the replay contradicts
//! (`ResultMismatch`). Completeness: honest proofs always verify, and
//! accepted proofs open exactly the touched set (`UnusedOpenings`
//! rejects padding), so |VO| is precisely the search's data footprint.

pub mod proof;
pub mod prover;
pub mod verifier;
