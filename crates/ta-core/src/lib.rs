//! ta-core: deterministic HNSW core for TraceANN.
//!
//! Everything in this crate is bit-deterministic across platforms:
//! integer-only distance arithmetic, canonical orderings, and (later)
//! a best-first search whose traversal can be replayed by a verifier.

pub mod build;
pub mod fixed;
pub mod graph;
pub mod search;
pub mod view;
