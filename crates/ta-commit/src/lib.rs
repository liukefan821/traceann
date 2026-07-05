//! ta-commit: Merkle commitment layer for TraceANN.
//!
//! Produces the digest δ that a verifier pins, and per-node openings
//! against it. blake3 throughout; every constant in `merkle` and
//! `commit` is proof-format-critical.

pub mod commit;
pub mod merkle;
