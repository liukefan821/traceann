# TraceANN

Succinct trace authentication for graph-based approximate nearest neighbor (ANN) search.

TraceANN lets a client holding only a 32-byte digest verify, for **every query**, that the top-k results returned by an untrusted server are exactly the output of a deterministic greedy search over the committed HNSW index — with verification objects sublinear in the vector dimension `d`.

**Status:** early development. API and proof format are unstable.

## Build

```
cargo test
```

## Workspace layout

- `crates/ta-core` — deterministic HNSW core (fixed-point arithmetic, graph, search)
- `crates/ta-commit` — blake3 Merkle commitment layer producing the digest δ
- `crates/ta-proof` — Tier-1 query proofs: prover, six-stage verifier, adversarial tests
- `specs/` — threat model, soundness notes, related-work survey

## License

Apache-2.0
