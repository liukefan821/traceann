# TraceANN Threat Model

*This document is normative for the implementation and feeds §3 of the
paper. Anything not guaranteed here is not guaranteed anywhere.*

## Setting

Outsourced vector search. Three roles (the first two may coincide):

- **Owner** — builds the index over a corpus of quantized vectors,
  computes the commitment, and publishes the digest δ.
- **Server** — stores the index and answers queries `(q, k, ef)` with a
  top-k result and a proof π. Untrusted.
- **Client (verifier)** — holds only δ (≈ 100 bytes: Merkle root,
  leaf count n, entry id, max level, degree caps m/m₀, dimension,
  metric tag) and its own query parameters. Honest.

δ is assumed to reach the client authentically (signed release,
pinned configuration, or an on-chain anchor); its distribution is out
of band and out of scope.

## Adversary

A malicious server with full control over its storage, computation,
and network responses, adaptive across queries. In particular it may:

1. **Tamper** — answer from a modified copy of the index (altered
   vectors, edges, or entry point).
2. **Skimp** — run a cheaper search than requested (smaller ef, wrong
   entry, truncated traversal) while charging for the full one
   ("service-level cheating").
3. **Forge** — return fabricated results, fabricated openings, padded
   or truncated proofs, or proofs generated against a different index.
4. **Equivocate within a proof** — open a leaf at position i whose
   decoded identity is j ≠ i.

## Guarantees

- **Per-query integrity (trace consistency).** If the verifier
  accepts, the returned `(distance, id)` list is exactly the output of
  the canonical deterministic search with parameters `(q, k, ef)` on
  the index committed by δ (Theorem 1, `specs/soundness.md`), except
  with probability bounded by the collision advantage against blake3.
- **Completeness.** Honest proofs always verify.
- **Tightness.** Accepted proofs open *exactly* the set of nodes the
  search touches — no padding (`UnusedOpenings`), no omissions
  (`MissingNode`). |VO| therefore equals the search's data footprint.

## Non-goals (explicit)

- **Confidentiality / privacy.** Queries, vectors, and graph structure
  are in plaintext; the protocol proves integrity only. (Contrast:
  zk-based audit systems trade orders-of-magnitude prover cost for
  hiding.)
- **Index quality.** The server commits whatever index it likes; the
  guarantee is consistency with *that* commitment and the declared
  parameters. Accuracy expectations are conveyed by the committed
  parameters (m, m₀, metric) and the published recall characteristics
  of the construction, not by the proof.
- **Availability.** A server may refuse to answer; detection of
  refusal is trivial and remediation is contractual.
- **Freshness across re-commits.** The current system verifies against
  a single committed snapshot. Journaled epochs with a signed root
  chain are designed (see `ta-commit::journal`, future work) but not
  yet part of the verified surface.

## Assumptions

- blake3 is collision resistant (Merkle binding; domain-separated
  leaf/node/empty hashing rules out cross-domain second preimages).
- The verifier's replay engine is the exact code path used by the
  prover (`ta_core::search::search_with_view`); behavioral equality is
  structural, not duplicated.
- Integer-exact arithmetic: all committed data and all distance
  computations are over fixed-point integers, so replay is bit-exact
  across architectures (demonstrated by identical digests on x86-64
  Linux and aarch64 macOS).
