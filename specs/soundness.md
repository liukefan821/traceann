# Trace Consistency: Definitions and Soundness

*Feeds §5 of the paper. Notation matches the code; every definition
cites the module that implements it.*

## 1. Objects

**Index.** `I = (G, X)` with committed parameters
`P = (n, e*, L, m, m0, dim, metric)`:

- `G` — a layered graph over ids `[n] = {0, …, n−1}`; node `i` exists
  on layers `0..=level(i)`; adjacency lists are canonical (strictly
  ascending ids, no self-loops, per-layer degree ≤ m₀ at layer 0 and
  ≤ m above); edges at layer ℓ point only to nodes existing at ℓ
  (`ta-core::graph`).
- `X : [n] → ℤ_{i8}^{dim}` — quantized vectors.
- `e*` — entry point (highest level, ties to the smallest id); `L` its
  level.

**Canonical payload.** `payload_i = adjbytes(i) ‖ vecbytes(i)` — a
byte string with exactly one parse (`ta-commit::commit::
decode_leaf_payload` consumes it strictly). Distinct nodes have
distinct payloads because the id is embedded in `adjbytes`.

**Commitment.** `δ = Commit(I) = (root, P)` where `root` is the
domain-separated, power-of-two-padded Merkle root over
`H_leaf(payload_0), …, H_leaf(payload_{n−1})` (`ta-commit::merkle`).

**Deterministic search.** `S(I, q, k, ef)` is the output of the fixed
engine (`ta-core::search`, replay rules R1–R7): greedy descent on
layers `L..1`, best-first at layer 0 with beam `max(ef, k, 1)`,
truncation to k; **all orderings are on the tuple `(dist, id)`** and
distances are integer-exact, so `S` is a total function of its
arguments — no randomness, no platform dependence.

## 2. Lemmas

**Lemma 1 (Merkle binding).** Under collision resistance of blake3,
no PPT adversary can produce, for the same `(root, n, position)`, two
distinct payloads whose openings both verify, except with negligible
probability. Domain separation (`0x00` leaf / `0x01` node / `0x02`
empty prefixes) excludes cross-domain second preimages; the verifier
derives the expected proof depth from `n`, excluding shape confusion.

**Lemma 2 (Locality).** The execution of `S(I, q, k, ef)` reads a
well-defined *touched set* `T(I, q, k, ef) ⊆ [n]` — the ids whose
level, adjacency, or vector the engine accesses — and the output of
`S` is a function of `(q, k, ef, P)` and the restriction `I|_T` alone.
*Proof: by inspection of the engine, which accesses node data only
through the `IndexView` interface; `RecordingView` materializes `T`.*

## 3. The verifier

`Verify(δ, q, k, ef, π)` (`ta-proof::verifier`, six stages):
(1) dimension and empty-index conventions; (2) batch Merkle
verification of all openings against `(root, n)`; (3) strict payload
decoding with the position↔identity check `decoded.id = position`;
(4) replay of the *same* engine over the partial view built from the
openings, aborting on any access outside it; (5) bit-exact equality of
the replayed list with `π.result`; (6) tightness: the replay's touched
set equals the opened set.

## 4. Theorem

**Theorem 1 (Soundness).** Let `δ = Commit(I)`. For every PPT
adversary `A` outputting `(q, k, ef, π)`:

```
Pr[ Verify(δ, q, k, ef, π) = 1  ∧  π.result ≠ S(I, q, k, ef) ]
    ≤ Adv_blake3^CR(B)
```

for an explicit reduction `B` that extracts a blake3 collision from
any accepting, deviating transcript.

*Proof sketch.* Suppose Verify accepts. Stage (2) plus Lemma 1 imply
that every opened payload equals `I`'s payload at that position — any
difference yields two verifying openings for one position, i.e. a
collision, which `B` outputs. Stage (3) makes the decoded local view a
*restriction of I* (identity binding excludes transplanting node j's
content to position i). Stage (4) ran to completion, so every access
the engine attempted succeeded; by Lemma 2 the opened set contains
`T(I, q, k, ef)` on the accessed portion and the replay output equals
`S(I, q, k, ef)`. Stage (5) then forces
`π.result = S(I, q, k, ef)` — contradicting the deviation. ∎

**Proposition 1 (Completeness).** The honest prover
(`ta-proof::prover`) runs the same engine over the full index, opens
exactly the recorded touched set, and therefore always verifies. (The
prover self-checks this in debug builds.)

**Proposition 2 (Tightness).** If Verify accepts, the opened set
equals `T(I, q, k, ef)`: stage (4) rules out omissions
(`MissingNode`), stage (6) rules out padding (`UnusedOpenings`).
Hence `|VO| = Θ(|T| · (payload + amortized path))` — the proof is
precisely the search's data footprint, and reported VO sizes are not
gameable by the server in either direction.

## 5. Scope and interpretation (read before defending)

- **What is verified is the execution, not the optimum.** True-top-k
  verification for an approximate index is either meaningless (the
  index itself is approximate) or as expensive as exact search. Trace
  consistency instead binds the answer to the *canonical execution on
  the committed index* — detecting result tampering, lazy `ef`,
  entry-point games, and stale copies, at per-query cost.
- **Quality is a property of the commitment, not the proof.** A server
  may commit a bad index; it cannot misrepresent what that index
  returns. Clients calibrate expectations from the committed
  parameters and published recall curves.
- **Adaptive queries add nothing.** δ is fixed before queries; each
  verification is stateless and per-query, so the bound is preserved
  under any adaptive strategy by a union bound over queries.
