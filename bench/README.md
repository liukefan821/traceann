# TraceANN measurement harness

## Run

```bash
mkdir -p bench/results
cargo run -p ta-bench --release -- smoke > bench/results/smoke.csv   # sanity, seconds
cargo run -p ta-bench --release -- paper > bench/results/paper.csv   # paper data, minutes
```

CSV rows go to stdout; progress goes to stderr. Runs are fully
deterministic (fixed seeds), so results are reproducible byte-for-byte
on any machine for the VO columns; timing columns are machine-specific.

## Methodology

Per query, each operation (plain search / prove / verify) is executed
REPS=3 times and the minimum wall time is kept (best estimator of
intrinsic cost under scheduler noise); the table reports median and p95
across the query set. VO metrics (opened leaves, proof bytes) are exact
and deterministic. Every proof produced during a sweep is verified, so
the harness doubles as a large randomized end-to-end test.

## Columns

- `sweep` — which axis this row belongs to (`d`, `ef`, `n`, `smoke`)
- `n, d, m, ef_construction, ef, k, queries` — configuration
- `build_ms, commit_ms` — one-off index build / commitment time
- `recall_at_k` — engine recall vs exact brute force
- `opened_med, opened_p95` — leaves opened per proof (= touched set)
- `proof_bytes_med, proof_bytes_p95` — wire VO size
- `search_us_med, prove_us_med, verify_us_med` — latencies (µs)
- `prove_over_search` — prover overhead ratio vs plaintext search

## Synthetic data model (`clustered`)

Points are planted in ~32-point clusters. Centroids live in a global
~16-dimensional subspace; each cluster adds noise in its own
~16-dimensional subspace. Intrinsic dimensionality is therefore fixed
(~32) while the ambient dimension `d` varies — the regime of real
embedding models — so the `d` sweep isolates the payload term of the
VO with the opened-leaf count held roughly flat.

Every knob fixes a failure mode we observed empirically:

- uniform random data → distance concentration; recall collapses with
  `d` and with `n`;
- full-dimensional cluster noise → the within-cluster subproblem is
  again uniform high-d;
- cluster size >= ef_construction → all-intra candidate sets during
  build; layer 0 degenerates into disconnected islands;
- uniform random centroids → no gradient for coarse navigation.

`cargo run -p ta-bench --release -- paper uniform` reproduces the
pathological uniform baseline for comparison.
