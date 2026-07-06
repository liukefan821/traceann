//! ta-bench: measurement harness for TraceANN Tier-1.
//!
//! Usage:
//!   cargo run -p ta-bench --release -- [smoke|paper]
//!   cargo run -p ta-bench --release -- paper > bench/results/paper.csv
//!
//! CSV rows go to stdout; progress goes to stderr. See bench/README.md
//! for the methodology and the column dictionary.

use std::hint::black_box;
use std::time::Instant;

use ta_commit::commit::commit_index;
use ta_core::build::{splitmix64, BuildParams, HnswIndex};
use ta_core::fixed::{dist, Metric, QVector};
use ta_proof::prover::prove_query;
use ta_proof::verifier::verify_query;

/// Per-operation repetitions; the minimum is kept.
const REPS: usize = 3;

fn hv(seed: u64, i: u64, d: usize) -> QVector {
    let mut s = splitmix64(seed ^ i.wrapping_mul(0x9E37_79B9_7F4A_7C15));
    let mut v = Vec::with_capacity(d);
    for _ in 0..d {
        s = splitmix64(s);
        v.push((s & 0xFF) as u8 as i8);
    }
    QVector(v)
}

const GOLD: u64 = 0x9E37_79B9_7F4A_7C15;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Data {
    Uniform,
    Clustered,
}

fn data_name(d: Data) -> &'static str {
    match d {
        Data::Uniform => "uniform",
        Data::Clustered => "clustered",
    }
}

/// ~32 points per planted cluster. Small clusters are load-bearing:
/// if cluster size >= ef_construction, every build-time candidate set
/// is all-intra-cluster and layer 0 degenerates into disconnected
/// islands (cross-cluster navigation then hangs on the sparse upper
/// layers alone). With 32-point clusters, W always contains
/// cross-cluster candidates and bridges form.
fn clusters_for(n: usize) -> u64 {
    ((n / 32).max(16)) as u64
}

/// Synthetic data generator.
///
/// Uniform random vectors suffer extreme distance concentration in
/// high dimensions: all pairs become nearly equidistant, ANN recall
/// collapses (falls with d and with n), and the numbers say nothing
/// about real embedding workloads. `Clustered` plants Gaussian-ish
/// blobs — centroid components in [-96, 96], per-point noise in
/// [-31, 31] — the standard structured synthetic benchmark, still
/// fully integer and deterministic.
fn gen_point(seed: u64, kind: Data, i: u64, d: usize, clusters: u64) -> QVector {
    match kind {
        Data::Uniform => hv(seed, i, d),
        Data::Clustered => {
            let c = splitmix64(seed ^ 0xC1 ^ i.wrapping_mul(GOLD)) % clusters;
            let mut cs = splitmix64(seed ^ 0xCE ^ c.wrapping_mul(GOLD));
            let mut ns = splitmix64(seed ^ 0x11 ^ i.wrapping_mul(GOLD));
            // Low intrinsic dimensionality: noise lives on ~S
            // cluster-specific dims; every other coordinate equals the
            // centroid exactly. Real embeddings behave the same way
            // (fast-decaying spectrum) — without this, the
            // within-cluster subproblem is again uniform-random high-d
            // and distance concentration kills recall.
            const S: usize = 16;
            let stride = (d / S).max(1) as u64;
            let mut v = Vec::with_capacity(d);
            for t in 0..d {
                cs = splitmix64(cs);
                ns = splitmix64(ns);
                // Centroids live in a GLOBAL ~S-dim subspace: without
                // this, 100s of centroids are mutually near-equidistant
                // in high ambient d and coarse navigation has no
                // gradient to follow (observed as recall stuck at ~0.6
                // for ef=64 while ef=256 reached ~0.95).
                let g_active = splitmix64(
                    seed ^ 0x67 ^ (t as u64).wrapping_mul(0xD6E8_FEB8_6659_FD93),
                ) % stride
                    == 0;
                let cent = if g_active { (cs % 193) as i64 - 96 } else { 0 };
                let active = splitmix64(
                    seed ^ 0xA5 ^ c.wrapping_mul(GOLD)
                        ^ (t as u64).wrapping_mul(0xD6E8_FEB8_6659_FD93),
                ) % stride
                    == 0;
                let noise = if active { (ns % 63) as i64 - 31 } else { 0 };
                v.push((cent + noise).clamp(-127, 127) as i8);
            }
            QVector(v)
        }
    }
}

struct Config {
    sweep: &'static str,
    n: usize,
    d: usize,
    m: usize,
    efc: usize,
    efs: &'static [usize],
    k: usize,
    queries: u64,
    recall_queries: u64,
}

fn presets(name: &str) -> Vec<Config> {
    match name {
        "smoke" => vec![
            Config {
                sweep: "smoke",
                n: 5_000,
                d: 32,
                m: 8,
                efc: 32,
                efs: &[16, 64],
                k: 10,
                queries: 10,
                recall_queries: 10,
            },
            Config {
                sweep: "smoke",
                n: 5_000,
                d: 768,
                m: 16,
                efc: 64,
                efs: &[64],
                k: 10,
                queries: 10,
                recall_queries: 5,
            },
        ],
        "mid" => vec![Config {
            sweep: "mid",
            n: 20_000,
            d: 128,
            m: 16,
            efc: 200,
            efs: &[16, 64, 256],
            k: 10,
            queries: 30,
            recall_queries: 15,
        }],
        "paper" => {
            let mut v = Vec::new();
            for d in [64, 128, 256, 512, 768] {
                v.push(Config {
                    sweep: "d",
                    n: 50_000,
                    d,
                    m: 16,
                    efc: 200,
                    efs: &[64],
                    k: 10,
                    queries: 50,
                    recall_queries: 20,
                });
            }
            v.push(Config {
                sweep: "ef",
                n: 50_000,
                d: 128,
                m: 16,
                efc: 200,
                efs: &[16, 32, 64, 128, 256],
                k: 10,
                queries: 50,
                recall_queries: 20,
            });
            for n in [10_000, 20_000, 100_000] {
                v.push(Config {
                    sweep: "n",
                    n,
                    d: 128,
                    m: 16,
                    efc: 200,
                    efs: &[64],
                    k: 10,
                    queries: 50,
                    recall_queries: 20,
                });
            }
            v
        }
        other => {
            eprintln!("unknown preset '{other}' (expected: smoke | mid | paper)");
            std::process::exit(2);
        }
    }
}

/// Minimum wall time over REPS runs, in microseconds.
fn time_us<R>(mut f: impl FnMut() -> R) -> f64 {
    let mut best = f64::INFINITY;
    for _ in 0..REPS {
        let t = Instant::now();
        black_box(f());
        let e = t.elapsed().as_secs_f64() * 1e6;
        if e < best {
            best = e;
        }
    }
    best
}

fn median(v: &mut [f64]) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

fn p95(v: &mut [f64]) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let i = ((v.len() - 1) as f64 * 0.95).round() as usize;
    v[i]
}

fn run(cfg: &Config, data: Data) {
    let clusters = clusters_for(cfg.n);
    eprintln!(
        "[{}/{}] building n={} d={} m={} efc={} ...",
        cfg.sweep, data_name(data), cfg.n, cfg.d, cfg.m, cfg.efc
    );
    let t = Instant::now();
    let mut idx = HnswIndex::new(
        cfg.d,
        Metric::L2Sq,
        BuildParams {
            m: cfg.m,
            ef_construction: cfg.efc,
            seed: 42,
        },
    );
    for i in 0..cfg.n {
        idx.insert(gen_point(0xDA7A, data, i as u64, cfg.d, clusters)).unwrap();
    }
    let build_ms = t.elapsed().as_secs_f64() * 1e3;

    let t = Instant::now();
    let com = commit_index(&idx);
    let commit_ms = t.elapsed().as_secs_f64() * 1e3;
    let dg = com.digest();
    eprintln!("    build {build_ms:.0} ms, commit {commit_ms:.0} ms");

    for &ef in cfg.efs {
        // Warm caches before measuring.
        for w in 0..3u64 {
            let q = gen_point(0xC0FFEE, data, w, cfg.d, clusters);
            black_box(idx.search(&q, cfg.k, ef).unwrap());
        }

        let mut s_us = Vec::new();
        let mut p_us = Vec::new();
        let mut v_us = Vec::new();
        let mut opened = Vec::new();
        let mut bytes = Vec::new();
        for qi in 0..cfg.queries {
            let q = gen_point(0xBEEF, data, qi, cfg.d, clusters);
            s_us.push(time_us(|| idx.search(&q, cfg.k, ef).unwrap()));
            p_us.push(time_us(|| prove_query(&idx, &com, &q, cfg.k, ef).unwrap()));
            let proof = prove_query(&idx, &com, &q, cfg.k, ef).unwrap();
            // Every proof in the sweep must verify — the harness is
            // also a large randomized end-to-end test.
            v_us.push(time_us(|| verify_query(dg, &q, cfg.k, ef, &proof).unwrap()));
            opened.push(proof.opened() as f64);
            bytes.push(proof.size_bytes() as f64);
        }

        // Engine recall vs exact brute force on a query subsample.
        let mut hits = 0usize;
        for qi in 0..cfg.recall_queries {
            let q = gen_point(0xBEEF, data, qi, cfg.d, clusters);
            let mut exact: Vec<(i64, u32)> = (0..cfg.n as u32)
                .map(|id| (dist(Metric::L2Sq, &q, idx.vector(id).unwrap()), id))
                .collect();
            exact.sort_unstable();
            let truth: std::collections::HashSet<u32> =
                exact[..cfg.k].iter().map(|&(_, id)| id).collect();
            let got = idx.search(&q, cfg.k, ef).unwrap();
            hits += got.iter().filter(|&&(_, id)| truth.contains(&id)).count();
        }
        let recall = hits as f64 / (cfg.k as u64 * cfg.recall_queries) as f64;

        let opened_med = median(&mut opened.clone());
        let opened_p95 = p95(&mut opened.clone());
        let bytes_med = median(&mut bytes.clone());
        let bytes_p95 = p95(&mut bytes.clone());
        let s_med = median(&mut s_us.clone());
        let p_med = median(&mut p_us.clone());
        let v_med = median(&mut v_us.clone());

        println!(
            "{},{},{},{},{},{},{},{},{},{:.0},{:.0},{:.4},{:.1},{:.1},{:.0},{:.0},{:.1},{:.1},{:.1},{:.2}",
            cfg.sweep,
            data_name(data),
            cfg.n,
            cfg.d,
            cfg.m,
            cfg.efc,
            ef,
            cfg.k,
            cfg.queries,
            build_ms,
            commit_ms,
            recall,
            opened_med,
            opened_p95,
            bytes_med,
            bytes_p95,
            s_med,
            p_med,
            v_med,
            p_med / s_med,
        );
        eprintln!(
            "    ef={ef}: opened_med={opened_med:.0} proof_med={bytes_med:.0}B \
             search={s_med:.0}us prove={p_med:.0}us verify={v_med:.0}us recall={recall:.3}"
        );
    }
}

fn main() {
    let preset = std::env::args().nth(1).unwrap_or_else(|| "smoke".to_string());
    let data = match std::env::args().nth(2).as_deref() {
        None | Some("clustered") => Data::Clustered,
        Some("uniform") => Data::Uniform,
        Some(other) => {
            eprintln!("unknown data model '{other}' (expected: clustered | uniform)");
            std::process::exit(2);
        }
    };
    let cfgs = presets(&preset);
    println!(
        "sweep,data,n,d,m,ef_construction,ef,k,queries,build_ms,commit_ms,recall_at_k,\
         opened_med,opened_p95,proof_bytes_med,proof_bytes_p95,\
         search_us_med,prove_us_med,verify_us_med,prove_over_search"
    );
    let t0 = Instant::now();
    for c in &cfgs {
        run(c, data);
    }
    eprintln!("done in {:.1}s", t0.elapsed().as_secs_f64());
}
