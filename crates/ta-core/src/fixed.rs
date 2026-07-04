//! Deterministic fixed-point vector arithmetic.
//!
//! All similarity computations in TraceANN run on integer-quantized
//! vectors with `i64` accumulation — never on floats. This gives
//! bit-identical results on every platform (x86-64, aarch64, wasm),
//! which is a hard prerequisite for search-trace replay: the verifier
//! must reproduce the server's greedy traversal *exactly*.
//!
//! Integer addition is associative and commutative, so later SIMD
//! kernels may reorder the accumulation freely without breaking
//! determinism — the same is not true of floating point.
//!
//! Overflow headroom: with i8 components, |a_i * b_i| <= 128 * 128
//! = 16_384 = 2^14, so a dot product over d = 4096 dims is bounded by
//! 2^26 in magnitude — comfortably inside i64 (we keep i64 for slack
//! and for a future i16 mode).

/// A quantized vector. Raw embeddings are mapped to `i8` once at index
/// build time using a single, committed `scale`; server and verifier
/// then operate on identical integers. (The f32 rounding in
/// [`quantize`] happens only at build time and is therefore outside
/// the deterministic replay path.)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QVector(pub Vec<i8>);

impl QVector {
    pub fn dim(&self) -> usize {
        self.0.len()
    }

    /// Inner product with `i64` accumulation. Panics on dimension mismatch.
    pub fn dot(&self, other: &QVector) -> i64 {
        assert_eq!(self.dim(), other.dim(), "dimension mismatch");
        self.0
            .iter()
            .zip(&other.0)
            .map(|(&a, &b)| (a as i64) * (b as i64))
            .sum()
    }

    /// Exact squared Euclidean distance in `i64`.
    pub fn l2sq(&self, other: &QVector) -> i64 {
        assert_eq!(self.dim(), other.dim(), "dimension mismatch");
        self.0
            .iter()
            .zip(&other.0)
            .map(|(&a, &b)| {
                let d = (a as i64) - (b as i64);
                d * d
            })
            .sum()
    }
}

/// Symmetric int8 quantization: `q_i = round(x_i / scale)` clamped to
/// `[-127, 127]` (we avoid -128 to keep the range symmetric).
///
/// `scale` must be positive and identical for all vectors in one
/// index; it is bound into the committed digest so that server and
/// verifier agree on the integer domain.
pub fn quantize(x: &[f32], scale: f32) -> QVector {
    assert!(scale > 0.0, "scale must be positive");
    QVector(
        x.iter()
            .map(|&v| (v / scale).round().clamp(-127.0, 127.0) as i8)
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dot_basic() {
        let a = QVector(vec![1, 2, 3]);
        let b = QVector(vec![4, -5, 6]);
        assert_eq!(a.dot(&b), 4 - 10 + 18);
    }

    #[test]
    fn dot_is_symmetric() {
        let a = QVector(vec![7, -3, 0, 55]);
        let b = QVector(vec![-2, 9, 41, -128]);
        assert_eq!(a.dot(&b), b.dot(&a));
    }

    #[test]
    fn dot_extremes_fit_i64() {
        let d = 4096;
        let a = QVector(vec![-128; d]);
        let b = QVector(vec![-128; d]);
        // 16_384 * 4096 = 2^26, far below i64::MAX — no overflow possible.
        assert_eq!(a.dot(&b), 16_384 * d as i64);
    }

    #[test]
    fn l2sq_basic() {
        let a = QVector(vec![0, 3]);
        let b = QVector(vec![4, 0]);
        assert_eq!(a.l2sq(&b), 25);
    }

    #[test]
    fn quantize_rounds_and_clamps() {
        let q = quantize(&[0.24, 0.26, -0.26, 100.0, -100.0], 0.5);
        assert_eq!(q.0, vec![0, 1, -1, 127, -127]);
    }
}
