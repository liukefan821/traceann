//! Readers for the TEXMEX fvecs/ivecs formats + affine int8 loading.
//!
//! fvecs: each record = `[d: i32 LE][d x f32 LE]`; ivecs likewise with
//! i32 components.
//!
//! SIFT descriptors are integer-valued in [0, 255] (stored as floats),
//! and squared L2 distance is invariant under a constant translation —
//! so the affine map `q = x - 128` embeds them into i8 **losslessly**:
//! the integer-exact engine then computes distances identical to the
//! float originals, and recall against the official ground truth
//! measures the engine with zero quantization confound. `clipped`
//! counts components that hit the i8 range; for SIFT it must be zero.

use std::fs::File;
use std::io::{BufReader, ErrorKind, Read, Result};

use ta_core::fixed::QVector;

pub fn read_ivecs(path: &str) -> Result<Vec<Vec<u32>>> {
    let mut r = BufReader::new(File::open(path)?);
    let mut out = Vec::new();
    loop {
        let mut hd = [0u8; 4];
        match r.read_exact(&mut hd) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }
        let d = i32::from_le_bytes(hd) as usize;
        let mut buf = vec![0u8; 4 * d];
        r.read_exact(&mut buf)?;
        out.push(
            buf.chunks_exact(4)
                .map(|c| i32::from_le_bytes(c.try_into().unwrap()) as u32)
                .collect(),
        );
    }
    Ok(out)
}

/// Stream-load an fvecs file, applying `q = round((x - offset) / scale)`
/// clamped to [-128, 127]. `limit = 0` loads every record.
/// Returns (dim, vectors, clipped-component count).
pub fn load_fvecs_quantized(
    path: &str,
    offset: f32,
    scale: f32,
    limit: usize,
) -> Result<(usize, Vec<QVector>, u64)> {
    assert!(scale > 0.0, "scale must be positive");
    let mut r = BufReader::new(File::open(path)?);
    let mut out = Vec::new();
    let mut dim = 0usize;
    let mut clipped = 0u64;
    loop {
        if limit != 0 && out.len() >= limit {
            break;
        }
        let mut hd = [0u8; 4];
        match r.read_exact(&mut hd) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }
        let d = i32::from_le_bytes(hd) as usize;
        if dim == 0 {
            dim = d;
        }
        assert_eq!(d, dim, "inconsistent dimension inside fvecs file");
        let mut buf = vec![0u8; 4 * d];
        r.read_exact(&mut buf)?;
        let v: Vec<i8> = buf
            .chunks_exact(4)
            .map(|c| {
                let x = f32::from_le_bytes(c.try_into().unwrap());
                let q = ((x - offset) / scale).round();
                if !(-128.0..=127.0).contains(&q) {
                    clipped += 1;
                }
                q.clamp(-128.0, 127.0) as i8
            })
            .collect();
        out.push(QVector(v));
    }
    Ok((dim, out, clipped))
}
