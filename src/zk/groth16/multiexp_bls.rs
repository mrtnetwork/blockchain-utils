//! Bellman-style multi-exponentiation (Pippenger buckets) over BLS12-381.
//!
//! Algorithm matches `zkcrypto/bellman` `multiexp_inner` (single-threaded):
//! - split each scalar into `c`-bit windows
//! - bucket bases by window value
//! - summation-by-parts per window
//! - combine windows with `c` doubles between parts
//!
//! `c = 3` for small `n`, else `ceil(ln n)` — same heuristic as Bellman.

#![cfg(feature = "groth16-prover")]

use crate::curve::bls::{G1Point, G2Point, Scalar};
use crate::curve::traits::CurvePoint;
use alloc::vec;
use alloc::vec::Vec;

const SCALAR_BITS: usize = 255;

fn chunk_bits_c(n: usize) -> usize {
    // Bellman multiexp EXACT: c = 1 if n=0; else if n < 32 { 3 } else ceil(ln n).
    // (Tried c=14 for n ≥ 64k: 7% fewer adds on paper, but 2MB buckets thrash
    // the shared L3 across workers — net loss. Keep bellman-exact.)
    if n < 32 {
        return 3;
    }
    // ceil(ln n) via integer: smallest c with e^c >= n
    let mut c = 1usize;
    let mut prod = 1u64;
    loop {
        let next = prod.saturating_mul(271828) / 100000;
        if next == 0 {
            break;
        }
        prod = next;
        if prod as usize >= n || c >= 20 {
            break;
        }
        c += 1;
    }
    let c = if c < 3 { 3 } else { c };
    if c > 12 {
        12
    } else {
        c
    }
}

/// Window value in bits `[bit_off, bit_off+c)`.
#[inline(always)]
fn window_value(le: &[u8; 32], bit_off: usize, c: usize) -> u64 {
    // Extract from up to 3 consecutive bytes instead of c bit tests
    let byte_off = bit_off >> 3;
    if byte_off >= 32 {
        return 0;
    }
    let bit_in = bit_off & 7;
    let mut v = (le[byte_off] as u64) >> bit_in;
    if byte_off + 1 < 32 {
        v |= (le[byte_off + 1] as u64) << (8 - bit_in);
    }
    if bit_in + c > 16 && byte_off + 2 < 32 {
        v |= (le[byte_off + 2] as u64) << (16 - bit_in);
    }
    v & ((1u64 << c) - 1)
}

fn is_one(le: &[u8; 32]) -> bool {
    le[0] == 1 && le[1..].iter().all(|&b| b == 0)
}

fn is_zero_bytes(le: &[u8; 32]) -> bool {
    le.iter().all(|&b| b == 0)
}

/// Multi-scalar multiplication in G1 (Bellman Pippenger).
///
/// Production (`std`) callers use the `_le` entry points; this base-scalar
/// form serves the `no_std`/wasm fallback and unit tests.
#[cfg(any(not(feature = "std"), target_arch = "wasm32", test))]
pub fn multiexp_g1(bases: &[G1Point], scalars: &[Scalar]) -> G1Point {
    let n = cores::min(bases.len(), scalars.len());
    if n == 0 {
        return G1Point::identity();
    }
    let mut les = Vec::with_capacity(n);
    for s in scalars.iter().take(n) {
        let mut le = [0u8; 32];
        s.to_bytes_le(&mut le);
        les.push(le);
    }
    multiexp_g1_with_le_c(bases, &les, chunk_bits_c(n))
}

/// Multi-scalar multiplication in G2 (Bellman Pippenger).
pub fn multiexp_g2(bases: &[G2Point], scalars: &[Scalar]) -> G2Point {
    let n = cores::min(bases.len(), scalars.len());
    if n == 0 {
        return G2Point::identity();
    }
    let mut les = Vec::with_capacity(n);
    for s in scalars.iter().take(n) {
        let mut le = [0u8; 32];
        s.to_bytes_le(&mut le);
        les.push(le);
    }
    multiexp_g2_le_c(bases, &les, chunk_bits_c(n))
}

/// G2 Pippenger core over precomputed LE scalars with explicit `c`.
fn multiexp_g2_le_c(bases: &[G2Point], les: &[[u8; 32]], c: usize) -> G2Point {
    let n = cores::min(bases.len(), les.len());
    if n == 0 {
        return G2Point::identity();
    }

    let num_chunks = SCALAR_BITS.div_ceil(c);
    let mut parts: Vec<G2Point> = Vec::with_capacity(num_chunks);

    for chunk in 0..num_chunks {
        let bit_off = chunk * c;
        let mut buckets = vec![G2Point::identity(); (1 << c) - 1];
        let mut acc = G2Point::identity();
        let handle_trivial = chunk == 0;

        for i in 0..n {
            let le = &les[i];
            if is_zero_bytes(le) {
                continue;
            }
            if is_one(le) {
                if handle_trivial {
                    acc = acc.add(&bases[i]);
                }
                continue;
            }
            let exp = window_value(le, bit_off, c);
            if exp != 0 {
                let idx = (exp - 1) as usize;
                buckets[idx] = buckets[idx].add_vartime(&bases[i]);
            }
        }

        let mut running = G2Point::identity();
        for b in buckets.into_iter().rev() {
            running = running.add_vartime(&b);
            acc = acc.add_vartime(&running);
        }
        parts.push(acc);
    }

    let mut acc = G2Point::identity();
    let mut started = false;
    for part in parts.into_iter().rev() {
        if !started {
            if part.ct_is_identity() == 1 {
                continue;
            }
            acc = part;
            started = true;
            continue;
        }
        for _ in 0..c {
            acc = acc.double_vartime();
        }
        acc = acc.add_vartime(&part);
    }
    acc
}

/// Parallel G1 MSM fallback (`no_std`/wasm32): single-threaded Pippenger.
#[cfg(any(not(feature = "std"), target_arch = "wasm32"))]
pub fn multiexp_g1_parallel(bases: &[G1Point], scalars: &[Scalar]) -> G1Point {
    multiexp_g1(bases, scalars)
}

#[cfg(all(feature = "std", not(target_arch = "wasm32")))]
pub fn multiexp_g2_parallel(bases: &[G2Point], scalars: &[Scalar]) -> G2Point {
    let n = cores::min(bases.len(), scalars.len());
    if n == 0 {
        return G2Point::identity();
    }
    #[cfg(feature = "multicore")]
    let nthreads = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(4)
        .clamp(1, 16);
    #[cfg(not(feature = "multicore"))]
    let nthreads = 1usize;
    if n < 128 || nthreads == 1 {
        return multiexp_g2(bases, scalars);
    }
    // Static point split (one slice per thread).
    let chunk = n.div_ceil(nthreads);
    let mut partials = vec![G2Point::identity(); nthreads];
    std::thread::scope(|scope| {
        let mut guards = Vec::with_capacity(nthreads);
        for (t, slot) in partials.iter_mut().enumerate() {
            let start = t * chunk;
            if start >= n {
                break;
            }
            let end = cores::min(start + chunk, n);
            let b = &bases[start..end];
            let s = &scalars[start..end];
            guards.push(scope.spawn(move || {
                *slot = multiexp_g2(b, s);
            }));
        }
        for g in guards {
            g.join().expect("msm g2 worker");
        }
    });
    let mut acc = G2Point::identity();
    for p in &partials {
        acc = acc.add_vartime(p);
    }
    acc
}

#[cfg(any(not(feature = "std"), target_arch = "wasm32"))]
pub fn multiexp_g2_parallel(bases: &[G2Point], scalars: &[Scalar]) -> G2Point {
    multiexp_g2(bases, scalars)
}

/// Pippenger G1 MSM with precomputed little-endian scalar bytes (skips mont→LE).
pub fn multiexp_g1_with_le(bases: &[G1Point], les: &[[u8; 32]]) -> G1Point {
    let n = cores::min(bases.len(), les.len());
    multiexp_g1_with_le_c(bases, les, chunk_bits_c(n))
}

/// One Pippenger window-chunk over the full point set: bucket fill +
/// summation-by-parts. Self-contained (own bucket alloc) so chunk-tasks run
/// independently on any thread (bellman `multiexp_inner` chunk shape).
fn pippenger_chunk_g1_le(
    bases: &[G1Point],
    les: &[[u8; 32]],
    chunk: usize,
    c: usize,
    n: usize,
    id: &G1Point,
) -> G1Point {
    let bit_off = chunk * c;
    let mut buckets = vec![G1Point::identity(); (1 << c) - 1];
    let mut acc = *id;
    let handle_trivial = chunk == 0;
    // Iterator zip (no index bounds checks) over the shared prefix.
    for (base, le) in bases.iter().zip(les.iter()).take(n) {
        if is_zero_bytes(le) {
            continue;
        }
        if is_one(le) {
            if handle_trivial {
                acc = acc.add_vartime(base);
            }
            continue;
        }
        let exp = window_value(le, bit_off, c);
        if exp != 0 {
            let idx = (exp - 1) as usize;
            buckets[idx] = buckets[idx].add_vartime(base);
        }
    }
    // summation-by-parts; skip identity bucket adds
    let mut running = *id;
    for b in buckets.iter().rev() {
        if b.ct_is_identity() == 0 {
            running = running.add_vartime(b);
        }
        acc = acc.add_vartime(&running);
    }
    acc
}

/// Pippenger core with explicit window width (caller picks `c`).
/// Callers pass the `c` matching their workload: full-problem `c` for
/// single-thread runs; per-slice `c` is equally good for point-split workers
/// (fewer buckets fit L1, less summation overhead on small slices).
pub fn multiexp_g1_with_le_c(bases: &[G1Point], les: &[[u8; 32]], c: usize) -> G1Point {
    let n = cores::min(bases.len(), les.len());
    if n == 0 {
        return G1Point::identity();
    }
    let num_chunks = SCALAR_BITS.div_ceil(c);
    let mut parts: Vec<G1Point> = Vec::with_capacity(num_chunks);
    let id = G1Point::identity();
    for chunk in 0..num_chunks {
        parts.push(pippenger_chunk_g1_le(bases, les, chunk, c, n, &id));
    }
    let mut acc = id;
    let mut started = false;
    for part in parts.into_iter().rev() {
        if !started {
            if part.ct_is_identity() == 1 {
                continue;
            }
            acc = part;
            started = true;
            continue;
        }
        for _ in 0..c {
            acc = acc.double_vartime();
        }
        acc = acc.add_vartime(&part);
    }
    acc
}

#[cfg(all(feature = "std", not(target_arch = "wasm32")))]
pub fn multiexp_g1_parallel_le(bases: &[G1Point], les: &[[u8; 32]]) -> G1Point {
    let n = cores::min(bases.len(), les.len());
    if n == 0 {
        return G1Point::identity();
    }
    #[cfg(feature = "multicore")]
    let nthreads = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(4)
        .clamp(1, 16);
    #[cfg(not(feature = "multicore"))]
    let nthreads = 1usize;
    if n < 256 || nthreads == 1 {
        return multiexp_g1_with_le(bases, les);
    }
    // Chunk-tasks over a shared atomic queue (bellman `into_par_iter` shape):
    // 22 window-chunks distributed dynamically across workers. Each task runs
    // the FULL point set for its chunk (great streaming locality, no point
    // slicing); stragglers don't stall anyone. Parts combine in order after.
    let c = chunk_bits_c(n);
    let num_chunks = SCALAR_BITS.div_ceil(c);
    let id = G1Point::identity();
    let mut parts: Vec<Option<G1Point>> = (0..num_chunks).map(|_| None).collect();
    let next = core::sync::atomic::AtomicUsize::new(0);
    let next_ref = &next;
    std::thread::scope(|scope| {
        // Worker-local (chunk, part) pairs merged after join (no shared mut).
        let mut guards = Vec::with_capacity(nthreads);
        for _ in 0..nthreads {
            let (bases, les) = (&bases, &les);
            guards.push(scope.spawn(move || {
                let mut done: Vec<(usize, G1Point)> = Vec::new();
                loop {
                    let chunk = next_ref.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                    if chunk >= num_chunks {
                        break;
                    }
                    done.push((chunk, pippenger_chunk_g1_le(bases, les, chunk, c, n, &id)));
                }
                done
            }));
        }
        for g in guards {
            for (chunk, part) in g.join().expect("msm chunk worker") {
                parts[chunk] = Some(part);
            }
        }
    });
    let mut acc = id;
    let mut started = false;
    for part in parts.into_iter().rev() {
        let part = part.expect("chunk part");
        if !started {
            if part.ct_is_identity() == 1 {
                continue;
            }
            acc = part;
            started = true;
            continue;
        }
        for _ in 0..c {
            acc = acc.double_vartime();
        }
        acc = acc.add_vartime(&part);
    }
    acc
}

#[cfg(any(not(feature = "std"), target_arch = "wasm32"))]
pub fn multiexp_g1_parallel_le(bases: &[G1Point], les: &[[u8; 32]]) -> G1Point {
    multiexp_g1_with_le(bases, les)
}

/// Sparse G1 MSM: `bases[k]` pairs with `assignment[dense_idx[k]]`.
///
/// Only the `no_std`/wasm prove path uses the sparse form; production
/// (`std`) prove filters through the `_le` entry points.
#[cfg(any(not(feature = "std"), target_arch = "wasm32"))]
pub fn multiexp_g1_sparse(
    bases: &[G1Point],
    dense_idx: &[usize],
    assignment: &[Scalar],
) -> G1Point {
    let m = cores::min(bases.len(), dense_idx.len());
    // Compact non-zero scalars only (skip identity contributions)
    let mut b = Vec::with_capacity(m);
    let mut s = Vec::with_capacity(m);
    for k in 0..m {
        let i = dense_idx[k];
        if i >= assignment.len() {
            continue;
        }
        let sc = &assignment[i];
        if sc.is_zero() {
            continue;
        }
        b.push(bases[k].clone());
        s.push(sc.clone());
    }
    if b.is_empty() {
        return G1Point::identity();
    }
    multiexp_g1_parallel(&b, &s)
}

pub fn multiexp_g2_sparse(
    bases: &[G2Point],
    dense_idx: &[usize],
    assignment: &[Scalar],
) -> G2Point {
    let m = cores::min(bases.len(), dense_idx.len());
    let mut b = Vec::with_capacity(m);
    let mut s = Vec::with_capacity(m);
    for k in 0..m {
        let i = dense_idx[k];
        if i >= assignment.len() {
            continue;
        }
        let sc = &assignment[i];
        if sc.is_zero() {
            continue;
        }
        b.push(bases[k]);
        s.push(*sc);
    }
    if b.is_empty() {
        return G2Point::identity();
    }
    multiexp_g2_parallel(&b, &s)
}

mod cores {
    pub fn min(a: usize, b: usize) -> usize {
        if a < b {
            a
        } else {
            b
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::traits::CurvePoint;

    #[test]
    fn multiexp_g1_matches_naive() {
        let g = G1Point::generator();
        let bases: Vec<_> = (0..64).map(|_| g).collect();
        let scalars: Vec<_> = (0..64).map(|i| Scalar::from_u64(i as u64 + 1)).collect();
        let got = multiexp_g1(&bases, &scalars);
        let mut expect = G1Point::identity();
        for (b, s) in bases.iter().zip(scalars.iter()) {
            expect = expect.add(&b.mul(s));
        }
        assert_eq!(
            got.add(&expect.neg()).ct_is_identity(),
            1,
            "G1 multiexp != naive"
        );
    }

    #[test]
    #[cfg(feature = "std")]
    fn bench_multiexp_g1_speed() {
        use std::time::Instant;
        let g = G1Point::generator();
        let n = 4096usize;
        let bases: Vec<_> = (0..n).map(|_| g).collect();
        let scalars: Vec<_> = (0..n)
            .map(|i| Scalar::from_u64((i as u64) * 17 + 3))
            .collect();

        let t0 = Instant::now();
        let mut naive = G1Point::identity();
        for (b, s) in bases.iter().zip(scalars.iter()) {
            if !s.is_zero() {
                naive = naive.add(&b.mul(s));
            }
        }
        let ms_naive = t0.elapsed().as_millis();

        let t1 = Instant::now();
        let pip = multiexp_g1(&bases, &scalars);
        let ms_pip = t1.elapsed().as_millis();

        assert_eq!(pip.add(&naive.neg()).ct_is_identity(), 1);
        println!(
            "MSM G1 n={n}: naive={ms_naive} ms  pippenger={ms_pip} ms  speedup={:.2}x",
            if ms_pip > 0 {
                ms_naive as f64 / ms_pip as f64
            } else {
                f64::INFINITY
            }
        );
    }

    #[test]
    fn multiexp_g1_empty_and_trivial() {
        assert_eq!(multiexp_g1(&[], &[]).ct_is_identity(), 1);
        let g = G1Point::generator();
        let got = multiexp_g1(&[g], &[Scalar::one()]);
        assert_eq!(got.add(&g.neg()).ct_is_identity(), 1);
        let got0 = multiexp_g1(&[g], &[Scalar::zero()]);
        assert_eq!(got0.ct_is_identity(), 1);
    }
}
