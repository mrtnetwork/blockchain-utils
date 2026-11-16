//! Radix-2 FFT / iFFT over BLS12-381 Fr (feature `groth16-prover`).

#![cfg(feature = "groth16-prover")]

use crate::curve::bls::Scalar;
use alloc::vec::Vec;

/// Evaluation domain of size `2^k` for BLS12-381 Fr.
///
/// 2-adicity of BLS Fr is 32, so `k <= 32`.
#[derive(Clone, Debug)]
pub struct DomainBls {
    pub size: usize,
    pub log_size: u32,
    pub omega: Scalar,
    pub omega_inv: Scalar,
    pub size_inv: Scalar,
    /// Stage roots: `omega^{n/(2m)}` for m=1,2,4,...,n/2 (fft)
    stage_roots: Vec<Scalar>,
    stage_roots_inv: Vec<Scalar>,
}

impl DomainBls {
    pub fn new(n: usize) -> Option<Self> {
        // NOTE: compare in u64 — `1 << 32` overflows 32-bit usize (wasm32).
        if n == 0 || !n.is_power_of_two() || (n as u64) > (1u64 << 32) {
            return None;
        }
        let log_size = n.trailing_zeros();
        let omega = root_of_unity(log_size)?;
        let omega_inv = omega.invert().ok()?;
        let size_inv = Scalar::from_u64(n as u64).invert().ok()?;
        // Precompute stage roots: for m=1,2,...,n/2 → ω^{n/(2m)}
        let mut stage_roots = Vec::with_capacity(log_size as usize);
        let mut stage_roots_inv = Vec::with_capacity(log_size as usize);
        let mut m = 1usize;
        while m < n {
            stage_roots.push(omega.pow_u64((n / (2 * m)) as u64));
            stage_roots_inv.push(omega_inv.pow_u64((n / (2 * m)) as u64));
            m *= 2;
        }
        Some(Self {
            size: n,
            log_size,
            omega,
            omega_inv,
            size_inv,
            stage_roots,
            stage_roots_inv,
        })
    }

    pub fn fft(&self, a: &mut [Scalar]) {
        assert_eq!(a.len(), self.size);
        bit_reverse(a);
        let mut m = 1usize;
        let mut stage = 0usize;
        while m < self.size {
            let w_m = &self.stage_roots[stage];
            let mut k = 0usize;
            while k < self.size {
                let mut w = Scalar::one();
                for j in 0..m {
                    let t = a[k + j + m].mul(&w);
                    let u = a[k + j];
                    a[k + j] = u.add(&t);
                    a[k + j + m] = u.sub(&t);
                    w = w.mul(w_m);
                }
                k += 2 * m;
            }
            m *= 2;
            stage += 1;
        }
    }

    pub fn ifft(&self, a: &mut [Scalar]) {
        assert_eq!(a.len(), self.size);
        bit_reverse(a);
        let mut m = 1usize;
        let mut stage = 0usize;
        while m < self.size {
            let w_m = &self.stage_roots_inv[stage];
            let mut k = 0usize;
            while k < self.size {
                let mut w = Scalar::one();
                for j in 0..m {
                    let t = a[k + j + m].mul(&w);
                    let u = a[k + j];
                    a[k + j] = u.add(&t);
                    a[k + j + m] = u.sub(&t);
                    w = w.mul(w_m);
                }
                k += 2 * m;
            }
            m *= 2;
            stage += 1;
        }
        for x in a.iter_mut() {
            *x = x.mul(&self.size_inv);
        }
    }

    /// Coset FFT: evaluate at `g · ω^i`.
    pub fn coset_fft(&self, a: &mut [Scalar], g: &Scalar) {
        let mut pow = Scalar::one();
        for x in a.iter_mut() {
            *x = x.mul(&pow);
            pow = pow.mul(g);
        }
        self.fft(a);
    }

    pub fn coset_ifft(&self, a: &mut [Scalar], g: &Scalar) {
        self.ifft(a);
        let g_inv = g.invert().expect("g inv");
        let mut pow = Scalar::one();
        for x in a.iter_mut() {
            *x = x.mul(&pow);
            pow = pow.mul(&g_inv);
        }
    }

    /// Variable-time FFT twin (vartime Fr leaf ops).
    ///
    /// New method — [`DomainBls::fft`] (CT) untouched. Prove-side only
    /// (same posture note as `Scalar::add_vartime`).
    /// Stages parallelize over independent k-blocks.
    pub fn fft_vartime(&self, a: &mut [Scalar]) {
        assert_eq!(a.len(), self.size);
        bit_reverse(a);
        let mut m = 1usize;
        let mut stage = 0usize;
        while m < self.size {
            let w_m = self.stage_roots[stage];
            fft_stage_blocks(a, m, w_m);
            m *= 2;
            stage += 1;
        }
    }

    /// Variable-time iFFT twin (vartime Fr leaf ops + final scale).
    pub fn ifft_vartime(&self, a: &mut [Scalar]) {
        assert_eq!(a.len(), self.size);
        bit_reverse(a);
        let mut m = 1usize;
        let mut stage = 0usize;
        while m < self.size {
            let w_m = self.stage_roots_inv[stage];
            fft_stage_blocks(a, m, w_m);
            m *= 2;
            stage += 1;
        }
        let size_inv = self.size_inv;
        par_chunks_mut(a, |_, slice| {
            for x in slice.iter_mut() {
                *x = x.mul_vartime(&size_inv);
            }
        });
    }

    /// Variable-time coset FFT twin.
    pub fn coset_fft_vartime(&self, a: &mut [Scalar], g: &Scalar) {
        par_chunks_mut(a, |base, slice| {
            let mut pow = g.pow_u64(base as u64);
            for x in slice.iter_mut() {
                *x = x.mul_vartime(&pow);
                pow = pow.mul_vartime(g);
            }
        });
        self.fft_vartime(a);
    }

    /// Variable-time coset iFFT twin.
    pub fn coset_ifft_vartime(&self, a: &mut [Scalar], g: &Scalar) {
        self.ifft_vartime(a);
        let g_inv = g.invert().expect("g inv");
        par_chunks_mut(a, |base, slice| {
            let mut pow = g_inv.pow_u64(base as u64);
            for x in slice.iter_mut() {
                *x = x.mul_vartime(&pow);
                pow = pow.mul_vartime(&g_inv);
            }
        });
    }
}

/// One NTT stage: butterflies over independent k-blocks of width 2m.
///
/// Each block restarts its twiddle progression (matches the sequential loop),
/// so blocks run in any order/on any thread. Native threads only with the
/// `multicore` feature; falls back to the sequential loop otherwise
/// (wasm32/no_std/no-multicore/single block).
fn fft_stage_blocks(a: &mut [Scalar], m: usize, w_m: Scalar) {
    #[cfg(all(feature = "std", feature = "multicore", not(target_arch = "wasm32")))]
    {
        let num_blocks = a.len() / (2 * m);
        let nthreads = num_blocks.clamp(1, 8);
        if nthreads > 1 {
            let mut blocks: Vec<&mut [Scalar]> = a.chunks_mut(2 * m).collect();
            let per = num_blocks.div_ceil(nthreads);
            std::thread::scope(|scope| {
                for group in blocks.chunks_mut(per) {
                    scope.spawn(move || {
                        for blk in group.iter_mut() {
                            let mut w = Scalar::one();
                            for j in 0..m {
                                let t = blk[j + m].mul_vartime(&w);
                                let u = blk[j];
                                blk[j] = u.add_vartime(&t);
                                blk[j + m] = u.sub_vartime(&t);
                                w = w.mul_vartime(&w_m);
                            }
                        }
                    });
                }
            });
            return;
        }
    }
    let n = a.len();
    let mut k = 0usize;
    while k < n {
        let mut w = Scalar::one();
        for j in 0..m {
            let t = a[k + j + m].mul_vartime(&w);
            let u = a[k + j];
            a[k + j] = u.add_vartime(&t);
            a[k + j + m] = u.sub_vartime(&t);
            w = w.mul_vartime(&w_m);
        }
        k += 2 * m;
    }
}

fn bit_reverse(a: &mut [Scalar]) {
    let n = a.len();
    let mut j = 0usize;
    for i in 1..n {
        let mut bit = n >> 1;
        while j & bit != 0 {
            j ^= bit;
            bit >>= 1;
        }
        j ^= bit;
        if i < j {
            a.swap(i, j);
        }
    }
}

/// Parallel element-wise pass over a coefficient array (native threads only).
///
/// Splits into contiguous chunks (one scope, up to 8 workers); `f` gets the
/// chunk's global base index + slice, so twiddle progressions restart per
/// chunk via a single `pow_u64` (bellman `distribute_powers` shape).
/// Falls back serial without `multicore` (also wasm32/no_std/tiny inputs).
/// Used for coset scalings and the h-quotient loop.
pub fn par_chunks_mut(a: &mut [Scalar], f: impl Fn(usize, &mut [Scalar]) + Send + Sync) {
    #[cfg(all(feature = "std", feature = "multicore", not(target_arch = "wasm32")))]
    {
        const MAX_THREADS: usize = 8;
        const MIN_CHUNK: usize = 4096;
        let n = a.len();
        if n >= MIN_CHUNK {
            let nthreads = MAX_THREADS.min(n.div_ceil(MIN_CHUNK)).max(1);
            if nthreads > 1 {
                let chunk = n.div_ceil(nthreads);
                std::thread::scope(|scope| {
                    for (t, slice) in a.chunks_mut(chunk).enumerate() {
                        let f = &f;
                        scope.spawn(move || {
                            f(t * chunk, slice);
                        });
                    }
                });
                return;
            }
        }
    }
    f(0, a);
}

/// ω_{2^32} = 7^{(r-1)/2^{32}} mod r (order 2^32).
fn root_of_unity(log_n: u32) -> Option<Scalar> {
    if log_n > 32 {
        return None;
    }
    // ω_{2^32} big-endian
    let omega_32 = Scalar::from_bytes_be(&[
        0x16, 0xa2, 0xa1, 0x9e, 0xdf, 0xe8, 0x1f, 0x20, 0xd0, 0x9b, 0x68, 0x19, 0x22, 0xc8, 0x13,
        0xb4, 0xb6, 0x36, 0x83, 0x50, 0x8c, 0x22, 0x80, 0xb9, 0x38, 0x29, 0x97, 0x1f, 0x43, 0x9f,
        0x0d, 0x2b,
    ])
    .ok()?;
    let mut w = omega_32;
    for _ in 0..(32 - log_n) {
        w = w.square();
    }
    Some(w)
}

/// Process-wide domains for Sapling ceremony sizes (Output 2^13, Spend 2^17).
#[cfg(feature = "std")]
pub fn domain_for_size(n: usize) -> Option<DomainBls> {
    use std::sync::OnceLock;
    static D8192: OnceLock<DomainBls> = OnceLock::new();
    static D131072: OnceLock<DomainBls> = OnceLock::new();
    match n {
        8192 => Some(
            D8192
                .get_or_init(|| DomainBls::new(8192).expect("8192"))
                .clone(),
        ),
        131072 => Some(
            D131072
                .get_or_init(|| DomainBls::new(131072).expect("131072"))
                .clone(),
        ),
        _ => DomainBls::new(n),
    }
}
#[cfg(not(feature = "std"))]
pub fn domain_for_size(n: usize) -> Option<DomainBls> {
    DomainBls::new(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::traits::Scalar as ScalarTrait;

    #[test]
    fn fft_ifft_roundtrip_bls() {
        let n = 8;
        let d = DomainBls::new(n).expect("domain");
        let mut a: Vec<Scalar> = (0..n).map(|i| Scalar::from_u64(i as u64 + 1)).collect();
        let orig = a.clone();
        d.fft(&mut a);
        d.ifft(&mut a);
        for i in 0..n {
            assert_eq!(ScalarTrait::ct_eq(&a[i], &orig[i]), 1, "idx {i}");
        }
    }

    #[test]
    fn root_order() {
        let w = root_of_unity(3).expect("w8");
        // ω^8 = 1
        assert_eq!(ScalarTrait::ct_eq(&w.pow_u64(8), &Scalar::one()), 1);
        // ω^4 = -1
        assert_eq!(
            ScalarTrait::ct_eq(&w.pow_u64(4), &Scalar::zero().sub(&Scalar::one())),
            1
        );
    }
}
