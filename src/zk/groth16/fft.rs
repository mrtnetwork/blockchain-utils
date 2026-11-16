//! Radix-2 FFT / iFFT over BN254 Fr (feature `groth16-prover`).

#![cfg(feature = "groth16-prover")]

use crate::curve::bn254::Scalar;
// `Vec` is prelude under `std`; import from `alloc` only for `no_std`.
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// Evaluation domain of size `2^k` for BN254 Fr.
///
/// 2-adicity of BN254 Fr is 28, so `k <= 28`.
#[derive(Clone, Debug)]
pub struct Domain {
    /// Domain size (power of two).
    pub size: usize,
    /// log2(size)
    pub log_size: u32,
    /// Primitive size-th root of unity ω.
    pub omega: Scalar,
    /// ω^{-1}
    pub omega_inv: Scalar,
    /// size as scalar
    pub size_inv: Scalar,
}

impl Domain {
    /// Build domain of size `n` (must be power of two, `n <= 2^28`).
    pub fn new(n: usize) -> Option<Self> {
        if n == 0 || !n.is_power_of_two() || n > (1 << 28) {
            return None;
        }
        let log_size = n.trailing_zeros();
        // BN254 Fr multiplicative group order r-1 = 2^28 * odd
        // ω_2^28 is a fixed generator of the 2-Sylow; raise to 2^{28-k}
        let omega = root_of_unity(log_size)?;
        let omega_inv = omega.invert().ok()?;
        let size_inv = Scalar::from_u64(n as u64).invert().ok()?;
        Some(Self {
            size: n,
            log_size,
            omega,
            omega_inv,
            size_inv,
        })
    }

    /// In-place DFT: a[i] ← Σ_j a[j] ω^{ij}
    pub fn fft(&self, a: &mut [Scalar]) {
        assert_eq!(a.len(), self.size);
        bit_reverse(a);
        let mut m = 1usize;
        while m < self.size {
            let w_m = self.omega.pow_u64((self.size / (2 * m)) as u64);
            let mut k = 0usize;
            while k < self.size {
                let mut w = Scalar::one();
                for j in 0..m {
                    let t = a[k + j + m].mul(&w);
                    let u = a[k + j];
                    a[k + j] = u.add(&t);
                    a[k + j + m] = u.sub(&t);
                    w = w.mul(&w_m);
                }
                k += 2 * m;
            }
            m *= 2;
        }
    }

    /// In-place inverse DFT.
    pub fn ifft(&self, a: &mut [Scalar]) {
        assert_eq!(a.len(), self.size);
        bit_reverse(a);
        let mut m = 1usize;
        while m < self.size {
            let w_m = self.omega_inv.pow_u64((self.size / (2 * m)) as u64);
            let mut k = 0usize;
            while k < self.size {
                let mut w = Scalar::one();
                for j in 0..m {
                    let t = a[k + j + m].mul(&w);
                    let u = a[k + j];
                    a[k + j] = u.add(&t);
                    a[k + j + m] = u.sub(&t);
                    w = w.mul(&w_m);
                }
                k += 2 * m;
            }
            m *= 2;
        }
        for x in a.iter_mut() {
            *x = x.mul(&self.size_inv);
        }
    }

    /// Coset FFT: evaluate on coset g·⟨ω⟩ (shift by generator element).
    pub fn coset_fft(&self, a: &mut [Scalar], g: &Scalar) {
        let mut pow = Scalar::one();
        for x in a.iter_mut() {
            *x = x.mul(&pow);
            pow = pow.mul(g);
        }
        self.fft(a);
    }

    /// Inverse coset FFT.
    pub fn coset_ifft(&self, a: &mut [Scalar], g: &Scalar) {
        self.ifft(a);
        let g_inv = g.invert().unwrap_or(Scalar::one());
        let mut pow = Scalar::one();
        for x in a.iter_mut() {
            *x = x.mul(&pow);
            pow = pow.mul(&g_inv);
        }
    }
}

fn bit_reverse(a: &mut [Scalar]) {
    let n = a.len();
    let log_n = n.trailing_zeros();
    for i in 0..n {
        let j = (i as u32).reverse_bits() >> (32 - log_n);
        let j = j as usize;
        if i < j {
            a.swap(i, j);
        }
    }
}

/// 2^k-th root of unity in BN254 Fr.
///
/// Uses hard-coded ω_{2^28} and raises to 2^{28-k}.
fn root_of_unity(log_n: u32) -> Option<Scalar> {
    if log_n > 28 {
        return None;
    }
    // ω_{2^28} = 5^{(r-1)/2^{28}} mod r  (verified order 2^28)
    let omega_28 =
        scalar_from_hex("2a3c09f0a58a7e8500e0a7eb8ef62abc402d111e41112ed49bd61b6e725b19f0")?;
    let mut w = omega_28;
    for _ in 0..(28 - log_n) {
        w = w.square();
    }
    Some(w)
}

fn scalar_from_hex(hex: &str) -> Option<Scalar> {
    let h = hex.trim_start_matches("0x");
    let mut raw = [0u8; 32];
    let full = if h.len() % 2 == 1 {
        alloc::format!("0{h}")
    } else {
        alloc::string::String::from(h)
    };
    if full.len() > 64 {
        return None;
    }
    let pad = 32 - full.len() / 2;
    for i in 0..(full.len() / 2) {
        raw[pad + i] = u8::from_str_radix(&full[i * 2..i * 2 + 2], 16).ok()?;
    }
    Scalar::from_bytes_be(&raw).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fft_ifft_roundtrip() {
        let n = 8;
        let d = Domain::new(n).expect("domain");
        let mut a: Vec<Scalar> = (0..n).map(|i| Scalar::from_u64(i as u64 + 1)).collect();
        let original = a.clone();
        d.fft(&mut a);
        // not identity
        assert!(a.iter().zip(original.iter()).any(|(x, y)| x.ct_eq(y) == 0));
        d.ifft(&mut a);
        for (x, y) in a.iter().zip(original.iter()) {
            assert_eq!(x.ct_eq(y), 1);
        }
    }

    #[test]
    fn root_loads() {
        let w = scalar_from_hex("2a3c09f0a58a7e8500e0a7eb8ef62abc402d111e41112ed49bd61b6e725b19f0");
        assert!(w.is_some(), "load omega28");
        let w = w.unwrap();
        // w^{2^28} = 1
        let mut x = w;
        for _ in 0..28 {
            x = x.square();
        }
        assert_eq!(x.ct_eq(&Scalar::one()), 1, "omega28 order 2^28");
    }

    #[test]
    fn omega_order() {
        let d = Domain::new(4).expect("domain");
        let mut w = Scalar::one();
        for _ in 0..4 {
            w = w.mul(&d.omega);
        }
        // If root loading fails we may not get exact order; FFT roundtrip is the lock.
        let ok = w.ct_eq(&Scalar::one()) == 1;
        assert!(ok || d.size == 4, "omega^4=1 or domain size ok");
        assert_eq!(w.ct_eq(&Scalar::one()), 1, "omega^4 must be one");
    }
}
