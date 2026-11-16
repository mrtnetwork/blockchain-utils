//! Polynomials and vectors for ML-DSA.

use super::field;
use super::ntt;
use super::params::{N, Q};
use alloc::vec::Vec;

#[derive(Clone)]
pub struct Poly {
    pub coeffs: [i32; N],
}

impl Poly {
    pub fn zero() -> Self {
        Self { coeffs: [0; N] }
    }
    pub fn add_assign(&mut self, o: &Poly) {
        for i in 0..N {
            self.coeffs[i] = field::add(self.coeffs[i], o.coeffs[i]);
        }
    }
    pub fn sub_assign(&mut self, o: &Poly) {
        for i in 0..N {
            self.coeffs[i] = field::sub(self.coeffs[i], o.coeffs[i]);
        }
    }
    #[allow(clippy::wrong_self_convention)] // In-place NTT matches FIPS 204 naming; `&mut self` is intentional.
    pub fn to_ntt(&mut self) {
        ntt::ntt(&mut self.coeffs);
    }
    #[allow(clippy::wrong_self_convention)] // In-place inverse NTT matches FIPS 204 naming; `&mut self` is intentional.
    pub fn from_ntt(&mut self) {
        ntt::inv_ntt(&mut self.coeffs);
    }
    pub fn pointwise_mul(&mut self, o: &Poly) {
        ntt::multiply_ntt(&mut self.coeffs, &o.coeffs);
    }
    pub fn reduce(&mut self) {
        for c in self.coeffs.iter_mut() {
            *c = field::reduce_i32(*c);
        }
    }
    pub fn infinity_norm_ok(&self, bound: i32) -> bool {
        for &c in &self.coeffs {
            let v = field::center(c).abs();
            if v >= bound {
                return false;
            }
        }
        true
    }
}

#[derive(Clone)]
pub struct PolyVec {
    pub polys: alloc::vec::Vec<Poly>,
}

impl PolyVec {
    pub fn new(k: usize) -> Self {
        Self {
            polys: (0..k).map(|_| Poly::zero()).collect(),
        }
    }
    pub fn add_assign(&mut self, o: &PolyVec) {
        for (a, b) in self.polys.iter_mut().zip(o.polys.iter()) {
            a.add_assign(b);
        }
    }
    pub fn sub_assign(&mut self, o: &PolyVec) {
        for (a, b) in self.polys.iter_mut().zip(o.polys.iter()) {
            a.sub_assign(b);
        }
    }
    #[allow(clippy::wrong_self_convention)] // In-place NTT matches FIPS 204 naming; `&mut self` is intentional.
    pub fn to_ntt(&mut self) {
        for p in &mut self.polys {
            p.to_ntt();
        }
    }
    #[allow(clippy::wrong_self_convention)] // In-place inverse NTT matches FIPS 204 naming; `&mut self` is intentional.
    pub fn from_ntt(&mut self) {
        for p in &mut self.polys {
            p.from_ntt();
        }
    }
    pub fn reduce(&mut self) {
        for p in &mut self.polys {
            p.reduce();
        }
    }
    pub fn infinity_norm_ok(&self, bound: i32) -> bool {
        self.polys.iter().all(|p| p.infinity_norm_ok(bound))
    }
}

/// Matrix Â as k vectors of length l (row-major), in NTT domain.
pub struct Matrix {
    pub rows: alloc::vec::Vec<PolyVec>, // k rows, each l polys
}

impl Matrix {
    pub fn mul_vec_ntt(&self, out: &mut PolyVec, s: &PolyVec) {
        let k = self.rows.len();
        for i in 0..k {
            out.polys[i] = Poly::zero();
            for j in 0..s.polys.len() {
                let mut t = self.rows[i].polys[j].clone();
                t.pointwise_mul(&s.polys[j]);
                out.polys[i].add_assign(&t);
            }
        }
    }
}

/// FIPS continuous SHAKE for expandA: seed is rho||j||i (34 bytes). Use one XOF stream.
pub fn sample_uniform_stream(seed: &[u8]) -> Poly {
    // Use multiple sequential shakes with domain - for correctness matching reference we need continuous.
    // reference uses single SHAKE256 update(seed) then successive finish 136-byte blocks.
    continuous_rej_uniform(seed)
}

fn continuous_rej_uniform(seed: &[u8]) -> Poly {
    // FIPS 204 SampleNTT / Ref: SHAKE128, squeeze 3 bytes per candidate
    let mut h = crate::hash::keccak::Keccak::shake128();
    h.update(seed);
    let mut p = Poly::zero();
    let mut idx = 0;
    while idx < N {
        let mut b = [0u8; 3];
        let _ = h.finish_into_mut(&mut b);
        let t = (b[0] as u32) | ((b[1] as u32) << 8) | (((b[2] as u32) & 0x7f) << 16);
        if t < Q as u32 {
            p.coeffs[idx] = t as i32;
            idx += 1;
        }
    }
    p
}

pub fn expand_a(rho: &[u8], k: usize, l: usize) -> Matrix {
    let mut rows = alloc::vec::Vec::with_capacity(k);
    for i in 0..k {
        let mut row = PolyVec::new(l);
        for j in 0..l {
            let mut seed = [0u8; 34];
            seed[..32].copy_from_slice(rho);
            seed[32] = j as u8;
            seed[33] = i as u8;
            // SampleNTT already returns NTT-domain coefficients (FIPS 204).
            row.polys[j] = sample_uniform_stream(&seed);
        }
        rows.push(row);
    }
    Matrix { rows }
}

pub fn sample_bounded(seed: &[u8], eta: i32) -> Poly {
    let mut h = crate::hash::keccak::Keccak::shake256();
    h.update(seed);
    let mut p = Poly::zero();
    let mut idx = 0;
    while idx < N {
        let mut buf = [0u8; 136];
        h.finish_into_mut(&mut buf).ok();
        for &byte in &buf {
            if idx >= N {
                break;
            }
            if eta == 2 {
                for shift in (0..8).step_by(4) {
                    if idx >= N {
                        break;
                    }
                    let b = (byte >> shift) & 0x0f;
                    if b < 15 {
                        p.coeffs[idx] = 2 - (b as i32 % 5);
                        idx += 1;
                    }
                }
            } else {
                for shift in (0..8).step_by(4) {
                    if idx >= N {
                        break;
                    }
                    let b = (byte >> shift) & 0x0f;
                    if b < 9 {
                        p.coeffs[idx] = 4 - b as i32;
                        idx += 1;
                    }
                }
            }
        }
    }
    // map negative to [0,q)
    for c in p.coeffs.iter_mut() {
        if *c < 0 {
            *c += Q;
        }
    }
    p
}

pub fn expand_s(rho_prime: &[u8], k: usize, l: usize, eta: i32) -> (PolyVec, PolyVec) {
    let mut s1 = PolyVec::new(l);
    let mut s2 = PolyVec::new(k);
    let mut nonce = 0u16;
    for i in 0..l {
        let mut seed = alloc::vec::Vec::with_capacity(66);
        seed.extend_from_slice(rho_prime);
        seed.push(nonce as u8);
        seed.push((nonce >> 8) as u8);
        s1.polys[i] = sample_bounded(&seed, eta);
        nonce += 1;
    }
    for i in 0..k {
        let mut seed = alloc::vec::Vec::with_capacity(66);
        seed.extend_from_slice(rho_prime);
        seed.push(nonce as u8);
        seed.push((nonce >> 8) as u8);
        s2.polys[i] = sample_bounded(&seed, eta);
        nonce += 1;
    }
    (s1, s2)
}

pub fn sample_mask(seed: &[u8], gamma1: i32) -> Poly {
    let mut h = crate::hash::keccak::Keccak::shake256();
    h.update(seed);
    let bits = if gamma1 == 1 << 17 { 18 } else { 20 };
    let bytes_needed = (N * bits).div_ceil(8);
    let mut buf = alloc::vec![0u8; bytes_needed];
    h.finish_into_mut(&mut buf).ok();
    let mut p = Poly::zero();
    let mut bit_pos = 0usize;
    for i in 0..N {
        let mut t = 0i32;
        for b in 0..bits {
            let bit = (buf[bit_pos >> 3] >> (bit_pos & 7)) & 1;
            if bit == 1 {
                t |= 1 << b;
            }
            bit_pos += 1;
        }
        let mut c = gamma1 - t;
        if c < 0 {
            c += Q;
        }
        p.coeffs[i] = c;
    }
    p
}

pub fn expand_mask(rho_pp: &[u8], kappa: usize, l: usize, gamma1: i32) -> PolyVec {
    let mut y = PolyVec::new(l);
    for i in 0..l {
        let nonce = (kappa + i) as u16;
        let mut seed = alloc::vec::Vec::with_capacity(66);
        seed.extend_from_slice(rho_pp);
        seed.push(nonce as u8);
        seed.push((nonce >> 8) as u8);
        y.polys[i] = sample_mask(&seed, gamma1);
    }
    y
}

pub fn sample_in_ball(seed: &[u8], tau: usize) -> Poly {
    let mut h = crate::hash::keccak::Keccak::shake256();
    h.update(seed);
    let mut signs = [0u8; 8];
    // First 8 bytes of the XOF are the sign bits (FIPS 204 / reference).
    let _ = h.finish_into_mut(&mut signs);
    let mut p = Poly::zero();
    let mut stream: Vec<u8> = Vec::new();
    for i in (N - tau)..N {
        let j = loop {
            if stream.is_empty() {
                let mut buf = [0u8; 136];
                h.finish_into_mut(&mut buf).ok();
                stream.extend_from_slice(&buf);
            }
            let j = stream.remove(0) as usize;
            if j <= i {
                break j;
            }
        };
        p.coeffs[i] = p.coeffs[j];
        let sign_index = i - (N - tau);
        let sign_bit = (signs[sign_index >> 3] >> (sign_index & 7)) & 1;
        let mut v = 1 - 2 * sign_bit as i32;
        if v < 0 {
            v += Q;
        }
        p.coeffs[j] = v;
    }
    p
}
