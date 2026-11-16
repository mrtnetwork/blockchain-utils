//! Packing / rounding helpers (FIPS 204).

use super::field;
use super::params::{N, Q};
use super::poly::{Poly, PolyVec};

const D: i32 = 13;

pub fn power2_round(r: i32) -> (i32, i32) {
    let r = field::reduce_i32(r);
    let mut r0 = r % (1 << D);
    if r0 > (1 << (D - 1)) {
        r0 -= 1 << D;
    }
    let r1 = (r - r0) >> D;
    (r1, r0)
}

pub fn decompose(r: i32, gamma2: i32) -> (i32, i32) {
    let r = field::reduce_i32(r);
    let alpha = 2 * gamma2;
    let mut r0 = r % alpha;
    if r0 > gamma2 {
        r0 -= alpha;
    }
    let mut r1 = (r - r0) / alpha;
    if r - r0 == Q - 1 {
        r1 = 0;
        r0 -= 1;
    }
    (r1, r0)
}

pub fn high_bits(r: i32, gamma2: i32) -> i32 {
    decompose(r, gamma2).0
}

pub fn low_bits(r: i32, gamma2: i32) -> i32 {
    decompose(r, gamma2).1
}

pub fn make_hint(z: i32, r: i32, gamma2: i32) -> u8 {
    if z <= gamma2 || z > Q - gamma2 || (z == Q - gamma2 && r == 0) {
        0
    } else {
        1
    }
}

pub fn use_hint(h: u8, r: i32, gamma2: i32) -> i32 {
    let (r1, r0) = decompose(r, gamma2);
    if h == 0 {
        return r1;
    }
    let m = (Q - 1) / (2 * gamma2);
    if r0 > 0 {
        (r1 + 1) % m
    } else {
        (r1 - 1 + m) % m
    }
}

pub fn simple_bit_pack(p: &Poly, b: usize) -> alloc::vec::Vec<u8> {
    let out_len = (N * b) / 8;
    let mut out = alloc::vec![0u8; out_len];
    let mut bit_pos = 0usize;
    for i in 0..N {
        let t = p.coeffs[i] as u32 & ((1u32 << b) - 1);
        for j in 0..b {
            if ((t >> j) & 1) == 1 {
                out[bit_pos >> 3] |= 1 << (bit_pos & 7);
            }
            bit_pos += 1;
        }
    }
    out
}

pub fn bit_pack_eta(p: &Poly, eta: i32) -> alloc::vec::Vec<u8> {
    // Pack coefficients in [q-eta, q) U [0, eta] as eta - c centered
    let bits = if eta == 2 { 3 } else { 4 };
    let out_len = (N * bits) / 8;
    let mut out = alloc::vec![0u8; out_len];
    let mut bit_pos = 0usize;
    for i in 0..N {
        let c = p.coeffs[i];
        // center then map: t = eta - center
        let mut center = c;
        if center > Q / 2 {
            center -= Q;
        }
        let t = (eta - center) as u32;
        for j in 0..bits {
            if ((t >> j) & 1) == 1 {
                out[bit_pos >> 3] |= 1 << (bit_pos & 7);
            }
            bit_pos += 1;
        }
    }
    out
}

pub fn bit_unpack_eta(bytes: &[u8], eta: i32) -> Poly {
    let bits = if eta == 2 { 3 } else { 4 };
    let mut p = Poly::zero();
    let mut bit_pos = 0usize;
    for i in 0..N {
        let mut t = 0u32;
        for j in 0..bits {
            if ((bytes[bit_pos >> 3] >> (bit_pos & 7)) & 1) == 1 {
                t |= 1 << j;
            }
            bit_pos += 1;
        }
        let mut c = eta - t as i32;
        if c < 0 {
            c += Q;
        }
        p.coeffs[i] = c;
    }
    p
}

pub fn bit_pack_z(p: &Poly, gamma1: i32) -> alloc::vec::Vec<u8> {
    let bits = if gamma1 == 1 << 17 { 18 } else { 20 };
    let out_len = (N * bits) / 8;
    let mut out = alloc::vec![0u8; out_len];
    let mut bit_pos = 0usize;
    for i in 0..N {
        let c = super::field::center(p.coeffs[i]);
        let t = (gamma1 - c) as u32;
        for j in 0..bits {
            if ((t >> j) & 1) == 1 {
                out[bit_pos >> 3] |= 1 << (bit_pos & 7);
            }
            bit_pos += 1;
        }
    }
    out
}

pub fn bit_unpack_z(bytes: &[u8], gamma1: i32) -> Poly {
    let bits = if gamma1 == 1 << 17 { 18 } else { 20 };
    let mut p = Poly::zero();
    let mut bit_pos = 0usize;
    for i in 0..N {
        let mut t = 0u32;
        for j in 0..bits {
            if ((bytes[bit_pos >> 3] >> (bit_pos & 7)) & 1) == 1 {
                t |= 1 << j;
            }
            bit_pos += 1;
        }
        let mut c = gamma1 - t as i32;
        if c < 0 {
            c += Q;
        }
        p.coeffs[i] = c;
    }
    p
}

pub fn pk_encode(rho: &[u8], t1: &PolyVec) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec::Vec::with_capacity(32 + t1.polys.len() * 320);
    out.extend_from_slice(rho);
    for p in &t1.polys {
        out.extend_from_slice(&simple_bit_pack(p, 10));
    }
    out
}

pub fn pk_decode(pk: &[u8], k: usize) -> ([u8; 32], PolyVec) {
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&pk[..32]);
    let mut t1 = PolyVec::new(k);
    let mut off = 32;
    for i in 0..k {
        // simple bit unpack 10
        let bytes = &pk[off..off + 320];
        let mut bit_pos = 0usize;
        for j in 0..N {
            let mut t = 0u32;
            for b in 0..10 {
                if ((bytes[bit_pos >> 3] >> (bit_pos & 7)) & 1) == 1 {
                    t |= 1 << b;
                }
                bit_pos += 1;
            }
            t1.polys[i].coeffs[j] = t as i32;
        }
        off += 320;
    }
    (rho, t1)
}

pub fn sk_encode(
    rho: &[u8],
    k_seed: &[u8],
    tr: &[u8],
    s1: &PolyVec,
    s2: &PolyVec,
    t0: &PolyVec,
    eta: i32,
) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec::Vec::new();
    out.extend_from_slice(rho);
    out.extend_from_slice(k_seed);
    out.extend_from_slice(tr);
    for p in &s1.polys {
        out.extend_from_slice(&bit_pack_eta(p, eta));
    }
    for p in &s2.polys {
        out.extend_from_slice(&bit_pack_eta(p, eta));
    }
    for p in &t0.polys {
        // t0 packed with 13 bits centered
        out.extend_from_slice(&bit_pack_t0(p));
    }
    out
}

fn bit_pack_t0(p: &Poly) -> alloc::vec::Vec<u8> {
    // 13 bits; FIPS/Ref: t = 2^{12} - center(c), then mask 13 bits
    let mut out = alloc::vec![0u8; 416];
    let mut bit_pos = 0usize;
    for i in 0..N {
        let mut c = p.coeffs[i];
        if c > Q / 2 {
            c -= Q;
        }
        let t = (((1 << 12) - c) as u32) & 0x1fff;
        for j in 0..13 {
            if ((t >> j) & 1) == 1 {
                out[bit_pos >> 3] |= 1 << (bit_pos & 7);
            }
            bit_pos += 1;
        }
    }
    out
}

pub fn bit_unpack_t0(bytes: &[u8]) -> Poly {
    // Inverse of t = 2^{12} - c  →  c = 2^{12} - t
    let mut p = Poly::zero();
    let mut bit_pos = 0usize;
    for i in 0..N {
        let mut t = 0u32;
        for j in 0..13 {
            if ((bytes[bit_pos >> 3] >> (bit_pos & 7)) & 1) == 1 {
                t |= 1 << j;
            }
            bit_pos += 1;
        }
        let mut c = (1 << 12) - t as i32;
        if c < 0 {
            c += Q;
        }
        p.coeffs[i] = c;
    }
    p
}

pub fn sig_encode(
    c_tilde: &[u8],
    z: &PolyVec,
    hints: &[alloc::vec::Vec<usize>],
    gamma1: i32,
    omega: usize,
    k: usize,
) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec::Vec::new();
    out.extend_from_slice(c_tilde);
    for p in &z.polys {
        out.extend_from_slice(&bit_pack_z(p, gamma1));
    }
    // hint packing
    let mut y = alloc::vec![0u8; omega + k];
    let mut pos = 0usize;
    for i in 0..k {
        for &j in &hints[i] {
            y[pos] = j as u8;
            pos += 1;
        }
        y[omega + i] = pos as u8;
    }
    out.extend_from_slice(&y);
    out
}
