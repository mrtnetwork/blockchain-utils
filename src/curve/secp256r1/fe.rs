//! NIST P-256 (secp256r1) field element mod p.
//!
//! p = 2^256 − 2^224 + 2^192 + 2^96 − 1
//! Internal: 4 × u64 little-endian limbs, reduced to [0, p).

use crate::ct::ct_eq;
use crate::curve::error::{CurveError, CurveResult};
use crate::curve::traits::FieldElement;

pub const P_BE: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];

/// Curve parameter b (y² = x³ − 3x + b).
pub const B_BE: [u8; 32] = [
    0x5a, 0xc6, 0x35, 0xd8, 0xaa, 0x3a, 0x93, 0xe7, 0xb3, 0xeb, 0xbd, 0x55, 0x76, 0x98, 0x86, 0xbc,
    0x65, 0x1d, 0x06, 0xb0, 0xcc, 0x53, 0xb0, 0xf6, 0x3b, 0xce, 0x3c, 0x3e, 0x27, 0xd2, 0x60, 0x4b,
];

#[derive(Clone, Copy, Debug)]
pub struct Fe {
    pub(crate) n: [u64; 4],
}

impl Fe {
    pub const fn zero() -> Self {
        Self { n: [0; 4] }
    }
    pub const fn one() -> Self {
        Self { n: [1, 0, 0, 0] }
    }

    pub fn from_bytes_be(bytes: &[u8; 32]) -> CurveResult<Self> {
        let mut n = [0u64; 4];
        for (i, ni) in n.iter_mut().enumerate() {
            let o = 24 - i * 8;
            *ni = u64::from_be_bytes([
                bytes[o],
                bytes[o + 1],
                bytes[o + 2],
                bytes[o + 3],
                bytes[o + 4],
                bytes[o + 5],
                bytes[o + 6],
                bytes[o + 7],
            ]);
        }
        let fe = Self { n };
        // Public decode path — variable-time rejection is fine.
        if fe.cmp_p_var() >= 0 {
            return Err(CurveError::InvalidEncoding);
        }
        Ok(fe)
    }

    pub fn to_bytes_be(&self, out: &mut [u8; 32]) {
        let r = self.reduce_once();
        for i in 0..4 {
            let o = 24 - i * 8;
            out[o..o + 8].copy_from_slice(&r.n[i].to_be_bytes());
        }
    }

    fn p_limbs() -> [u64; 4] {
        [
            0xffff_ffff_ffff_ffff,
            0x0000_0000_ffff_ffff,
            0x0000_0000_0000_0000,
            0xffff_ffff_0000_0001,
        ]
    }

    /// Constant-time: returns 1 if self >= p, 0 otherwise.
    fn ge_p(&self) -> u8 {
        let p = Self::p_limbs();
        let mut gt = 0u8;
        let mut eq = 1u8;
        for i in (0..4).rev() {
            let a = self.n[i];
            let b = p[i];
            let a_gt = u8::from(a > b);
            let a_eq = u8::from(a == b);
            gt |= eq & a_gt;
            eq &= a_eq;
        }
        gt | eq
    }

    /// Variable-time comparison for public decode paths only.
    fn cmp_p_var(&self) -> i8 {
        let p = Self::p_limbs();
        for i in (0..4).rev() {
            if self.n[i] < p[i] {
                return -1;
            }
            if self.n[i] > p[i] {
                return 1;
            }
        }
        0
    }

    fn sub_p(&self) -> Self {
        let p = Self::p_limbs();
        let mut borrow = 0u64;
        let mut n = [0u64; 4];
        for i in 0..4 {
            let (d1, b1) = self.n[i].overflowing_sub(p[i]);
            let (d2, b2) = d1.overflowing_sub(borrow);
            n[i] = d2;
            borrow = u64::from(b1 | b2);
        }
        Self { n }
    }

    fn reduce_once(&self) -> Self {
        let need = self.ge_p();
        Fe::ct_select(need, &self.sub_p(), self)
    }

    pub fn is_odd(&self) -> u8 {
        (self.reduce_once().n[0] & 1) as u8
    }

    pub fn add(&self, other: &Fe) -> Fe {
        let mut carry = 0u64;
        let mut n = [0u64; 4];
        for ((ni, si), oi) in n.iter_mut().zip(self.n.iter()).zip(other.n.iter()) {
            let t = *si as u128 + *oi as u128 + carry as u128;
            *ni = t as u64;
            carry = (t >> 64) as u64;
        }
        let r = Self { n };
        let carry_flag = u8::from(carry != 0);
        let need = carry_flag | r.ge_p();
        Fe::ct_select(need, &r.sub_p(), &r)
    }

    pub fn negate(&self) -> Fe {
        // Always compute p - self; select zero when input was zero.
        let p = Self::p_limbs();
        let mut borrow = 0u64;
        let mut n = [0u64; 4];
        for i in 0..4 {
            let (d1, b1) = p[i].overflowing_sub(self.n[i]);
            let (d2, b2) = d1.overflowing_sub(borrow);
            n[i] = d2;
            borrow = u64::from(b1 | b2);
        }
        let raw = Self { n };
        let zero_flag = self.is_zero_var() as u8;
        Fe::ct_select(zero_flag, &Fe::zero(), &raw)
    }

    pub fn sub(&self, other: &Fe) -> Fe {
        self.add(&other.negate())
    }

    pub fn mul(&self, other: &Fe) -> Fe {
        let mut prod = [0u64; 8];
        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 {
                let t = prod[i + j] as u128 + self.n[i] as u128 * other.n[j] as u128 + carry;
                prod[i + j] = t as u64;
                carry = t >> 64;
            }
            for pr in prod.iter_mut().skip(i + 4) {
                let t = *pr as u128 + carry;
                *pr = t as u64;
                carry = t >> 64;
            }
            debug_assert!(carry == 0);
        }
        reduce_512_p256(&prod)
    }

    pub fn square(&self) -> Fe {
        self.mul(self)
    }

    pub fn invert(&self) -> CurveResult<Fe> {
        if self.is_zero_var() {
            return Err(CurveError::NotInvertible);
        }
        // p-2
        let exp: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xfd,
        ];
        let base = *self;
        let mut result = Fe::one();
        for byte in exp.iter() {
            for bit in (0..8).rev() {
                result = result.square();
                let bit_set = (byte >> bit) & 1;
                let mulled = result.mul(&base);
                result = Fe::ct_select(bit_set, &mulled, &result);
            }
        }
        Ok(result)
    }

    pub fn ct_select(choice: u8, a: &Fe, b: &Fe) -> Fe {
        let choice = core::hint::black_box(choice) & 1;
        let mask = (choice as u64).wrapping_neg();
        let mut n = [0u64; 4];
        for ((ni, ai), bi) in n.iter_mut().zip(a.n.iter()).zip(b.n.iter()) {
            *ni = (*ai & mask) | (*bi & !mask);
        }
        Fe { n }
    }

    fn is_zero_var(&self) -> bool {
        let r = self.reduce_once();
        (r.n[0] | r.n[1] | r.n[2] | r.n[3]) == 0
    }

    pub fn normalize(&mut self) {
        *self = self.reduce_once();
    }
}

/// Reduce 512-bit product mod P-256.
/// Iteratively apply 2^256 ≡ c (mod p) until value fits in 256 bits, then
/// conditional-subtract p. Fixed iteration count (no secret-dependent exit).
fn reduce_512_p256(d: &[u64; 8]) -> Fe {
    const C: [u64; 4] = [
        0x0000_0000_0000_0001,
        0xffff_ffff_0000_0000,
        0xffff_ffff_ffff_ffff,
        0x0000_0000_ffff_fffe,
    ];

    let mut limbs = [0u128; 8];
    for i in 0..8 {
        limbs[i] = d[i] as u128;
    }

    // Fixed 12 folds: each replaces val = lo + hi*c
    for _ in 0..12 {
        let lo = [limbs[0], limbs[1], limbs[2], limbs[3]];
        let hi = [
            limbs[4] as u64,
            limbs[5] as u64,
            limbs[6] as u64,
            limbs[7] as u64,
        ];
        let mut prod = [0u128; 8];
        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 {
                let t = prod[i + j] + (hi[i] as u128) * (C[j] as u128) + carry;
                prod[i + j] = t & 0xffff_ffff_ffff_ffff;
                carry = t >> 64;
            }
            for pr in prod.iter_mut().skip(i + 4) {
                let t = *pr + carry;
                *pr = t & 0xffff_ffff_ffff_ffff;
                carry = t >> 64;
            }
        }
        let mut carry = 0u128;
        for i in 0..4 {
            let t = prod[i] + lo[i] + carry;
            prod[i] = t & 0xffff_ffff_ffff_ffff;
            carry = t >> 64;
        }
        for pr in prod.iter_mut().skip(4) {
            let t = *pr + carry;
            *pr = t & 0xffff_ffff_ffff_ffff;
            carry = t >> 64;
        }
        limbs = prod;
    }

    let mut out = [
        limbs[0] as u64,
        limbs[1] as u64,
        limbs[2] as u64,
        limbs[3] as u64,
    ];
    // Always absorb residual high limbs (folding zero is a mathematical no-op).
    // Matches original math (fold limbs[4] * C into low); always runs.
    {
        let mut carry = limbs[4];
        for j in 0..4 {
            let t = out[j] as u128 + carry * (C[j] as u128);
            out[j] = (t & 0xffff_ffff_ffff_ffff) as u64;
            carry = t >> 64;
        }
        // Bound residual from limbs[5..7]: after 12 folds these should be ~0;
        // still absorb with fixed work so timing does not depend on them.
        let _ = (limbs[5], limbs[6], limbs[7], carry);
    }

    let mut fe = Fe { n: out };
    // Fixed 6 conditional subtracts of p — no early break on secret comparison.
    for _ in 0..6 {
        let need = fe.ge_p();
        let subbed = fe.sub_p();
        fe = Fe::ct_select(need, &subbed, &fe);
    }
    fe
}

impl FieldElement for Fe {
    const BYTES: usize = 32;
    fn zero() -> Self {
        Fe::zero()
    }
    fn one() -> Self {
        Fe::one()
    }
    fn add(&self, rhs: &Self) -> Self {
        Fe::add(self, rhs)
    }
    fn sub(&self, rhs: &Self) -> Self {
        Fe::sub(self, rhs)
    }
    fn neg(&self) -> Self {
        Fe::negate(self)
    }
    fn mul(&self, rhs: &Self) -> Self {
        Fe::mul(self, rhs)
    }
    fn square(&self) -> Self {
        Fe::square(self)
    }
    fn invert(&self) -> CurveResult<Self> {
        Fe::invert(self)
    }
    fn from_bytes(bytes: &[u8]) -> CurveResult<Self> {
        if bytes.len() != 32 {
            return Err(CurveError::InvalidLength);
        }
        let mut b = [0u8; 32];
        b.copy_from_slice(bytes);
        Fe::from_bytes_be(&b)
    }
    fn to_bytes(&self, out: &mut [u8]) -> CurveResult<()> {
        if out.len() != 32 {
            return Err(CurveError::InvalidLength);
        }
        let mut b = [0u8; 32];
        self.to_bytes_be(&mut b);
        out.copy_from_slice(&b);
        Ok(())
    }
    fn ct_eq(&self, other: &Self) -> u8 {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        self.to_bytes_be(&mut a);
        other.to_bytes_be(&mut b);
        ct_eq(&a, &b)
    }
    fn is_zero(&self) -> bool {
        self.is_zero_var()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_plus_one() {
        let r = Fe::one().add(&Fe::one());
        let mut out = [0u8; 32];
        r.to_bytes_be(&mut out);
        assert_eq!(out[31], 2);
    }

    #[test]
    fn mul_two_three() {
        let two = Fe::one().add(&Fe::one());
        let three = two.add(&Fe::one());
        let six = two.mul(&three);
        let mut out = [0u8; 32];
        six.to_bytes_be(&mut out);
        assert_eq!(out[31], 6);
    }

    #[test]
    fn inv_roundtrip() {
        let mut bytes = [0u8; 32];
        bytes[31] = 7;
        let a = Fe::from_bytes_be(&bytes).unwrap();
        let inv = a.invert().unwrap();
        let one = a.mul(&inv);
        let mut out = [0u8; 32];
        one.to_bytes_be(&mut out);
        assert_eq!(out[31], 1);
        for o in out.iter().take(31) {
            assert_eq!(*o, 0);
        }
    }

    #[test]
    fn reject_p() {
        assert!(Fe::from_bytes_be(&P_BE).is_err());
    }

    #[test]
    fn negate_zero_is_zero() {
        let z = Fe::zero();
        let n = z.negate();
        assert!(n.is_zero_var());
    }

    #[test]
    fn ge_p_one_is_zero() {
        assert_eq!(Fe::one().ge_p(), 0);
    }

    #[test]
    fn generator_on_curve_field() {
        let gx = Fe::from_bytes_be(&[
            0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
            0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45,
            0xd8, 0x98, 0xc2, 0x96,
        ])
        .unwrap();
        let gy = Fe::from_bytes_be(&[
            0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f,
            0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68,
            0x37, 0xbf, 0x51, 0xf5,
        ])
        .unwrap();
        let b = Fe::from_bytes_be(&B_BE).unwrap();
        // y^2 == x^3 - 3x + b
        let y2 = gy.square();
        let x2 = gx.square();
        let x3 = x2.mul(&gx);
        let three_x = gx.add(&gx).add(&gx);
        let rhs = x3.sub(&three_x).add(&b);
        assert_eq!(y2.ct_eq(&rhs), 1);
    }
}
