//! secp256k1 field element mod p = 2^256 - 2^32 - 977.
//!
//! Internal form: 4 × `u64` little-endian limbs (limb 0 = least significant),
//! always reduced to `[0, p)`. Constant-time selection; arithmetic avoids
//! secret-dependent branches on the hot path.

use crate::ct::ct_eq;
use crate::curve::error::{CurveError, CurveResult};
use crate::curve::traits::FieldElement;

/// Field prime p (big-endian).
pub const P_BE: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f,
];

/// Field element.
#[derive(Clone, Copy, Debug)]
pub struct Fe {
    /// LE 64-bit limbs.
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
        // Public decode path — variable-time rejection of out-of-range encodings is fine.
        if fe.cmp_p_var() >= 0 {
            return Err(CurveError::InvalidEncoding);
        }
        Ok(fe)
    }

    pub fn to_bytes_be(&self, out: &mut [u8; 32]) {
        for i in 0..4 {
            let o = 24 - i * 8;
            out[o..o + 8].copy_from_slice(&self.n[i].to_be_bytes());
        }
    }

    /// Constant-time: returns 1 if self >= p, 0 otherwise.
    /// Fixed iteration count — no early exit on secret limbs.
    fn ge_p(&self) -> u8 {
        let p = p_limbs();
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

    fn cmp_p_var(&self) -> i8 {
        let p = p_limbs();
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
        let p = p_limbs();
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

    /// Reduce into [0,p) assuming self is in [0, 2p). Constant-time.
    fn reduce_once(&self) -> Self {
        let ge = self.ge_p();
        // Also handle carry-out case callers may pass via limb overflow stored externally;
        // here we only have the four limbs.
        Fe::ct_select(ge, &self.sub_p(), self)
    }

    pub fn is_odd(&self) -> u8 {
        (self.n[0] & 1) as u8
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
        // Need subtract p if carry or r ≥ p — fully constant-time.
        let carry_flag = u8::from(carry != 0);
        let need = carry_flag | r.ge_p();
        Fe::ct_select(need, &r.sub_p(), &r)
    }

    pub fn negate(&self) -> Fe {
        // Always compute p - self, then select zero when self was zero.
        // When self == 0, p - 0 == p (not a reduced field element); select Zero.
        let p = p_limbs();
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
        // Product as 512-bit (8 LE u64 limbs). Inner product is schoolbook;
        // carry propagation into high limbs is fixed-bound (no secret early exit).
        let mut prod = [0u64; 8];
        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 {
                let t = prod[i + j] as u128 + self.n[i] as u128 * other.n[j] as u128 + carry;
                prod[i + j] = t as u64;
                carry = t >> 64;
            }
            // Propagate remaining carry through high limbs with fixed upper bound.
            for pr in prod.iter_mut().skip(i + 4) {
                let t = *pr as u128 + carry;
                *pr = t as u64;
                carry = t >> 64;
            }
            // carry into index >= 8 is impossible for two 256-bit factors.
            debug_assert!(carry == 0);
        }
        reduce_512_simple(&prod)
    }

    pub fn square(&self) -> Fe {
        self.mul(self)
    }

    pub fn invert(&self) -> CurveResult<Fe> {
        if self.is_zero_var() {
            return Err(CurveError::NotInvertible);
        }
        // a^(p-2) mod p
        let exp: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
            0xff, 0xff, 0xfc, 0x2d,
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
        // black_box prevents the optimizer from reconstructing a branch on choice.
        let choice = core::hint::black_box(choice) & 1;
        let mask = (choice as u64).wrapping_neg();
        let mut n = [0u64; 4];
        for ((ni, ai), bi) in n.iter_mut().zip(a.n.iter()).zip(b.n.iter()) {
            *ni = (*ai & mask) | (*bi & !mask);
        }
        Fe { n }
    }

    fn is_zero_var(&self) -> bool {
        (self.n[0] | self.n[1] | self.n[2] | self.n[3]) == 0
    }

    pub fn normalize(&mut self) {
        *self = self.reduce_once();
    }
}

/// Reduce 512-bit product (8 LE u64 limbs) mod p using Solinas form:
/// `2^256 ≡ K (mod p)` where `K = 2^32 + 977 = 0x1_0000_03D1`.
///
/// Algorithm (independent of libsecp256k1 source; same math):
/// 1. Fold high half: `acc[i] = lo[i] + hi[i]*K` with 128-bit carries.
/// 2. Fold remaining overflow `ov * K` back into low limbs.
/// 3. At most a few conditional subtracts of `p` to bring into `[0, p)`.
fn reduce_512_simple(d: &[u64; 8]) -> Fe {
    const K: u128 = (1u128 << 32) + 977; // 0x1_0000_03D1
    const MASK: u128 = 0xffff_ffff_ffff_ffff;

    // Pass 1: a_i = w_i + w_{i+4} * K  (may produce carries into a fourth overflow)
    let mut a0 = d[0] as u128 + (d[4] as u128) * K;
    let mut a1 = d[1] as u128 + (d[5] as u128) * K;
    let mut a2 = d[2] as u128 + (d[6] as u128) * K;
    let mut a3 = d[3] as u128 + (d[7] as u128) * K;

    // Propagate carries a0 → a1 → a2 → a3 → ov
    a1 += a0 >> 64;
    a0 &= MASK;
    a2 += a1 >> 64;
    a1 &= MASK;
    a3 += a2 >> 64;
    a2 &= MASK;
    let mut ov = a3 >> 64;
    a3 &= MASK;

    // Pass 2: fold ov * K into low limbs (ov is small: ≤ ~2^64 for full 512-bit).
    // Always run a fixed number of iterations (worst-case bound); no early exit
    // on secret-derived overflow.
    for _ in 0..3 {
        let t0 = a0 + ov * K;
        a0 = t0 & MASK;
        let mut c = t0 >> 64;
        let t1 = a1 + c;
        a1 = t1 & MASK;
        c = t1 >> 64;
        let t2 = a2 + c;
        a2 = t2 & MASK;
        c = t2 >> 64;
        let t3 = a3 + c;
        a3 = t3 & MASK;
        ov = t3 >> 64;
    }

    let mut fe = Fe {
        n: [a0 as u64, a1 as u64, a2 as u64, a3 as u64],
    };
    // Final reduction into [0, p). Product of two <p elements is < p^2,
    // so after folds we are well below 4p; always pay for worst-case subtracts.
    for _ in 0..4 {
        let need = fe.ge_p();
        let subbed = fe.sub_p();
        fe = Fe::ct_select(need, &subbed, &fe);
    }
    fe
}

fn p_limbs() -> [u64; 4] {
    let mut n = [0u64; 4];
    for (i, ni) in n.iter_mut().enumerate() {
        let o = 24 - i * 8;
        *ni = u64::from_be_bytes([
            P_BE[o],
            P_BE[o + 1],
            P_BE[o + 2],
            P_BE[o + 3],
            P_BE[o + 4],
            P_BE[o + 5],
            P_BE[o + 6],
            P_BE[o + 7],
        ]);
    }
    n
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
    fn roundtrip_bytes() {
        let gx = [
            0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87,
            0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B,
            0x16, 0xF8, 0x17, 0x98,
        ];
        let a = Fe::from_bytes_be(&gx).unwrap();
        let mut out = [0u8; 32];
        a.to_bytes_be(&mut out);
        assert_eq!(out, gx);
        let a2 = a.mul(&a); // x^2
        let a3 = a2.mul(&a);
        let mut seven = [0u8; 32];
        seven[31] = 7;
        let s = Fe::from_bytes_be(&seven).unwrap();
        let rhs = a3.add(&s);
        let mut rb = [0u8; 32];
        rhs.to_bytes_be(&mut rb);
        // just ensure no panic
        assert_ne!(rb, [0u8; 32]);
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
    fn add_p_minus_one_plus_one() {
        // (p-1) + 1 should reduce to 0
        let mut bytes = P_BE;
        // p-1 in BE
        let mut i = 31;
        loop {
            if bytes[i] > 0 {
                bytes[i] -= 1;
                break;
            }
            bytes[i] = 0xff;
            if i == 0 {
                break;
            }
            i -= 1;
        }
        let pm1 = Fe::from_bytes_be(&bytes).unwrap();
        let r = pm1.add(&Fe::one());
        assert!(r.is_zero_var());
    }

    #[test]
    fn ge_p_matches_cmp_for_public() {
        let a = Fe::one();
        assert_eq!(a.ge_p(), 0);
        // value just below p
        let mut bytes = P_BE;
        bytes[31] -= 1;
        let pm1 = Fe::from_bytes_be(&bytes).unwrap();
        assert_eq!(pm1.ge_p(), 0);
    }
}
