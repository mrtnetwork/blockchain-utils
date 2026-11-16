//! NIST P-256 scalar mod n (constant-time where secrets are involved).

use crate::ct::ct_eq;
use crate::curve::error::{CurveError, CurveResult};
use crate::curve::traits::Scalar as ScalarTrait;

pub const N_BE: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

/// λ = 2^256 − n limbs LE.
const LAM: [u32; 8] = [
    0x039c_daaf,
    0x0c46_353d,
    0x58e8_617b,
    0x4319_0552,
    0x0000_0000,
    0x0000_0000,
    0xffff_ffff,
    0x0000_0000,
];

#[derive(Clone, Copy, Debug)]
pub struct Scalar {
    pub(crate) d: [u32; 8],
}

impl Scalar {
    pub const fn zero() -> Self {
        Self { d: [0; 8] }
    }
    pub const fn one() -> Self {
        Self {
            d: [1, 0, 0, 0, 0, 0, 0, 0],
        }
    }

    /// Best-effort wipe (type is `Copy`; call explicitly after use).
    #[inline(never)]
    pub fn zeroize(&mut self) {
        for limb in self.d.iter_mut() {
            *limb = 0;
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        core::hint::black_box(self.d);
    }

    pub fn from_bytes_be(bytes: &[u8; 32]) -> CurveResult<Self> {
        let mut d = [0u32; 8];
        for (i, di) in d.iter_mut().enumerate() {
            let o = 28 - i * 4;
            *di = u32::from_be_bytes([bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]]);
        }
        let s = Self { d };
        if s.ct_gte_n() == 1 {
            return Err(CurveError::InvalidScalar);
        }
        Ok(s)
    }

    /// Parse 32 BE bytes as integer mod n (never rejects; for RFC 6979 bits2int).
    pub fn from_bytes_mod_order(bytes: &[u8; 32]) -> Self {
        let mut d = [0u32; 8];
        for (i, di) in d.iter_mut().enumerate() {
            let o = 28 - i * 4;
            *di = u32::from_be_bytes([bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]]);
        }
        let s = Self { d };
        s.reduce_once().reduce_once()
    }

    pub fn to_bytes_be(&self, out: &mut [u8; 32]) {
        for i in 0..8 {
            let o = 28 - i * 4;
            out[o..o + 4].copy_from_slice(&self.d[i].to_be_bytes());
        }
    }

    fn limbs_n() -> [u32; 8] {
        let mut d = [0u32; 8];
        for (i, di) in d.iter_mut().enumerate() {
            let o = 28 - i * 4;
            *di = u32::from_be_bytes([N_BE[o], N_BE[o + 1], N_BE[o + 2], N_BE[o + 3]]);
        }
        d
    }

    fn ct_gte_n(&self) -> u8 {
        let n = Self::limbs_n();
        let mut gt = 0u8;
        let mut eq = 1u8;
        for i in (0..8).rev() {
            let a_gt = u8::from(self.d[i] > n[i]);
            let a_eq = u8::from(self.d[i] == n[i]);
            gt |= eq & a_gt;
            eq &= a_eq;
        }
        gt | eq
    }

    fn sub_n(&self) -> Self {
        let n = Self::limbs_n();
        let mut borrow = 0i64;
        let mut d = [0u32; 8];
        for i in 0..8 {
            let t = self.d[i] as i64 - n[i] as i64 - borrow;
            d[i] = t as u32;
            borrow = i64::from(t < 0);
        }
        Self { d }
    }

    fn reduce_once(&self) -> Self {
        let need = self.ct_gte_n();
        Self::ct_select(need, &self.sub_n(), self)
    }

    pub fn is_zero(&self) -> bool {
        // Fixed-cost OR of all limbs — no short-circuit via Iterator::all.
        self.d.iter().fold(0u32, |acc, &x| acc | x) == 0
    }

    pub fn bit(&self, i: usize) -> u8 {
        if i >= 256 {
            return 0;
        }
        ((self.d[i / 32] >> (i % 32)) & 1) as u8
    }

    pub fn ct_select(choice: u8, a: &Self, b: &Self) -> Self {
        let choice = core::hint::black_box(choice) & 1;
        let mask = (choice as u32).wrapping_neg();
        let mut d = [0u32; 8];
        for ((di, ai), bi) in d.iter_mut().zip(a.d.iter()).zip(b.d.iter()) {
            *di = (*ai & mask) | (*bi & !mask);
        }
        Self { d }
    }

    pub fn add(&self, other: &Self) -> Self {
        let mut carry = 0u64;
        let mut d = [0u32; 8];
        for ((di, si), oi) in d.iter_mut().zip(self.d.iter()).zip(other.d.iter()) {
            let s = *si as u64 + *oi as u64 + carry;
            *di = s as u32;
            carry = s >> 32;
        }
        let mut r = Self { d };
        // Always run λ-fold with fixed bound (extra may be 0 — still constant work).
        let mut extra = carry;
        for _ in 0..3 {
            let mut c5 = 0u64;
            for (rj, &lam) in r.d.iter_mut().zip(LAM.iter()) {
                let t = *rj as u64 + extra * (lam as u64) + c5;
                *rj = t as u32;
                c5 = t >> 32;
            }
            extra = c5;
        }
        r.reduce_once().reduce_once()
    }

    pub fn neg(&self) -> Self {
        let n = Self::limbs_n();
        let mut borrow = 0i64;
        let mut d = [0u32; 8];
        for i in 0..8 {
            let t = n[i] as i64 - self.d[i] as i64 - borrow;
            d[i] = t as u32;
            borrow = i64::from(t < 0);
        }
        let raw = Self { d };
        let zero_flag = self.is_zero() as u8;
        Self::ct_select(zero_flag, &Self::zero(), &raw)
    }

    pub fn mul(&self, other: &Self) -> Self {
        // Schoolbook product into 16 × u32 limbs stored as u64.
        let mut acc = [0u64; 16];
        for i in 0..8 {
            let mut carry = 0u64;
            for j in 0..8 {
                let t = acc[i + j] + (self.d[i] as u64) * (other.d[j] as u64) + carry;
                acc[i + j] = t & 0xffff_ffff;
                carry = t >> 32;
            }
            acc[i + 8] += carry;
        }
        // Propagate any residual
        let mut c = 0u64;
        for a in acc.iter_mut() {
            let t = *a + c;
            *a = t & 0xffff_ffff;
            c = t >> 32;
        }
        reduce_512_n(&acc)
    }

    /// Invert mod n via a^(n-2). Branches only on public exponent bits.
    pub fn invert(&self) -> CurveResult<Self> {
        if self.is_zero() {
            return Err(CurveError::NotInvertible);
        }
        let mut exp = N_BE;
        let mut borrow = 2u16;
        for i in (0..32).rev() {
            let v = exp[i] as u16;
            if v >= borrow {
                exp[i] = (v - borrow) as u8;
                borrow = 0;
            } else {
                exp[i] = (v + 256 - borrow) as u8;
                borrow = 1;
            }
        }
        let base = *self;
        let mut result = Self::one();
        for byte in exp.iter() {
            for bit in (0..8).rev() {
                result = result.mul(&result);
                let bit_set = (byte >> bit) & 1;
                let mulled = result.mul(&base);
                result = Self::ct_select(bit_set, &mulled, &result);
            }
        }
        Ok(result)
    }
}

fn reduce_512_n(acc: &[u64; 16]) -> Scalar {
    // Iteratively fold: (lo + hi * 2^256) ≡ (lo + hi * λ) (mod n)
    // until the value fits in 256 bits, then reduce_once into [0, n).
    let mut limbs = [0u64; 16];
    limbs.copy_from_slice(acc);

    for _ in 0..16 {
        // Split lo / hi (8 limbs each)
        let lo = [
            limbs[0] as u32,
            limbs[1] as u32,
            limbs[2] as u32,
            limbs[3] as u32,
            limbs[4] as u32,
            limbs[5] as u32,
            limbs[6] as u32,
            limbs[7] as u32,
        ];
        let hi = [
            limbs[8] as u32,
            limbs[9] as u32,
            limbs[10] as u32,
            limbs[11] as u32,
            limbs[12] as u32,
            limbs[13] as u32,
            limbs[14] as u32,
            limbs[15] as u32,
        ];
        // prod = hi * λ — fixed work (no secret-dependent skip).
        let mut prod = [0u64; 16];
        for i in 0..8 {
            let mut carry = 0u128;
            for j in 0..8 {
                let t = prod[i + j] as u128 + (hi[i] as u128) * (LAM[j] as u128) + carry;
                prod[i + j] = (t as u64) & 0xffff_ffff;
                carry = t >> 32;
            }
            // Fixed drain over public index range; always propagates
            // (possibly zero) carry so timing is secret-independent.
            for pr in prod.iter_mut().skip(i + 8) {
                let t = *pr as u128 + carry;
                *pr = (t as u64) & 0xffff_ffff;
                carry = t >> 32;
            }
        }
        // prod += lo
        let mut carry = 0u128;
        for i in 0..8 {
            let t = prod[i] as u128 + lo[i] as u128 + carry;
            prod[i] = (t as u64) & 0xffff_ffff;
            carry = t >> 32;
        }
        for pr in prod.iter_mut().skip(8) {
            let t = *pr as u128 + carry;
            *pr = (t as u64) & 0xffff_ffff;
            carry = t >> 32;
        }
        limbs = prod;
    }

    let mut out = [0u32; 8];
    for i in 0..8 {
        out[i] = limbs[i] as u32;
    }
    let mut r = Scalar { d: out };
    for _ in 0..16 {
        r = r.reduce_once();
    }
    r
}

impl ScalarTrait for Scalar {
    const BYTES: usize = 32;
    fn zero() -> Self {
        Scalar::zero()
    }
    fn one() -> Self {
        Scalar::one()
    }
    fn add(&self, rhs: &Self) -> Self {
        Scalar::add(self, rhs)
    }
    fn mul(&self, rhs: &Self) -> Self {
        Scalar::mul(self, rhs)
    }
    fn neg(&self) -> Self {
        Scalar::neg(self)
    }
    fn from_bytes(bytes: &[u8]) -> CurveResult<Self> {
        if bytes.len() != 32 {
            return Err(CurveError::InvalidLength);
        }
        let mut b = [0u8; 32];
        b.copy_from_slice(bytes);
        Scalar::from_bytes_be(&b)
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
        Scalar::is_zero(self)
    }
}

/// Non-`Copy` wrapper for private P-256 scalars (zeroizes on drop).
#[derive(Clone, Debug)]
pub struct SecretScalar {
    inner: Scalar,
}

impl SecretScalar {
    pub fn from_scalar(s: Scalar) -> Self {
        Self { inner: s }
    }
    pub fn from_bytes(bytes: &[u8]) -> CurveResult<Self> {
        if bytes.len() != 32 {
            return Err(CurveError::InvalidLength);
        }
        let mut b = [0u8; 32];
        b.copy_from_slice(bytes);
        let s = Scalar::from_bytes_be(&b)?;
        if s.is_zero() {
            return Err(CurveError::InvalidScalar);
        }
        Ok(Self { inner: s })
    }
    pub fn as_scalar(&self) -> &Scalar {
        &self.inner
    }
    pub fn zeroize(&mut self) {
        // best-effort wipe
        for limb in self.inner.d.iter_mut() {
            *limb = 0;
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        core::hint::black_box(self.inner.d);
    }
}

impl Drop for SecretScalar {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn one_plus_one() {
        let r = Scalar::one().add(&Scalar::one());
        let mut out = [0u8; 32];
        r.to_bytes_be(&mut out);
        assert_eq!(out[31], 2);
    }

    #[test]
    fn neg_one_is_nm1() {
        let nm1 = Scalar::one().neg();
        let mut out = [0u8; 32];
        nm1.to_bytes_be(&mut out);
        // n-1 BE
        let n = N_BE;
        let mut expect = n;
        // subtract 1
        let mut i = 31;
        loop {
            if expect[i] > 0 {
                expect[i] -= 1;
                break;
            }
            expect[i] = 0xff;
            i -= 1;
        }
        assert_eq!(out, expect, "neg(1) limbs");
    }

    #[test]
    fn mul_nm1_nm1() {
        let nm1 = Scalar::one().neg();
        let r = nm1.mul(&nm1);
        let mut out = [0u8; 32];
        r.to_bytes_be(&mut out);
        assert_eq!(out[31], 1, " (n-1)^2 != 1, got {:?}", out);
        for o in out.iter().take(31) {
            assert_eq!(*o, 0);
        }
    }

    #[test]
    fn reject_n() {
        assert!(Scalar::from_bytes_be(&N_BE).is_err());
    }

    #[test]
    fn mul_two_three() {
        let two = Scalar::one().add(&Scalar::one());
        let three = two.add(&Scalar::one());
        let six = two.mul(&three);
        let mut out = [0u8; 32];
        six.to_bytes_be(&mut out);
        assert_eq!(out[31], 6);
    }
}
