//! secp256k1 scalar (mod n), fully constant-time for secret values.
//!
//! Representation: 8 × u32 little-endian limbs.
//! Reduction uses 2^256 ≡ λ (mod n) where λ = 2^256 − n.

use crate::ct::ct_eq;
use crate::curve::error::{CurveError, CurveResult};
use crate::curve::traits::Scalar as ScalarTrait;

/// Group order n (big-endian).
pub const N_BE: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

/// λ = 2^256 − n limbs little-endian (λ fits in 5 × u32).
const LAM: [u32; 8] = [
    0x2fc9_bebf,
    0x402d_a173,
    0x50b7_5fc4,
    0x4551_2319,
    0x0000_0001,
    0,
    0,
    0,
];

/// Scalar as 8 × 32-bit limbs, little-endian (limb 0 = least significant).
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

    /// Best-effort wipe of limb storage (Scalar is `Copy` — prefer this over relying on Drop).
    #[inline(never)]
    pub fn zeroize(&mut self) {
        for limb in self.d.iter_mut() {
            *limb = 0;
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        core::hint::black_box(self.d);
    }

    pub fn from_bytes(bytes: &[u8]) -> CurveResult<Self> {
        if bytes.len() != 32 {
            return Err(CurveError::InvalidLength);
        }
        let mut b = [0u8; 32];
        b.copy_from_slice(bytes);
        Self::from_bytes_be(&b)
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

    /// Interpret 32 bytes as a big-endian integer and reduce modulo n (BIP-340 style).
    /// Always succeeds; result is in `[0, n)`.
    pub fn from_bytes_mod_order(bytes: &[u8; 32]) -> Self {
        let mut d = [0u32; 8];
        for (i, di) in d.iter_mut().enumerate() {
            let o = 28 - i * 4;
            *di = u32::from_be_bytes([bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]]);
        }
        let mut s = Self { d };
        // value < 2^256 < 2n, so at most one subtraction of n is needed; run a few for safety
        s = s.reduce_once();
        s = s.reduce_once();
        s
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
            let a = self.d[i];
            let b = n[i];
            let a_gt = u8::from(a > b);
            let a_eq = u8::from(a == b);
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
        let subbed = self.sub_n();
        Self::ct_select(need, &subbed, self)
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
        // Always fold carry*λ with fixed bound (carry may be 0).
        let mut c4 = carry;
        let mut out = r.d;
        for _ in 0..3 {
            let mut c5 = 0u64;
            for j in 0..8 {
                let t = out[j] as u64 + c4 * (LAM[j] as u64) + c5;
                out[j] = t as u32;
                c5 = t >> 32;
            }
            c4 = c5;
        }
        r = Self { d: out };
        r.reduce_once().reduce_once()
    }

    pub fn neg(&self) -> Self {
        // Always compute n - self; when self == 0 this yields n, then select zero.
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
        let mut c = 0u64;
        for a in acc.iter_mut() {
            let t = *a + c;
            *a = t & 0xffff_ffff;
            c = t >> 32;
        }
        reduce_512(&acc)
    }

    /// Invert mod n via a^(n-2).
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
                // Public exponent: branch would be OK value-wise, but use
                // ct_select for uniformity so the shape never depends on
                // a secret `base`/`result` via mul-skip timing.
                let sq = result.mul(&result);
                let bit_set = (byte >> bit) & 1;
                let mulled = sq.mul(&base);
                result = Self::ct_select(bit_set, &mulled, &sq);
            }
        }
        Ok(result)
    }
}

fn reduce_512(acc: &[u64; 16]) -> Scalar {
    // low + high * λ — fixed work, no secret-dependent skips.
    // Every (i,j) MAC always executes; carry drains are fixed-length
    // (trip count depends only on public loop index `i`, never on `carry`).
    let mut prod = [0u64; 16];
    for i in 0..8 {
        let mut carry = 0u64;
        for j in 0..8 {
            let t = prod[i + j] + (acc[8 + i]) * (LAM[j] as u64) + carry;
            prod[i + j] = t & 0xffff_ffff;
            carry = t >> 32;
        }
        // Fixed drain: always walk k = i+8..16, propagating (possibly zero) carry.
        for pr in prod.iter_mut().skip(i + 8) {
            let t = *pr + carry;
            *pr = t & 0xffff_ffff;
            carry = t >> 32;
        }
    }
    // + low
    let mut carry = 0u64;
    for i in 0..8 {
        let t = prod[i] + acc[i] + carry;
        prod[i] = t & 0xffff_ffff;
        carry = t >> 32;
    }
    for pr in prod.iter_mut().skip(8) {
        let t = *pr + carry;
        *pr = t & 0xffff_ffff;
        carry = t >> 32;
    }

    // Second fold of remaining high limbs.
    // prod2 sized 16 (not 12): hi(8 limbs) * λ(8 limbs) needs up to 15.
    // (Old 12-limb version relied on secret-dependent skips of zero LAM
    // limbs to avoid OOB; fixed version always executes, so size correctly.)
    let mut prod2 = [0u64; 16];
    for i in 0..8 {
        let mut c2 = 0u64;
        for j in 0..8 {
            let t = prod2[i + j] + prod[8 + i] * (LAM[j] as u64) + c2;
            prod2[i + j] = t & 0xffff_ffff;
            c2 = t >> 32;
        }
        for pr in prod2.iter_mut().skip(i + 8) {
            let t = *pr + c2;
            *pr = t & 0xffff_ffff;
            c2 = t >> 32;
            // Keep propagating even when c2 becomes zero: fixed trip count.
        }
    }

    let mut c3 = 0u64;
    let mut out = [0u32; 8];
    for i in 0..8 {
        let t = prod[i] + prod2[i] + c3;
        out[i] = (t & 0xffff_ffff) as u32;
        c3 = t >> 32;
    }
    // residual from prod2[8..] + c3 — fixed 8 folds, always executed
    // (folding a zero `extra` is a no-op value-wise, constant time-wise).
    // u128 arithmetic: extra can exceed 2^32 when summing 8 limbs.
    let mut extra: u128 = c3 as u128;
    for pr in prod2.iter().skip(8) {
        extra += *pr as u128;
    }
    for _ in 0..8 {
        let mut c5: u128 = 0;
        for j in 0..8 {
            let t = out[j] as u128 + extra * (LAM[j] as u128) + c5;
            out[j] = (t & 0xffff_ffff) as u32;
            c5 = t >> 32;
        }
        extra = c5;
    }

    let mut r = Scalar { d: out };
    r = r.reduce_once();
    r.reduce_once()
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

/// Non-`Copy` wrapper for private scalars.
///
/// `Scalar` is `Copy` for arithmetic convenience; that means secret material
/// can be silently duplicated on the stack. Prefer this type for long-lived
/// private keys: it zeroizes limbs on drop and is not accidentally copied.
///
/// # Zeroization note
///
/// Without the external `zeroize` crate (this crate is zero-dependency),
/// zeroization uses the same best-effort pattern as `Scalar::zeroize`
/// (write zeros + compiler fence + `black_box`). On platforms where you
/// need stronger guarantees, call `into_scalar` and manage a secure buffer
/// yourself, or audit assembly under your target optimization level.
#[derive(Clone, Debug)]
pub struct SecretScalar {
    inner: Scalar,
}

impl SecretScalar {
    /// Create from a reduced scalar. Caller must ensure the value is secret.
    pub fn from_scalar(s: Scalar) -> Self {
        Self { inner: s }
    }

    /// Parse 32 big-endian bytes; reject if ≥ n or zero (invalid private key).
    pub fn from_bytes(bytes: &[u8]) -> CurveResult<Self> {
        let s = Scalar::from_bytes(bytes)?;
        if s.is_zero() {
            return Err(CurveError::InvalidScalar);
        }
        Ok(Self { inner: s })
    }

    /// Borrow the underlying scalar for CT arithmetic (e.g. point mul).
    pub fn as_scalar(&self) -> &Scalar {
        &self.inner
    }

    /// Consume and return the scalar; caller is responsible for further wiping.
    pub fn into_scalar(mut self) -> Scalar {
        let s = self.inner;
        // Zero our copy before forget, so Drop doesn't double-zero a moved value.
        self.inner.zeroize();
        core::mem::forget(self);
        s
    }

    /// Explicit wipe (also done on Drop).
    pub fn zeroize(&mut self) {
        self.inner.zeroize();
    }

    /// Constant-time equality of secret scalars.
    pub fn ct_eq(&self, other: &Self) -> u8 {
        self.inner.ct_eq(&other.inner)
    }
}

impl Drop for SecretScalar {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

// Intentionally no Copy impl.

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
        for o in out.iter().take(31) {
            assert_eq!(*o, 0);
        }
    }

    #[test]
    fn mul_n_minus_one() {
        let nm1 = Scalar::one().neg();
        let r = nm1.mul(&nm1);
        let mut out = [0u8; 32];
        r.to_bytes_be(&mut out);
        assert_eq!(out[31], 1);
        for o in out.iter().take(31) {
            assert_eq!(*o, 0);
        }
    }

    #[test]
    fn secret_scalar_rejects_zero() {
        let z = [0u8; 32];
        assert!(SecretScalar::from_bytes(&z).is_err());
    }

    #[test]
    fn secret_scalar_roundtrip_and_drop() {
        let mut b = [0u8; 32];
        b[31] = 5;
        let sk = SecretScalar::from_bytes(&b).unwrap();
        assert!(!sk.as_scalar().is_zero());
        let mut out = [0u8; 32];
        sk.as_scalar().to_bytes_be(&mut out);
        assert_eq!(out[31], 5);
        drop(sk);
    }

    #[test]
    fn neg_zero_is_zero() {
        let z = Scalar::zero();
        let n = z.neg();
        assert!(n.is_zero());
    }

    #[test]
    fn edge_n_minus_one_add_one() {
        let nm1 = Scalar::one().neg();
        let r = nm1.add(&Scalar::one());
        assert!(r.is_zero());
    }
}
