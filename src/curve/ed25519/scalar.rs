//! Ed25519 scalar modulo L = 2^252 + 27742317777372353535851937790883648493.
//!
//! Representation: 8 × u32 little-endian limbs (limb 0 = least significant).
//! Arithmetic is structured for constant-time use on secret scalars.

use crate::ct::ct_eq;
use crate::curve::error::{CurveError, CurveResult};
use crate::curve::traits::Scalar as ScalarTrait;

/// Group order L (little-endian bytes).
pub const L_LE: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// 2^256 mod L (little-endian) = 2^256 - L.
const LAMBDA_LE: [u8; 32] = [
    0x1d, 0x95, 0x98, 0x8d, 0x74, 0x31, 0xec, 0xd6, 0x70, 0xcf, 0x7d, 0x73, 0xf4, 0x5b, 0xef, 0xc6,
    0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0f,
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

    /// Parse little-endian 32 bytes; reject if ≥ L.
    pub fn from_bytes_le(bytes: &[u8; 32]) -> CurveResult<Self> {
        let mut d = [0u32; 8];
        for (i, di) in d.iter_mut().enumerate() {
            let o = i * 4;
            *di = u32::from_le_bytes([bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]]);
        }
        let s = Self { d };
        if s.ct_gte_l() == 1 {
            return Err(CurveError::InvalidScalar);
        }
        Ok(s)
    }

    /// Parse LE 32 bytes and reduce mod L (always succeeds).
    pub fn from_bytes_mod_order(bytes: &[u8; 32]) -> Self {
        let mut d = [0u32; 8];
        for (i, di) in d.iter_mut().enumerate() {
            let o = i * 4;
            *di = u32::from_le_bytes([bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]]);
        }
        let mut s = Self { d };
        for _ in 0..16 {
            s = s.reduce_once();
        }
        s
    }

    /// Reduce 64-byte LE integer mod L (SHA-512 digest → scalar).
    ///
    /// Same as Monero / ref10 [`sc_reduce`] / `sc_reduce64`: 64-byte little-endian
    /// integer → canonical 32-byte scalar mod L.
    pub fn from_bytes_wide(bytes: &[u8; 64]) -> Self {
        let mut acc = [0u64; 64];
        for i in 0..64 {
            acc[i] = bytes[i] as u64;
        }
        reduce_64_bytes_mod_l(&acc)
    }

    /// Monero `sc_reduce32`: reduce a 32-byte little-endian integer modulo L.
    /// Always succeeds (unlike [`from_bytes_le`], which rejects ≥ L).
    #[inline]
    pub fn sc_reduce32(bytes: &[u8; 32]) -> Self {
        Self::from_bytes_mod_order(bytes)
    }

    /// Monero `sc_reduce` / `sc_reduce64`: reduce a 64-byte little-endian integer modulo L.
    #[inline]
    pub fn sc_reduce64(bytes: &[u8; 64]) -> Self {
        Self::from_bytes_wide(bytes)
    }

    /// Write reduced 32-byte LE encoding of [`sc_reduce64`].
    pub fn sc_reduce64_into(bytes: &[u8; 64], out: &mut [u8; 32]) {
        Self::sc_reduce64(bytes).to_bytes_le(out);
    }

    /// Write reduced 32-byte LE encoding of [`sc_reduce32`].
    pub fn sc_reduce32_into(bytes: &[u8; 32], out: &mut [u8; 32]) {
        Self::sc_reduce32(bytes).to_bytes_le(out);
    }

    /// Multiplicative inverse mod L via a^(L-2).
    /// Exponent is public; the square-and-multiply ladder is branchless
    /// (ct_select) so mul-skip timing never depends on the secret base.
    pub fn invert(&self) -> CurveResult<Self> {
        if self.is_zero() {
            return Err(CurveError::NotInvertible);
        }
        // L-2 LE
        let mut exp = L_LE;
        // subtract 2 from L
        let mut borrow = 2u32;
        for e in exp.iter_mut() {
            let v = *e as u32;
            let (d, b) = v.overflowing_sub(borrow);
            *e = d as u8;
            borrow = u32::from(b);
        }
        let mut base = *self;
        let mut result = Self::one();
        for byte in exp.iter() {
            for bit in 0..8 {
                let sq = base.mul(&base);
                let mulled = result.mul(&base);
                // NOTE: classic ladder is result=result.mul(base) on bit==1
                // then base=base.square(). Keep that schedule branchless:
                let bit_set = (byte >> bit) & 1;
                let new_result = Self::ct_select(bit_set, &mulled, &result);
                result = new_result;
                base = sq;
            }
        }
        Ok(result)
    }

    /// Ed25519 clamp: clear low 3 bits, clear high bit, set second-highest bit.
    pub fn clamp_ed25519(bytes: &mut [u8; 32]) {
        bytes[0] &= 248;
        bytes[31] &= 63;
        bytes[31] |= 64;
    }

    pub fn to_bytes_le(&self, out: &mut [u8; 32]) {
        for i in 0..8 {
            let o = i * 4;
            out[o..o + 4].copy_from_slice(&self.d[i].to_le_bytes());
        }
    }

    fn limbs_l() -> [u32; 8] {
        let mut d = [0u32; 8];
        for (i, di) in d.iter_mut().enumerate() {
            let o = i * 4;
            *di = u32::from_le_bytes([L_LE[o], L_LE[o + 1], L_LE[o + 2], L_LE[o + 3]]);
        }
        d
    }

    /// Constant-time compare ≥ L → 1 if ≥, 0 otherwise.
    /// Branchless flag accumulation (no `if` on secret limbs).
    fn ct_gte_l(&self) -> u8 {
        let l = Self::limbs_l();
        let mut gt = 0u8;
        let mut eq = 1u8;
        for i in (0..8).rev() {
            let a = self.d[i];
            let b = l[i];
            let a_gt_b = u8::from(a > b);
            let a_eq_b = u8::from(a == b);
            gt |= eq & a_gt_b;
            eq &= a_eq_b;
        }
        gt | eq
    }

    fn sub_l(&self) -> Self {
        let l = Self::limbs_l();
        let mut borrow = 0i64;
        let mut d = [0u32; 8];
        for i in 0..8 {
            let t = self.d[i] as i64 - l[i] as i64 - borrow;
            d[i] = t as u32;
            // Branchless borrow: 1 if t < 0 else 0 (arithmetic shift, no `if`).
            borrow = (t >> 63) & 1;
            // i64::from(t<0) compiles to setcc (branchless) but keep explicit
            // arithmetic form so the intent survives opt-level changes.
        }
        Self { d }
    }

    /// Conditional subtract L if ≥ L (branching on public reduction flag is avoided via select).
    fn reduce_once(&self) -> Self {
        let need = self.ct_gte_l();
        let subbed = self.sub_l();
        Self::ct_select(need, &subbed, self)
    }

    pub fn is_zero(&self) -> bool {
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
        let mut d = [0u32; 8];
        let mask = (choice as u32).wrapping_neg();
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
        // Always fold carry * λ (carry may be 0).
        let mut cbytes = [0u8; 32];
        cbytes[0] = carry as u8;
        let fold = mul_le_bytes_mod_l(&cbytes, &LAMBDA_LE);
        r = r.add_no_reduce(&fold);
        r.reduce_once().reduce_once()
    }

    fn add_no_reduce(&self, other: &Self) -> Self {
        let mut carry = 0u64;
        let mut d = [0u32; 8];
        for ((di, si), oi) in d.iter_mut().zip(self.d.iter()).zip(other.d.iter()) {
            let s = *si as u64 + *oi as u64 + carry;
            *di = s as u32;
            carry = s >> 32;
        }
        // ignore final carry for intermediate
        let _ = carry;
        Self { d }
    }

    pub fn neg(&self) -> Self {
        let l = Self::limbs_l();
        let mut borrow = 0i64;
        let mut d = [0u32; 8];
        for i in 0..8 {
            let t = l[i] as i64 - self.d[i] as i64 - borrow;
            d[i] = t as u32;
            borrow = (t >> 63) & 1;
        }
        let raw = Self { d };
        Self::ct_select(self.is_zero() as u8, &Self::zero(), &raw)
    }

    pub fn mul(&self, other: &Self) -> Self {
        // 8×8 → 16 u32 product (as u64 accum)
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
        // Normalize carries
        let mut c = 0u64;
        for a in acc.iter_mut() {
            let t = *a + c;
            *a = t & 0xffff_ffff;
            c = t >> 32;
        }

        let low = Self {
            d: [
                acc[0] as u32,
                acc[1] as u32,
                acc[2] as u32,
                acc[3] as u32,
                acc[4] as u32,
                acc[5] as u32,
                acc[6] as u32,
                acc[7] as u32,
            ],
        };
        let high = Self {
            d: [
                acc[8] as u32,
                acc[9] as u32,
                acc[10] as u32,
                acc[11] as u32,
                acc[12] as u32,
                acc[13] as u32,
                acc[14] as u32,
                acc[15] as u32,
            ],
        };

        // Pack full 512-bit product and reduce (fixed work).
        let mut bytes = [0u64; 64];
        for (i, &a) in acc.iter().enumerate() {
            let v = a as u32;
            let o = i * 4;
            let b = v.to_le_bytes();
            bytes[o] = b[0] as u64;
            bytes[o + 1] = b[1] as u64;
            bytes[o + 2] = b[2] as u64;
            bytes[o + 3] = b[3] as u64;
        }
        let _ = (low, high);
        reduce_64_bytes_mod_l(&bytes)
    }
}

/// Schoolbook 32×32 LE byte mul then reduce mod L (used for high*λ).
fn mul_le_bytes_mod_l(a: &[u8; 32], b: &[u8; 32]) -> Scalar {
    let mut acc = [0u64; 64];
    for i in 0..32 {
        let mut carry = 0u64;
        for j in 0..32 {
            let t = acc[i + j] + (a[i] as u64) * (b[j] as u64) + carry;
            acc[i + j] = t & 0xff;
            carry = t >> 8;
        }
        for ak in acc.iter_mut().skip(i + 32) {
            let t = *ak + carry;
            *ak = t & 0xff;
            carry = t >> 8;
        }
    }
    reduce_64_bytes_mod_l(&acc)
}

fn reduce_64_bytes_mod_l(acc: &[u64; 64]) -> Scalar {
    let mut limbs = [0u64; 8];
    for (i, li) in limbs.iter_mut().enumerate() {
        let o = i * 8;
        *li = u64::from_le_bytes([
            acc[o] as u8,
            acc[o + 1] as u8,
            acc[o + 2] as u8,
            acc[o + 3] as u8,
            acc[o + 4] as u8,
            acc[o + 5] as u8,
            acc[o + 6] as u8,
            acc[o + 7] as u8,
        ]);
    }
    let mut lam = [0u64; 4];
    for (i, li) in lam.iter_mut().enumerate() {
        let o = i * 8;
        *li = u64::from_le_bytes([
            LAMBDA_LE[o],
            LAMBDA_LE[o + 1],
            LAMBDA_LE[o + 2],
            LAMBDA_LE[o + 3],
            LAMBDA_LE[o + 4],
            LAMBDA_LE[o + 5],
            LAMBDA_LE[o + 6],
            LAMBDA_LE[o + 7],
        ]);
    }
    for _ in 0..96 {
        let lo = [limbs[0], limbs[1], limbs[2], limbs[3]];
        let hi = [limbs[4], limbs[5], limbs[6], limbs[7]];
        let mut prod = [0u128; 8];
        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 {
                let t = prod[i + j] + (hi[i] as u128) * (lam[j] as u128) + carry;
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
            let t = prod[i] + lo[i] as u128 + carry;
            prod[i] = t & 0xffff_ffff_ffff_ffff;
            carry = t >> 64;
        }
        for pr in prod.iter_mut().skip(4) {
            let t = *pr + carry;
            *pr = t & 0xffff_ffff_ffff_ffff;
            carry = t >> 64;
        }
        for i in 0..8 {
            limbs[i] = prod[i] as u64;
        }
    }
    let mut d = [0u32; 8];
    for i in 0..4 {
        let v = limbs[i];
        d[i * 2] = v as u32;
        d[i * 2 + 1] = (v >> 32) as u32;
    }
    let mut r = Scalar { d };
    for _ in 0..16 {
        r = r.reduce_once();
    }
    r
}

/// Non-`Copy` wrapper for private scalars (Ed25519 / Monero spend keys).
///
/// `Scalar` is `Copy` for arithmetic convenience; prefer this type for
/// long-lived secrets. Zeroizes limbs on `Drop` (best-effort, zero-dep).
#[derive(Clone, Debug)]
pub struct SecretScalar {
    inner: Scalar,
}

impl SecretScalar {
    /// Wrap an already-reduced scalar. Caller must ensure the value is secret.
    pub fn from_scalar(s: Scalar) -> Self {
        Self { inner: s }
    }

    /// Parse little-endian 32 bytes; reject if ≥ L or zero.
    pub fn from_bytes_le(bytes: &[u8; 32]) -> CurveResult<Self> {
        let s = Scalar::from_bytes_le(bytes)?;
        if s.is_zero() {
            return Err(CurveError::InvalidScalar);
        }
        Ok(Self { inner: s })
    }

    /// Parse 32 bytes (LE). Rejects invalid / zero scalars.
    pub fn from_bytes(bytes: &[u8]) -> CurveResult<Self> {
        if bytes.len() != 32 {
            return Err(CurveError::InvalidLength);
        }
        let mut b = [0u8; 32];
        b.copy_from_slice(bytes);
        Self::from_bytes_le(&b)
    }

    /// Borrow the underlying scalar for CT arithmetic (e.g. point mul).
    pub fn as_scalar(&self) -> &Scalar {
        &self.inner
    }

    /// Consume and return the scalar; caller is responsible for further wiping.
    pub fn into_scalar(mut self) -> Scalar {
        let s = self.inner;
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
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        self.inner.to_bytes_le(&mut a);
        other.inner.to_bytes_le(&mut b);
        crate::ct::ct_eq(&a, &b)
    }
}

impl Drop for SecretScalar {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

// Intentionally no Copy impl.

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
        // Trait uses LE for Ed25519 (wire format)
        Scalar::from_bytes_le(&b)
    }
    fn to_bytes(&self, out: &mut [u8]) -> CurveResult<()> {
        if out.len() != 32 {
            return Err(CurveError::InvalidLength);
        }
        let mut b = [0u8; 32];
        self.to_bytes_le(&mut b);
        out.copy_from_slice(&b);
        Ok(())
    }
    fn ct_eq(&self, other: &Self) -> u8 {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        self.to_bytes_le(&mut a);
        other.to_bytes_le(&mut b);
        ct_eq(&a, &b)
    }
    fn is_zero(&self) -> bool {
        Scalar::is_zero(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_plus_one() {
        let r = Scalar::one().add(&Scalar::one());
        let mut out = [0u8; 32];
        r.to_bytes_le(&mut out);
        assert_eq!(out[0], 2);
    }

    #[test]
    fn reject_l() {
        assert!(Scalar::from_bytes_le(&L_LE).is_err());
    }

    #[test]
    fn secret_scalar_rejects_zero() {
        let z = [0u8; 32];
        assert!(SecretScalar::from_bytes(&z).is_err());
    }

    #[test]
    fn secret_scalar_roundtrip() {
        let mut b = [0u8; 32];
        b[0] = 7;
        let sk = SecretScalar::from_bytes(&b).unwrap();
        let mut out = [0u8; 32];
        sk.as_scalar().to_bytes_le(&mut out);
        assert_eq!(out[0], 7);
        assert_eq!(sk.ct_eq(&SecretScalar::from_bytes(&b).unwrap()), 1);
    }

    #[test]
    fn mul_two_three() {
        let two = Scalar::one().add(&Scalar::one());
        let three = two.add(&Scalar::one());
        let six = two.mul(&three);
        let mut out = [0u8; 32];
        six.to_bytes_le(&mut out);
        assert_eq!(out[0], 6);
        for o in out.iter().skip(1) {
            assert_eq!(*o, 0);
        }
    }

    #[test]
    fn sc_reduce32_reduces_l_to_zero() {
        let s = Scalar::sc_reduce32(&L_LE);
        assert!(s.is_zero());
    }

    #[test]
    fn sc_reduce64_sha512_style() {
        let wide = [0xffu8; 64];
        let s = Scalar::sc_reduce64(&wide);
        let mut out = [0u8; 32];
        s.to_bytes_le(&mut out);
        assert_ne!(out, [0xffu8; 32]);
        assert!(Scalar::from_bytes_le(&out).is_ok());
        let mut out2 = [0u8; 32];
        Scalar::sc_reduce64_into(&wide, &mut out2);
        assert_eq!(out, out2);
    }

    #[test]
    fn sc_reduce64_low_half_matches_reduce32() {
        let mut wide = [0u8; 64];
        for (i, w) in wide.iter_mut().enumerate().take(32) {
            *w = (i * 7 + 3) as u8;
        }
        let a = Scalar::sc_reduce64(&wide);
        let mut lo = [0u8; 32];
        lo.copy_from_slice(&wide[..32]);
        let b = Scalar::sc_reduce32(&lo);
        let mut oa = [0u8; 32];
        let mut ob = [0u8; 32];
        a.to_bytes_le(&mut oa);
        b.to_bytes_le(&mut ob);
        assert_eq!(oa, ob);
    }
}
