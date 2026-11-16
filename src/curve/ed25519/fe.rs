//! Ed25519 field element mod p = 2^255 − 19.
//!
//! Internal form: 4 × `u64` little-endian limbs, reduced to `[0, 2p)`.
//! Constant-time selection; hot-path arithmetic avoids secret branches.
//! Informed by ref10 / Monero crypto_ops math (independent implementation).

use crate::ct::ct_eq;
use crate::curve::error::{CurveError, CurveResult};
use crate::curve::traits::FieldElement;

/// p = 2^255 − 19 (big-endian).
pub const P_BE: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xed,
];

/// Field element (limbs private to this module via crate visibility).
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

    /// Parse 32-byte little-endian field element (Ed25519 convention).
    pub fn from_bytes_le(bytes: &[u8; 32]) -> CurveResult<Self> {
        let mut n = [0u64; 4];
        for (i, ni) in n.iter_mut().enumerate() {
            let o = i * 8;
            *ni = u64::from_le_bytes([
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
        // Clear top bit (canonical Ed25519 encoding ignores bit 255)
        n[3] &= 0x7fff_ffff_ffff_ffff;
        let fe = Self { n };
        Ok(fe.reduce())
    }

    /// Parse 32-byte little-endian field element, rejecting non-canonical
    /// encodings (value >= p). Used by point decoders (RFC 8032 parity with
    /// the decoder and every other curve in this crate). X25519 and
    /// Monero paths keep the wrapping [`from_bytes_le`]/[`from_bytes_full`].
    pub fn from_bytes_canonical(bytes: &[u8; 32]) -> CurveResult<Self> {
        let mut n = [0u64; 4];
        for (i, ni) in n.iter_mut().enumerate() {
            let o = i * 8;
            *ni = u64::from_le_bytes([
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
        // Clear top bit (canonical Ed25519 encoding ignores bit 255)
        n[3] &= 0x7fff_ffff_ffff_ffff;
        let fe = Self { n };
        if fe.ge_p() != 0 {
            return Err(CurveError::InvalidEncoding);
        }
        Ok(fe.reduce())
    }

    /// Parse full 32 bytes as a field element (top bit folded in, then
    /// reduced mod p). Matches Monero `fe_frombytes` as used by
    /// `ge_fromfe_frombytes` (hash-to-point feeds arbitrary digests whose
    /// top bit must NOT be cleared).
    pub fn from_bytes_full(bytes: &[u8; 32]) -> Self {
        let mut n = [0u64; 4];
        for (i, ni) in n.iter_mut().enumerate() {
            let o = i * 8;
            *ni = u64::from_le_bytes([
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
        Self { n }.reduce()
    }

    pub fn to_bytes_le(&self, out: &mut [u8; 32]) {
        let r = self.reduce();
        for i in 0..4 {
            let o = i * 8;
            out[o..o + 8].copy_from_slice(&r.n[i].to_le_bytes());
        }
    }

    fn limbs_p() -> [u64; 4] {
        // 2^255 - 19 in LE limbs
        [
            0xffff_ffff_ffff_ffed,
            0xffff_ffff_ffff_ffff,
            0xffff_ffff_ffff_ffff,
            0x7fff_ffff_ffff_ffff,
        ]
    }

    /// Constant-time: 1 if self >= p, else 0.
    fn ge_p(&self) -> u8 {
        let p = Self::limbs_p();
        let mut gt = 0u8;
        let mut eq = 1u8;
        for i in (0..4).rev() {
            let a = self.n[i];
            let b = p[i];
            gt |= eq & u8::from(a > b);
            eq &= u8::from(a == b);
        }
        gt | eq
    }

    fn sub_p(&self) -> Self {
        let p = Self::limbs_p();
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

    /// Fully reduce into [0, p). Constant-time fixed work.
    pub fn reduce(&self) -> Self {
        let mut r = *self;
        // Always fold top bit * 19 (top is 0 or 1; folding 0 is a no-op).
        let top = (r.n[3] >> 63) as u8;
        r.n[3] &= 0x7fff_ffff_ffff_ffff;
        let t = r.n[0] as u128 + (top as u128) * 19;
        r.n[0] = t as u64;
        let mut c = t >> 64;
        for i in 1..4 {
            let t = r.n[i] as u128 + c;
            r.n[i] = t as u64;
            c = t >> 64;
        }
        // Fixed 3 conditional subtracts of p — no early break.
        for _ in 0..3 {
            let need = r.ge_p();
            let subbed = r.sub_p();
            r = Fe::ct_select(need, &subbed, &r);
        }
        r
    }

    pub fn is_odd(&self) -> u8 {
        (self.reduce().n[0] & 1) as u8
    }

    /// RFC 9496 IS_NEGATIVE: least significant bit of the canonical encoding.
    pub fn is_negative(&self) -> u8 {
        self.is_odd()
    }

    /// Absolute value: negate if negative.
    pub fn abs(&self) -> Fe {
        let neg = self.negate();
        Fe::ct_select(self.is_negative(), &neg, self)
    }

    pub fn add(&self, other: &Fe) -> Fe {
        let mut carry = 0u64;
        let mut n = [0u64; 4];
        for ((ni, si), oi) in n.iter_mut().zip(self.n.iter()).zip(other.n.iter()) {
            let t = *si as u128 + *oi as u128 + carry as u128;
            *ni = t as u64;
            carry = (t >> 64) as u64;
        }
        // Always fold carry * 19 (carry may be 0).
        let mut r = Self { n };
        let t = r.n[0] as u128 + carry as u128 * 19;
        r.n[0] = t as u64;
        let mut c = t >> 64;
        for i in 1..4 {
            let t = r.n[i] as u128 + c;
            r.n[i] = t as u64;
            c = t >> 64;
        }
        r.reduce()
    }

    pub fn negate(&self) -> Fe {
        let p = Self::limbs_p();
        let mut borrow = 0u64;
        let mut n = [0u64; 4];
        for i in 0..4 {
            let (d1, b1) = p[i].overflowing_sub(self.n[i]);
            let (d2, b2) = d1.overflowing_sub(borrow);
            n[i] = d2;
            borrow = u64::from(b1 | b2);
        }
        let raw = Self { n }.reduce();
        let zero_flag = self.is_zero_var() as u8;
        Fe::ct_select(zero_flag, &Fe::zero(), &raw)
    }

    pub fn sub(&self, other: &Fe) -> Fe {
        self.add(&other.negate())
    }

    pub fn mul(&self, other: &Fe) -> Fe {
        // Fully reduce operands so limbs are in [0, p)
        let a = self.reduce();
        let b = other.reduce();
        let mut prod = [0u64; 8];
        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 {
                let t = prod[i + j] as u128 + a.n[i] as u128 * b.n[j] as u128 + carry;
                prod[i + j] = t as u64;
                carry = t >> 64;
            }
            for pr in prod.iter_mut().skip(i + 4) {
                let t = *pr as u128 + carry;
                *pr = t as u64;
                carry = t >> 64;
            }
        }
        reduce_512_ed(&prod)
    }

    pub fn square(&self) -> Fe {
        self.mul(self)
    }

    pub fn invert(&self) -> CurveResult<Fe> {
        if self.is_zero_var() {
            return Err(CurveError::NotInvertible);
        }
        // a^(p-2) mod p; p-2 = 2^255 - 21
        let exp: [u8; 32] = [
            0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xeb,
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
        let r = self.reduce();
        (r.n[0] | r.n[1] | r.n[2] | r.n[3]) == 0
    }
}

/// Reduce 512-bit product mod 2^255−19.
/// 2^256 ≡ 38 (mod p) because 2^255 ≡ 19 ⇒ 2^256 ≡ 38.
fn reduce_512_ed(d: &[u64; 8]) -> Fe {
    // lo + hi * 2^256 ≡ lo + hi * 38 (mod 2^255-19)
    let mut r = [0u128; 4];
    let mut carry = 0u128;
    for i in 0..4 {
        let t = d[i] as u128 + (d[i + 4] as u128) * 38 + carry;
        r[i] = t & 0xffff_ffff_ffff_ffff;
        carry = t >> 64;
    }
    // Fixed-bound carry folds (worst-case residual is tiny after 38-fold).
    for _ in 0..4 {
        let t0 = r[0] + carry * 38;
        r[0] = t0 & 0xffff_ffff_ffff_ffff;
        carry = t0 >> 64;
        for rj in r.iter_mut().skip(1) {
            let ti = *rj + carry;
            *rj = ti & 0xffff_ffff_ffff_ffff;
            carry = ti >> 64;
        }
    }
    let mut fe = Fe {
        n: [r[0] as u64, r[1] as u64, r[2] as u64, r[3] as u64],
    };
    fe = fe.reduce();
    fe = fe.reduce();
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
        // Accept BE for trait consistency; Ed25519 wire format is LE via from_bytes_le
        // For FieldElement trait we use BE like secp; point layer uses LE.
        let mut le = [0u8; 32];
        for i in 0..32 {
            le[i] = b[31 - i];
        }
        Fe::from_bytes_le(&le)
    }
    fn to_bytes(&self, out: &mut [u8]) -> CurveResult<()> {
        if out.len() != 32 {
            return Err(CurveError::InvalidLength);
        }
        let mut le = [0u8; 32];
        self.to_bytes_le(&mut le);
        for i in 0..32 {
            out[i] = le[31 - i];
        }
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
        r.to_bytes_le(&mut out);
        assert_eq!(out[0], 2);
    }

    #[test]
    fn mul_two_three() {
        let two = Fe::one().add(&Fe::one());
        let three = two.add(&Fe::one());
        let six = two.mul(&three);
        let mut out = [0u8; 32];
        six.to_bytes_le(&mut out);
        assert_eq!(out[0], 6);
    }

    #[test]
    fn inv_roundtrip() {
        let mut bytes = [0u8; 32];
        bytes[0] = 7;
        let a = Fe::from_bytes_le(&bytes).unwrap();
        let inv = a.invert().unwrap();
        let one = a.mul(&inv);
        let mut out = [0u8; 32];
        one.to_bytes_le(&mut out);
        assert_eq!(out[0], 1);
        for o in out.iter().skip(1) {
            assert_eq!(*o, 0);
        }
    }
}
