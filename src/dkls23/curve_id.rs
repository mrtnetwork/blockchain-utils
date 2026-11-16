//! Curve abstraction for DKLs23: secp256k1 and secp256r1.
//!
//! Both curves expose 33-byte compressed points and 32-byte big-endian
//! scalars, so every codec layout in [`super::codec`] is curve-agnostic.
//! What varies is the group arithmetic and the group order (transcript
//! challenges and share math all reduce mod `q`).
//!
//! [`DklsScalar`] / [`DklsPoint`] dispatch to the crate's constant-time
//! backends. The [`CurveId`] discriminant is a public session parameter,
//! never secret material, so matching on it adds no secret-dependent
//! branch; each arm stays inside the CT backends.

use crate::curve::secp256k1::{Scalar as K1Scalar, Secp256k1Point as K1Point};
use crate::curve::secp256r1::{Scalar as R1Scalar, Secp256r1Point as R1Point};
use crate::curve::traits::CurvePoint;

/// Curve selector (public session parameter).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CurveId {
    /// secp256k1.
    K1 = 0,
    /// secp256r1 (NIST P-256).
    R1 = 1,
}

impl CurveId {
    /// Parse `0`/`1`; `None` otherwise.
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(CurveId::K1),
            1 => Some(CurveId::R1),
            _ => None,
        }
    }

    /// Group order, big-endian.
    pub fn order_be(self) -> [u8; 32] {
        match self {
            CurveId::K1 => K1_ORDER_BE,
            CurveId::R1 => R1_ORDER_BE,
        }
    }

    /// Human-readable curve name for transcripts and diagnostics.
    pub fn name(self) -> &'static str {
        match self {
            CurveId::K1 => "secp256k1",
            CurveId::R1 => "secp256r1",
        }
    }
}

/// secp256k1 group order (BE).
pub const K1_ORDER_BE: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

/// secp256r1 (P-256) group order (BE).
pub const R1_ORDER_BE: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
];

/// Curve scalar (k1 or r1). Zeroized on drop; not `Copy` so key
/// material is never silently duplicated.
#[derive(Clone, Debug)]
pub enum DklsScalar {
    /// secp256k1 scalar.
    K1(K1Scalar),
    /// secp256r1 scalar.
    R1(R1Scalar),
}

/// Curve point (k1 or r1).
#[derive(Clone, Debug)]
pub enum DklsPoint {
    /// secp256k1 point.
    K1(K1Point),
    /// secp256r1 point.
    R1(R1Point),
}

impl DklsScalar {
    /// Curve of this scalar.
    pub fn curve(&self) -> CurveId {
        match self {
            DklsScalar::K1(_) => CurveId::K1,
            DklsScalar::R1(_) => CurveId::R1,
        }
    }

    /// Zero.
    pub fn zero(curve: CurveId) -> Self {
        match curve {
            CurveId::K1 => DklsScalar::K1(K1Scalar::zero()),
            CurveId::R1 => DklsScalar::R1(R1Scalar::zero()),
        }
    }

    /// One.
    pub fn one(curve: CurveId) -> Self {
        match curve {
            CurveId::K1 => DklsScalar::K1(K1Scalar::one()),
            CurveId::R1 => DklsScalar::R1(R1Scalar::one()),
        }
    }

    /// Parse a canonical scalar (`< q`, 32 bytes BE).
    pub fn from_bytes_be(curve: CurveId, bytes: &[u8; 32]) -> Option<Self> {
        match curve {
            CurveId::K1 => K1Scalar::from_bytes_be(bytes).ok().map(DklsScalar::K1),
            CurveId::R1 => R1Scalar::from_bytes_be(bytes).ok().map(DklsScalar::R1),
        }
    }

    /// Reduce 32 bytes mod `q` (never rejects).
    pub fn from_bytes_mod_order(curve: CurveId, bytes: &[u8; 32]) -> Self {
        match curve {
            CurveId::K1 => DklsScalar::K1(K1Scalar::from_bytes_mod_order(bytes)),
            CurveId::R1 => DklsScalar::R1(R1Scalar::from_bytes_mod_order(bytes)),
        }
    }

    /// Canonical big-endian encoding.
    pub fn to_bytes_be(&self, out: &mut [u8; 32]) {
        match self {
            DklsScalar::K1(s) => {
                s.to_bytes_be(out);
            }
            DklsScalar::R1(s) => {
                s.to_bytes_be(out);
            }
        }
    }

    /// Convenience allocation-free encoding.
    pub fn to_array_be(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        self.to_bytes_be(&mut out);
        out
    }

    /// `self + rhs` mod `q` (same-curve only; mismatched curves panic
    /// instead of silently returning a wrong-curve value).
    pub fn add(&self, rhs: &Self) -> Self {
        match (self, rhs) {
            (DklsScalar::K1(a), DklsScalar::K1(b)) => DklsScalar::K1(a.add(b)),
            (DklsScalar::R1(a), DklsScalar::R1(b)) => DklsScalar::R1(a.add(b)),
            _ => panic!("dkls23: scalar curve mismatch in add"),
        }
    }

    /// `self - rhs` mod `q` (same-curve only, as above).
    pub fn sub(&self, rhs: &Self) -> Self {
        self.add(&rhs.neg())
    }

    /// `self * rhs` mod `q` (same-curve only; mismatched curves panic).
    pub fn mul(&self, rhs: &Self) -> Self {
        match (self, rhs) {
            (DklsScalar::K1(a), DklsScalar::K1(b)) => DklsScalar::K1(a.mul(b)),
            (DklsScalar::R1(a), DklsScalar::R1(b)) => DklsScalar::R1(a.mul(b)),
            _ => panic!("dkls23: scalar curve mismatch in mul"),
        }
    }

    /// `-self` mod `q`.
    pub fn neg(&self) -> Self {
        match self {
            DklsScalar::K1(a) => DklsScalar::K1(a.neg()),
            DklsScalar::R1(a) => DklsScalar::R1(a.neg()),
        }
    }

    /// Modular inverse (`None` for zero).
    pub fn invert(&self) -> Option<Self> {
        match self {
            DklsScalar::K1(a) => a.invert().ok().map(DklsScalar::K1),
            DklsScalar::R1(a) => a.invert().ok().map(DklsScalar::R1),
        }
    }

    /// Whether the scalar is zero.
    pub fn is_zero(&self) -> bool {
        match self {
            DklsScalar::K1(a) => a.is_zero(),
            DklsScalar::R1(a) => a.is_zero(),
        }
    }

    /// Constant-time equality (same-curve only; cross-curve is false).
    pub fn ct_eq(&self, other: &Self) -> u8 {
        use crate::curve::traits::Scalar as ScalarTrait;
        match (self, other) {
            (DklsScalar::K1(a), DklsScalar::K1(b)) => a.ct_eq(b),
            (DklsScalar::R1(a), DklsScalar::R1(b)) => a.ct_eq(b),
            _ => 0,
        }
    }

    /// Best-effort wipe (limbs only; the enum tag is public).
    pub fn zeroize(&mut self) {
        match self {
            DklsScalar::K1(a) => a.zeroize(),
            DklsScalar::R1(a) => a.zeroize(),
        }
    }
}

impl Drop for DklsScalar {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl DklsPoint {
    /// Curve of this point.
    pub fn curve(&self) -> CurveId {
        match self {
            DklsPoint::K1(_) => CurveId::K1,
            DklsPoint::R1(_) => CurveId::R1,
        }
    }

    /// Generator.
    pub fn generator(curve: CurveId) -> Self {
        match curve {
            CurveId::K1 => DklsPoint::K1(K1Point::generator()),
            CurveId::R1 => DklsPoint::R1(R1Point::generator()),
        }
    }

    /// Identity.
    pub fn identity(curve: CurveId) -> Self {
        match curve {
            CurveId::K1 => DklsPoint::K1(K1Point::identity()),
            CurveId::R1 => DklsPoint::R1(R1Point::identity()),
        }
    }

    /// Parse a point (compressed or uncompressed accepted; identity
    /// allowed here — callers reject it where forbidden).
    pub fn from_bytes(curve: CurveId, bytes: &[u8]) -> Option<Self> {
        match curve {
            CurveId::K1 => K1Point::from_bytes(bytes).ok().map(DklsPoint::K1),
            CurveId::R1 => R1Point::from_bytes(bytes).ok().map(DklsPoint::R1),
        }
    }

    /// Compressed encoding. Returns `false` when the backend cannot
    /// encode into the 33-byte slot.
    pub fn to_bytes_compressed(&self, out: &mut [u8; 33]) -> bool {
        match self {
            DklsPoint::K1(p) => p.to_bytes_compressed(&mut out[..]).is_ok(),
            DklsPoint::R1(p) => p.to_bytes_compressed(&mut out[..]).is_ok(),
        }
    }

    /// Compressed encoding as an owned array (`None` when unencodable).
    pub fn to_array_compressed(&self) -> Option<[u8; 33]> {
        let mut out = [0u8; 33];
        if self.to_bytes_compressed(&mut out) {
            Some(out)
        } else {
            None
        }
    }

    /// Point addition (same-curve only; mismatched curves panic instead
    /// of silently returning a wrong-curve value).
    pub fn add(&self, other: &Self) -> Self {
        match (self, other) {
            (DklsPoint::K1(a), DklsPoint::K1(b)) => DklsPoint::K1(a.add(b)),
            (DklsPoint::R1(a), DklsPoint::R1(b)) => DklsPoint::R1(a.add(b)),
            _ => panic!("dkls23: point curve mismatch in add"),
        }
    }

    /// Negation.
    pub fn neg(&self) -> Self {
        match self {
            DklsPoint::K1(a) => DklsPoint::K1(a.neg()),
            DklsPoint::R1(a) => DklsPoint::R1(a.neg()),
        }
    }

    /// Scalar multiplication, CT in the scalar (same-curve only;
    /// mismatched curves panic).
    pub fn mul(&self, scalar: &DklsScalar) -> Self {
        match (self, scalar) {
            (DklsPoint::K1(a), DklsScalar::K1(b)) => DklsPoint::K1(a.mul(b)),
            (DklsPoint::R1(a), DklsScalar::R1(b)) => DklsPoint::R1(a.mul(b)),
            _ => panic!("dkls23: point/scalar curve mismatch in mul"),
        }
    }

    /// Constant-time identity check (1 = identity).
    pub fn ct_is_identity(&self) -> u8 {
        match self {
            DklsPoint::K1(a) => a.ct_is_identity(),
            DklsPoint::R1(a) => a.ct_is_identity(),
        }
    }

    /// Affine x-coordinate (for ECDSA `r`). Rejects non-compressed
    /// prefixes (including any identity slot) via the prefix check.
    pub fn x_bytes(&self, out: &mut [u8; 32]) -> bool {
        let mut enc = [0u8; 33];
        if !self.to_bytes_compressed(&mut enc) {
            return false;
        }
        if enc[0] != 0x02 && enc[0] != 0x03 {
            return false;
        }
        out.copy_from_slice(&enc[1..33]);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn order_rejected_both_curves() {
        assert!(DklsScalar::from_bytes_be(CurveId::K1, &K1_ORDER_BE).is_none());
        assert!(DklsScalar::from_bytes_be(CurveId::R1, &R1_ORDER_BE).is_none());
    }

    #[test]
    fn add_mul_agree_both_curves() {
        for curve in [CurveId::K1, CurveId::R1] {
            let g = DklsPoint::generator(curve);
            let two = DklsScalar::one(curve).add(&DklsScalar::one(curve));
            let (mut a, mut b) = ([0u8; 33], [0u8; 33]);
            assert!(g.add(&g).to_bytes_compressed(&mut a));
            assert!(g.mul(&two).to_bytes_compressed(&mut b));
            assert_eq!(a, b);
        }
    }

    #[test]
    fn cross_curve_never_equal() {
        let a = DklsScalar::one(CurveId::K1);
        let b = DklsScalar::one(CurveId::R1);
        assert_eq!(a.ct_eq(&b), 0);
    }

    #[test]
    #[should_panic(expected = "curve mismatch")]
    fn cross_curve_scalar_add_panics() {
        let a = DklsScalar::one(CurveId::K1);
        let b = DklsScalar::one(CurveId::R1);
        let _ = a.add(&b);
    }

    #[test]
    #[should_panic(expected = "curve mismatch")]
    fn cross_curve_scalar_mul_panics() {
        let a = DklsScalar::one(CurveId::K1);
        let b = DklsScalar::one(CurveId::R1);
        let _ = a.mul(&b);
    }

    #[test]
    #[should_panic(expected = "curve mismatch")]
    fn cross_curve_point_add_panics() {
        let a = DklsPoint::generator(CurveId::K1);
        let b = DklsPoint::generator(CurveId::R1);
        let _ = a.add(&b);
    }

    #[test]
    #[should_panic(expected = "curve mismatch")]
    fn cross_curve_point_mul_panics() {
        let a = DklsPoint::generator(CurveId::K1);
        let b = DklsScalar::one(CurveId::R1);
        let _ = a.mul(&b);
    }
}
