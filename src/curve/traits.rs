//! Shared traits for prime fields, scalars, and curve points.
//!
//! One **interface**, many concrete types. Limb layout stays private to each
//! curve implementation. Constant-time behavior is required for secret data
//! (especially scalar multiplication).

use super::error::CurveResult;

/// Element of a prime field (curve coordinate field).
///
/// Implementations must not branch on secret field values in arithmetic used
/// on the secret path (e.g. during scalar multiplication).
pub trait FieldElement: Sized + Clone {
    /// Byte length of a canonical encoding.
    const BYTES: usize;

    /// Additive identity.
    fn zero() -> Self;
    /// Multiplicative identity.
    fn one() -> Self;

    /// `self + rhs`.
    fn add(&self, rhs: &Self) -> Self;
    /// `self - rhs`.
    fn sub(&self, rhs: &Self) -> Self;
    /// `-self`.
    fn neg(&self) -> Self;
    /// `self * rhs`.
    fn mul(&self, rhs: &Self) -> Self;
    /// `self * self`.
    fn square(&self) -> Self;

    /// Multiplicative inverse. Returns error if `self` is zero.
    fn invert(&self) -> CurveResult<Self>;

    /// Parse a canonical big-endian field element.
    fn from_bytes(bytes: &[u8]) -> CurveResult<Self>;
    /// Write a canonical big-endian encoding into `out` (length `BYTES`).
    fn to_bytes(&self, out: &mut [u8]) -> CurveResult<()>;

    /// Constant-time equality (1 = equal, 0 = not). Prefer this over `==` for secrets.
    fn ct_eq(&self, other: &Self) -> u8;

    /// True if this is the zero element (may be non-CT on public values).
    fn is_zero(&self) -> bool;
}

/// Scalar for a curve group (integer mod the group order `n`).
pub trait Scalar: Sized + Clone {
    /// Byte length of a canonical encoding.
    const BYTES: usize;

    /// Zero scalar.
    fn zero() -> Self;
    /// One scalar.
    fn one() -> Self;

    /// `self + rhs` mod n.
    fn add(&self, rhs: &Self) -> Self;
    /// `self * rhs` mod n.
    fn mul(&self, rhs: &Self) -> Self;
    /// `-self` mod n.
    fn neg(&self) -> Self;

    /// Parse big-endian scalar; reject if ≥ n (strict).
    fn from_bytes(bytes: &[u8]) -> CurveResult<Self>;
    /// Write big-endian encoding into `out`.
    fn to_bytes(&self, out: &mut [u8]) -> CurveResult<()>;

    /// Constant-time equality.
    fn ct_eq(&self, other: &Self) -> u8;
    /// Whether scalar is zero.
    fn is_zero(&self) -> bool;
}

/// Point on an elliptic curve group.
///
/// Scalar multiplication **must** be constant-time with respect to the scalar
/// when the scalar is secret.
pub trait CurvePoint: Sized + Clone {
    /// Associated scalar type.
    type Scalar: Scalar;
    /// Compressed encoding size (e.g. 33 for secp256k1).
    const COMPRESSED_BYTES: usize;
    /// Uncompressed encoding size (e.g. 65 for secp256k1).
    const UNCOMPRESSED_BYTES: usize;

    /// Identity / point at infinity.
    fn identity() -> Self;
    /// Constant-time check for identity (1 = identity).
    fn ct_is_identity(&self) -> u8;
    /// Non-CT convenience.
    fn is_identity(&self) -> bool {
        self.ct_is_identity() == 1
    }

    /// Point doubling.
    fn double(&self) -> Self;
    /// Point addition.
    fn add(&self, other: &Self) -> Self;
    /// Negation.
    fn neg(&self) -> Self;

    /// Variable-base scalar multiplication (constant-time in the scalar).
    fn mul(&self, scalar: &Self::Scalar) -> Self;

    /// Decode from compressed or uncompressed SEC1-style bytes.
    fn from_bytes(bytes: &[u8]) -> CurveResult<Self>;
    /// Encode compressed into `out` (length `COMPRESSED_BYTES`).
    fn to_bytes_compressed(&self, out: &mut [u8]) -> CurveResult<()>;
    /// Encode uncompressed into `out` (length `UNCOMPRESSED_BYTES`).
    fn to_bytes_uncompressed(&self, out: &mut [u8]) -> CurveResult<()>;
}
