//! Monero RingCT helpers: Bulletproofs+ (prove + verify).
//!
//! Pure `no_std` + `alloc` port of the Monero reference implementation
//! `BulletproofsPlusGenerator` logic (itself adapted from the Monero
//! Project C++ `bulletproofs_plus` implementation).
//!
//! [`bulletproofs_plus::bp_plus_verify`] verifies a batch of proofs;
//! [`bulletproofs_plus::bp_plus_prove_amounts`] proves `v = sum 2^i`
//! commitments for amounts with the given gamma masks.
//!
//! Randomness for proving comes from a caller-supplied 32-byte seed
//! driving a local ChaCha20 stream (deterministic per seed; pass fresh
//! randomness per proof in production).

#![cfg(feature = "monero")]

pub mod bulletproofs_plus;
pub mod multiexp;
pub mod scan;

use crate::curve::ed25519::monero as ed_mono;
use crate::curve::ed25519::{Ed25519Point, Scalar};
use crate::curve::traits::CurvePoint;
use crate::curve::CurveError;
use crate::hash::keccak;
use crate::hash::HashError;
use crate::rng::ChaCha20Rng;
use alloc::vec::Vec;

/// Fixed-size helpers.
pub type S32 = [u8; 32];

/// Errors for the Monero module.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MoneroError {
    /// Input has the wrong length.
    InvalidLength,
    /// Point failed to decode / is invalid.
    InvalidPoint,
    /// Scalar is not canonical / out of range.
    InvalidScalar,
    /// Proof structure / size is invalid.
    InvalidProof,
    /// Inversion of zero was attempted.
    ZeroScalar,
    /// Fiat-Shamir challenge came out zero (prover must retry).
    ZeroChallenge,
    /// RNG output reduced to zero (prover must redraw).
    ZeroRandom,
    /// Hash failure (should not happen).
    HashFailed,
}

impl From<CurveError> for MoneroError {
    fn from(_: CurveError) -> Self {
        MoneroError::InvalidPoint
    }
}

impl From<HashError> for MoneroError {
    fn from(_: HashError) -> Self {
        MoneroError::HashFailed
    }
}

/// Result alias for the Monero module.
pub type MoneroResult<T> = core::result::Result<T, MoneroError>;

/// ed25519 group order L (little-endian) — used for canonical checks.
const ORDER_L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// Monero `H` point (compressed, from `RCTConst.h`).
pub const MONERO_H: [u8; 32] = [
    0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf, 0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad, 0xd0, 0xea,
    0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9, 0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c, 0x1f, 0x94,
];

/// Bulletproofs+ generator hash key: ASCII `"bulletproof_plus"`.
pub const BP_HASH_KEY: &[u8; 16] = b"bulletproof_plus";

/// Bulletproofs+ initial transcript (from `RCTConst`).
pub const BP_INIT_TRANSCRIPT: [u8; 32] = [
    0x4a, 0x67, 0x7c, 0x90, 0xeb, 0x73, 0x05, 0x1e, 0x79, 0x0d, 0xa4, 0x55, 0x91, 0x10, 0x7f, 0x6e,
    0xe1, 0x05, 0x90, 0x4d, 0x91, 0x87, 0xc5, 0xd3, 0x54, 0x71, 0x09, 0x6c, 0x44, 0x5a, 0x22, 0x75,
];

/// Scalar `1` (`RCTConst.i`).
pub const SCALAR_ONE: [u8; 32] = [
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Scalar `2`.
pub const SCALAR_TWO: [u8; 32] = [
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Scalar `-1` (`RCTConst.minusOne`).
pub const SCALAR_MINUS_ONE: [u8; 32] = [
    0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// Scalar `1/8` (`RCTConst.invEight`).
pub const SCALAR_INV_EIGHT: [u8; 32] = [
    0x79, 0x2f, 0xdc, 0xe2, 0x29, 0xe5, 0x06, 0x61, 0xd0, 0xda, 0x1c, 0x7d, 0xb3, 0x9d, 0xd3, 0x07,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06,
];

/// Scalar `-1/8` (`RCTConst.minusInvEight`).
pub const SCALAR_MINUS_INV_EIGHT: [u8; 32] = [
    0x74, 0xa4, 0x19, 0x7a, 0xf0, 0x7d, 0x0b, 0xf7, 0x05, 0xc2, 0xda, 0x25, 0x2b, 0x5c, 0x0b, 0x0d,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a,
];

/// `2^64 - 1` as scalar bytes (`RCTConst.twoSixtyFourMinusOne`).
pub const SCALAR_TWO64M1: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Zero scalar bytes.
pub const SCALAR_ZERO: [u8; 32] = [0u8; 32];

/// Canonical scalar check (`< L`, zero allowed) — mirrors the reference implementation
pub fn sc_check(bytes: &[u8; 32]) -> bool {
    // Big-endian lexicographic compare against L.
    for i in (0..32).rev() {
        if bytes[i] < ORDER_L[i] {
            return true;
        }
        if bytes[i] > ORDER_L[i] {
            return false;
        }
    }
    // Equal to L is NOT canonical.
    false
}

/// Decode a canonical scalar, erroring on non-canonical encodings.
pub fn sc_from_bytes(bytes: &[u8; 32]) -> MoneroResult<Scalar> {
    if !sc_check(bytes) {
        return Err(MoneroError::InvalidScalar);
    }
    Scalar::from_bytes_le(bytes).map_err(|_| MoneroError::InvalidScalar)
}

/// Reduce 32 bytes mod L.
pub fn sc_reduce(bytes: &[u8; 32]) -> Scalar {
    Scalar::from_bytes_mod_order(bytes)
}

/// Scalar → 32 LE bytes.
pub fn sc_bytes(s: &Scalar) -> S32 {
    let mut out = [0u8; 32];
    s.to_bytes_le(&mut out);
    out
}

/// Decode a compressed ed25519 point.
pub fn pt_decode(bytes: &[u8; 32]) -> MoneroResult<Ed25519Point> {
    Ed25519Point::from_bytes(bytes).map_err(|_| MoneroError::InvalidPoint)
}

/// Encode a point (compressed).
pub fn pt_encode(p: &Ed25519Point) -> MoneroResult<S32> {
    let mut out = [0u8; 32];
    p.to_bytes_compressed(&mut out)
        .map_err(|_| MoneroError::InvalidPoint)?;
    Ok(out)
}

/// keccak256 → 32 bytes.
pub fn keccak256(data: &[u8]) -> MoneroResult<S32> {
    keccak::keccak256(data).map_err(|_| MoneroError::HashFailed)
}

/// `hash_to_scalar`: keccak256 then reduce mod L.
pub fn hash_to_scalar(data: &[u8]) -> MoneroResult<Scalar> {
    let h = keccak256(data)?;
    Ok(sc_reduce(&h))
}

/// Monero unsigned varint (LEB128) encoding.
pub fn varint(mut v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut b = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            break;
        }
    }
    out
}

/// Monero `H` point.
pub fn h_point() -> MoneroResult<Ed25519Point> {
    pt_decode(&MONERO_H)
}

/// Hash-to-point used for BP generators.
///
/// mirrors the reference implementation
/// including the double hash: `8 * from_fe(keccak(keccak(H || key ||
/// varint(idx))))` — `hashToP3Bytes` re-hashes its input.
pub fn generator_point(idx: usize) -> MoneroResult<Ed25519Point> {
    let mut data = Vec::with_capacity(32 + 16 + 10);
    data.extend_from_slice(&MONERO_H);
    data.extend_from_slice(BP_HASH_KEY);
    data.extend_from_slice(&varint(idx as u64));
    let h1 = keccak256(&data)?;
    let h2 = keccak256(&h1)?;
    let p = ed_mono::from_fe_bytes_vartime(&h2).map_err(|_| MoneroError::InvalidPoint)?;
    // Multiply by 8 (cofactor clearing, mirrors okgeMul8).
    Ok(p.double().double().double())
}

/// Cache of `Gi`/`Hi` generator points.
/// `gi(i) = generator(2*i + 1)`, `hi(i) = generator(2*i)`.
pub struct GeneratorCache {
    pts: Vec<Ed25519Point>,
}

impl GeneratorCache {
    /// Precompute the first `n` generator points (indices `0..n`).
    pub fn new(n: usize) -> MoneroResult<Self> {
        let mut pts = Vec::with_capacity(n);
        for i in 0..n {
            pts.push(generator_point(i)?);
        }
        Ok(Self { pts })
    }

    /// `Gi` point for position `i`.
    pub fn gi(&self, i: usize) -> MoneroResult<Ed25519Point> {
        self.pts
            .get(2 * i + 1)
            .copied()
            .ok_or(MoneroError::InvalidProof)
    }

    /// `Hi` point for position `i`.
    pub fn hi(&self, i: usize) -> MoneroResult<Ed25519Point> {
        self.pts
            .get(2 * i)
            .copied()
            .ok_or(MoneroError::InvalidProof)
    }
}

/// Local ChaCha20 RNG stream for proving (seeded explicitly per call).
pub struct ProveRng {
    rng: ChaCha20Rng,
}

impl ProveRng {
    /// New stream from a 32-byte seed.
    pub fn new(seed: &[u8; 32]) -> Self {
        Self {
            rng: ChaCha20Rng::from_seed(seed),
        }
    }

    fn next_32(&mut self) -> S32 {
        let mut out = [0u8; 32];
        self.rng.next_bytes(32, &mut out);
        out
    }

    /// Random nonzero reduced scalar (mirrors `RCT.skGen_`).
    pub fn sk_gen(&mut self) -> Scalar {
        loop {
            let s = Scalar::from_bytes_mod_order(&self.next_32());
            if !s.is_zero() {
                return s;
            }
        }
    }
}
