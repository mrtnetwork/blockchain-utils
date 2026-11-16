//! Bulletproof generator points (zero-dep port).
//!
//! /// Byte-compatible port of
//! `zk-sdk/src/range_proof/generators.rs`: `GeneratorsChain` squeezes
//! SHAKE256(`b"GeneratorsChain" || label`) into 64-byte blocks mapped with
//! `from_uniform_bytes`. Matches upstream (and dalek) exactly, so proofs
//! verify against the on-chain program.

use crate::curve::RistrettoPoint;

/// Maximum generator count (mirrors upstream u32 bound).
pub const MAX_GENERATOR_LENGTH: usize = u32::MAX as usize;

/// Cached generator count (matches upstream).
pub const CACHED_GENERATOR_LENGTH: usize = 256;

/// SHAKE256 XOF stream for one generator chain label.
struct GeneratorsChain {
    /// Buffered XOF output.
    stream: Vec<u8>,
    /// Read position.
    pos: usize,
}

impl GeneratorsChain {
    /// New chain for `label` (squeezes `blocks` 64-byte chunks
    /// up front; SHAKE is an XOF so one-shot squeeze is exact).
    fn new(label: &[u8], blocks: usize) -> Self {
        let mut input = Vec::with_capacity(16 + label.len());
        input.extend_from_slice(b"GeneratorsChain");
        input.extend_from_slice(label);
        let mut stream = vec![0u8; blocks * 64];
        crate::hash::shake256(&input, &mut stream)
            .expect("shake256 squeeze");
        Self { stream, pos: 0 }
    }

    /// Next generator point, if any remain.
    fn next_point(&mut self) -> Option<RistrettoPoint> {
        if self.pos + 64 > self.stream.len() {
            return None;
        }
        let mut wide = [0u8; 64];
        wide.copy_from_slice(&self.stream[self.pos..self.pos + 64]);
        self.pos += 64;
        Some(RistrettoPoint::from_uniform_bytes(&wide))
    }
}

/// Precomputed G/H generator vectors for range proofs.
#[derive(Clone)]
pub struct RangeProofGens {
    /// Number of G (and H) generators available.
    pub gens_capacity: usize,
    /// G generators.
    pub(crate) g_vec: Vec<RistrettoPoint>,
    /// H generators.
    pub(crate) h_vec: Vec<RistrettoPoint>,
}

impl RangeProofGens {
    /// Build `gens_capacity` generators per side.
    pub fn new(gens_capacity: usize) -> Result<Self, RangeError> {
        if gens_capacity > MAX_GENERATOR_LENGTH {
            return Err(RangeError::MaximumGeneratorLengthExceeded);
        }
        let mut g = GeneratorsChain::new(b"G", gens_capacity);
        let mut h = GeneratorsChain::new(b"H", gens_capacity);
        let mut g_vec = Vec::with_capacity(gens_capacity);
        let mut h_vec = Vec::with_capacity(gens_capacity);
        for _ in 0..gens_capacity {
            g_vec.push(g.next_point().ok_or(RangeError::Internal)?);
            h_vec.push(h.next_point().ok_or(RangeError::Internal)?);
        }
        Ok(Self {
            gens_capacity,
            g_vec,
            h_vec,
        })
    }

    /// First `n` G generators.
    pub fn g(&self, n: usize) -> impl Iterator<Item = &RistrettoPoint> {
        self.g_vec.iter().take(n)
    }

    /// First `n` H generators.
    pub fn h(&self, n: usize) -> impl Iterator<Item = &RistrettoPoint> {
        self.h_vec.iter().take(n)
    }
}

/// Range-proof errors (generation + verification).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RangeError {
    /// Generator capacity exceeds the u32 bound.
    MaximumGeneratorLengthExceeded,
    /// Vector lengths disagree.
    VectorLengthMismatch,
    /// Bit size is zero, > 64, or (for prove) not power-of-two sum.
    InvalidBitSize,
    /// Inner-product vectors disagree in length.
    InnerProductLengthMismatch,
    /// Identity commitment (explicitly rejected).
    IdentityCommitment,
    /// Identity point where a generator-multiple is required.
    IdentityPoint,
    /// Verification equation failed.
    AlgebraicRelation,
    /// Malformed proof encoding.
    Deserialization,
    /// Well-formed but failing proof input.
    InvalidProof,
    /// Non-canonical scalar encoding.
    InvalidScalar,
    /// Invalid curve point.
    InvalidPoint,
    /// Internal error (should not happen).
    Internal,
}

/// Map transcript/point validation failures.
impl From<crate::solana_zk::sigma_proofs::SigmaError> for RangeError {
    fn from(e: crate::solana_zk::sigma_proofs::SigmaError) -> Self {
        match e {
            crate::solana_zk::sigma_proofs::SigmaError::Deserialization => {
                RangeError::Deserialization
            }
            crate::solana_zk::sigma_proofs::SigmaError::IdentityPoint => {
                RangeError::IdentityPoint
            }
            crate::solana_zk::sigma_proofs::SigmaError::AlgebraicRelation => {
                RangeError::AlgebraicRelation
            }
        }
    }
}

/// Result alias for range proofs.
pub type RangeResult<T> = core::result::Result<T, RangeError>;

// Map core ZK errors into range errors.
impl From<crate::solana_zk::SolanaZkError> for RangeError {
    fn from(e: crate::solana_zk::SolanaZkError) -> Self {
        match e {
            crate::solana_zk::SolanaZkError::InvalidLength => RangeError::Deserialization,
            crate::solana_zk::SolanaZkError::InvalidPoint => RangeError::InvalidPoint,
            crate::solana_zk::SolanaZkError::InvalidProof => RangeError::InvalidProof,
            crate::solana_zk::SolanaZkError::BackendNotLinked => RangeError::Internal,
        }
    }
}
