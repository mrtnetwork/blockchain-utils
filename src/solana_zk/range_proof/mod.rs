//! Aggregated Bulletproof range proofs (zero-dep port).
//!
//! /// Pure-Rust dalek-compatible Bulletproofs: utilities,
//! SHAKE256-derived generators, the inner-product argument, and aggregated
//! range prove/verify. No trusted setup; matches `zk-sdk` encodings so proofs
//! verify against the on-chain program.

pub mod generators;
pub mod inner_product;
pub mod range;
pub mod util;

pub use generators::{RangeError, RangeProofGens, RangeResult, CACHED_GENERATOR_LENGTH};
pub use inner_product::InnerProductProof;
pub use range::{prove_range, prove_range_inner, prove_range_instruction,
    verify_range, verify_range_inner, verify_range_instruction,
    MAX_RANGE_COMMITMENTS};
