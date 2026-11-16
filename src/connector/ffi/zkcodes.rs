//! Unified zk interop codes + helpers (features `ffi`).
//!
//! Mirrors the legacy global error codes so Callers match on stable
//! values across the new direct (non-CBOR) surface:
//! `KeyError = 1, EncodingError = 2, InvalidInput = 3, ProofError = 4,
//! WitnessError = 5, MerkleError = 6, Internal = 7, Missing = 8,
//! HashError = 9`. Success is always 0.
//!
//! Also hosts [`bu_zk_version`] (API version 1, like legacy `Version()`)
//! and [`bu_zk_enable_logging`] (accepted no-op: this crate ships no logger
//! backend, keeping the zero-dependency core).

#![cfg(feature = "ffi")]

/// Success.
pub const ZK_OK: i32 = 0;
/// Invalid key material.
pub const ZK_ERR_KEY: i32 = 1;
/// Invalid encoding.
pub const ZK_ERR_ENCODING: i32 = 2;
/// Invalid input / length / discriminant.
pub const ZK_ERR_INPUT: i32 = 3;
/// Proof creation or verification failure.
pub const ZK_ERR_PROOF: i32 = 4;
/// Witness construction failure.
pub const ZK_ERR_WITNESS: i32 = 5;
/// Merkle tree failure.
pub const ZK_ERR_MERKLE: i32 = 6;
/// Internal error.
pub const ZK_ERR_INTERNAL: i32 = 7;
/// Missing handle / params.
pub const ZK_ERR_MISSING: i32 = 8;
/// Hash failure.
pub const ZK_ERR_HASH: i32 = 9;

/// API version (legacy `Version()` answered 1).
pub const ZK_API_VERSION: u32 = 1;

/// API version.
#[no_mangle]
pub extern "C" fn bu_zk_version() -> u32 {
    ZK_API_VERSION
}

/// Logging toggle (accepted no-op for legacy compat; no backend linked).
#[no_mangle]
pub extern "C" fn bu_zk_enable_logging(_enable: u32, _mode: u32) -> i32 {
    ZK_OK
}

/// Backend interface version (see `connector::BU_BUILD_VERSION`).
#[no_mangle]
pub extern "C" fn bu_build_version() -> u32 {
    crate::connector::BU_BUILD_VERSION
}

/// Cargo feature bitmask of this `.so` (see `connector::build_features`).
#[no_mangle]
pub extern "C" fn bu_build_features() -> u32 {
    crate::connector::build_features()
}

/// Map [`crate::zk::incrementalmerkletree::MerkleError`] to a global code.
#[cfg(any(
    feature = "zcash-incrementalmerkle",
    feature = "groth16-prover",
    feature = "orchard-halo2"
))]
pub fn map_merkle_err(e: crate::zk::incrementalmerkletree::MerkleError) -> i32 {
    use crate::zk::incrementalmerkletree::MerkleError::*;
    match e {
        PositionMismatch { .. } | LengthMismatch { .. } | PositionOutOfRange { .. } => ZK_ERR_INPUT,
        MaxDepthExceeded { .. } | TreeFull => ZK_ERR_MERKLE,
        InconsistentTree => ZK_ERR_MERKLE,
        InvalidEncoding => ZK_ERR_ENCODING,
        PositionUnderflow => ZK_ERR_INPUT,
        Missing => ZK_ERR_MISSING,
    }
}

/// Map [`crate::zk::groth16::Groth16Error`] to a global code.
#[cfg(feature = "groth16")]
pub fn map_groth16_err(e: crate::zk::groth16::Groth16Error) -> i32 {
    use crate::zk::groth16::Groth16Error::*;
    match e {
        InputLength => ZK_ERR_INPUT,
        InvalidPoint | InvalidScalar => ZK_ERR_ENCODING,
        InvalidLength => ZK_ERR_INPUT,
        VerificationFailed => ZK_ERR_PROOF,
    }
}

/// Map [`crate::hash::HashError`] to a global code.
pub fn map_hash_err(_e: crate::hash::HashError) -> i32 {
    ZK_ERR_HASH
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_one() {
        assert_eq!(bu_zk_version(), 1);
        assert_eq!(bu_zk_enable_logging(1, 0), ZK_OK);
        assert_eq!(ZK_OK, 0);
    }
}
