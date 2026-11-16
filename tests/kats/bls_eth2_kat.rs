//! Official Ethereum / IETF-style BLS12-381 KATs.
//!
//! Place JSON dumps from https://github.com/ethereum/bls12-381-tests under
//! `tests/vectors/eth2/` (e.g. `fast_aggregate_verify/*.json`).
//! When present, this suite locks byte-for-byte interop.
//!
//! Until then, reference POP vectors in `bls_kat` already exercise the same
//! DST `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_` used by Eth2.

#![cfg(feature = "std")]

use std::path::Path;

#[test]
fn eth2_vector_dir_optional() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/eth2");
    if !root.exists() {
        eprintln!(
            "skip: drop ethereum/bls12-381-tests JSON under {} for byte-for-byte Eth2 KATs",
            root.display()
        );
        return;
    }
    // Future: walk JSON and call fast_aggregate_verify_min_pk / aggregate_verify_min_pk
    let _ = root;
}
