//! Implements crypto/context logic (`ZKCryptoContext`).
//! LE wire bytes; `to_debug_string` via `format!`; Result style, no `assert!`.
//! Poseidon spec is a compile-time constant: `get_poseidon_spec()` borrows a
//! `&'static` table and never regenerates (no Grain re-run per call).
//! Domain points and the Sinsemilla S2 table are precomputed LE constants
//! (`tables.rs`, bit-exact from the reference implementation) — no runtime
//! hash-to-curve.

use crate::zk::orchard_halo2::curve::PallasAffine;
use crate::zk::orchard_halo2::error::{Halo2Error, Halo2Result};
use crate::zk::orchard_halo2::poseidon::spec_const::{PoseidonSpec, POSEIDON_SPEC};
use crate::zk::orchard_halo2::tables::{
    DOMAIN_COMMIT_IVK_X, DOMAIN_COMMIT_IVK_Y, DOMAIN_MERKLE_CRH_X, DOMAIN_MERKLE_CRH_Y,
    DOMAIN_NOTE_COMMIT_X, DOMAIN_NOTE_COMMIT_Y,
};
use crate::zk::orchard_halo2::tables_ipa_mont::{
    DOMAIN_COMMIT_IVK_MONT, DOMAIN_MERKLE_CRH_MONT, DOMAIN_NOTE_COMMIT_MONT, SINSEMILLA_S2_MONT,
};

/// Crypto context needed by Halo2 circuits (domain points, Poseidon, S).
pub trait CryptoContext {
    fn get_poseidon_spec(&self) -> &'static PoseidonSpec;
    fn get_domain_point_le(&self, domain: &[u8]) -> Halo2Result<([u8; 32], [u8; 32])>;
    /// Domain point as affine from Montgomery limbs (unchecked trusted const).
    fn get_domain_point_affine(&self, domain: &[u8]) -> Halo2Result<PallasAffine>;
    /// Precomputed S2 table (bit-exact, LE). No runtime hashing.
    fn sinsemilla_s2(&self) -> Halo2Result<alloc::vec::Vec<PallasAffine>>;
}

/// Default context. Poseidon spec is shared static; nothing is regenerated.
#[derive(Clone, Copy)]
pub struct DefaultCryptoContext;

impl CryptoContext for DefaultCryptoContext {
    fn get_poseidon_spec(&self) -> &'static PoseidonSpec {
        &POSEIDON_SPEC
    }

    /// Precomputed domain points (`getDomainPoint`, bit-exact LE).
    /// Known domains: `z.cash:Orchard-CommitIvk-M`, `z.cash:Orchard-NoteCommit-M`
    /// (default separator) and `z.cash:Orchard-MerkleCRH` (no separator).
    fn get_domain_point_le(&self, domain: &[u8]) -> Halo2Result<([u8; 32], [u8; 32])> {
        if domain == b"z.cash:Orchard-CommitIvk-M" {
            Ok((DOMAIN_COMMIT_IVK_X, DOMAIN_COMMIT_IVK_Y))
        } else if domain == b"z.cash:Orchard-NoteCommit-M" {
            Ok((DOMAIN_NOTE_COMMIT_X, DOMAIN_NOTE_COMMIT_Y))
        } else if domain == b"z.cash:Orchard-MerkleCRH" {
            Ok((DOMAIN_MERKLE_CRH_X, DOMAIN_MERKLE_CRH_Y))
        } else {
            Err(Halo2Error::operation_failed(
                "get_domain_point",
                "unknown domain",
            ))
        }
    }

    fn get_domain_point_affine(&self, domain: &[u8]) -> Halo2Result<PallasAffine> {
        if domain == b"z.cash:Orchard-CommitIvk-M" {
            let m = DOMAIN_COMMIT_IVK_MONT[0];
            Ok(PallasAffine::from_affine_mont_limbs(m[0], m[1]))
        } else if domain == b"z.cash:Orchard-NoteCommit-M" {
            let m = DOMAIN_NOTE_COMMIT_MONT[0];
            Ok(PallasAffine::from_affine_mont_limbs(m[0], m[1]))
        } else if domain == b"z.cash:Orchard-MerkleCRH" {
            let m = DOMAIN_MERKLE_CRH_MONT[0];
            Ok(PallasAffine::from_affine_mont_limbs(m[0], m[1]))
        } else {
            Err(Halo2Error::operation_failed(
                "get_domain_point",
                "unknown domain",
            ))
        }
    }

    fn sinsemilla_s2(&self) -> Halo2Result<alloc::vec::Vec<PallasAffine>> {
        // Montgomery-limb table (unchecked trusted consts; no decode).
        let mut out = alloc::vec::Vec::with_capacity(SINSEMILLA_S2_MONT.len());
        for pair in SINSEMILLA_S2_MONT.iter() {
            out.push(PallasAffine::from_affine_mont_limbs(pair[0], pair[1]));
        }
        Ok(out)
    }
}

/// Borrow the compile-time Poseidon spec without generating anything.
pub fn get_poseidon_spec() -> &'static PoseidonSpec {
    &POSEIDON_SPEC
}
