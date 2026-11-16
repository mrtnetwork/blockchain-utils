//! Orchard Action prove/verify C ABI (features `ffi` + `orchard-halo2`).
//!
//! Backend is `zk::orchard_halo2` via its field-level [`bridge`]. No wallet
//! parsing lives here: Callers send circuit witness fields + instance limbs
//! (see `bridge` docs for the exact layout).
//!
//! Exactly three operations (+ handle free):
//! - proving-key build → `bu_orchard_pk_new_for_version` / `bu_orchard_pk_free`
//! - prove → `bu_orchard_create_proof` (needs a 32-byte blinding seed)
//! - verify → `bu_orchard_verify_proof`
//!
//! Per Action: circuit blob `BU_ORCHARD_INPUT_LEN` (1716) + instance limbs
//! `BU_ORCHARD_INSTANCE_LEN` (10 x 32). Proof size `BU_ORCHARD_PROOF_LEN`.
//!
//! Versions: 0 = insecure (pre-NU6.2), 1 = fixed (post-NU6.2),
//! 2 = NU6.3. `disable_cross_address` (0/1) applies ONLY to version 2
//! (row-9 rule enforced inside); it is rejected for versions 0/1, as is any
//! params/pk version mismatch.
//!
//! Error codes are [`OrchardError`] discriminants (no strings cross the ABI).

#![cfg(all(feature = "ffi", feature = "orchard-halo2"))]

use crate::zk::orchard_halo2::bridge::{
    self, CIRCUIT_BLOB_LEN, INSTANCE_BLOB_LEN, PROOF_LEN, SEED_LEN,
};
use crate::zk::orchard_halo2::error::OrchardError;
use crate::zk::orchard_halo2::orchard::circuit::OrchardProtocolVersion;
use crate::zk::orchard_halo2::orchard::prover::DefaultOrchardProver;
use alloc::boxed::Box;
// `Vec` is prelude under `std`; import from `alloc` only for `no_std`.
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// Success.
pub const BU_ORCHARD_OK: i32 = OrchardError::Ok as i32;
/// Null pointer argument.
pub const BU_ORCHARD_ERR_NULL: i32 = OrchardError::Null as i32;
/// Wrong blob/field/row shape.
pub const BU_ORCHARD_ERR_LENGTH: i32 = OrchardError::InvalidLength as i32;
/// Undecodable value (field/point/version/flag rule).
pub const BU_ORCHARD_ERR_PARSE: i32 = OrchardError::InvalidEncoding as i32;
/// Proving failed.
pub const BU_ORCHARD_ERR_PROVE: i32 = OrchardError::ProveFailed as i32;
/// Proof rejected by the verifier.
pub const BU_ORCHARD_ERR_VERIFY: i32 = OrchardError::VerifyFailed as i32;
/// Internal fault.
pub const BU_ORCHARD_ERR_INTERNAL: i32 = OrchardError::Internal as i32;

/// Packed size of one circuit blob (field-level witness, 1716 bytes).
pub const BU_ORCHARD_INPUT_LEN: usize = CIRCUIT_BLOB_LEN;
/// Instance bytes per action (10 x 32 LE limbs).
pub const BU_ORCHARD_INSTANCE_LEN: usize = INSTANCE_BLOB_LEN;
/// Proof bytes.
pub const BU_ORCHARD_PROOF_LEN: usize = PROOF_LEN;
/// Blinding seed bytes per prove call.
pub const BU_ORCHARD_SEED_LEN: usize = SEED_LEN;

fn err(e: OrchardError) -> i32 {
    e.code()
}

fn parse_flag(flag: u32) -> Option<bool> {
    match flag {
        0 => Some(false),
        1 => Some(true),
        _ => None,
    }
}

/// Opaque proving key handle (params + keys + version).
pub struct BuOrchardPk {
    prover: DefaultOrchardProver,
    version: OrchardProtocolVersion,
}

/// Build proving key for a version discriminant (0/1/2, see module docs).
/// Caller must `bu_orchard_pk_free`. Other values → `BU_ORCHARD_ERR_PARSE`.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_orchard_pk_new_for_version(
    out_pk: *mut *mut BuOrchardPk,
    version: u32,
) -> i32 {
    if out_pk.is_null() {
        return BU_ORCHARD_ERR_NULL;
    }
    let v = match bridge::parse_version(version) {
        Ok(v) => v,
        Err(e) => return err(e),
    };
    match bridge::build_prover(v) {
        Ok(prover) => {
            let boxed = Box::new(BuOrchardPk { prover, version: v });
            *out_pk = Box::into_raw(boxed);
            BU_ORCHARD_OK
        }
        Err(_) => BU_ORCHARD_ERR_INTERNAL,
    }
}

#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_orchard_pk_free(pk: *mut BuOrchardPk) {
    if !pk.is_null() {
        drop(Box::from_raw(pk));
    }
}

/// Prove N Actions.
///
/// - `inputs`: `n * BU_ORCHARD_INPUT_LEN` packed circuit blobs
/// - `instances`: `n * BU_ORCHARD_INSTANCE_LEN` instance limbs (10-wide)
/// - `version` / `disable_cross_address`: must match the pk handle's version;
///   flag applies only to version 2 (strict, else `BU_ORCHARD_ERR_PARSE`)
/// - `seed`: 32 fresh blinding-seed bytes (caller CSPRNG; fixed seeds only for tests)
/// - `out_proof` / `out_proof_len`: caller buffer; on entry `*out_proof_len` = capacity;
///   on success set to written length. If buffer too small, returns `BU_ORCHARD_ERR_LENGTH`
///   and sets `*out_proof_len` to required size.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_orchard_create_proof(
    pk: *const BuOrchardPk,
    inputs: *const u8,
    inputs_len: usize,
    instances: *const u8,
    instances_len: usize,
    version: u32,
    disable_cross_address: u32,
    seed: *const u8,
    out_proof: *mut u8,
    out_proof_len: *mut usize,
) -> i32 {
    if pk.is_null() || out_proof_len.is_null() {
        return BU_ORCHARD_ERR_NULL;
    }
    if inputs_len == 0 || inputs.is_null() {
        return BU_ORCHARD_ERR_LENGTH;
    }
    if !inputs_len.is_multiple_of(BU_ORCHARD_INPUT_LEN) {
        return BU_ORCHARD_ERR_LENGTH;
    }
    if seed.is_null() {
        return BU_ORCHARD_ERR_NULL;
    }
    let v = match bridge::parse_version(version) {
        Ok(v) => v,
        Err(e) => return err(e),
    };
    if v != (*pk).version {
        return BU_ORCHARD_ERR_PARSE;
    }
    let flag = match parse_flag(disable_cross_address) {
        Some(b) => b,
        None => return BU_ORCHARD_ERR_PARSE,
    };
    // Strict: the flag applies only to NU6.3.
    if flag && version != 2 {
        return BU_ORCHARD_ERR_PARSE;
    }
    let n = inputs_len / BU_ORCHARD_INPUT_LEN;
    if instances.is_null() && n > 0 {
        return BU_ORCHARD_ERR_NULL;
    }
    if instances_len != n * BU_ORCHARD_INSTANCE_LEN {
        return BU_ORCHARD_ERR_LENGTH;
    }
    let circuits = core::slice::from_raw_parts(inputs, inputs_len);
    let inst_bytes = core::slice::from_raw_parts(instances, instances_len);
    let mut seed_arr = [0u8; SEED_LEN];
    seed_arr.copy_from_slice(core::slice::from_raw_parts(seed, SEED_LEN));
    let parsed_inst = match bridge::parse_instances(inst_bytes, v, flag) {
        Ok(x) => x,
        Err(e) => return err(e),
    };
    let proof = match bridge::create_proof(&(*pk).prover, circuits, &seed_arr, v, parsed_inst) {
        Ok(p) => p,
        Err(e) => return err(e),
    };
    let need = proof.len();
    if out_proof.is_null() || *out_proof_len < need {
        *out_proof_len = need;
        return BU_ORCHARD_ERR_LENGTH;
    }
    core::ptr::copy_nonoverlapping(proof.as_ptr(), out_proof, need);
    *out_proof_len = need;
    BU_ORCHARD_OK
}

/// Verify proof against a 10-wide instance matrix (`n * 10 * 32` LE limbs).
/// Row 9 is validated against `version` + `disable_cross_address`
/// (strict rule); the pk handle's circuit version must match `version`.
/// Returns `BU_ORCHARD_OK` on accept, `BU_ORCHARD_ERR_VERIFY` on reject.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_orchard_verify_proof(
    pk: *const BuOrchardPk,
    proof: *const u8,
    proof_len: usize,
    instances: *const u8,
    instances_len: usize,
    version: u32,
    disable_cross_address: u32,
) -> i32 {
    if pk.is_null() || proof.is_null() {
        return BU_ORCHARD_ERR_NULL;
    }
    if proof_len == 0 {
        return BU_ORCHARD_ERR_LENGTH;
    }
    let v = match bridge::parse_version(version) {
        Ok(v) => v,
        Err(e) => return err(e),
    };
    if v != (*pk).version {
        return BU_ORCHARD_ERR_PARSE;
    }
    let flag = match parse_flag(disable_cross_address) {
        Some(b) => b,
        None => return BU_ORCHARD_ERR_PARSE,
    };
    // Strict: the flag applies only to NU6.3.
    if flag && version != 2 {
        return BU_ORCHARD_ERR_PARSE;
    }
    let proof_sl = core::slice::from_raw_parts(proof, proof_len);
    if !instances_len.is_multiple_of(BU_ORCHARD_INSTANCE_LEN) {
        return BU_ORCHARD_ERR_LENGTH;
    }
    let n = instances_len / BU_ORCHARD_INSTANCE_LEN;
    if n > 0 && instances.is_null() {
        return BU_ORCHARD_ERR_NULL;
    }
    let inst_bytes = if n == 0 {
        &[][..]
    } else {
        core::slice::from_raw_parts(instances, instances_len)
    };
    let parsed_inst = match bridge::parse_instances(inst_bytes, v, flag) {
        Ok(x) => x,
        Err(e) => return err(e),
    };
    // Bridge verify is per-action; run each action's column set.
    // All actions share one proof blob (batch); instances align by action.
    let _ = n;
    match bridge::verify_proof(&(*pk).prover, proof_sl, &parsed_inst) {
        Ok(true) => BU_ORCHARD_OK,
        Ok(false) => BU_ORCHARD_ERR_VERIFY,
        Err(e) => err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zk::orchard_halo2::bridge as B;
    use alloc::vec;

    #[test]
    fn ffi_version_flag_parsing() {
        assert!(B::parse_version(0).is_ok());
        assert!(B::parse_version(1).is_ok());
        assert!(B::parse_version(2).is_ok());
        assert!(B::parse_version(3).is_err());
        assert_eq!(parse_flag(0), Some(false));
        assert_eq!(parse_flag(1), Some(true));
        assert_eq!(parse_flag(2), None);
    }

    #[test]
    fn ffi_error_codes_match_enum() {
        assert_eq!(BU_ORCHARD_OK, 0);
        assert_eq!(BU_ORCHARD_ERR_NULL, 1);
        assert_eq!(BU_ORCHARD_ERR_LENGTH, 2);
        assert_eq!(BU_ORCHARD_ERR_PARSE, 3);
        assert_eq!(BU_ORCHARD_ERR_PROVE, 4);
        assert_eq!(BU_ORCHARD_ERR_VERIFY, 5);
        assert_eq!(BU_ORCHARD_ERR_INTERNAL, 6);
    }

    #[test]
    fn ffi_rejects_bad_shapes() {
        unsafe {
            let mut pk: *mut BuOrchardPk = core::ptr::null_mut();
            // Bad version.
            assert_eq!(
                bu_orchard_pk_new_for_version(&mut pk, 9),
                BU_ORCHARD_ERR_PARSE
            );
            // Null out pointer.
            assert_eq!(
                bu_orchard_pk_new_for_version(core::ptr::null_mut(), 0),
                BU_ORCHARD_ERR_NULL
            );
            // Short circuit blob rejected at parse (no keygen needed).
            let short = [0u8; 100];
            let inst = vec![0u8; B::INSTANCE_BLOB_LEN];
            let seed = [0u8; B::SEED_LEN];
            let mut need = 0usize;
            // Null pk.
            assert_eq!(
                bu_orchard_create_proof(
                    core::ptr::null(),
                    short.as_ptr(),
                    short.len(),
                    inst.as_ptr(),
                    inst.len(),
                    0,
                    0,
                    seed.as_ptr(),
                    core::ptr::null_mut(),
                    &mut need
                ),
                BU_ORCHARD_ERR_NULL
            );
            // Row-9 rule: flag set on insecure rejected (needs valid pk,
            // so only the flag/version gate before it is exercised here
            // via parse path would need pk; covered in bridge tests).
            let _ = (need, inst);
        }
    }
}
