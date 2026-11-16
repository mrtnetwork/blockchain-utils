//! Groth16 verifier C ABI (feature `ffi` + `groth16`).

#![cfg(all(feature = "ffi", feature = "groth16"))]

use crate::zk::groth16::codec::{
    unpack_public_inputs_sui, unpack_public_inputs_zcash, AptosProofBytes, SuiProofBytes,
    SuiVkBytes, ZcashProofBytes, ZcashVkBytes,
};
use crate::zk::groth16::{verify, verify_bn254};

/// Success.
pub const BU_G16_OK: i32 = 0;
/// Null pointer.
pub const BU_G16_ERR_NULL: i32 = 1;
/// Invalid length / encoding.
pub const BU_G16_ERR_LENGTH: i32 = 2;
/// Invalid point / scalar.
pub const BU_G16_ERR_ENCODING: i32 = 3;
/// Public input count mismatch.
pub const BU_G16_ERR_INPUTS: i32 = 4;
/// Pairing product check failed.
pub const BU_G16_ERR_VERIFY: i32 = 5;
/// Feature / internal.
pub const BU_G16_ERR_INTERNAL: i32 = 6;

fn map_err(e: crate::zk::groth16::Groth16Error) -> i32 {
    use crate::zk::groth16::Groth16Error::*;
    match e {
        InputLength => BU_G16_ERR_INPUTS,
        InvalidPoint | InvalidScalar => BU_G16_ERR_ENCODING,
        InvalidLength => BU_G16_ERR_LENGTH,
        VerificationFailed => BU_G16_ERR_VERIFY,
    }
}

/// Verify BLS12-381 Groth16 proof (Zcash / Tezos BLS path).
///
/// - `proof`: 192-byte compressed (48‖96‖48)
/// - `vk`: ZcashVkBytes layout
/// - `public_inputs`: `n * 32` little-endian Fr
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_groth16_verify_bls(
    proof: *const u8,
    proof_len: usize,
    vk: *const u8,
    vk_len: usize,
    public_inputs: *const u8,
    public_len: usize,
) -> i32 {
    if proof.is_null() || vk.is_null() {
        return BU_G16_ERR_NULL;
    }
    if public_len > 0 && public_inputs.is_null() {
        return BU_G16_ERR_NULL;
    }
    let proof_bytes = core::slice::from_raw_parts(proof, proof_len);
    let vk_bytes = core::slice::from_raw_parts(vk, vk_len);
    let pub_bytes = if public_len == 0 {
        &[][..]
    } else {
        core::slice::from_raw_parts(public_inputs, public_len)
    };

    let proof = match ZcashProofBytes::decode(proof_bytes) {
        Ok(p) => p,
        Err(e) => return map_err(e),
    };
    let vk = match ZcashVkBytes::decode(vk_bytes) {
        Ok(v) => v,
        Err(e) => return map_err(e),
    };
    let inputs = match unpack_public_inputs_zcash(pub_bytes) {
        Ok(v) => v,
        Err(e) => return map_err(e),
    };

    match verify(&vk, &inputs, &proof) {
        Ok(()) => BU_G16_OK,
        Err(e) => map_err(e),
    }
}

/// Verify BN254 Groth16 proof (Sui / Aptos / Tezos BN path).
///
/// - `proof`: 256-byte uncompressed (64‖128‖64)
/// - `vk`: SuiVkBytes layout
/// - `public_inputs`: `n * 32` big-endian Fr
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_groth16_verify_bn254(
    proof: *const u8,
    proof_len: usize,
    vk: *const u8,
    vk_len: usize,
    public_inputs: *const u8,
    public_len: usize,
) -> i32 {
    if proof.is_null() || vk.is_null() {
        return BU_G16_ERR_NULL;
    }
    if public_len > 0 && public_inputs.is_null() {
        return BU_G16_ERR_NULL;
    }
    let proof_bytes = core::slice::from_raw_parts(proof, proof_len);
    let vk_bytes = core::slice::from_raw_parts(vk, vk_len);
    let pub_bytes = if public_len == 0 {
        &[][..]
    } else {
        core::slice::from_raw_parts(public_inputs, public_len)
    };

    let proof = match SuiProofBytes::decode(proof_bytes)
        .or_else(|_| AptosProofBytes::decode(proof_bytes))
    {
        Ok(p) => p,
        Err(e) => return map_err(e),
    };
    let vk = match SuiVkBytes::decode(vk_bytes) {
        Ok(v) => v,
        Err(e) => return map_err(e),
    };
    let inputs = match unpack_public_inputs_sui(pub_bytes) {
        Ok(v) => v,
        Err(e) => return map_err(e),
    };

    match verify_bn254(&vk, &inputs, &proof) {
        Ok(()) => BU_G16_OK,
        Err(e) => map_err(e),
    }
}

/// Proof byte lengths.
#[no_mangle]
pub extern "C" fn bu_groth16_bls_proof_len() -> usize {
    ZcashProofBytes::LEN
}

#[no_mangle]
pub extern "C" fn bu_groth16_bn254_proof_len() -> usize {
    SuiProofBytes::LEN
}

/// Sapling Spend verify: proof (192) + VK + 7×32 LE public inputs (cv‖rk‖rt‖nf).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_sapling_verify_spend(
    proof: *const u8,
    proof_len: usize,
    vk: *const u8,
    vk_len: usize,
    public_inputs: *const u8,
    public_len: usize,
) -> i32 {
    if public_len != 7 * 32 {
        return BU_G16_ERR_INPUTS;
    }
    bu_groth16_verify_bls(proof, proof_len, vk, vk_len, public_inputs, public_len)
}

/// Sapling Output verify: proof (192) + VK + 5×32 LE public inputs.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_sapling_verify_output(
    proof: *const u8,
    proof_len: usize,
    vk: *const u8,
    vk_len: usize,
    public_inputs: *const u8,
    public_len: usize,
) -> i32 {
    if public_len != 5 * 32 {
        return BU_G16_ERR_INPUTS;
    }
    bu_groth16_verify_bls(proof, proof_len, vk, vk_len, public_inputs, public_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::bn254::{G1Point, G2Point};
    use crate::curve::traits::CurvePoint;
    use crate::zk::groth16::codec::{pack_public_inputs_sui, SuiProofBytes, SuiVkBytes};
    use crate::zk::groth16::{ProofBn254, VerifyingKeyBn254};

    #[test]
    fn proof_len_helpers() {
        assert_eq!(bu_groth16_bn254_proof_len(), 256);
        assert_eq!(bu_groth16_bls_proof_len(), 192);
    }

    #[test]
    fn null_ptr_returns_err() {
        let rc = unsafe {
            bu_groth16_verify_bn254(
                core::ptr::null(),
                0,
                core::ptr::null(),
                0,
                core::ptr::null(),
                0,
            )
        };
        assert_eq!(rc, BU_G16_ERR_NULL);
        let rc = unsafe {
            bu_groth16_verify_bls(
                core::ptr::null(),
                0,
                core::ptr::null(),
                0,
                core::ptr::null(),
                0,
            )
        };
        assert_eq!(rc, BU_G16_ERR_NULL);
    }

    #[test]
    fn bn254_generator_proof_fails_verify() {
        let proof = ProofBn254 {
            a: G1Point::generator(),
            b: G2Point::generator(),
            c: G1Point::generator(),
        };
        let vk = VerifyingKeyBn254 {
            alpha_g1: G1Point::generator(),
            beta_g2: G2Point::generator(),
            gamma_g2: G2Point::generator(),
            delta_g2: G2Point::generator(),
            ic: alloc::vec![G1Point::identity()],
        };
        let pb = SuiProofBytes::encode(&proof).unwrap();
        let vb = SuiVkBytes::encode(&vk).unwrap();
        let pub_in = pack_public_inputs_sui(&[]);
        let rc = unsafe {
            bu_groth16_verify_bn254(
                pb.as_ptr(),
                pb.len(),
                vb.as_ptr(),
                vb.len(),
                pub_in.as_ptr(),
                pub_in.len(),
            )
        };
        assert_eq!(rc, BU_G16_ERR_VERIFY);
    }
}

#[cfg(all(test, feature = "groth16-prover"))]
mod prover_e2e {
    use super::*;
    use crate::curve::bn254::Scalar;
    use crate::zk::groth16::codec::{pack_public_inputs_sui, SuiProofBytes, SuiVkBytes};
    use crate::zk::groth16::{prove_bn254, setup_mult_circuit_synthetic};

    #[test]
    fn ffi_verify_after_prove() {
        let (pk, cs) = setup_mult_circuit_synthetic();
        let assignment = [
            Scalar::one(),
            Scalar::from_u64(6),
            Scalar::from_u64(2),
            Scalar::from_u64(3),
        ];
        let proof = prove_bn254(&pk, &cs, &assignment).expect("prove");
        let pb = SuiProofBytes::encode(&proof).unwrap();
        let vb = SuiVkBytes::encode(&pk.vk).unwrap();
        let pub_in = pack_public_inputs_sui(&[Scalar::from_u64(6)]);
        let rc = unsafe {
            bu_groth16_verify_bn254(
                pb.as_ptr(),
                pb.len(),
                vb.as_ptr(),
                vb.len(),
                pub_in.as_ptr(),
                pub_in.len(),
            )
        };
        assert_eq!(rc, BU_G16_OK, "FFI verify after prove must succeed");
    }
}
