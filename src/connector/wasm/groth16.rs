//! Groth16 verifier WASM exports (`BuWasm.groth16*`).
//!
//! Mirrors the C ABI (`connector::ffi::groth16`): BLS12-381 Zcash path +
//! BN254 Sui/Aptos path, over plain byte blobs. Returns bool (verify ok).

#![cfg(all(feature = "wasm", feature = "groth16"))]

use wasm_bindgen::prelude::*;

use crate::zk::groth16::codec::{
    unpack_public_inputs_sui, unpack_public_inputs_zcash, AptosProofBytes, SuiProofBytes,
    SuiVkBytes, ZcashProofBytes, ZcashVkBytes,
};
use crate::zk::groth16::{verify, verify_bn254};

fn copy(u: &[u8]) -> Vec<u8> {
    let mut v = vec![0u8; u.len() as usize];
    v.copy_from_slice(u);
    v
}

fn map_err(e: crate::zk::groth16::Groth16Error) -> JsValue {
    JsValue::from_str(match e {
        crate::zk::groth16::Groth16Error::InputLength => "E4:inputs",
        crate::zk::groth16::Groth16Error::InvalidPoint
        | crate::zk::groth16::Groth16Error::InvalidScalar => "E3:encoding",
        crate::zk::groth16::Groth16Error::InvalidLength => "E2:length",
        crate::zk::groth16::Groth16Error::VerificationFailed => "E5:verify",
    })
}

/// Verify BLS12-381 Groth16 proof (192-byte proof, Zcash vk, n*32 LE inputs).
/// Ok(true) on valid, Ok(false) on verify failure, Err "E2:length"/"E3:encoding"/"E4:inputs"/"E5:verify".
#[wasm_bindgen(js_name = groth16VerifyBls)]
pub fn groth16_verify_bls_js(
    proof: &[u8],
    vk: &[u8],
    public_inputs: &[u8],
) -> Result<bool, JsValue> {
    let pb = copy(proof);
    let vb = copy(vk);
    let ib = copy(public_inputs);
    let proof = ZcashProofBytes::decode(&pb).map_err(map_err)?;
    let vk = ZcashVkBytes::decode(&vb).map_err(map_err)?;
    let inputs = unpack_public_inputs_zcash(&ib).map_err(map_err)?;
    match verify(&vk, &inputs, &proof) {
        Ok(()) => Ok(true),
        Err(crate::zk::groth16::Groth16Error::VerificationFailed) => Ok(false),
        Err(e) => Err(map_err(e)),
    }
}

/// Verify BN254 Groth16 proof (256-byte Sui/Aptos proof, Sui vk, n*32 BE inputs).
/// Ok(true) on valid, Ok(false) on verify failure, Err "E2:length"/"E3:encoding"/"E4:inputs"/"E5:verify".
#[wasm_bindgen(js_name = groth16VerifyBn254)]
pub fn groth16_verify_bn254_js(
    proof: &[u8],
    vk: &[u8],
    public_inputs: &[u8],
) -> Result<bool, JsValue> {
    let pb = copy(proof);
    let vb = copy(vk);
    let ib = copy(public_inputs);
    let proof = SuiProofBytes::decode(&pb)
        .or_else(|_| AptosProofBytes::decode(&pb))
        .map_err(map_err)?;
    let vk = SuiVkBytes::decode(&vb).map_err(map_err)?;
    let inputs = unpack_public_inputs_sui(&ib).map_err(map_err)?;
    match verify_bn254(&vk, &inputs, &proof) {
        Ok(()) => Ok(true),
        Err(crate::zk::groth16::Groth16Error::VerificationFailed) => Ok(false),
        Err(e) => Err(map_err(e)),
    }
}

/// BLS12-381 Groth16 proof length in bytes (192).
#[wasm_bindgen(js_name = groth16BlsProofLen)]
pub fn groth16_bls_proof_len_js() -> usize {
    ZcashProofBytes::LEN
}

/// BN254 Groth16 proof length in bytes (256).
#[wasm_bindgen(js_name = groth16Bn254ProofLen)]
pub fn groth16_bn254_proof_len_js() -> usize {
    SuiProofBytes::LEN
}
