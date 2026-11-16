//! Sapling Groth16 WASM exports (`BuWasm.sapling*`).
//!
//! Mirrors the C ABI (`connector::ffi::sapling`): params handles plus
//! prove / verify, over packed blobs.
//!
//! - `saplingSetSpendParams(params) -> handle`
//! - `saplingSetOutputParams(params) -> handle`
//! - `saplingParamsFree(handle)`
//! - `saplingProve(handle, kind, witness) -> { proof, inputs }`
//!   packed as `proof_len_u32le ‖ proof ‖ inputs` (inputs 7/5×32B)
//! - `saplingVerify(handle, kind, proof, inputs) -> bool`
//!
//! `kind`: 0 = Spend, 1 = Output. Witness layouts match the FFI docs.

#![cfg(all(
    feature = "wasm",
    any(feature = "zcash-sapling", feature = "groth16-prover")
))]

use std::cell::RefCell;
use std::collections::HashMap;

use wasm_bindgen::prelude::*;

use super::handles::alloc_id;
use crate::zk::groth16::ZcashParameters;
use crate::zk::sapling::load_parameters;
use crate::zk::{
    build_output_witness, build_spend_witness, parse_input_scalars, prove_output_with_params,
    prove_spend_with_params, verify_output_with_params, verify_spend_with_params,
    SaplingOutputBytes, SaplingSpendBytes, GROTH_PROOF_SIZE, KIND_OUTPUT, KIND_SPEND,
    MAX_AUTH_PATH, MAX_OUTPUT_VERIFY_INPUTS, MAX_SPEND_VERIFY_INPUTS, OUTPUT_WITNESS_PACKED_LEN,
    SPEND_WITNESS_PACKED_LEN,
};

thread_local! {
    static PARAMS: RefCell<HashMap<u32, (ZcashParameters, bool)>> =
        RefCell::new(HashMap::new());
}

fn copy(u: &[u8]) -> Vec<u8> {
    let mut v = vec![0u8; u.len() as usize];
    v.copy_from_slice(u);
    v
}

fn to_js(v: &[u8]) -> Vec<u8> {
    (v).to_vec()
}

fn parse_spend_witness(buf: &[u8]) -> Result<SaplingSpendBytes, JsValue> {
    let err = || JsValue::from_str("bad spend witness");
    if buf.len() < SPEND_WITNESS_PACKED_LEN {
        return Err(err());
    }
    let mut o = 0usize;
    let mut v8 = [0u8; 8];
    v8.copy_from_slice(&buf[o..o + 8]);
    let value = u64::from_le_bytes(v8);
    o += 8;
    let mut take = |o: &mut usize| -> Result<[u8; 32], JsValue> {
        if *o + 32 > buf.len() {
            return Err(err());
        }
        let mut a = [0u8; 32];
        a.copy_from_slice(&buf[*o..*o + 32]);
        *o += 32;
        Ok(a)
    };
    let randomness = take(&mut o)?;
    let ak = take(&mut o)?;
    let nsk = take(&mut o)?;
    let payment_address_diversify_hash = take(&mut o)?;
    let commitment_randomness = take(&mut o)?;
    let ar = take(&mut o)?;
    let mut auth_path = [[0u8; 32]; MAX_AUTH_PATH];
    for i in 0..MAX_AUTH_PATH {
        auth_path[i] = take(&mut o)?;
    }
    if o + MAX_AUTH_PATH > buf.len() {
        return Err(err());
    }
    let mut auth_path_pos = [false; MAX_AUTH_PATH];
    for i in 0..MAX_AUTH_PATH {
        match buf[o] {
            0 => auth_path_pos[i] = false,
            1 => auth_path_pos[i] = true,
            _ => return Err(err()),
        }
        o += 1;
    }
    let anchor = take(&mut o)?;
    Ok(SaplingSpendBytes {
        value,
        randomness,
        ak,
        nsk,
        payment_address_diversify_hash,
        commitment_randomness,
        ar,
        auth_path,
        auth_path_pos,
        anchor,
    })
}

fn parse_output_witness(buf: &[u8]) -> Result<SaplingOutputBytes, JsValue> {
    let err = || JsValue::from_str("bad output witness");
    if buf.len() < OUTPUT_WITNESS_PACKED_LEN {
        return Err(err());
    }
    let mut o = 0usize;
    let mut v8 = [0u8; 8];
    v8.copy_from_slice(&buf[o..o + 8]);
    let value = u64::from_le_bytes(v8);
    o += 8;
    let mut take = |o: &mut usize| -> Result<[u8; 32], JsValue> {
        if *o + 32 > buf.len() {
            return Err(err());
        }
        let mut a = [0u8; 32];
        a.copy_from_slice(&buf[*o..*o + 32]);
        *o += 32;
        Ok(a)
    };
    let randomness = take(&mut o)?;
    let recipient_address_diversify_hash = take(&mut o)?;
    let recipient_address_pk_d = take(&mut o)?;
    let commitment_randomness = take(&mut o)?;
    let esk = take(&mut o)?;
    Ok(SaplingOutputBytes {
        value,
        randomness,
        recipient_address_diversify_hash,
        recipient_address_pk_d,
        commitment_randomness,
        esk,
    })
}

fn with_params<T>(
    handle: u32,
    f: impl FnOnce(&(ZcashParameters, bool)) -> Result<T, JsValue>,
) -> Result<T, JsValue> {
    PARAMS.with(|m| {
        let m = m.borrow();
        match m.get(&handle) {
            Some(p) => f(p),
            None => Err(JsValue::from_str("bad params handle")),
        }
    })
}

fn scalar_le_bytes(s: &crate::curve::bls::Scalar) -> [u8; 32] {
    let mut b = [0u8; 32];
    s.to_bytes_le(&mut b);
    b
}

/// Load Spend ceremony params bytes; returns a handle. Err `bad params` on parse failure.
#[wasm_bindgen(js_name = saplingSetSpendParams)]
pub fn sapling_set_spend_params(params: &[u8]) -> Result<u32, JsValue> {
    let bytes = copy(params);
    let loaded = load_parameters(&bytes, false).map_err(|_| JsValue::from_str("bad params"))?;
    let id = alloc_id();
    PARAMS.with(|m| {
        m.borrow_mut().insert(id, (loaded, true));
    });
    Ok(id)
}

/// Load Output ceremony params bytes; returns a handle. Err `bad params` on parse failure.
#[wasm_bindgen(js_name = saplingSetOutputParams)]
pub fn sapling_set_output_params(params: &[u8]) -> Result<u32, JsValue> {
    let bytes = copy(params);
    let loaded = load_parameters(&bytes, false).map_err(|_| JsValue::from_str("bad params"))?;
    let id = alloc_id();
    PARAMS.with(|m| {
        m.borrow_mut().insert(id, (loaded, false));
    });
    Ok(id)
}

/// Free a params handle.
#[wasm_bindgen(js_name = saplingParamsFree)]
pub fn sapling_params_free(handle: u32) {
    PARAMS.with(|m| {
        m.borrow_mut().remove(&handle);
    });
}

/// Prove under a params handle (`kind` 0 Spend / 1 Output); returns `proof_len_u32le ‖ proof ‖ inputs`.
/// Err `bad spend witness`/`bad output witness` on bad witness, `kind/handle mismatch` on wrong handle, `prove` on failure.
#[wasm_bindgen(js_name = saplingProve)]
pub fn sapling_prove(handle: u32, kind: u32, witness: &[u8]) -> Result<Vec<u8>, JsValue> {
    let buf = copy(witness);
    with_params(handle, |(params, is_spend)| match kind {
        k if k == KIND_SPEND as u32 => {
            if !is_spend {
                return Err(JsValue::from_str("kind/handle mismatch"));
            }
            let w = parse_spend_witness(&buf)?;
            let full = build_spend_witness(&w).map_err(|_| JsValue::from_str("bad witness"))?;
            let (out, _) =
                prove_spend_with_params(params, &full).map_err(|_| JsValue::from_str("prove"))?;
            let mut packed =
                Vec::with_capacity(4 + GROTH_PROOF_SIZE + out.public_inputs.len() * 32);
            packed.extend_from_slice(&(out.proof.len() as u32).to_le_bytes());
            packed.extend_from_slice(&out.proof);
            for s in &out.public_inputs {
                packed.extend_from_slice(&scalar_le_bytes(s));
            }
            Ok(to_js(&packed))
        }
        k if k == KIND_OUTPUT as u32 => {
            if *is_spend {
                return Err(JsValue::from_str("kind/handle mismatch"));
            }
            let w = parse_output_witness(&buf)?;
            let full = build_output_witness(&w);
            let (out, _) =
                prove_output_with_params(params, &full).map_err(|_| JsValue::from_str("prove"))?;
            let mut packed =
                Vec::with_capacity(4 + GROTH_PROOF_SIZE + out.public_inputs.len() * 32);
            packed.extend_from_slice(&(out.proof.len() as u32).to_le_bytes());
            packed.extend_from_slice(&out.proof);
            for s in &out.public_inputs {
                packed.extend_from_slice(&scalar_le_bytes(s));
            }
            Ok(to_js(&packed))
        }
        _ => Err(JsValue::from_str("bad kind")),
    })
}

/// Verify a 192-byte proof against positional inputs (7×32B Spend, 5×32B Output); returns validity.
/// Err `bad proof length`/`kind/length mismatch` on bad sizes, `bad inputs` on bad scalars.
#[wasm_bindgen(js_name = saplingVerify)]
pub fn sapling_verify(
    handle: u32,
    kind: u32,
    proof: &[u8],
    inputs: &[u8],
) -> Result<bool, JsValue> {
    let proof_bytes = copy(proof);
    if proof_bytes.len() != GROTH_PROOF_SIZE {
        return Err(JsValue::from_str("bad proof length"));
    }
    let mut proof_arr = [0u8; GROTH_PROOF_SIZE];
    proof_arr.copy_from_slice(&proof_bytes);
    let inst_bytes = copy(inputs);
    with_params(handle, |(params, is_spend)| match kind {
        k if k == KIND_SPEND as u32 => {
            if !is_spend || inst_bytes.len() != MAX_SPEND_VERIFY_INPUTS * 32 {
                return Err(JsValue::from_str("kind/length mismatch"));
            }
            let mut limbs = [[0u8; 32]; MAX_SPEND_VERIFY_INPUTS];
            for (i, limb) in limbs.iter_mut().enumerate() {
                limb.copy_from_slice(&inst_bytes[i * 32..(i + 1) * 32]);
            }
            let scalars =
                parse_input_scalars(&limbs).map_err(|_| JsValue::from_str("bad inputs"))?;
            Ok(verify_spend_with_params(params, &proof_arr, &scalars).is_ok())
        }
        k if k == KIND_OUTPUT as u32 => {
            if *is_spend || inst_bytes.len() != MAX_OUTPUT_VERIFY_INPUTS * 32 {
                return Err(JsValue::from_str("kind/length mismatch"));
            }
            let mut limbs = [[0u8; 32]; MAX_OUTPUT_VERIFY_INPUTS];
            for (i, limb) in limbs.iter_mut().enumerate() {
                limb.copy_from_slice(&inst_bytes[i * 32..(i + 1) * 32]);
            }
            let scalars =
                parse_input_scalars(&limbs).map_err(|_| JsValue::from_str("bad inputs"))?;
            Ok(verify_output_with_params(params, &proof_arr, &scalars).is_ok())
        }
        _ => Err(JsValue::from_str("bad kind")),
    })
}

/// Presence probe for a params handle (legacy `has_*_params` equivalent).
#[wasm_bindgen(js_name = saplingHasSpendParams)]
pub fn sapling_has_spend_params(handle: u32) -> bool {
    PARAMS.with(|m| {
        m.borrow()
            .get(&handle)
            .map(|(_, is_spend)| *is_spend)
            .unwrap_or(false)
    })
}

/// Presence probe for a params handle (legacy `has_*_params` equivalent).
#[wasm_bindgen(js_name = saplingHasOutputParams)]
pub fn sapling_has_output_params(handle: u32) -> bool {
    PARAMS.with(|m| {
        m.borrow()
            .get(&handle)
            .map(|(_, is_spend)| !is_spend)
            .unwrap_or(false)
    })
}

/// Jubjub Pedersen hash over packed LSB-first bits.
/// `has_personalization`: 0 → NoteCommitment domain, else MerkleTree
/// `layer` (must be < 64). Returns 32-byte compressed point.
#[wasm_bindgen(js_name = saplingPedersenHash)]
pub fn sapling_pedersen_hash(
    bits: &[u8],
    has_personalization: u32,
    layer: u8,
) -> Result<Vec<u8>, JsValue> {
    use crate::hash::pedersen::{PedersenHash, Personalization};
    let bytes = copy(bits);
    let pers = match has_personalization {
        0 => Personalization::NoteCommitment,
        _ => {
            if layer > 63 {
                return Err(JsValue::from_str("bad layer"));
            }
            Personalization::MerkleTree { layer }
        }
    };
    let mut bools = Vec::with_capacity(bytes.len().saturating_mul(8));
    for b in bytes {
        for i in 0..8 {
            bools.push(((b >> i) & 1) == 1);
        }
    }
    let hasher = PedersenHash::new().map_err(|_| JsValue::from_str("internal"))?;
    let point = hasher.hash(pers, &bools);
    let (u, v) = point
        .affine_uv()
        .map_err(|_| JsValue::from_str("internal"))?;
    let mut ube = [0u8; 32];
    let mut vbe = [0u8; 32];
    u.to_bytes_be(&mut ube);
    v.to_bytes_be(&mut vbe);
    let mut enc = [0u8; 32];
    for i in 0..32 {
        enc[i] = vbe[31 - i];
    }
    if ube[31] & 1 == 1 {
        enc[31] |= 0x80;
    }
    Ok(enc.to_vec())
}
