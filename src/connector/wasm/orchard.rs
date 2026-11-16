//! Orchard Action prove/verify WASM exports (`BuWasm.orchard*`).
//!
//! Backend is `zk::orchard_halo2` via its field-level [`bridge`]; same wire
//! as the C ABI (`connector::ffi::orchard`): 1716-byte circuit blobs,
//! 10-wide instance limbs, 32-byte blinding seed per prove call.
//!
//! - `orchardPkNew(version) -> handle`
//! - `orchardPkFree(handle)`
//! - `orchardCreateProof(handle, inputs, instances, version, disable, seed)`
//!   `-> proof bytes`
//! - `orchardVerifyProof(handle, proof, instances, version, disable) -> bool`
//!
//! Versions 0/1/2; flag strict to version 2 (row-9 rule inside).

#![cfg(all(feature = "wasm", feature = "orchard-halo2"))]

use std::cell::RefCell;
use std::collections::HashMap;

use wasm_bindgen::prelude::*;

use super::handles::alloc_id;
use crate::zk::orchard_halo2::bridge::{self, CIRCUIT_BLOB_LEN, INSTANCE_BLOB_LEN, SEED_LEN};
use crate::zk::orchard_halo2::error::OrchardError;
use crate::zk::orchard_halo2::orchard::circuit::OrchardProtocolVersion;
use crate::zk::orchard_halo2::orchard::prover::DefaultOrchardProver;

thread_local! {
    static PKS: RefCell<HashMap<u32, (DefaultOrchardProver, OrchardProtocolVersion)>> =
        RefCell::new(HashMap::new());
}

fn copy(u: &[u8]) -> Vec<u8> {
    let mut v = vec![0u8; u.len() as usize];
    v.copy_from_slice(u);
    v
}

fn err_code(e: OrchardError) -> JsValue {
    JsValue::from_str(match e {
        OrchardError::Ok => "ok",
        OrchardError::Null => "null",
        OrchardError::InvalidLength => "bad length",
        OrchardError::InvalidEncoding => "bad encoding",
        OrchardError::ProveFailed => "prove",
        OrchardError::VerifyFailed => "verify",
        OrchardError::Internal => "internal",
    })
}

fn parse_flag(flag: u32) -> Option<bool> {
    match flag {
        0 => Some(false),
        1 => Some(true),
        _ => None,
    }
}

fn with_pk<T>(
    handle: u32,
    f: impl FnOnce(&DefaultOrchardProver) -> Result<T, JsValue>,
) -> Result<T, JsValue> {
    PKS.with(|m| {
        let m = m.borrow();
        match m.get(&handle) {
            Some((pk, _)) => f(pk),
            None => Err(JsValue::from_str("bad proving-key handle")),
        }
    })
}

fn with_pk_version<T>(
    handle: u32,
    f: impl FnOnce(&DefaultOrchardProver, OrchardProtocolVersion) -> Result<T, JsValue>,
) -> Result<T, JsValue> {
    PKS.with(|m| {
        let m = m.borrow();
        match m.get(&handle) {
            Some((pk, v)) => f(pk, *v),
            None => Err(JsValue::from_str("bad proving-key handle")),
        }
    })
}

/// Build a proving key for version discriminant (0/1/2); returns its handle.
/// Err `bad version` on unknown version, `keygen` on build failure.
#[wasm_bindgen(js_name = orchardPkNew)]
pub fn orchard_pk_new(version: u32) -> Result<u32, JsValue> {
    let v = bridge::parse_version(version).map_err(err_code)?;
    let pk = bridge::build_prover(v).map_err(|_| JsValue::from_str("keygen"))?;
    let id = alloc_id();
    PKS.with(|m| {
        m.borrow_mut().insert(id, (pk, v));
    });
    Ok(id)
}

/// Free a proving-key handle.
#[wasm_bindgen(js_name = orchardPkFree)]
pub fn orchard_pk_free(handle: u32) {
    PKS.with(|m| {
        m.borrow_mut().remove(&handle);
    });
}

/// Prove N Actions from `n * 1716` circuit blobs + `n * 320` instance limbs
/// with a 32-byte blinding `seed`; returns proof bytes.
#[wasm_bindgen(js_name = orchardCreateProof)]
pub fn orchard_create_proof(
    handle: u32,
    inputs: &[u8],
    instances: &[u8],
    version: u32,
    disable_cross_address: u32,
    seed: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let v = bridge::parse_version(version).map_err(err_code)?;
    let flag = parse_flag(disable_cross_address).ok_or_else(|| JsValue::from_str("bad flag"))?;
    if flag && version != 2 {
        return Err(JsValue::from_str("bad flag"));
    }
    let circuits = copy(inputs);
    if circuits.is_empty() || circuits.len() % CIRCUIT_BLOB_LEN != 0 {
        return Err(JsValue::from_str("bad inputs length"));
    }
    let n = circuits.len() / CIRCUIT_BLOB_LEN;
    let inst_bytes = copy(instances);
    if inst_bytes.len() != n * INSTANCE_BLOB_LEN {
        return Err(JsValue::from_str("bad instances length"));
    }
    if seed.len() != SEED_LEN {
        return Err(JsValue::from_str("bad seed length"));
    }
    let mut seed_arr = [0u8; SEED_LEN];
    seed_arr.copy_from_slice(seed);
    let parsed_inst = bridge::parse_instances(&inst_bytes, v, flag).map_err(err_code)?;
    with_pk_version(handle, |pk, kv| {
        if v != kv {
            return Err(JsValue::from_str("version mismatch"));
        }
        bridge::create_proof(pk, &circuits, &seed_arr, v, parsed_inst).map_err(err_code)
    })
}

/// Verify a proof against `n * 320` instance limbs; returns validity.
#[wasm_bindgen(js_name = orchardVerifyProof)]
pub fn orchard_verify_proof(
    handle: u32,
    proof: &[u8],
    instances: &[u8],
    version: u32,
    disable_cross_address: u32,
) -> Result<bool, JsValue> {
    let v = bridge::parse_version(version).map_err(err_code)?;
    let flag = parse_flag(disable_cross_address).ok_or_else(|| JsValue::from_str("bad flag"))?;
    if flag && version != 2 {
        return Err(JsValue::from_str("bad flag"));
    }
    let proof_bytes = copy(proof);
    if proof_bytes.is_empty() {
        return Err(JsValue::from_str("empty proof"));
    }
    let inst_bytes = copy(instances);
    if inst_bytes.is_empty() || inst_bytes.len() % INSTANCE_BLOB_LEN != 0 {
        return Err(JsValue::from_str("bad instances length"));
    }
    let parsed_inst = bridge::parse_instances(&inst_bytes, v, flag).map_err(err_code)?;
    with_pk_version(handle, |pk, kv| {
        if v != kv {
            return Err(JsValue::from_str("version mismatch"));
        }
        bridge::verify_proof(pk, &proof_bytes, &parsed_inst).map_err(err_code)
    })
}
