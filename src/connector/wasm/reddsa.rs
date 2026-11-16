//! RedDSA WASM exports.
#![cfg(all(feature = "wasm", feature = "alloc"))]
use crate::signature::reddsa;
use wasm_bindgen::prelude::*;

fn sk32(sk: &[u8]) -> Result<[u8; 32], JsValue> {
    if sk.len() != 32 {
        return Err(JsValue::from_str("sk"));
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(sk);
    Ok(a)
}

/// Empty or missing rand is rejected: signing randomness is
/// caller-supplied (80 bytes), never generated here.
fn r80(r: Option<Vec<u8>>) -> Result<[u8; 80], JsValue> {
    let mut a = [0u8; 80];
    match r {
        Some(v) if v.len() == 80 => a.copy_from_slice(&v),
        _ => return Err(JsValue::from_str("rand must be 80 bytes")),
    }
    Ok(a)
}

/// Jubjub SpendAuth sign `msg` with 32-byte sk (+ optional 80-byte rand) → 64-byte sig; `Err("sk"|"sign")`.
#[wasm_bindgen(js_name = reddsaJubjubAuthSign)]
pub fn jubjub_auth_sign(
    sk: &[u8],
    msg: &[u8],
    rand80: Option<Vec<u8>>,
) -> Result<Vec<u8>, JsValue> {
    reddsa::jubjub_auth_sign(&sk32(sk)?, msg, &r80(rand80)?)
        .map(|s| s.to_vec())
        .map_err(|_| JsValue::from_str("sign"))
}
/// Jubjub SpendAuth verify 32-byte pk + 64-byte sig over `msg`; returns bool.
#[wasm_bindgen(js_name = reddsaJubjubAuthVerify)]
pub fn jubjub_auth_verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    if pk.len() != 32 || sig.len() != 64 {
        return false;
    }
    let mut p = [0u8; 32];
    p.copy_from_slice(pk);
    let mut s = [0u8; 64];
    s.copy_from_slice(sig);
    reddsa::jubjub_auth_verify(&p, msg, &s)
}
/// Jubjub Binding sign `msg` with 32-byte sk (+ optional 80-byte rand) → 64-byte sig; `Err("sk"|"sign")`.
#[wasm_bindgen(js_name = reddsaJubjubBindingSign)]
pub fn jubjub_binding_sign(
    sk: &[u8],
    msg: &[u8],
    rand80: Option<Vec<u8>>,
) -> Result<Vec<u8>, JsValue> {
    reddsa::jubjub_binding_sign(&sk32(sk)?, msg, &r80(rand80)?)
        .map(|s| s.to_vec())
        .map_err(|_| JsValue::from_str("sign"))
}
/// Jubjub Binding verify 32-byte pk + 64-byte sig over `msg`; returns bool.
#[wasm_bindgen(js_name = reddsaJubjubBindingVerify)]
pub fn jubjub_binding_verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    if pk.len() != 32 || sig.len() != 64 {
        return false;
    }
    let mut p = [0u8; 32];
    p.copy_from_slice(pk);
    let mut s = [0u8; 64];
    s.copy_from_slice(sig);
    reddsa::jubjub_binding_verify(&p, msg, &s)
}
/// Pallas SpendAuth sign `msg` with 32-byte sk (+ optional 80-byte rand) → 64-byte sig; `Err("sk"|"sign")`.
#[wasm_bindgen(js_name = reddsaPallasAuthSign)]
pub fn pallas_auth_sign(
    sk: &[u8],
    msg: &[u8],
    rand80: Option<Vec<u8>>,
) -> Result<Vec<u8>, JsValue> {
    reddsa::pallas_auth_sign(&sk32(sk)?, msg, &r80(rand80)?)
        .map(|s| s.to_vec())
        .map_err(|_| JsValue::from_str("sign"))
}
/// Pallas SpendAuth verify 32-byte pk + 64-byte sig over `msg`; returns bool.
#[wasm_bindgen(js_name = reddsaPallasAuthVerify)]
pub fn pallas_auth_verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    if pk.len() != 32 || sig.len() != 64 {
        return false;
    }
    let mut p = [0u8; 32];
    p.copy_from_slice(pk);
    let mut s = [0u8; 64];
    s.copy_from_slice(sig);
    reddsa::pallas_auth_verify(&p, msg, &s)
}
/// Pallas Binding sign `msg` with 32-byte sk (+ optional 80-byte rand) → 64-byte sig; `Err("sk"|"sign")`.
#[wasm_bindgen(js_name = reddsaPallasBindingSign)]
pub fn pallas_binding_sign(
    sk: &[u8],
    msg: &[u8],
    rand80: Option<Vec<u8>>,
) -> Result<Vec<u8>, JsValue> {
    reddsa::pallas_binding_sign(&sk32(sk)?, msg, &r80(rand80)?)
        .map(|s| s.to_vec())
        .map_err(|_| JsValue::from_str("sign"))
}
/// Pallas Binding verify 32-byte pk + 64-byte sig over `msg`; returns bool.
#[wasm_bindgen(js_name = reddsaPallasBindingVerify)]
pub fn pallas_binding_verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    if pk.len() != 32 || sig.len() != 64 {
        return false;
    }
    let mut p = [0u8; 32];
    p.copy_from_slice(pk);
    let mut s = [0u8; 64];
    s.copy_from_slice(sig);
    reddsa::pallas_binding_verify(&p, msg, &s)
}

/// Jubjub SpendAuth public key (32 bytes) from 32-byte secret; `Err("sk"|"pk")`.
#[wasm_bindgen(js_name = reddsaJubjubAuthPk)]
pub fn jubjub_auth_pk(sk: &[u8]) -> Result<Vec<u8>, JsValue> {
    let ska = sk32(sk)?;
    let base = reddsa::jubjub_spend_auth_generator();
    reddsa::jubjub_public_from_secret(&ska, &base)
        .map(|p| p.to_vec())
        .map_err(|_| JsValue::from_str("pk"))
}
/// Jubjub Binding public key (32 bytes) from 32-byte secret; `Err("sk"|"pk")`.
#[wasm_bindgen(js_name = reddsaJubjubBindingPk)]
pub fn jubjub_binding_pk(sk: &[u8]) -> Result<Vec<u8>, JsValue> {
    let ska = sk32(sk)?;
    let base = reddsa::jubjub_binding_generator();
    reddsa::jubjub_public_from_secret(&ska, &base)
        .map(|p| p.to_vec())
        .map_err(|_| JsValue::from_str("pk"))
}
/// Pallas SpendAuth public key (32 bytes) from 32-byte secret; `Err("sk"|"pk")`.
#[wasm_bindgen(js_name = reddsaPallasAuthPk)]
pub fn pallas_auth_pk(sk: &[u8]) -> Result<Vec<u8>, JsValue> {
    let ska = sk32(sk)?;
    let base = reddsa::pallas_spend_auth_generator();
    reddsa::pallas_public_from_secret(&ska, &base)
        .map(|p| p.to_vec())
        .map_err(|_| JsValue::from_str("pk"))
}
/// Pallas Binding public key (32 bytes) from 32-byte secret; `Err("sk"|"pk")`.
#[wasm_bindgen(js_name = reddsaPallasBindingPk)]
pub fn pallas_binding_pk(sk: &[u8]) -> Result<Vec<u8>, JsValue> {
    let ska = sk32(sk)?;
    let base = reddsa::pallas_binding_generator();
    reddsa::pallas_public_from_secret(&ska, &base)
        .map(|p| p.to_vec())
        .map_err(|_| JsValue::from_str("pk"))
}
