//! X25519 WASM exports (RFC 7748).
#![cfg(all(feature = "wasm", feature = "alloc"))]

use crate::curve::x25519::{
    diffie_hellman, ed25519_pk_to_x25519, ed25519_seed_to_x25519, public_key, x25519,
};
use wasm_bindgen::prelude::*;

fn read32(a: &[u8]) -> Result<[u8; 32], JsValue> {
    if a.len() != 32 {
        return Err(JsValue::from_str("x25519: need 32 bytes"));
    }
    let mut b = [0u8; 32];
    b.copy_from_slice(a);
    Ok(b)
}
fn to_u8(v: &[u8]) -> Vec<u8> {
    v.to_vec()
}

/// Raw `X25519(k, u)` with 32-byte scalar and point → 32 bytes; `Err("x25519: need 32 bytes")`.
#[wasm_bindgen(js_name = x25519)]
pub fn x25519_js(k: &[u8], u: &[u8]) -> Result<Vec<u8>, JsValue> {
    let r = x25519(&read32(k)?, &read32(u)?);
    Ok(to_u8(&r))
}

/// X25519 public key from 32-byte private (`X(k, 9)`); `Err("x25519: need 32 bytes")`.
#[wasm_bindgen(js_name = x25519PublicKey)]
pub fn x25519_public_key_js(private_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    Ok(to_u8(&public_key(&read32(private_key)?)))
}

/// X25519 DH shared secret, rejects all-zero output; `Err("dh"|"x25519: need 32 bytes")`.
#[wasm_bindgen(js_name = x25519Dh)]
pub fn x25519_dh_js(private_key: &[u8], peer: &[u8]) -> Result<Vec<u8>, JsValue> {
    let r = diffie_hellman(&read32(private_key)?, &read32(peer)?)
        .map_err(|_| JsValue::from_str("dh"))?;
    Ok(to_u8(&r))
}

/// Ed25519 compressed pk (32) → X25519 pk (32); `Err("convert"|"x25519: need 32 bytes")`.
#[wasm_bindgen(js_name = ed25519PkToX25519)]
pub fn ed25519_pk_to_x25519_js(ed_pk: &[u8]) -> Result<Vec<u8>, JsValue> {
    let r = ed25519_pk_to_x25519(&read32(ed_pk)?).map_err(|_| JsValue::from_str("convert"))?;
    Ok(to_u8(&r))
}

/// Ed25519 32-byte seed → X25519 private key; `Err("x25519: need 32 bytes")`.
#[wasm_bindgen(js_name = ed25519SeedToX25519)]
pub fn ed25519_seed_to_x25519_js(seed: &[u8]) -> Result<Vec<u8>, JsValue> {
    Ok(to_u8(&ed25519_seed_to_x25519(&read32(seed)?)))
}
