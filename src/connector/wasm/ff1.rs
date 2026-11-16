//! FF1 WASM exports.
#![cfg(all(feature = "wasm", feature = "alloc"))]

use crate::cipher::ff1::{
    ff1_decrypt_binary, ff1_decrypt_flexible, ff1_encrypt_binary, ff1_encrypt_flexible,
};
use wasm_bindgen::prelude::*;

fn u8_vec(a: &[u8]) -> Vec<u8> {
    let mut v = vec![0u8; a.len() as usize];
    v.copy_from_slice(a);
    v
}
fn to_u8(v: &[u8]) -> Vec<u8> {
    v.to_vec()
}

/// FF1 encrypt flexible digits; Err "ff1 encrypt" on bad key/radix/input.
#[wasm_bindgen(js_name = ff1Encrypt)]
pub fn ff1_encrypt_js(key: &[u8], radix: u32, pt: &[u8], tweak: &[u8]) -> Result<Vec<u8>, JsValue> {
    let ct = ff1_encrypt_flexible(&u8_vec(key), radix, &u8_vec(pt), &u8_vec(tweak))
        .map_err(|_| JsValue::from_str("ff1 encrypt"))?;
    Ok(to_u8(&ct))
}

/// FF1 decrypt flexible digits; Err "ff1 decrypt" on bad key/radix/input.
#[wasm_bindgen(js_name = ff1Decrypt)]
pub fn ff1_decrypt_js(key: &[u8], radix: u32, ct: &[u8], tweak: &[u8]) -> Result<Vec<u8>, JsValue> {
    let pt = ff1_decrypt_flexible(&u8_vec(key), radix, &u8_vec(ct), &u8_vec(tweak))
        .map_err(|_| JsValue::from_str("ff1 decrypt"))?;
    Ok(to_u8(&pt))
}

/// FF1 encrypt packed binary (radix 2); Err "ff1 encrypt binary".
#[wasm_bindgen(js_name = ff1EncryptBinary)]
pub fn ff1_encrypt_binary_js(key: &[u8], pt: &[u8], tweak: &[u8]) -> Result<Vec<u8>, JsValue> {
    let ct = ff1_encrypt_binary(&u8_vec(key), &u8_vec(pt), &u8_vec(tweak))
        .map_err(|_| JsValue::from_str("ff1 encrypt binary"))?;
    Ok(to_u8(&ct))
}

/// FF1 decrypt packed binary (radix 2); Err "ff1 decrypt binary".
#[wasm_bindgen(js_name = ff1DecryptBinary)]
pub fn ff1_decrypt_binary_js(key: &[u8], ct: &[u8], tweak: &[u8]) -> Result<Vec<u8>, JsValue> {
    let pt = ff1_decrypt_binary(&u8_vec(key), &u8_vec(ct), &u8_vec(tweak))
        .map_err(|_| JsValue::from_str("ff1 decrypt binary"))?;
    Ok(to_u8(&pt))
}
