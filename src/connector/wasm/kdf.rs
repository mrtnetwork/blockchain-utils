//! KDF WASM exports: PBKDF2, scrypt, HKDF.

use wasm_bindgen::prelude::*;

use crate::hash::hkdf::{hkdf_expand_sha512, hkdf_extract_sha512, hkdf_sha256};
use crate::hash::pbkdf2::{pbkdf2_hmac_sha256, pbkdf2_hmac_sha512};
use crate::hash::scrypt::{scrypt, ScryptParams};

fn copy(arr: &[u8]) -> Vec<u8> {
    let mut v = vec![0u8; arr.len() as usize];
    v.copy_from_slice(arr);
    v
}

fn hkdf_sha512(salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) -> Result<(), ()> {
    let mut prk = [0u8; 64];
    hkdf_extract_sha512(salt, ikm, &mut prk).map_err(|_| ())?;
    hkdf_expand_sha512(&prk, info, okm).map_err(|_| ())
}

/// prf: 1 = HMAC-SHA256, 2 = HMAC-SHA512
#[wasm_bindgen(js_name = pbkdf2)]
pub fn wasm_pbkdf2(
    prf: u32,
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    out_len: u32,
) -> Vec<u8> {
    let pw = copy(password);
    let sa = copy(salt);
    let mut out = vec![0u8; out_len as usize];
    let ok = match prf {
        2 => pbkdf2_hmac_sha512(&pw, &sa, iterations, &mut out).is_ok(),
        _ => pbkdf2_hmac_sha256(&pw, &sa, iterations, &mut out).is_ok(),
    };
    if ok {
        out
    } else {
        Vec::new()
    }
}

/// scrypt (RFC 7914) with N=`n`, r=`r`, p=`p`.
/// Returns `out_len` bytes, empty array on failure.
#[wasm_bindgen(js_name = scrypt)]
pub fn wasm_scrypt(password: &[u8], salt: &[u8], n: u32, r: u32, p: u32, out_len: u32) -> Vec<u8> {
    let pw = copy(password);
    let sa = copy(salt);
    let mut out = vec![0u8; out_len as usize];
    let params = ScryptParams { n, r, p };
    match scrypt(&pw, &sa, params, &mut out) {
        Ok(()) => out,
        Err(_) => Vec::new(),
    }
}

/// HKDF (prf 1=SHA256, 2=SHA512 — connector KDF ids, same as FFI).
/// Returns `out_len` bytes, empty array on failure or unknown prf
/// (unknown ids fail loudly instead of silently falling back to SHA-256).
#[wasm_bindgen(js_name = hkdf)]
pub fn wasm_hkdf(
    prf: u32,
    ikm: &[u8],
    salt: Option<Vec<u8>>,
    info: Option<Vec<u8>>,
    out_len: u32,
) -> Vec<u8> {
    let ikm = copy(ikm);
    let salt = salt.map(|a| copy(&a)).unwrap_or_default();
    let info = info.map(|a| copy(&a)).unwrap_or_default();
    let mut out = vec![0u8; out_len as usize];
    let ok = match prf {
        1 => hkdf_sha256(&salt, &ikm, &info, &mut out).is_ok(),
        2 => hkdf_sha512(&salt, &ikm, &info, &mut out).is_ok(),
        _ => false,
    };
    if ok {
        out
    } else {
        Vec::new()
    }
}
