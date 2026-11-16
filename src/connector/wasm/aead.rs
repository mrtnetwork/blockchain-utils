//! AEAD WASM exports.

use wasm_bindgen::prelude::*;

use crate::aead::{
    aes_gcm_decrypt, aes_gcm_encrypt, chacha20_poly1305_decrypt, chacha20_poly1305_encrypt,
    salsabox_beforenm, salsabox_decrypt, salsabox_encrypt, xsalsa20_poly1305_decrypt,
    xsalsa20_poly1305_encrypt,
};

fn copy(arr: &[u8]) -> Vec<u8> {
    let mut v = vec![0u8; arr.len() as usize];
    v.copy_from_slice(arr);
    v
}

fn opt_copy(a: Option<Vec<u8>>) -> Vec<u8> {
    a.map(|x| copy(&x)).unwrap_or_default()
}

/// ChaCha20-Poly1305 encrypt (key 32 bytes, nonce 8..=16 bytes).
/// `out_len` must be plaintext+16; returns ciphertext‖tag, empty array on failure.
#[wasm_bindgen(js_name = chacha20Poly1305Encrypt)]
pub fn chacha_enc(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: Option<Vec<u8>>,
    out_len: u32,
) -> Vec<u8> {
    let mut out = vec![0u8; out_len as usize];
    match chacha20_poly1305_encrypt(
        &copy(key),
        &copy(nonce),
        &copy(plaintext),
        &opt_copy(aad),
        &mut out,
    ) {
        Ok(()) => out,
        Err(_) => Vec::new(),
    }
}

/// ChaCha20-Poly1305 decrypt (ciphertext‖tag, `out_len` = ct-16).
/// Returns plaintext, `None` on auth/failure.
#[wasm_bindgen(js_name = chacha20Poly1305Decrypt)]
pub fn chacha_dec(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: Option<Vec<u8>>,
    out_len: u32,
) -> Option<Vec<u8>> {
    let mut out = vec![0u8; out_len as usize];
    match chacha20_poly1305_decrypt(
        &copy(key),
        &copy(nonce),
        &copy(ciphertext),
        &opt_copy(aad),
        &mut out,
    ) {
        Ok(()) => Some(out),
        Err(_) => None,
    }
}

/// AES-GCM encrypt (key 16/24/32 bytes, nonce 12 bytes).
/// `out_len` must be plaintext+16; returns ciphertext‖tag, empty array on failure.
#[wasm_bindgen(js_name = aesGcmEncrypt)]
pub fn aes_gcm_enc(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: Option<Vec<u8>>,
    out_len: u32,
) -> Vec<u8> {
    let mut out = vec![0u8; out_len as usize];
    match aes_gcm_encrypt(
        &copy(key),
        &copy(nonce),
        &copy(plaintext),
        &opt_copy(aad),
        &mut out,
    ) {
        Ok(()) => out,
        Err(_) => Vec::new(),
    }
}

/// AES-GCM decrypt (ciphertext‖tag, `out_len` = ct-16).
/// Returns plaintext, `None` on auth/failure.
#[wasm_bindgen(js_name = aesGcmDecrypt)]
pub fn aes_gcm_dec(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: Option<Vec<u8>>,
    out_len: u32,
) -> Option<Vec<u8>> {
    let mut out = vec![0u8; out_len as usize];
    match aes_gcm_decrypt(
        &copy(key),
        &copy(nonce),
        &copy(ciphertext),
        &opt_copy(aad),
        &mut out,
    ) {
        Ok(()) => Some(out),
        Err(_) => None,
    }
}

/// XSalsa20-Poly1305 encrypt (key 32 bytes, nonce strictly 24 bytes).
/// `out_len` must be plaintext+16; returns `TAG ‖ CIPHERTEXT`
/// (NaCl order: authenticator first), empty array on failure.
#[wasm_bindgen(js_name = xsalsa20Poly1305Encrypt)]
pub fn xsalsa_enc(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    out_len: u32,
) -> Vec<u8> {
    let mut out = vec![0u8; out_len as usize];
    match xsalsa20_poly1305_encrypt(
        &copy(key),
        &copy(nonce),
        &copy(plaintext),
        &[],
        &mut out,
    ) {
        Ok(()) => out,
        Err(_) => Vec::new(),
    }
}

/// XSalsa20-Poly1305 decrypt (`TAG ‖ CIPHERTEXT`, `out_len` = sealed-16).
/// Returns plaintext, `None` on auth/failure.
#[wasm_bindgen(js_name = xsalsa20Poly1305Decrypt)]
pub fn xsalsa_dec(
    key: &[u8],
    nonce: &[u8],
    sealed: &[u8],
    out_len: u32,
) -> Option<Vec<u8>> {
    let mut out = vec![0u8; out_len as usize];
    match xsalsa20_poly1305_decrypt(&copy(key), &copy(nonce), &copy(sealed), &[], &mut out) {
        Ok(()) => Some(out),
        Err(_) => None,
    }
}

/// NaCl `crypto_box_beforenm`: 32-byte transport key.
/// Returns 32 bytes, empty array on invalid keys / zero shared secret.
#[wasm_bindgen(js_name = salsaBoxBeforenm)]
pub fn box_beforenm(peer_public_key: &[u8], secret_key: &[u8]) -> Vec<u8> {
    match salsabox_beforenm(&copy(peer_public_key), &copy(secret_key)) {
        Ok(k) => k.to_vec(),
        Err(_) => Vec::new(),
    }
}

/// NaCl `crypto_box_easy` detached encrypt (`TAG ‖ CIPHERTEXT`).
/// `out_len` must be plaintext+16; empty array on failure.
#[wasm_bindgen(js_name = salsaBoxEncrypt)]
pub fn box_enc(
    peer_public_key: &[u8],
    secret_key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    out_len: u32,
) -> Vec<u8> {
    let mut out = vec![0u8; out_len as usize];
    match salsabox_encrypt(
        &copy(peer_public_key),
        &copy(secret_key),
        &copy(nonce),
        &copy(plaintext),
        &mut out,
    ) {
        Ok(()) => out,
        Err(_) => Vec::new(),
    }
}

/// NaCl `crypto_box_open_easy` detached decrypt.
/// Returns plaintext, `None` on auth/failure.
#[wasm_bindgen(js_name = salsaBoxDecrypt)]
pub fn box_dec(
    peer_public_key: &[u8],
    secret_key: &[u8],
    nonce: &[u8],
    sealed: &[u8],
    out_len: u32,
) -> Option<Vec<u8>> {
    let mut out = vec![0u8; out_len as usize];
    match salsabox_decrypt(
        &copy(peer_public_key),
        &copy(secret_key),
        &copy(nonce),
        &copy(sealed),
        &mut out,
    ) {
        Ok(()) => Some(out),
        Err(_) => None,
    }
}
