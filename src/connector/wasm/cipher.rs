//! Block / stream cipher WASM exports.

use std::cell::RefCell;
use std::collections::HashMap;

use wasm_bindgen::prelude::*;

use crate::cipher::aes::Aes;
use crate::cipher::block::BlockCipher;
use crate::cipher::chacha20::chacha20_xor;

use super::handles::alloc_id;

thread_local! {
    static AES: RefCell<HashMap<u32, Aes>> = RefCell::new(HashMap::new());
}

fn copy(arr: &[u8]) -> Vec<u8> {
    let mut v = vec![0u8; arr.len() as usize];
    v.copy_from_slice(arr);
    v
}

/// Create AES schedule from 16/24/32-byte key; returns handle, 0 on bad key len.
#[wasm_bindgen(js_name = aesNew)]
pub fn aes_new(key: &[u8]) -> u32 {
    let k = copy(key);
    let aes = match k.len() {
        16 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(&k);
            Aes::aes128(&a)
        }
        24 => {
            let mut a = [0u8; 24];
            a.copy_from_slice(&k);
            Aes::aes192(&a)
        }
        32 => {
            let mut a = [0u8; 32];
            a.copy_from_slice(&k);
            Aes::aes256(&a)
        }
        _ => return 0,
    };
    let id = alloc_id();
    AES.with(|m| m.borrow_mut().insert(id, aes));
    id
}

/// Free AES handle.
#[wasm_bindgen(js_name = aesFree)]
pub fn aes_free(handle: u32) {
    AES.with(|m| {
        m.borrow_mut().remove(&handle);
    });
}

/// Encrypt one 16-byte block (first 16 bytes of `src`); returns 16 bytes.
#[wasm_bindgen(js_name = aesEncryptBlock)]
pub fn aes_encrypt_block(handle: u32, src: &[u8]) -> Vec<u8> {
    let s = copy(src);
    let mut block = [0u8; 16];
    if s.len() >= 16 {
        block.copy_from_slice(&s[..16]);
    }
    AES.with(|m| {
        if let Some(aes) = m.borrow().get(&handle) {
            let _ = aes.encrypt_block(&mut block);
        }
    });
    (&block[..]).to_vec()
}

/// Decrypt one 16-byte block (first 16 bytes of `src`); returns 16 bytes.
#[wasm_bindgen(js_name = aesDecryptBlock)]
pub fn aes_decrypt_block(handle: u32, src: &[u8]) -> Vec<u8> {
    let s = copy(src);
    let mut block = [0u8; 16];
    if s.len() >= 16 {
        block.copy_from_slice(&s[..16]);
    }
    AES.with(|m| {
        if let Some(aes) = m.borrow().get(&handle) {
            let _ = aes.decrypt_block(&mut block);
        }
    });
    (&block[..]).to_vec()
}

/// AES-CBC encrypt (key 16/24/32, iv 16, data multiple of 16).
/// Returns ciphertext, empty array on failure.
#[wasm_bindgen(js_name = aesCbcEncrypt)]
pub fn aes_cbc_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Vec<u8> {
    use crate::cipher::modes::cbc;
    if iv.len() != 16 || plaintext.len() % 16 != 0 {
        return Vec::new();
    }
    let mut iv_arr = [0u8; 16];
    iv_arr.copy_from_slice(iv);
    let mut out = vec![0u8; plaintext.len()];
    match cbc::aes_cbc_encrypt(&copy(key), &iv_arr, &copy(plaintext), &mut out) {
        Ok(()) => out,
        Err(_) => Vec::new(),
    }
}

/// AES-CBC decrypt (key 16/24/32, iv 16, data multiple of 16).
/// Returns plaintext, empty array on failure.
#[wasm_bindgen(js_name = aesCbcDecrypt)]
pub fn aes_cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    use crate::cipher::modes::cbc;
    if iv.len() != 16 || ciphertext.len() % 16 != 0 {
        return Vec::new();
    }
    let mut iv_arr = [0u8; 16];
    iv_arr.copy_from_slice(iv);
    let mut out = vec![0u8; ciphertext.len()];
    match cbc::aes_cbc_decrypt(&copy(key), &iv_arr, &copy(ciphertext), &mut out) {
        Ok(()) => out,
        Err(_) => Vec::new(),
    }
}

/// ChaCha20 XOR (key 32 bytes, nonce 12 bytes, `counter`).
/// Returns xored bytes, empty array on failure.
#[wasm_bindgen(js_name = chacha20Xor)]
pub fn wasm_chacha20_xor(key: &[u8], nonce: &[u8], counter: u32, data: &[u8]) -> Vec<u8> {
    let src = copy(data);
    let mut out = vec![0u8; src.len()];
    match chacha20_xor(&copy(key), &copy(nonce), counter, &src, &mut out) {
        Ok(()) => out,
        Err(_) => Vec::new(),
    }
}

/// ChaCha20 stream XOR with seek + optional in-place counter layout
/// (mirrors `bu_chacha20_stream_xor`; arg order matches the caller).
#[wasm_bindgen(js_name = chacha20StreamXor)]
pub fn wasm_chacha20_stream_xor(
    key: &[u8],
    nonce: &[u8],
    data: &[u8],
    counter_len: u32,
    seek: u32,
) -> Result<Vec<u8>, JsValue> {
    use crate::cipher::chacha20::stream_xor;
    let src = copy(data);
    let mut out = vec![0u8; src.len()];
    stream_xor(
        &copy(key),
        &copy(nonce),
        &src,
        &mut out,
        counter_len as usize,
        seek as usize,
    )
    .map_err(|_| JsValue::from_str("chacha20 stream xor failed"))?;
    Ok(out)
}

use crate::cipher::{
    aes_ctr, aes_ecb_decrypt, aes_ecb_decrypt_padded, aes_ecb_encrypt, aes_ecb_encrypt_padded,
    padded_len, PaddingAlgorithm,
};

/// AES-CTR crypt (`nonce` 16-byte counter block).
/// Err "nonce must be 16 bytes"/"aes_ctr failed" on failure.
#[wasm_bindgen(js_name = aesCtr)]
pub fn aes_ctr_js(key: &[u8], nonce: &[u8], data: &[u8]) -> Result<Vec<u8>, JsValue> {
    let k = copy(key);
    let n = copy(nonce);
    let d = copy(data);
    if n.len() != 16 {
        return Err(JsValue::from_str("nonce must be 16 bytes"));
    }
    let mut nb = [0u8; 16];
    nb.copy_from_slice(&n);
    let mut out = vec![0u8; d.len()];
    aes_ctr(&k, &nb, &d, &mut out).map_err(|_| JsValue::from_str("aes_ctr failed"))?;
    Ok(out)
}

/// AES-ECB encrypt (no padding, data multiple of 16).
/// Err "aes_ecb_encrypt failed" on failure.
#[wasm_bindgen(js_name = aesEcbEncrypt)]
pub fn aes_ecb_encrypt_js(key: &[u8], data: &[u8]) -> Result<Vec<u8>, JsValue> {
    let k = copy(key);
    let d = copy(data);
    let mut out = vec![0u8; d.len()];
    aes_ecb_encrypt(&k, &d, &mut out).map_err(|_| JsValue::from_str("aes_ecb_encrypt failed"))?;
    Ok(out)
}

/// AES-ECB decrypt (no padding, data multiple of 16).
/// Err "aes_ecb_decrypt failed" on failure.
#[wasm_bindgen(js_name = aesEcbDecrypt)]
pub fn aes_ecb_decrypt_js(key: &[u8], data: &[u8]) -> Result<Vec<u8>, JsValue> {
    let k = copy(key);
    let d = copy(data);
    let mut out = vec![0u8; d.len()];
    aes_ecb_decrypt(&k, &d, &mut out).map_err(|_| JsValue::from_str("aes_ecb_decrypt failed"))?;
    Ok(out)
}

/// `pad`: 0=None, 1=PKCS7, 2=ISO7816, 3=X923
#[wasm_bindgen(js_name = aesEcbEncryptPadded)]
pub fn aes_ecb_encrypt_padded_js(key: &[u8], data: &[u8], pad: u8) -> Result<Vec<u8>, JsValue> {
    let k = copy(key);
    let d = copy(data);
    let algo = PaddingAlgorithm::from_u8(pad).ok_or_else(|| JsValue::from_str("bad pad"))?;
    let need = padded_len(d.len(), 16, algo).map_err(|_| JsValue::from_str("pad len"))?;
    let mut out = vec![0u8; need];
    aes_ecb_encrypt_padded(&k, &d, algo, &mut out)
        .map_err(|_| JsValue::from_str("encrypt failed"))?;
    Ok(out)
}

/// AES-ECB decrypt with padding (`pad`: 0=None, 1=PKCS7, 2=ISO7816, 3=X923).
/// Returns trimmed plaintext; Err "bad pad"/"decrypt failed" on failure.
#[wasm_bindgen(js_name = aesEcbDecryptPadded)]
pub fn aes_ecb_decrypt_padded_js(key: &[u8], data: &[u8], pad: u8) -> Result<Vec<u8>, JsValue> {
    let k = copy(key);
    let d = copy(data);
    let algo = PaddingAlgorithm::from_u8(pad).ok_or_else(|| JsValue::from_str("bad pad"))?;
    let mut out = vec![0u8; d.len()];
    let n = aes_ecb_decrypt_padded(&k, &d, algo, &mut out)
        .map_err(|_| JsValue::from_str("decrypt failed"))?;
    Ok((&out[..n]).to_vec())
}
