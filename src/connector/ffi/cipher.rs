//! Block / stream cipher FFI: AES (ECB block), AES-CBC, ChaCha20.

use alloc::boxed::Box;
use core::ptr;
use core::slice;

use crate::cipher::aes::Aes;
use crate::cipher::block::BlockCipher;
use crate::cipher::chacha20::{chacha20_xor, stream_xor};
use crate::cipher::modes::cbc::{aes_cbc_decrypt, aes_cbc_encrypt};

pub const BU_CIPHER_OK: i32 = 0;
pub const BU_CIPHER_ERR_NULL: i32 = 1;
pub const BU_CIPHER_ERR_KEY: i32 = 2;
pub const BU_CIPHER_ERR_IV: i32 = 3;
pub const BU_CIPHER_ERR_LEN: i32 = 4;
pub const BU_CIPHER_ERR_INTERNAL: i32 = 5;

/// Opaque AES key schedule handle.
pub struct BuAes {
    inner: Aes,
}

#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_aes_new(key: *const u8, key_len: usize) -> *mut BuAes {
    if key.is_null() || (key_len != 16 && key_len != 24 && key_len != 32) {
        return ptr::null_mut();
    }
    let k = slice::from_raw_parts(key, key_len);
    match Aes::new(k) {
        Ok(inner) => Box::into_raw(Box::new(BuAes { inner })),
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_aes_free(ptr: *mut BuAes) {
    if !ptr.is_null() {
        drop(Box::from_raw(ptr));
    }
}

#[no_mangle]
pub extern "C" fn bu_aes_block_size(_ptr: *const BuAes) -> usize {
    16
}

/// Encrypt one 16-byte block. `out` must be ≥ 16.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_aes_encrypt_block(
    ptr: *mut BuAes,
    src: *const u8,
    out: *mut u8,
) -> i32 {
    if ptr.is_null() || src.is_null() || out.is_null() {
        return BU_CIPHER_ERR_NULL;
    }
    let aes = &(*ptr).inner;
    let mut block = [0u8; 16];
    block.copy_from_slice(slice::from_raw_parts(src, 16));
    if aes.encrypt_block(&mut block).is_err() {
        return BU_CIPHER_ERR_INTERNAL;
    }
    slice::from_raw_parts_mut(out, 16).copy_from_slice(&block);
    BU_CIPHER_OK
}

#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_aes_decrypt_block(
    ptr: *mut BuAes,
    src: *const u8,
    out: *mut u8,
) -> i32 {
    if ptr.is_null() || src.is_null() || out.is_null() {
        return BU_CIPHER_ERR_NULL;
    }
    let aes = &(*ptr).inner;
    let mut block = [0u8; 16];
    block.copy_from_slice(slice::from_raw_parts(src, 16));
    if aes.decrypt_block(&mut block).is_err() {
        return BU_CIPHER_ERR_INTERNAL;
    }
    slice::from_raw_parts_mut(out, 16).copy_from_slice(&block);
    BU_CIPHER_OK
}

/// AES-CBC encrypt (no padding). lengths multiple of 16. `iv` 16 bytes.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_aes_cbc_encrypt(
    key: *const u8,
    key_len: usize,
    iv: *const u8,
    iv_len: usize,
    data: *const u8,
    data_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if key.is_null() || iv.is_null() || (data_len > 0 && data.is_null()) || out.is_null() {
        return BU_CIPHER_ERR_NULL;
    }
    if key_len != 16 && key_len != 24 && key_len != 32 {
        return BU_CIPHER_ERR_KEY;
    }
    if iv_len != 16 {
        return BU_CIPHER_ERR_IV;
    }
    if !data_len.is_multiple_of(16) || out_len < data_len {
        return BU_CIPHER_ERR_LEN;
    }
    let mut iv_arr = [0u8; 16];
    iv_arr.copy_from_slice(slice::from_raw_parts(iv, 16));
    let key_s = slice::from_raw_parts(key, key_len);
    let data_s = slice::from_raw_parts(data, data_len);
    let out_s = slice::from_raw_parts_mut(out, data_len);
    match aes_cbc_encrypt(key_s, &iv_arr, data_s, out_s) {
        Ok(()) => BU_CIPHER_OK,
        Err(_) => BU_CIPHER_ERR_INTERNAL,
    }
}

#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_aes_cbc_decrypt(
    key: *const u8,
    key_len: usize,
    iv: *const u8,
    iv_len: usize,
    data: *const u8,
    data_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if key.is_null() || iv.is_null() || (data_len > 0 && data.is_null()) || out.is_null() {
        return BU_CIPHER_ERR_NULL;
    }
    if key_len != 16 && key_len != 24 && key_len != 32 {
        return BU_CIPHER_ERR_KEY;
    }
    if iv_len != 16 {
        return BU_CIPHER_ERR_IV;
    }
    if !data_len.is_multiple_of(16) || out_len < data_len {
        return BU_CIPHER_ERR_LEN;
    }
    let mut iv_arr = [0u8; 16];
    iv_arr.copy_from_slice(slice::from_raw_parts(iv, 16));
    let key_s = slice::from_raw_parts(key, key_len);
    let data_s = slice::from_raw_parts(data, data_len);
    let out_s = slice::from_raw_parts_mut(out, data_len);
    match aes_cbc_decrypt(key_s, &iv_arr, data_s, out_s) {
        Ok(()) => BU_CIPHER_OK,
        Err(_) => BU_CIPHER_ERR_INTERNAL,
    }
}

/// ChaCha20 stream XOR (IETF 12-byte nonce). key=32, nonce=12.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_chacha20_xor(
    key: *const u8,
    key_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    counter: u32,
    data: *const u8,
    data_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if key.is_null() || nonce.is_null() || (data_len > 0 && data.is_null()) || out.is_null() {
        return BU_CIPHER_ERR_NULL;
    }
    if key_len != 32 {
        return BU_CIPHER_ERR_KEY;
    }
    if nonce_len != 12 {
        return BU_CIPHER_ERR_IV;
    }
    if out_len < data_len {
        return BU_CIPHER_ERR_LEN;
    }
    let key_s = slice::from_raw_parts(key, key_len);
    let nonce_s = slice::from_raw_parts(nonce, nonce_len);
    let data_s = slice::from_raw_parts(data, data_len);
    let out_s = slice::from_raw_parts_mut(out, data_len);
    match chacha20_xor(key_s, nonce_s, counter, data_s, out_s) {
        Ok(()) => BU_CIPHER_OK,
        Err(_) => BU_CIPHER_ERR_INTERNAL,
    }
}

/// Keccak-f[1600] on 25×u64 state (200 bytes LE).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_keccak_f1600(state: *mut u8) -> i32 {
    if state.is_null() {
        return BU_CIPHER_ERR_NULL;
    }
    let bytes = slice::from_raw_parts_mut(state, 200);
    let mut st = [0u64; 25];
    for i in 0..25 {
        let mut w = [0u8; 8];
        w.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        st[i] = u64::from_le_bytes(w);
    }
    crate::hash::keccak::keccak_f_1600(&mut st);
    for i in 0..25 {
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&st[i].to_le_bytes());
    }
    BU_CIPHER_OK
}

/// ChaCha20 stream XOR with seek + optional in-place counter layout .
///
/// * `nonce_inplace_counter_length` — 0 = auto (8 or 12-byte nonce); else nonce is 16 bytes
/// * `seek_bytes` — keystream bytes to skip before XOR
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_chacha20_stream_xor(
    key: *const u8,
    key_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    data: *const u8,
    data_len: usize,
    out: *mut u8,
    out_len: usize,
    nonce_inplace_counter_length: usize,
    seek_bytes: usize,
) -> i32 {
    if key.is_null() || nonce.is_null() || (data_len > 0 && data.is_null()) || out.is_null() {
        return BU_CIPHER_ERR_NULL;
    }
    if key_len != 32 {
        return BU_CIPHER_ERR_KEY;
    }
    if out_len < data_len {
        return BU_CIPHER_ERR_LEN;
    }
    let key_s = slice::from_raw_parts(key, key_len);
    let nonce_s = slice::from_raw_parts(nonce, nonce_len);
    let data_s = slice::from_raw_parts(data, data_len);
    let out_s = slice::from_raw_parts_mut(out, data_len);
    match stream_xor(
        key_s,
        nonce_s,
        data_s,
        out_s,
        nonce_inplace_counter_length,
        seek_bytes,
    ) {
        Ok(()) => BU_CIPHER_OK,
        Err(_) => BU_CIPHER_ERR_INTERNAL,
    }
}

// ---- AES-CTR ----

/// AES-CTR encrypt/decrypt. `nonce` is 16-byte counter block. `out_len` must equal `data_len`.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_aes_ctr(
    key: *const u8,
    key_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    data: *const u8,
    data_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if key.is_null() || nonce.is_null() || data.is_null() || out.is_null() {
        return BU_CIPHER_ERR_NULL;
    }
    if nonce_len != 16 {
        return BU_CIPHER_ERR_IV;
    }
    if out_len < data_len {
        return BU_CIPHER_ERR_LEN;
    }
    let key_s = slice::from_raw_parts(key, key_len);
    let mut n = [0u8; 16];
    n.copy_from_slice(slice::from_raw_parts(nonce, 16));
    let data_s = slice::from_raw_parts(data, data_len);
    let out_s = slice::from_raw_parts_mut(out, out_len);
    match crate::cipher::aes_ctr(key_s, &n, data_s, out_s) {
        Ok(()) => BU_CIPHER_OK,
        Err(_) => BU_CIPHER_ERR_INTERNAL,
    }
}

// ---- AES-ECB ----

/// AES-ECB encrypt (no padding). `data_len` must be multiple of 16; `out_len == data_len`.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_aes_ecb_encrypt(
    key: *const u8,
    key_len: usize,
    data: *const u8,
    data_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if key.is_null() || data.is_null() || out.is_null() {
        return BU_CIPHER_ERR_NULL;
    }
    if !data_len.is_multiple_of(16) || out_len != data_len {
        return BU_CIPHER_ERR_LEN;
    }
    let key_s = slice::from_raw_parts(key, key_len);
    let data_s = slice::from_raw_parts(data, data_len);
    let out_s = slice::from_raw_parts_mut(out, out_len);
    match crate::cipher::aes_ecb_encrypt(key_s, data_s, out_s) {
        Ok(()) => BU_CIPHER_OK,
        Err(_) => BU_CIPHER_ERR_INTERNAL,
    }
}

/// AES-ECB decrypt (no padding).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_aes_ecb_decrypt(
    key: *const u8,
    key_len: usize,
    data: *const u8,
    data_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if key.is_null() || data.is_null() || out.is_null() {
        return BU_CIPHER_ERR_NULL;
    }
    if !data_len.is_multiple_of(16) || out_len != data_len {
        return BU_CIPHER_ERR_LEN;
    }
    let key_s = slice::from_raw_parts(key, key_len);
    let data_s = slice::from_raw_parts(data, data_len);
    let out_s = slice::from_raw_parts_mut(out, out_len);
    match crate::cipher::aes_ecb_decrypt(key_s, data_s, out_s) {
        Ok(()) => BU_CIPHER_OK,
        Err(_) => BU_CIPHER_ERR_INTERNAL,
    }
}

/// AES-ECB encrypt with padding.
/// `pad`: 0=None, 1=PKCS7, 2=ISO7816, 3=X923.
/// Returns ciphertext length written, or negative error code.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_aes_ecb_encrypt_padded(
    key: *const u8,
    key_len: usize,
    data: *const u8,
    data_len: usize,
    pad: u8,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if key.is_null() || data.is_null() || out.is_null() {
        return -BU_CIPHER_ERR_NULL;
    }
    let Some(algo) = crate::cipher::PaddingAlgorithm::from_u8(pad) else {
        return -BU_CIPHER_ERR_INTERNAL;
    };
    let need = match crate::cipher::padded_len(data_len, 16, algo) {
        Ok(n) => n,
        Err(_) => return BU_CIPHER_ERR_LEN,
    };
    if out_len < need {
        return -BU_CIPHER_ERR_LEN;
    }
    let key_s = slice::from_raw_parts(key, key_len);
    let data_s = slice::from_raw_parts(data, data_len);
    let out_s = slice::from_raw_parts_mut(out, need);
    match crate::cipher::aes_ecb_encrypt_padded(key_s, data_s, algo, out_s) {
        Ok(()) => need as i32,
        Err(_) => -BU_CIPHER_ERR_INTERNAL,
    }
}

/// AES-ECB decrypt with padding. Returns plaintext length, or negative error.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_aes_ecb_decrypt_padded(
    key: *const u8,
    key_len: usize,
    data: *const u8,
    data_len: usize,
    pad: u8,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if key.is_null() || data.is_null() || out.is_null() {
        return -BU_CIPHER_ERR_NULL;
    }
    let Some(algo) = crate::cipher::PaddingAlgorithm::from_u8(pad) else {
        return -BU_CIPHER_ERR_INTERNAL;
    };
    if out_len < data_len {
        return -BU_CIPHER_ERR_LEN;
    }
    let key_s = slice::from_raw_parts(key, key_len);
    let data_s = slice::from_raw_parts(data, data_len);
    let out_s = slice::from_raw_parts_mut(out, out_len);
    match crate::cipher::aes_ecb_decrypt_padded(key_s, data_s, algo, out_s) {
        Ok(n) => n as i32,
        Err(_) => -BU_CIPHER_ERR_INTERNAL,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes128_block_roundtrip() {
        let key = [0u8; 16];
        unsafe {
            let h = bu_aes_new(key.as_ptr(), 16);
            assert!(!h.is_null());
            let src = [0u8; 16];
            let mut ct = [0u8; 16];
            let mut pt = [0u8; 16];
            assert_eq!(
                bu_aes_encrypt_block(h, src.as_ptr(), ct.as_mut_ptr()),
                BU_CIPHER_OK
            );
            assert_eq!(
                bu_aes_decrypt_block(h, ct.as_ptr(), pt.as_mut_ptr()),
                BU_CIPHER_OK
            );
            assert_eq!(pt, src);
            bu_aes_free(h);
        }
    }

    #[test]
    fn chacha20_xor_roundtrip() {
        let key = [9u8; 32];
        let nonce = [7u8; 12];
        let data = b"hello stream cipher!!";
        let mut ct = [0u8; 32];
        let mut pt = [0u8; 32];
        unsafe {
            assert_eq!(
                bu_chacha20_xor(
                    key.as_ptr(),
                    32,
                    nonce.as_ptr(),
                    12,
                    1,
                    data.as_ptr(),
                    data.len(),
                    ct.as_mut_ptr(),
                    ct.len(),
                ),
                BU_CIPHER_OK
            );
            assert_eq!(
                bu_chacha20_xor(
                    key.as_ptr(),
                    32,
                    nonce.as_ptr(),
                    12,
                    1,
                    ct.as_ptr(),
                    data.len(),
                    pt.as_mut_ptr(),
                    pt.len(),
                ),
                BU_CIPHER_OK
            );
            assert_eq!(&pt[..data.len()], data);
        }
    }
}
