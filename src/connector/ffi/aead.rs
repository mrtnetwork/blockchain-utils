//! AEAD FFI: ChaCha20-Poly1305, AES-GCM, XSalsa20-Poly1305 and NaCl box.

use core::slice;

use crate::aead::{
    aes_gcm_decrypt, aes_gcm_encrypt, chacha20_poly1305_decrypt, chacha20_poly1305_encrypt,
    salsabox_beforenm, salsabox_decrypt, salsabox_encrypt, xsalsa20_poly1305_decrypt,
    xsalsa20_poly1305_encrypt,
};
use crate::cipher::error::CipherError;

/// Success.
pub const BU_AEAD_OK: i32 = 0;
pub const BU_AEAD_ERR_NULL: i32 = 1;
pub const BU_AEAD_ERR_BUFFER: i32 = 2;
pub const BU_AEAD_ERR_KEY: i32 = 3;
pub const BU_AEAD_ERR_NONCE: i32 = 4;
pub const BU_AEAD_ERR_AUTH: i32 = 5;
pub const BU_AEAD_ERR_INTERNAL: i32 = 6;

fn map_cipher(e: CipherError) -> i32 {
    match e {
        CipherError::InvalidKeyLength => BU_AEAD_ERR_KEY,
        CipherError::InvalidNonceLength => BU_AEAD_ERR_NONCE,
        CipherError::AuthenticationFailed => BU_AEAD_ERR_AUTH,
        CipherError::InvalidLength => BU_AEAD_ERR_BUFFER,
        _ => BU_AEAD_ERR_INTERNAL,
    }
}

fn check_in(ptr: *const u8, len: usize) -> Result<(), i32> {
    if len > 0 && ptr.is_null() {
        return Err(BU_AEAD_ERR_NULL);
    }
    Ok(())
}

fn check_out(ptr: *mut u8, len: usize) -> Result<(), i32> {
    if len > 0 && ptr.is_null() {
        return Err(BU_AEAD_ERR_NULL);
    }
    Ok(())
}

/// ChaCha20-Poly1305 encrypt.
///
/// * `key` — 32 bytes
/// * `nonce` — 8..=16 bytes (12 = RFC 8439)
/// * `out` — must be `pt_len + 16` (ciphertext ‖ tag)
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_chacha20poly1305_encrypt(
    key: *const u8,
    key_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    plaintext: *const u8,
    pt_len: usize,
    aad: *const u8,
    aad_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if let Err(e) = check_in(key, key_len) {
        return e;
    }
    if let Err(e) = check_in(nonce, nonce_len) {
        return e;
    }
    if let Err(e) = check_in(plaintext, pt_len) {
        return e;
    }
    if let Err(e) = check_in(aad, aad_len) {
        return e;
    }
    if let Err(e) = check_out(out, out_len) {
        return e;
    }
    if key_len != 32 {
        return BU_AEAD_ERR_KEY;
    }
    if out_len != pt_len + 16 {
        return BU_AEAD_ERR_BUFFER;
    }
    let key_s = unsafe { slice::from_raw_parts(key, key_len) };
    let nonce_s = unsafe { slice::from_raw_parts(nonce, nonce_len) };
    let pt = if pt_len == 0 {
        &[][..]
    } else {
        unsafe { slice::from_raw_parts(plaintext, pt_len) }
    };
    let aad_s = if aad_len == 0 {
        &[][..]
    } else {
        unsafe { slice::from_raw_parts(aad, aad_len) }
    };
    let out_s = unsafe { slice::from_raw_parts_mut(out, out_len) };
    match chacha20_poly1305_encrypt(key_s, nonce_s, pt, aad_s, out_s) {
        Ok(()) => BU_AEAD_OK,
        Err(e) => map_cipher(e),
    }
}

/// ChaCha20-Poly1305 decrypt. `ct` is ciphertext ‖ tag; `out` is plaintext (`ct_len - 16`).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_chacha20poly1305_decrypt(
    key: *const u8,
    key_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    ct_and_tag: *const u8,
    ct_len: usize,
    aad: *const u8,
    aad_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if let Err(e) = check_in(key, key_len) {
        return e;
    }
    if let Err(e) = check_in(nonce, nonce_len) {
        return e;
    }
    if let Err(e) = check_in(ct_and_tag, ct_len) {
        return e;
    }
    if let Err(e) = check_in(aad, aad_len) {
        return e;
    }
    if ct_len < 16 {
        return BU_AEAD_ERR_BUFFER;
    }
    if out_len != ct_len - 16 {
        return BU_AEAD_ERR_BUFFER;
    }
    if let Err(e) = check_out(out, out_len) {
        return e;
    }
    if key_len != 32 {
        return BU_AEAD_ERR_KEY;
    }
    let key_s = unsafe { slice::from_raw_parts(key, key_len) };
    let nonce_s = unsafe { slice::from_raw_parts(nonce, nonce_len) };
    let ct = unsafe { slice::from_raw_parts(ct_and_tag, ct_len) };
    let aad_s = if aad_len == 0 {
        &[][..]
    } else {
        unsafe { slice::from_raw_parts(aad, aad_len) }
    };
    let out_s = unsafe { slice::from_raw_parts_mut(out, out_len) };
    match chacha20_poly1305_decrypt(key_s, nonce_s, ct, aad_s, out_s) {
        Ok(()) => BU_AEAD_OK,
        Err(e) => map_cipher(e),
    }
}

/// AES-GCM encrypt. `key` 16/24/32 bytes, `nonce` 12 bytes, `out` = pt_len + 16.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_aes_gcm_encrypt(
    key: *const u8,
    key_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    plaintext: *const u8,
    pt_len: usize,
    aad: *const u8,
    aad_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if let Err(e) = check_in(key, key_len) {
        return e;
    }
    if let Err(e) = check_in(nonce, nonce_len) {
        return e;
    }
    if let Err(e) = check_in(plaintext, pt_len) {
        return e;
    }
    if let Err(e) = check_in(aad, aad_len) {
        return e;
    }
    if let Err(e) = check_out(out, out_len) {
        return e;
    }
    if nonce_len != 12 {
        return BU_AEAD_ERR_NONCE;
    }
    if out_len != pt_len + 16 {
        return BU_AEAD_ERR_BUFFER;
    }
    let key_s = unsafe { slice::from_raw_parts(key, key_len) };
    let nonce_s = unsafe { slice::from_raw_parts(nonce, nonce_len) };
    let pt = if pt_len == 0 {
        &[][..]
    } else {
        unsafe { slice::from_raw_parts(plaintext, pt_len) }
    };
    let aad_s = if aad_len == 0 {
        &[][..]
    } else {
        unsafe { slice::from_raw_parts(aad, aad_len) }
    };
    let out_s = unsafe { slice::from_raw_parts_mut(out, out_len) };
    match aes_gcm_encrypt(key_s, nonce_s, pt, aad_s, out_s) {
        Ok(()) => BU_AEAD_OK,
        Err(e) => map_cipher(e),
    }
}

/// AES-GCM decrypt.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_aes_gcm_decrypt(
    key: *const u8,
    key_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    ct_and_tag: *const u8,
    ct_len: usize,
    aad: *const u8,
    aad_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if let Err(e) = check_in(key, key_len) {
        return e;
    }
    if let Err(e) = check_in(nonce, nonce_len) {
        return e;
    }
    if let Err(e) = check_in(ct_and_tag, ct_len) {
        return e;
    }
    if let Err(e) = check_in(aad, aad_len) {
        return e;
    }
    if ct_len < 16 {
        return BU_AEAD_ERR_BUFFER;
    }
    if out_len != ct_len - 16 {
        return BU_AEAD_ERR_BUFFER;
    }
    if let Err(e) = check_out(out, out_len) {
        return e;
    }
    if nonce_len != 12 {
        return BU_AEAD_ERR_NONCE;
    }
    let key_s = unsafe { slice::from_raw_parts(key, key_len) };
    let nonce_s = unsafe { slice::from_raw_parts(nonce, nonce_len) };
    let ct = unsafe { slice::from_raw_parts(ct_and_tag, ct_len) };
    let aad_s = if aad_len == 0 {
        &[][..]
    } else {
        unsafe { slice::from_raw_parts(aad, aad_len) }
    };
    let out_s = unsafe { slice::from_raw_parts_mut(out, out_len) };
    match aes_gcm_decrypt(key_s, nonce_s, ct, aad_s, out_s) {
        Ok(()) => BU_AEAD_OK,
        Err(e) => map_cipher(e),
    }
}

/// XSalsa20-Poly1305 encrypt (NaCl `crypto_secretbox_easy`).
///
/// * `key` — 32 bytes; `nonce` — strictly 24 bytes.
/// * `out` — must be `pt_len + 16`, layout `TAG ‖ CIPHERTEXT`
///   (authenticator first, unlike ChaCha20-Poly1305).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_xsalsa20poly1305_encrypt(
    key: *const u8,
    key_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    plaintext: *const u8,
    pt_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if let Err(e) = check_in(key, key_len) {
        return e;
    }
    if let Err(e) = check_in(nonce, nonce_len) {
        return e;
    }
    if let Err(e) = check_in(plaintext, pt_len) {
        return e;
    }
    if let Err(e) = check_out(out, out_len) {
        return e;
    }
    if key_len != 32 {
        return BU_AEAD_ERR_KEY;
    }
    if nonce_len != 24 {
        return BU_AEAD_ERR_NONCE;
    }
    if out_len != pt_len + 16 {
        return BU_AEAD_ERR_BUFFER;
    }
    let key_s = unsafe { slice::from_raw_parts(key, key_len) };
    let nonce_s = unsafe { slice::from_raw_parts(nonce, nonce_len) };
    let pt = if pt_len == 0 {
        &[][..]
    } else {
        unsafe { slice::from_raw_parts(plaintext, pt_len) }
    };
    let out_s = unsafe { slice::from_raw_parts_mut(out, out_len) };
    match xsalsa20_poly1305_encrypt(key_s, nonce_s, pt, &[], out_s) {
        Ok(()) => BU_AEAD_OK,
        Err(e) => map_cipher(e),
    }
}

/// XSalsa20-Poly1305 decrypt. `tag_ct` is `TAG ‖ CIPHERTEXT`;
/// `out` is plaintext (`tag_ct_len - 16`).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_xsalsa20poly1305_decrypt(
    key: *const u8,
    key_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    tag_ct: *const u8,
    tag_ct_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if let Err(e) = check_in(key, key_len) {
        return e;
    }
    if let Err(e) = check_in(nonce, nonce_len) {
        return e;
    }
    if let Err(e) = check_in(tag_ct, tag_ct_len) {
        return e;
    }
    if tag_ct_len < 16 {
        return BU_AEAD_ERR_BUFFER;
    }
    if out_len != tag_ct_len - 16 {
        return BU_AEAD_ERR_BUFFER;
    }
    if let Err(e) = check_out(out, out_len) {
        return e;
    }
    if key_len != 32 {
        return BU_AEAD_ERR_KEY;
    }
    if nonce_len != 24 {
        return BU_AEAD_ERR_NONCE;
    }
    let key_s = unsafe { slice::from_raw_parts(key, key_len) };
    let nonce_s = unsafe { slice::from_raw_parts(nonce, nonce_len) };
    let sealed = unsafe { slice::from_raw_parts(tag_ct, tag_ct_len) };
    let out_s = unsafe { slice::from_raw_parts_mut(out, out_len) };
    match xsalsa20_poly1305_decrypt(key_s, nonce_s, sealed, &[], out_s) {
        Ok(()) => BU_AEAD_OK,
        Err(e) => map_cipher(e),
    }
}

fn check_box_keys(
    peer: *const u8,
    peer_len: usize,
    sk: *const u8,
    sk_len: usize,
) -> Result<(), i32> {
    check_in(peer, peer_len)?;
    check_in(sk, sk_len)?;
    if peer_len != 32 || sk_len != 32 {
        return Err(BU_AEAD_ERR_KEY);
    }
    Ok(())
}

/// NaCl `crypto_box_beforenm`: X25519 DH + HSalsa20 → 32-byte transport key.
/// `out` must be 32 bytes. Rejects a zero shared secret.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_salsabox_beforenm(
    peer: *const u8,
    peer_len: usize,
    sk: *const u8,
    sk_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if let Err(e) = check_box_keys(peer, peer_len, sk, sk_len) {
        return e;
    }
    if let Err(e) = check_out(out, out_len) {
        return e;
    }
    if out_len != 32 {
        return BU_AEAD_ERR_BUFFER;
    }
    let peer_s = unsafe { slice::from_raw_parts(peer, peer_len) };
    let sk_s = unsafe { slice::from_raw_parts(sk, sk_len) };
    let out_s = unsafe { slice::from_raw_parts_mut(out, out_len) };
    match salsabox_beforenm(peer_s, sk_s) {
        Ok(k) => {
            out_s.copy_from_slice(&k);
            BU_AEAD_OK
        }
        Err(e) => map_cipher(e),
    }
}

/// NaCl `crypto_box_easy` detached encrypt (`TAG ‖ CIPHERTEXT`).
/// `out` must be `pt_len + 16`.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_salsabox_encrypt(
    peer: *const u8,
    peer_len: usize,
    sk: *const u8,
    sk_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    plaintext: *const u8,
    pt_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if let Err(e) = check_box_keys(peer, peer_len, sk, sk_len) {
        return e;
    }
    if let Err(e) = check_in(nonce, nonce_len) {
        return e;
    }
    if let Err(e) = check_in(plaintext, pt_len) {
        return e;
    }
    if let Err(e) = check_out(out, out_len) {
        return e;
    }
    if nonce_len != 24 {
        return BU_AEAD_ERR_NONCE;
    }
    if out_len != pt_len + 16 {
        return BU_AEAD_ERR_BUFFER;
    }
    let peer_s = unsafe { slice::from_raw_parts(peer, peer_len) };
    let sk_s = unsafe { slice::from_raw_parts(sk, sk_len) };
    let nonce_s = unsafe { slice::from_raw_parts(nonce, nonce_len) };
    let pt = if pt_len == 0 {
        &[][..]
    } else {
        unsafe { slice::from_raw_parts(plaintext, pt_len) }
    };
    let out_s = unsafe { slice::from_raw_parts_mut(out, out_len) };
    match salsabox_encrypt(peer_s, sk_s, nonce_s, pt, out_s) {
        Ok(()) => BU_AEAD_OK,
        Err(e) => map_cipher(e),
    }
}

/// NaCl `crypto_box_open_easy` detached decrypt. `out` is plaintext
/// (`tag_ct_len - 16`); on auth failure returns `BU_AEAD_ERR_AUTH`.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_salsabox_decrypt(
    peer: *const u8,
    peer_len: usize,
    sk: *const u8,
    sk_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    tag_ct: *const u8,
    tag_ct_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if let Err(e) = check_box_keys(peer, peer_len, sk, sk_len) {
        return e;
    }
    if let Err(e) = check_in(nonce, nonce_len) {
        return e;
    }
    if let Err(e) = check_in(tag_ct, tag_ct_len) {
        return e;
    }
    if tag_ct_len < 16 {
        return BU_AEAD_ERR_BUFFER;
    }
    if out_len != tag_ct_len - 16 {
        return BU_AEAD_ERR_BUFFER;
    }
    if let Err(e) = check_out(out, out_len) {
        return e;
    }
    if nonce_len != 24 {
        return BU_AEAD_ERR_NONCE;
    }
    let peer_s = unsafe { slice::from_raw_parts(peer, peer_len) };
    let sk_s = unsafe { slice::from_raw_parts(sk, sk_len) };
    let nonce_s = unsafe { slice::from_raw_parts(nonce, nonce_len) };
    let sealed = unsafe { slice::from_raw_parts(tag_ct, tag_ct_len) };
    let out_s = unsafe { slice::from_raw_parts_mut(out, out_len) };
    match salsabox_decrypt(peer_s, sk_s, nonce_s, sealed, out_s) {
        Ok(()) => BU_AEAD_OK,
        Err(e) => map_cipher(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chacha_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0u8; 12];
        let pt = b"hello aead world!!";
        let aad = b"aad";
        let mut ct = [0u8; 18 + 16];
        assert_eq!(
            unsafe {
                bu_chacha20poly1305_encrypt(
                    key.as_ptr(),
                    32,
                    nonce.as_ptr(),
                    12,
                    pt.as_ptr(),
                    pt.len(),
                    aad.as_ptr(),
                    aad.len(),
                    ct.as_mut_ptr(),
                    ct.len(),
                )
            },
            BU_AEAD_OK
        );
        let mut out = [0u8; 18];
        assert_eq!(
            unsafe {
                bu_chacha20poly1305_decrypt(
                    key.as_ptr(),
                    32,
                    nonce.as_ptr(),
                    12,
                    ct.as_ptr(),
                    ct.len(),
                    aad.as_ptr(),
                    aad.len(),
                    out.as_mut_ptr(),
                    out.len(),
                )
            },
            BU_AEAD_OK
        );
        assert_eq!(&out, pt);
    }

    #[test]
    fn aes_gcm_roundtrip() {
        let key = [0x11u8; 16];
        let nonce = [0x22u8; 12];
        let pt = b"aes-gcm test bytes";
        let mut ct = [0u8; 18 + 16];
        assert_eq!(
            unsafe {
                bu_aes_gcm_encrypt(
                    key.as_ptr(),
                    16,
                    nonce.as_ptr(),
                    12,
                    pt.as_ptr(),
                    pt.len(),
                    core::ptr::null(),
                    0,
                    ct.as_mut_ptr(),
                    ct.len(),
                )
            },
            BU_AEAD_OK
        );
        let mut out = [0u8; 18];
        assert_eq!(
            unsafe {
                bu_aes_gcm_decrypt(
                    key.as_ptr(),
                    16,
                    nonce.as_ptr(),
                    12,
                    ct.as_ptr(),
                    ct.len(),
                    core::ptr::null(),
                    0,
                    out.as_mut_ptr(),
                    out.len(),
                )
            },
            BU_AEAD_OK
        );
        assert_eq!(&out, pt);
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn xsalsa_box_ffi_golden() {
        // TON Connect tweetnacl golden (same as `aead::xsalsa20poly1305`).
        let sealed = unhex("69696ee955b62b73cd62bda875fc73d68219e0036b7a0b374f143feef2ba7f7dabdcb006973180de64d12a7a37868ec868e1378cba7808d0");
        let bob_pk = unhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let alice_sk = unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let alice_pk = unhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        let bob_sk = unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let nonce = &sealed[..24];
        let pt = b"TON Connect core";

        // beforenm shared with the secretbox path below.
        let mut session = [0u8; 32];
        assert_eq!(
            unsafe {
                bu_salsabox_beforenm(
                    bob_pk.as_ptr(),
                    32,
                    alice_sk.as_ptr(),
                    32,
                    session.as_mut_ptr(),
                    32,
                )
            },
            BU_AEAD_OK
        );

        // Detached box seal matches the golden body byte-exact.
        let mut body = vec![0u8; pt.len() + 16];
        assert_eq!(
            unsafe {
                bu_salsabox_encrypt(
                    bob_pk.as_ptr(),
                    32,
                    alice_sk.as_ptr(),
                    32,
                    nonce.as_ptr(),
                    24,
                    pt.as_ptr(),
                    pt.len(),
                    body.as_mut_ptr(),
                    body.len(),
                )
            },
            BU_AEAD_OK
        );
        assert_eq!(body, &sealed[24..]);

        // Secretbox under the beforenm key agrees too.
        let mut body2 = vec![0u8; pt.len() + 16];
        assert_eq!(
            unsafe {
                bu_xsalsa20poly1305_encrypt(
                    session.as_ptr(),
                    32,
                    nonce.as_ptr(),
                    24,
                    pt.as_ptr(),
                    pt.len(),
                    body2.as_mut_ptr(),
                    body2.len(),
                )
            },
            BU_AEAD_OK
        );
        assert_eq!(body2, &sealed[24..]);

        // Bob opens via box decrypt.
        let mut open = vec![0u8; pt.len()];
        assert_eq!(
            unsafe {
                bu_salsabox_decrypt(
                    alice_pk.as_ptr(),
                    32,
                    bob_sk.as_ptr(),
                    32,
                    nonce.as_ptr(),
                    24,
                    sealed[24..].as_ptr(),
                    sealed.len() - 24,
                    open.as_mut_ptr(),
                    open.len(),
                )
            },
            BU_AEAD_OK
        );
        assert_eq!(&open, pt);

        // Tampered tag fails with AUTH.
        let mut bad = sealed[24..].to_vec();
        bad[0] ^= 1;
        assert_eq!(
            unsafe {
                bu_salsabox_decrypt(
                    alice_pk.as_ptr(),
                    32,
                    bob_sk.as_ptr(),
                    32,
                    nonce.as_ptr(),
                    24,
                    bad.as_ptr(),
                    bad.len(),
                    open.as_mut_ptr(),
                    open.len(),
                )
            },
            BU_AEAD_ERR_AUTH
        );

        // Bad nonce length is rejected before crypto.
        assert_eq!(
            unsafe {
                bu_xsalsa20poly1305_encrypt(
                    session.as_ptr(),
                    32,
                    nonce.as_ptr(),
                    12,
                    pt.as_ptr(),
                    pt.len(),
                    body2.as_mut_ptr(),
                    body2.len(),
                )
            },
            BU_AEAD_ERR_NONCE
        );
    }
}
