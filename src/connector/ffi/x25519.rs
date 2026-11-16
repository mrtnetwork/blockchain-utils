//! X25519 Diffie–Hellman FFI (feature `ffi`).

use core::slice;

use crate::curve::x25519::{
    diffie_hellman, diffie_hellman_raw, ed25519_pk_to_x25519, ed25519_seed_to_x25519, public_key,
    x25519, X25519_LEN,
};

/// Success.
pub const BU_X25519_OK: i32 = 0;
/// Null pointer argument.
pub const BU_X25519_ERR_NULL: i32 = 1;
/// Output or input buffer too small.
pub const BU_X25519_ERR_BUFFER: i32 = 2;
/// Invalid point / all-zero shared secret / conversion failure.
pub const BU_X25519_ERR_INVALID: i32 = 3;

fn check_buf(ptr: *const u8, len: usize, need: usize) -> Result<(), i32> {
    if ptr.is_null() {
        return Err(BU_X25519_ERR_NULL);
    }
    if len < need {
        return Err(BU_X25519_ERR_BUFFER);
    }
    Ok(())
}

fn check_out(ptr: *mut u8, len: usize, need: usize) -> Result<(), i32> {
    if ptr.is_null() {
        return Err(BU_X25519_ERR_NULL);
    }
    if len < need {
        return Err(BU_X25519_ERR_BUFFER);
    }
    Ok(())
}

fn read32(ptr: *const u8) -> [u8; 32] {
    let s = unsafe { slice::from_raw_parts(ptr, 32) };
    let mut a = [0u8; 32];
    a.copy_from_slice(s);
    a
}

/// `X25519(k, u)` — clamp `k`, Montgomery ladder with peer/base `u`.
///
/// All buffers must be at least 32 bytes.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_x25519(
    k: *const u8,
    k_len: usize,
    u: *const u8,
    u_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if let Err(e) = check_buf(k, k_len, X25519_LEN) {
        return e;
    }
    if let Err(e) = check_buf(u, u_len, X25519_LEN) {
        return e;
    }
    if let Err(e) = check_out(out, out_len, X25519_LEN) {
        return e;
    }
    let r = x25519(&read32(k), &read32(u));
    unsafe {
        slice::from_raw_parts_mut(out, X25519_LEN).copy_from_slice(&r);
    }
    BU_X25519_OK
}

/// Derive public key: `X25519(private, 9)`.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_x25519_public_key(
    private_key: *const u8,
    private_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if let Err(e) = check_buf(private_key, private_len, X25519_LEN) {
        return e;
    }
    if let Err(e) = check_out(out, out_len, X25519_LEN) {
        return e;
    }
    let r = public_key(&read32(private_key));
    unsafe {
        slice::from_raw_parts_mut(out, X25519_LEN).copy_from_slice(&r);
    }
    BU_X25519_OK
}

/// Diffie–Hellman shared secret; rejects all-zero result (`BU_X25519_ERR_INVALID`).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_x25519_dh(
    private_key: *const u8,
    private_len: usize,
    peer_public: *const u8,
    peer_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if let Err(e) = check_buf(private_key, private_len, X25519_LEN) {
        return e;
    }
    if let Err(e) = check_buf(peer_public, peer_len, X25519_LEN) {
        return e;
    }
    if let Err(e) = check_out(out, out_len, X25519_LEN) {
        return e;
    }
    match diffie_hellman(&read32(private_key), &read32(peer_public)) {
        Ok(r) => {
            unsafe {
                slice::from_raw_parts_mut(out, X25519_LEN).copy_from_slice(&r);
            }
            BU_X25519_OK
        }
        Err(_) => BU_X25519_ERR_INVALID,
    }
}

/// Diffie–Hellman without rejecting all-zero shared secret.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_x25519_dh_raw(
    private_key: *const u8,
    private_len: usize,
    peer_public: *const u8,
    peer_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if let Err(e) = check_buf(private_key, private_len, X25519_LEN) {
        return e;
    }
    if let Err(e) = check_buf(peer_public, peer_len, X25519_LEN) {
        return e;
    }
    if let Err(e) = check_out(out, out_len, X25519_LEN) {
        return e;
    }
    let r = diffie_hellman_raw(&read32(private_key), &read32(peer_public));
    unsafe {
        slice::from_raw_parts_mut(out, X25519_LEN).copy_from_slice(&r);
    }
    BU_X25519_OK
}

/// Ed25519 compressed public key → X25519 public key (birational map).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_ed25519_pk_to_x25519(
    ed_pk: *const u8,
    ed_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if let Err(e) = check_buf(ed_pk, ed_len, X25519_LEN) {
        return e;
    }
    if let Err(e) = check_out(out, out_len, X25519_LEN) {
        return e;
    }
    match ed25519_pk_to_x25519(&read32(ed_pk)) {
        Ok(r) => {
            unsafe {
                slice::from_raw_parts_mut(out, X25519_LEN).copy_from_slice(&r);
            }
            BU_X25519_OK
        }
        Err(_) => BU_X25519_ERR_INVALID,
    }
}

/// Ed25519 32-byte seed → X25519 private key (`clamp(SHA-512(seed)[0..32])`).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_ed25519_seed_to_x25519(
    seed: *const u8,
    seed_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if let Err(e) = check_buf(seed, seed_len, X25519_LEN) {
        return e;
    }
    if let Err(e) = check_out(out, out_len, X25519_LEN) {
        return e;
    }
    let r = ed25519_seed_to_x25519(&read32(seed));
    unsafe {
        slice::from_raw_parts_mut(out, X25519_LEN).copy_from_slice(&r);
    }
    BU_X25519_OK
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::x25519::public_key;

    fn hex_decode(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn ffi_alice_public() {
        let sk = hex_decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let mut out = [0u8; 32];
        let rc = unsafe { bu_x25519_public_key(sk.as_ptr(), 32, out.as_mut_ptr(), 32) };
        assert_eq!(rc, BU_X25519_OK);
        assert_eq!(out, public_key(&sk));
        assert_eq!(
            out,
            hex_decode("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        );
    }

    #[test]
    fn ffi_dh_alice_bob() {
        let alice_sk =
            hex_decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let bob_pk = hex_decode("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let mut out = [0u8; 32];
        let rc = unsafe {
            bu_x25519_dh(
                alice_sk.as_ptr(),
                32,
                bob_pk.as_ptr(),
                32,
                out.as_mut_ptr(),
                32,
            )
        };
        assert_eq!(rc, BU_X25519_OK);
        assert_eq!(
            out,
            hex_decode("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
        );
    }
}
