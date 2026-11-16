//! FF1 (NIST SP 800-38G) FFI — flexible numeral strings as digit bytes.
#![cfg(feature = "alloc")]

use crate::cipher::ff1::{
    ff1_decrypt_binary, ff1_decrypt_flexible, ff1_encrypt_binary, ff1_encrypt_flexible, Ff1Error,
};
use core::slice;

pub const BU_FF1_OK: i32 = 0;
pub const BU_FF1_ERR_NULL: i32 = 1;
pub const BU_FF1_ERR_BUFFER: i32 = 2;
pub const BU_FF1_ERR_INVALID: i32 = 3;
pub const BU_FF1_ERR_RADIX: i32 = 4;
pub const BU_FF1_ERR_LENGTH: i32 = 5;

fn map_err(e: Ff1Error) -> i32 {
    match e {
        Ff1Error::InvalidKey | Ff1Error::Cipher(_) => BU_FF1_ERR_INVALID,
        Ff1Error::InvalidRadix => BU_FF1_ERR_RADIX,
        Ff1Error::InvalidInput => BU_FF1_ERR_INVALID,
        Ff1Error::InvalidLength => BU_FF1_ERR_LENGTH,
    }
}

/// FF1 encrypt flexible digits.
///
/// `pt`/`out` are digit arrays (each byte a digit in `0..radix`).
/// `out_len` must equal `pt_len`. Returns length written on success.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_ff1_encrypt(
    key: *const u8,
    key_len: usize,
    radix: u32,
    pt: *const u8,
    pt_len: usize,
    tweak: *const u8,
    tweak_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if key.is_null() || (pt_len > 0 && pt.is_null()) || out.is_null() {
        return BU_FF1_ERR_NULL;
    }
    if out_len < pt_len {
        return BU_FF1_ERR_BUFFER;
    }
    let key = slice::from_raw_parts(key, key_len);
    let pt = if pt_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(pt, pt_len)
    };
    let tweak = if tweak_len == 0 || tweak.is_null() {
        &[][..]
    } else {
        slice::from_raw_parts(tweak, tweak_len)
    };
    match ff1_encrypt_flexible(key, radix, pt, tweak) {
        Ok(ct) => {
            if ct.len() > out_len {
                return BU_FF1_ERR_BUFFER;
            }
            slice::from_raw_parts_mut(out, ct.len()).copy_from_slice(&ct);
            BU_FF1_OK
        }
        Err(e) => map_err(e),
    }
}

/// FF1 decrypt flexible digits. Same buffer conventions as encrypt.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_ff1_decrypt(
    key: *const u8,
    key_len: usize,
    radix: u32,
    ct: *const u8,
    ct_len: usize,
    tweak: *const u8,
    tweak_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if key.is_null() || (ct_len > 0 && ct.is_null()) || out.is_null() {
        return BU_FF1_ERR_NULL;
    }
    if out_len < ct_len {
        return BU_FF1_ERR_BUFFER;
    }
    let key = slice::from_raw_parts(key, key_len);
    let ct = if ct_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(ct, ct_len)
    };
    let tweak = if tweak_len == 0 || tweak.is_null() {
        &[][..]
    } else {
        slice::from_raw_parts(tweak, tweak_len)
    };
    match ff1_decrypt_flexible(key, radix, ct, tweak) {
        Ok(pt) => {
            if pt.len() > out_len {
                return BU_FF1_ERR_BUFFER;
            }
            slice::from_raw_parts_mut(out, pt.len()).copy_from_slice(&pt);
            BU_FF1_OK
        }
        Err(e) => map_err(e),
    }
}

/// FF1 encrypt packed binary (radix 2). `pt`/`out` same length (byte-packed bits).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_ff1_encrypt_binary(
    key: *const u8,
    key_len: usize,
    pt: *const u8,
    pt_len: usize,
    tweak: *const u8,
    tweak_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if key.is_null() || (pt_len > 0 && pt.is_null()) || out.is_null() {
        return BU_FF1_ERR_NULL;
    }
    if out_len < pt_len {
        return BU_FF1_ERR_BUFFER;
    }
    let key = core::slice::from_raw_parts(key, key_len);
    let pt = if pt_len == 0 {
        &[][..]
    } else {
        core::slice::from_raw_parts(pt, pt_len)
    };
    let tweak = if tweak_len == 0 || tweak.is_null() {
        &[][..]
    } else {
        core::slice::from_raw_parts(tweak, tweak_len)
    };
    match ff1_encrypt_binary(key, pt, tweak) {
        Ok(ct) => {
            if ct.len() > out_len {
                return BU_FF1_ERR_BUFFER;
            }
            core::slice::from_raw_parts_mut(out, ct.len()).copy_from_slice(&ct);
            BU_FF1_OK
        }
        Err(e) => map_err(e),
    }
}

/// FF1 decrypt packed binary (radix 2).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_ff1_decrypt_binary(
    key: *const u8,
    key_len: usize,
    ct: *const u8,
    ct_len: usize,
    tweak: *const u8,
    tweak_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if key.is_null() || (ct_len > 0 && ct.is_null()) || out.is_null() {
        return BU_FF1_ERR_NULL;
    }
    if out_len < ct_len {
        return BU_FF1_ERR_BUFFER;
    }
    let key = core::slice::from_raw_parts(key, key_len);
    let ct = if ct_len == 0 {
        &[][..]
    } else {
        core::slice::from_raw_parts(ct, ct_len)
    };
    let tweak = if tweak_len == 0 || tweak.is_null() {
        &[][..]
    } else {
        core::slice::from_raw_parts(tweak, tweak_len)
    };
    match ff1_decrypt_binary(key, ct, tweak) {
        Ok(pt) => {
            if pt.len() > out_len {
                return BU_FF1_ERR_BUFFER;
            }
            core::slice::from_raw_parts_mut(out, pt.len()).copy_from_slice(&pt);
            BU_FF1_OK
        }
        Err(e) => map_err(e),
    }
}
