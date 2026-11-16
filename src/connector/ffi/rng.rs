//! Global RNG seeding FFI.
#![cfg(feature = "ffi")]

use crate::rng::{global_fill, is_global_seeded, seed_global};
use core::slice;

pub const BU_RNG_OK: i32 = 0;
pub const BU_RNG_ERR: i32 = 1;
pub const BU_RNG_ALREADY: i32 = 2;

/// Seed global ChaCha20 RNG once with 32 bytes. Second call → BU_RNG_ALREADY.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_rng_seed(seed: *const u8, seed_len: usize) -> i32 {
    if seed.is_null() || seed_len != 32 {
        return BU_RNG_ERR;
    }
    let mut s = [0u8; 32];
    s.copy_from_slice(slice::from_raw_parts(seed, 32));
    if seed_global(&s) {
        BU_RNG_OK
    } else {
        BU_RNG_ALREADY
    }
}

#[no_mangle]
pub extern "C" fn bu_rng_is_seeded() -> i32 {
    if is_global_seeded() {
        1
    } else {
        0
    }
}

/// Fill `out` from global RNG (must have been seeded for production use).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_rng_fill(out: *mut u8, out_len: usize) -> i32 {
    if out.is_null() || out_len == 0 {
        return BU_RNG_ERR;
    }
    let dest = slice::from_raw_parts_mut(out, out_len);
    global_fill(dest);
    BU_RNG_OK
}
