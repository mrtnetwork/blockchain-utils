//! ML-DSA (FIPS 204) FFI — feature `ffi`.
#![cfg(feature = "alloc")]

use core::slice;

use crate::signature::ml_dsa::MlDsa;

pub const BU_MLDSA_OK: i32 = 0;
pub const BU_MLDSA_ERR: i32 = 1;

fn dsa_for(set: u32) -> Option<MlDsa> {
    match set {
        44 => Some(MlDsa::mldsa44()),
        65 => Some(MlDsa::mldsa65()),
        87 => Some(MlDsa::mldsa87()),
        _ => None,
    }
}

/// `set` ∈ {44,65,87}. Writes pk then sk lengths via out params if non-null.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_mldsa_sizes(
    set: u32,
    pk_len: *mut usize,
    sk_len: *mut usize,
    sig_len: *mut usize,
) -> i32 {
    let Some(d) = dsa_for(set) else {
        return BU_MLDSA_ERR;
    };
    if !pk_len.is_null() {
        *pk_len = d.params.public_key_bytes();
    }
    if !sk_len.is_null() {
        *sk_len = d.params.secret_key_bytes();
    }
    if !sig_len.is_null() {
        *sig_len = d.params.signature_bytes();
    }
    BU_MLDSA_OK
}

/// Keygen from 32-byte seed. `pk_out`/`sk_out` must have correct sizes.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_mldsa_keygen(
    set: u32,
    seed: *const u8,
    seed_len: usize,
    pk_out: *mut u8,
    pk_len: usize,
    sk_out: *mut u8,
    sk_len: usize,
) -> i32 {
    let Some(d) = dsa_for(set) else {
        return BU_MLDSA_ERR;
    };
    if pk_out.is_null() || sk_out.is_null() {
        return BU_MLDSA_ERR;
    }
    if pk_len != d.params.public_key_bytes() || sk_len != d.params.secret_key_bytes() {
        return BU_MLDSA_ERR;
    }
    let mut s = [0u8; 32];
    // Keygen seeds are key material: caller-supplied, never generated here.
    if seed.is_null() || seed_len != 32 {
        return BU_MLDSA_ERR;
    }
    s.copy_from_slice(slice::from_raw_parts(seed, 32));
    let Ok((pk, sk)) = d.keygen(&s) else {
        return BU_MLDSA_ERR;
    };
    slice::from_raw_parts_mut(pk_out, pk_len).copy_from_slice(&pk);
    slice::from_raw_parts_mut(sk_out, sk_len).copy_from_slice(&sk);
    BU_MLDSA_OK
}

/// Sign: `rnd` (32 bytes) is required — FIPS 204 randomness used *directly*
/// in ρ″ = H(K || rnd || μ). Null is rejected; callers without randomness
/// must obtain it from the platform RNG first (never silently generated).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_mldsa_sign(
    set: u32,
    sk: *const u8,
    sk_len: usize,
    msg: *const u8,
    msg_len: usize,
    rnd: *const u8,
    rnd_len: usize,
    ctx: *const u8,
    ctx_len: usize,
    sig_out: *mut u8,
    sig_len: usize,
) -> i32 {
    let Some(d) = dsa_for(set) else {
        return BU_MLDSA_ERR;
    };
    if sk.is_null() || msg.is_null() || sig_out.is_null() {
        return BU_MLDSA_ERR;
    }
    if sk_len != d.params.secret_key_bytes() || sig_len != d.params.signature_bytes() {
        return BU_MLDSA_ERR;
    }
    if ctx_len > 255 {
        return BU_MLDSA_ERR;
    }
    let mut r = [0u8; 32];
    // FIPS 204: `rnd` is the 32-byte randomness used *directly* in
    // ρ″ = H(K || rnd || μ). Do NOT expand through ChaCha; a null pointer
    // is rejected so no silent fallback randomness can become `rnd`.
    if rnd.is_null() || rnd_len != 32 {
        return BU_MLDSA_ERR;
    }
    r.copy_from_slice(slice::from_raw_parts(rnd, 32));
    let sk_s = slice::from_raw_parts(sk, sk_len);
    let msg_s = slice::from_raw_parts(msg, msg_len);
    let ctx_s = if ctx.is_null() || ctx_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(ctx, ctx_len)
    };
    let Ok(sig) = d.sign(sk_s, msg_s, &r, ctx_s) else {
        return BU_MLDSA_ERR;
    };
    slice::from_raw_parts_mut(sig_out, sig_len).copy_from_slice(&sig);
    BU_MLDSA_OK
}

#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_mldsa_verify(
    set: u32,
    pk: *const u8,
    pk_len: usize,
    msg: *const u8,
    msg_len: usize,
    sig: *const u8,
    sig_len: usize,
    ctx: *const u8,
    ctx_len: usize,
) -> i32 {
    let Some(d) = dsa_for(set) else {
        return BU_MLDSA_ERR;
    };
    if pk.is_null() || msg.is_null() || sig.is_null() {
        return BU_MLDSA_ERR;
    }
    if pk_len != d.params.public_key_bytes() || sig_len != d.params.signature_bytes() {
        return BU_MLDSA_ERR;
    }
    if ctx_len > 255 {
        return BU_MLDSA_ERR;
    }
    let pk_s = slice::from_raw_parts(pk, pk_len);
    let msg_s = slice::from_raw_parts(msg, msg_len);
    let sig_s = slice::from_raw_parts(sig, sig_len);
    let ctx_s = if ctx.is_null() || ctx_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(ctx, ctx_len)
    };
    if d.verify(pk_s, msg_s, sig_s, ctx_s) {
        BU_MLDSA_OK
    } else {
        BU_MLDSA_ERR
    }
}

#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_mldsa_pk_from_sk(
    set: u32,
    sk: *const u8,
    sk_len: usize,
    pk_out: *mut u8,
    pk_len: usize,
) -> i32 {
    let Some(d) = dsa_for(set) else {
        return BU_MLDSA_ERR;
    };
    if sk.is_null() || pk_out.is_null() {
        return BU_MLDSA_ERR;
    }
    if sk_len != d.params.secret_key_bytes() || pk_len != d.params.public_key_bytes() {
        return BU_MLDSA_ERR;
    }
    let Ok(pk) = d.public_key_from_secret_key(slice::from_raw_parts(sk, sk_len)) else {
        return BU_MLDSA_ERR;
    };
    slice::from_raw_parts_mut(pk_out, pk_len).copy_from_slice(&pk);
    BU_MLDSA_OK
}

#[cfg(test)]
mod strictness_tests {
    use super::*;
    use core::ptr;

    #[test]
    fn keygen_rejects_null_seed() {
        // ML-DSA-65 sizes; only the seed is missing.
        let mut pk = [0u8; 1952];
        let mut sk = [0u8; 4032];
        assert_eq!(
            unsafe {
                bu_mldsa_keygen(
                    65,
                    ptr::null(),
                    0,
                    pk.as_mut_ptr(),
                    pk.len(),
                    sk.as_mut_ptr(),
                    sk.len(),
                )
            },
            BU_MLDSA_ERR
        );
    }

    #[test]
    fn sign_rejects_null_rnd() {
        let sk = [0u8; 4032];
        let msg = [0u8; 1];
        let mut sig = [0u8; 3309];
        assert_eq!(
            unsafe {
                bu_mldsa_sign(
                    65,
                    sk.as_ptr(),
                    sk.len(),
                    msg.as_ptr(),
                    0,
                    ptr::null(),
                    0,
                    ptr::null(),
                    0,
                    sig.as_mut_ptr(),
                    sig.len(),
                )
            },
            BU_MLDSA_ERR
        );
    }
}
