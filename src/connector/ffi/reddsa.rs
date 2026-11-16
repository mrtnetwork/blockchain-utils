//! RedDSA FFI — Jubjub Auth/Binding + Pallas Auth/Binding.

#![cfg(feature = "ffi")]

use crate::signature::reddsa;
use core::slice;

const OK: i32 = 0;
const ERR: i32 = 1;

unsafe fn sk32(sk: *const u8) -> [u8; 32] {
    let mut a = [0u8; 32];
    a.copy_from_slice(slice::from_raw_parts(sk, 32));
    a
}

macro_rules! reddsa_sign_ffi {
    ($name:ident, $rust:path) => {
        #[no_mangle]
        /// # Safety
        /// Pointer arguments must be non-null and address readable/writable
        /// memory of at least the documented lengths. Null pointers are
        /// rejected with an error code; short or invalid buffers are the
        /// caller’s responsibility.
        pub unsafe extern "C" fn $name(
            sk: *const u8,
            msg: *const u8,
            msg_len: usize,
            rand80: *const u8,
            sig_out: *mut u8,
        ) -> i32 {
            if sk.is_null() || msg.is_null() || sig_out.is_null() {
                return ERR;
            }
            // Signing randomness is caller-supplied (80 bytes): no silent
            // generation — a null pointer is rejected so unseeded/global
            // RNG output can never become a signature nonce.
            if rand80.is_null() {
                return ERR;
            }
            let ska = sk32(sk);
            let m = slice::from_raw_parts(msg, msg_len);
            let mut r80 = [0u8; 80];
            r80.copy_from_slice(slice::from_raw_parts(rand80, 80));
            match $rust(&ska, m, &r80) {
                Ok(sig) => {
                    slice::from_raw_parts_mut(sig_out, 64).copy_from_slice(&sig);
                    OK
                }
                Err(_) => ERR,
            }
        }
    };
}

macro_rules! reddsa_verify_ffi {
    ($name:ident, $rust:path) => {
        #[no_mangle]
        /// # Safety
        /// Pointer arguments must be non-null and address readable/writable
        /// memory of at least the documented lengths. Null pointers are
        /// rejected with an error code; short or invalid buffers are the
        /// caller’s responsibility.
        pub unsafe extern "C" fn $name(
            pk: *const u8,
            msg: *const u8,
            msg_len: usize,
            sig: *const u8,
        ) -> i32 {
            if pk.is_null() || msg.is_null() || sig.is_null() {
                return ERR;
            }
            let mut pka = [0u8; 32];
            pka.copy_from_slice(slice::from_raw_parts(pk, 32));
            let m = slice::from_raw_parts(msg, msg_len);
            let mut s = [0u8; 64];
            s.copy_from_slice(slice::from_raw_parts(sig, 64));
            if $rust(&pka, m, &s) {
                OK
            } else {
                ERR
            }
        }
    };
}

reddsa_sign_ffi!(bu_reddsa_jubjub_auth_sign, reddsa::jubjub_auth_sign);
reddsa_verify_ffi!(bu_reddsa_jubjub_auth_verify, reddsa::jubjub_auth_verify);
reddsa_sign_ffi!(bu_reddsa_jubjub_binding_sign, reddsa::jubjub_binding_sign);
reddsa_verify_ffi!(
    bu_reddsa_jubjub_binding_verify,
    reddsa::jubjub_binding_verify
);
reddsa_sign_ffi!(bu_reddsa_pallas_auth_sign, reddsa::pallas_auth_sign);
reddsa_verify_ffi!(bu_reddsa_pallas_auth_verify, reddsa::pallas_auth_verify);
reddsa_sign_ffi!(bu_reddsa_pallas_binding_sign, reddsa::pallas_binding_sign);
reddsa_verify_ffi!(
    bu_reddsa_pallas_binding_verify,
    reddsa::pallas_binding_verify
);

#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_reddsa_jubjub_auth_pk(sk: *const u8, pk_out: *mut u8) -> i32 {
    if sk.is_null() || pk_out.is_null() {
        return ERR;
    }
    let ska = sk32(sk);
    let base = reddsa::jubjub_spend_auth_generator();
    match reddsa::jubjub_public_from_secret(&ska, &base) {
        Ok(pk) => {
            slice::from_raw_parts_mut(pk_out, 32).copy_from_slice(&pk);
            OK
        }
        Err(_) => ERR,
    }
}

#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_reddsa_jubjub_binding_pk(sk: *const u8, pk_out: *mut u8) -> i32 {
    if sk.is_null() || pk_out.is_null() {
        return ERR;
    }
    let ska = sk32(sk);
    let base = reddsa::jubjub_binding_generator();
    match reddsa::jubjub_public_from_secret(&ska, &base) {
        Ok(pk) => {
            slice::from_raw_parts_mut(pk_out, 32).copy_from_slice(&pk);
            OK
        }
        Err(_) => ERR,
    }
}

#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_reddsa_pallas_auth_pk(sk: *const u8, pk_out: *mut u8) -> i32 {
    if sk.is_null() || pk_out.is_null() {
        return ERR;
    }
    let ska = sk32(sk);
    let base = reddsa::pallas_spend_auth_generator();
    match reddsa::pallas_public_from_secret(&ska, &base) {
        Ok(pk) => {
            slice::from_raw_parts_mut(pk_out, 32).copy_from_slice(&pk);
            OK
        }
        Err(_) => ERR,
    }
}

#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_reddsa_pallas_binding_pk(sk: *const u8, pk_out: *mut u8) -> i32 {
    if sk.is_null() || pk_out.is_null() {
        return ERR;
    }
    let ska = sk32(sk);
    let base = reddsa::pallas_binding_generator();
    match reddsa::pallas_public_from_secret(&ska, &base) {
        Ok(pk) => {
            slice::from_raw_parts_mut(pk_out, 32).copy_from_slice(&pk);
            OK
        }
        Err(_) => ERR,
    }
}

#[cfg(test)]
mod strictness_tests {
    use super::*;
    use core::ptr;

    #[test]
    fn sign_rejects_null_rand() {
        let sk = [0u8; 32];
        let msg = [0u8; 1];
        let mut sig = [0u8; 64];
        // Valid pointers except rand: must error, never silently generate.
        assert_eq!(
            unsafe {
                bu_reddsa_jubjub_auth_sign(
                    sk.as_ptr(),
                    msg.as_ptr(),
                    0,
                    ptr::null(),
                    sig.as_mut_ptr(),
                )
            },
            ERR
        );
        assert_eq!(
            unsafe {
                bu_reddsa_jubjub_binding_sign(
                    sk.as_ptr(),
                    msg.as_ptr(),
                    0,
                    ptr::null(),
                    sig.as_mut_ptr(),
                )
            },
            ERR
        );
        assert_eq!(
            unsafe {
                bu_reddsa_pallas_auth_sign(
                    sk.as_ptr(),
                    msg.as_ptr(),
                    0,
                    ptr::null(),
                    sig.as_mut_ptr(),
                )
            },
            ERR
        );
        assert_eq!(
            unsafe {
                bu_reddsa_pallas_binding_sign(
                    sk.as_ptr(),
                    msg.as_ptr(),
                    0,
                    ptr::null(),
                    sig.as_mut_ptr(),
                )
            },
            ERR
        );
    }
}
