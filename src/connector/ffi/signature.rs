//! Signature scheme FFI (feature `ffi`).
//!
//! Schemes:
//! - Ed25519 (RFC 8032) — 32-byte seed, 32-byte pk, 64-byte sig, arbitrary message
//! - ECDSA secp256k1 — 32-byte sk, 33-byte compressed pk, 64-byte compact (r‖s), 32-byte hash
//! - ECDSA secp256r1 — same layout as k1
//! - BIP-340 Schnorr — 32-byte sk, 32-byte x-only pk, 64-byte sig, message bytes

use core::slice;

use crate::signature::ecdsa::{
    self as ecdsa_k1, PublicKey as EcdsaK1Pk, SecretKey as EcdsaK1Sk, Signature as EcdsaK1Sig,
};
use crate::signature::ecdsa_p256::{
    self as ecdsa_r1, PublicKey as EcdsaR1Pk, SecretKey as EcdsaR1Sk, Signature as EcdsaR1Sig,
};
use crate::signature::ed25519::{
    self as ed25519, PublicKey as EdPk, SecretKey as EdSk, Signature as EdSig, Variant as EdVariant,
};
use crate::signature::schnorr::{
    self as bip340, PublicKey as SchnorrPk, SecretKey as SchnorrSk, Signature as SchnorrSig,
};
use crate::signature::schnorr_bch;

/// Success.
pub const BU_SIG_OK: i32 = 0;
/// Null pointer.
pub const BU_SIG_ERR_NULL: i32 = 1;
/// Buffer too small / wrong length.
pub const BU_SIG_ERR_BUFFER: i32 = 2;
/// Invalid private key.
pub const BU_SIG_ERR_INVALID_SK: i32 = 3;
/// Invalid public key.
pub const BU_SIG_ERR_INVALID_PK: i32 = 4;
/// Invalid signature encoding.
pub const BU_SIG_ERR_INVALID_SIG: i32 = 5;
/// Verification failed.
pub const BU_SIG_ERR_VERIFY: i32 = 6;
/// Internal / other failure.
pub const BU_SIG_ERR_INTERNAL: i32 = 7;

fn map_err(e: crate::signature::error::SignatureError) -> i32 {
    use crate::signature::error::SignatureError::*;
    match e {
        InvalidLength | InvalidEncoding => BU_SIG_ERR_BUFFER,
        InvalidPrivateKey => BU_SIG_ERR_INVALID_SK,
        InvalidPublicKey => BU_SIG_ERR_INVALID_PK,
        InvalidSignature => BU_SIG_ERR_INVALID_SIG,
        VerificationFailed => BU_SIG_ERR_VERIFY,
        Unsupported | Failure(_) => BU_SIG_ERR_INTERNAL,
    }
}

fn check_in(ptr: *const u8, len: usize, need: usize) -> Result<(), i32> {
    if ptr.is_null() {
        return Err(BU_SIG_ERR_NULL);
    }
    if len < need {
        return Err(BU_SIG_ERR_BUFFER);
    }
    Ok(())
}

fn check_out(ptr: *mut u8, len: usize, need: usize) -> Result<(), i32> {
    if ptr.is_null() {
        return Err(BU_SIG_ERR_NULL);
    }
    if len < need {
        return Err(BU_SIG_ERR_BUFFER);
    }
    Ok(())
}

fn read32(ptr: *const u8) -> [u8; 32] {
    let mut a = [0u8; 32];
    a.copy_from_slice(unsafe { slice::from_raw_parts(ptr, 32) });
    a
}

fn write_bytes(out: *mut u8, data: &[u8]) {
    unsafe {
        slice::from_raw_parts_mut(out, data.len()).copy_from_slice(data);
    }
}

// ---------------------------------------------------------------------------
// Ed25519
// ---------------------------------------------------------------------------

/// Derive Ed25519 public key from 32-byte seed.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_ed25519_public_key(
    sk: *const u8,
    sk_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if let Err(e) = check_in(sk, sk_len, 32) {
        return e;
    }
    if let Err(e) = check_out(out, out_len, 32) {
        return e;
    }
    let secret = match EdSk::from_bytes(&read32(sk)) {
        Ok(s) => s,
        Err(e) => return map_err(e),
    };
    match secret.public_key() {
        Ok(pk) => {
            write_bytes(out, &pk.0);
            BU_SIG_OK
        }
        Err(e) => map_err(e),
    }
}

/// Ed25519 sign: `sig` must be ≥ 64 bytes. Message may be any length (including 0).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_ed25519_sign(
    sk: *const u8,
    sk_len: usize,
    msg: *const u8,
    msg_len: usize,
    sig_out: *mut u8,
    sig_len: usize,
) -> i32 {
    if let Err(e) = check_in(sk, sk_len, 32) {
        return e;
    }
    if msg_len > 0 {
        if let Err(e) = check_in(msg, msg_len, msg_len) {
            return e;
        }
    } else if msg.is_null() && msg_len != 0 {
        return BU_SIG_ERR_NULL;
    }
    if let Err(e) = check_out(sig_out, sig_len, 64) {
        return e;
    }
    let secret = match EdSk::from_bytes(&read32(sk)) {
        Ok(s) => s,
        Err(e) => return map_err(e),
    };
    let message = if msg_len == 0 {
        &[][..]
    } else {
        unsafe { slice::from_raw_parts(msg, msg_len) }
    };
    match ed25519::sign(&secret, message) {
        Ok(sig) => {
            write_bytes(sig_out, &sig.0);
            BU_SIG_OK
        }
        Err(e) => map_err(e),
    }
}

/// Ed25519 verify. Returns `BU_SIG_OK` or `BU_SIG_ERR_VERIFY`.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_ed25519_verify(
    pk: *const u8,
    pk_len: usize,
    msg: *const u8,
    msg_len: usize,
    sig: *const u8,
    sig_len: usize,
) -> i32 {
    if let Err(e) = check_in(pk, pk_len, 32) {
        return e;
    }
    if let Err(e) = check_in(sig, sig_len, 64) {
        return e;
    }
    if msg_len > 0 {
        if let Err(e) = check_in(msg, msg_len, msg_len) {
            return e;
        }
    }
    let public = match EdPk::from_bytes(&read32(pk)) {
        Ok(p) => p,
        Err(e) => return map_err(e),
    };
    let mut sb = [0u8; 64];
    sb.copy_from_slice(unsafe { slice::from_raw_parts(sig, 64) });
    let signature = match EdSig::from_bytes(&sb) {
        Ok(s) => s,
        Err(e) => return map_err(e),
    };
    let message = if msg_len == 0 {
        &[][..]
    } else {
        unsafe { slice::from_raw_parts(msg, msg_len) }
    };
    match ed25519::verify(&public, message, &signature) {
        Ok(()) => BU_SIG_OK,
        Err(e) => map_err(e),
    }
}

// ---------------------------------------------------------------------------
// ECDSA secp256k1
// ---------------------------------------------------------------------------

/// secp256k1 public key (33-byte compressed) from 32-byte secret.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_ecdsa_k1_public_key(
    sk: *const u8,
    sk_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if let Err(e) = check_in(sk, sk_len, 32) {
        return e;
    }
    if let Err(e) = check_out(out, out_len, 33) {
        return e;
    }
    let secret = match EcdsaK1Sk::from_bytes(&read32(sk)) {
        Ok(s) => s,
        Err(e) => return map_err(e),
    };
    match secret.public_key() {
        Ok(pk) => {
            let mut buf = [0u8; 33];
            if let Err(e) = pk.to_bytes_compressed(&mut buf) {
                return map_err(e);
            }
            write_bytes(out, &buf);
            BU_SIG_OK
        }
        Err(e) => map_err(e),
    }
}

/// ECDSA-secp256k1 sign over a **32-byte message hash** (caller hashes).
/// Output: 64-byte compact `r‖s` (low-S).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_ecdsa_k1_sign(
    sk: *const u8,
    sk_len: usize,
    hash32: *const u8,
    hash_len: usize,
    sig_out: *mut u8,
    sig_len: usize,
) -> i32 {
    if let Err(e) = check_in(sk, sk_len, 32) {
        return e;
    }
    if let Err(e) = check_in(hash32, hash_len, 32) {
        return e;
    }
    if let Err(e) = check_out(sig_out, sig_len, 64) {
        return e;
    }
    let secret = match EcdsaK1Sk::from_bytes(&read32(sk)) {
        Ok(s) => s,
        Err(e) => return map_err(e),
    };
    let h = read32(hash32);
    match ecdsa_k1::sign(&secret, &h) {
        Ok(sig) => {
            let mut buf = [0u8; 64];
            sig.to_compact(&mut buf);
            write_bytes(sig_out, &buf);
            BU_SIG_OK
        }
        Err(e) => map_err(e),
    }
}

/// ECDSA-secp256k1 sign with optional RFC 6979 extra entropy.
/// `extra` may be null (omit) or point to any length (callers pass 32-byte entropy).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_ecdsa_k1_sign_ex(
    sk: *const u8,
    sk_len: usize,
    hash32: *const u8,
    hash_len: usize,
    extra: *const u8,
    extra_len: usize,
    sig_out: *mut u8,
    sig_len: usize,
) -> i32 {
    if let Err(e) = check_in(sk, sk_len, 32) {
        return e;
    }
    if let Err(e) = check_in(hash32, hash_len, 32) {
        return e;
    }
    if let Err(e) = check_out(sig_out, sig_len, 64) {
        return e;
    }
    let secret = match EcdsaK1Sk::from_bytes(&read32(sk)) {
        Ok(s) => s,
        Err(e) => return map_err(e),
    };
    let h = read32(hash32);
    let extra_opt = if extra.is_null() || extra_len == 0 {
        None
    } else {
        Some(unsafe { slice::from_raw_parts(extra, extra_len) })
    };
    match ecdsa_k1::sign_ex(&secret, &h, extra_opt) {
        Ok(sig) => {
            let mut buf = [0u8; 64];
            sig.to_compact(&mut buf);
            write_bytes(sig_out, &buf);
            BU_SIG_OK
        }
        Err(e) => map_err(e),
    }
}

/// ECDSA-secp256k1 verify. `hash32` is the 32-byte message digest; `sig` is 64-byte compact.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_ecdsa_k1_verify(
    pk: *const u8,
    pk_len: usize,
    hash32: *const u8,
    hash_len: usize,
    sig: *const u8,
    sig_len: usize,
) -> i32 {
    if let Err(e) = check_in(pk, pk_len, 33) {
        return e;
    }
    if let Err(e) = check_in(hash32, hash_len, 32) {
        return e;
    }
    if let Err(e) = check_in(sig, sig_len, 64) {
        return e;
    }
    let pk_bytes = unsafe { slice::from_raw_parts(pk, 33) };
    let public = match EcdsaK1Pk::from_bytes(pk_bytes) {
        Ok(p) => p,
        Err(e) => return map_err(e),
    };
    let signature = match EcdsaK1Sig::from_compact(unsafe { slice::from_raw_parts(sig, 64) }) {
        Ok(s) => s,
        Err(e) => return map_err(e),
    };
    let h = read32(hash32);
    match ecdsa_k1::verify(&public, &h, &signature) {
        Ok(()) => BU_SIG_OK,
        Err(e) => map_err(e),
    }
}

// ---------------------------------------------------------------------------
// ECDSA secp256r1
// ---------------------------------------------------------------------------

/// secp256r1 public key (33-byte compressed) from 32-byte secret.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_ecdsa_r1_public_key(
    sk: *const u8,
    sk_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if let Err(e) = check_in(sk, sk_len, 32) {
        return e;
    }
    if let Err(e) = check_out(out, out_len, 33) {
        return e;
    }
    let secret = match EcdsaR1Sk::from_bytes(&read32(sk)) {
        Ok(s) => s,
        Err(e) => return map_err(e),
    };
    match secret.public_key() {
        Ok(pk) => {
            let mut buf = [0u8; 33];
            if let Err(e) = pk.to_bytes_compressed(&mut buf) {
                return map_err(e);
            }
            write_bytes(out, &buf);
            BU_SIG_OK
        }
        Err(e) => map_err(e),
    }
}

/// ECDSA-secp256r1 sign over a 32-byte hash → 64-byte compact `r‖s`.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_ecdsa_r1_sign(
    sk: *const u8,
    sk_len: usize,
    hash32: *const u8,
    hash_len: usize,
    sig_out: *mut u8,
    sig_len: usize,
) -> i32 {
    if let Err(e) = check_in(sk, sk_len, 32) {
        return e;
    }
    if let Err(e) = check_in(hash32, hash_len, 32) {
        return e;
    }
    if let Err(e) = check_out(sig_out, sig_len, 64) {
        return e;
    }
    let secret = match EcdsaR1Sk::from_bytes(&read32(sk)) {
        Ok(s) => s,
        Err(e) => return map_err(e),
    };
    let h = read32(hash32);
    match ecdsa_r1::sign(&secret, &h) {
        Ok(sig) => {
            let mut buf = [0u8; 64];
            sig.to_compact(&mut buf);
            write_bytes(sig_out, &buf);
            BU_SIG_OK
        }
        Err(e) => map_err(e),
    }
}

/// ECDSA-secp256r1 verify.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_ecdsa_r1_verify(
    pk: *const u8,
    pk_len: usize,
    hash32: *const u8,
    hash_len: usize,
    sig: *const u8,
    sig_len: usize,
) -> i32 {
    if let Err(e) = check_in(pk, pk_len, 33) {
        return e;
    }
    if let Err(e) = check_in(hash32, hash_len, 32) {
        return e;
    }
    if let Err(e) = check_in(sig, sig_len, 64) {
        return e;
    }
    let pk_bytes = unsafe { slice::from_raw_parts(pk, 33) };
    let public = match EcdsaR1Pk::from_bytes(pk_bytes) {
        Ok(p) => p,
        Err(e) => return map_err(e),
    };
    let signature = match EcdsaR1Sig::from_compact(unsafe { slice::from_raw_parts(sig, 64) }) {
        Ok(s) => s,
        Err(e) => return map_err(e),
    };
    let h = read32(hash32);
    match ecdsa_r1::verify(&public, &h, &signature) {
        Ok(()) => BU_SIG_OK,
        Err(e) => map_err(e),
    }
}

// ---------------------------------------------------------------------------

/// Recover compressed pubkey (33) from hash32 + compact sig64 + recovery id (0..3).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_ecdsa_r1_recover(
    hash32: *const u8,
    sig: *const u8,
    rec_id: u8,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if let Err(e) = check_in(hash32, 32, 32) {
        return e;
    }
    if let Err(e) = check_in(sig, 64, 64) {
        return e;
    }
    if let Err(e) = check_out(out, out_len, 33) {
        return e;
    }
    let h = read32(hash32);
    let raw = unsafe { slice::from_raw_parts(sig, 64) };
    let signature = match EcdsaR1Sig::from_compact(raw) {
        Ok(s) => s,
        Err(e) => return map_err(e),
    };
    match ecdsa_r1::recover(&h, &signature, rec_id) {
        Ok(pk) => {
            let mut buf = [0u8; 33];
            if pk.to_bytes_compressed(&mut buf).is_err() {
                return BU_SIG_ERR_INVALID_PK;
            }
            write_bytes(out, &buf);
            BU_SIG_OK
        }
        Err(e) => map_err(e),
    }
}

/// Compute recovery id (0..3) for known compressed pubkey (33 bytes).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_ecdsa_r1_recovery_id(
    hash32: *const u8,
    sig: *const u8,
    pk: *const u8,
    pk_len: usize,
    out_id: *mut u8,
) -> i32 {
    if let Err(e) = check_in(hash32, 32, 32) {
        return e;
    }
    if let Err(e) = check_in(sig, 64, 64) {
        return e;
    }
    if pk.is_null() || pk_len != 33 || out_id.is_null() {
        return BU_SIG_ERR_INVALID_PK;
    }
    let h = read32(hash32);
    let raw = unsafe { slice::from_raw_parts(sig, 64) };
    let signature = match EcdsaR1Sig::from_compact(raw) {
        Ok(s) => s,
        Err(e) => return map_err(e),
    };
    let public = match EcdsaR1Pk::from_bytes(unsafe { slice::from_raw_parts(pk, 33) }) {
        Ok(p) => p,
        Err(e) => return map_err(e),
    };
    match ecdsa_r1::recovery_id_for(&h, &signature, &public) {
        Ok(id) => {
            *out_id = id;
            BU_SIG_OK
        }
        Err(e) => map_err(e),
    }
}

// BIP-340 Schnorr (secp256k1)
// ---------------------------------------------------------------------------

/// BIP-340 x-only public key (32 bytes) from 32-byte secret.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_schnorr_public_key(
    sk: *const u8,
    sk_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if let Err(e) = check_in(sk, sk_len, 32) {
        return e;
    }
    if let Err(e) = check_out(out, out_len, 32) {
        return e;
    }
    let secret = match SchnorrSk::from_bytes(&read32(sk)) {
        Ok(s) => s,
        Err(e) => return map_err(e),
    };
    match secret.public_key() {
        Ok(pk) => {
            write_bytes(out, &pk.0);
            BU_SIG_OK
        }
        Err(e) => map_err(e),
    }
}

/// BIP-340 sign over `msg` (any length) → 64-byte signature.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_schnorr_sign(
    sk: *const u8,
    sk_len: usize,
    msg: *const u8,
    msg_len: usize,
    sig_out: *mut u8,
    sig_len: usize,
) -> i32 {
    if let Err(e) = check_in(sk, sk_len, 32) {
        return e;
    }
    if msg_len > 0 {
        if let Err(e) = check_in(msg, msg_len, msg_len) {
            return e;
        }
    }
    if let Err(e) = check_out(sig_out, sig_len, 64) {
        return e;
    }
    let secret = match SchnorrSk::from_bytes(&read32(sk)) {
        Ok(s) => s,
        Err(e) => return map_err(e),
    };
    let message = if msg_len == 0 {
        &[][..]
    } else {
        unsafe { slice::from_raw_parts(msg, msg_len) }
    };
    match bip340::sign(&secret, message) {
        Ok(sig) => {
            let mut buf = [0u8; 64];
            buf[0..32].copy_from_slice(&sig.rx);
            buf[32..64].copy_from_slice(&sig.s);
            write_bytes(sig_out, &buf);
            BU_SIG_OK
        }
        Err(e) => map_err(e),
    }
}

/// BIP-340 verify.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_schnorr_verify(
    pk: *const u8,
    pk_len: usize,
    msg: *const u8,
    msg_len: usize,
    sig: *const u8,
    sig_len: usize,
) -> i32 {
    if let Err(e) = check_in(pk, pk_len, 32) {
        return e;
    }
    if let Err(e) = check_in(sig, sig_len, 64) {
        return e;
    }
    if msg_len > 0 {
        if let Err(e) = check_in(msg, msg_len, msg_len) {
            return e;
        }
    }
    let public = match SchnorrPk::from_bytes(&read32(pk)) {
        Ok(p) => p,
        Err(e) => return map_err(e),
    };
    let raw = unsafe { slice::from_raw_parts(sig, 64) };
    let mut rx = [0u8; 32];
    let mut ss = [0u8; 32];
    rx.copy_from_slice(&raw[0..32]);
    ss.copy_from_slice(&raw[32..64]);
    let signature = SchnorrSig { rx, s: ss };
    let message = if msg_len == 0 {
        &[][..]
    } else {
        unsafe { slice::from_raw_parts(msg, msg_len) }
    };
    match bip340::verify(&public, message, &signature) {
        Ok(()) => BU_SIG_OK,
        Err(e) => map_err(e),
    }
}

// ---------------------------------------------------------------------------
// BIP-340 aux / tweak
// ---------------------------------------------------------------------------

/// BIP-340 sign with optional 32-byte aux and optional 32-byte tweak.
/// `aux` / `tweak` may be null (omit).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_schnorr_sign_aux(
    sk: *const u8,
    sk_len: usize,
    msg: *const u8,
    msg_len: usize,
    aux: *const u8,
    tweak: *const u8,
    sig_out: *mut u8,
    sig_len: usize,
) -> i32 {
    if let Err(e) = check_in(sk, sk_len, 32) {
        return e;
    }
    if let Err(e) = check_out(sig_out, sig_len, 64) {
        return e;
    }
    if msg_len > 0 {
        if let Err(e) = check_in(msg, msg_len, msg_len) {
            return e;
        }
    }
    let secret = match SchnorrSk::from_bytes(&read32(sk)) {
        Ok(s) => s,
        Err(e) => return map_err(e),
    };
    let message = if msg_len == 0 {
        &[][..]
    } else {
        unsafe { slice::from_raw_parts(msg, msg_len) }
    };
    let aux_opt = if aux.is_null() {
        None
    } else {
        Some(read32(aux))
    };
    let tweak_opt = if tweak.is_null() {
        None
    } else {
        Some(read32(tweak))
    };
    match bip340::sign_with_aux_and_tweak(&secret, message, aux_opt.as_ref(), tweak_opt.as_ref()) {
        Ok(sig) => {
            let mut buf = [0u8; 64];
            buf[0..32].copy_from_slice(&sig.rx);
            buf[32..64].copy_from_slice(&sig.s);
            write_bytes(sig_out, &buf);
            BU_SIG_OK
        }
        Err(e) => map_err(e),
    }
}

/// Tweak secret key: out 32-byte sk' = sk + tweak (even-Y adjusted).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_schnorr_tweak_secret(
    sk: *const u8,
    tweak: *const u8,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if let Err(e) = check_in(sk, 32, 32) {
        return e;
    }
    if let Err(e) = check_in(tweak, 32, 32) {
        return e;
    }
    if let Err(e) = check_out(out, out_len, 32) {
        return e;
    }
    let secret = match SchnorrSk::from_bytes(&read32(sk)) {
        Ok(s) => s,
        Err(e) => return map_err(e),
    };
    match bip340::tweak_secret(&secret, &read32(tweak)) {
        Ok(sk2) => {
            let mut b = [0u8; 32];
            sk2.to_bytes(&mut b);
            write_bytes(out, &b);
            BU_SIG_OK
        }
        Err(e) => map_err(e),
    }
}

/// Tweak x-only public key (32 → 32).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_schnorr_tweak_public(
    pk: *const u8,
    tweak: *const u8,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if let Err(e) = check_in(pk, 32, 32) {
        return e;
    }
    if let Err(e) = check_in(tweak, 32, 32) {
        return e;
    }
    if let Err(e) = check_out(out, out_len, 32) {
        return e;
    }
    let public = match SchnorrPk::from_bytes(&read32(pk)) {
        Ok(p) => p,
        Err(e) => return map_err(e),
    };
    match bip340::tweak_public(&public, &read32(tweak)) {
        Ok(pk2) => {
            write_bytes(out, &pk2.0);
            BU_SIG_OK
        }
        Err(e) => map_err(e),
    }
}

// ---------------------------------------------------------------------------
// ECDSA secp256k1 recover
// ---------------------------------------------------------------------------

/// Recover compressed pubkey (33) from hash32 + compact sig64 + recovery id (0..3).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_ecdsa_k1_recover(
    hash32: *const u8,
    sig: *const u8,
    rec_id: u8,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if let Err(e) = check_in(hash32, 32, 32) {
        return e;
    }
    if let Err(e) = check_in(sig, 64, 64) {
        return e;
    }
    if let Err(e) = check_out(out, out_len, 33) {
        return e;
    }
    let h = read32(hash32);
    let raw = unsafe { slice::from_raw_parts(sig, 64) };
    let signature = match EcdsaK1Sig::from_compact(raw) {
        Ok(s) => s,
        Err(e) => return map_err(e),
    };
    match ecdsa_k1::recover(&h, &signature, rec_id) {
        Ok(pk) => {
            let mut buf = [0u8; 33];
            if pk.to_bytes_compressed(&mut buf).is_err() {
                return BU_SIG_ERR_INVALID_PK;
            }
            write_bytes(out, &buf);
            BU_SIG_OK
        }
        Err(e) => map_err(e),
    }
}

/// Try rec_id 0..3; write compressed pk and return recovery id, or error.
/// `rec_out` optional (nullable) single byte.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_ecdsa_k1_recover_any(
    hash32: *const u8,
    sig: *const u8,
    out: *mut u8,
    out_len: usize,
    rec_out: *mut u8,
) -> i32 {
    if let Err(e) = check_in(hash32, 32, 32) {
        return e;
    }
    if let Err(e) = check_in(sig, 64, 64) {
        return e;
    }
    if let Err(e) = check_out(out, out_len, 33) {
        return e;
    }
    let h = read32(hash32);
    let raw = unsafe { slice::from_raw_parts(sig, 64) };
    let signature = match EcdsaK1Sig::from_compact(raw) {
        Ok(s) => s,
        Err(e) => return map_err(e),
    };
    match ecdsa_k1::recover_and_verify(&h, &signature) {
        Ok((pk, id)) => {
            let mut buf = [0u8; 33];
            if pk.to_bytes_compressed(&mut buf).is_err() {
                return BU_SIG_ERR_INVALID_PK;
            }
            write_bytes(out, &buf);
            if !rec_out.is_null() {
                *rec_out = id;
            }
            BU_SIG_OK
        }
        Err(e) => map_err(e),
    }
}

// ---------------------------------------------------------------------------
// BCH / legacy Schnorr (not BIP-340)
// ---------------------------------------------------------------------------

/// BCH-style Schnorr sign (digest 32 → sig 64). Optional extra entropy; null → default "Schnorr+SHA256  ".
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_schnorr_bch_sign(
    sk: *const u8,
    sk_len: usize,
    digest: *const u8,
    digest_len: usize,
    extra: *const u8,
    extra_len: usize,
    sig_out: *mut u8,
    sig_len: usize,
) -> i32 {
    if let Err(e) = check_in(sk, sk_len, 32) {
        return e;
    }
    if let Err(e) = check_in(digest, digest_len, 32) {
        return e;
    }
    if let Err(e) = check_out(sig_out, sig_len, 64) {
        return e;
    }
    let secret = match EcdsaK1Sk::from_bytes(&read32(sk)) {
        Ok(s) => s,
        Err(e) => return map_err(e),
    };
    let h = read32(digest);
    let extra_opt = if extra.is_null() || extra_len == 0 {
        None
    } else {
        Some(unsafe { slice::from_raw_parts(extra, extra_len) })
    };
    match schnorr_bch::sign(&secret, &h, extra_opt) {
        Ok(sig) => {
            let mut buf = [0u8; 64];
            sig.to_compact(&mut buf);
            write_bytes(sig_out, &buf);
            BU_SIG_OK
        }
        Err(e) => map_err(e),
    }
}

/// BCH-style Schnorr verify.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_schnorr_bch_verify(
    pk: *const u8,
    pk_len: usize,
    digest: *const u8,
    digest_len: usize,
    sig: *const u8,
    sig_len: usize,
) -> i32 {
    if let Err(e) = check_in(pk, pk_len, 33) {
        return e;
    }
    if let Err(e) = check_in(digest, digest_len, 32) {
        return e;
    }
    if let Err(e) = check_in(sig, sig_len, 64) {
        return e;
    }
    let public = match EcdsaK1Pk::from_bytes(unsafe { slice::from_raw_parts(pk, 33) }) {
        Ok(p) => p,
        Err(e) => return map_err(e),
    };
    let h = read32(digest);
    let signature = match EcdsaK1Sig::from_compact(unsafe { slice::from_raw_parts(sig, 64) }) {
        Ok(s) => s,
        Err(e) => return map_err(e),
    };
    match schnorr_bch::verify(&public, &h, &signature) {
        Ok(()) => BU_SIG_OK,
        Err(e) => map_err(e),
    }
}

/// Derive public key for Ed25519 variant.
/// `variant`: 0=Ed25519, 1=Blake2b, 2=Kholaw, 3=Monero.
/// `sk_len` 32 for 0/1, 64 for 2/3.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_ed25519_public_key_variant(
    variant: u8,
    sk: *const u8,
    sk_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if sk.is_null() || out.is_null() {
        return BU_SIG_ERR_NULL;
    }
    if out_len < 32 {
        return BU_SIG_ERR_BUFFER;
    }
    let Some(v) = EdVariant::from_u8(variant) else {
        return BU_SIG_ERR_INTERNAL;
    };
    if sk_len != v.secret_len() {
        return BU_SIG_ERR_BUFFER;
    }
    let secret = slice::from_raw_parts(sk, sk_len);
    match ed25519::public_key_variant(secret, v) {
        Ok(pk) => {
            slice::from_raw_parts_mut(out, 32).copy_from_slice(&pk.0);
            BU_SIG_OK
        }
        Err(e) => map_err(e),
    }
}

/// Sign with Ed25519 variant (see `bu_ed25519_public_key_variant` for variant codes).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_ed25519_sign_variant(
    variant: u8,
    sk: *const u8,
    sk_len: usize,
    msg: *const u8,
    msg_len: usize,
    sig_out: *mut u8,
    sig_len: usize,
) -> i32 {
    if sk.is_null() || msg.is_null() || sig_out.is_null() {
        return BU_SIG_ERR_NULL;
    }
    if sig_len < 64 {
        return BU_SIG_ERR_BUFFER;
    }
    let Some(v) = EdVariant::from_u8(variant) else {
        return BU_SIG_ERR_INTERNAL;
    };
    if sk_len != v.secret_len() {
        return BU_SIG_ERR_BUFFER;
    }
    let secret = slice::from_raw_parts(sk, sk_len);
    let message = slice::from_raw_parts(msg, msg_len);
    match ed25519::sign_variant(secret, message, v) {
        Ok(sig) => {
            slice::from_raw_parts_mut(sig_out, 64).copy_from_slice(&sig.0);
            BU_SIG_OK
        }
        Err(e) => map_err(e),
    }
}

/// Verify with Ed25519 variant.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_ed25519_verify_variant(
    variant: u8,
    pk: *const u8,
    pk_len: usize,
    msg: *const u8,
    msg_len: usize,
    sig: *const u8,
    sig_len: usize,
) -> i32 {
    if pk.is_null() || msg.is_null() || sig.is_null() {
        return BU_SIG_ERR_NULL;
    }
    if pk_len != 32 || sig_len != 64 {
        return BU_SIG_ERR_BUFFER;
    }
    let Some(v) = EdVariant::from_u8(variant) else {
        return BU_SIG_ERR_INTERNAL;
    };
    let public = match ed25519::PublicKey::from_bytes(slice::from_raw_parts(pk, 32)) {
        Ok(p) => p,
        Err(e) => return map_err(e),
    };
    let signature = match ed25519::Signature::from_bytes(slice::from_raw_parts(sig, 64)) {
        Ok(s) => s,
        Err(e) => return map_err(e),
    };
    let message = slice::from_raw_parts(msg, msg_len);
    match ed25519::verify_variant(&public, message, &signature, v) {
        Ok(()) => BU_SIG_OK,
        Err(e) => map_err(e),
    }
}

/// ECDSA P-256 sign with optional extra entropy (null = pure RFC6979).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_ecdsa_r1_sign_ex(
    sk: *const u8,
    sk_len: usize,
    hash: *const u8,
    hash_len: usize,
    extra: *const u8,
    extra_len: usize,
    sig_out: *mut u8,
    sig_len: usize,
) -> i32 {
    if let Err(e) = check_in(sk, sk_len, 32) {
        return e;
    }
    if let Err(e) = check_in(hash, hash_len, 32) {
        return e;
    }
    if let Err(e) = check_out(sig_out, sig_len, 64) {
        return e;
    }
    let secret = match crate::signature::ecdsa_p256::SecretKey::from_bytes(&read32(sk)) {
        Ok(s) => s,
        Err(e) => return map_err(e),
    };
    let h = read32(hash);
    let extra_opt = if extra.is_null() || extra_len == 0 {
        None
    } else {
        Some(slice::from_raw_parts(extra, extra_len))
    };
    match crate::signature::ecdsa_p256::sign_ex(&secret, &h, extra_opt) {
        Ok(sig) => {
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&sig.r);
            buf[32..].copy_from_slice(&sig.s);
            write_bytes(sig_out, &buf);
            BU_SIG_OK
        }
        Err(e) => map_err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(s: &str) -> [u8; 32] {
        let mut o = [0u8; 32];
        for i in 0..32 {
            o[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        o
    }

    #[test]
    fn ed25519_sign_verify_roundtrip() {
        let sk = hex32("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let mut pk = [0u8; 32];
        assert_eq!(
            unsafe { bu_ed25519_public_key(sk.as_ptr(), 32, pk.as_mut_ptr(), 32) },
            BU_SIG_OK
        );
        let msg = b"test message";
        let mut sig = [0u8; 64];
        assert_eq!(
            unsafe {
                bu_ed25519_sign(
                    sk.as_ptr(),
                    32,
                    msg.as_ptr(),
                    msg.len(),
                    sig.as_mut_ptr(),
                    64,
                )
            },
            BU_SIG_OK
        );
        assert_eq!(
            unsafe {
                bu_ed25519_verify(pk.as_ptr(), 32, msg.as_ptr(), msg.len(), sig.as_ptr(), 64)
            },
            BU_SIG_OK
        );
        // tamper — may yield INVALID_SIG (bad point) or VERIFY failure
        sig[0] ^= 1;
        let rc = unsafe {
            bu_ed25519_verify(pk.as_ptr(), 32, msg.as_ptr(), msg.len(), sig.as_ptr(), 64)
        };
        assert!(
            rc == BU_SIG_ERR_VERIFY || rc == BU_SIG_ERR_INVALID_SIG,
            "tampered sig rc={rc}"
        );
    }

    #[test]
    fn ecdsa_k1_sign_verify_roundtrip() {
        let sk = hex32("0000000000000000000000000000000000000000000000000000000000000001");
        let mut pk = [0u8; 33];
        assert_eq!(
            unsafe { bu_ecdsa_k1_public_key(sk.as_ptr(), 32, pk.as_mut_ptr(), 33) },
            BU_SIG_OK
        );
        let hash = [0xabu8; 32];
        let mut sig = [0u8; 64];
        assert_eq!(
            unsafe { bu_ecdsa_k1_sign(sk.as_ptr(), 32, hash.as_ptr(), 32, sig.as_mut_ptr(), 64) },
            BU_SIG_OK
        );
        assert_eq!(
            unsafe { bu_ecdsa_k1_verify(pk.as_ptr(), 33, hash.as_ptr(), 32, sig.as_ptr(), 64) },
            BU_SIG_OK
        );
    }

    #[test]
    fn ecdsa_r1_sign_verify_roundtrip() {
        let sk = hex32("0000000000000000000000000000000000000000000000000000000000000001");
        let mut pk = [0u8; 33];
        let rc = unsafe { bu_ecdsa_r1_public_key(sk.as_ptr(), 32, pk.as_mut_ptr(), 33) };
        assert_eq!(rc, BU_SIG_OK, "r1 public_key");
        let hash = [0xcdu8; 32];
        let mut sig = [0u8; 64];
        assert_eq!(
            unsafe { bu_ecdsa_r1_sign(sk.as_ptr(), 32, hash.as_ptr(), 32, sig.as_mut_ptr(), 64) },
            BU_SIG_OK
        );
        assert_eq!(
            unsafe { bu_ecdsa_r1_verify(pk.as_ptr(), 33, hash.as_ptr(), 32, sig.as_ptr(), 64) },
            BU_SIG_OK
        );
    }

    #[test]
    fn schnorr_sign_verify_roundtrip() {
        let sk = hex32("0000000000000000000000000000000000000000000000000000000000000001");
        let mut pk = [0u8; 32];
        assert_eq!(
            unsafe { bu_schnorr_public_key(sk.as_ptr(), 32, pk.as_mut_ptr(), 32) },
            BU_SIG_OK
        );
        let msg = b"bip340 test";
        let mut sig = [0u8; 64];
        assert_eq!(
            unsafe {
                bu_schnorr_sign(
                    sk.as_ptr(),
                    32,
                    msg.as_ptr(),
                    msg.len(),
                    sig.as_mut_ptr(),
                    64,
                )
            },
            BU_SIG_OK
        );
        assert_eq!(
            unsafe {
                bu_schnorr_verify(pk.as_ptr(), 32, msg.as_ptr(), msg.len(), sig.as_ptr(), 64)
            },
            BU_SIG_OK
        );
    }
}
