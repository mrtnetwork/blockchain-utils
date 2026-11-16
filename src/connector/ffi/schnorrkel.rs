//! Schnorrkel (sr25519) FFI: sign/verify, HDKD, VRF/DLEQ, validity checks.

#![cfg(feature = "ffi")]

use crate::merlin::Transcript;
use crate::schnorrkel::{
    vrf_hash, vrf_script, MiniSecretKey, PublicKey, SecretKey, Signature, VrfInOut, VrfProof,
};
use core::slice;

pub const BU_SR25519_OK: i32 = 0;
pub const BU_SR25519_ERR_NULL: i32 = 1;
pub const BU_SR25519_ERR_LEN: i32 = 2;
pub const BU_SR25519_ERR_INVALID: i32 = 3;
pub const BU_SR25519_ERR_VERIFY: i32 = 4;

fn check_in(p: *const u8, len: usize, need: usize) -> Result<(), i32> {
    if p.is_null() && need > 0 {
        return Err(BU_SR25519_ERR_NULL);
    }
    if len < need {
        return Err(BU_SR25519_ERR_LEN);
    }
    Ok(())
}
fn check_out(p: *mut u8, len: usize, need: usize) -> Result<(), i32> {
    if p.is_null() {
        return Err(BU_SR25519_ERR_NULL);
    }
    if len < need {
        return Err(BU_SR25519_ERR_LEN);
    }
    Ok(())
}
unsafe fn read32(p: *const u8) -> [u8; 32] {
    let mut b = [0u8; 32];
    b.copy_from_slice(slice::from_raw_parts(p, 32));
    b
}
unsafe fn read64(p: *const u8) -> [u8; 64] {
    let mut b = [0u8; 64];
    b.copy_from_slice(slice::from_raw_parts(p, 64));
    b
}
unsafe fn write_slice(out: *mut u8, data: &[u8]) {
    slice::from_raw_parts_mut(out, data.len()).copy_from_slice(data);
}
fn sk_from_seed(seed: &[u8; 32], uniform: bool) -> SecretKey {
    let m = MiniSecretKey::from_bytes(seed);
    if uniform {
        m.expand_uniform()
    } else {
        m.expand_ed25519()
    }
}
fn sk_from_ptr(
    seed_or_sk: *const u8,
    len: usize,
    from_seed: bool,
    uniform: bool,
) -> Result<SecretKey, i32> {
    if from_seed {
        if len < 32 {
            return Err(BU_SR25519_ERR_LEN);
        }
        Ok(sk_from_seed(&unsafe { read32(seed_or_sk) }, uniform))
    } else {
        if len < 64 {
            return Err(BU_SR25519_ERR_LEN);
        }
        SecretKey::from_bytes(&unsafe { read64(seed_or_sk) }).ok_or(BU_SR25519_ERR_INVALID)
    }
}
fn signing_context(ctx: &[u8], msg: &[u8]) -> Transcript {
    let mut t = Transcript::new(b"SigningContext");
    t.append_message(b"", ctx);
    t.append_message(b"sign-bytes", msg);
    t
}

/// Public key from 32-byte mini-secret. `uniform != 0` → expand_uniform, else ed25519.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_sr25519_public_key(
    seed: *const u8,
    seed_len: usize,
    uniform: i32,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if let Err(e) = check_in(seed, seed_len, 32) {
        return e;
    }
    if let Err(e) = check_out(out, out_len, 32) {
        return e;
    }
    let sk = sk_from_seed(&read32(seed), uniform != 0);
    write_slice(out, &sk.public_key().to_bytes());
    BU_SR25519_OK
}

/// Mini-secret (32) → expanded secret (64 = scalar‖nonce).
/// `uniform != 0` → expand_uniform, else Ed25519 expand (default / Substrate).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_sr25519_secret_from_seed(
    seed: *const u8,
    seed_len: usize,
    uniform: i32,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if let Err(e) = check_in(seed, seed_len, 32) {
        return e;
    }
    if let Err(e) = check_out(out, out_len, 64) {
        return e;
    }
    let sk = sk_from_seed(&read32(seed), uniform != 0);
    write_slice(out, &sk.to_bytes());
    BU_SR25519_OK
}

/// Public key from 64-byte expanded secret.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_sr25519_public_key_from_secret(
    sk: *const u8,
    sk_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if let Err(e) = check_in(sk, sk_len, 64) {
        return e;
    }
    if let Err(e) = check_out(out, out_len, 32) {
        return e;
    }
    let secret = match SecretKey::from_bytes(&read64(sk)) {
        Some(s) => s,
        None => return BU_SR25519_ERR_INVALID,
    };
    write_slice(out, &secret.public_key().to_bytes());
    BU_SR25519_OK
}

/// 1 if pk is valid non-identity Ristretto, else 0.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_sr25519_is_valid_public_key(pk: *const u8, pk_len: usize) -> i32 {
    if check_in(pk, pk_len, 32).is_err() {
        return 0;
    }
    if PublicKey::is_valid(&read32(pk)) {
        1
    } else {
        0
    }
}

/// 1 if 64-byte expanded secret parses, else 0.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_sr25519_is_valid_secret_key(sk: *const u8, sk_len: usize) -> i32 {
    if check_in(sk, sk_len, 64).is_err() {
        return 0;
    }
    if SecretKey::from_bytes(&read64(sk)).is_some() {
        1
    } else {
        0
    }
}

/// Sign: seed(32) or sk(64) + message + nonce64 → sig64.
/// `from_seed != 0` uses mini-secret; `uniform` only applies when from_seed.
/// `ctx` / `ctx_len` = SigningContext domain (default empty → use "substrate" if ctx null).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_sr25519_sign(
    seed_or_sk: *const u8,
    seed_or_sk_len: usize,
    from_seed: i32,
    uniform: i32,
    ctx: *const u8,
    ctx_len: usize,
    msg: *const u8,
    msg_len: usize,
    nonce64: *const u8,
    nonce_len: usize,
    sig_out: *mut u8,
    sig_out_len: usize,
) -> i32 {
    if let Err(e) = check_out(sig_out, sig_out_len, 64) {
        return e;
    }
    if let Err(e) = check_in(nonce64, nonce_len, 64) {
        return e;
    }
    let sk = match sk_from_ptr(seed_or_sk, seed_or_sk_len, from_seed != 0, uniform != 0) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let context = if ctx.is_null() || ctx_len == 0 {
        b"substrate".as_slice()
    } else {
        slice::from_raw_parts(ctx, ctx_len)
    };
    let message = if msg_len == 0 || msg.is_null() {
        &[][..]
    } else {
        slice::from_raw_parts(msg, msg_len)
    };
    let mut t = signing_context(context, message);
    let sig = sk.sign(&mut t, &read64(nonce64));
    write_slice(sig_out, &sig.to_bytes());
    BU_SR25519_OK
}

#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_sr25519_verify(
    pk: *const u8,
    pk_len: usize,
    ctx: *const u8,
    ctx_len: usize,
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
    let public = match PublicKey::from_bytes(&read32(pk)) {
        Ok(p) => p,
        Err(_) => return BU_SR25519_ERR_INVALID,
    };
    let context = if ctx.is_null() || ctx_len == 0 {
        b"substrate".as_slice()
    } else {
        slice::from_raw_parts(ctx, ctx_len)
    };
    let message = if msg_len == 0 || msg.is_null() {
        &[][..]
    } else {
        slice::from_raw_parts(msg, msg_len)
    };
    let mut t = signing_context(context, message);
    let signature = match Signature::from_bytes(&read64(sig)) {
        Some(s) => s,
        None => return BU_SR25519_ERR_INVALID,
    };
    if public.verify(&mut t, &signature) {
        BU_SR25519_OK
    } else {
        BU_SR25519_ERR_VERIFY
    }
}

/// Expanded secret → Ed25519-style (8·sk ‖ nonce).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_sr25519_to_ed25519_bytes(
    sk: *const u8,
    sk_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if let Err(e) = check_in(sk, sk_len, 64) {
        return e;
    }
    if let Err(e) = check_out(out, out_len, 64) {
        return e;
    }
    let secret = match SecretKey::from_bytes(&read64(sk)) {
        Some(s) => s,
        None => return BU_SR25519_ERR_INVALID,
    };
    write_slice(out, &secret.to_ed25519_bytes());
    BU_SR25519_OK
}

/// Hard derive: seed/sk → new expanded sk64 + chaincode32.
/// out must be 96 bytes: sk(64) || chain(32).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_sr25519_hard_derive(
    seed_or_sk: *const u8,
    seed_or_sk_len: usize,
    from_seed: i32,
    uniform: i32,
    chain: *const u8,
    chain_len: usize,
    msg: *const u8,
    msg_len: usize,
    out96: *mut u8,
    out_len: usize,
) -> i32 {
    if let Err(e) = check_in(chain, chain_len, 32) {
        return e;
    }
    if let Err(e) = check_out(out96, out_len, 96) {
        return e;
    }
    let sk = match sk_from_ptr(seed_or_sk, seed_or_sk_len, from_seed != 0, uniform != 0) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let message = if msg_len == 0 || msg.is_null() {
        &[][..]
    } else {
        slice::from_raw_parts(msg, msg_len)
    };
    let (new_sk, cc) = sk.hard_derive(&read32(chain), message, uniform == 0);
    let bytes = new_sk.to_bytes();
    let o = slice::from_raw_parts_mut(out96, 96);
    o[..64].copy_from_slice(&bytes);
    o[64..].copy_from_slice(&cc);
    BU_SR25519_OK
}

/// Soft derive: requires new_nonce32. out96 = sk64 || chain32.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_sr25519_soft_derive(
    seed_or_sk: *const u8,
    seed_or_sk_len: usize,
    from_seed: i32,
    uniform: i32,
    chain: *const u8,
    chain_len: usize,
    msg: *const u8,
    msg_len: usize,
    new_nonce: *const u8,
    new_nonce_len: usize,
    out96: *mut u8,
    out_len: usize,
) -> i32 {
    if let Err(e) = check_in(chain, chain_len, 32) {
        return e;
    }
    if let Err(e) = check_in(new_nonce, new_nonce_len, 32) {
        return e;
    }
    if let Err(e) = check_out(out96, out_len, 96) {
        return e;
    }
    let sk = match sk_from_ptr(seed_or_sk, seed_or_sk_len, from_seed != 0, uniform != 0) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let message = if msg_len == 0 || msg.is_null() {
        &[][..]
    } else {
        slice::from_raw_parts(msg, msg_len)
    };
    let (new_sk, cc) = match sk.soft_derive(&read32(chain), message, &read32(new_nonce)) {
        Some(x) => x,
        None => return BU_SR25519_ERR_INVALID,
    };
    let bytes = new_sk.to_bytes();
    let o = slice::from_raw_parts_mut(out96, 96);
    o[..64].copy_from_slice(&bytes);
    o[64..].copy_from_slice(&cc);
    BU_SR25519_OK
}

/// Public soft derive: pk32 + chain32 → out64 = new_pk32 || chain32.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_sr25519_derive_public(
    pk: *const u8,
    pk_len: usize,
    chain: *const u8,
    chain_len: usize,
    msg: *const u8,
    msg_len: usize,
    out64: *mut u8,
    out_len: usize,
) -> i32 {
    if let Err(e) = check_in(pk, pk_len, 32) {
        return e;
    }
    if let Err(e) = check_in(chain, chain_len, 32) {
        return e;
    }
    if let Err(e) = check_out(out64, out_len, 64) {
        return e;
    }
    let public = match PublicKey::from_bytes(&read32(pk)) {
        Ok(p) => p,
        Err(_) => return BU_SR25519_ERR_INVALID,
    };
    let message = if msg_len == 0 || msg.is_null() {
        &[][..]
    } else {
        slice::from_raw_parts(msg, msg_len)
    };
    let (new_pk, cc) = match public.derive(&read32(chain), message) {
        Some(x) => x,
        None => return BU_SR25519_ERR_INVALID,
    };
    let o = slice::from_raw_parts_mut(out64, 64);
    o[..32].copy_from_slice(&new_pk.to_bytes());
    o[32..].copy_from_slice(&cc);
    BU_SR25519_OK
}

/// VRF hash: SigningContext(ctx)+msg → 32-byte input point (needs pk for vrf-nm-pk).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_sr25519_vrf_hash(
    pk: *const u8,
    pk_len: usize,
    ctx: *const u8,
    ctx_len: usize,
    msg: *const u8,
    msg_len: usize,
    out32: *mut u8,
    out_len: usize,
) -> i32 {
    if let Err(e) = check_in(pk, pk_len, 32) {
        return e;
    }
    if let Err(e) = check_out(out32, out_len, 32) {
        return e;
    }
    let context = if ctx.is_null() || ctx_len == 0 {
        b"substrate".as_slice()
    } else {
        slice::from_raw_parts(ctx, ctx_len)
    };
    let message = if msg_len == 0 || msg.is_null() {
        &[][..]
    } else {
        slice::from_raw_parts(msg, msg_len)
    };
    let mut t = signing_context(context, message);
    let h = vrf_hash(&mut t, &read32(pk));
    let mut enc = [0u8; 32];
    if h.encode(&mut enc).is_err() {
        return BU_SR25519_ERR_INVALID;
    }
    write_slice(out32, &enc);
    BU_SR25519_OK
}

/// VRF in/out: out64 = input32 || output32.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_sr25519_vrf_in_out(
    seed_or_sk: *const u8,
    seed_or_sk_len: usize,
    from_seed: i32,
    uniform: i32,
    ctx: *const u8,
    ctx_len: usize,
    msg: *const u8,
    msg_len: usize,
    out64: *mut u8,
    out_len: usize,
) -> i32 {
    if let Err(e) = check_out(out64, out_len, 64) {
        return e;
    }
    let sk = match sk_from_ptr(seed_or_sk, seed_or_sk_len, from_seed != 0, uniform != 0) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let context = if ctx.is_null() || ctx_len == 0 {
        b"substrate".as_slice()
    } else {
        slice::from_raw_parts(ctx, ctx_len)
    };
    let message = if msg_len == 0 || msg.is_null() {
        &[][..]
    } else {
        slice::from_raw_parts(msg, msg_len)
    };
    let mut t = signing_context(context, message);
    let io = sk.vrf_in_out(&mut t);
    let o = slice::from_raw_parts_mut(out64, 64);
    o[..32].copy_from_slice(&io.input);
    o[32..].copy_from_slice(&io.output);
    BU_SR25519_OK
}

/// DLEQ prove: out64 = c32||s32. `nonce64` is 64 random bytes. kusama!=0 → Kusama ordering.
/// `extra` optional prove-transcript data (`vrfScript(extra:)`).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_sr25519_dleq_prove(
    seed_or_sk: *const u8,
    seed_or_sk_len: usize,
    from_seed: i32,
    uniform: i32,
    inout64: *const u8,
    inout_len: usize,
    nonce64: *const u8,
    nonce_len: usize,
    kusama: i32,
    extra: *const u8,
    extra_len: usize,
    out64: *mut u8,
    out_len: usize,
) -> i32 {
    if let Err(e) = check_in(inout64, inout_len, 64) {
        return e;
    }
    if let Err(e) = check_in(nonce64, nonce_len, 64) {
        return e;
    }
    if let Err(e) = check_out(out64, out_len, 64) {
        return e;
    }
    let sk = match sk_from_ptr(seed_or_sk, seed_or_sk_len, from_seed != 0, uniform != 0) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let raw = read64(inout64);
    let mut input = [0u8; 32];
    let mut output = [0u8; 32];
    input.copy_from_slice(&raw[..32]);
    output.copy_from_slice(&raw[32..]);
    let inout = VrfInOut { input, output };
    let extra_sl: Option<&[u8]> = if extra.is_null() || extra_len == 0 {
        None
    } else {
        Some(slice::from_raw_parts(extra, extra_len))
    };
    let mut prove_t = vrf_script(extra_sl);
    let proof = match sk.dleq_prove(&mut prove_t, &inout, &read64(nonce64), kusama != 0) {
        Some(p) => p,
        None => return BU_SR25519_ERR_INVALID,
    };
    write_slice(out64, &proof.to_bytes());
    BU_SR25519_OK
}

/// DLEQ verify. `extra` must match prove-time `vrfScript(extra:)`.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_sr25519_dleq_verify(
    pk: *const u8,
    pk_len: usize,
    inout64: *const u8,
    inout_len: usize,
    proof64: *const u8,
    proof_len: usize,
    kusama: i32,
    extra: *const u8,
    extra_len: usize,
) -> i32 {
    if let Err(e) = check_in(pk, pk_len, 32) {
        return e;
    }
    if let Err(e) = check_in(inout64, inout_len, 64) {
        return e;
    }
    if let Err(e) = check_in(proof64, proof_len, 64) {
        return e;
    }
    let public = match PublicKey::from_bytes(&read32(pk)) {
        Ok(p) => p,
        Err(_) => return BU_SR25519_ERR_INVALID,
    };
    let raw = read64(inout64);
    let mut input = [0u8; 32];
    let mut output = [0u8; 32];
    input.copy_from_slice(&raw[..32]);
    output.copy_from_slice(&raw[32..]);
    let inout = VrfInOut { input, output };
    let proof = VrfProof::from_bytes(&read64(proof64));
    let extra_sl: Option<&[u8]> = if extra.is_null() || extra_len == 0 {
        None
    } else {
        Some(slice::from_raw_parts(extra, extra_len))
    };
    let mut t = vrf_script(extra_sl);
    if public.dleq_verify(&mut t, &inout, &proof, kusama != 0) {
        BU_SR25519_OK
    } else {
        BU_SR25519_ERR_VERIFY
    }
}

/// VRF sign: out96 = preout32 || proof64 (c||s).
///
/// `ctx` is the SigningContext domain (null/empty → empty, not "substrate").
/// `extra` is optional prove-transcript domain (`vrfScript(extra:)`).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_sr25519_vrf_sign(
    seed_or_sk: *const u8,
    seed_or_sk_len: usize,
    from_seed: i32,
    uniform: i32,
    ctx: *const u8,
    ctx_len: usize,
    msg: *const u8,
    msg_len: usize,
    nonce64: *const u8,
    nonce_len: usize,
    kusama: i32,
    extra: *const u8,
    extra_len: usize,
    out96: *mut u8,
    out_len: usize,
) -> i32 {
    if let Err(e) = check_in(nonce64, nonce_len, 64) {
        return e;
    }
    if let Err(e) = check_out(out96, out_len, 96) {
        return e;
    }
    let sk = match sk_from_ptr(seed_or_sk, seed_or_sk_len, from_seed != 0, uniform != 0) {
        Ok(s) => s,
        Err(e) => return e,
    };
    // Substrate VRF: context defaults to empty, not "substrate"
    let context = if ctx.is_null() || ctx_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(ctx, ctx_len)
    };
    let message = if msg_len == 0 || msg.is_null() {
        &[][..]
    } else {
        slice::from_raw_parts(msg, msg_len)
    };
    let extra_sl: Option<&[u8]> = if extra.is_null() || extra_len == 0 {
        None
    } else {
        Some(slice::from_raw_parts(extra, extra_len))
    };
    let mut t = signing_context(context, message);
    let mut prove_t = vrf_script(extra_sl);
    let (inout, proof) = match sk.vrf_sign(&mut t, &mut prove_t, &read64(nonce64), kusama != 0) {
        Some(x) => x,
        None => return BU_SR25519_ERR_INVALID,
    };
    let o = slice::from_raw_parts_mut(out96, 96);
    o[..32].copy_from_slice(&inout.output);
    o[32..].copy_from_slice(&proof.to_bytes());
    BU_SR25519_OK
}

/// VRF verify: needs preout32, proof64; optional `extra` for prove transcript.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_sr25519_vrf_verify(
    pk: *const u8,
    pk_len: usize,
    ctx: *const u8,
    ctx_len: usize,
    msg: *const u8,
    msg_len: usize,
    preout32: *const u8,
    preout_len: usize,
    proof64: *const u8,
    proof_len: usize,
    kusama: i32,
    extra: *const u8,
    extra_len: usize,
) -> i32 {
    if let Err(e) = check_in(pk, pk_len, 32) {
        return e;
    }
    if let Err(e) = check_in(preout32, preout_len, 32) {
        return e;
    }
    if let Err(e) = check_in(proof64, proof_len, 64) {
        return e;
    }
    let public = match PublicKey::from_bytes(&read32(pk)) {
        Ok(p) => p,
        Err(_) => return BU_SR25519_ERR_INVALID,
    };
    let context = if ctx.is_null() || ctx_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(ctx, ctx_len)
    };
    let message = if msg_len == 0 || msg.is_null() {
        &[][..]
    } else {
        slice::from_raw_parts(msg, msg_len)
    };
    let extra_sl: Option<&[u8]> = if extra.is_null() || extra_len == 0 {
        None
    } else {
        Some(slice::from_raw_parts(extra, extra_len))
    };
    let mut t = signing_context(context, message);
    let pk_b = read32(pk);
    let h = vrf_hash(&mut t, &pk_b);
    let mut input = [0u8; 32];
    if h.encode(&mut input).is_err() {
        return BU_SR25519_ERR_INVALID;
    }
    let inout = VrfInOut {
        input,
        output: read32(preout32),
    };
    let proof = VrfProof::from_bytes(&read64(proof64));
    let mut prove_t = vrf_script(extra_sl);
    if public.vrf_verify(
        &mut signing_context(context, message),
        &mut prove_t,
        &inout,
        &proof,
        kusama != 0,
    ) {
        BU_SR25519_OK
    } else {
        BU_SR25519_ERR_VERIFY
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sr25519_roundtrip_and_valid() {
        let seed = [7u8; 32];
        let mut pk = [0u8; 32];
        assert_eq!(
            unsafe { bu_sr25519_public_key(seed.as_ptr(), 32, 0, pk.as_mut_ptr(), 32) },
            BU_SR25519_OK
        );
        assert_eq!(
            unsafe { bu_sr25519_is_valid_public_key(pk.as_ptr(), 32) },
            1
        );
        let msg = b"substrate hello";
        let nonce = [9u8; 64];
        let mut sig = [0u8; 64];
        assert_eq!(
            unsafe {
                bu_sr25519_sign(
                    seed.as_ptr(),
                    32,
                    1,
                    0,
                    core::ptr::null(),
                    0,
                    msg.as_ptr(),
                    msg.len(),
                    nonce.as_ptr(),
                    64,
                    sig.as_mut_ptr(),
                    64,
                )
            },
            BU_SR25519_OK
        );
        assert_eq!(
            unsafe {
                bu_sr25519_verify(
                    pk.as_ptr(),
                    32,
                    core::ptr::null(),
                    0,
                    msg.as_ptr(),
                    msg.len(),
                    sig.as_ptr(),
                    64,
                )
            },
            BU_SR25519_OK
        );
    }
}
