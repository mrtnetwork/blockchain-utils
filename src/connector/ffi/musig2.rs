//! FFI for BIP-327 MuSig2 (requires `alloc` + `ffi`).

#![cfg(all(feature = "ffi", feature = "alloc"))]

use core::slice;

use crate::curve::traits::CurvePoint;
use crate::musig2::{
    deterministic_sign, key_agg, key_agg_and_tweak, nonce_agg, nonce_generate, partial_sig_agg,
    partial_sig_verify, partial_sign, verify_aggregate, Session, Tweak,
};

pub const BU_MUSIG_OK: i32 = 0;
pub const BU_MUSIG_ERR: i32 = 1;
pub const BU_MUSIG_ERR_LEN: i32 = 2;
pub const BU_MUSIG_ERR_KEY: i32 = 3;
pub const BU_MUSIG_ERR_VERIFY: i32 = 4;

fn map_err(e: crate::musig2::Musig2Error) -> i32 {
    use crate::musig2::Musig2Error::*;
    match e {
        InvalidLength | TooFewKeys => BU_MUSIG_ERR_LEN,
        InvalidKey | InvalidScalar | InvalidNonce => BU_MUSIG_ERR_KEY,
        _ => BU_MUSIG_ERR,
    }
}

/// Aggregate compressed pubkeys. `keys` is concatenated 33-byte keys, `n_keys` count.
/// Writes 33-byte aggregated Q into `out`.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_musig2_key_agg(
    keys: *const u8,
    n_keys: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if keys.is_null() || out.is_null() || n_keys < 2 || out_len < 33 {
        return BU_MUSIG_ERR_LEN;
    }
    let raw = slice::from_raw_parts(keys, n_keys * 33);
    let mut refs: alloc::vec::Vec<&[u8]> = alloc::vec::Vec::with_capacity(n_keys);
    for i in 0..n_keys {
        refs.push(&raw[i * 33..(i + 1) * 33]);
    }
    match key_agg(&refs) {
        Ok(ctx) => {
            let out = slice::from_raw_parts_mut(out, 33);
            if CurvePoint::to_bytes_compressed(&ctx.q, out).is_err() {
                return BU_MUSIG_ERR_KEY;
            }
            BU_MUSIG_OK
        }
        Err(e) => map_err(e),
    }
}

/// Key aggregation with optional tweaks.
/// `tweaks` is concatenated 33-byte records: [is_x_only:u8][tweak:32].
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_musig2_key_agg_tweak(
    keys: *const u8,
    n_keys: usize,
    tweaks: *const u8,
    n_tweaks: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if keys.is_null() || out.is_null() || n_keys < 2 || out_len < 33 {
        return BU_MUSIG_ERR_LEN;
    }
    let raw = slice::from_raw_parts(keys, n_keys * 33);
    let mut refs: alloc::vec::Vec<&[u8]> = alloc::vec::Vec::with_capacity(n_keys);
    for i in 0..n_keys {
        refs.push(&raw[i * 33..(i + 1) * 33]);
    }
    let mut tw: alloc::vec::Vec<Tweak> = alloc::vec::Vec::new();
    if n_tweaks > 0 {
        if tweaks.is_null() {
            return BU_MUSIG_ERR_LEN;
        }
        let traw = slice::from_raw_parts(tweaks, n_tweaks * 33);
        for i in 0..n_tweaks {
            let chunk = &traw[i * 33..(i + 1) * 33];
            let mut t = [0u8; 32];
            t.copy_from_slice(&chunk[1..33]);
            tw.push(Tweak {
                tweak: t,
                is_x_only: chunk[0] != 0,
            });
        }
    }
    match key_agg_and_tweak(&refs, &tw) {
        Ok(ctx) => {
            let out = slice::from_raw_parts_mut(out, 33);
            if CurvePoint::to_bytes_compressed(&ctx.q, out).is_err() {
                return BU_MUSIG_ERR_KEY;
            }
            BU_MUSIG_OK
        }
        Err(e) => map_err(e),
    }
}

/// Generate nonce. Writes secnonce (97) and pubnonce (66).
/// Optional: pk (33), agg_pk (33), msg, extra. Required: 32-byte `rand` (non-null).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_musig2_nonce_gen(
    sk: *const u8,
    sk_len: usize,
    pk: *const u8,
    pk_len: usize,
    agg_pk: *const u8,
    agg_pk_len: usize,
    msg: *const u8,
    msg_len: usize,
    extra: *const u8,
    extra_len: usize,
    rand: *const u8,
    secnonce_out: *mut u8,
    secnonce_len: usize,
    pubnonce_out: *mut u8,
    pubnonce_len: usize,
) -> i32 {
    if secnonce_out.is_null() || pubnonce_out.is_null() {
        return BU_MUSIG_ERR_LEN;
    }
    if secnonce_len < 97 || pubnonce_len < 66 {
        return BU_MUSIG_ERR_LEN;
    }
    let sk_opt = if !sk.is_null() && sk_len == 32 {
        let mut a = [0u8; 32];
        a.copy_from_slice(slice::from_raw_parts(sk, 32));
        Some(a)
    } else {
        None
    };
    let pk_sl = if !pk.is_null() && pk_len == 33 {
        Some(slice::from_raw_parts(pk, 33))
    } else {
        None
    };
    let agg_xonly: Option<[u8; 32]> = if !agg_pk.is_null() && agg_pk_len == 33 {
        let s = slice::from_raw_parts(agg_pk, 33);
        let mut x = [0u8; 32];
        x.copy_from_slice(&s[1..33]);
        Some(x)
    } else if !agg_pk.is_null() && agg_pk_len == 32 {
        let mut x = [0u8; 32];
        x.copy_from_slice(slice::from_raw_parts(agg_pk, 32));
        Some(x)
    } else {
        None
    };
    let agg_sl = agg_xonly.as_ref().map(|x| x.as_slice());
    // BIP-327: absent msg → 0x00; present empty msg → 0x01||len=0.
    // Non-null pointer with msg_len==0 means empty message present.
    let msg_sl = if msg.is_null() {
        None
    } else {
        Some(slice::from_raw_parts(msg, msg_len))
    };
    let extra_sl = if !extra.is_null() && extra_len > 0 {
        Some(slice::from_raw_parts(extra, extra_len))
    } else {
        None
    };
    if rand.is_null() {
        return BU_MUSIG_ERR_LEN;
    }
    let mut rand_a = [0u8; 32];
    rand_a.copy_from_slice(slice::from_raw_parts(rand, 32));
    // Our nonce_generate signature: (sk, pk, agg_pk, extra, msg, rand)
    match nonce_generate(
        sk_opt.as_ref(),
        pk_sl,
        agg_sl,
        extra_sl,
        msg_sl,
        &rand_a,
    ) {
        Ok(pair) => {
            let so = slice::from_raw_parts_mut(secnonce_out, 97);
            let po = slice::from_raw_parts_mut(pubnonce_out, 66);
            if pair.secnonce.len() < 97 || pair.pubnonce.len() < 66 {
                return BU_MUSIG_ERR;
            }
            so.copy_from_slice(&pair.secnonce[..97]);
            po.copy_from_slice(&pair.pubnonce[..66]);
            BU_MUSIG_OK
        }
        Err(e) => map_err(e),
    }
}

/// Aggregate public nonces (each 66 bytes). Writes 66-byte aggnonce.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_musig2_nonce_agg(
    pubnonces: *const u8,
    n: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if pubnonces.is_null() || out.is_null() || n < 1 || out_len < 66 {
        return BU_MUSIG_ERR_LEN;
    }
    let raw = slice::from_raw_parts(pubnonces, n * 66);
    let mut refs: alloc::vec::Vec<&[u8]> = alloc::vec::Vec::with_capacity(n);
    for i in 0..n {
        refs.push(&raw[i * 66..(i + 1) * 66]);
    }
    match nonce_agg(&refs) {
        Ok(agg) => {
            if agg.len() != 66 {
                return BU_MUSIG_ERR;
            }
            slice::from_raw_parts_mut(out, 66).copy_from_slice(&agg);
            BU_MUSIG_OK
        }
        Err(e) => map_err(e),
    }
}

fn build_session(
    keys: *const u8,
    n_keys: usize,
    aggnonce: *const u8,
    msg: *const u8,
    msg_len: usize,
    tweaks: *const u8,
    n_tweaks: usize,
) -> Result<Session, i32> {
    if keys.is_null() || aggnonce.is_null() || n_keys < 2 {
        return Err(BU_MUSIG_ERR_LEN);
    }
    let raw = unsafe { slice::from_raw_parts(keys, n_keys * 33) };
    let mut public_keys = alloc::vec::Vec::with_capacity(n_keys);
    for i in 0..n_keys {
        public_keys.push(raw[i * 33..(i + 1) * 33].to_vec());
    }
    let mut ag = [0u8; 66];
    ag.copy_from_slice(unsafe { slice::from_raw_parts(aggnonce, 66) });
    let message = if msg.is_null() || msg_len == 0 {
        alloc::vec::Vec::new()
    } else {
        unsafe { slice::from_raw_parts(msg, msg_len).to_vec() }
    };
    let mut tw = alloc::vec::Vec::new();
    if n_tweaks > 0 {
        if tweaks.is_null() {
            return Err(BU_MUSIG_ERR_LEN);
        }
        let traw = unsafe { slice::from_raw_parts(tweaks, n_tweaks * 33) };
        for i in 0..n_tweaks {
            let chunk = &traw[i * 33..(i + 1) * 33];
            let mut t = [0u8; 32];
            t.copy_from_slice(&chunk[1..33]);
            tw.push(Tweak {
                tweak: t,
                is_x_only: chunk[0] != 0,
            });
        }
    }
    Ok(Session {
        public_keys,
        aggnonce: ag.to_vec(),
        msg: message,
        tweaks: tw,
    })
}

/// Partial sign. Writes 32-byte partial.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_musig2_partial_sign(
    secnonce: *const u8,
    secnonce_len: usize,
    sk: *const u8,
    sk_len: usize,
    keys: *const u8,
    n_keys: usize,
    aggnonce: *const u8,
    msg: *const u8,
    msg_len: usize,
    tweaks: *const u8,
    n_tweaks: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if secnonce.is_null() || sk.is_null() || out.is_null() || sk_len != 32 || out_len < 32 {
        return BU_MUSIG_ERR_LEN;
    }
    if secnonce_len < 97 {
        return BU_MUSIG_ERR_LEN;
    }
    let session = match build_session(keys, n_keys, aggnonce, msg, msg_len, tweaks, n_tweaks) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sn = slice::from_raw_parts(secnonce, secnonce_len);
    let mut sk_a = [0u8; 32];
    sk_a.copy_from_slice(slice::from_raw_parts(sk, 32));
    match partial_sign(sn, &sk_a, &session) {
        Ok(ps) => {
            slice::from_raw_parts_mut(out, 32).copy_from_slice(&ps);
            BU_MUSIG_OK
        }
        Err(e) => map_err(e),
    }
}

/// Aggregate partials → BIP-340 64-byte signature.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_musig2_partial_sig_agg(
    partials: *const u8,
    n_partials: usize,
    keys: *const u8,
    n_keys: usize,
    aggnonce: *const u8,
    msg: *const u8,
    msg_len: usize,
    tweaks: *const u8,
    n_tweaks: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if partials.is_null() || out.is_null() || n_partials == 0 || out_len < 64 {
        return BU_MUSIG_ERR_LEN;
    }
    let session = match build_session(keys, n_keys, aggnonce, msg, msg_len, tweaks, n_tweaks) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let raw = slice::from_raw_parts(partials, n_partials * 32);
    let mut parts: alloc::vec::Vec<[u8; 32]> = alloc::vec::Vec::with_capacity(n_partials);
    for i in 0..n_partials {
        let mut p = [0u8; 32];
        p.copy_from_slice(&raw[i * 32..(i + 1) * 32]);
        parts.push(p);
    }
    match partial_sig_agg(&parts, &session) {
        Ok(sig) => {
            slice::from_raw_parts_mut(out, 64).copy_from_slice(&sig);
            BU_MUSIG_OK
        }
        Err(e) => map_err(e),
    }
}

/// Verify a partial signature. Returns 0 if ok, BU_MUSIG_ERR_VERIFY if false.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_musig2_partial_sig_verify(
    partial: *const u8,
    pubnonce: *const u8,
    pk: *const u8,
    keys: *const u8,
    n_keys: usize,
    aggnonce: *const u8,
    msg: *const u8,
    msg_len: usize,
    tweaks: *const u8,
    n_tweaks: usize,
) -> i32 {
    if partial.is_null() || pubnonce.is_null() || pk.is_null() {
        return BU_MUSIG_ERR_LEN;
    }
    let session = match build_session(keys, n_keys, aggnonce, msg, msg_len, tweaks, n_tweaks) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let mut ps = [0u8; 32];
    ps.copy_from_slice(slice::from_raw_parts(partial, 32));
    let mut pn = [0u8; 66];
    pn.copy_from_slice(slice::from_raw_parts(pubnonce, 66));
    let pk_sl = slice::from_raw_parts(pk, 33);
    match partial_sig_verify(&ps, &pn, pk_sl, &session) {
        Ok(true) => BU_MUSIG_OK,
        Ok(false) => BU_MUSIG_ERR_VERIFY,
        Err(e) => map_err(e),
    }
}

/// BIP-327 DeterministicSign.
/// Writes pubnonce (66) and partial (32).
/// `aggother` is 66 bytes; `keys` concatenated 33-byte pubs; optional `rand` (null = none).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_musig2_deterministic_sign(
    sk: *const u8,
    aggother: *const u8,
    keys: *const u8,
    n_keys: usize,
    msg: *const u8,
    msg_len: usize,
    tweaks: *const u8,
    n_tweaks: usize,
    rand: *const u8,
    pubnonce_out: *mut u8,
    partial_out: *mut u8,
) -> i32 {
    if sk.is_null()
        || aggother.is_null()
        || keys.is_null()
        || pubnonce_out.is_null()
        || partial_out.is_null()
    {
        return BU_MUSIG_ERR_LEN;
    }
    if n_keys < 2 {
        return BU_MUSIG_ERR_LEN;
    }
    let mut ska = [0u8; 32];
    ska.copy_from_slice(slice::from_raw_parts(sk, 32));
    let other = slice::from_raw_parts(aggother, 66);
    let raw = slice::from_raw_parts(keys, n_keys * 33);
    let mut pks: alloc::vec::Vec<alloc::vec::Vec<u8>> = alloc::vec::Vec::with_capacity(n_keys);
    for i in 0..n_keys {
        pks.push(raw[i * 33..(i + 1) * 33].to_vec());
    }
    let mut tw: alloc::vec::Vec<Tweak> = alloc::vec::Vec::new();
    if n_tweaks > 0 {
        if tweaks.is_null() {
            return BU_MUSIG_ERR_LEN;
        }
        let traw = slice::from_raw_parts(tweaks, n_tweaks * 33);
        for i in 0..n_tweaks {
            let chunk = &traw[i * 33..(i + 1) * 33];
            let mut t32 = [0u8; 32];
            t32.copy_from_slice(&chunk[1..33]);
            tw.push(Tweak {
                tweak: t32,
                is_x_only: chunk[0] != 0,
            });
        }
    }
    let msg_sl = if msg.is_null() {
        &[][..]
    } else {
        slice::from_raw_parts(msg, msg_len)
    };
    let rand_a = if rand.is_null() {
        None
    } else {
        let mut r = [0u8; 32];
        r.copy_from_slice(slice::from_raw_parts(rand, 32));
        Some(r)
    };
    match deterministic_sign(&ska, other, &pks, &tw, msg_sl, rand_a.as_ref()) {
        Ok(d) => {
            slice::from_raw_parts_mut(pubnonce_out, 66).copy_from_slice(&d.pubnonce[..66]);
            slice::from_raw_parts_mut(partial_out, 32).copy_from_slice(&d.partial);
            BU_MUSIG_OK
        }
        Err(e) => map_err(e),
    }
}

/// BIP-340 verify of MuSig2 aggregate: msg, sig64, agg_xonly32.
/// Returns 0 if valid, BU_MUSIG_ERR_VERIFY if invalid.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_musig2_verify_aggregate(
    msg: *const u8,
    msg_len: usize,
    sig: *const u8,
    sig_len: usize,
    agg_xonly: *const u8,
    agg_len: usize,
) -> i32 {
    if msg.is_null() || sig.is_null() || agg_xonly.is_null() {
        return BU_MUSIG_ERR_LEN;
    }
    if sig_len != 64 || agg_len != 32 {
        return BU_MUSIG_ERR_LEN;
    }
    let m = slice::from_raw_parts(msg, msg_len);
    let s = slice::from_raw_parts(sig, 64);
    let x = slice::from_raw_parts(agg_xonly, 32);
    match verify_aggregate(m, s, x) {
        Ok(true) => BU_MUSIG_OK,
        Ok(false) => BU_MUSIG_ERR_VERIFY,
        Err(e) => map_err(e),
    }
}
