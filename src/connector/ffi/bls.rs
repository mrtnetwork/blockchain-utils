//! BLS12-381 signature FFI (min-pk / min-sig).

use core::slice;

use crate::signature::bls12_381::{
    aggregate_public_keys_g1, aggregate_public_keys_g2, aggregate_signatures_g1,
    aggregate_signatures_g2, aggregate_verify_min_pk, aggregate_verify_min_sig,
    batch_verify_min_pk, batch_verify_min_sig, fast_aggregate_verify_min_pk,
    fast_aggregate_verify_min_sig, sign_min_pk, sign_min_sig, verify_min_pk, verify_min_sig,
    PublicKeyG1, PublicKeyG2, SecretKey, SignatureG1, SignatureG2,
};

pub const BU_BLS_OK: i32 = 0;
pub const BU_BLS_ERR: i32 = 1;

/// Decode `n` messages from a blob of `[u32_be len][bytes]…`.
unsafe fn decode_msgs(
    blob: *const u8,
    blob_len: usize,
    n: usize,
) -> Option<std::vec::Vec<std::vec::Vec<u8>>> {
    if blob.is_null() && blob_len > 0 {
        return None;
    }
    let raw = if blob_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(blob, blob_len)
    };
    let mut out = std::vec::Vec::with_capacity(n);
    let mut off = 0usize;
    for _ in 0..n {
        if off + 4 > raw.len() {
            return None;
        }
        let len = u32::from_be_bytes([raw[off], raw[off + 1], raw[off + 2], raw[off + 3]]) as usize;
        off += 4;
        if off + len > raw.len() {
            return None;
        }
        out.push(raw[off..off + len].to_vec());
        off += len;
    }
    if off != raw.len() {
        return None;
    }
    Some(out)
}

#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_bls_sk_to_pk_g1(
    sk: *const u8,
    sk_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if sk.is_null() || out.is_null() || sk_len != 32 || out_len < 48 {
        return BU_BLS_ERR;
    }
    let Ok(secret) = SecretKey::from_bytes(slice::from_raw_parts(sk, 32)) else {
        return BU_BLS_ERR;
    };
    let mut buf = [0u8; 48];
    if secret
        .public_key_g1()
        .to_bytes_compressed(&mut buf)
        .is_err()
    {
        return BU_BLS_ERR;
    }
    slice::from_raw_parts_mut(out, 48).copy_from_slice(&buf);
    BU_BLS_OK
}

#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_bls_sk_to_pk_g2(
    sk: *const u8,
    sk_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if sk.is_null() || out.is_null() || sk_len != 32 || out_len < 96 {
        return BU_BLS_ERR;
    }
    let Ok(secret) = SecretKey::from_bytes(slice::from_raw_parts(sk, 32)) else {
        return BU_BLS_ERR;
    };
    let mut buf = [0u8; 96];
    if secret
        .public_key_g2()
        .to_bytes_compressed(&mut buf)
        .is_err()
    {
        return BU_BLS_ERR;
    }
    slice::from_raw_parts_mut(out, 96).copy_from_slice(&buf);
    BU_BLS_OK
}

#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_bls_sign_min_pk(
    sk: *const u8,
    sk_len: usize,
    msg: *const u8,
    msg_len: usize,
    dst: *const u8,
    dst_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if sk.is_null() || msg.is_null() || out.is_null() || sk_len != 32 || out_len < 96 {
        return BU_BLS_ERR;
    }
    let Ok(secret) = SecretKey::from_bytes(slice::from_raw_parts(sk, 32)) else {
        return BU_BLS_ERR;
    };
    let message = slice::from_raw_parts(msg, msg_len);
    let d = if dst.is_null() || dst_len == 0 {
        None
    } else {
        Some(slice::from_raw_parts(dst, dst_len))
    };
    let Ok(sig) = sign_min_pk(&secret, message, d) else {
        return BU_BLS_ERR;
    };
    let mut buf = [0u8; 96];
    if sig.to_bytes_compressed(&mut buf).is_err() {
        return BU_BLS_ERR;
    }
    slice::from_raw_parts_mut(out, 96).copy_from_slice(&buf);
    BU_BLS_OK
}

#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_bls_sign_min_sig(
    sk: *const u8,
    sk_len: usize,
    msg: *const u8,
    msg_len: usize,
    dst: *const u8,
    dst_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if sk.is_null() || msg.is_null() || out.is_null() || sk_len != 32 || out_len < 48 {
        return BU_BLS_ERR;
    }
    let Ok(secret) = SecretKey::from_bytes(slice::from_raw_parts(sk, 32)) else {
        return BU_BLS_ERR;
    };
    let message = slice::from_raw_parts(msg, msg_len);
    let d = if dst.is_null() || dst_len == 0 {
        None
    } else {
        Some(slice::from_raw_parts(dst, dst_len))
    };
    let Ok(sig) = sign_min_sig(&secret, message, d) else {
        return BU_BLS_ERR;
    };
    let mut buf = [0u8; 48];
    if sig.to_bytes_compressed(&mut buf).is_err() {
        return BU_BLS_ERR;
    }
    slice::from_raw_parts_mut(out, 48).copy_from_slice(&buf);
    BU_BLS_OK
}

#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_bls_verify_min_pk(
    pk: *const u8,
    pk_len: usize,
    msg: *const u8,
    msg_len: usize,
    sig: *const u8,
    sig_len: usize,
    dst: *const u8,
    dst_len: usize,
) -> i32 {
    if pk.is_null() || msg.is_null() || sig.is_null() || pk_len != 48 || sig_len != 96 {
        return BU_BLS_ERR;
    }
    let Ok(public) = PublicKeyG1::from_bytes(slice::from_raw_parts(pk, 48)) else {
        return BU_BLS_ERR;
    };
    let Ok(signature) = SignatureG2::from_bytes(slice::from_raw_parts(sig, 96)) else {
        return BU_BLS_ERR;
    };
    let message = slice::from_raw_parts(msg, msg_len);
    let d = if dst.is_null() || dst_len == 0 {
        None
    } else {
        Some(slice::from_raw_parts(dst, dst_len))
    };
    match verify_min_pk(&public, message, &signature, d) {
        Ok(()) => BU_BLS_OK,
        Err(_) => BU_BLS_ERR,
    }
}

#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_bls_verify_min_sig(
    pk: *const u8,
    pk_len: usize,
    msg: *const u8,
    msg_len: usize,
    sig: *const u8,
    sig_len: usize,
    dst: *const u8,
    dst_len: usize,
) -> i32 {
    if pk.is_null() || msg.is_null() || sig.is_null() || pk_len != 96 || sig_len != 48 {
        return BU_BLS_ERR;
    }
    let Ok(public) = PublicKeyG2::from_bytes(slice::from_raw_parts(pk, 96)) else {
        return BU_BLS_ERR;
    };
    let Ok(signature) = SignatureG1::from_bytes(slice::from_raw_parts(sig, 48)) else {
        return BU_BLS_ERR;
    };
    let message = slice::from_raw_parts(msg, msg_len);
    let d = if dst.is_null() || dst_len == 0 {
        None
    } else {
        Some(slice::from_raw_parts(dst, dst_len))
    };
    match verify_min_sig(&public, message, &signature, d) {
        Ok(()) => BU_BLS_OK,
        Err(_) => BU_BLS_ERR,
    }
}

// ---- Aggregation ----

/// Aggregate G1 public keys. `pks` is concatenated 48-byte compressed points.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_bls_aggregate_pks_g1(
    pks: *const u8,
    pks_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if pks.is_null() || out.is_null() || pks_len == 0 || !pks_len.is_multiple_of(48) || out_len < 48 {
        return BU_BLS_ERR;
    }
    let n = pks_len / 48;
    let raw = slice::from_raw_parts(pks, pks_len);
    let mut list = std::vec::Vec::with_capacity(n);
    for i in 0..n {
        match PublicKeyG1::from_bytes(&raw[i * 48..(i + 1) * 48]) {
            Ok(pk) => list.push(pk),
            Err(_) => return BU_BLS_ERR,
        }
    }
    let Ok(agg) = aggregate_public_keys_g1(&list) else {
        return BU_BLS_ERR;
    };
    let mut buf = [0u8; 48];
    if agg.to_bytes_compressed(&mut buf).is_err() {
        return BU_BLS_ERR;
    }
    slice::from_raw_parts_mut(out, 48).copy_from_slice(&buf);
    BU_BLS_OK
}

#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_bls_aggregate_pks_g2(
    pks: *const u8,
    pks_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if pks.is_null() || out.is_null() || pks_len == 0 || !pks_len.is_multiple_of(96) || out_len < 96 {
        return BU_BLS_ERR;
    }
    let n = pks_len / 96;
    let raw = slice::from_raw_parts(pks, pks_len);
    let mut list = std::vec::Vec::with_capacity(n);
    for i in 0..n {
        match PublicKeyG2::from_bytes(&raw[i * 96..(i + 1) * 96]) {
            Ok(pk) => list.push(pk),
            Err(_) => return BU_BLS_ERR,
        }
    }
    let Ok(agg) = aggregate_public_keys_g2(&list) else {
        return BU_BLS_ERR;
    };
    let mut buf = [0u8; 96];
    if agg.to_bytes_compressed(&mut buf).is_err() {
        return BU_BLS_ERR;
    }
    slice::from_raw_parts_mut(out, 96).copy_from_slice(&buf);
    BU_BLS_OK
}

#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_bls_aggregate_sigs_g1(
    sigs: *const u8,
    sigs_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if sigs.is_null() || out.is_null() || sigs_len == 0 || !sigs_len.is_multiple_of(48) || out_len < 48 {
        return BU_BLS_ERR;
    }
    let n = sigs_len / 48;
    let raw = slice::from_raw_parts(sigs, sigs_len);
    let mut list = std::vec::Vec::with_capacity(n);
    for i in 0..n {
        match SignatureG1::from_bytes(&raw[i * 48..(i + 1) * 48]) {
            Ok(s) => list.push(s),
            Err(_) => return BU_BLS_ERR,
        }
    }
    let Ok(agg) = aggregate_signatures_g1(&list) else {
        return BU_BLS_ERR;
    };
    let mut buf = [0u8; 48];
    if agg.to_bytes_compressed(&mut buf).is_err() {
        return BU_BLS_ERR;
    }
    slice::from_raw_parts_mut(out, 48).copy_from_slice(&buf);
    BU_BLS_OK
}

#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_bls_aggregate_sigs_g2(
    sigs: *const u8,
    sigs_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if sigs.is_null() || out.is_null() || sigs_len == 0 || !sigs_len.is_multiple_of(96) || out_len < 96 {
        return BU_BLS_ERR;
    }
    let n = sigs_len / 96;
    let raw = slice::from_raw_parts(sigs, sigs_len);
    let mut list = std::vec::Vec::with_capacity(n);
    for i in 0..n {
        match SignatureG2::from_bytes(&raw[i * 96..(i + 1) * 96]) {
            Ok(s) => list.push(s),
            Err(_) => return BU_BLS_ERR,
        }
    }
    let Ok(agg) = aggregate_signatures_g2(&list) else {
        return BU_BLS_ERR;
    };
    let mut buf = [0u8; 96];
    if agg.to_bytes_compressed(&mut buf).is_err() {
        return BU_BLS_ERR;
    }
    slice::from_raw_parts_mut(out, 96).copy_from_slice(&buf);
    BU_BLS_OK
}

/// Fast aggregate verify min-pk: concatenated 48-byte pks, one msg, 96-byte sig.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_bls_fast_aggregate_verify_min_pk(
    apk: *const u8,
    apk_len: usize,
    msg: *const u8,
    msg_len: usize,
    sig: *const u8,
    sig_len: usize,
    dst: *const u8,
    dst_len: usize,
) -> i32 {
    // apk: single aggregated 48-byte G1 public key (not a list)
    if apk.is_null() || msg.is_null() || sig.is_null() || apk_len != 48 || sig_len != 96 {
        return BU_BLS_ERR;
    }
    let Ok(apk) = PublicKeyG1::from_bytes(slice::from_raw_parts(apk, 48)) else {
        return BU_BLS_ERR;
    };
    let Ok(signature) = SignatureG2::from_bytes(slice::from_raw_parts(sig, 96)) else {
        return BU_BLS_ERR;
    };
    let message = slice::from_raw_parts(msg, msg_len);
    let d = if dst.is_null() || dst_len == 0 {
        None
    } else {
        Some(slice::from_raw_parts(dst, dst_len))
    };
    match fast_aggregate_verify_min_pk(&apk, message, &signature, d) {
        Ok(()) => BU_BLS_OK,
        Err(_) => BU_BLS_ERR,
    }
}

#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_bls_fast_aggregate_verify_min_sig(
    apk: *const u8,
    apk_len: usize,
    msg: *const u8,
    msg_len: usize,
    sig: *const u8,
    sig_len: usize,
    dst: *const u8,
    dst_len: usize,
) -> i32 {
    // apk: single aggregated 96-byte G2 public key
    if apk.is_null() || msg.is_null() || sig.is_null() || apk_len != 96 || sig_len != 48 {
        return BU_BLS_ERR;
    }
    let Ok(apk) = PublicKeyG2::from_bytes(slice::from_raw_parts(apk, 96)) else {
        return BU_BLS_ERR;
    };
    let Ok(signature) = SignatureG1::from_bytes(slice::from_raw_parts(sig, 48)) else {
        return BU_BLS_ERR;
    };
    let message = slice::from_raw_parts(msg, msg_len);
    let d = if dst.is_null() || dst_len == 0 {
        None
    } else {
        Some(slice::from_raw_parts(dst, dst_len))
    };
    match fast_aggregate_verify_min_sig(&apk, message, &signature, d) {
        Ok(()) => BU_BLS_OK,
        Err(_) => BU_BLS_ERR,
    }
}

/// Aggregate-verify min-pk (distinct messages).
///
/// * `pks` — concatenated 48-byte G1 public keys (`n * 48`)
/// * `msgs` — `n` messages as `[u32_be len][bytes]…`
/// * `sig` — 96-byte aggregated G2 signature
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_bls_aggregate_verify_min_pk(
    pks: *const u8,
    pks_len: usize,
    msgs: *const u8,
    msgs_len: usize,
    n_msgs: usize,
    sig: *const u8,
    sig_len: usize,
    dst: *const u8,
    dst_len: usize,
) -> i32 {
    if pks.is_null() || sig.is_null() || pks_len == 0 || !pks_len.is_multiple_of(48) || sig_len != 96 {
        return BU_BLS_ERR;
    }
    let n = pks_len / 48;
    if n != n_msgs || n == 0 {
        return BU_BLS_ERR;
    }
    let raw = slice::from_raw_parts(pks, pks_len);
    let mut list = std::vec::Vec::with_capacity(n);
    for i in 0..n {
        match PublicKeyG1::from_bytes(&raw[i * 48..(i + 1) * 48]) {
            Ok(pk) => list.push(pk),
            Err(_) => return BU_BLS_ERR,
        }
    }
    let Some(messages) = decode_msgs(msgs, msgs_len, n) else {
        return BU_BLS_ERR;
    };
    let msg_refs: std::vec::Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();
    let Ok(signature) = SignatureG2::from_bytes(slice::from_raw_parts(sig, 96)) else {
        return BU_BLS_ERR;
    };
    let d = if dst.is_null() || dst_len == 0 {
        None
    } else {
        Some(slice::from_raw_parts(dst, dst_len))
    };
    match aggregate_verify_min_pk(&list, &msg_refs, &signature, d) {
        Ok(()) => BU_BLS_OK,
        Err(_) => BU_BLS_ERR,
    }
}

/// Aggregate-verify min-sig (distinct messages).
/// pks: concat 96-byte G2; sig: 48-byte G1.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_bls_aggregate_verify_min_sig(
    pks: *const u8,
    pks_len: usize,
    msgs: *const u8,
    msgs_len: usize,
    n_msgs: usize,
    sig: *const u8,
    sig_len: usize,
    dst: *const u8,
    dst_len: usize,
) -> i32 {
    if pks.is_null() || sig.is_null() || pks_len == 0 || !pks_len.is_multiple_of(96) || sig_len != 48 {
        return BU_BLS_ERR;
    }
    let n = pks_len / 96;
    if n != n_msgs || n == 0 {
        return BU_BLS_ERR;
    }
    let raw = slice::from_raw_parts(pks, pks_len);
    let mut list = std::vec::Vec::with_capacity(n);
    for i in 0..n {
        match PublicKeyG2::from_bytes(&raw[i * 96..(i + 1) * 96]) {
            Ok(pk) => list.push(pk),
            Err(_) => return BU_BLS_ERR,
        }
    }
    let Some(messages) = decode_msgs(msgs, msgs_len, n) else {
        return BU_BLS_ERR;
    };
    let msg_refs: std::vec::Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();
    let Ok(signature) = SignatureG1::from_bytes(slice::from_raw_parts(sig, 48)) else {
        return BU_BLS_ERR;
    };
    let d = if dst.is_null() || dst_len == 0 {
        None
    } else {
        Some(slice::from_raw_parts(dst, dst_len))
    };
    match aggregate_verify_min_sig(&list, &msg_refs, &signature, d) {
        Ok(()) => BU_BLS_OK,
        Err(_) => BU_BLS_ERR,
    }
}

/// Batch verify min-pk: independent (pk, msg, sig) triples.
/// pks: n*48, sigs: n*96, msgs: length-prefixed blob.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_bls_batch_verify_min_pk(
    pks: *const u8,
    pks_len: usize,
    msgs: *const u8,
    msgs_len: usize,
    n_msgs: usize,
    sigs: *const u8,
    sigs_len: usize,
    dst: *const u8,
    dst_len: usize,
) -> i32 {
    if pks.is_null() || sigs.is_null() || pks_len == 0 || !pks_len.is_multiple_of(48) || !sigs_len.is_multiple_of(96) {
        return BU_BLS_ERR;
    }
    let n = pks_len / 48;
    if n != n_msgs || n == 0 || sigs_len / 96 != n {
        return BU_BLS_ERR;
    }
    let praw = slice::from_raw_parts(pks, pks_len);
    let sraw = slice::from_raw_parts(sigs, sigs_len);
    let mut pk_list = std::vec::Vec::with_capacity(n);
    let mut sig_list = std::vec::Vec::with_capacity(n);
    for i in 0..n {
        match PublicKeyG1::from_bytes(&praw[i * 48..(i + 1) * 48]) {
            Ok(pk) => pk_list.push(pk),
            Err(_) => return BU_BLS_ERR,
        }
        match SignatureG2::from_bytes(&sraw[i * 96..(i + 1) * 96]) {
            Ok(s) => sig_list.push(s),
            Err(_) => return BU_BLS_ERR,
        }
    }
    let Some(messages) = decode_msgs(msgs, msgs_len, n) else {
        return BU_BLS_ERR;
    };
    let msg_refs: std::vec::Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();
    let d = if dst.is_null() || dst_len == 0 {
        None
    } else {
        Some(slice::from_raw_parts(dst, dst_len))
    };
    match batch_verify_min_pk(&pk_list, &msg_refs, &sig_list, d) {
        Ok(()) => BU_BLS_OK,
        Err(_) => BU_BLS_ERR,
    }
}

#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_bls_batch_verify_min_sig(
    pks: *const u8,
    pks_len: usize,
    msgs: *const u8,
    msgs_len: usize,
    n_msgs: usize,
    sigs: *const u8,
    sigs_len: usize,
    dst: *const u8,
    dst_len: usize,
) -> i32 {
    if pks.is_null() || sigs.is_null() || pks_len == 0 || !pks_len.is_multiple_of(96) || !sigs_len.is_multiple_of(48) {
        return BU_BLS_ERR;
    }
    let n = pks_len / 96;
    if n != n_msgs || n == 0 || sigs_len / 48 != n {
        return BU_BLS_ERR;
    }
    let praw = slice::from_raw_parts(pks, pks_len);
    let sraw = slice::from_raw_parts(sigs, sigs_len);
    let mut pk_list = std::vec::Vec::with_capacity(n);
    let mut sig_list = std::vec::Vec::with_capacity(n);
    for i in 0..n {
        match PublicKeyG2::from_bytes(&praw[i * 96..(i + 1) * 96]) {
            Ok(pk) => pk_list.push(pk),
            Err(_) => return BU_BLS_ERR,
        }
        match SignatureG1::from_bytes(&sraw[i * 48..(i + 1) * 48]) {
            Ok(s) => sig_list.push(s),
            Err(_) => return BU_BLS_ERR,
        }
    }
    let Some(messages) = decode_msgs(msgs, msgs_len, n) else {
        return BU_BLS_ERR;
    };
    let msg_refs: std::vec::Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();
    let d = if dst.is_null() || dst_len == 0 {
        None
    } else {
        Some(slice::from_raw_parts(dst, dst_len))
    };
    match batch_verify_min_sig(&pk_list, &msg_refs, &sig_list, d) {
        Ok(()) => BU_BLS_OK,
        Err(_) => BU_BLS_ERR,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::bls12_381::{sign_min_pk, SecretKey, DST_MIN_PK_NUL};

    #[test]
    fn ffi_fast_agg_min_pk() {
        use crate::signature::bls12_381::{aggregate_signatures_g2, SignatureG2};
        let mut b1 = [0u8; 32];
        b1[31] = 1;
        let mut b2 = [0u8; 32];
        b2[31] = 2;
        let sk1 = SecretKey::from_bytes_le(&b1).unwrap();
        let sk2 = SecretKey::from_bytes_le(&b2).unwrap();
        let msg = b"ffi-agg";
        let s1 = sign_min_pk(&sk1, msg, Some(DST_MIN_PK_NUL)).unwrap();
        let s2 = sign_min_pk(&sk2, msg, Some(DST_MIN_PK_NUL)).unwrap();
        let mut sig1 = [0u8; 96];
        let mut sig2 = [0u8; 96];
        s1.to_bytes_compressed(&mut sig1).unwrap();
        s2.to_bytes_compressed(&mut sig2).unwrap();
        // roundtrip each sig through bytes
        let s1b = SignatureG2::from_bytes(&sig1).expect("sig1 from_bytes");
        let s2b = SignatureG2::from_bytes(&sig2).expect("sig2 from_bytes");
        let _ = aggregate_signatures_g2(&[s1b, s2b]).expect("rust aggregate");
        let mut sigs = [0u8; 192];
        sigs[..96].copy_from_slice(&sig1);
        sigs[96..].copy_from_slice(&sig2);
        let mut agg_sig = [0u8; 96];
        unsafe {
            assert_eq!(
                bu_bls_aggregate_sigs_g2(sigs.as_ptr(), 192, agg_sig.as_mut_ptr(), 96),
                BU_BLS_OK
            );
        }
        let mut pk1 = [0u8; 48];
        let mut pk2 = [0u8; 48];
        sk1.public_key_g1().to_bytes_compressed(&mut pk1).unwrap();
        sk2.public_key_g1().to_bytes_compressed(&mut pk2).unwrap();
        {
            use crate::signature::bls12_381 as bls;
            let p1 = bls::PublicKeyG1::from_bytes(&pk1).expect("pk1");
            let p2 = bls::PublicKeyG1::from_bytes(&pk2).expect("pk2");
            let agg_s = bls::SignatureG2::from_bytes(&agg_sig).expect("agg sig bytes");
            let apk = bls::aggregate_public_keys_g1(&[p1, p2]).expect("apk");
            bls::fast_aggregate_verify_min_pk(&apk, msg, &agg_s, Some(DST_MIN_PK_NUL))
                .expect("rust fast agg after bytes");
            let mut apk_b = [0u8; 48];
            apk.to_bytes_compressed(&mut apk_b).unwrap();
            assert_eq!(
                unsafe {
                    bu_bls_fast_aggregate_verify_min_pk(
                        apk_b.as_ptr(),
                        48,
                        msg.as_ptr(),
                        msg.len(),
                        agg_sig.as_ptr(),
                        96,
                        DST_MIN_PK_NUL.as_ptr(),
                        DST_MIN_PK_NUL.len(),
                    )
                },
                BU_BLS_OK
            );
        }
    }
}
