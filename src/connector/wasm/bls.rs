//! BLS12-381 WASM bindings (min-pk / min-sig + aggregate).

use wasm_bindgen::prelude::*;

use crate::signature::bls12_381::{
    aggregate_public_keys_g1, aggregate_public_keys_g2, aggregate_signatures_g1,
    aggregate_signatures_g2, aggregate_verify_min_pk, aggregate_verify_min_sig,
    batch_verify_min_pk, batch_verify_min_sig, fast_aggregate_verify_min_pk,
    fast_aggregate_verify_min_sig, sign_min_pk, sign_min_sig, verify_min_pk, verify_min_sig,
    PublicKeyG1, PublicKeyG2, SecretKey, SignatureG1, SignatureG2,
};

fn copy(u: &[u8]) -> Vec<u8> {
    let mut v = vec![0u8; u.len() as usize];
    v.copy_from_slice(u);
    v
}

fn to_js(v: &[u8]) -> Vec<u8> {
    (v).to_vec()
}

/// Derive 48-byte compressed G1 pubkey from 32-byte sk.
/// Err "invalid sk"/"encode" on failure.
#[wasm_bindgen(js_name = blsSkToPkG1)]
pub fn bls_sk_to_pk_g1_js(sk: &[u8]) -> Result<Vec<u8>, JsValue> {
    let s = copy(sk);
    let secret = SecretKey::from_bytes(&s).map_err(|_| JsValue::from_str("invalid sk"))?;
    let mut buf = [0u8; 48];
    secret
        .public_key_g1()
        .to_bytes_compressed(&mut buf)
        .map_err(|_| JsValue::from_str("encode"))?;
    Ok(to_js(&buf))
}

/// Derive 96-byte compressed G2 pubkey from 32-byte sk.
/// Err "invalid sk"/"encode" on failure.
#[wasm_bindgen(js_name = blsSkToPkG2)]
pub fn bls_sk_to_pk_g2_js(sk: &[u8]) -> Result<Vec<u8>, JsValue> {
    let s = copy(sk);
    let secret = SecretKey::from_bytes(&s).map_err(|_| JsValue::from_str("invalid sk"))?;
    let mut buf = [0u8; 96];
    secret
        .public_key_g2()
        .to_bytes_compressed(&mut buf)
        .map_err(|_| JsValue::from_str("encode"))?;
    Ok(to_js(&buf))
}

/// Sign message (min-pk, 96-byte G2 sig); empty `dst` = default.
/// Err "invalid sk"/"sign"/"encode" on failure.
#[wasm_bindgen(js_name = blsSignMinPk)]
pub fn bls_sign_min_pk_js(sk: &[u8], msg: &[u8], dst: &[u8]) -> Result<Vec<u8>, JsValue> {
    let secret = SecretKey::from_bytes(&copy(sk)).map_err(|_| JsValue::from_str("invalid sk"))?;
    let message = copy(msg);
    let d = copy(dst);
    let dst_opt = if d.is_empty() {
        None
    } else {
        Some(d.as_slice())
    };
    let sig = sign_min_pk(&secret, &message, dst_opt).map_err(|_| JsValue::from_str("sign"))?;
    let mut buf = [0u8; 96];
    sig.to_bytes_compressed(&mut buf)
        .map_err(|_| JsValue::from_str("encode"))?;
    Ok(to_js(&buf))
}

/// Sign message (min-sig, 48-byte G1 sig); empty `dst` = default.
/// Err "invalid sk"/"sign"/"encode" on failure.
#[wasm_bindgen(js_name = blsSignMinSig)]
pub fn bls_sign_min_sig_js(sk: &[u8], msg: &[u8], dst: &[u8]) -> Result<Vec<u8>, JsValue> {
    let secret = SecretKey::from_bytes(&copy(sk)).map_err(|_| JsValue::from_str("invalid sk"))?;
    let message = copy(msg);
    let d = copy(dst);
    let dst_opt = if d.is_empty() {
        None
    } else {
        Some(d.as_slice())
    };
    let sig = sign_min_sig(&secret, &message, dst_opt).map_err(|_| JsValue::from_str("sign"))?;
    let mut buf = [0u8; 48];
    sig.to_bytes_compressed(&mut buf)
        .map_err(|_| JsValue::from_str("encode"))?;
    Ok(to_js(&buf))
}

/// Verify min-pk (pk 48 bytes, sig 96 bytes); false on bad input/failure.
#[wasm_bindgen(js_name = blsVerifyMinPk)]
pub fn bls_verify_min_pk_js(pk: &[u8], msg: &[u8], sig: &[u8], dst: &[u8]) -> bool {
    let Ok(public) = PublicKeyG1::from_bytes(&copy(pk)) else {
        return false;
    };
    let Ok(signature) = SignatureG2::from_bytes(&copy(sig)) else {
        return false;
    };
    let message = copy(msg);
    let d = copy(dst);
    let dst_opt = if d.is_empty() {
        None
    } else {
        Some(d.as_slice())
    };
    verify_min_pk(&public, &message, &signature, dst_opt).is_ok()
}

/// Verify min-sig (pk 96 bytes, sig 48 bytes); false on bad input/failure.
#[wasm_bindgen(js_name = blsVerifyMinSig)]
pub fn bls_verify_min_sig_js(pk: &[u8], msg: &[u8], sig: &[u8], dst: &[u8]) -> bool {
    let Ok(public) = PublicKeyG2::from_bytes(&copy(pk)) else {
        return false;
    };
    let Ok(signature) = SignatureG1::from_bytes(&copy(sig)) else {
        return false;
    };
    let message = copy(msg);
    let d = copy(dst);
    let dst_opt = if d.is_empty() {
        None
    } else {
        Some(d.as_slice())
    };
    verify_min_sig(&public, &message, &signature, dst_opt).is_ok()
}

/// Aggregate concatenated 48-byte G1 pks into one 48-byte pk.
/// Err "bad pks len"/"bad pk"/"agg"/"encode" on failure.
#[wasm_bindgen(js_name = blsAggregatePksG1)]
pub fn bls_aggregate_pks_g1_js(pks: &[u8]) -> Result<Vec<u8>, JsValue> {
    let raw = copy(pks);
    if raw.is_empty() || raw.len() % 48 != 0 {
        return Err(JsValue::from_str("bad pks len"));
    }
    let n = raw.len() / 48;
    let mut list = Vec::with_capacity(n);
    for i in 0..n {
        list.push(
            PublicKeyG1::from_bytes(&raw[i * 48..(i + 1) * 48])
                .map_err(|_| JsValue::from_str("bad pk"))?,
        );
    }
    let agg = aggregate_public_keys_g1(&list).map_err(|_| JsValue::from_str("agg"))?;
    let mut buf = [0u8; 48];
    agg.to_bytes_compressed(&mut buf)
        .map_err(|_| JsValue::from_str("encode"))?;
    Ok(to_js(&buf))
}

/// Aggregate concatenated 96-byte G2 pks into one 96-byte pk.
/// Err "bad pks len"/"bad pk"/"agg"/"encode" on failure.
#[wasm_bindgen(js_name = blsAggregatePksG2)]
pub fn bls_aggregate_pks_g2_js(pks: &[u8]) -> Result<Vec<u8>, JsValue> {
    let raw = copy(pks);
    if raw.is_empty() || raw.len() % 96 != 0 {
        return Err(JsValue::from_str("bad pks len"));
    }
    let n = raw.len() / 96;
    let mut list = Vec::with_capacity(n);
    for i in 0..n {
        list.push(
            PublicKeyG2::from_bytes(&raw[i * 96..(i + 1) * 96])
                .map_err(|_| JsValue::from_str("bad pk"))?,
        );
    }
    let agg = aggregate_public_keys_g2(&list).map_err(|_| JsValue::from_str("agg"))?;
    let mut buf = [0u8; 96];
    agg.to_bytes_compressed(&mut buf)
        .map_err(|_| JsValue::from_str("encode"))?;
    Ok(to_js(&buf))
}

/// Aggregate concatenated 48-byte G1 sigs into one 48-byte sig.
/// Err "bad sigs len"/"bad sig"/"agg"/"encode" on failure.
#[wasm_bindgen(js_name = blsAggregateSigsG1)]
pub fn bls_aggregate_sigs_g1_js(sigs: &[u8]) -> Result<Vec<u8>, JsValue> {
    let raw = copy(sigs);
    if raw.is_empty() || raw.len() % 48 != 0 {
        return Err(JsValue::from_str("bad sigs len"));
    }
    let n = raw.len() / 48;
    let mut list = Vec::with_capacity(n);
    for i in 0..n {
        list.push(
            SignatureG1::from_bytes(&raw[i * 48..(i + 1) * 48])
                .map_err(|_| JsValue::from_str("bad sig"))?,
        );
    }
    let agg = aggregate_signatures_g1(&list).map_err(|_| JsValue::from_str("agg"))?;
    let mut buf = [0u8; 48];
    agg.to_bytes_compressed(&mut buf)
        .map_err(|_| JsValue::from_str("encode"))?;
    Ok(to_js(&buf))
}

/// Aggregate concatenated 96-byte G2 sigs into one 96-byte sig.
/// Err "bad sigs len"/"bad sig"/"agg"/"encode" on failure.
#[wasm_bindgen(js_name = blsAggregateSigsG2)]
pub fn bls_aggregate_sigs_g2_js(sigs: &[u8]) -> Result<Vec<u8>, JsValue> {
    let raw = copy(sigs);
    if raw.is_empty() || raw.len() % 96 != 0 {
        return Err(JsValue::from_str("bad sigs len"));
    }
    let n = raw.len() / 96;
    let mut list = Vec::with_capacity(n);
    for i in 0..n {
        list.push(
            SignatureG2::from_bytes(&raw[i * 96..(i + 1) * 96])
                .map_err(|_| JsValue::from_str("bad sig"))?,
        );
    }
    let agg = aggregate_signatures_g2(&list).map_err(|_| JsValue::from_str("agg"))?;
    let mut buf = [0u8; 96];
    agg.to_bytes_compressed(&mut buf)
        .map_err(|_| JsValue::from_str("encode"))?;
    Ok(to_js(&buf))
}

/// Fast-verify one message against aggregated G1 pk (48 bytes or concatenated list).
/// False on bad input/failure.
#[wasm_bindgen(js_name = blsFastAggregateVerifyMinPk)]
pub fn bls_fast_aggregate_verify_min_pk_js(apk: &[u8], msg: &[u8], sig: &[u8], dst: &[u8]) -> bool {
    // Single aggregated 48-byte G1 public key (or list → aggregate first)
    let raw = copy(apk);
    let apk = if raw.len() == 48 {
        match PublicKeyG1::from_bytes(&raw) {
            Ok(p) => p,
            Err(_) => return false,
        }
    } else if !raw.is_empty() && raw.len() % 48 == 0 {
        let n = raw.len() / 48;
        let mut list = Vec::with_capacity(n);
        for i in 0..n {
            let Ok(pk) = PublicKeyG1::from_bytes(&raw[i * 48..(i + 1) * 48]) else {
                return false;
            };
            list.push(pk);
        }
        match aggregate_public_keys_g1(&list) {
            Ok(p) => p,
            Err(_) => return false,
        }
    } else {
        return false;
    };
    let Ok(signature) = SignatureG2::from_bytes(&copy(sig)) else {
        return false;
    };
    let message = copy(msg);
    let d = copy(dst);
    let dst_opt = if d.is_empty() {
        None
    } else {
        Some(d.as_slice())
    };
    fast_aggregate_verify_min_pk(&apk, &message, &signature, dst_opt).is_ok()
}

/// Fast-verify one message against single aggregated 96-byte G2 pk.
/// False on bad input/failure.
#[wasm_bindgen(js_name = blsFastAggregateVerifyMinSig)]
pub fn bls_fast_aggregate_verify_min_sig_js(
    apk: &[u8],
    msg: &[u8],
    sig: &[u8],
    dst: &[u8],
) -> bool {
    // Single aggregated 96-byte G2 public key
    let raw = copy(apk);
    if raw.len() != 96 {
        return false;
    }
    let Ok(apk) = PublicKeyG2::from_bytes(&raw) else {
        return false;
    };
    let Ok(signature) = SignatureG1::from_bytes(&copy(sig)) else {
        return false;
    };
    let message = copy(msg);
    let d = copy(dst);
    let dst_opt = if d.is_empty() {
        None
    } else {
        Some(d.as_slice())
    };
    fast_aggregate_verify_min_sig(&apk, &message, &signature, dst_opt).is_ok()
}

fn decode_msgs_js(blob: &[u8], n: usize) -> Option<Vec<Vec<u8>>> {
    let mut out = Vec::with_capacity(n);
    let mut off = 0usize;
    for _ in 0..n {
        if off + 4 > blob.len() {
            return None;
        }
        let len =
            u32::from_be_bytes([blob[off], blob[off + 1], blob[off + 2], blob[off + 3]]) as usize;
        off += 4;
        if off + len > blob.len() {
            return None;
        }
        out.push(blob[off..off + len].to_vec());
        off += len;
    }
    if off != blob.len() {
        return None;
    }
    Some(out)
}

/// Aggregate-verify distinct messages (pks n*48, sig 96-byte G2).
/// `msgs` is `[u32_be len][bytes]…`; false on count mismatch/failure.
#[wasm_bindgen(js_name = blsAggregateVerifyMinPk)]
pub fn bls_aggregate_verify_min_pk_js(
    pks: &[u8],
    msgs: &[u8],
    n_msgs: u32,
    sig: &[u8],
    dst: &[u8],
) -> bool {
    let raw = copy(pks);
    if raw.is_empty() || raw.len() % 48 != 0 {
        return false;
    }
    let n = raw.len() / 48;
    if n != n_msgs as usize {
        return false;
    }
    let mut list = Vec::with_capacity(n);
    for i in 0..n {
        let Ok(pk) = PublicKeyG1::from_bytes(&raw[i * 48..(i + 1) * 48]) else {
            return false;
        };
        list.push(pk);
    }
    let Some(messages) = decode_msgs_js(&copy(msgs), n) else {
        return false;
    };
    let msg_refs: Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();
    let Ok(signature) = SignatureG2::from_bytes(&copy(sig)) else {
        return false;
    };
    let d = copy(dst);
    let dst_opt = if d.is_empty() {
        None
    } else {
        Some(d.as_slice())
    };
    aggregate_verify_min_pk(&list, &msg_refs, &signature, dst_opt).is_ok()
}

/// Aggregate-verify distinct messages (pks n*96, sig 48-byte G1).
/// `msgs` is `[u32_be len][bytes]…`; false on count mismatch/failure.
#[wasm_bindgen(js_name = blsAggregateVerifyMinSig)]
pub fn bls_aggregate_verify_min_sig_js(
    pks: &[u8],
    msgs: &[u8],
    n_msgs: u32,
    sig: &[u8],
    dst: &[u8],
) -> bool {
    let raw = copy(pks);
    if raw.is_empty() || raw.len() % 96 != 0 {
        return false;
    }
    let n = raw.len() / 96;
    if n != n_msgs as usize {
        return false;
    }
    let mut list = Vec::with_capacity(n);
    for i in 0..n {
        let Ok(pk) = PublicKeyG2::from_bytes(&raw[i * 96..(i + 1) * 96]) else {
            return false;
        };
        list.push(pk);
    }
    let Some(messages) = decode_msgs_js(&copy(msgs), n) else {
        return false;
    };
    let msg_refs: Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();
    let Ok(signature) = SignatureG1::from_bytes(&copy(sig)) else {
        return false;
    };
    let d = copy(dst);
    let dst_opt = if d.is_empty() {
        None
    } else {
        Some(d.as_slice())
    };
    aggregate_verify_min_sig(&list, &msg_refs, &signature, dst_opt).is_ok()
}

/// Batch-verify independent triples (pks n*48, sigs n*96, length-prefixed `msgs`).
/// False on count mismatch/failure.
#[wasm_bindgen(js_name = blsBatchVerifyMinPk)]
pub fn bls_batch_verify_min_pk_js(
    pks: &[u8],
    msgs: &[u8],
    n_msgs: u32,
    sigs: &[u8],
    dst: &[u8],
) -> bool {
    let raw = copy(pks);
    let sraw = copy(sigs);
    if raw.is_empty() || raw.len() % 48 != 0 || sraw.len() % 96 != 0 {
        return false;
    }
    let n = raw.len() / 48;
    if n != n_msgs as usize || sraw.len() / 96 != n {
        return false;
    }
    let mut pks_l = Vec::with_capacity(n);
    let mut sigs_l = Vec::with_capacity(n);
    for i in 0..n {
        let Ok(pk) = PublicKeyG1::from_bytes(&raw[i * 48..(i + 1) * 48]) else {
            return false;
        };
        let Ok(sig) = SignatureG2::from_bytes(&sraw[i * 96..(i + 1) * 96]) else {
            return false;
        };
        pks_l.push(pk);
        sigs_l.push(sig);
    }
    let Some(messages) = decode_msgs_js(&copy(msgs), n) else {
        return false;
    };
    let msg_refs: Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();
    let d = copy(dst);
    let dst_opt = if d.is_empty() {
        None
    } else {
        Some(d.as_slice())
    };
    batch_verify_min_pk(&pks_l, &msg_refs, &sigs_l, dst_opt).is_ok()
}

/// Batch-verify independent triples (pks n*96, sigs n*48, length-prefixed `msgs`).
/// False on count mismatch/failure.
#[wasm_bindgen(js_name = blsBatchVerifyMinSig)]
pub fn bls_batch_verify_min_sig_js(
    pks: &[u8],
    msgs: &[u8],
    n_msgs: u32,
    sigs: &[u8],
    dst: &[u8],
) -> bool {
    let raw = copy(pks);
    let sraw = copy(sigs);
    if raw.is_empty() || raw.len() % 96 != 0 || sraw.len() % 48 != 0 {
        return false;
    }
    let n = raw.len() / 96;
    if n != n_msgs as usize || sraw.len() / 48 != n {
        return false;
    }
    let mut pks_l = Vec::with_capacity(n);
    let mut sigs_l = Vec::with_capacity(n);
    for i in 0..n {
        let Ok(pk) = PublicKeyG2::from_bytes(&raw[i * 96..(i + 1) * 96]) else {
            return false;
        };
        let Ok(sig) = SignatureG1::from_bytes(&sraw[i * 48..(i + 1) * 48]) else {
            return false;
        };
        pks_l.push(pk);
        sigs_l.push(sig);
    }
    let Some(messages) = decode_msgs_js(&copy(msgs), n) else {
        return false;
    };
    let msg_refs: Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();
    let d = copy(dst);
    let dst_opt = if d.is_empty() {
        None
    } else {
        Some(d.as_slice())
    };
    batch_verify_min_sig(&pks_l, &msg_refs, &sigs_l, dst_opt).is_ok()
}
