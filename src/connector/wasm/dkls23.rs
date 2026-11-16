//! DKLs23 WASM exports for the web connector.
//!
//! Same framed-blob protocol as the FFI layer (`connector::ffi::dkls23`):
//! DKG/refresh exchange `frame([keyshare, …])` blobs, signatures are
//! compact 64-byte `r || s`, hashes/seeds are 32 bytes.

#![cfg(all(feature = "wasm", feature = "alloc"))]

use wasm_bindgen::prelude::*;

use crate::dkls23::codec::{keyshare_bytes, parse_keyshare};
use crate::dkls23::curve_id::CurveId;

fn curve_of(v: u32) -> Result<CurveId, JsValue> {
    CurveId::from_u32(v).ok_or_else(|| JsValue::from_str("unknown curve (0=k1, 1=r1)"))
}

fn parse_blob(raw: &[u8]) -> Result<Vec<crate::dkls23::codec::KeyShare>, JsValue> {
    let frames =
        crate::dkls23::codec::unframe(raw).ok_or_else(|| JsValue::from_str("bad frame"))?;
    if frames.is_empty() {
        return Err(JsValue::from_str("empty shares"));
    }
    let mut out = Vec::with_capacity(frames.len());
    for f in &frames {
        out.push(parse_keyshare(f).map_err(|_| JsValue::from_str("bad share"))?);
    }
    Ok(out)
}

fn seeds_of(raw: &[u8], n: usize) -> Result<Vec<[u8; 32]>, JsValue> {
    if raw.len() != n * 32 || n == 0 {
        return Err(JsValue::from_str("seeds must be 32*n bytes"));
    }
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let mut s = [0u8; 32];
        s.copy_from_slice(&raw[i * 32..(i + 1) * 32]);
        out.push(s);
    }
    Ok(out)
}

/// Full DKG → framed shares blob.
#[wasm_bindgen(js_name = dkls23Dkg)]
pub fn dkls23_dkg(
    curve: u32,
    sid: &[u8],
    n: u32,
    t: u32,
    seeds: &[u8],
) -> Result<Vec<u8>, JsValue> {
    if sid.is_empty() {
        return Err(JsValue::from_str("sid must not be empty"));
    }
    let id = curve_of(curve)?;
    let seed_list = seeds_of(seeds, n as usize)?;
    let shares = crate::dkls23::session::dkg_oneshot(id, sid, n as usize, t as usize, &seed_list)
        .map_err(|_| JsValue::from_str("dkg failed"))?;
    let frames: Vec<Vec<u8>> = shares.iter().map(keyshare_bytes).collect();
    Ok(crate::dkls23::codec::frame(&frames))
}

/// Threshold sign → compact 64-byte signature.
#[wasm_bindgen(js_name = dkls23Sign)]
pub fn dkls23_sign(
    curve: u32,
    sid: &[u8],
    msg_hash: &[u8],
    shares_blob: &[u8],
    seeds: &[u8],
) -> Result<Vec<u8>, JsValue> {
    if msg_hash.len() != 32 {
        return Err(JsValue::from_str("msg_hash must be 32 bytes"));
    }
    if sid.is_empty() {
        return Err(JsValue::from_str("sid must not be empty"));
    }
    let id = curve_of(curve)?;
    let list = parse_blob(shares_blob)?;
    if list[0].curve != id {
        return Err(JsValue::from_str("curve/share mismatch"));
    }
    let seed_list = seeds_of(seeds, list.len())?;
    let mut h = [0u8; 32];
    h.copy_from_slice(msg_hash);
    let sig = crate::dkls23::session::sign_oneshot(&list, sid, &h, &seed_list)
        .map_err(|_| JsValue::from_str("sign failed"))?;
    Ok(sig.to_bytes().to_vec())
}

/// Refresh shares → framed shares blob (group key unchanged).
#[wasm_bindgen(js_name = dkls23Refresh)]
pub fn dkls23_refresh(sid: &[u8], shares_blob: &[u8], seeds: &[u8]) -> Result<Vec<u8>, JsValue> {
    if sid.is_empty() {
        return Err(JsValue::from_str("sid must not be empty"));
    }
    let list = parse_blob(shares_blob)?;
    let seed_list = seeds_of(seeds, list.len())?;
    let out = crate::dkls23::session::refresh_oneshot(&list, sid, &seed_list)
        .map_err(|_| JsValue::from_str("refresh failed"))?;
    let frames: Vec<Vec<u8>> = out.iter().map(keyshare_bytes).collect();
    Ok(crate::dkls23::codec::frame(&frames))
}

/// Aggregate member public keys (`n*33` bytes) → 33-byte group key.
#[wasm_bindgen(js_name = dkls23AggPublicKeys)]
pub fn dkls23_agg_public_keys(curve: u32, members: &[u8], n: u32) -> Result<Vec<u8>, JsValue> {
    if members.len() != n as usize * 33 || n == 0 {
        return Err(JsValue::from_str("members must be 33*n bytes"));
    }
    let id = curve_of(curve)?;
    let mut list = Vec::with_capacity(n as usize);
    for i in 0..n as usize {
        let mut m = [0u8; 33];
        m.copy_from_slice(&members[i * 33..(i + 1) * 33]);
        list.push(m);
    }
    let agg = crate::dkls23::keys::DklsAggregatePublicKey::agg_public_keys(id, &list)
        .map_err(|_| JsValue::from_str("agg failed"))?;
    Ok(agg.group_key().to_vec())
}

/// X-only form of a group key → 32 bytes.
#[wasm_bindgen(js_name = dkls23XOnly)]
pub fn dkls23_x_only(curve: u32, group_pk: &[u8]) -> Result<Vec<u8>, JsValue> {
    if group_pk.len() != 33 {
        return Err(JsValue::from_str("group key must be 33 bytes"));
    }
    let id = curve_of(curve)?;
    let mut pk = [0u8; 33];
    pk.copy_from_slice(group_pk);
    let x = crate::dkls23::keys::group_x_only(id, &pk)
        .map_err(|_| JsValue::from_str("bad group key"))?;
    Ok(x.to_vec())
}

/// Import existing secrets as an additive n-of-n quorum (no DKG):
/// `n*32` secret bytes → framed shares blob.
#[wasm_bindgen(js_name = dkls23ImportSecrets)]
pub fn dkls23_import_secrets(curve: u32, secrets: &[u8], n: u32) -> Result<Vec<u8>, JsValue> {
    if secrets.len() != n as usize * 32 || n == 0 {
        return Err(JsValue::from_str("secrets must be 32*n bytes"));
    }
    let id = curve_of(curve)?;
    let mut list = Vec::with_capacity(n as usize);
    for i in 0..n as usize {
        let mut s = [0u8; 32];
        s.copy_from_slice(&secrets[i * 32..(i + 1) * 32]);
        list.push(s);
    }
    let shares = crate::dkls23::session::import_secrets(id, &list)
        .map_err(|_| JsValue::from_str("import failed"))?;
    let frames: Vec<Vec<u8>> = shares.iter().map(keyshare_bytes).collect();
    Ok(crate::dkls23::codec::frame(&frames))
}

/// Verify a compact signature; false on bad lengths or invalid sig.
#[wasm_bindgen(js_name = dkls23Verify)]
pub fn dkls23_verify_js(curve: u32, group_pk: &[u8], msg_hash: &[u8], sig: &[u8]) -> bool {
    let Ok(id) = curve_of(curve) else {
        return false;
    };
    if group_pk.len() != 33 || msg_hash.len() != 32 || sig.len() != 64 {
        return false;
    }
    let mut h = [0u8; 32];
    h.copy_from_slice(msg_hash);
    let raw = sig.to_vec();
    let Ok(cs) = crate::dkls23::codec::CompactSig::from_bytes(&raw) else {
        return false;
    };
    match id {
        CurveId::K1 => {
            let (Ok(p), Ok(s)) = (
                crate::signature::ecdsa::PublicKey::from_bytes(group_pk),
                crate::signature::ecdsa::Signature::from_compact(&cs.to_bytes()),
            ) else {
                return false;
            };
            crate::signature::ecdsa::verify(&p, &h, &s).is_ok()
        }
        CurveId::R1 => {
            let (Ok(p), Ok(s)) = (
                crate::signature::ecdsa_p256::PublicKey::from_bytes(group_pk),
                crate::signature::ecdsa_p256::Signature::from_compact(&cs.to_bytes()),
            ) else {
                return false;
            };
            crate::signature::ecdsa_p256::verify(&p, &h, &s).is_ok()
        }
    }
}
