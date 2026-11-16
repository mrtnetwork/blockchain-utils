//! MuSig2 WASM exports for web.

#![cfg(all(feature = "wasm", feature = "alloc"))]

use wasm_bindgen::prelude::*;

use crate::curve::traits::CurvePoint;
use crate::musig2::{
    deterministic_sign, key_agg, key_agg_and_tweak, nonce_agg, nonce_generate, partial_sig_agg,
    partial_sig_verify, partial_sign, verify_aggregate, Session, Tweak,
};

fn u8_vec(a: &[u8]) -> Vec<u8> {
    let mut v = vec![0u8; a.len() as usize];
    v.copy_from_slice(a);
    v
}

fn to_u8(v: &[u8]) -> Vec<u8> {
    v.to_vec()
}

/// Parse concatenated 33-byte tweak records ([is_x_only:u8][tweak:32]).
fn parse_tweaks(tweaks: Option<Vec<u8>>, n_tweaks: u32) -> Result<Vec<Tweak>, JsValue> {
    let mut tw = Vec::new();
    let nt = n_tweaks as usize;
    if nt > 0 {
        let traw = u8_vec(&tweaks.ok_or_else(|| JsValue::from_str("tweaks missing"))?);
        if traw.len() != nt * 33 {
            return Err(JsValue::from_str("invalid tweaks length"));
        }
        for i in 0..nt {
            let chunk = &traw[i * 33..(i + 1) * 33];
            let mut t = [0u8; 32];
            t.copy_from_slice(&chunk[1..33]);
            tw.push(Tweak {
                tweak: t,
                is_x_only: chunk[0] != 0,
            });
        }
    }
    Ok(tw)
}

/// Aggregate n compressed 33-byte keys (concatenated) → 33-byte Q.
#[wasm_bindgen(js_name = musig2KeyAgg)]
pub fn musig2_key_agg(keys: &[u8], n_keys: u32) -> Result<Vec<u8>, JsValue> {
    let raw = u8_vec(keys);
    let n = n_keys as usize;
    if n < 2 || raw.len() != n * 33 {
        return Err(JsValue::from_str("invalid keys length"));
    }
    let mut refs: Vec<&[u8]> = Vec::with_capacity(n);
    for i in 0..n {
        refs.push(&raw[i * 33..(i + 1) * 33]);
    }
    let ctx = key_agg(&refs).map_err(|_| JsValue::from_str("key_agg failed"))?;
    let mut out = [0u8; 33];
    ctx.q
        .to_bytes_compressed(&mut out)
        .map_err(|_| JsValue::from_str("encode failed"))?;
    Ok(to_u8(&out))
}

/// Returns secnonce(97) ++ pubnonce(66) = 163 bytes (flat; no JS objects).
/// `rand` is required (32 bytes, caller-provided CSPRNG output).
#[wasm_bindgen(js_name = musig2NonceGen)]
pub fn musig2_nonce_gen(
    sk: &[u8],
    pk: Option<Vec<u8>>,
    msg: Option<Vec<u8>>,
    rand: &[u8],
) -> Result<Vec<u8>, JsValue> {
    if sk.len() != 32 {
        return Err(JsValue::from_str("sk must be 32 bytes"));
    }
    if rand.len() != 32 {
        return Err(JsValue::from_str("rand must be 32 bytes"));
    }
    let mut ska = [0u8; 32];
    ska.copy_from_slice(sk);
    let mut rand_a = [0u8; 32];
    rand_a.copy_from_slice(rand);
    let pair = nonce_generate(
        Some(&ska),
        pk.as_deref(),
        None,
        None,
        msg.as_deref(),
        &rand_a,
    )
    .map_err(|_| JsValue::from_str("nonce_gen failed"))?;
    let mut out = Vec::with_capacity(163);
    out.extend_from_slice(&pair.secnonce);
    out.extend_from_slice(&pair.pubnonce);
    Ok(out)
}

/// Aggregate n concatenated 66-byte pubnonces → 66-byte aggnonce.
/// Err `invalid pubnonces` on bad count/length, `nonce_agg failed` on aggregation error.
#[wasm_bindgen(js_name = musig2NonceAgg)]
pub fn musig2_nonce_agg(pubnonces: &[u8], n: u32) -> Result<Vec<u8>, JsValue> {
    let raw = u8_vec(pubnonces);
    let n = n as usize;
    if n < 2 || raw.len() != n * 66 {
        return Err(JsValue::from_str("invalid pubnonces"));
    }
    let mut refs: Vec<&[u8]> = Vec::with_capacity(n);
    for i in 0..n {
        refs.push(&raw[i * 66..(i + 1) * 66]);
    }
    let agg = nonce_agg(&refs).map_err(|_| JsValue::from_str("nonce_agg failed"))?;
    Ok(to_u8(&agg))
}

/// Create a 32-byte partial signature (secnonce 97B, sk 32B, aggnonce 66B).
/// Err `invalid lengths`/`keys length` on bad sizes, `partial_sign` on sign failure.
#[wasm_bindgen(js_name = musig2PartialSign)]
pub fn musig2_partial_sign(
    secnonce: &[u8],
    sk: &[u8],
    keys: &[u8],
    n_keys: u32,
    aggnonce: &[u8],
    msg: &[u8],
    tweaks: Option<Vec<u8>>,
    n_tweaks: u32,
) -> Result<Vec<u8>, JsValue> {
    if secnonce.len() != 97 || sk.len() != 32 || aggnonce.len() != 66 {
        return Err(JsValue::from_str("invalid lengths"));
    }
    let sec = u8_vec(secnonce);
    let mut ska = [0u8; 32];
    ska.copy_from_slice(sk);
    let raw_keys = u8_vec(keys);
    let n = n_keys as usize;
    if raw_keys.len() != n * 33 {
        return Err(JsValue::from_str("keys length"));
    }
    let mut pks = Vec::with_capacity(n);
    for i in 0..n {
        pks.push(raw_keys[i * 33..(i + 1) * 33].to_vec());
    }
    let session = Session {
        public_keys: pks,
        tweaks: parse_tweaks(tweaks, n_tweaks)?,
        aggnonce: u8_vec(aggnonce),
        msg: u8_vec(msg),
    };
    let s = partial_sign(&sec, &ska, &session).map_err(|_| JsValue::from_str("partial_sign"))?;
    Ok(to_u8(&s))
}

/// Aggregate partials → BIP-340 64-byte signature.
/// Err `invalid lengths` on bad sizes, `agg failed` on aggregation error.
#[wasm_bindgen(js_name = musig2PartialSigAgg)]
pub fn musig2_partial_sig_agg(
    partials: &[u8],
    n: u32,
    keys: &[u8],
    n_keys: u32,
    aggnonce: &[u8],
    msg: &[u8],
    tweaks: Option<Vec<u8>>,
    n_tweaks: u32,
) -> Result<Vec<u8>, JsValue> {
    let raw = u8_vec(partials);
    let n = n as usize;
    if raw.len() != n * 32 || aggnonce.len() != 66 {
        return Err(JsValue::from_str("invalid lengths"));
    }
    let mut parts = Vec::with_capacity(n);
    for i in 0..n {
        let mut s = [0u8; 32];
        s.copy_from_slice(&raw[i * 32..(i + 1) * 32]);
        parts.push(s);
    }
    let raw_keys = u8_vec(keys);
    let nk = n_keys as usize;
    let mut pks = Vec::with_capacity(nk);
    for i in 0..nk {
        pks.push(raw_keys[i * 33..(i + 1) * 33].to_vec());
    }
    let session = Session {
        public_keys: pks,
        tweaks: parse_tweaks(tweaks, n_tweaks)?,
        aggnonce: u8_vec(aggnonce),
        msg: u8_vec(msg),
    };
    let sig = partial_sig_agg(&parts, &session).map_err(|_| JsValue::from_str("agg failed"))?;
    Ok(to_u8(&sig))
}

/// Verify a BIP-340 aggregate signature (sig 64B, agg_xonly 32B); false on bad lengths or invalid signature.
#[wasm_bindgen(js_name = musig2VerifyAggregate)]
pub fn musig2_verify_aggregate_js(msg: &[u8], sig: &[u8], agg_xonly: &[u8]) -> bool {
    if sig.len() != 64 || agg_xonly.len() != 32 {
        return false;
    }
    let m = u8_vec(msg);
    let s = u8_vec(sig);
    let x = u8_vec(agg_xonly);
    verify_aggregate(&m, &s, &x).unwrap_or(false)
}

/// Deterministic MuSig2: returns pubnonce(66) || partial(32) = 98 bytes.
#[wasm_bindgen(js_name = musig2DeterministicSign)]
pub fn musig2_deterministic_sign_js(
    sk: &[u8],
    aggother: &[u8],
    keys: &[u8],
    n_keys: u32,
    msg: &[u8],
    tweaks: &[u8],
    n_tweaks: u32,
    rand: Option<Vec<u8>>,
) -> Result<Vec<u8>, JsValue> {
    if sk.len() != 32 || n_keys < 2 {
        return Err(JsValue::from_str("len"));
    }
    let mut ska = [0u8; 32];
    ska.copy_from_slice(sk);
    let other = u8_vec(aggother);
    let raw = u8_vec(keys);
    let nk = n_keys as usize;
    let mut pks = Vec::with_capacity(nk);
    for i in 0..nk {
        pks.push(raw[i * 33..(i + 1) * 33].to_vec());
    }
    let mut tw = Vec::new();
    if n_tweaks > 0 {
        let traw = u8_vec(tweaks);
        for i in 0..(n_tweaks as usize) {
            let chunk = &traw[i * 33..(i + 1) * 33];
            let mut t32 = [0u8; 32];
            t32.copy_from_slice(&chunk[1..33]);
            tw.push(Tweak {
                tweak: t32,
                is_x_only: chunk[0] != 0,
            });
        }
    }
    let msg_v = u8_vec(msg);
    let rand_a = match rand {
        Some(r) if r.len() == 32 => {
            let mut b = [0u8; 32];
            b.copy_from_slice(&r);
            Some(b)
        }
        Some(_) => return Err(JsValue::from_str("rand must be 32 bytes")),
        _ => None,
    };
    let d = deterministic_sign(&ska, &other, &pks, &tw, &msg_v, rand_a.as_ref())
        .map_err(|_| JsValue::from_str("det sign"))?;
    let mut out = [0u8; 98];
    out[..66].copy_from_slice(&d.pubnonce[..66]);
    out[66..].copy_from_slice(&d.partial);
    Ok(to_u8(&out))
}

/// Aggregate n keys with optional tweaks (mirrors `bu_musig2_key_agg_tweak`).
/// `tweaks` is concatenated 33-byte records: [is_x_only:u8][tweak:32].
#[wasm_bindgen(js_name = musig2KeyAggTweak)]
pub fn musig2_key_agg_tweak(
    keys: &[u8],
    n_keys: u32,
    tweaks: &[u8],
    n_tweaks: u32,
) -> Result<Vec<u8>, JsValue> {
    let raw = u8_vec(keys);
    let n = n_keys as usize;
    if n < 2 || raw.len() != n * 33 {
        return Err(JsValue::from_str("invalid keys length"));
    }
    let mut refs: Vec<&[u8]> = Vec::with_capacity(n);
    for i in 0..n {
        refs.push(&raw[i * 33..(i + 1) * 33]);
    }
    let mut tw = Vec::new();
    let nt = n_tweaks as usize;
    if nt > 0 {
        let traw = u8_vec(tweaks);
        if traw.len() != nt * 33 {
            return Err(JsValue::from_str("invalid tweaks length"));
        }
        for i in 0..nt {
            let chunk = &traw[i * 33..(i + 1) * 33];
            let mut t = [0u8; 32];
            t.copy_from_slice(&chunk[1..33]);
            tw.push(Tweak {
                tweak: t,
                is_x_only: chunk[0] != 0,
            });
        }
    }
    let ctx = key_agg_and_tweak(&refs, &tw).map_err(|_| JsValue::from_str("key_agg failed"))?;
    let mut out = [0u8; 33];
    ctx.q
        .to_bytes_compressed(&mut out)
        .map_err(|_| JsValue::from_str("encode failed"))?;
    Ok(to_u8(&out))
}

/// Verify a partial signature (mirrors `bu_musig2_partial_sig_verify`).
#[wasm_bindgen(js_name = musig2PartialSigVerify)]
pub fn musig2_partial_sig_verify(
    partial: &[u8],
    pubnonce: &[u8],
    pk: &[u8],
    keys: &[u8],
    n_keys: u32,
    aggnonce: &[u8],
    msg: &[u8],
    tweaks: Option<Vec<u8>>,
    n_tweaks: u32,
) -> bool {
    if partial.len() != 32 || pubnonce.len() != 66 {
        return false;
    }
    let mut ps = [0u8; 32];
    ps.copy_from_slice(partial);
    let mut pn = [0u8; 66];
    pn.copy_from_slice(pubnonce);
    let pk_v = u8_vec(pk);
    let raw_keys = u8_vec(keys);
    let nk = n_keys as usize;
    if raw_keys.len() != nk * 33 {
        return false;
    }
    let mut pks = Vec::with_capacity(nk);
    for i in 0..nk {
        pks.push(raw_keys[i * 33..(i + 1) * 33].to_vec());
    }
    let tw = match parse_tweaks(tweaks, n_tweaks) {
        Ok(t) => t,
        Err(_) => return false,
    };
    let session = Session {
        public_keys: pks,
        tweaks: tw,
        aggnonce: u8_vec(aggnonce),
        msg: u8_vec(msg),
    };
    partial_sig_verify(&ps, &pn, &pk_v, &session).unwrap_or(false)
}
