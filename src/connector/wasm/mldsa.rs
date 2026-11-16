//! ML-DSA wasm-bindgen exports.
//!
//! `rnd` semantics (FIPS 204):
//! - `Some(32 bytes)` → used **directly** as the FIPS `rnd` (NOT as a ChaCha seed).
//! - `None` → rejected: signing randomness is caller-supplied, never generated.
#![cfg(all(feature = "wasm", feature = "alloc"))]

use crate::signature::ml_dsa::MlDsa;
use wasm_bindgen::prelude::*;

fn dsa(set: u32) -> Result<MlDsa, JsValue> {
    match set {
        44 => Ok(MlDsa::mldsa44()),
        65 => Ok(MlDsa::mldsa65()),
        87 => Ok(MlDsa::mldsa87()),
        _ => Err(JsValue::from_str("invalid ML-DSA set")),
    }
}

/// ML-DSA keygen (`set` 44/65/87, `seed` 32 bytes); returns pk ++ sk
/// (flat; lengths known per set on the caller side).
/// Err "invalid ML-DSA set"/"seed len"/"keygen" on failure.
#[wasm_bindgen(js_name = mldsaKeygen)]
pub fn bu_mldsa_keygen(set: u32, seed: &[u8]) -> Result<Vec<u8>, JsValue> {
    let d = dsa(set)?;
    if seed.len() != 32 {
        return Err(JsValue::from_str("seed len"));
    }
    let mut s = [0u8; 32];
    s.copy_from_slice(seed);
    let (pk, sk) = d.keygen(&s).map_err(|_| JsValue::from_str("keygen"))?;
    let mut out = Vec::with_capacity(pk.len() + sk.len());
    out.extend_from_slice(&pk);
    out.extend_from_slice(&sk);
    Ok(out)
}

/// Sign with required 32-byte FIPS `rnd` and optional context.
///
/// - `rnd = Some(32)` → those bytes are used **as-is** in ρ″ = H(K‖rnd‖μ).
/// - `rnd = None` → rejected: callers without randomness must obtain it
///   from the platform RNG first (never silently generated).
#[wasm_bindgen(js_name = mldsaSign)]
pub fn bu_mldsa_sign(
    set: u32,
    sk: &[u8],
    msg: &[u8],
    rnd: Option<Vec<u8>>,
    ctx: Option<Vec<u8>>,
) -> Result<Vec<u8>, JsValue> {
    let d = dsa(set)?;
    let mut r = [0u8; 32];
    match rnd {
        Some(bytes) if bytes.len() == 32 => {
            r.copy_from_slice(&bytes);
        }
        _ => return Err(JsValue::from_str("rnd must be 32 bytes")),
    }
    let ctx = ctx.unwrap_or_default();
    if ctx.len() > 255 {
        return Err(JsValue::from_str("context too long"));
    }
    d.sign(sk, msg, &r, &ctx)
        .map_err(|_| JsValue::from_str("sign"))
}

/// ML-DSA verify (`set`, pk, msg, sig, optional ctx ≤255 bytes).
/// False on bad set/ctx/failure.
#[wasm_bindgen(js_name = mldsaVerify)]
pub fn bu_mldsa_verify(set: u32, pk: &[u8], msg: &[u8], sig: &[u8], ctx: Option<Vec<u8>>) -> bool {
    let Ok(d) = dsa(set) else {
        return false;
    };
    let ctx = ctx.unwrap_or_default();
    if ctx.len() > 255 {
        return false;
    }
    d.verify(pk, msg, sig, &ctx)
}

/// Derive ML-DSA pubkey from secret key.
/// Err "invalid ML-DSA set"/"pk_from_sk" on failure.
#[wasm_bindgen(js_name = mldsaPkFromSk)]
pub fn bu_mldsa_pk_from_sk(set: u32, sk: &[u8]) -> Result<Vec<u8>, JsValue> {
    let d = dsa(set)?;
    d.public_key_from_secret_key(sk)
        .map_err(|_| JsValue::from_str("pk_from_sk"))
}
