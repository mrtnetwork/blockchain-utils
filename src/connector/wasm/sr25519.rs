//! sr25519 / Schnorrkel WASM exports.
#![cfg(all(feature = "wasm", feature = "alloc"))]

use crate::curve::traits::CurvePoint;
use crate::merlin::Transcript;
use crate::schnorrkel::{
    vrf_hash, vrf_script, MiniSecretKey, PublicKey, SecretKey, Signature, VrfInOut, VrfProof,
};
use wasm_bindgen::prelude::*;

fn u8_vec(a: &[u8]) -> Vec<u8> {
    let mut v = vec![0u8; a.len() as usize];
    v.copy_from_slice(a);
    v
}
fn to_u8(v: &[u8]) -> Vec<u8> {
    v.to_vec()
}
fn read32(a: &[u8]) -> Result<[u8; 32], JsValue> {
    if a.len() != 32 {
        return Err(JsValue::from_str("len32"));
    }
    let mut b = [0u8; 32];
    b.copy_from_slice(a);
    Ok(b)
}
fn read64(a: &[u8]) -> Result<[u8; 64], JsValue> {
    if a.len() != 64 {
        return Err(JsValue::from_str("len64"));
    }
    let mut b = [0u8; 64];
    b.copy_from_slice(a);
    Ok(b)
}
fn sk_from(seed_or_sk: &[u8], from_seed: bool, uniform: bool) -> Result<SecretKey, JsValue> {
    if from_seed {
        let s = read32(seed_or_sk)?;
        let m = MiniSecretKey::from_bytes(&s);
        Ok(if uniform {
            m.expand_uniform()
        } else {
            m.expand_ed25519()
        })
    } else {
        SecretKey::from_bytes(&read64(seed_or_sk)?).ok_or_else(|| JsValue::from_str("bad sk"))
    }
}
fn ctx_msg(ctx: &[u8], msg: &[u8]) -> Transcript {
    let c = u8_vec(ctx);
    let context = if c.is_empty() {
        b"substrate".as_slice()
    } else {
        &c
    };
    let mut t = Transcript::new(b"SigningContext");
    t.append_message(b"", context);
    t.append_message(b"sign-bytes", &u8_vec(msg));
    t
}

/// Public key (32 bytes) from 32-byte mini-secret; `uniform` selects expand_uniform; `Err("len32")`.
#[wasm_bindgen(js_name = sr25519PublicKey)]
pub fn sr25519_public_key(seed: &[u8], uniform: bool) -> Result<Vec<u8>, JsValue> {
    Ok(to_u8(
        &sk_from(seed, true, uniform)?.public_key().to_bytes(),
    ))
}

/// Expand 32-byte mini-secret to 64-byte secret; `uniform` selects expand_uniform; `Err("len32")`.
#[wasm_bindgen(js_name = sr25519SecretFromSeed)]
pub fn sr25519_secret_from_seed(seed: &[u8], uniform: bool) -> Result<Vec<u8>, JsValue> {
    let sk = sk_from(seed, true, uniform)?;
    Ok(to_u8(&sk.to_bytes()))
}

/// Public key (32 bytes) from 64-byte expanded secret; `Err("len64"|"bad sk")`.
#[wasm_bindgen(js_name = sr25519PublicKeyFromSecret)]
pub fn sr25519_public_key_from_secret(sk: &[u8]) -> Result<Vec<u8>, JsValue> {
    Ok(to_u8(&sk_from(sk, false, false)?.public_key().to_bytes()))
}

/// True if 32-byte `pk` is a valid non-identity Ristretto point.
#[wasm_bindgen(js_name = sr25519IsValidPublicKey)]
pub fn sr25519_is_valid_public_key(pk: &[u8]) -> bool {
    read32(pk).map(|b| PublicKey::is_valid(&b)).unwrap_or(false)
}

/// True if 64-byte `sk` parses as an expanded secret.
#[wasm_bindgen(js_name = sr25519IsValidSecretKey)]
pub fn sr25519_is_valid_secret_key(sk: &[u8]) -> bool {
    read64(sk)
        .map(|b| SecretKey::from_bytes(&b).is_some())
        .unwrap_or(false)
}

/// Sign with seed(32) or secret(64) over `ctx`/`msg` + 64-byte nonce → 64-byte sig; `Err("len32"|"len64"|"bad sk")`.
#[wasm_bindgen(js_name = sr25519Sign)]
pub fn sr25519_sign(
    seed_or_sk: &[u8],
    from_seed: bool,
    uniform: bool,
    ctx: &[u8],
    msg: &[u8],
    nonce64: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let sk = sk_from(seed_or_sk, from_seed, uniform)?;
    let mut t = ctx_msg(ctx, msg);
    let sig = sk.sign(&mut t, &read64(nonce64)?);
    Ok(to_u8(&sig.to_bytes()))
}

/// Verify 32-byte pk + 64-byte sig over `ctx`/`msg`; returns bool.
#[wasm_bindgen(js_name = sr25519Verify)]
pub fn sr25519_verify(pk: &[u8], ctx: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let public = match PublicKey::from_bytes(&match read32(pk) {
        Ok(b) => b,
        Err(_) => return false,
    }) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let mut t = ctx_msg(ctx, msg);
    let signature = match Signature::from_bytes(&match read64(sig) {
        Ok(b) => b,
        Err(_) => return false,
    }) {
        Some(s) => s,
        None => return false,
    };
    public.verify(&mut t, &signature)
}

/// Expanded secret → Ed25519-style bytes (64); `Err("len64"|"bad sk")`.
#[wasm_bindgen(js_name = sr25519ToEd25519Bytes)]
pub fn sr25519_to_ed25519_bytes(sk: &[u8]) -> Result<Vec<u8>, JsValue> {
    Ok(to_u8(&sk_from(sk, false, false)?.to_ed25519_bytes()))
}

/// Hard derive to new secret64 + chaincode32 (96 bytes out); `Err("len32"|"len64"|"bad sk")`.
#[wasm_bindgen(js_name = sr25519HardDerive)]
pub fn sr25519_hard_derive(
    seed_or_sk: &[u8],
    from_seed: bool,
    uniform: bool,
    chain: &[u8],
    msg: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let sk = sk_from(seed_or_sk, from_seed, uniform)?;
    let (new_sk, cc) = sk.hard_derive(&read32(chain)?, &u8_vec(msg), !uniform);
    let mut out = [0u8; 96];
    out[..64].copy_from_slice(&new_sk.to_bytes());
    out[64..].copy_from_slice(&cc);
    Ok(to_u8(&out))
}

/// Soft derive with 32-byte `chain` + 32-byte `new_nonce` → 96 bytes; `Err("soft"|"len32"|"bad sk")`.
#[wasm_bindgen(js_name = sr25519SoftDerive)]
pub fn sr25519_soft_derive(
    seed_or_sk: &[u8],
    from_seed: bool,
    uniform: bool,
    chain: &[u8],
    msg: &[u8],
    new_nonce: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let sk = sk_from(seed_or_sk, from_seed, uniform)?;
    let (new_sk, cc) = sk
        .soft_derive(&read32(chain)?, &u8_vec(msg), &read32(new_nonce)?)
        .ok_or_else(|| JsValue::from_str("soft"))?;
    let mut out = [0u8; 96];
    out[..64].copy_from_slice(&new_sk.to_bytes());
    out[64..].copy_from_slice(&cc);
    Ok(to_u8(&out))
}

/// Soft derive 32-byte pk with `chain` → new pk32 + chain32 (64 bytes); `Err("pk"|"derive")`.
#[wasm_bindgen(js_name = sr25519DerivePublic)]
pub fn sr25519_derive_public(pk: &[u8], chain: &[u8], msg: &[u8]) -> Result<Vec<u8>, JsValue> {
    let public = PublicKey::from_bytes(&read32(pk)?).map_err(|_| JsValue::from_str("pk"))?;
    let (new_pk, cc) = public
        .derive(&read32(chain)?, &u8_vec(msg))
        .ok_or_else(|| JsValue::from_str("derive"))?;
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&new_pk.to_bytes());
    out[32..].copy_from_slice(&cc);
    Ok(to_u8(&out))
}

/// VRF input hash (32 bytes) for pk over `ctx`/`msg`; `Err("len32"|"enc")`.
#[wasm_bindgen(js_name = sr25519VrfHash)]
pub fn sr25519_vrf_hash(pk: &[u8], ctx: &[u8], msg: &[u8]) -> Result<Vec<u8>, JsValue> {
    let mut t = ctx_msg(ctx, msg);
    let h = vrf_hash(&mut t, &read32(pk)?);
    let mut enc = [0u8; 32];
    h.encode(&mut enc).map_err(|_| JsValue::from_str("enc"))?;
    Ok(to_u8(&enc))
}

/// VRF input‖output (64 bytes) for seed/sk over `ctx`/`msg`; `Err("len32"|"len64"|"bad sk")`.
#[wasm_bindgen(js_name = sr25519VrfInOut)]
pub fn sr25519_vrf_in_out(
    seed_or_sk: &[u8],
    from_seed: bool,
    uniform: bool,
    ctx: &[u8],
    msg: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let sk = sk_from(seed_or_sk, from_seed, uniform)?;
    let mut t = ctx_msg(ctx, msg);
    let io = sk.vrf_in_out(&mut t);
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&io.input);
    out[32..].copy_from_slice(&io.output);
    Ok(to_u8(&out))
}

/// DLEQ prove for 64-byte inout + 64-byte nonce → 64-byte proof; `Err("prove"|"len64"|"bad sk")`.
#[wasm_bindgen(js_name = sr25519DleqProve)]
pub fn sr25519_dleq_prove(
    seed_or_sk: &[u8],
    from_seed: bool,
    uniform: bool,
    inout64: &[u8],
    nonce64: &[u8],
    kusama: bool,
    extra: Option<Vec<u8>>,
) -> Result<Vec<u8>, JsValue> {
    let sk = sk_from(seed_or_sk, from_seed, uniform)?;
    let raw = read64(inout64)?;
    let mut input = [0u8; 32];
    let mut output = [0u8; 32];
    input.copy_from_slice(&raw[..32]);
    output.copy_from_slice(&raw[32..]);
    let extra_sl = extra.as_ref().map(|e| {
        let mut v = vec![0u8; e.len() as usize];
        v.copy_from_slice(e);
        v
    });
    let mut t = vrf_script(extra_sl.as_deref());
    let proof = sk
        .dleq_prove(
            &mut t,
            &VrfInOut { input, output },
            &read64(nonce64)?,
            kusama,
        )
        .ok_or_else(|| JsValue::from_str("prove"))?;
    Ok(to_u8(&proof.to_bytes()))
}

/// DLEQ verify pk + inout64 + proof64 (`kusama` ordering, optional `extra`); returns bool.
#[wasm_bindgen(js_name = sr25519DleqVerify)]
pub fn sr25519_dleq_verify(
    pk: &[u8],
    inout64: &[u8],
    proof64: &[u8],
    kusama: bool,
    extra: Option<Vec<u8>>,
) -> bool {
    let public = match PublicKey::from_bytes(&match read32(pk) {
        Ok(b) => b,
        Err(_) => return false,
    }) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let raw = match read64(inout64) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let mut input = [0u8; 32];
    let mut output = [0u8; 32];
    input.copy_from_slice(&raw[..32]);
    output.copy_from_slice(&raw[32..]);
    let proof = VrfProof::from_bytes(&match read64(proof64) {
        Ok(b) => b,
        Err(_) => return false,
    });
    let extra_sl = extra.as_ref().map(|e| {
        let mut v = vec![0u8; e.len() as usize];
        v.copy_from_slice(e);
        v
    });
    let mut t = vrf_script(extra_sl.as_deref());
    public.dleq_verify(&mut t, &VrfInOut { input, output }, &proof, kusama)
}

/// VRF sign over `ctx`/`msg` + nonce64 → preout32‖proof64 (96 bytes); `Err("vrf"|"len64"|"bad sk")`.
#[wasm_bindgen(js_name = sr25519VrfSign)]
pub fn sr25519_vrf_sign(
    seed_or_sk: &[u8],
    from_seed: bool,
    uniform: bool,
    ctx: &[u8],
    msg: &[u8],
    nonce64: &[u8],
    kusama: bool,
    extra: Option<Vec<u8>>,
) -> Result<Vec<u8>, JsValue> {
    let sk = sk_from(seed_or_sk, from_seed, uniform)?;
    // VRF SigningContext: empty context when ctx length is 0
    let mut t = if ctx.len() == 0 {
        let mut tr = Transcript::new(b"SigningContext");
        tr.append_message(b"", &[]);
        let mut m = vec![0u8; msg.len() as usize];
        m.copy_from_slice(msg);
        tr.append_message(b"sign-bytes", &m);
        tr
    } else {
        ctx_msg(ctx, msg)
    };
    let extra_sl = extra.as_ref().map(|e| {
        let mut v = vec![0u8; e.len() as usize];
        v.copy_from_slice(e);
        v
    });
    let mut prove_t = vrf_script(extra_sl.as_deref());
    let (inout, proof) = sk
        .vrf_sign(&mut t, &mut prove_t, &read64(nonce64)?, kusama)
        .ok_or_else(|| JsValue::from_str("vrf"))?;
    let mut out = [0u8; 96];
    out[..32].copy_from_slice(&inout.output);
    out[32..].copy_from_slice(&proof.to_bytes());
    Ok(to_u8(&out))
}

/// VRF verify pk + preout32 + proof64 over `ctx`/`msg` (`kusama`, optional `extra`); returns bool.
#[wasm_bindgen(js_name = sr25519VrfVerify)]
pub fn sr25519_vrf_verify(
    pk: &[u8],
    ctx: &[u8],
    msg: &[u8],
    preout32: &[u8],
    proof64: &[u8],
    kusama: bool,
    extra: Option<Vec<u8>>,
) -> bool {
    let pk_b = match read32(pk) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let public = match PublicKey::from_bytes(&pk_b) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let make_t = || {
        if ctx.len() == 0 {
            let mut tr = Transcript::new(b"SigningContext");
            tr.append_message(b"", &[]);
            let mut m = vec![0u8; msg.len() as usize];
            m.copy_from_slice(msg);
            tr.append_message(b"sign-bytes", &m);
            tr
        } else {
            ctx_msg(ctx, msg)
        }
    };
    let mut t = make_t();
    let h = vrf_hash(&mut t, &pk_b);
    let mut input = [0u8; 32];
    if h.encode(&mut input).is_err() {
        return false;
    }
    let inout = VrfInOut {
        input,
        output: match read32(preout32) {
            Ok(b) => b,
            Err(_) => return false,
        },
    };
    let proof = VrfProof::from_bytes(&match read64(proof64) {
        Ok(b) => b,
        Err(_) => return false,
    });
    let extra_sl = extra.as_ref().map(|e| {
        let mut v = vec![0u8; e.len() as usize];
        v.copy_from_slice(e);
        v
    });
    let mut prove_t = vrf_script(extra_sl.as_deref());
    public.vrf_verify(&mut make_t(), &mut prove_t, &inout, &proof, kusama)
}
