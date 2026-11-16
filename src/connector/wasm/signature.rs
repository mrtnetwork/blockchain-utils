//! Signature WASM exports (ECDSA k1/r1, BIP-340, Ed25519).

#![cfg(all(feature = "wasm", feature = "alloc"))]

use wasm_bindgen::prelude::*;

use crate::signature::ecdsa::{self, PublicKey as K1Pk, SecretKey as K1Sk, Signature as K1Sig};
use crate::signature::ecdsa_p256::{
    self, PublicKey as R1Pk, SecretKey as R1Sk, Signature as R1Sig,
};
use crate::signature::ed25519::{self, PublicKey as EdPk, SecretKey as EdSk, Signature as EdSig};
use crate::signature::schnorr::{
    self, PublicKey as SchnorrPk, SecretKey as SchnorrSk, Signature as SchnorrSig,
};

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
        return Err(JsValue::from_str("need 32 bytes"));
    }
    let mut b = [0u8; 32];
    b.copy_from_slice(a);
    Ok(b)
}
fn read64(a: &[u8]) -> Result<[u8; 64], JsValue> {
    if a.len() != 64 {
        return Err(JsValue::from_str("need 64 bytes"));
    }
    let mut b = [0u8; 64];
    b.copy_from_slice(a);
    Ok(b)
}

// ---- Ed25519 ----
/// Ed25519 public key (32 bytes) from 32-byte secret; `Err("sk"|"pk"|"need 32 bytes")`.
#[wasm_bindgen(js_name = ed25519PublicKey)]
pub fn ed25519_public_key(sk: &[u8]) -> Result<Vec<u8>, JsValue> {
    let s = EdSk::from_bytes(&read32(sk)?).map_err(|_| JsValue::from_str("sk"))?;
    let pk = s.public_key().map_err(|_| JsValue::from_str("pk"))?;
    Ok(to_u8(&pk.0))
}

/// Ed25519 sign `msg` with 32-byte secret → 64-byte sig; `Err("sk"|"sign"|"need 32 bytes")`.
#[wasm_bindgen(js_name = ed25519Sign)]
pub fn ed25519_sign(sk: &[u8], msg: &[u8]) -> Result<Vec<u8>, JsValue> {
    let s = EdSk::from_bytes(&read32(sk)?).map_err(|_| JsValue::from_str("sk"))?;
    let sig = ed25519::sign(&s, &u8_vec(msg)).map_err(|_| JsValue::from_str("sign"))?;
    Ok(to_u8(&sig.0))
}

/// Ed25519 verify 32-byte pk and 64-byte sig over `msg`; returns bool.
#[wasm_bindgen(js_name = ed25519Verify)]
pub fn ed25519_verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, JsValue> {
    let p = EdPk::from_bytes(&read32(pk)?).map_err(|_| JsValue::from_str("pk"))?;
    let s = EdSig::from_bytes(&read64(sig)?).map_err(|_| JsValue::from_str("sig"))?;
    Ok(ed25519::verify(&p, &u8_vec(msg), &s).is_ok())
}

/// Ed25519-variant public key (32 bytes) from secret material; `variant`:
/// 0 = Ed25519 (32-byte seed), 1 = Blake2b (32-byte seed), 2 = Kholaw
/// (64-byte `a || prefix`), 3 = Monero (64-byte `a || prefix`).
#[wasm_bindgen(js_name = ed25519PublicKeyVariant)]
pub fn ed25519_public_key_variant(variant: u8, sk: &[u8]) -> Result<Vec<u8>, JsValue> {
    let v = ed25519::Variant::from_u8(variant).ok_or_else(|| JsValue::from_str("variant"))?;
    let pk = ed25519::public_key_variant(&u8_vec(sk), v).map_err(|_| JsValue::from_str("pk"))?;
    Ok(to_u8(&pk.0))
}

/// Ed25519-variant sign `msg` → 64-byte sig; same `variant` codes as above.
#[wasm_bindgen(js_name = ed25519SignVariant)]
pub fn ed25519_sign_variant(
    variant: u8,
    sk: &[u8],
    msg: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let v = ed25519::Variant::from_u8(variant).ok_or_else(|| JsValue::from_str("variant"))?;
    let sig =
        ed25519::sign_variant(&u8_vec(sk), &u8_vec(msg), v).map_err(|_| JsValue::from_str("sign"))?;
    Ok(to_u8(&sig.0))
}

/// Ed25519-variant verify 32-byte pk and 64-byte sig over `msg`; returns bool.
#[wasm_bindgen(js_name = ed25519VerifyVariant)]
pub fn ed25519_verify_variant(
    variant: u8,
    pk: &[u8],
    msg: &[u8],
    sig: &[u8],
) -> Result<bool, JsValue> {
    let v = ed25519::Variant::from_u8(variant).ok_or_else(|| JsValue::from_str("variant"))?;
    let p = EdPk::from_bytes(&read32(pk)?).map_err(|_| JsValue::from_str("pk"))?;
    let s = EdSig::from_bytes(&read64(sig)?).map_err(|_| JsValue::from_str("sig"))?;
    Ok(ed25519::verify_variant(&p, &u8_vec(msg), &s, v).is_ok())
}

// ---- ECDSA secp256k1 ----
/// secp256k1 compressed public key (33 bytes) from 32-byte secret; `Err("sk"|"pk"|"enc")`.
#[wasm_bindgen(js_name = ecdsaK1PublicKey)]
pub fn ecdsa_k1_public_key(sk: &[u8]) -> Result<Vec<u8>, JsValue> {
    let s = K1Sk::from_bytes(&read32(sk)?).map_err(|_| JsValue::from_str("sk"))?;
    let pk = s.public_key().map_err(|_| JsValue::from_str("pk"))?;
    let mut out = [0u8; 33];
    pk.to_bytes_compressed(&mut out)
        .map_err(|_| JsValue::from_str("enc"))?;
    Ok(to_u8(&out))
}

/// secp256k1 sign 32-byte `hash` → 64-byte compact `r‖s`; `Err("sk"|"sign"|"need 32 bytes")`.
#[wasm_bindgen(js_name = ecdsaK1Sign)]
pub fn ecdsa_k1_sign(sk: &[u8], hash: &[u8]) -> Result<Vec<u8>, JsValue> {
    let s = K1Sk::from_bytes(&read32(sk)?).map_err(|_| JsValue::from_str("sk"))?;
    let h = read32(hash)?;
    let sig = ecdsa::sign(&s, &h).map_err(|_| JsValue::from_str("sign"))?;
    let mut out = [0u8; 64];
    sig.to_compact(&mut out);
    Ok(to_u8(&out))
}

/// secp256k1 sign 32-byte `hash` with optional `extra` entropy → 64-byte sig; `Err("sk"|"sign")`.
#[wasm_bindgen(js_name = ecdsaK1SignEx)]
pub fn ecdsa_k1_sign_ex(
    sk: &[u8],
    hash: &[u8],
    extra: Option<Vec<u8>>,
) -> Result<Vec<u8>, JsValue> {
    let s = K1Sk::from_bytes(&read32(sk)?).map_err(|_| JsValue::from_str("sk"))?;
    let h = read32(hash)?;
    let ex = extra.as_ref().map(|a| u8_vec(a));
    let sig = ecdsa::sign_ex(&s, &h, ex.as_deref()).map_err(|_| JsValue::from_str("sign"))?;
    let mut out = [0u8; 64];
    sig.to_compact(&mut out);
    Ok(to_u8(&out))
}

/// secp256k1 verify compressed pk + 32-byte hash + 64-byte sig; returns bool.
#[wasm_bindgen(js_name = ecdsaK1Verify)]
pub fn ecdsa_k1_verify(pk: &[u8], hash: &[u8], sig: &[u8]) -> Result<bool, JsValue> {
    let p = K1Pk::from_bytes(&u8_vec(pk)).map_err(|_| JsValue::from_str("pk"))?;
    let h = read32(hash)?;
    let s = K1Sig::from_compact(&read64(sig)?).map_err(|_| JsValue::from_str("sig"))?;
    Ok(ecdsa::verify(&p, &h, &s).is_ok())
}

/// secp256k1 recover 33-byte compressed pk from hash + 64-byte sig + `rec_id`; `Err("sig"|"recover")`.
#[wasm_bindgen(js_name = ecdsaK1Recover)]
pub fn ecdsa_k1_recover(hash: &[u8], sig: &[u8], rec_id: u8) -> Result<Vec<u8>, JsValue> {
    let h = read32(hash)?;
    let s = K1Sig::from_compact(&read64(sig)?).map_err(|_| JsValue::from_str("sig"))?;
    let pk = ecdsa::recover(&h, &s, rec_id).map_err(|_| JsValue::from_str("recover"))?;
    let mut out = [0u8; 33];
    pk.to_bytes_compressed(&mut out)
        .map_err(|_| JsValue::from_str("enc"))?;
    Ok(to_u8(&out))
}

// ---- ECDSA secp256r1 ----
/// secp256r1 compressed public key (33 bytes) from 32-byte secret; `Err("sk"|"pk"|"enc")`.
#[wasm_bindgen(js_name = ecdsaR1PublicKey)]
pub fn ecdsa_r1_public_key(sk: &[u8]) -> Result<Vec<u8>, JsValue> {
    let s = R1Sk::from_bytes(&read32(sk)?).map_err(|_| JsValue::from_str("sk"))?;
    let pk = s.public_key().map_err(|_| JsValue::from_str("pk"))?;
    let mut out = [0u8; 33];
    pk.to_bytes_compressed(&mut out)
        .map_err(|_| JsValue::from_str("enc"))?;
    Ok(to_u8(&out))
}

/// secp256r1 sign 32-byte `hash` → 64-byte compact `r‖s`; `Err("sk"|"sign"|"need 32 bytes")`.
#[wasm_bindgen(js_name = ecdsaR1Sign)]
pub fn ecdsa_r1_sign(sk: &[u8], hash: &[u8]) -> Result<Vec<u8>, JsValue> {
    let s = R1Sk::from_bytes(&read32(sk)?).map_err(|_| JsValue::from_str("sk"))?;
    let h = read32(hash)?;
    let sig = ecdsa_p256::sign(&s, &h).map_err(|_| JsValue::from_str("sign"))?;
    let mut out = [0u8; 64];
    sig.to_compact(&mut out);
    Ok(to_u8(&out))
}

/// secp256r1 sign 32-byte `hash` with optional `extra` entropy → 64-byte sig; `Err("sk"|"sign")`.
#[wasm_bindgen(js_name = ecdsaR1SignEx)]
pub fn ecdsa_r1_sign_ex(
    sk: &[u8],
    hash: &[u8],
    extra: Option<Vec<u8>>,
) -> Result<Vec<u8>, JsValue> {
    let s = R1Sk::from_bytes(&read32(sk)?).map_err(|_| JsValue::from_str("sk"))?;
    let h = read32(hash)?;
    let ex = extra.as_ref().map(|a| u8_vec(a));
    let sig = ecdsa_p256::sign_ex(&s, &h, ex.as_deref()).map_err(|_| JsValue::from_str("sign"))?;
    let mut out = [0u8; 64];
    sig.to_compact(&mut out);
    Ok(to_u8(&out))
}

/// secp256r1 verify compressed pk + 32-byte hash + 64-byte sig; returns bool.
#[wasm_bindgen(js_name = ecdsaR1Verify)]
pub fn ecdsa_r1_verify(pk: &[u8], hash: &[u8], sig: &[u8]) -> Result<bool, JsValue> {
    let p = R1Pk::from_bytes(&u8_vec(pk)).map_err(|_| JsValue::from_str("pk"))?;
    let h = read32(hash)?;
    let s = R1Sig::from_compact(&read64(sig)?).map_err(|_| JsValue::from_str("sig"))?;
    Ok(ecdsa_p256::verify(&p, &h, &s).is_ok())
}

/// secp256r1 recover 33-byte compressed pk from hash + 64-byte sig + `rec_id`; `Err("sig"|"recover")`.
#[wasm_bindgen(js_name = ecdsaR1Recover)]
pub fn ecdsa_r1_recover(hash: &[u8], sig: &[u8], rec_id: u8) -> Result<Vec<u8>, JsValue> {
    let h = read32(hash)?;
    let s = R1Sig::from_compact(&read64(sig)?).map_err(|_| JsValue::from_str("sig"))?;
    let pk = ecdsa_p256::recover(&h, &s, rec_id).map_err(|_| JsValue::from_str("recover"))?;
    let mut out = [0u8; 33];
    pk.to_bytes_compressed(&mut out)
        .map_err(|_| JsValue::from_str("enc"))?;
    Ok(to_u8(&out))
}

// ---- BIP-340 Schnorr ----
/// BIP-340 x-only public key (32 bytes) from 32-byte secret; `Err("sk"|"pk"|"need 32 bytes")`.
#[wasm_bindgen(js_name = schnorrPublicKey)]
pub fn schnorr_public_key(sk: &[u8]) -> Result<Vec<u8>, JsValue> {
    let s = SchnorrSk::from_bytes(&read32(sk)?).map_err(|_| JsValue::from_str("sk"))?;
    let pk = s.public_key().map_err(|_| JsValue::from_str("pk"))?;
    Ok(to_u8(&pk.0))
}

/// BIP-340 sign `msg` with optional 32-byte `aux` → 64-byte sig; `Err("sk"|"sign"|"need 32 bytes")`.
#[wasm_bindgen(js_name = schnorrSign)]
pub fn schnorr_sign(sk: &[u8], msg: &[u8], aux: Option<Vec<u8>>) -> Result<Vec<u8>, JsValue> {
    let s = SchnorrSk::from_bytes(&read32(sk)?).map_err(|_| JsValue::from_str("sk"))?;
    let aux_b = match aux {
        Some(a) => Some(read32(&a)?),
        None => None,
    };
    let sig = schnorr::sign_with_aux(&s, &u8_vec(msg), aux_b.as_ref())
        .map_err(|_| JsValue::from_str("sign"))?;
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&sig.rx);
    out[32..].copy_from_slice(&sig.s);
    Ok(to_u8(&out))
}

/// BIP-340 verify 32-byte x-only pk + 64-byte sig over `msg`; returns bool.
#[wasm_bindgen(js_name = schnorrVerify)]
pub fn schnorr_verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, JsValue> {
    let p = SchnorrPk::from_bytes(&read32(pk)?).map_err(|_| JsValue::from_str("pk"))?;
    let sb = read64(sig)?;
    let s = SchnorrSig {
        rx: {
            let mut r = [0u8; 32];
            r.copy_from_slice(&sb[..32]);
            r
        },
        s: {
            let mut r = [0u8; 32];
            r.copy_from_slice(&sb[32..]);
            r
        },
    };
    Ok(schnorr::verify(&p, &u8_vec(msg), &s).is_ok())
}

/// BIP-340 tweaked secret key (32-byte sk + 32-byte tweak → 32-byte sk).
#[wasm_bindgen(js_name = schnorrTweakSecret)]
pub fn schnorr_tweak_secret(sk: &[u8], tweak: &[u8]) -> Result<Vec<u8>, JsValue> {
    let s = SchnorrSk::from_bytes(&read32(sk)?).map_err(|_| JsValue::from_str("sk"))?;
    let sk2 = schnorr::tweak_secret(&s, &read32(tweak)?).map_err(|_| JsValue::from_str("tweak"))?;
    let mut b = [0u8; 32];
    sk2.to_bytes(&mut b);
    Ok(to_u8(&b))
}

/// BIP-340 tweaked x-only public key (32-byte pk + 32-byte tweak → 32-byte pk).
#[wasm_bindgen(js_name = schnorrTweakPublic)]
pub fn schnorr_tweak_public(pk: &[u8], tweak: &[u8]) -> Result<Vec<u8>, JsValue> {
    let p = SchnorrPk::from_bytes(&read32(pk)?).map_err(|_| JsValue::from_str("pk"))?;
    let pk2 = schnorr::tweak_public(&p, &read32(tweak)?).map_err(|_| JsValue::from_str("tweak"))?;
    Ok(to_u8(&pk2.0))
}

/// BCH-style Schnorr verify (33-byte pk, 32-byte digest, 64-byte sig).
/// (Sign lives in curve.rs as `schnorrBchSign`.)
#[wasm_bindgen(js_name = schnorrBchVerify)]
pub fn schnorr_bch_verify(pk: &[u8], digest: &[u8], sig: &[u8]) -> Result<bool, JsValue> {
    use crate::signature::schnorr_bch;
    let p = K1Pk::from_bytes(&u8_vec(pk)).map_err(|_| JsValue::from_str("pk"))?;
    let h = read32(digest)?;
    let sb = read64(sig)?;
    let s = K1Sig::from_compact(&sb).map_err(|_| JsValue::from_str("sig"))?;
    Ok(schnorr_bch::verify(&p, &h, &s).is_ok())
}

/// Recovery id (0..3) for a known compressed pubkey.
/// Mirrors `bu_ecdsa_k1_recover_any` selection via `recovery_id_for`.
#[wasm_bindgen(js_name = ecdsaK1RecoveryId)]
pub fn ecdsa_k1_recovery_id(hash32: &[u8], sig64: &[u8], pk33: &[u8]) -> Result<u8, JsValue> {
    let h = read32(hash32)?;
    let sb = read64(sig64)?;
    let s = K1Sig::from_compact(&sb).map_err(|_| JsValue::from_str("sig"))?;
    let p = K1Pk::from_bytes(&u8_vec(pk33)).map_err(|_| JsValue::from_str("pk"))?;
    ecdsa::recovery_id_for(&h, &s, &p).map_err(|_| JsValue::from_str("no match"))
}

/// R1 recovery id (0..3) for (`hash`, 64-byte compact `sig`, 33-byte `pk`);
/// mirrors `bu_ecdsa_r1_recovery_id`.
#[wasm_bindgen(js_name = ecdsaR1RecoveryId)]
pub fn ecdsa_r1_recovery_id(hash32: &[u8], sig64: &[u8], pk33: &[u8]) -> Result<u8, JsValue> {
    let h = read32(hash32)?;
    let s = R1Sig::from_compact(&read64(sig64)?).map_err(|_| JsValue::from_str("sig"))?;
    if pk33.len() != 33 {
        return Err(JsValue::from_str("pk"));
    }
    let mut pb = [0u8; 33];
    pb.copy_from_slice(pk33);
    let p = R1Pk::from_bytes(&pb).map_err(|_| JsValue::from_str("pk"))?;
    ecdsa_p256::recovery_id_for(&h, &s, &p).map_err(|_| JsValue::from_str("no match"))
}

/// BIP-340 sign with explicit 32-byte `aux` and optional 32-byte Taproot
/// `tweak` → 64-byte sig; mirrors `bu_schnorr_sign_aux`.
#[wasm_bindgen(js_name = schnorrSignAux)]
pub fn schnorr_sign_aux(
    sk: &[u8],
    msg: &[u8],
    aux: Option<Vec<u8>>,
    tweak: Option<Vec<u8>>,
) -> Result<Vec<u8>, JsValue> {
    let s = SchnorrSk::from_bytes(&read32(sk)?).map_err(|_| JsValue::from_str("sk"))?;
    let aux_b = match aux {
        Some(a) => Some(read32(&a)?),
        None => None,
    };
    let tweak_b = match tweak {
        Some(t) => Some(read32(&t)?),
        None => None,
    };
    let sig = schnorr::sign_with_aux_and_tweak(&s, &u8_vec(msg), aux_b.as_ref(), tweak_b.as_ref())
        .map_err(|_| JsValue::from_str("sign"))?;
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&sig.rx);
    out[32..].copy_from_slice(&sig.s);
    Ok(to_u8(&out))
}
