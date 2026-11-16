//! Curve / Ed25519 scalar WASM exports for the web connector.

#![cfg(all(feature = "wasm", feature = "alloc"))]

use wasm_bindgen::prelude::*;

use crate::curve::ed25519::Ed25519Point;
use crate::curve::ed25519::Scalar as EdScalar;
use crate::curve::pallas::{self as pallas, hash_to_curve_pasta, to_bytes_pasta};
use crate::curve::secp256k1::Scalar as K1Scalar;
use crate::curve::secp256k1::Secp256k1Point;
use crate::curve::traits::CurvePoint;
use crate::curve::vesta::{self as vesta};

fn u8_vec(a: &[u8]) -> Vec<u8> {
    let mut v = vec![0u8; a.len() as usize];
    v.copy_from_slice(a);
    v
}

fn to_u8(v: &[u8]) -> Vec<u8> {
    v.to_vec()
}

/// Monero `sc_reduce32`: 32-byte LE → 32-byte scalar mod L.
#[wasm_bindgen(js_name = ed25519ScReduce32)]
pub fn ed25519_sc_reduce32(scalar32: &[u8]) -> Result<Vec<u8>, JsValue> {
    if scalar32.len() != 32 {
        return Err(JsValue::from_str("scalar must be 32 bytes"));
    }
    let mut inn = [0u8; 32];
    inn.copy_from_slice(scalar32);
    let s = EdScalar::sc_reduce32(&inn);
    let mut out = [0u8; 32];
    s.to_bytes_le(&mut out);
    Ok(to_u8(&out))
}

/// Monero `sc_reduce64`: 64-byte LE → 32-byte scalar mod L.
#[wasm_bindgen(js_name = ed25519ScReduce64)]
pub fn ed25519_sc_reduce64(scalar64: &[u8]) -> Result<Vec<u8>, JsValue> {
    if scalar64.len() != 64 {
        return Err(JsValue::from_str("scalar must be 64 bytes"));
    }
    let mut inn = [0u8; 64];
    inn.copy_from_slice(scalar64);
    let s = EdScalar::sc_reduce64(&inn);
    let mut out = [0u8; 32];
    s.to_bytes_le(&mut out);
    Ok(to_u8(&out))
}

/// Ed25519 base-point multiply (32-byte LE scalar → 32-byte compressed point).
#[wasm_bindgen(js_name = ed25519MulBase)]
pub fn ed25519_mul_base(scalar: &[u8]) -> Result<Vec<u8>, JsValue> {
    if scalar.len() != 32 {
        return Err(JsValue::from_str("scalar must be 32 bytes"));
    }
    let mut sb = [0u8; 32];
    sb.copy_from_slice(scalar);
    let s = EdScalar::from_bytes_mod_order(&sb);
    let p = Ed25519Point::generator().mul(&s);
    let mut out = [0u8; 32];
    CurvePoint::to_bytes_compressed(&p, &mut out).map_err(|_| JsValue::from_str("encode"))?;
    Ok(to_u8(&out))
}

/// secp256k1 base-point multiply (32-byte BE scalar → 33-byte compressed).
#[wasm_bindgen(js_name = secp256k1MulBase)]
pub fn secp256k1_mul_base(scalar: &[u8]) -> Result<Vec<u8>, JsValue> {
    if scalar.len() != 32 {
        return Err(JsValue::from_str("scalar must be 32 bytes"));
    }
    let mut sb = [0u8; 32];
    sb.copy_from_slice(scalar);
    let s = K1Scalar::from_bytes_be(&sb).map_err(|_| JsValue::from_str("invalid scalar"))?;
    let p = Secp256k1Point::generator().mul(&s);
    let mut out = [0u8; 33];
    CurvePoint::to_bytes_compressed(&p, &mut out).map_err(|_| JsValue::from_str("encode"))?;
    Ok(to_u8(&out))
}

/// BCH legacy Schnorr sign (digest 32).
#[wasm_bindgen(js_name = schnorrBchSign)]
pub fn schnorr_bch_sign(
    sk: &[u8],
    digest: &[u8],
    extra: Option<Vec<u8>>,
) -> Result<Vec<u8>, JsValue> {
    if sk.len() != 32 || digest.len() != 32 {
        return Err(JsValue::from_str("sk/digest must be 32 bytes"));
    }
    let mut sb = [0u8; 32];
    let mut db = [0u8; 32];
    sb.copy_from_slice(sk);
    db.copy_from_slice(digest);
    let secret = crate::signature::ecdsa::SecretKey::from_bytes(&sb)
        .map_err(|_| JsValue::from_str("invalid sk"))?;
    let extra_v = extra.map(|a| u8_vec(&a));
    let sig = crate::signature::schnorr_bch::sign(&secret, &db, extra_v.as_deref())
        .map_err(|_| JsValue::from_str("sign failed"))?;
    let mut out = [0u8; 64];
    sig.to_compact(&mut out);
    Ok(to_u8(&out))
}

/// Jubjub sc_reduce64: 64-byte LE → 32-byte LE scalar.
#[wasm_bindgen(js_name = jubjubScReduce64)]
pub fn jubjub_sc_reduce64(scalar64: &[u8]) -> Result<Vec<u8>, JsValue> {
    if scalar64.len() != 64 {
        return Err(JsValue::from_str("len"));
    }
    let mut inn = [0u8; 64];
    inn.copy_from_slice(scalar64);
    let s = crate::curve::jubjub::Scalar::sc_reduce64_le(&inn);
    let mut le = [0u8; 32];
    s.to_bytes_le(&mut le);
    Ok(le.to_vec())
}

/// Pallas sc_reduce64: 64-byte LE → 32-byte LE scalar.
#[wasm_bindgen(js_name = pallasScReduce64)]
pub fn pallas_sc_reduce64(scalar64: &[u8]) -> Result<Vec<u8>, JsValue> {
    if scalar64.len() != 64 {
        return Err(JsValue::from_str("len"));
    }
    let mut inn = [0u8; 64];
    inn.copy_from_slice(scalar64);
    let s = crate::curve::pallas::Scalar::sc_reduce64_le(&inn);
    let mut le = [0u8; 32];
    s.to_bytes_le(&mut le);
    Ok(le.to_vec())
}

/// Vesta sc_reduce64: 64-byte LE → 32-byte LE scalar.
#[wasm_bindgen(js_name = vestaScReduce64)]
pub fn vesta_sc_reduce64(scalar64: &[u8]) -> Result<Vec<u8>, JsValue> {
    if scalar64.len() != 64 {
        return Err(JsValue::from_str("len"));
    }
    let mut inn = [0u8; 64];
    inn.copy_from_slice(scalar64);
    let s = crate::curve::vesta::Scalar::sc_reduce64_le(&inn);
    let mut le = [0u8; 32];
    s.to_bytes_le(&mut le);
    Ok(le.to_vec())
}

/// Pallas hash-to-curve (RFC 9380 XMD:SHA-256_SSWU_RO) → 32-byte Pasta
/// compressed point. Mirrors `bu_pallas_hash_to_curve`.
#[wasm_bindgen(js_name = pallasHashToCurve)]
pub fn pallas_hash_to_curve(msg: &[u8], dst: &[u8]) -> Result<Vec<u8>, JsValue> {
    let p = pallas::hash_to_curve(msg, dst);
    Ok(to_bytes_pasta(&p).to_vec())
}

/// Pallas Pasta/Halo2 hash-to-curve: UTF-8 domain prefix + message →
/// 32-byte Pasta compressed point. Mirrors
/// `bu_pallas_hash_to_curve_pasta`.
#[wasm_bindgen(js_name = pallasHashToCurvePasta)]
pub fn pallas_hash_to_curve_pasta(
    domain_prefix: &[u8],
    message: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let dom = core::str::from_utf8(domain_prefix)
        .map_err(|_| JsValue::from_str("domain must be UTF-8"))?;
    let p = hash_to_curve_pasta(dom, message);
    Ok(to_bytes_pasta(&p).to_vec())
}

/// Vesta hash-to-curve (RFC 9380 style) → 32-byte compressed point.
/// Mirrors `bu_vesta_hash_to_curve`.
#[wasm_bindgen(js_name = vestaHashToCurve)]
pub fn vesta_hash_to_curve(msg: &[u8], dst: &[u8]) -> Result<Vec<u8>, JsValue> {
    let p = vesta::hash_to_curve(msg, dst);
    let mut buf = [0u8; 32];
    p.to_bytes_compressed(&mut buf)
        .map_err(|_| JsValue::from_str("identity unencodable"))?;
    Ok(buf.to_vec())
}

/// Monero ge_fromfe_frombytes_vartime → 32-byte compressed point.
#[wasm_bindgen(js_name = ed25519FromFeBytes)]
pub fn ed25519_from_fe_bytes(fe32: &[u8]) -> Result<Vec<u8>, JsValue> {
    if fe32.len() != 32 {
        return Err(JsValue::from_str("len"));
    }
    let mut inn = [0u8; 32];
    inn.copy_from_slice(fe32);
    let p = crate::curve::ed25519::from_fe_bytes(&inn).map_err(|_| JsValue::from_str("point"))?;
    let mut out = [0u8; 32];
    p.to_bytes_compressed(&mut out)
        .map_err(|_| JsValue::from_str("enc"))?;
    Ok(out.to_vec())
}

/// Monero [8] Hp(u) — clear-cofactor hash-to-point.
#[wasm_bindgen(js_name = ed25519FromFeBytesClearCofactor)]
pub fn ed25519_from_fe_bytes_clear_cofactor(fe32: &[u8]) -> Result<Vec<u8>, JsValue> {
    if fe32.len() != 32 {
        return Err(JsValue::from_str("len"));
    }
    let mut inn = [0u8; 32];
    inn.copy_from_slice(fe32);
    let p = crate::curve::ed25519::from_fe_bytes_clear_cofactor(&inn)
        .map_err(|_| JsValue::from_str("point"))?;
    let mut out = [0u8; 32];
    p.to_bytes_compressed(&mut out)
        .map_err(|_| JsValue::from_str("enc"))?;
    Ok(out.to_vec())
}

/// Monero hash_to_ec: Keccak-256(data) → from_fe → ×8 → compressed.
#[wasm_bindgen(js_name = ed25519HashToEc)]
pub fn ed25519_hash_to_ec(data: &[u8]) -> Result<Vec<u8>, JsValue> {
    let v = u8_vec(data);
    let out = crate::curve::ed25519::hash_to_ec(&v).map_err(|_| JsValue::from_str("hash_to_ec"))?;
    Ok(to_u8(&out))
}

/// True if `pk32` is a valid on-curve Ed25519 key (false if bad length).
#[wasm_bindgen(js_name = ed25519CheckKey)]
pub fn ed25519_check_key(pk32: &[u8]) -> bool {
    if pk32.len() != 32 {
        return false;
    }
    let mut b = [0u8; 32];
    b.copy_from_slice(pk32);
    crate::curve::ed25519::check_key(&b)
}

/// Multiply point by cofactor 8; Err "len"/"point"/"enc".
#[wasm_bindgen(js_name = ed25519MulByCofactor)]
pub fn ed25519_mul_by_cofactor(point32: &[u8]) -> Result<Vec<u8>, JsValue> {
    if point32.len() != 32 {
        return Err(JsValue::from_str("len"));
    }
    let mut b = [0u8; 32];
    b.copy_from_slice(point32);
    let p = Ed25519Point::from_bytes(&b).map_err(|_| JsValue::from_str("point"))?;
    let q = crate::curve::ed25519::mul_by_cofactor(&p);
    let mut out = [0u8; 32];
    q.to_bytes_compressed(&mut out)
        .map_err(|_| JsValue::from_str("enc"))?;
    Ok(to_u8(&out))
}

/// Key image `a * Hp`; Err "len"/"point"/"scalar"/"enc".
#[wasm_bindgen(js_name = ed25519ScalarmultKeyImage)]
pub fn ed25519_scalarmult_key_image(hp32: &[u8], a32: &[u8]) -> Result<Vec<u8>, JsValue> {
    if hp32.len() != 32 || a32.len() != 32 {
        return Err(JsValue::from_str("len"));
    }
    let mut hp = [0u8; 32];
    let mut a = [0u8; 32];
    hp.copy_from_slice(hp32);
    a.copy_from_slice(a32);
    let p = Ed25519Point::from_bytes(&hp).map_err(|_| JsValue::from_str("point"))?;
    let sc = EdScalar::from_bytes_le(&a).map_err(|_| JsValue::from_str("scalar"))?;
    let q = crate::curve::ed25519::scalarmult_key_image(&p, &sc);
    let mut out = [0u8; 32];
    q.to_bytes_compressed(&mut out)
        .map_err(|_| JsValue::from_str("enc"))?;
    Ok(to_u8(&out))
}

/// Fused `8 * (s * P)` (CT on secret `s`); Err "len"/"point"/"scalar"/"enc".
#[wasm_bindgen(js_name = ed25519Mul8Mult)]
pub fn ed25519_mul8_mult(s32: &[u8], p32: &[u8]) -> Result<Vec<u8>, JsValue> {
    if s32.len() != 32 || p32.len() != 32 {
        return Err(JsValue::from_str("len"));
    }
    let mut s = [0u8; 32];
    let mut p = [0u8; 32];
    s.copy_from_slice(s32);
    p.copy_from_slice(p32);
    let pp = Ed25519Point::from_bytes(&p).map_err(|_| JsValue::from_str("point"))?;
    let sc = EdScalar::from_bytes_le(&s).map_err(|_| JsValue::from_str("scalar"))?;
    let q = crate::curve::ed25519::scalarmult8(&pp, &sc);
    let mut out = [0u8; 32];
    q.to_bytes_compressed(&mut out)
        .map_err(|_| JsValue::from_str("enc"))?;
    Ok(to_u8(&out))
}

fn parse_precomp(t: &[u8]) -> Result<[Ed25519Point; 8], JsValue> {
    if t.len() != 256 {
        return Err(JsValue::from_str("precomp len"));
    }
    let mut bytes = [0u8; 256];
    bytes.copy_from_slice(t);
    let mut out = [Ed25519Point::identity(); 8];
    for i in 0..8 {
        let mut b = [0u8; 32];
        b.copy_from_slice(&bytes[i * 32..(i + 1) * 32]);
        out[i] = Ed25519Point::from_bytes(&b).map_err(|_| JsValue::from_str("precomp point"))?;
    }
    Ok(out)
}

fn write_precomp(table: &[Ed25519Point; 8]) -> Result<Vec<u8>, JsValue> {
    let mut bytes = [0u8; 256];
    for i in 0..8 {
        let mut b = [0u8; 32];
        table[i]
            .to_bytes_compressed(&mut b)
            .map_err(|_| JsValue::from_str("enc"))?;
        bytes[i * 32..(i + 1) * 32].copy_from_slice(&b);
    }
    Ok(to_u8(&bytes))
}

/// Build odd-multiples precomp table (256 bytes); Err "len"/"point".
#[wasm_bindgen(js_name = ed25519GeDsmPrecomp)]
pub fn ed25519_ge_dsm_precomp(point32: &[u8]) -> Result<Vec<u8>, JsValue> {
    if point32.len() != 32 {
        return Err(JsValue::from_str("len"));
    }
    let mut b = [0u8; 32];
    b.copy_from_slice(point32);
    let p = Ed25519Point::from_bytes(&b).map_err(|_| JsValue::from_str("point"))?;
    let t = crate::curve::ed25519::ge_dsm_precomp_var(&p);
    write_precomp(&t)
}

/// `a*A + b*B` with precomp tables; Err "precomp point"/"enc".
#[wasm_bindgen(js_name = ed25519GeDoubleScalarMultPrecomp)]
pub fn ed25519_ge_double_scalar_mult_precomp(
    a32: &[u8],
    a_i: &[u8],
    b32: &[u8],
    b_i: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    a.copy_from_slice(a32);
    b.copy_from_slice(b32);
    let ai = parse_precomp(a_i)?;
    let bi = parse_precomp(b_i)?;
    let r = crate::curve::ed25519::ge_double_scalar_mult_precomp_point_var(&a, &ai, &b, &bi);
    let mut out = [0u8; 32];
    r.to_bytes_compressed(&mut out)
        .map_err(|_| JsValue::from_str("enc"))?;
    Ok(to_u8(&out))
}

/// `a*A + b*B` with B = basepoint; Err "point"/"enc".
#[wasm_bindgen(js_name = ed25519GeDoubleScalarMultBase)]
pub fn ed25519_ge_double_scalar_mult_base(
    a32: &[u8],
    g_a32: &[u8],
    b32: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let mut a = [0u8; 32];
    let mut ga = [0u8; 32];
    let mut b = [0u8; 32];
    a.copy_from_slice(a32);
    ga.copy_from_slice(g_a32);
    b.copy_from_slice(b32);
    let gap = Ed25519Point::from_bytes(&ga).map_err(|_| JsValue::from_str("point"))?;
    let r = crate::curve::ed25519::ge_double_scalar_mult_base_point_var(&a, &gap, &b);
    let mut out = [0u8; 32];
    r.to_bytes_compressed(&mut out)
        .map_err(|_| JsValue::from_str("enc"))?;
    Ok(to_u8(&out))
}

/// `a*B + b*P + c*Q` with base; Err "precomp point"/"enc".
#[wasm_bindgen(js_name = ed25519GeTripleScalarMultBase)]
pub fn ed25519_ge_triple_scalar_mult_base(
    a32: &[u8],
    b32: &[u8],
    b_i: &[u8],
    c32: &[u8],
    c_i: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    let mut c = [0u8; 32];
    a.copy_from_slice(a32);
    b.copy_from_slice(b32);
    c.copy_from_slice(c32);
    let bi = parse_precomp(b_i)?;
    let ci = parse_precomp(c_i)?;
    let r = crate::curve::ed25519::ge_triple_scalar_mult_base_point_var(&a, &b, &bi, &c, &ci);
    let mut out = [0u8; 32];
    r.to_bytes_compressed(&mut out)
        .map_err(|_| JsValue::from_str("enc"))?;
    Ok(to_u8(&out))
}

/// `a*A + b*B + c*C` with precomp tables; Err "precomp point"/"enc".
#[wasm_bindgen(js_name = ed25519GeTripleScalarMultPrecomp)]
pub fn ed25519_ge_triple_scalar_mult_precomp(
    a32: &[u8],
    a_i: &[u8],
    b32: &[u8],
    b_i: &[u8],
    c32: &[u8],
    c_i: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    let mut c = [0u8; 32];
    a.copy_from_slice(a32);
    b.copy_from_slice(b32);
    c.copy_from_slice(c32);
    let ai = parse_precomp(a_i)?;
    let bi = parse_precomp(b_i)?;
    let ci = parse_precomp(c_i)?;
    let r =
        crate::curve::ed25519::ge_triple_scalar_mult_precomp_point_var(&a, &ai, &b, &bi, &c, &ci);
    let mut out = [0u8; 32];
    r.to_bytes_compressed(&mut out)
        .map_err(|_| JsValue::from_str("enc"))?;
    Ok(to_u8(&out))
}

/// Variable-time [s]P (public scalar).
#[wasm_bindgen(js_name = ed25519MulVartime)]
pub fn ed25519_mul_vartime(scalar: &[u8], point: &[u8]) -> Result<Vec<u8>, JsValue> {
    use crate::curve::traits::{CurvePoint, Scalar as ScalarTrait};
    if scalar.len() != 32 || point.len() != 32 {
        return Err(JsValue::from_str("len"));
    }
    let mut s = [0u8; 32];
    let mut p = [0u8; 32];
    s.copy_from_slice(scalar);
    p.copy_from_slice(point);
    let sc = EdScalar::from_bytes_le(&s).map_err(|_| JsValue::from_str("scalar"))?;
    let pt = Ed25519Point::from_bytes(&p).map_err(|_| JsValue::from_str("point"))?;
    let r = pt.mul_vartime(&sc);
    let mut out = [0u8; 32];
    r.to_bytes_compressed(&mut out)
        .map_err(|_| JsValue::from_str("enc"))?;
    Ok(to_u8(&out))
}

/// Variable-time base-point multiply; Err "len"/"scalar"/"enc".
#[wasm_bindgen(js_name = ed25519MulBaseVartime)]
pub fn ed25519_mul_base_vartime(scalar: &[u8]) -> Result<Vec<u8>, JsValue> {
    use crate::curve::traits::CurvePoint;
    if scalar.len() != 32 {
        return Err(JsValue::from_str("len"));
    }
    let mut s = [0u8; 32];
    s.copy_from_slice(scalar);
    let sc = EdScalar::from_bytes_le(&s).map_err(|_| JsValue::from_str("scalar"))?;
    let r = Ed25519Point::mul_vartime_base(&sc);
    let mut out = [0u8; 32];
    r.to_bytes_compressed(&mut out)
        .map_err(|_| JsValue::from_str("enc"))?;
    Ok(to_u8(&out))
}

/// Variable-time `s1*p1 + s2*p2`; Err "s1"/"s2"/"p1"/"p2"/"enc".
#[wasm_bindgen(js_name = ed25519MulAddVartime)]
pub fn ed25519_mul_add_vartime(
    s1: &[u8],
    p1: &[u8],
    s2: &[u8],
    p2: &[u8],
) -> Result<Vec<u8>, JsValue> {
    use crate::curve::traits::{CurvePoint, Scalar as ScalarTrait};
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    let mut pa = [0u8; 32];
    let mut pb = [0u8; 32];
    a.copy_from_slice(s1);
    b.copy_from_slice(s2);
    pa.copy_from_slice(p1);
    pb.copy_from_slice(p2);
    let sa = EdScalar::from_bytes_le(&a).map_err(|_| JsValue::from_str("s1"))?;
    let sb = EdScalar::from_bytes_le(&b).map_err(|_| JsValue::from_str("s2"))?;
    let ap = Ed25519Point::from_bytes(&pa).map_err(|_| JsValue::from_str("p1"))?;
    let bp = Ed25519Point::from_bytes(&pb).map_err(|_| JsValue::from_str("p2"))?;
    let r = Ed25519Point::mul_vartime_add(&sa, &ap, &sb, &bp);
    let mut out = [0u8; 32];
    r.to_bytes_compressed(&mut out)
        .map_err(|_| JsValue::from_str("enc"))?;
    Ok(to_u8(&out))
}

/// Variable-time `a + b`; Err "a"/"b"/"enc".
#[wasm_bindgen(js_name = ed25519AddVartime)]
pub fn ed25519_add_vartime(a: &[u8], b: &[u8]) -> Result<Vec<u8>, JsValue> {
    use crate::curve::traits::CurvePoint;
    let mut aa = [0u8; 32];
    let mut bb = [0u8; 32];
    aa.copy_from_slice(a);
    bb.copy_from_slice(b);
    let pa = Ed25519Point::from_bytes(&aa).map_err(|_| JsValue::from_str("a"))?;
    let pb = Ed25519Point::from_bytes(&bb).map_err(|_| JsValue::from_str("b"))?;
    let mut out = [0u8; 32];
    pa.add(&pb)
        .to_bytes_compressed(&mut out)
        .map_err(|_| JsValue::from_str("enc"))?;
    Ok(to_u8(&out))
}

/// Variable-time `a - b`; Err "a"/"b"/"enc".
#[wasm_bindgen(js_name = ed25519SubVartime)]
pub fn ed25519_sub_vartime(a: &[u8], b: &[u8]) -> Result<Vec<u8>, JsValue> {
    use crate::curve::traits::CurvePoint;
    let mut aa = [0u8; 32];
    let mut bb = [0u8; 32];
    aa.copy_from_slice(a);
    bb.copy_from_slice(b);
    let pa = Ed25519Point::from_bytes(&aa).map_err(|_| JsValue::from_str("a"))?;
    let pb = Ed25519Point::from_bytes(&bb).map_err(|_| JsValue::from_str("b"))?;
    let mut out = [0u8; 32];
    pa.add(&pb.neg())
        .to_bytes_compressed(&mut out)
        .map_err(|_| JsValue::from_str("enc"))?;
    Ok(to_u8(&out))
}

/// Variable-time `-p`; Err "p"/"enc".
#[wasm_bindgen(js_name = ed25519NegVartime)]
pub fn ed25519_neg_vartime(p: &[u8]) -> Result<Vec<u8>, JsValue> {
    use crate::curve::traits::CurvePoint;
    let mut bb = [0u8; 32];
    bb.copy_from_slice(p);
    let pa = Ed25519Point::from_bytes(&bb).map_err(|_| JsValue::from_str("p"))?;
    let mut out = [0u8; 32];
    pa.neg()
        .to_bytes_compressed(&mut out)
        .map_err(|_| JsValue::from_str("enc"))?;
    Ok(to_u8(&out))
}

/// Variable-time `2*p`; Err "p"/"enc".
#[wasm_bindgen(js_name = ed25519DoubleVartime)]
pub fn ed25519_double_vartime(p: &[u8]) -> Result<Vec<u8>, JsValue> {
    use crate::curve::traits::CurvePoint;
    let mut bb = [0u8; 32];
    bb.copy_from_slice(p);
    let pa = Ed25519Point::from_bytes(&bb).map_err(|_| JsValue::from_str("p"))?;
    let mut out = [0u8; 32];
    pa.double()
        .to_bytes_compressed(&mut out)
        .map_err(|_| JsValue::from_str("enc"))?;
    Ok(to_u8(&out))
}

/// Edwards compressed → Ristretto compressed.
#[wasm_bindgen(js_name = ristrettoFromEdwards)]
pub fn ristretto_from_edwards(ed32: &[u8]) -> Result<Vec<u8>, JsValue> {
    if ed32.len() != 32 {
        return Err(JsValue::from_str("edwards point must be 32 bytes"));
    }
    let mut eb = [0u8; 32];
    eb.copy_from_slice(ed32);
    let ed_pt =
        Ed25519Point::from_bytes(&eb).map_err(|_| JsValue::from_str("invalid edwards point"))?;
    let r = crate::curve::ristretto::RistrettoPoint::from_ed25519(ed_pt);
    let mut out = [0u8; 32];
    r.encode(&mut out)
        .map_err(|_| JsValue::from_str("ristretto encode failed"))?;
    Ok(to_u8(&out))
}

/// Ristretto compressed → Edwards compressed.
#[wasm_bindgen(js_name = ristrettoToEdwards)]
pub fn ristretto_to_edwards(ristretto32: &[u8]) -> Result<Vec<u8>, JsValue> {
    if ristretto32.len() != 32 {
        return Err(JsValue::from_str("ristretto point must be 32 bytes"));
    }
    let mut rb = [0u8; 32];
    rb.copy_from_slice(ristretto32);
    let r = crate::curve::ristretto::RistrettoPoint::decode(&rb)
        .map_err(|_| JsValue::from_str("invalid ristretto point"))?;
    let mut out = [0u8; 32];
    r.as_ed25519()
        .to_bytes_compressed(&mut out)
        .map_err(|_| JsValue::from_str("edwards encode failed"))?;
    Ok(to_u8(&out))
}

// ---- generic compressed/uncompressed conversion (curve-id dispatch) ----
// Ids mirror `connector::ffi::curve::BU_CURVE_*` (kept local: the ffi module
// is not compiled into wasm-only builds).
const C_SECP256K1: u32 = 1;
const C_SECP256R1: u32 = 2;
const C_ED25519: u32 = 3;
const C_RISTRETTO: u32 = 4;
const C_PALLAS: u32 = 5;
const C_VESTA: u32 = 6;
const C_JUBJUB: u32 = 7;
const C_BLS_G1: u32 = 8;
const C_BLS_G2: u32 = 9;
const C_BN254_G1: u32 = 10;
const C_BN254_G2: u32 = 11;

macro_rules! with_point_wasm {
    ($curve:expr, $body:ident) => {
        match $curve {
            C_SECP256K1 => $body!(crate::curve::Secp256k1Point),
            C_SECP256R1 => $body!(crate::curve::Secp256r1Point),
            C_ED25519 => $body!(crate::curve::Ed25519Point),
            C_RISTRETTO => $body!(crate::curve::RistrettoPoint),
            C_PALLAS => $body!(crate::curve::PallasPoint),
            C_VESTA => $body!(crate::curve::VestaPoint),
            C_JUBJUB => $body!(crate::curve::JubJubPoint),
            C_BLS_G1 => $body!(crate::curve::BlsG1Point),
            C_BLS_G2 => $body!(crate::curve::BlsG2Point),
            C_BN254_G1 => $body!(crate::curve::Bn254G1Point),
            C_BN254_G2 => $body!(crate::curve::bn254::G2Point),
            _ => Err(JsValue::from_str("unknown curve")),
        }
    };
}

/// Uncompressed point length for a curve id (0 = unknown).
#[wasm_bindgen(js_name = curvePointUncompressedLen)]
pub fn wasm_curve_point_uncompressed_len(curve: u32) -> usize {
    match curve {
        C_SECP256K1 => crate::curve::Secp256k1Point::UNCOMPRESSED_BYTES,
        C_SECP256R1 => crate::curve::Secp256r1Point::UNCOMPRESSED_BYTES,
        C_ED25519 => crate::curve::Ed25519Point::UNCOMPRESSED_BYTES,
        C_RISTRETTO => crate::curve::RistrettoPoint::UNCOMPRESSED_BYTES,
        C_PALLAS => crate::curve::PallasPoint::UNCOMPRESSED_BYTES,
        C_VESTA => crate::curve::VestaPoint::UNCOMPRESSED_BYTES,
        C_JUBJUB => crate::curve::JubJubPoint::UNCOMPRESSED_BYTES,
        C_BLS_G1 => crate::curve::BlsG1Point::UNCOMPRESSED_BYTES,
        C_BLS_G2 => crate::curve::BlsG2Point::UNCOMPRESSED_BYTES,
        C_BN254_G1 => crate::curve::Bn254G1Point::UNCOMPRESSED_BYTES,
        C_BN254_G2 => crate::curve::bn254::G2Point::UNCOMPRESSED_BYTES,
        _ => 0,
    }
}

/// Validate any accepted form and re-encode it as compressed, rejecting
/// the point at infinity (key-domain check used by public-key constructors).
#[wasm_bindgen(js_name = curveNormalizePubkey)]
pub fn wasm_curve_normalize_pubkey(curve: u32, point: &[u8]) -> Result<Vec<u8>, JsValue> {
    macro_rules! op {
        ($P:ty) => {{
            let pt = <$P>::from_bytes(point).map_err(|_| JsValue::from_str("point"))?;
            if pt.is_identity() {
                return Err(JsValue::from_str("infinity"));
            }
            let mut out = vec![0u8; <$P>::COMPRESSED_BYTES];
            CurvePoint::to_bytes_compressed(&pt, &mut out)
                .map_err(|_| JsValue::from_str("encode"))?;
            Ok(out)
        }};
    }
    with_point_wasm!(curve, op)
}

/// Re-encode any accepted form as compressed (strict validation on decode).
#[wasm_bindgen(js_name = curveCompress)]
pub fn wasm_curve_compress(curve: u32, point: &[u8]) -> Result<Vec<u8>, JsValue> {
    macro_rules! op {
        ($P:ty) => {{
            let pt = <$P>::from_bytes(point).map_err(|_| JsValue::from_str("point"))?;
            let mut out = vec![0u8; <$P>::COMPRESSED_BYTES];
            CurvePoint::to_bytes_compressed(&pt, &mut out)
                .map_err(|_| JsValue::from_str("encode"))?;
            Ok(out)
        }};
    }
    with_point_wasm!(curve, op)
}

/// Re-encode any accepted form as uncompressed (strict validation on decode).
#[wasm_bindgen(js_name = curveUncompress)]
pub fn wasm_curve_uncompress(curve: u32, point: &[u8]) -> Result<Vec<u8>, JsValue> {
    macro_rules! op {
        ($P:ty) => {{
            let pt = <$P>::from_bytes(point).map_err(|_| JsValue::from_str("point"))?;
            let mut out = vec![0u8; <$P>::UNCOMPRESSED_BYTES];
            CurvePoint::to_bytes_uncompressed(&pt, &mut out)
                .map_err(|_| JsValue::from_str("encode"))?;
            Ok(out)
        }};
    }
    with_point_wasm!(curve, op)
}

/// True when `scalar` is a canonical scalar encoding for `curve`
/// (same ids/semantics as `bu_curve_sc_check`: correct length and range).
#[wasm_bindgen(js_name = curveScCheck)]
pub fn wasm_curve_sc_check(curve: u32, scalar: &[u8]) -> bool {
    macro_rules! op {
        ($P:ty) => {{
            Ok(
                <<$P as CurvePoint>::Scalar as crate::curve::traits::Scalar>::from_bytes(scalar)
                    .is_ok(),
            )
        }};
    }
    with_point_wasm!(curve, op).unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Generic curve arithmetic (same curve ids and semantics as `bu_curve_*`).
// Lets the web connector serve the full `CurveApi` instead of `_u()`.
// ---------------------------------------------------------------------------

use crate::curve::traits::Scalar as ScalarTrait;

fn wasm_sc_from<P: CurvePoint>(b: &[u8]) -> Result<P::Scalar, JsValue> {
    <<P as CurvePoint>::Scalar as ScalarTrait>::from_bytes(b)
        .map_err(|_| JsValue::from_str("scalar"))
}

fn wasm_sc_out<P: CurvePoint>(s: &P::Scalar, len: usize) -> Result<Vec<u8>, JsValue> {
    let mut o = vec![0u8; len];
    <<P as CurvePoint>::Scalar as ScalarTrait>::to_bytes(s, &mut o)
        .map_err(|_| JsValue::from_str("encode"))?;
    Ok(o)
}

fn wasm_pt_out<P: CurvePoint>(p: &P) -> Result<Vec<u8>, JsValue> {
    let mut o = vec![0u8; P::COMPRESSED_BYTES];
    p.to_bytes_compressed(&mut o)
        .map_err(|_| JsValue::from_str("encode"))?;
    Ok(o)
}

fn wasm_pt_from<P: CurvePoint>(b: &[u8]) -> Result<P, JsValue> {
    <P>::from_bytes(b).map_err(|_| JsValue::from_str("point"))
}

/// Compressed generator for `curve`.
#[wasm_bindgen(js_name = curveGenerator)]
pub fn wasm_curve_generator(curve: u32) -> Result<Vec<u8>, JsValue> {
    let p = match curve {
        C_SECP256K1 => wasm_pt_out(&crate::curve::Secp256k1Point::generator()),
        C_SECP256R1 => wasm_pt_out(&crate::curve::Secp256r1Point::generator()),
        C_ED25519 => wasm_pt_out(&crate::curve::Ed25519Point::generator()),
        C_RISTRETTO => wasm_pt_out(&crate::curve::RistrettoPoint::generator()),
        C_PALLAS => wasm_pt_out(&crate::curve::PallasPoint::generator()),
        C_VESTA => wasm_pt_out(&crate::curve::VestaPoint::generator()),
        C_JUBJUB => wasm_pt_out(&crate::curve::JubJubPoint::generator()),
        C_BLS_G1 => wasm_pt_out(&crate::curve::BlsG1Point::generator()),
        C_BLS_G2 => wasm_pt_out(&crate::curve::BlsG2Point::generator()),
        C_BN254_G1 => wasm_pt_out(&crate::curve::Bn254G1Point::generator()),
        C_BN254_G2 => wasm_pt_out(&crate::curve::bn254::G2Point::generator()),
        _ => Err(JsValue::from_str("unknown curve")),
    }?;
    Ok(p)
}

/// Compressed identity for `curve`.
#[wasm_bindgen(js_name = curveIdentity)]
pub fn wasm_curve_identity(curve: u32) -> Result<Vec<u8>, JsValue> {
    macro_rules! op {
        ($P:ty) => {{
            wasm_pt_out(&<$P>::identity())
        }};
    }
    with_point_wasm!(curve, op)
}

/// `out = a + b`.
#[wasm_bindgen(js_name = curveAdd)]
pub fn wasm_curve_add(curve: u32, a: &[u8], b: &[u8]) -> Result<Vec<u8>, JsValue> {
    macro_rules! op {
        ($P:ty) => {{
            let pa = wasm_pt_from::<$P>(a)?;
            let pb = wasm_pt_from::<$P>(b)?;
            wasm_pt_out(&pa.add(&pb))
        }};
    }
    with_point_wasm!(curve, op)
}

/// `out = a - b`.
#[wasm_bindgen(js_name = curveSub)]
pub fn wasm_curve_sub(curve: u32, a: &[u8], b: &[u8]) -> Result<Vec<u8>, JsValue> {
    macro_rules! op {
        ($P:ty) => {{
            let pa = wasm_pt_from::<$P>(a)?;
            let pb = wasm_pt_from::<$P>(b)?;
            wasm_pt_out(&pa.add(&pb.neg()))
        }};
    }
    with_point_wasm!(curve, op)
}

/// `out = -a`.
#[wasm_bindgen(js_name = curveNeg)]
pub fn wasm_curve_neg(curve: u32, a: &[u8]) -> Result<Vec<u8>, JsValue> {
    macro_rules! op {
        ($P:ty) => {{
            let pa = wasm_pt_from::<$P>(a)?;
            wasm_pt_out(&pa.neg())
        }};
    }
    with_point_wasm!(curve, op)
}

/// `out = scalar * point`.
#[wasm_bindgen(js_name = curveMul)]
pub fn wasm_curve_mul(curve: u32, scalar: &[u8], point: &[u8]) -> Result<Vec<u8>, JsValue> {
    macro_rules! op {
        ($P:ty) => {{
            let p = wasm_pt_from::<$P>(point)?;
            let s = wasm_sc_from::<$P>(scalar)?;
            wasm_pt_out(&p.mul(&s))
        }};
    }
    with_point_wasm!(curve, op)
}

/// `out = scalar * G`.
#[wasm_bindgen(js_name = curveMulBase)]
pub fn wasm_curve_mul_base(curve: u32, scalar: &[u8]) -> Result<Vec<u8>, JsValue> {
    macro_rules! op {
        ($P:ty) => {{
            let s = wasm_sc_from::<$P>(scalar)?;
            // NB: generator() is inherent per type; re-derive via identity
            // trick is impossible, so dispatch explicitly like curveGenerator.
            let g = wasm_curve_generator(curve).and_then(|b| wasm_pt_from::<$P>(&b))?;
            wasm_pt_out(&g.mul(&s))
        }};
    }
    with_point_wasm!(curve, op)
}

/// `out = s1 * p1 + s2 * p2`.
#[wasm_bindgen(js_name = curveMulAdd)]
pub fn wasm_curve_mul_add(
    curve: u32,
    s1: &[u8],
    p1: &[u8],
    s2: &[u8],
    p2: &[u8],
) -> Result<Vec<u8>, JsValue> {
    macro_rules! op {
        ($P:ty) => {{
            let a = wasm_pt_from::<$P>(p1)?;
            let b = wasm_pt_from::<$P>(p2)?;
            let sa = wasm_sc_from::<$P>(s1)?;
            let sb = wasm_sc_from::<$P>(s2)?;
            wasm_pt_out(&a.mul(&sa).add(&b.mul(&sb)))
        }};
    }
    with_point_wasm!(curve, op)
}

/// Scalar `a + b` (same encoding length as inputs).
#[wasm_bindgen(js_name = curveScAdd)]
pub fn wasm_curve_sc_add(curve: u32, a: &[u8], b: &[u8]) -> Result<Vec<u8>, JsValue> {
    macro_rules! op {
        ($P:ty) => {{
            let sa = wasm_sc_from::<$P>(a)?;
            let sb = wasm_sc_from::<$P>(b)?;
            wasm_sc_out::<$P>(&sa.add(&sb), a.len())
        }};
    }
    with_point_wasm!(curve, op)
}

/// Scalar `a - b`.
#[wasm_bindgen(js_name = curveScSub)]
pub fn wasm_curve_sc_sub(curve: u32, a: &[u8], b: &[u8]) -> Result<Vec<u8>, JsValue> {
    macro_rules! op {
        ($P:ty) => {{
            let sa = wasm_sc_from::<$P>(a)?;
            let sb = wasm_sc_from::<$P>(b)?;
            wasm_sc_out::<$P>(&sa.add(&sb.neg()), a.len())
        }};
    }
    with_point_wasm!(curve, op)
}

/// Scalar `a * b`.
#[wasm_bindgen(js_name = curveScMul)]
pub fn wasm_curve_sc_mul(curve: u32, a: &[u8], b: &[u8]) -> Result<Vec<u8>, JsValue> {
    macro_rules! op {
        ($P:ty) => {{
            let sa = wasm_sc_from::<$P>(a)?;
            let sb = wasm_sc_from::<$P>(b)?;
            wasm_sc_out::<$P>(&sa.mul(&sb), a.len())
        }};
    }
    with_point_wasm!(curve, op)
}

/// Scalar `-s`.
#[wasm_bindgen(js_name = curveScNeg)]
pub fn wasm_curve_sc_neg(curve: u32, s: &[u8]) -> Result<Vec<u8>, JsValue> {
    macro_rules! op {
        ($P:ty) => {{
            let ss = wasm_sc_from::<$P>(s)?;
            wasm_sc_out::<$P>(&ss.neg(), s.len())
        }};
    }
    with_point_wasm!(curve, op)
}

/// Reduce a scalar encoding modulo the curve order (mirrors
/// `bu_curve_sc_reduce`: ed25519/ristretto accept 64- and 32-byte LE,
/// all other curves exactly 32 bytes; always 32-byte output).
#[wasm_bindgen(js_name = curveScReduce)]
pub fn wasm_curve_sc_reduce(curve: u32, scalar: &[u8]) -> Result<Vec<u8>, JsValue> {
    if curve == C_ED25519 || curve == C_RISTRETTO {
        if scalar.len() == 64 {
            let mut inn = [0u8; 64];
            inn.copy_from_slice(scalar);
            let s = crate::curve::ed25519::Scalar::sc_reduce64(&inn);
            let mut o = [0u8; 32];
            s.to_bytes_le(&mut o);
            return Ok(o.to_vec());
        }
        if scalar.len() == 32 {
            let mut inn = [0u8; 32];
            inn.copy_from_slice(scalar);
            let s = crate::curve::ed25519::Scalar::sc_reduce32(&inn);
            let mut o = [0u8; 32];
            s.to_bytes_le(&mut o);
            return Ok(o.to_vec());
        }
        return Err(JsValue::from_str("scalar must be 32 or 64 bytes"));
    }
    if scalar.len() != 32 {
        return Err(JsValue::from_str("scalar must be 32 bytes"));
    }
    let mut inn = [0u8; 32];
    inn.copy_from_slice(scalar);
    let mut o = [0u8; 32];
    match curve {
        C_SECP256K1 => {
            let s = crate::curve::Secp256k1Scalar::from_bytes_mod_order(&inn);
            s.to_bytes_be(&mut o);
        }
        C_SECP256R1 => {
            let s = crate::curve::Secp256r1Scalar::from_bytes_mod_order(&inn);
            s.to_bytes_be(&mut o);
        }
        C_JUBJUB => {
            let mut wide = [0u8; 64];
            wide[..32].copy_from_slice(&inn);
            let s = crate::curve::jubjub::Scalar::sc_reduce64_le(&wide);
            s.to_bytes_le(&mut o);
        }
        C_PALLAS => {
            let mut wide = [0u8; 64];
            wide[..32].copy_from_slice(&inn);
            let s = crate::curve::pallas::Scalar::sc_reduce64_le(&wide);
            s.to_bytes_le(&mut o);
        }
        C_VESTA => {
            let mut wide = [0u8; 64];
            wide[..32].copy_from_slice(&inn);
            let s = crate::curve::vesta::Scalar::sc_reduce64_le(&wide);
            s.to_bytes_le(&mut o);
        }
        C_BLS_G1 | C_BLS_G2 => {
            let b256 = crate::curve::bls::Scalar::from_u64(256);
            let mut acc = crate::curve::bls::Scalar::zero();
            for &byte in inn.iter() {
                acc = acc
                    .mul(&b256)
                    .add(&crate::curve::bls::Scalar::from_u64(byte as u64));
            }
            acc.to_bytes_be(&mut o);
        }
        C_BN254_G1 | C_BN254_G2 => {
            use crate::curve::bn254::Scalar as Bn254Scalar;
            let b256 = Bn254Scalar::from_u64(256);
            let mut acc = Bn254Scalar::zero();
            for &byte in inn.iter() {
                acc = acc.mul(&b256).add(&Bn254Scalar::from_u64(byte as u64));
            }
            acc.to_bytes_be(&mut o);
        }
        _ => return Err(JsValue::from_str("unknown curve")),
    }
    Ok(o.to_vec())
}

/// Compressed point length for `curve` (0 = unknown; mirrors
/// `bu_curve_point_len`).
#[wasm_bindgen(js_name = curvePointLen)]
pub fn wasm_curve_point_len(curve: u32) -> usize {
    macro_rules! op {
        ($P:ty) => {{
            Ok(<$P>::COMPRESSED_BYTES)
        }};
    }
    with_point_wasm!(curve, op).unwrap_or(0)
}

/// Scalar length for `curve` (0 = unknown; mirrors `bu_curve_scalar_len`).
#[wasm_bindgen(js_name = curveScalarLen)]
pub fn wasm_curve_scalar_len(curve: u32) -> usize {
    macro_rules! op {
        ($P:ty) => {{
            Ok(<<$P as CurvePoint>::Scalar as ScalarTrait>::BYTES)
        }};
    }
    with_point_wasm!(curve, op).unwrap_or(0)
}

/// True when `point` decodes to the point at infinity (any accepted form).
/// Mirrors `bu_curve_is_infinity` (1 = infinity, 0 = not).
#[wasm_bindgen(js_name = curveIsInfinity)]
pub fn wasm_curve_is_infinity(curve: u32, point: &[u8]) -> Result<bool, JsValue> {
    macro_rules! op {
        ($P:ty) => {{
            let pt = <$P>::from_bytes(point).map_err(|_| JsValue::from_str("point"))?;
            Ok(pt.is_identity())
        }};
    }
    with_point_wasm!(curve, op)
}

/// Deterministic secret scalar from `seed` (SHA-256 then parse, rehash with
/// domain byte on failure — mirrors `bu_curve_generate_secret`).
/// Returns `curveScalarLen(curve)` bytes.
#[wasm_bindgen(js_name = curveGenerateSecret)]
pub fn wasm_curve_generate_secret(curve: u32, seed: &[u8]) -> Result<Vec<u8>, JsValue> {
    if seed.is_empty() {
        return Err(JsValue::from_str("empty seed"));
    }
    let need = wasm_curve_scalar_len(curve);
    if need == 0 || need > 64 {
        return Err(JsValue::from_str("unknown curve"));
    }
    fn try_parse<P>(candidate: &[u8], need: usize) -> Option<Vec<u8>>
    where
        P: CurvePoint,
    {
        let s =
            <<P as CurvePoint>::Scalar as crate::curve::traits::Scalar>::from_bytes(&candidate[..need])
                .ok()?;
        let mut out = vec![0u8; need];
        s.to_bytes(&mut out[..]).ok()?;
        Some(out)
    }
    let mut h = crate::hash::sha256::sha256(seed).map_err(|_| JsValue::from_str("hash"))?;
    for attempt in 0u8..8 {
        if attempt > 0 {
            let mut buf = [0u8; 33];
            buf[..32].copy_from_slice(&h);
            buf[32] = attempt;
            h = crate::hash::sha256::sha256(&buf).map_err(|_| JsValue::from_str("hash"))?;
        }
        let mut candidate = [0u8; 64];
        let n = need.min(32);
        candidate[..n].copy_from_slice(&h[..n]);
        let found = match curve {
            C_SECP256K1 => try_parse::<crate::curve::Secp256k1Point>(&candidate, need),
            C_SECP256R1 => try_parse::<crate::curve::Secp256r1Point>(&candidate, need),
            C_ED25519 => try_parse::<crate::curve::Ed25519Point>(&candidate, need),
            C_RISTRETTO => try_parse::<crate::curve::RistrettoPoint>(&candidate, need),
            C_PALLAS => try_parse::<crate::curve::PallasPoint>(&candidate, need),
            C_VESTA => try_parse::<crate::curve::VestaPoint>(&candidate, need),
            C_JUBJUB => try_parse::<crate::curve::JubJubPoint>(&candidate, need),
            C_BLS_G1 => try_parse::<crate::curve::BlsG1Point>(&candidate, need),
            C_BLS_G2 => try_parse::<crate::curve::BlsG2Point>(&candidate, need),
            C_BN254_G1 => try_parse::<crate::curve::Bn254G1Point>(&candidate, need),
            C_BN254_G2 => try_parse::<crate::curve::bn254::G2Point>(&candidate, need),
            _ => None,
        };
        if let Some(out) = found {
            return Ok(out);
        }
    }
    Err(JsValue::from_str("no scalar found"))
}

/// Hash message to BLS12-381 G1 (RFC 9380 style) → 48-byte compressed point.
/// Mirrors `bu_bls_hash_to_g1`.
#[wasm_bindgen(js_name = blsHashToG1)]
pub fn wasm_bls_hash_to_g1(msg: &[u8], dst: &[u8]) -> Result<Vec<u8>, JsValue> {
    let p = crate::curve::bls::hash_to_g1(msg, dst);
    let mut out = vec![0u8; crate::curve::BlsG1Point::COMPRESSED_BYTES];
    CurvePoint::to_bytes_compressed(&p, &mut out).map_err(|_| JsValue::from_str("encode"))?;
    Ok(out)
}

/// Hash message to BLS12-381 G2 (RFC 9380 style) → 96-byte compressed point.
/// Mirrors `bu_bls_hash_to_g2`.
#[wasm_bindgen(js_name = blsHashToG2)]
pub fn wasm_bls_hash_to_g2(msg: &[u8], dst: &[u8]) -> Result<Vec<u8>, JsValue> {
    let p = crate::curve::bls::hash_to_g2(msg, dst);
    let mut out = vec![0u8; crate::curve::BlsG2Point::COMPRESSED_BYTES];
    CurvePoint::to_bytes_compressed(&p, &mut out).map_err(|_| JsValue::from_str("encode"))?;
    Ok(out)
}
