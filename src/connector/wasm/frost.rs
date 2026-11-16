//! FROST WASM exports for the web connector.
//!
//! Same fixed-size blob protocol as the FFI layer (`connector::ffi::frost`):
//! commitment records (70 B k1 / 68 B ed), factor records (36 B),
//! share records (36 B). Signing calls return fixed blobs; verify calls
//! return `bool`.

#![cfg(all(feature = "wasm", feature = "alloc"))]

use wasm_bindgen::prelude::*;

use crate::frost::{ed as fed, k1 as fk1};

fn u8_vec(a: &[u8]) -> Vec<u8> {
    a.to_vec()
}

fn arr32(a: &[u8]) -> Result<[u8; 32], JsValue> {
    if a.len() != 32 {
        return Err(JsValue::from_str("expected 32 bytes"));
    }
    let mut o = [0u8; 32];
    o.copy_from_slice(a);
    Ok(o)
}

fn arr33(a: &[u8]) -> Result<[u8; 33], JsValue> {
    if a.len() != 33 {
        return Err(JsValue::from_str("expected 33 bytes"));
    }
    let mut o = [0u8; 33];
    o.copy_from_slice(a);
    Ok(o)
}

fn rd32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

fn parse_k1_coms(raw: &[u8], n: usize) -> Result<Vec<fk1::Commitment>, JsValue> {
    if raw.len() != n * 70 {
        return Err(JsValue::from_str("invalid commitments length"));
    }
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let rec = &raw[i * 70..(i + 1) * 70];
        let mut hiding = [0u8; 33];
        let mut binding = [0u8; 33];
        hiding.copy_from_slice(&rec[4..37]);
        binding.copy_from_slice(&rec[37..70]);
        out.push(fk1::Commitment {
            id: rd32(&rec[..4]),
            hiding,
            binding,
        });
    }
    Ok(out)
}

fn parse_k1_factors(raw: &[u8], n: usize) -> Result<Vec<(u32, [u8; 32])>, JsValue> {
    if raw.len() != n * 36 {
        return Err(JsValue::from_str("invalid factors length"));
    }
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let rec = &raw[i * 36..(i + 1) * 36];
        let mut rho = [0u8; 32];
        rho.copy_from_slice(&rec[4..36]);
        out.push((rd32(&rec[..4]), rho));
    }
    Ok(out)
}

fn parse_ed_coms(raw: &[u8], n: usize) -> Result<Vec<fed::Commitment>, JsValue> {
    if raw.len() != n * 68 {
        return Err(JsValue::from_str("invalid commitments length"));
    }
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let rec = &raw[i * 68..(i + 1) * 68];
        let mut hiding = [0u8; 32];
        let mut binding = [0u8; 32];
        hiding.copy_from_slice(&rec[4..36]);
        binding.copy_from_slice(&rec[36..68]);
        out.push(fed::Commitment {
            id: rd32(&rec[..4]),
            hiding,
            binding,
        });
    }
    Ok(out)
}

fn parse_ed_factors(raw: &[u8], n: usize) -> Result<Vec<(u32, [u8; 32])>, JsValue> {
    if raw.len() != n * 36 {
        return Err(JsValue::from_str("invalid factors length"));
    }
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let rec = &raw[i * 36..(i + 1) * 36];
        let mut rho = [0u8; 32];
        rho.copy_from_slice(&rec[4..36]);
        out.push((rd32(&rec[..4]), rho));
    }
    Ok(out)
}

fn parse_shares_k1(raw: &[u8], n: usize) -> Result<Vec<fk1::KeyShare>, JsValue> {
    if raw.len() != n * 36 {
        return Err(JsValue::from_str("invalid shares length"));
    }
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let rec = &raw[i * 36..(i + 1) * 36];
        let mut share = [0u8; 32];
        share.copy_from_slice(&rec[4..36]);
        out.push(fk1::KeyShare {
            id: rd32(&rec[..4]),
            share,
        });
    }
    Ok(out)
}

fn parse_shares_ed(raw: &[u8], n: usize) -> Result<Vec<fed::KeyShare>, JsValue> {
    if raw.len() != n * 36 {
        return Err(JsValue::from_str("invalid shares length"));
    }
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let rec = &raw[i * 36..(i + 1) * 36];
        let mut share = [0u8; 32];
        share.copy_from_slice(&rec[4..36]);
        out.push(fed::KeyShare {
            id: rd32(&rec[..4]),
            share,
        });
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// secp256k1 suite.
// ---------------------------------------------------------------------------

/// Dealer shard → `shares(max*36) ++ poly((1+n_coeffs)*32)`.
#[wasm_bindgen(js_name = frostK1Shard)]
pub fn frost_k1_shard(
    secret: &[u8],
    coeffs: &[u8],
    n_coeffs: u32,
    max: u16,
) -> Result<Vec<u8>, JsValue> {
    let s = arr32(secret)?;
    if coeffs.len() != n_coeffs as usize * 32 {
        return Err(JsValue::from_str("invalid coeffs length"));
    }
    let mut cf = Vec::with_capacity(n_coeffs as usize);
    for i in 0..n_coeffs as usize {
        let mut c = [0u8; 32];
        c.copy_from_slice(&coeffs[i * 32..(i + 1) * 32]);
        cf.push(c);
    }
    let (shares, poly) = fk1::shard(&s, &cf, max).map_err(|_| JsValue::from_str("shard failed"))?;
    let mut out = Vec::with_capacity(shares.len() * 36 + poly.len() * 32);
    for sh in &shares {
        out.extend_from_slice(&sh.id.to_le_bytes());
        out.extend_from_slice(&sh.share);
    }
    for p in &poly {
        out.extend_from_slice(p);
    }
    Ok(out)
}

/// Prepare signing shares → `n*32` rescaled scalars (`threshold 0` = additive).
#[wasm_bindgen(js_name = frostK1PrepareShares)]
pub fn frost_k1_prepare_shares(shares: &[u8], n: u32, threshold: u16) -> Result<Vec<u8>, JsValue> {
    let list = parse_shares_k1(&u8_vec(shares), n as usize)?;
    let ids: Vec<u32> = list.iter().map(|s| s.id).collect();
    let raws: Vec<[u8; 32]> = list.iter().map(|s| s.share).collect();
    let v = fk1::prepare_shares(&ids, &raws, threshold)
        .map_err(|_| JsValue::from_str("prepare failed"))?;
    let mut out = Vec::with_capacity(v.len() * 32);
    for s in &v {
        out.extend_from_slice(s);
    }
    Ok(out)
}

/// Group key from member points (`ids`: `n*4` u32 LE, `pubs`: `n*33`).
#[wasm_bindgen(js_name = frostK1GroupFromMembers)]
pub fn frost_k1_group_from_members(
    ids: &[u8],
    pubs: &[u8],
    n: u32,
    threshold: u16,
) -> Result<Vec<u8>, JsValue> {
    if ids.len() != n as usize * 4 || pubs.len() != n as usize * 33 {
        return Err(JsValue::from_str("invalid members length"));
    }
    let mut id_list = Vec::with_capacity(n as usize);
    let mut pub_list = Vec::with_capacity(n as usize);
    for i in 0..n as usize {
        id_list.push(rd32(&ids[i * 4..(i + 1) * 4]));
        let mut p = [0u8; 33];
        p.copy_from_slice(&pubs[i * 33..(i + 1) * 33]);
        pub_list.push(p);
    }
    let g = fk1::group_from_members(&id_list, &pub_list, threshold)
        .map_err(|_| JsValue::from_str("group failed"))?;
    Ok(u8_vec(&g))
}

/// Combine share records → 32-byte secret.
#[wasm_bindgen(js_name = frostK1Combine)]
pub fn frost_k1_combine(shares: &[u8], n: u32) -> Result<Vec<u8>, JsValue> {
    let raw = u8_vec(shares);
    let list = parse_shares_k1(&raw, n as usize)?;
    let s = fk1::combine(&list).map_err(|_| JsValue::from_str("combine failed"))?;
    Ok(u8_vec(&s))
}

/// Round-1 commit → `hiding(32) ++ binding(32) ++ hc(33) ++ bc(33)` (130 B).
#[wasm_bindgen(js_name = frostK1Commit)]
pub fn frost_k1_commit(
    secret_share: &[u8],
    hiding_rand: &[u8],
    binding_rand: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let n = fk1::commit_with_randomness(&arr32(secret_share)?, &arr32(hiding_rand)?, &arr32(binding_rand)?)
        .map_err(|_| JsValue::from_str("commit failed"))?;
    let mut out = Vec::with_capacity(130);
    out.extend_from_slice(&n.hiding);
    out.extend_from_slice(&n.binding);
    out.extend_from_slice(&n.hiding_commitment);
    out.extend_from_slice(&n.binding_commitment);
    Ok(out)
}

/// Binding factors → `n*36` factor records.
#[wasm_bindgen(js_name = frostK1BindingFactors)]
pub fn frost_k1_binding_factors(
    group_pk: &[u8],
    commitments: &[u8],
    n: u32,
    msg: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let pk = arr33(group_pk)?;
    let list = parse_k1_coms(&u8_vec(commitments), n as usize)?;
    let f = fk1::compute_binding_factors(&pk, &list, &u8_vec(msg))
        .map_err(|_| JsValue::from_str("binding factors failed"))?;
    let mut out = Vec::with_capacity(f.len() * 36);
    for (id, rho) in &f {
        out.extend_from_slice(&id.to_le_bytes());
        out.extend_from_slice(rho);
    }
    Ok(out)
}

/// Group commitment → 33-byte `R`.
#[wasm_bindgen(js_name = frostK1GroupCommitment)]
pub fn frost_k1_group_commitment(commitments: &[u8], factors: &[u8], n: u32) -> Result<Vec<u8>, JsValue> {
    let list = parse_k1_coms(&u8_vec(commitments), n as usize)?;
    let fac = parse_k1_factors(&u8_vec(factors), n as usize)?;
    let r = fk1::compute_group_commitment(&list, &fac)
        .map_err(|_| JsValue::from_str("group commitment failed"))?;
    Ok(u8_vec(&r))
}

/// Round-2 sign → 32-byte share. Nonces passed as the 130-byte commit blob.
#[wasm_bindgen(js_name = frostK1Sign)]
pub fn frost_k1_sign(
    id: u32,
    secret_share: &[u8],
    group_pk: &[u8],
    nonces130: &[u8],
    commitments: &[u8],
    n: u32,
    msg: &[u8],
) -> Result<Vec<u8>, JsValue> {
    if nonces130.len() != 130 {
        return Err(JsValue::from_str("invalid nonces length"));
    }
    let mut h = [0u8; 32];
    let mut b = [0u8; 32];
    let mut hc = [0u8; 33];
    let mut bc = [0u8; 33];
    h.copy_from_slice(&nonces130[..32]);
    b.copy_from_slice(&nonces130[32..64]);
    hc.copy_from_slice(&nonces130[64..97]);
    bc.copy_from_slice(&nonces130[97..130]);
    let nonces = fk1::NoncePair {
        hiding: h,
        binding: b,
        hiding_commitment: hc,
        binding_commitment: bc,
    };
    let list = parse_k1_coms(&u8_vec(commitments), n as usize)?;
    let s = fk1::sign(id, &arr32(secret_share)?, &arr33(group_pk)?, &nonces, &u8_vec(msg), &list)
        .map_err(|_| JsValue::from_str("sign failed"))?;
    Ok(u8_vec(&s))
}

/// Aggregate → `R(33) ++ z(32)` (65 B).
#[wasm_bindgen(js_name = frostK1Aggregate)]
pub fn frost_k1_aggregate(
    commitments: &[u8],
    n: u32,
    msg: &[u8],
    group_pk: &[u8],
    shares: &[u8],
    n_shares: u32,
) -> Result<Vec<u8>, JsValue> {
    let list = parse_k1_coms(&u8_vec(commitments), n as usize)?;
    let raw = u8_vec(shares);
    if raw.len() != n_shares as usize * 32 {
        return Err(JsValue::from_str("invalid shares length"));
    }
    let mut sh = Vec::with_capacity(n_shares as usize);
    for i in 0..n_shares as usize {
        let mut x = [0u8; 32];
        x.copy_from_slice(&raw[i * 32..(i + 1) * 32]);
        sh.push(x);
    }
    let (r, z) = fk1::aggregate(&list, &u8_vec(msg), &arr33(group_pk)?, &sh)
        .map_err(|_| JsValue::from_str("aggregate failed"))?;
    let mut out = Vec::with_capacity(65);
    out.extend_from_slice(&r);
    out.extend_from_slice(&z);
    Ok(out)
}

/// Verify one share; false on bad share or bad inputs.
#[wasm_bindgen(js_name = frostK1VerifyShare)]
pub fn frost_k1_verify_share(
    id: u32,
    pk_share: &[u8],
    comm68: &[u8],
    share: &[u8],
    commitments: &[u8],
    n: u32,
    group_pk: &[u8],
    msg: &[u8],
) -> bool {
    let Ok(ps) = arr33(pk_share) else {
        return false;
    };
    let Ok(pk) = arr33(group_pk) else {
        return false;
    };
    let Ok(sh) = arr32(share) else {
        return false;
    };
    if comm68.len() != 70 {
        return false;
    }
    if rd32(&comm68[..4]) != id {
        return false;
    }
    let mut hc = [0u8; 33];
    let mut bc = [0u8; 33];
    hc.copy_from_slice(&comm68[4..37]);
    bc.copy_from_slice(&comm68[37..70]);
    let c = fk1::Commitment {
        id,
        hiding: hc,
        binding: bc,
    };
    let Ok(list) = parse_k1_coms(&u8_vec(commitments), n as usize) else {
        return false;
    };
    fk1::verify_share(id, &ps, &c, &sh, &list, &pk, &u8_vec(msg)).unwrap_or(false)
}

/// Verify final signature (65 B); false on bad lengths or invalid sig.
#[wasm_bindgen(js_name = frostK1Verify)]
pub fn frost_k1_verify_js(sig: &[u8], group_pk: &[u8], msg: &[u8]) -> bool {
    if sig.len() != 65 || group_pk.len() != 33 {
        return false;
    }
    let mut r = [0u8; 33];
    let mut z = [0u8; 32];
    let mut pk = [0u8; 33];
    r.copy_from_slice(&sig[..33]);
    z.copy_from_slice(&sig[33..65]);
    pk.copy_from_slice(group_pk);
    fk1::verify_signature(&r, &z, &pk, &u8_vec(msg))
}

/// Reshare over independent secrets → `shares(n*32) ++ pubs(n*33) ++ group(33)`.
/// `ids`: `n*4` u32 LE, `secrets`: `n*32`, `coeffs`: `n_coeffs*32`
/// (expect `n*(threshold-1)` row-major).
#[wasm_bindgen(js_name = frostK1Reshare)]
pub fn frost_k1_reshare(
    ids: &[u8],
    secrets: &[u8],
    n: u32,
    coeffs: &[u8],
    n_coeffs: u32,
    threshold: u16,
) -> Result<Vec<u8>, JsValue> {
    let n = n as usize;
    if n < 2 {
        return Err(JsValue::from_str("invalid n"));
    }
    if threshold < 2 || (threshold as usize) > n {
        return Err(JsValue::from_str("invalid threshold"));
    }
    if ids.len() != n * 4 || secrets.len() != n * 32 || coeffs.len() != n_coeffs as usize * 32 {
        return Err(JsValue::from_str("invalid reshare length"));
    }
    if n_coeffs as usize != n * (threshold as usize - 1) {
        return Err(JsValue::from_str("invalid coeffs length"));
    }
    let mut id_list = Vec::with_capacity(n);
    let mut sec_list = Vec::with_capacity(n);
    let mut cf_list = Vec::with_capacity(n_coeffs as usize);
    for i in 0..n {
        id_list.push(rd32(&ids[i * 4..(i + 1) * 4]));
        let mut s = [0u8; 32];
        s.copy_from_slice(&secrets[i * 32..(i + 1) * 32]);
        sec_list.push(s);
    }
    for i in 0..n_coeffs as usize {
        let mut c = [0u8; 32];
        c.copy_from_slice(&coeffs[i * 32..(i + 1) * 32]);
        cf_list.push(c);
    }
    let (shares, pubs, group) = fk1::reshare(&id_list, &sec_list, &cf_list, threshold)
        .map_err(|_| JsValue::from_str("reshare failed"))?;
    let mut out = Vec::with_capacity(n * 32 + n * 33 + 33);
    for s in &shares {
        out.extend_from_slice(s);
    }
    for p in &pubs {
        out.extend_from_slice(p);
    }
    out.extend_from_slice(&group);
    Ok(out)
}

/// VSS commitment → `n_coeffs*33` points.
#[wasm_bindgen(js_name = frostK1VssCommit)]
pub fn frost_k1_vss_commit(coeffs: &[u8], n_coeffs: u32) -> Result<Vec<u8>, JsValue> {
    if coeffs.len() != n_coeffs as usize * 32 {
        return Err(JsValue::from_str("invalid coeffs length"));
    }
    let mut cf = Vec::with_capacity(n_coeffs as usize);
    for i in 0..n_coeffs as usize {
        let mut c = [0u8; 32];
        c.copy_from_slice(&coeffs[i * 32..(i + 1) * 32]);
        cf.push(c);
    }
    let v = fk1::vss_commit(&cf).map_err(|_| JsValue::from_str("vss_commit failed"))?;
    let mut out = Vec::with_capacity(v.len() * 33);
    for p in &v {
        out.extend_from_slice(p);
    }
    Ok(out)
}

/// VSS verify → bool.
#[wasm_bindgen(js_name = frostK1VssVerify)]
pub fn frost_k1_vss_verify_js(id: u32, share: &[u8], commitment: &[u8], n_comms: u32) -> bool {
    let Ok(sh) = arr32(share) else {
        return false;
    };
    if commitment.len() != n_comms as usize * 33 || n_comms == 0 {
        return false;
    }
    let mut com = Vec::with_capacity(n_comms as usize);
    for i in 0..n_comms as usize {
        let mut c = [0u8; 33];
        c.copy_from_slice(&commitment[i * 33..(i + 1) * 33]);
        com.push(c);
    }
    fk1::vss_verify(&fk1::KeyShare { id, share: sh }, &com).unwrap_or(false)
}

/// Group info: `vss(n_comms*33)` + max → `group(33) ++ pks(max*33)`.
#[wasm_bindgen(js_name = frostK1GroupInfo)]
pub fn frost_k1_group_info(vss: &[u8], n_comms: u32, max: u16) -> Result<Vec<u8>, JsValue> {
    if vss.len() != n_comms as usize * 33 || n_comms == 0 || max == 0 {
        return Err(JsValue::from_str("invalid vss length"));
    }
    let mut com = Vec::with_capacity(n_comms as usize);
    for i in 0..n_comms as usize {
        let mut c = [0u8; 33];
        c.copy_from_slice(&vss[i * 33..(i + 1) * 33]);
        com.push(c);
    }
    let (g, pks) =
        fk1::group_info(max, &com).map_err(|_| JsValue::from_str("group_info failed"))?;
    let mut out = Vec::with_capacity(33 + pks.len() * 33);
    out.extend_from_slice(&g);
    for p in &pks {
        out.extend_from_slice(p);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Ed25519 suite.
// ---------------------------------------------------------------------------

/// Dealer shard → `shares(max*36) ++ poly((1+n_coeffs)*32)`.
/// `is_scalar`: true = canonical scalars, false = RFC 8032 seeds.
#[wasm_bindgen(js_name = frostEdShard)]
pub fn frost_ed_shard(
    secret: &[u8],
    coeffs: &[u8],
    n_coeffs: u32,
    max: u16,
    is_scalar: bool,
) -> Result<Vec<u8>, JsValue> {
    let s_raw = arr32(secret)?;
    let s = fed::secret_to_scalar_bytes(&s_raw, is_scalar as u8)
        .map_err(|_| JsValue::from_str("invalid secret"))?;
    if coeffs.len() != n_coeffs as usize * 32 {
        return Err(JsValue::from_str("invalid coeffs length"));
    }
    let mut cf = Vec::with_capacity(n_coeffs as usize);
    for i in 0..n_coeffs as usize {
        let mut c = [0u8; 32];
        c.copy_from_slice(&coeffs[i * 32..(i + 1) * 32]);
        cf.push(
            fed::secret_to_scalar_bytes(&c, is_scalar as u8)
                .map_err(|_| JsValue::from_str("invalid coeff"))?,
        );
    }
    let (shares, poly) = fed::shard(&s, &cf, max).map_err(|_| JsValue::from_str("shard failed"))?;
    let mut out = Vec::with_capacity(shares.len() * 36 + poly.len() * 32);
    for sh in &shares {
        out.extend_from_slice(&sh.id.to_le_bytes());
        out.extend_from_slice(&sh.share);
    }
    for p in &poly {
        out.extend_from_slice(p);
    }
    Ok(out)
}

/// Prepare signing shares → `n*32` rescaled scalars.
/// `is_scalar`: true = canonical scalars, false = RFC 8032 seeds.
#[wasm_bindgen(js_name = frostEdPrepareShares)]
pub fn frost_ed_prepare_shares(
    shares: &[u8],
    n: u32,
    threshold: u16,
    is_scalar: bool,
) -> Result<Vec<u8>, JsValue> {
    let list = parse_shares_ed(&u8_vec(shares), n as usize)?;
    let ids: Vec<u32> = list.iter().map(|s| s.id).collect();
    let raws: Vec<[u8; 32]> = list.iter().map(|s| s.share).collect();
    let v = fed::prepare_shares(&ids, &raws, threshold, is_scalar as u8)
        .map_err(|_| JsValue::from_str("prepare failed"))?;
    let mut out = Vec::with_capacity(v.len() * 32);
    for s in &v {
        out.extend_from_slice(s);
    }
    Ok(out)
}

/// Group key from member points (`ids`: `n*4` u32 LE, `pubs`: `n*32`).
#[wasm_bindgen(js_name = frostEdGroupFromMembers)]
pub fn frost_ed_group_from_members(
    ids: &[u8],
    pubs: &[u8],
    n: u32,
    threshold: u16,
) -> Result<Vec<u8>, JsValue> {
    if ids.len() != n as usize * 4 || pubs.len() != n as usize * 32 {
        return Err(JsValue::from_str("invalid members length"));
    }
    let mut id_list = Vec::with_capacity(n as usize);
    let mut pub_list = Vec::with_capacity(n as usize);
    for i in 0..n as usize {
        id_list.push(rd32(&ids[i * 4..(i + 1) * 4]));
        let mut p = [0u8; 32];
        p.copy_from_slice(&pubs[i * 32..(i + 1) * 32]);
        pub_list.push(p);
    }
    let g = fed::group_from_members(&id_list, &pub_list, threshold)
        .map_err(|_| JsValue::from_str("group failed"))?;
    Ok(u8_vec(&g))
}

/// Combine share records → 32-byte secret.
/// `is_scalar`: true = scalars, false = seeds.
#[wasm_bindgen(js_name = frostEdCombine)]
pub fn frost_ed_combine(shares: &[u8], n: u32, is_scalar: bool) -> Result<Vec<u8>, JsValue> {
    let raw = u8_vec(shares);
    let list_in = parse_shares_ed(&raw, n as usize)?;
    let mut list = Vec::with_capacity(list_in.len());
    for sh in &list_in {
        let share = fed::secret_to_scalar_bytes(&sh.share, is_scalar as u8)
            .map_err(|_| JsValue::from_str("invalid share"))?;
        list.push(fed::KeyShare { id: sh.id, share });
    }
    let s = fed::combine(&list).map_err(|_| JsValue::from_str("combine failed"))?;
    Ok(u8_vec(&s))
}

/// Round-1 commit → `hiding(32) ++ binding(32) ++ hc(32) ++ bc(32)` (128 B).
/// `is_scalar`: true = `secret_share` is a scalar, false = seed.
#[wasm_bindgen(js_name = frostEdCommit)]
pub fn frost_ed_commit(
    secret_share: &[u8],
    hiding_rand: &[u8],
    binding_rand: &[u8],
    is_scalar: bool,
) -> Result<Vec<u8>, JsValue> {
    let ss_raw = arr32(secret_share)?;
    let ss = fed::secret_to_scalar_bytes(&ss_raw, is_scalar as u8)
        .map_err(|_| JsValue::from_str("invalid secret share"))?;
    let n = fed::commit_with_randomness(&ss, &arr32(hiding_rand)?, &arr32(binding_rand)?)
        .map_err(|_| JsValue::from_str("commit failed"))?;
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(&n.hiding);
    out.extend_from_slice(&n.binding);
    out.extend_from_slice(&n.hiding_commitment);
    out.extend_from_slice(&n.binding_commitment);
    Ok(out)
}

/// Binding factors → `n*36` factor records.
#[wasm_bindgen(js_name = frostEdBindingFactors)]
pub fn frost_ed_binding_factors(
    group_pk: &[u8],
    commitments: &[u8],
    n: u32,
    msg: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let pk = arr32(group_pk)?;
    let list = parse_ed_coms(&u8_vec(commitments), n as usize)?;
    let f = fed::compute_binding_factors(&pk, &list, &u8_vec(msg))
        .map_err(|_| JsValue::from_str("binding factors failed"))?;
    let mut out = Vec::with_capacity(f.len() * 36);
    for (id, rho) in &f {
        out.extend_from_slice(&id.to_le_bytes());
        out.extend_from_slice(rho);
    }
    Ok(out)
}

/// Group commitment → 32-byte `R`.
#[wasm_bindgen(js_name = frostEdGroupCommitment)]
pub fn frost_ed_group_commitment(commitments: &[u8], factors: &[u8], n: u32) -> Result<Vec<u8>, JsValue> {
    let list = parse_ed_coms(&u8_vec(commitments), n as usize)?;
    let fac = parse_ed_factors(&u8_vec(factors), n as usize)?;
    let r = fed::compute_group_commitment(&list, &fac)
        .map_err(|_| JsValue::from_str("group commitment failed"))?;
    Ok(u8_vec(&r))
}

/// Round-2 sign → 32-byte share. Nonces passed as the 128-byte commit blob.
/// `is_scalar`: true = `secret_share` is a scalar, false = seed.
#[wasm_bindgen(js_name = frostEdSign)]
pub fn frost_ed_sign(
    id: u32,
    secret_share: &[u8],
    group_pk: &[u8],
    nonces128: &[u8],
    commitments: &[u8],
    n: u32,
    msg: &[u8],
    is_scalar: bool,
) -> Result<Vec<u8>, JsValue> {
    if nonces128.len() != 128 {
        return Err(JsValue::from_str("invalid nonces length"));
    }
    let mut h = [0u8; 32];
    let mut b = [0u8; 32];
    let mut hc = [0u8; 32];
    let mut bc = [0u8; 32];
    h.copy_from_slice(&nonces128[..32]);
    b.copy_from_slice(&nonces128[32..64]);
    hc.copy_from_slice(&nonces128[64..96]);
    bc.copy_from_slice(&nonces128[96..128]);
    let nonces = fed::NoncePair {
        hiding: h,
        binding: b,
        hiding_commitment: hc,
        binding_commitment: bc,
    };
    let list = parse_ed_coms(&u8_vec(commitments), n as usize)?;
    let ss_raw = arr32(secret_share)?;
    let ss = fed::secret_to_scalar_bytes(&ss_raw, is_scalar as u8)
        .map_err(|_| JsValue::from_str("invalid secret share"))?;
    let s = fed::sign(id, &ss, &arr32(group_pk)?, &nonces, &u8_vec(msg), &list)
        .map_err(|_| JsValue::from_str("sign failed"))?;
    Ok(u8_vec(&s))
}

/// Aggregate → `R(32) ++ z(32)` (64 B).
#[wasm_bindgen(js_name = frostEdAggregate)]
pub fn frost_ed_aggregate(
    commitments: &[u8],
    n: u32,
    msg: &[u8],
    group_pk: &[u8],
    shares: &[u8],
    n_shares: u32,
) -> Result<Vec<u8>, JsValue> {
    let list = parse_ed_coms(&u8_vec(commitments), n as usize)?;
    let raw = u8_vec(shares);
    if raw.len() != n_shares as usize * 32 {
        return Err(JsValue::from_str("invalid shares length"));
    }
    let mut sh = Vec::with_capacity(n_shares as usize);
    for i in 0..n_shares as usize {
        let mut x = [0u8; 32];
        x.copy_from_slice(&raw[i * 32..(i + 1) * 32]);
        sh.push(x);
    }
    let (r, z) = fed::aggregate(&list, &u8_vec(msg), &arr32(group_pk)?, &sh)
        .map_err(|_| JsValue::from_str("aggregate failed"))?;
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&r);
    out.extend_from_slice(&z);
    Ok(out)
}

/// Verify one share; false on bad share or bad inputs.
#[wasm_bindgen(js_name = frostEdVerifyShare)]
pub fn frost_ed_verify_share(
    id: u32,
    pk_share: &[u8],
    comm68: &[u8],
    share: &[u8],
    commitments: &[u8],
    n: u32,
    group_pk: &[u8],
    msg: &[u8],
) -> bool {
    let Ok(ps) = arr32(pk_share) else {
        return false;
    };
    let Ok(pk) = arr32(group_pk) else {
        return false;
    };
    let Ok(sh) = arr32(share) else {
        return false;
    };
    if comm68.len() != 68 {
        return false;
    }
    if rd32(&comm68[..4]) != id {
        return false;
    }
    let mut hc = [0u8; 32];
    let mut bc = [0u8; 32];
    hc.copy_from_slice(&comm68[4..36]);
    bc.copy_from_slice(&comm68[36..68]);
    let c = fed::Commitment {
        id,
        hiding: hc,
        binding: bc,
    };
    let Ok(list) = parse_ed_coms(&u8_vec(commitments), n as usize) else {
        return false;
    };
    fed::verify_share(id, &ps, &c, &sh, &list, &pk, &u8_vec(msg)).unwrap_or(false)
}

/// Verify final signature (64 B); false on bad lengths or invalid sig.
#[wasm_bindgen(js_name = frostEdVerify)]
pub fn frost_ed_verify_js(sig: &[u8], group_pk: &[u8], msg: &[u8]) -> bool {
    if sig.len() != 64 || group_pk.len() != 32 {
        return false;
    }
    let mut r = [0u8; 32];
    let mut z = [0u8; 32];
    let mut pk = [0u8; 32];
    r.copy_from_slice(&sig[..32]);
    z.copy_from_slice(&sig[32..64]);
    pk.copy_from_slice(group_pk);
    fed::verify_signature(&r, &z, &pk, &u8_vec(msg))
}

/// Reshare over independent seeds → `shares(n*32) ++ pubs(n*32) ++ group(32)`.
/// `ids`: `n*4` u32 LE, `secrets`: `n*32` seeds, `coeffs`: `n_coeffs*32`
/// seeds (expect `n*(threshold-1)` row-major). Seeds are expanded here
/// at the boundary (`secret_to_scalar_bytes(x, 0)`); the core
/// `fed::reshare` takes canonical scalars only and never hashes.
#[wasm_bindgen(js_name = frostEdReshare)]
pub fn frost_ed_reshare(
    ids: &[u8],
    secrets: &[u8],
    n: u32,
    coeffs: &[u8],
    n_coeffs: u32,
    threshold: u16,
) -> Result<Vec<u8>, JsValue> {
    let n = n as usize;
    if n < 2 {
        return Err(JsValue::from_str("invalid n"));
    }
    if threshold < 2 || (threshold as usize) > n {
        return Err(JsValue::from_str("invalid threshold"));
    }
    if ids.len() != n * 4 || secrets.len() != n * 32 || coeffs.len() != n_coeffs as usize * 32 {
        return Err(JsValue::from_str("invalid reshare length"));
    }
    if n_coeffs as usize != n * (threshold as usize - 1) {
        return Err(JsValue::from_str("invalid coeffs length"));
    }
    let mut id_list = Vec::with_capacity(n);
    let mut sec_list = Vec::with_capacity(n);
    let mut cf_list = Vec::with_capacity(n_coeffs as usize);
    for i in 0..n {
        id_list.push(rd32(&ids[i * 4..(i + 1) * 4]));
        let mut s = [0u8; 32];
        s.copy_from_slice(&secrets[i * 32..(i + 1) * 32]);
        // Seeds are expanded here; `fed::reshare` takes scalars only.
        sec_list.push(
            fed::secret_to_scalar_bytes(&s, 0).map_err(|_| JsValue::from_str("invalid secret seed"))?,
        );
    }
    for i in 0..n_coeffs as usize {
        let mut c = [0u8; 32];
        c.copy_from_slice(&coeffs[i * 32..(i + 1) * 32]);
        cf_list.push(
            fed::secret_to_scalar_bytes(&c, 0).map_err(|_| JsValue::from_str("invalid coeff seed"))?,
        );
    }
    let (shares, pubs, group) = fed::reshare(&id_list, &sec_list, &cf_list, threshold)
        .map_err(|_| JsValue::from_str("reshare failed"))?;
    let mut out = Vec::with_capacity(n * 32 + n * 32 + 32);
    for s in &shares {
        out.extend_from_slice(s);
    }
    for p in &pubs {
        out.extend_from_slice(p);
    }
    out.extend_from_slice(&group);
    Ok(out)
}

/// VSS commitment → `n_coeffs*32` points.
/// `is_scalar`: true = coeffs are scalars, false = seeds.
#[wasm_bindgen(js_name = frostEdVssCommit)]
pub fn frost_ed_vss_commit(coeffs: &[u8], n_coeffs: u32, is_scalar: bool) -> Result<Vec<u8>, JsValue> {
    if coeffs.len() != n_coeffs as usize * 32 {
        return Err(JsValue::from_str("invalid coeffs length"));
    }
    let mut cf = Vec::with_capacity(n_coeffs as usize);
    for i in 0..n_coeffs as usize {
        let mut c = [0u8; 32];
        c.copy_from_slice(&coeffs[i * 32..(i + 1) * 32]);
        cf.push(
            fed::secret_to_scalar_bytes(&c, is_scalar as u8)
                .map_err(|_| JsValue::from_str("invalid coeff"))?,
        );
    }
    let v = fed::vss_commit(&cf).map_err(|_| JsValue::from_str("vss_commit failed"))?;
    let mut out = Vec::with_capacity(v.len() * 32);
    for p in &v {
        out.extend_from_slice(p);
    }
    Ok(out)
}

/// VSS verify → bool.
/// `is_scalar`: true = share is a scalar, false = seed.
#[wasm_bindgen(js_name = frostEdVssVerify)]
pub fn frost_ed_vss_verify_js(id: u32, share: &[u8], commitment: &[u8], n_comms: u32, is_scalar: bool) -> bool {
    let Ok(sh_raw) = arr32(share) else {
        return false;
    };
    let Ok(sh) = fed::secret_to_scalar_bytes(&sh_raw, is_scalar as u8) else {
        return false;
    };
    if commitment.len() != n_comms as usize * 32 || n_comms == 0 {
        return false;
    }
    let mut com = Vec::with_capacity(n_comms as usize);
    for i in 0..n_comms as usize {
        let mut c = [0u8; 32];
        c.copy_from_slice(&commitment[i * 32..(i + 1) * 32]);
        com.push(c);
    }
    fed::vss_verify(&fed::KeyShare { id, share: sh }, &com).unwrap_or(false)
}

/// Group info: `vss(n_comms*32)` + max → `group(32) ++ pks(max*32)`.
#[wasm_bindgen(js_name = frostEdGroupInfo)]
pub fn frost_ed_group_info(vss: &[u8], n_comms: u32, max: u16) -> Result<Vec<u8>, JsValue> {
    if vss.len() != n_comms as usize * 32 || n_comms == 0 || max == 0 {
        return Err(JsValue::from_str("invalid vss length"));
    }
    let mut com = Vec::with_capacity(n_comms as usize);
    for i in 0..n_comms as usize {
        let mut c = [0u8; 32];
        c.copy_from_slice(&vss[i * 32..(i + 1) * 32]);
        com.push(c);
    }
    let (g, pks) =
        fed::group_info(max, &com).map_err(|_| JsValue::from_str("group_info failed"))?;
    let mut out = Vec::with_capacity(32 + pks.len() * 32);
    out.extend_from_slice(&g);
    for p in &pks {
        out.extend_from_slice(p);
    }
    Ok(out)
}
