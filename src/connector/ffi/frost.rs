//! FFI for RFC 9591 FROST (requires `alloc` + `ffi`).
//!
//! Two ciphersuites: `k1` = FROST(secp256k1, SHA-256), `ed` =
//! FROST(Ed25519, SHA-512). Layouts are fixed-size blobs so callers can
//! pass them without extra translation:
//!
//! - scalars / secret shares: 32 bytes
//! - Ed secret inputs (`shard` secret+coeffs, `combine` shares,
//!   `commit`/`sign` secret_share, `vss_commit` coeffs, `vss_verify`
//!   share) take a trailing `is_scalar: u8`: `!= 0` = canonical scalar
//!   bytes, `0` = RFC 8032 seed expanded via SHA-512 + clamp.
//!   k1 inputs are always scalars (key bytes ARE the scalar).
//! - k1 points: 33 bytes (SEC1 compressed); ed points: 32 bytes
//! - commitment record k1: `[id:u32 LE][hiding:33][binding:33]` (70 B)
//! - commitment record ed: `[id:u32 LE][hiding:32][binding:32]` (68 B)
//! - binding-factor record: `[id:u32 LE][rho:32]` (36 B)
//! - key-share record: `[id:u32 LE][share:32]` (36 B)
//! - final signature k1: `R(33) || z(32)` (65 B); ed: 64 B

#![cfg(all(feature = "ffi", feature = "alloc"))]

use core::slice;

use crate::frost::{ed as fed, k1 as fk1, FrostError};

pub const BU_FROST_OK: i32 = 0;
pub const BU_FROST_ERR: i32 = 1;
pub const BU_FROST_ERR_LEN: i32 = 2;
pub const BU_FROST_ERR_KEY: i32 = 3;
pub const BU_FROST_ERR_VERIFY: i32 = 4;

fn map_err(e: FrostError) -> i32 {
    use FrostError::*;
    match e {
        InvalidLength | TooFewShares => BU_FROST_ERR_LEN,
        InvalidScalar | InvalidKey | InvalidNonce | InvalidCommitment | IdentityCommitment => {
            BU_FROST_ERR_KEY
        }
        InvalidParticipant => BU_FROST_ERR_KEY,
        Internal => BU_FROST_ERR,
    }
}

fn read_u32_le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

// ---------------------------------------------------------------------------
// secp256k1 suite.
// ---------------------------------------------------------------------------

const K1_REC: usize = 4 + 33 + 33;

fn parse_k1_commitments(ptr: *const u8, n: usize) -> Result<alloc::vec::Vec<fk1::Commitment>, i32> {
    if ptr.is_null() || n == 0 {
        return Err(BU_FROST_ERR_LEN);
    }
    let raw = unsafe { slice::from_raw_parts(ptr, n * K1_REC) };
    let mut out = alloc::vec::Vec::with_capacity(n);
    for i in 0..n {
        let rec = &raw[i * K1_REC..(i + 1) * K1_REC];
        let mut hiding = [0u8; 33];
        let mut binding = [0u8; 33];
        hiding.copy_from_slice(&rec[4..37]);
        binding.copy_from_slice(&rec[37..70]);
        out.push(fk1::Commitment {
            id: read_u32_le(&rec[..4]),
            hiding,
            binding,
        });
    }
    Ok(out)
}

fn parse_k1_factors(ptr: *const u8, n: usize) -> Result<alloc::vec::Vec<(u32, [u8; 32])>, i32> {
    if ptr.is_null() || n == 0 {
        return Err(BU_FROST_ERR_LEN);
    }
    let raw = unsafe { slice::from_raw_parts(ptr, n * 36) };
    let mut out = alloc::vec::Vec::with_capacity(n);
    for i in 0..n {
        let rec = &raw[i * 36..(i + 1) * 36];
        let mut rho = [0u8; 32];
        rho.copy_from_slice(&rec[4..36]);
        out.push((read_u32_le(&rec[..4]), rho));
    }
    Ok(out)
}

/// Dealer shard: `secret(32)`, `coeffs(n_coeffs*32)`, ids `1..=max`.
/// Writes `max` share records (36 B each) and `(1+n_coeffs)*32` poly bytes.
#[no_mangle]
/// # Safety
/// Pointers must reference readable/writable memory of the documented
/// lengths. Null pointers are rejected; short buffers are the caller's
/// responsibility.
pub unsafe extern "C" fn bu_frost_k1_shard(
    secret: *const u8,
    coeffs: *const u8,
    n_coeffs: usize,
    max: u16,
    shares_out: *mut u8,
    shares_len: usize,
    poly_out: *mut u8,
    poly_len: usize,
) -> i32 {
    if secret.is_null() || shares_out.is_null() || poly_out.is_null() || max == 0 {
        return BU_FROST_ERR_LEN;
    }
    if n_coeffs > 0 && coeffs.is_null() {
        return BU_FROST_ERR_LEN;
    }
    if shares_len < max as usize * 36 || poly_len < (1 + n_coeffs) * 32 {
        return BU_FROST_ERR_LEN;
    }
    let s = slice::from_raw_parts(secret, 32);
    let mut sec = [0u8; 32];
    sec.copy_from_slice(s);
    let mut cf = alloc::vec::Vec::with_capacity(n_coeffs);
    if n_coeffs > 0 {
        let raw = slice::from_raw_parts(coeffs, n_coeffs * 32);
        for i in 0..n_coeffs {
            let mut c = [0u8; 32];
            c.copy_from_slice(&raw[i * 32..(i + 1) * 32]);
            cf.push(c);
        }
    }
    match fk1::shard(&sec, &cf, max) {
        Ok((shares, poly)) => {
            let so = slice::from_raw_parts_mut(shares_out, max as usize * 36);
            for (i, sh) in shares.iter().enumerate() {
                so[i * 36..i * 36 + 4].copy_from_slice(&sh.id.to_le_bytes());
                so[i * 36 + 4..(i + 1) * 36].copy_from_slice(&sh.share);
            }
            let po = slice::from_raw_parts_mut(poly_out, (1 + n_coeffs) * 32);
            for (i, p) in poly.iter().enumerate() {
                po[i * 32..(i + 1) * 32].copy_from_slice(p);
            }
            BU_FROST_OK
        }
        Err(e) => map_err(e),
    }
}

/// Combine share records (`n` x 36 B) → secret (32 B).
#[no_mangle]
/// # Safety
/// Pointers must reference readable/writable memory of the documented lengths.
pub unsafe extern "C" fn bu_frost_k1_combine(
    shares: *const u8,
    n: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if shares.is_null() || out.is_null() || n == 0 || out_len < 32 {
        return BU_FROST_ERR_LEN;
    }
    let raw = slice::from_raw_parts(shares, n * 36);
    let mut list = alloc::vec::Vec::with_capacity(n);
    for i in 0..n {
        let rec = &raw[i * 36..(i + 1) * 36];
        let mut share = [0u8; 32];
        share.copy_from_slice(&rec[4..36]);
        list.push(fk1::KeyShare {
            id: read_u32_le(&rec[..4]),
            share,
        });
    }
    match fk1::combine(&list) {
        Ok(s) => {
            slice::from_raw_parts_mut(out, 32).copy_from_slice(&s);
            BU_FROST_OK
        }
        Err(e) => map_err(e),
    }
}

/// Prepare signing shares: `shares` (`n` x 36 B `[id:u32][share:32]`),
/// `threshold` (`0` = additive full-set rescale, else Shamir passthrough)
/// → `out` (`n` x 32 B rescaled scalars). Secrets stay scalars end to end.
#[no_mangle]
/// # Safety
/// Pointers must reference readable/writable memory of the documented lengths.
pub unsafe extern "C" fn bu_frost_k1_prepare_shares(
    shares: *const u8,
    n: usize,
    threshold: u16,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if shares.is_null() || out.is_null() || n == 0 || out_len < n * 32 {
        return BU_FROST_ERR_LEN;
    }
    let raw = slice::from_raw_parts(shares, n * 36);
    let mut ids = alloc::vec::Vec::with_capacity(n);
    let mut list = alloc::vec::Vec::with_capacity(n);
    for i in 0..n {
        let rec = &raw[i * 36..(i + 1) * 36];
        let mut share = [0u8; 32];
        share.copy_from_slice(&rec[4..36]);
        ids.push(read_u32_le(&rec[..4]));
        list.push(share);
    }
    match fk1::prepare_shares(&ids, &list, threshold) {
        Ok(v) => {
            let o = slice::from_raw_parts_mut(out, n * 32);
            for (i, s) in v.iter().enumerate() {
                o[i * 32..(i + 1) * 32].copy_from_slice(s);
            }
            BU_FROST_OK
        }
        Err(e) => map_err(e),
    }
}

/// Group key from member points: `ids` (`n` x u32 LE), `pubs` (`n` x 33 B),
/// `threshold` (`0` = additive sum, else Lagrange at zero) → `group` (33 B).
#[no_mangle]
/// # Safety
/// Pointers must reference readable/writable memory of the documented lengths.
pub unsafe extern "C" fn bu_frost_k1_group_from_members(
    ids: *const u8,
    pubs: *const u8,
    n: usize,
    threshold: u16,
    group_out: *mut u8,
    group_len: usize,
) -> i32 {
    if ids.is_null() || pubs.is_null() || group_out.is_null() || n == 0 || group_len < 33 {
        return BU_FROST_ERR_LEN;
    }
    let raw_ids = slice::from_raw_parts(ids, n * 4);
    let raw_pubs = slice::from_raw_parts(pubs, n * 33);
    let mut id_list = alloc::vec::Vec::with_capacity(n);
    let mut pub_list = alloc::vec::Vec::with_capacity(n);
    for i in 0..n {
        id_list.push(read_u32_le(&raw_ids[i * 4..(i + 1) * 4]));
        let mut p = [0u8; 33];
        p.copy_from_slice(&raw_pubs[i * 33..(i + 1) * 33]);
        pub_list.push(p);
    }
    match fk1::group_from_members(&id_list, &pub_list, threshold) {
        Ok(g) => {
            slice::from_raw_parts_mut(group_out, 33).copy_from_slice(&g);
            BU_FROST_OK
        }
        Err(e) => map_err(e),
    }
}

/// Feldman VSS commit: `coeffs(n*32)` → `n*33` bytes.
#[no_mangle]
/// # Safety
/// Pointers must reference readable/writable memory of the documented lengths.
pub unsafe extern "C" fn bu_frost_k1_vss_commit(
    coeffs: *const u8,
    n_coeffs: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if coeffs.is_null() || out.is_null() || n_coeffs == 0 || out_len < n_coeffs * 33 {
        return BU_FROST_ERR_LEN;
    }
    let raw = slice::from_raw_parts(coeffs, n_coeffs * 32);
    let mut cf = alloc::vec::Vec::with_capacity(n_coeffs);
    for i in 0..n_coeffs {
        let mut c = [0u8; 32];
        c.copy_from_slice(&raw[i * 32..(i + 1) * 32]);
        cf.push(c);
    }
    match fk1::vss_commit(&cf) {
        Ok(v) => {
            let o = slice::from_raw_parts_mut(out, n_coeffs * 33);
            for (i, p) in v.iter().enumerate() {
                o[i * 33..(i + 1) * 33].copy_from_slice(p);
            }
            BU_FROST_OK
        }
        Err(e) => map_err(e),
    }
}

/// VSS verify: `id`, `share(32)`, `commitment(n_comms*33)`.
/// Returns OK / VERIFY / error.
#[no_mangle]
/// # Safety
/// Pointers must reference readable/writable memory of the documented lengths.
pub unsafe extern "C" fn bu_frost_k1_vss_verify(
    id: u32,
    share: *const u8,
    commitment: *const u8,
    n_comms: usize,
) -> i32 {
    if share.is_null() || commitment.is_null() || n_comms == 0 {
        return BU_FROST_ERR_LEN;
    }
    let mut sh = [0u8; 32];
    sh.copy_from_slice(slice::from_raw_parts(share, 32));
    let raw = slice::from_raw_parts(commitment, n_comms * 33);
    let mut com = alloc::vec::Vec::with_capacity(n_comms);
    for i in 0..n_comms {
        let mut c = [0u8; 33];
        c.copy_from_slice(&raw[i * 33..(i + 1) * 33]);
        com.push(c);
    }
    match fk1::vss_verify(&fk1::KeyShare { id, share: sh }, &com) {
        Ok(true) => BU_FROST_OK,
        Ok(false) => BU_FROST_ERR_VERIFY,
        Err(e) => map_err(e),
    }
}

/// Group info: `vss(n_comms*33)` → group key (33) + `max*33` member keys.
#[no_mangle]
/// # Safety
/// Pointers must reference readable/writable memory of the documented lengths.
pub unsafe extern "C" fn bu_frost_k1_group_info(
    vss: *const u8,
    n_comms: usize,
    max: u16,
    group_out: *mut u8,
    pks_out: *mut u8,
    pks_len: usize,
) -> i32 {
    if vss.is_null() || group_out.is_null() || pks_out.is_null() || n_comms == 0 || max == 0 {
        return BU_FROST_ERR_LEN;
    }
    if pks_len < max as usize * 33 {
        return BU_FROST_ERR_LEN;
    }
    let raw = slice::from_raw_parts(vss, n_comms * 33);
    let mut com = alloc::vec::Vec::with_capacity(n_comms);
    for i in 0..n_comms {
        let mut c = [0u8; 33];
        c.copy_from_slice(&raw[i * 33..(i + 1) * 33]);
        com.push(c);
    }
    match fk1::group_info(max, &com) {
        Ok((g, pks)) => {
            slice::from_raw_parts_mut(group_out, 33).copy_from_slice(&g);
            let o = slice::from_raw_parts_mut(pks_out, max as usize * 33);
            for (i, p) in pks.iter().enumerate() {
                o[i * 33..(i + 1) * 33].copy_from_slice(p);
            }
            BU_FROST_OK
        }
        Err(e) => map_err(e),
    }
}

/// Round-1 commit. Writes hiding/binding scalars (32+32) and commitments (33+33).
#[no_mangle]
/// # Safety
/// Pointers must reference readable/writable memory of the documented lengths.
pub unsafe extern "C" fn bu_frost_k1_commit(
    secret_share: *const u8,
    hiding_rand: *const u8,
    binding_rand: *const u8,
    hiding_out: *mut u8,
    binding_out: *mut u8,
    hiding_comm_out: *mut u8,
    binding_comm_out: *mut u8,
) -> i32 {
    if secret_share.is_null()
        || hiding_rand.is_null()
        || binding_rand.is_null()
        || hiding_out.is_null()
        || binding_out.is_null()
        || hiding_comm_out.is_null()
        || binding_comm_out.is_null()
    {
        return BU_FROST_ERR_LEN;
    }
    let mut s = [0u8; 32];
    let mut hr = [0u8; 32];
    let mut br = [0u8; 32];
    s.copy_from_slice(slice::from_raw_parts(secret_share, 32));
    hr.copy_from_slice(slice::from_raw_parts(hiding_rand, 32));
    br.copy_from_slice(slice::from_raw_parts(binding_rand, 32));
    match fk1::commit_with_randomness(&s, &hr, &br) {
        Ok(n) => {
            slice::from_raw_parts_mut(hiding_out, 32).copy_from_slice(&n.hiding);
            slice::from_raw_parts_mut(binding_out, 32).copy_from_slice(&n.binding);
            slice::from_raw_parts_mut(hiding_comm_out, 33).copy_from_slice(&n.hiding_commitment);
            slice::from_raw_parts_mut(binding_comm_out, 33).copy_from_slice(&n.binding_commitment);
            BU_FROST_OK
        }
        Err(e) => map_err(e),
    }
}

/// Binding factors: `commitments(n*70)`, `msg` → `n*36` factor records.
#[no_mangle]
/// # Safety
/// Pointers must reference readable/writable memory of the documented lengths.
pub unsafe extern "C" fn bu_frost_k1_binding_factors(
    group_pk: *const u8,
    commitments: *const u8,
    n: usize,
    msg: *const u8,
    msg_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if group_pk.is_null() || out.is_null() || n == 0 || out_len < n * 36 {
        return BU_FROST_ERR_LEN;
    }
    if msg.is_null() && msg_len > 0 {
        return BU_FROST_ERR_LEN;
    }
    let list = match parse_k1_commitments(commitments, n) {
        Ok(l) => l,
        Err(e) => return e,
    };
    let mut pk = [0u8; 33];
    pk.copy_from_slice(slice::from_raw_parts(group_pk, 33));
    let m = if msg_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(msg, msg_len)
    };
    match fk1::compute_binding_factors(&pk, &list, m) {
        Ok(f) => {
            let o = slice::from_raw_parts_mut(out, n * 36);
            for (i, (id, rho)) in f.iter().enumerate() {
                o[i * 36..i * 36 + 4].copy_from_slice(&id.to_le_bytes());
                o[i * 36 + 4..(i + 1) * 36].copy_from_slice(rho);
            }
            BU_FROST_OK
        }
        Err(e) => map_err(e),
    }
}

/// Group commitment: `commitments(n*70)` + `factors(n*36)` → `R(33)`.
#[no_mangle]
/// # Safety
/// Pointers must reference readable/writable memory of the documented lengths.
pub unsafe extern "C" fn bu_frost_k1_group_commitment(
    commitments: *const u8,
    factors: *const u8,
    n: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if out.is_null() || n == 0 || out_len < 33 {
        return BU_FROST_ERR_LEN;
    }
    let list = match parse_k1_commitments(commitments, n) {
        Ok(l) => l,
        Err(e) => return e,
    };
    let fac = match parse_k1_factors(factors, n) {
        Ok(f) => f,
        Err(e) => return e,
    };
    match fk1::compute_group_commitment(&list, &fac) {
        Ok(r) => {
            slice::from_raw_parts_mut(out, 33).copy_from_slice(&r);
            BU_FROST_OK
        }
        Err(e) => map_err(e),
    }
}

/// Round-2 sign: writes 32-byte share.
#[no_mangle]
/// # Safety
/// Pointers must reference readable/writable memory of the documented lengths.
pub unsafe extern "C" fn bu_frost_k1_sign(
    id: u32,
    secret_share: *const u8,
    group_pk: *const u8,
    hiding_nonce: *const u8,
    binding_nonce: *const u8,
    hiding_comm: *const u8,
    binding_comm: *const u8,
    commitments: *const u8,
    n: usize,
    msg: *const u8,
    msg_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if secret_share.is_null()
        || group_pk.is_null()
        || hiding_nonce.is_null()
        || binding_nonce.is_null()
        || hiding_comm.is_null()
        || binding_comm.is_null()
        || out.is_null()
        || n == 0
        || out_len < 32
    {
        return BU_FROST_ERR_LEN;
    }
    if msg.is_null() && msg_len > 0 {
        return BU_FROST_ERR_LEN;
    }
    let list = match parse_k1_commitments(commitments, n) {
        Ok(l) => l,
        Err(e) => return e,
    };
    let mut s = [0u8; 32];
    let mut h = [0u8; 32];
    let mut b = [0u8; 32];
    let mut hc = [0u8; 33];
    let mut bc = [0u8; 33];
    let mut pk = [0u8; 33];
    s.copy_from_slice(slice::from_raw_parts(secret_share, 32));
    h.copy_from_slice(slice::from_raw_parts(hiding_nonce, 32));
    b.copy_from_slice(slice::from_raw_parts(binding_nonce, 32));
    hc.copy_from_slice(slice::from_raw_parts(hiding_comm, 33));
    bc.copy_from_slice(slice::from_raw_parts(binding_comm, 33));
    pk.copy_from_slice(slice::from_raw_parts(group_pk, 33));
    let m = if msg_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(msg, msg_len)
    };
    let nonces = fk1::NoncePair {
        hiding: h,
        binding: b,
        hiding_commitment: hc,
        binding_commitment: bc,
    };
    match fk1::sign(id, &s, &pk, &nonces, m, &list) {
        Ok(share) => {
            slice::from_raw_parts_mut(out, 32).copy_from_slice(&share);
            BU_FROST_OK
        }
        Err(e) => map_err(e),
    }
}

/// Aggregate: `commitments(n*70)`, `shares(n_shares*32)` → `R(33) || z(32)`.
#[no_mangle]
/// # Safety
/// Pointers must reference readable/writable memory of the documented lengths.
pub unsafe extern "C" fn bu_frost_k1_aggregate(
    commitments: *const u8,
    n: usize,
    msg: *const u8,
    msg_len: usize,
    group_pk: *const u8,
    shares: *const u8,
    n_shares: usize,
    r_out: *mut u8,
    z_out: *mut u8,
) -> i32 {
    if shares.is_null() || r_out.is_null() || z_out.is_null() || n == 0 || n_shares == 0 {
        return BU_FROST_ERR_LEN;
    }
    if (msg.is_null() && msg_len > 0) || group_pk.is_null() {
        return BU_FROST_ERR_LEN;
    }
    let list = match parse_k1_commitments(commitments, n) {
        Ok(l) => l,
        Err(e) => return e,
    };
    let mut pk = [0u8; 33];
    pk.copy_from_slice(slice::from_raw_parts(group_pk, 33));
    let m = if msg_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(msg, msg_len)
    };
    let raw = slice::from_raw_parts(shares, n_shares * 32);
    let mut sh = alloc::vec::Vec::with_capacity(n_shares);
    for i in 0..n_shares {
        let mut x = [0u8; 32];
        x.copy_from_slice(&raw[i * 32..(i + 1) * 32]);
        sh.push(x);
    }
    match fk1::aggregate(&list, m, &pk, &sh) {
        Ok((r, z)) => {
            slice::from_raw_parts_mut(r_out, 33).copy_from_slice(&r);
            slice::from_raw_parts_mut(z_out, 32).copy_from_slice(&z);
            BU_FROST_OK
        }
        Err(e) => map_err(e),
    }
}

/// Verify one share. `comm` is a single 70-byte commitment record.
/// Returns OK / VERIFY / error.
#[no_mangle]
/// # Safety
/// Pointers must reference readable/writable memory of the documented lengths.
pub unsafe extern "C" fn bu_frost_k1_verify_share(
    id: u32,
    pk_share: *const u8,
    comm: *const u8,
    share: *const u8,
    commitments: *const u8,
    n: usize,
    group_pk: *const u8,
    msg: *const u8,
    msg_len: usize,
) -> i32 {
    if pk_share.is_null() || comm.is_null() || share.is_null() || group_pk.is_null() || n == 0 {
        return BU_FROST_ERR_LEN;
    }
    if msg.is_null() && msg_len > 0 {
        return BU_FROST_ERR_LEN;
    }
    let list = match parse_k1_commitments(commitments, n) {
        Ok(l) => l,
        Err(e) => return e,
    };
    let mut pk = [0u8; 33];
    let mut ps = [0u8; 33];
    let mut sh = [0u8; 32];
    let mut hc = [0u8; 33];
    let mut bc = [0u8; 33];
    pk.copy_from_slice(slice::from_raw_parts(group_pk, 33));
    ps.copy_from_slice(slice::from_raw_parts(pk_share, 33));
    sh.copy_from_slice(slice::from_raw_parts(share, 32));
    let crec = slice::from_raw_parts(comm, K1_REC);
    if read_u32_le(&crec[..4]) != id {
        return BU_FROST_ERR_KEY;
    }
    hc.copy_from_slice(&crec[4..37]);
    bc.copy_from_slice(&crec[37..70]);
    let m = if msg_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(msg, msg_len)
    };
    let c = fk1::Commitment {
        id,
        hiding: hc,
        binding: bc,
    };
    match fk1::verify_share(id, &ps, &c, &sh, &list, &pk, m) {
        Ok(true) => BU_FROST_OK,
        Ok(false) => BU_FROST_ERR_VERIFY,
        Err(e) => map_err(e),
    }
}

/// Reshare over independent secrets: `ids` (`n` x u32 LE), `secrets`
/// (`n` x 32 B scalars), `coeffs` (`n_coeffs` x 32 B, expect
/// `n*(threshold-1)` row-major) → `shares_out` (`n` x 32 B),
/// `pubs_out` (`n` x 33 B), `group_out` (33 B).
#[no_mangle]
/// # Safety
/// Pointers must reference readable/writable memory of the documented lengths.
pub unsafe extern "C" fn bu_frost_k1_reshare(
    ids: *const u8,
    secrets: *const u8,
    n: usize,
    coeffs: *const u8,
    n_coeffs: usize,
    threshold: u16,
    shares_out: *mut u8,
    shares_len: usize,
    pubs_out: *mut u8,
    pubs_len: usize,
    group_out: *mut u8,
    group_len: usize,
) -> i32 {
    if ids.is_null()
        || secrets.is_null()
        || shares_out.is_null()
        || pubs_out.is_null()
        || group_out.is_null()
        || n < 2
    {
        return BU_FROST_ERR_LEN;
    }
    if threshold < 2 || (threshold as usize) > n {
        return BU_FROST_ERR_LEN;
    }
    if n_coeffs != n * (threshold as usize - 1) {
        return BU_FROST_ERR_LEN;
    }
    if coeffs.is_null() {
        return BU_FROST_ERR_LEN;
    }
    if shares_len < n * 32 || pubs_len < n * 33 || group_len < 33 {
        return BU_FROST_ERR_LEN;
    }
    let raw_ids = slice::from_raw_parts(ids, n * 4);
    let raw_sec = slice::from_raw_parts(secrets, n * 32);
    let raw_cf = slice::from_raw_parts(coeffs, n_coeffs * 32);
    let mut id_list = alloc::vec::Vec::with_capacity(n);
    let mut sec_list = alloc::vec::Vec::with_capacity(n);
    let mut cf_list = alloc::vec::Vec::with_capacity(n_coeffs);
    for i in 0..n {
        id_list.push(read_u32_le(&raw_ids[i * 4..(i + 1) * 4]));
        let mut s = [0u8; 32];
        s.copy_from_slice(&raw_sec[i * 32..(i + 1) * 32]);
        sec_list.push(s);
    }
    for i in 0..n_coeffs {
        let mut c = [0u8; 32];
        c.copy_from_slice(&raw_cf[i * 32..(i + 1) * 32]);
        cf_list.push(c);
    }
    match fk1::reshare(&id_list, &sec_list, &cf_list, threshold) {
        Ok((shares, pubs, group)) => {
            let so = slice::from_raw_parts_mut(shares_out, n * 32);
            for (i, s) in shares.iter().enumerate() {
                so[i * 32..(i + 1) * 32].copy_from_slice(s);
            }
            let po = slice::from_raw_parts_mut(pubs_out, n * 33);
            for (i, p) in pubs.iter().enumerate() {
                po[i * 33..(i + 1) * 33].copy_from_slice(p);
            }
            slice::from_raw_parts_mut(group_out, 33).copy_from_slice(&group);
            BU_FROST_OK
        }
        Err(e) => map_err(e),
    }
}

/// Verify final signature `R(33) || z(32)`. Returns OK / VERIFY.
#[no_mangle]
/// # Safety
/// Pointers must reference readable/writable memory of the documented lengths.
pub unsafe extern "C" fn bu_frost_k1_verify(
    r: *const u8,
    z: *const u8,
    group_pk: *const u8,
    msg: *const u8,
    msg_len: usize,
) -> i32 {
    if r.is_null() || z.is_null() || group_pk.is_null() {
        return BU_FROST_ERR_LEN;
    }
    if msg.is_null() && msg_len > 0 {
        return BU_FROST_ERR_LEN;
    }
    let mut rr = [0u8; 33];
    let mut zz = [0u8; 32];
    let mut pk = [0u8; 33];
    rr.copy_from_slice(slice::from_raw_parts(r, 33));
    zz.copy_from_slice(slice::from_raw_parts(z, 32));
    pk.copy_from_slice(slice::from_raw_parts(group_pk, 33));
    let m = if msg_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(msg, msg_len)
    };
    if fk1::verify_signature(&rr, &zz, &pk, m) {
        BU_FROST_OK
    } else {
        BU_FROST_ERR_VERIFY
    }
}

// ---------------------------------------------------------------------------
// Ed25519 suite.
// ---------------------------------------------------------------------------

const ED_REC: usize = 4 + 32 + 32;

fn parse_ed_commitments(ptr: *const u8, n: usize) -> Result<alloc::vec::Vec<fed::Commitment>, i32> {
    if ptr.is_null() || n == 0 {
        return Err(BU_FROST_ERR_LEN);
    }
    let raw = unsafe { slice::from_raw_parts(ptr, n * ED_REC) };
    let mut out = alloc::vec::Vec::with_capacity(n);
    for i in 0..n {
        let rec = &raw[i * ED_REC..(i + 1) * ED_REC];
        let mut hiding = [0u8; 32];
        let mut binding = [0u8; 32];
        hiding.copy_from_slice(&rec[4..36]);
        binding.copy_from_slice(&rec[36..68]);
        out.push(fed::Commitment {
            id: read_u32_le(&rec[..4]),
            hiding,
            binding,
        });
    }
    Ok(out)
}

fn parse_ed_factors(ptr: *const u8, n: usize) -> Result<alloc::vec::Vec<(u32, [u8; 32])>, i32> {
    if ptr.is_null() || n == 0 {
        return Err(BU_FROST_ERR_LEN);
    }
    let raw = unsafe { slice::from_raw_parts(ptr, n * 36) };
    let mut out = alloc::vec::Vec::with_capacity(n);
    for i in 0..n {
        let rec = &raw[i * 36..(i + 1) * 36];
        let mut rho = [0u8; 32];
        rho.copy_from_slice(&rec[4..36]);
        out.push((read_u32_le(&rec[..4]), rho));
    }
    Ok(out)
}

/// Dealer shard: `secret(32)`, `coeffs(n_coeffs*32)`, ids `1..=max`.
/// `is_scalar != 0`: inputs are canonical scalars; `0`: RFC 8032 seeds
/// (SHA-512 + clamp, same as `expand_secret`).
/// Writes `max` share records (36 B each) and `(1+n_coeffs)*32` poly bytes.
#[no_mangle]
/// # Safety
/// Pointers must reference readable/writable memory of the documented lengths.
pub unsafe extern "C" fn bu_frost_ed_shard(
    secret: *const u8,
    coeffs: *const u8,
    n_coeffs: usize,
    max: u16,
    shares_out: *mut u8,
    shares_len: usize,
    poly_out: *mut u8,
    poly_len: usize,
    is_scalar: u8,
) -> i32 {
    if secret.is_null() || shares_out.is_null() || poly_out.is_null() || max == 0 {
        return BU_FROST_ERR_LEN;
    }
    if n_coeffs > 0 && coeffs.is_null() {
        return BU_FROST_ERR_LEN;
    }
    if shares_len < max as usize * 36 || poly_len < (1 + n_coeffs) * 32 {
        return BU_FROST_ERR_LEN;
    }
    let mut sec = [0u8; 32];
    sec.copy_from_slice(slice::from_raw_parts(secret, 32));
    let sec = match fed::secret_to_scalar_bytes(&sec, is_scalar) {
        Ok(s) => s,
        Err(e) => return map_err(e),
    };
    let mut cf = alloc::vec::Vec::with_capacity(n_coeffs);
    if n_coeffs > 0 {
        let raw = slice::from_raw_parts(coeffs, n_coeffs * 32);
        for i in 0..n_coeffs {
            let mut c = [0u8; 32];
            c.copy_from_slice(&raw[i * 32..(i + 1) * 32]);
            match fed::secret_to_scalar_bytes(&c, is_scalar) {
                Ok(s) => cf.push(s),
                Err(e) => return map_err(e),
            }
        }
    }
    match fed::shard(&sec, &cf, max) {
        Ok((shares, poly)) => {
            let so = slice::from_raw_parts_mut(shares_out, max as usize * 36);
            for (i, sh) in shares.iter().enumerate() {
                so[i * 36..i * 36 + 4].copy_from_slice(&sh.id.to_le_bytes());
                so[i * 36 + 4..(i + 1) * 36].copy_from_slice(&sh.share);
            }
            let po = slice::from_raw_parts_mut(poly_out, (1 + n_coeffs) * 32);
            for (i, p) in poly.iter().enumerate() {
                po[i * 32..(i + 1) * 32].copy_from_slice(p);
            }
            BU_FROST_OK
        }
        Err(e) => map_err(e),
    }
}

/// Combine share records (`n` x 36 B) → secret (32 B).
/// `is_scalar != 0`: shares hold scalars; `0`: shares hold seeds.
#[no_mangle]
/// # Safety
/// Pointers must reference readable/writable memory of the documented lengths.
pub unsafe extern "C" fn bu_frost_ed_combine(
    shares: *const u8,
    n: usize,
    out: *mut u8,
    out_len: usize,
    is_scalar: u8,
) -> i32 {
    if shares.is_null() || out.is_null() || n == 0 || out_len < 32 {
        return BU_FROST_ERR_LEN;
    }
    let raw = slice::from_raw_parts(shares, n * 36);
    let mut list = alloc::vec::Vec::with_capacity(n);
    for i in 0..n {
        let rec = &raw[i * 36..(i + 1) * 36];
        let mut share = [0u8; 32];
        share.copy_from_slice(&rec[4..36]);
        let share = match fed::secret_to_scalar_bytes(&share, is_scalar) {
            Ok(s) => s,
            Err(e) => return map_err(e),
        };
        list.push(fed::KeyShare {
            id: read_u32_le(&rec[..4]),
            share,
        });
    }
    match fed::combine(&list) {
        Ok(s) => {
            slice::from_raw_parts_mut(out, 32).copy_from_slice(&s);
            BU_FROST_OK
        }
        Err(e) => map_err(e),
    }
}

/// Prepare signing shares: `shares` (`n` x 36 B `[id:u32][share:32]`),
/// `threshold` (`0` = additive full-set rescale, else Shamir passthrough),
/// `is_scalar` (`!= 0` canonical scalars, `0` RFC 8032 seeds expanded via
/// SHA-512 + clamp) → `out` (`n` x 32 B rescaled scalars).
#[no_mangle]
/// # Safety
/// Pointers must reference readable/writable memory of the documented lengths.
pub unsafe extern "C" fn bu_frost_ed_prepare_shares(
    shares: *const u8,
    n: usize,
    threshold: u16,
    is_scalar: u8,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if shares.is_null() || out.is_null() || n == 0 || out_len < n * 32 {
        return BU_FROST_ERR_LEN;
    }
    let raw = slice::from_raw_parts(shares, n * 36);
    let mut ids = alloc::vec::Vec::with_capacity(n);
    let mut list = alloc::vec::Vec::with_capacity(n);
    for i in 0..n {
        let rec = &raw[i * 36..(i + 1) * 36];
        let mut share = [0u8; 32];
        share.copy_from_slice(&rec[4..36]);
        ids.push(read_u32_le(&rec[..4]));
        list.push(share);
    }
    match fed::prepare_shares(&ids, &list, threshold, is_scalar) {
        Ok(v) => {
            let o = slice::from_raw_parts_mut(out, n * 32);
            for (i, s) in v.iter().enumerate() {
                o[i * 32..(i + 1) * 32].copy_from_slice(s);
            }
            BU_FROST_OK
        }
        Err(e) => map_err(e),
    }
}

/// Group key from member points: `ids` (`n` x u32 LE), `pubs` (`n` x 32 B),
/// `threshold` (`0` = additive sum, else Lagrange at zero) → `group` (32 B).
#[no_mangle]
/// # Safety
/// Pointers must reference readable/writable memory of the documented lengths.
pub unsafe extern "C" fn bu_frost_ed_group_from_members(
    ids: *const u8,
    pubs: *const u8,
    n: usize,
    threshold: u16,
    group_out: *mut u8,
    group_len: usize,
) -> i32 {
    if ids.is_null() || pubs.is_null() || group_out.is_null() || n == 0 || group_len < 32 {
        return BU_FROST_ERR_LEN;
    }
    let raw_ids = slice::from_raw_parts(ids, n * 4);
    let raw_pubs = slice::from_raw_parts(pubs, n * 32);
    let mut id_list = alloc::vec::Vec::with_capacity(n);
    let mut pub_list = alloc::vec::Vec::with_capacity(n);
    for i in 0..n {
        id_list.push(read_u32_le(&raw_ids[i * 4..(i + 1) * 4]));
        let mut p = [0u8; 32];
        p.copy_from_slice(&raw_pubs[i * 32..(i + 1) * 32]);
        pub_list.push(p);
    }
    match fed::group_from_members(&id_list, &pub_list, threshold) {
        Ok(g) => {
            slice::from_raw_parts_mut(group_out, 32).copy_from_slice(&g);
            BU_FROST_OK
        }
        Err(e) => map_err(e),
    }
}

/// Feldman VSS commit: `coeffs(n*32)` → `n*32` bytes.
/// `is_scalar != 0`: coeffs are scalars; `0`: coeffs are seeds.
#[no_mangle]
/// # Safety
/// Pointers must reference readable/writable memory of the documented lengths.
pub unsafe extern "C" fn bu_frost_ed_vss_commit(
    coeffs: *const u8,
    n_coeffs: usize,
    out: *mut u8,
    out_len: usize,
    is_scalar: u8,
) -> i32 {
    if coeffs.is_null() || out.is_null() || n_coeffs == 0 || out_len < n_coeffs * 32 {
        return BU_FROST_ERR_LEN;
    }
    let raw = slice::from_raw_parts(coeffs, n_coeffs * 32);
    let mut cf = alloc::vec::Vec::with_capacity(n_coeffs);
    for i in 0..n_coeffs {
        let mut c = [0u8; 32];
        c.copy_from_slice(&raw[i * 32..(i + 1) * 32]);
        match fed::secret_to_scalar_bytes(&c, is_scalar) {
            Ok(s) => cf.push(s),
            Err(e) => return map_err(e),
        }
    }
    match fed::vss_commit(&cf) {
        Ok(v) => {
            let o = slice::from_raw_parts_mut(out, n_coeffs * 32);
            for (i, p) in v.iter().enumerate() {
                o[i * 32..(i + 1) * 32].copy_from_slice(p);
            }
            BU_FROST_OK
        }
        Err(e) => map_err(e),
    }
}

/// VSS verify: `id`, `share(32)`, `commitment(n_comms*32)`.
/// `is_scalar != 0`: share is a scalar; `0`: share is a seed.
/// Returns OK / VERIFY / error.
#[no_mangle]
/// # Safety
/// Pointers must reference readable/writable memory of the documented lengths.
pub unsafe extern "C" fn bu_frost_ed_vss_verify(
    id: u32,
    share: *const u8,
    commitment: *const u8,
    n_comms: usize,
    is_scalar: u8,
) -> i32 {
    if share.is_null() || commitment.is_null() || n_comms == 0 {
        return BU_FROST_ERR_LEN;
    }
    let mut sh = [0u8; 32];
    sh.copy_from_slice(slice::from_raw_parts(share, 32));
    let sh = match fed::secret_to_scalar_bytes(&sh, is_scalar) {
        Ok(s) => s,
        Err(e) => return map_err(e),
    };
    let raw = slice::from_raw_parts(commitment, n_comms * 32);
    let mut com = alloc::vec::Vec::with_capacity(n_comms);
    for i in 0..n_comms {
        let mut c = [0u8; 32];
        c.copy_from_slice(&raw[i * 32..(i + 1) * 32]);
        com.push(c);
    }
    match fed::vss_verify(&fed::KeyShare { id, share: sh }, &com) {
        Ok(true) => BU_FROST_OK,
        Ok(false) => BU_FROST_ERR_VERIFY,
        Err(e) => map_err(e),
    }
}

/// Group info: `vss(n_comms*32)` → group key (32) + `max*32` member keys.
#[no_mangle]
/// # Safety
/// Pointers must reference readable/writable memory of the documented lengths.
pub unsafe extern "C" fn bu_frost_ed_group_info(
    vss: *const u8,
    n_comms: usize,
    max: u16,
    group_out: *mut u8,
    pks_out: *mut u8,
    pks_len: usize,
) -> i32 {
    if vss.is_null() || group_out.is_null() || pks_out.is_null() || n_comms == 0 || max == 0 {
        return BU_FROST_ERR_LEN;
    }
    if pks_len < max as usize * 32 {
        return BU_FROST_ERR_LEN;
    }
    let raw = slice::from_raw_parts(vss, n_comms * 32);
    let mut com = alloc::vec::Vec::with_capacity(n_comms);
    for i in 0..n_comms {
        let mut c = [0u8; 32];
        c.copy_from_slice(&raw[i * 32..(i + 1) * 32]);
        com.push(c);
    }
    match fed::group_info(max, &com) {
        Ok((g, pks)) => {
            slice::from_raw_parts_mut(group_out, 32).copy_from_slice(&g);
            let o = slice::from_raw_parts_mut(pks_out, max as usize * 32);
            for (i, p) in pks.iter().enumerate() {
                o[i * 32..(i + 1) * 32].copy_from_slice(p);
            }
            BU_FROST_OK
        }
        Err(e) => map_err(e),
    }
}

/// Round-1 commit. Writes hiding/binding scalars (32+32) and commitments (32+32).
/// `is_scalar != 0`: `secret_share` is a scalar; `0`: it is a seed.
/// Hiding/binding randomness inputs are always raw scalars.
#[no_mangle]
/// # Safety
/// Pointers must reference readable/writable memory of the documented lengths.
pub unsafe extern "C" fn bu_frost_ed_commit(
    secret_share: *const u8,
    hiding_rand: *const u8,
    binding_rand: *const u8,
    hiding_out: *mut u8,
    binding_out: *mut u8,
    hiding_comm_out: *mut u8,
    binding_comm_out: *mut u8,
    is_scalar: u8,
) -> i32 {
    if secret_share.is_null()
        || hiding_rand.is_null()
        || binding_rand.is_null()
        || hiding_out.is_null()
        || binding_out.is_null()
        || hiding_comm_out.is_null()
        || binding_comm_out.is_null()
    {
        return BU_FROST_ERR_LEN;
    }
    let mut s = [0u8; 32];
    let mut hr = [0u8; 32];
    let mut br = [0u8; 32];
    s.copy_from_slice(slice::from_raw_parts(secret_share, 32));
    let s = match fed::secret_to_scalar_bytes(&s, is_scalar) {
        Ok(v) => v,
        Err(e) => return map_err(e),
    };
    hr.copy_from_slice(slice::from_raw_parts(hiding_rand, 32));
    br.copy_from_slice(slice::from_raw_parts(binding_rand, 32));
    match fed::commit_with_randomness(&s, &hr, &br) {
        Ok(n) => {
            slice::from_raw_parts_mut(hiding_out, 32).copy_from_slice(&n.hiding);
            slice::from_raw_parts_mut(binding_out, 32).copy_from_slice(&n.binding);
            slice::from_raw_parts_mut(hiding_comm_out, 32).copy_from_slice(&n.hiding_commitment);
            slice::from_raw_parts_mut(binding_comm_out, 32).copy_from_slice(&n.binding_commitment);
            BU_FROST_OK
        }
        Err(e) => map_err(e),
    }
}

/// Binding factors: `commitments(n*68)`, `msg` → `n*36` factor records.
#[no_mangle]
/// # Safety
/// Pointers must reference readable/writable memory of the documented lengths.
pub unsafe extern "C" fn bu_frost_ed_binding_factors(
    group_pk: *const u8,
    commitments: *const u8,
    n: usize,
    msg: *const u8,
    msg_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if group_pk.is_null() || out.is_null() || n == 0 || out_len < n * 36 {
        return BU_FROST_ERR_LEN;
    }
    if msg.is_null() && msg_len > 0 {
        return BU_FROST_ERR_LEN;
    }
    let list = match parse_ed_commitments(commitments, n) {
        Ok(l) => l,
        Err(e) => return e,
    };
    let mut pk = [0u8; 32];
    pk.copy_from_slice(slice::from_raw_parts(group_pk, 32));
    let m = if msg_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(msg, msg_len)
    };
    match fed::compute_binding_factors(&pk, &list, m) {
        Ok(f) => {
            let o = slice::from_raw_parts_mut(out, n * 36);
            for (i, (id, rho)) in f.iter().enumerate() {
                o[i * 36..i * 36 + 4].copy_from_slice(&id.to_le_bytes());
                o[i * 36 + 4..(i + 1) * 36].copy_from_slice(rho);
            }
            BU_FROST_OK
        }
        Err(e) => map_err(e),
    }
}

/// Group commitment: `commitments(n*68)` + `factors(n*36)` → `R(32)`.
#[no_mangle]
/// # Safety
/// Pointers must reference readable/writable memory of the documented lengths.
pub unsafe extern "C" fn bu_frost_ed_group_commitment(
    commitments: *const u8,
    factors: *const u8,
    n: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if out.is_null() || n == 0 || out_len < 32 {
        return BU_FROST_ERR_LEN;
    }
    let list = match parse_ed_commitments(commitments, n) {
        Ok(l) => l,
        Err(e) => return e,
    };
    let fac = match parse_ed_factors(factors, n) {
        Ok(f) => f,
        Err(e) => return e,
    };
    match fed::compute_group_commitment(&list, &fac) {
        Ok(r) => {
            slice::from_raw_parts_mut(out, 32).copy_from_slice(&r);
            BU_FROST_OK
        }
        Err(e) => map_err(e),
    }
}

/// Round-2 sign: writes 32-byte share.
/// `is_scalar != 0`: `secret_share` is a scalar; `0`: it is a seed.
#[no_mangle]
/// # Safety
/// Pointers must reference readable/writable memory of the documented lengths.
pub unsafe extern "C" fn bu_frost_ed_sign(
    id: u32,
    secret_share: *const u8,
    group_pk: *const u8,
    hiding_nonce: *const u8,
    binding_nonce: *const u8,
    hiding_comm: *const u8,
    binding_comm: *const u8,
    commitments: *const u8,
    n: usize,
    msg: *const u8,
    msg_len: usize,
    out: *mut u8,
    out_len: usize,
    is_scalar: u8,
) -> i32 {
    if secret_share.is_null()
        || group_pk.is_null()
        || hiding_nonce.is_null()
        || binding_nonce.is_null()
        || hiding_comm.is_null()
        || binding_comm.is_null()
        || out.is_null()
        || n == 0
        || out_len < 32
    {
        return BU_FROST_ERR_LEN;
    }
    if msg.is_null() && msg_len > 0 {
        return BU_FROST_ERR_LEN;
    }
    let list = match parse_ed_commitments(commitments, n) {
        Ok(l) => l,
        Err(e) => return e,
    };
    let mut s = [0u8; 32];
    let mut h = [0u8; 32];
    let mut b = [0u8; 32];
    let mut hc = [0u8; 32];
    let mut bc = [0u8; 32];
    let mut pk = [0u8; 32];
    s.copy_from_slice(slice::from_raw_parts(secret_share, 32));
    let s = match fed::secret_to_scalar_bytes(&s, is_scalar) {
        Ok(v) => v,
        Err(e) => return map_err(e),
    };
    h.copy_from_slice(slice::from_raw_parts(hiding_nonce, 32));
    b.copy_from_slice(slice::from_raw_parts(binding_nonce, 32));
    hc.copy_from_slice(slice::from_raw_parts(hiding_comm, 32));
    bc.copy_from_slice(slice::from_raw_parts(binding_comm, 32));
    pk.copy_from_slice(slice::from_raw_parts(group_pk, 32));
    let m = if msg_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(msg, msg_len)
    };
    let nonces = fed::NoncePair {
        hiding: h,
        binding: b,
        hiding_commitment: hc,
        binding_commitment: bc,
    };
    match fed::sign(id, &s, &pk, &nonces, m, &list) {
        Ok(share) => {
            slice::from_raw_parts_mut(out, 32).copy_from_slice(&share);
            BU_FROST_OK
        }
        Err(e) => map_err(e),
    }
}

/// Aggregate: `commitments(n*68)`, `shares(n_shares*32)` → `R(32) || z(32)`.
#[no_mangle]
/// # Safety
/// Pointers must reference readable/writable memory of the documented lengths.
pub unsafe extern "C" fn bu_frost_ed_aggregate(
    commitments: *const u8,
    n: usize,
    msg: *const u8,
    msg_len: usize,
    group_pk: *const u8,
    shares: *const u8,
    n_shares: usize,
    r_out: *mut u8,
    z_out: *mut u8,
) -> i32 {
    if shares.is_null() || r_out.is_null() || z_out.is_null() || n == 0 || n_shares == 0 {
        return BU_FROST_ERR_LEN;
    }
    if (msg.is_null() && msg_len > 0) || group_pk.is_null() {
        return BU_FROST_ERR_LEN;
    }
    let list = match parse_ed_commitments(commitments, n) {
        Ok(l) => l,
        Err(e) => return e,
    };
    let mut pk = [0u8; 32];
    pk.copy_from_slice(slice::from_raw_parts(group_pk, 32));
    let m = if msg_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(msg, msg_len)
    };
    let raw = slice::from_raw_parts(shares, n_shares * 32);
    let mut sh = alloc::vec::Vec::with_capacity(n_shares);
    for i in 0..n_shares {
        let mut x = [0u8; 32];
        x.copy_from_slice(&raw[i * 32..(i + 1) * 32]);
        sh.push(x);
    }
    match fed::aggregate(&list, m, &pk, &sh) {
        Ok((r, z)) => {
            slice::from_raw_parts_mut(r_out, 32).copy_from_slice(&r);
            slice::from_raw_parts_mut(z_out, 32).copy_from_slice(&z);
            BU_FROST_OK
        }
        Err(e) => map_err(e),
    }
}

/// Verify one share. `comm` is a single 68-byte commitment record.
/// Returns OK / VERIFY / error.
#[no_mangle]
/// # Safety
/// Pointers must reference readable/writable memory of the documented lengths.
pub unsafe extern "C" fn bu_frost_ed_verify_share(
    id: u32,
    pk_share: *const u8,
    comm: *const u8,
    share: *const u8,
    commitments: *const u8,
    n: usize,
    group_pk: *const u8,
    msg: *const u8,
    msg_len: usize,
) -> i32 {
    if pk_share.is_null() || comm.is_null() || share.is_null() || group_pk.is_null() || n == 0 {
        return BU_FROST_ERR_LEN;
    }
    if msg.is_null() && msg_len > 0 {
        return BU_FROST_ERR_LEN;
    }
    let list = match parse_ed_commitments(commitments, n) {
        Ok(l) => l,
        Err(e) => return e,
    };
    let mut pk = [0u8; 32];
    let mut ps = [0u8; 32];
    let mut sh = [0u8; 32];
    let mut hc = [0u8; 32];
    let mut bc = [0u8; 32];
    pk.copy_from_slice(slice::from_raw_parts(group_pk, 32));
    ps.copy_from_slice(slice::from_raw_parts(pk_share, 32));
    sh.copy_from_slice(slice::from_raw_parts(share, 32));
    let crec = slice::from_raw_parts(comm, ED_REC);
    if read_u32_le(&crec[..4]) != id {
        return BU_FROST_ERR_KEY;
    }
    hc.copy_from_slice(&crec[4..36]);
    bc.copy_from_slice(&crec[36..68]);
    let m = if msg_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(msg, msg_len)
    };
    let c = fed::Commitment {
        id,
        hiding: hc,
        binding: bc,
    };
    match fed::verify_share(id, &ps, &c, &sh, &list, &pk, m) {
        Ok(true) => BU_FROST_OK,
        Ok(false) => BU_FROST_ERR_VERIFY,
        Err(e) => map_err(e),
    }
}

/// Reshare over independent seeds: `ids` (`n` x u32 LE), `secrets`
/// (`n` x 32 B seeds, expanded via SHA-512 + clamp), `coeffs`
/// (`n_coeffs` x 32 B seeds, expect `n*(threshold-1)` row-major) →
/// `shares_out` (`n` x 32 B), `pubs_out` (`n` x 32 B),
/// `group_out` (32 B).
///
/// Seed expansion happens here at the boundary
/// (`secret_to_scalar_bytes(x, 0)`); the core `fed::reshare` takes
/// canonical scalars only and never hashes.
#[no_mangle]
/// # Safety
/// Pointers must reference readable/writable memory of the documented lengths.
pub unsafe extern "C" fn bu_frost_ed_reshare(
    ids: *const u8,
    secrets: *const u8,
    n: usize,
    coeffs: *const u8,
    n_coeffs: usize,
    threshold: u16,
    shares_out: *mut u8,
    shares_len: usize,
    pubs_out: *mut u8,
    pubs_len: usize,
    group_out: *mut u8,
    group_len: usize,
) -> i32 {
    if ids.is_null()
        || secrets.is_null()
        || shares_out.is_null()
        || pubs_out.is_null()
        || group_out.is_null()
        || n < 2
    {
        return BU_FROST_ERR_LEN;
    }
    if threshold < 2 || (threshold as usize) > n {
        return BU_FROST_ERR_LEN;
    }
    if n_coeffs != n * (threshold as usize - 1) {
        return BU_FROST_ERR_LEN;
    }
    if coeffs.is_null() {
        return BU_FROST_ERR_LEN;
    }
    if shares_len < n * 32 || pubs_len < n * 32 || group_len < 32 {
        return BU_FROST_ERR_LEN;
    }
    let raw_ids = slice::from_raw_parts(ids, n * 4);
    let raw_sec = slice::from_raw_parts(secrets, n * 32);
    let raw_cf = slice::from_raw_parts(coeffs, n_coeffs * 32);
    let mut id_list = alloc::vec::Vec::with_capacity(n);
    let mut sec_list = alloc::vec::Vec::with_capacity(n);
    let mut cf_list = alloc::vec::Vec::with_capacity(n_coeffs);
    for i in 0..n {
        id_list.push(read_u32_le(&raw_ids[i * 4..(i + 1) * 4]));
        let mut s = [0u8; 32];
        s.copy_from_slice(&raw_sec[i * 32..(i + 1) * 32]);
        // Seeds are expanded here; `fed::reshare` takes scalars only.
        match fed::secret_to_scalar_bytes(&s, 0) {
            Ok(v) => sec_list.push(v),
            Err(e) => return map_err(e),
        }
    }
    for i in 0..n_coeffs {
        let mut c = [0u8; 32];
        c.copy_from_slice(&raw_cf[i * 32..(i + 1) * 32]);
        match fed::secret_to_scalar_bytes(&c, 0) {
            Ok(v) => cf_list.push(v),
            Err(e) => return map_err(e),
        }
    }
    match fed::reshare(&id_list, &sec_list, &cf_list, threshold) {
        Ok((shares, pubs, group)) => {
            let so = slice::from_raw_parts_mut(shares_out, n * 32);
            for (i, s) in shares.iter().enumerate() {
                so[i * 32..(i + 1) * 32].copy_from_slice(s);
            }
            let po = slice::from_raw_parts_mut(pubs_out, n * 32);
            for (i, p) in pubs.iter().enumerate() {
                po[i * 32..(i + 1) * 32].copy_from_slice(p);
            }
            slice::from_raw_parts_mut(group_out, 32).copy_from_slice(&group);
            BU_FROST_OK
        }
        Err(e) => map_err(e),
    }
}

/// Verify final signature `R(32) || z(32)`. Returns OK / VERIFY.
#[no_mangle]
/// # Safety
/// Pointers must reference readable/writable memory of the documented lengths.
pub unsafe extern "C" fn bu_frost_ed_verify(
    r: *const u8,
    z: *const u8,
    group_pk: *const u8,
    msg: *const u8,
    msg_len: usize,
) -> i32 {
    if r.is_null() || z.is_null() || group_pk.is_null() {
        return BU_FROST_ERR_LEN;
    }
    if msg.is_null() && msg_len > 0 {
        return BU_FROST_ERR_LEN;
    }
    let mut rr = [0u8; 32];
    let mut zz = [0u8; 32];
    let mut pk = [0u8; 32];
    rr.copy_from_slice(slice::from_raw_parts(r, 32));
    zz.copy_from_slice(slice::from_raw_parts(z, 32));
    pk.copy_from_slice(slice::from_raw_parts(group_pk, 32));
    let m = if msg_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(msg, msg_len)
    };
    if fed::verify_signature(&rr, &zz, &pk, m) {
        BU_FROST_OK
    } else {
        BU_FROST_ERR_VERIFY
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hx(s: &str) -> alloc::vec::Vec<u8> {
        let bytes: alloc::vec::Vec<u8> =
            s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        let mut out = alloc::vec::Vec::with_capacity(bytes.len() / 2);
        let val = |c: u8| match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("hex"),
        };
        for i in (0..bytes.len()).step_by(2) {
            out.push(val(bytes[i]) << 4 | val(bytes[i + 1]));
        }
        out
    }

    /// End-to-end k1 flow through the raw FFI boundary (E.5 pins).
    #[test]
    fn ffi_k1_e5_flow() {
        let secret = hx("0d004150d27c3bf2a42f312683d35fac7394b1e9e318249c1bfe7f0795a83114");
        let coeff = hx("fbf85eadae3058ea14f19148bb72b45e4399c0b16028acaf0395c9b03c823579");
        let msg = hx("74657374");
        let mut shares = [0u8; 3 * 36];
        let mut poly = [0u8; 2 * 32];
        unsafe {
            assert_eq!(
                bu_frost_k1_shard(
                    secret.as_ptr(),
                    coeff.as_ptr(),
                    1,
                    3,
                    shares.as_mut_ptr(),
                    shares.len(),
                    poly.as_mut_ptr(),
                    poly.len()
                ),
                BU_FROST_OK
            );
        }
        // Share 1 must equal the E.5 P1 participant_share.
        let exp1 = hx("08f89ffe80ac94dcb920c26f3f46140bfc7f95b493f8310f5fc1ea2b01f4254c");
        assert_eq!(&shares[4..36], exp1.as_slice());

        // Commit both signers with E.5 randomness.
        let hr1 = hx("7ea5ed09af19f6ff21040c07ec2d2adbd35b759da5a401d4c99dd26b82391cb2");
        let br1 = hx("47acab018f116020c10cb9b9abdc7ac10aae1b48ca6e36dc15acb6ec9be5cdc5");
        let hr3 = hx("e6cc56ccbd0502b3f6f831d91e2ebd01c4de0479e0191b66895a4ffd9b68d544");
        let br3 = hx("7203d55eb82a5ca0d7d83674541ab55f6e76f1b85391d2c13706a89a064fd5b9");
        let (mut h1, mut b1, mut hc1, mut bc1) = ([0u8; 32], [0u8; 32], [0u8; 33], [0u8; 33]);
        let (mut h3, mut b3, mut hc3, mut bc3) = ([0u8; 32], [0u8; 32], [0u8; 33], [0u8; 33]);
        // share bytes live at shares[0*36+4..36] (id 1) and shares[2*36+4..] (id 3).
        unsafe {
            assert_eq!(
                bu_frost_k1_commit(
                    shares[4..].as_ptr(),
                    hr1.as_ptr(),
                    br1.as_ptr(),
                    h1.as_mut_ptr(),
                    b1.as_mut_ptr(),
                    hc1.as_mut_ptr(),
                    bc1.as_mut_ptr()
                ),
                BU_FROST_OK
            );
            assert_eq!(
                bu_frost_k1_commit(
                    shares[2 * 36 + 4..].as_ptr(),
                    hr3.as_ptr(),
                    br3.as_ptr(),
                    h3.as_mut_ptr(),
                    b3.as_mut_ptr(),
                    hc3.as_mut_ptr(),
                    bc3.as_mut_ptr()
                ),
                BU_FROST_OK
            );
        }
        assert_eq!(
            h1.as_slice(),
            hx("841d3a6450d7580b4da83c8e618414d0f024391f2aeb511d7579224420aa81f0").as_slice()
        );
        // Commitment list: id LE + hiding + binding per record.
        let mut coms = [0u8; 2 * 70];
        coms[0..4].copy_from_slice(&1u32.to_le_bytes());
        coms[4..37].copy_from_slice(&hc1);
        coms[37..70].copy_from_slice(&bc1);
        coms[70..74].copy_from_slice(&3u32.to_le_bytes());
        coms[74..107].copy_from_slice(&hc3);
        coms[107..140].copy_from_slice(&bc3);

        let pk = hx("02f37c34b66ced1fb51c34a90bdae006901f10625cc06c4f64663b0eae87d87b4f");
        let (mut s1, mut s3) = ([0u8; 32], [0u8; 32]);
        unsafe {
            assert_eq!(
                bu_frost_k1_sign(
                    1,
                    shares[4..].as_ptr(),
                    pk.as_ptr(),
                    h1.as_ptr(),
                    b1.as_ptr(),
                    hc1.as_ptr(),
                    bc1.as_ptr(),
                    coms.as_ptr(),
                    2,
                    msg.as_ptr(),
                    msg.len(),
                    s1.as_mut_ptr(),
                    32
                ),
                BU_FROST_OK
            );
            assert_eq!(
                bu_frost_k1_sign(
                    3,
                    shares[2 * 36 + 4..].as_ptr(),
                    pk.as_ptr(),
                    h3.as_ptr(),
                    b3.as_ptr(),
                    hc3.as_ptr(),
                    bc3.as_ptr(),
                    coms.as_ptr(),
                    2,
                    msg.as_ptr(),
                    msg.len(),
                    s3.as_mut_ptr(),
                    32
                ),
                BU_FROST_OK
            );
        }
        assert_eq!(
            s1.as_slice(),
            hx("c4fce1775a1e141fb579944166eab0d65eefe7b98d480a569bbbfcb14f91c197").as_slice()
        );
        let mut parts = [0u8; 64];
        parts[..32].copy_from_slice(&s1);
        parts[32..].copy_from_slice(&s3);
        let (mut r, mut z) = ([0u8; 33], [0u8; 32]);
        unsafe {
            assert_eq!(
                bu_frost_k1_aggregate(
                    coms.as_ptr(),
                    2,
                    msg.as_ptr(),
                    msg.len(),
                    pk.as_ptr(),
                    parts.as_ptr(),
                    2,
                    r.as_mut_ptr(),
                    z.as_mut_ptr()
                ),
                BU_FROST_OK
            );
            assert_eq!(
                bu_frost_k1_verify(r.as_ptr(), z.as_ptr(), pk.as_ptr(), msg.as_ptr(), msg.len()),
                BU_FROST_OK
            );
            // Wrong message → VERIFY.
            assert_eq!(
                bu_frost_k1_verify(r.as_ptr(), z.as_ptr(), pk.as_ptr(), [0x00].as_ptr(), 1),
                BU_FROST_ERR_VERIFY
            );
        }
        let exp_sig = hx("0205b6d04d3774c8929413e3c76024d54149c372d57aae62574ed74319b5ea14d0c65dde8492a7471437e6c2fe3da49b90d23f642b5c6dbe7e36089f096dd97324");
        let mut got = alloc::vec::Vec::with_capacity(65);
        got.extend_from_slice(&r);
        got.extend_from_slice(&z);
        assert_eq!(got, exp_sig);
    }

    /// k1 reshare through the raw FFI boundary: 3 secrets, t=2.
    #[test]
    fn ffi_k1_reshare_roundtrip() {
        let n = 3usize;
        let threshold = 2u16;
        // Small nonzero scalars (LE): secrets 1,2,3 and coeffs 4,5,6.
        let mut secrets = [[0u8; 32]; 3];
        let mut coeffs = [[0u8; 32]; 3];
        secrets[0][0] = 1;
        secrets[1][0] = 2;
        secrets[2][0] = 3;
        coeffs[0][0] = 4;
        coeffs[1][0] = 5;
        coeffs[2][0] = 6;
        let mut ids_raw = [0u8; 3 * 4];
        for (i, id) in [1u32, 2, 3].iter().enumerate() {
            ids_raw[i * 4..(i + 1) * 4].copy_from_slice(&id.to_le_bytes());
        }
        let mut sec_raw = [0u8; 3 * 32];
        let mut cf_raw = [0u8; 3 * 32];
        for i in 0..3 {
            sec_raw[i * 32..(i + 1) * 32].copy_from_slice(&secrets[i]);
            cf_raw[i * 32..(i + 1) * 32].copy_from_slice(&coeffs[i]);
        }
        let mut shares = [0u8; 3 * 32];
        let mut pubs = [0u8; 3 * 33];
        let mut group = [0u8; 33];
        unsafe {
            assert_eq!(
                bu_frost_k1_reshare(
                    ids_raw.as_ptr(),
                    sec_raw.as_ptr(),
                    n,
                    cf_raw.as_ptr(),
                    n * (threshold as usize - 1),
                    threshold,
                    shares.as_mut_ptr(),
                    shares.len(),
                    pubs.as_mut_ptr(),
                    pubs.len(),
                    group.as_mut_ptr(),
                    group.len()
                ),
                BU_FROST_OK
            );
            // Wrong coeff count → LEN.
            assert_eq!(
                bu_frost_k1_reshare(
                    ids_raw.as_ptr(),
                    sec_raw.as_ptr(),
                    n,
                    cf_raw.as_ptr(),
                    1,
                    threshold,
                    shares.as_mut_ptr(),
                    shares.len(),
                    pubs.as_mut_ptr(),
                    pubs.len(),
                    group.as_mut_ptr(),
                    group.len()
                ),
                BU_FROST_ERR_LEN
            );
        }
        assert_eq!(shares.len(), n * 32);
        // Outputs must match the direct core call.
        let (exp_shares, exp_pubs, exp_group) =
            fk1::reshare(&[1u32, 2, 3], &secrets, &coeffs, threshold).unwrap();
        for i in 0..n {
            assert_eq!(&shares[i * 32..(i + 1) * 32], &exp_shares[i]);
            assert_eq!(&pubs[i * 33..(i + 1) * 33], &exp_pubs[i]);
        }
        assert_eq!(&group, &exp_group);
    }
}
