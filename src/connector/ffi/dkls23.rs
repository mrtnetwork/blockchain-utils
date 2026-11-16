//! FFI for DKLs23 threshold ECDSA (requires `alloc` + `ffi`).
//!
//! Curve-agnostic surface (`curve`: `0` = secp256k1, `1` = secp256r1).
//! Shares cross the boundary as framed blobs of [`keyshare_bytes`]
//! records (see [`crate::dkls23::codec`]): `frame([share, …])`.
//! Signatures are compact `r(32) || s(32)` (64 B, low-S); message hashes
//! are 32 bytes; seeds are 32 bytes per party.
//!
//! - DKG: `bu_dkls23_dkg` runs the full commit→release→complain ceremony
//!   deterministically from explicit seeds (no OS RNG — WASM-safe).
//! - Sign: `bu_dkls23_sign` thresholds-signs with any `>= t` subset of
//!   shares (Lagrange rescale inside); subset order is preserved for
//!   seed alignment (`seeds[i]` belongs to `shares[i]`).
//! - Refresh: `bu_dkls23_refresh` rotates shares, group key unchanged.
//! - Verify: `bu_dkls23_verify` checks a compact signature.
//!
//! [`keyshare_bytes`]: crate::dkls23::codec::keyshare_bytes

#![cfg(all(feature = "ffi", feature = "alloc"))]

use core::slice;

use crate::dkls23::codec::{keyshare_bytes, parse_keyshare, CompactSig, KeyShare};
use crate::dkls23::curve_id::CurveId;
use crate::dkls23::error::DklsError;
use crate::dkls23::session::{dkg_oneshot, refresh_oneshot, sign_oneshot};

pub const BU_DKLS23_OK: i32 = 0;
pub const BU_DKLS23_ERR: i32 = 1;
pub const BU_DKLS23_ERR_LEN: i32 = 2;
pub const BU_DKLS23_ERR_KEY: i32 = 3;
pub const BU_DKLS23_ERR_VERIFY: i32 = 4;

fn map_err(e: DklsError) -> i32 {
    use DklsError::*;
    match e {
        InvalidLength | TooFew | BadEncoding => BU_DKLS23_ERR_LEN,
        InvalidScalar | InvalidPoint | InvalidParticipant | ZeroSecret => BU_DKLS23_ERR_KEY,
        BadCommitment | BadProof | BadShare => BU_DKLS23_ERR_VERIFY,
        Internal => BU_DKLS23_ERR,
    }
}

fn parse_curve(curve: u32) -> Result<CurveId, i32> {
    CurveId::from_u32(curve).ok_or(BU_DKLS23_ERR_KEY)
}

fn parse_shares_blob(raw: &[u8]) -> Result<alloc::vec::Vec<KeyShare>, i32> {
    let frames = crate::dkls23::codec::unframe(raw).ok_or(BU_DKLS23_ERR_LEN)?;
    if frames.is_empty() {
        return Err(BU_DKLS23_ERR_LEN);
    }
    let mut out = alloc::vec::Vec::with_capacity(frames.len());
    for f in &frames {
        out.push(parse_keyshare(f).map_err(map_err)?);
    }
    let curve = out[0].curve;
    if out.iter().any(|s| s.curve != curve) {
        return Err(BU_DKLS23_ERR_KEY);
    }
    Ok(out)
}

fn parse_seeds(ptr: *const u8, n: usize) -> Result<alloc::vec::Vec<[u8; 32]>, i32> {
    if ptr.is_null() || n == 0 {
        return Err(BU_DKLS23_ERR_LEN);
    }
    let raw = unsafe { slice::from_raw_parts(ptr, n * 32) };
    let mut out = alloc::vec::Vec::with_capacity(n);
    for i in 0..n {
        let mut s = [0u8; 32];
        s.copy_from_slice(&raw[i * 32..(i + 1) * 32]);
        out.push(s);
    }
    Ok(out)
}

/// Full DKG: `seeds(n*32)` → framed shares blob. Writes the blob length
/// to `out_len`; `out_cap` is the caller buffer capacity.
#[no_mangle]
/// # Safety
/// Pointers must reference readable/writable memory of the documented
/// lengths. Null pointers are rejected; short buffers are the caller's
/// responsibility.
pub unsafe extern "C" fn bu_dkls23_dkg(
    curve: u32,
    sid: *const u8,
    sid_len: usize,
    n: usize,
    t: usize,
    seeds: *const u8,
    out: *mut u8,
    out_len: *mut usize,
    out_cap: usize,
) -> i32 {
    if sid.is_null() && sid_len > 0 {
        return BU_DKLS23_ERR_LEN;
    }
    if sid_len == 0 {
        // Empty session ids would replay transcripts across ceremonies.
        return BU_DKLS23_ERR_LEN;
    }
    if out_len.is_null() || n == 0 {
        return BU_DKLS23_ERR_LEN;
    }
    let id = match parse_curve(curve) {
        Ok(c) => c,
        Err(e) => return e,
    };
    // Framed-share length depends only on `n` (fixed record sizes), so
    // length probes (`out == null` / short buffers) are answered without
    // running the ceremony — mirroring the `_roundsFetch` contract:
    // write the needed length, return `ERR_LEN`.
    let share_len = 4 + 4 + 4 + 4 + 32 + 33 + n * 33;
    let need = n * (4 + share_len);
    if out.is_null() || out_cap < need {
        unsafe { *out_len = need };
        return BU_DKLS23_ERR_LEN;
    }
    let sid_bytes =
        if sid_len == 0 { &[][..] } else { slice::from_raw_parts(sid, sid_len) };
    let seed_list = match parse_seeds(seeds, n) {
        Ok(s) => s,
        Err(e) => return e,
    };
    match dkg_oneshot(id, sid_bytes, n, t, &seed_list) {
        Ok(shares) => {
            let frames: alloc::vec::Vec<alloc::vec::Vec<u8>> =
                shares.iter().map(keyshare_bytes).collect();
            let blob = crate::dkls23::codec::frame(&frames);
            if blob.len() > out_cap {
                return BU_DKLS23_ERR_LEN;
            }
            slice::from_raw_parts_mut(out, blob.len()).copy_from_slice(&blob);
            *out_len = blob.len();
            BU_DKLS23_OK
        }
        Err(e) => map_err(e),
    }
}

/// Import existing secrets as an additive n-of-n quorum (no DKG):
/// `secrets(n*32)` → framed shares blob. See
/// [`crate::dkls23::session::import_secrets`].
#[no_mangle]
/// # Safety
/// Pointers must reference readable/writable memory of the documented
/// lengths. Null pointers are rejected; short buffers are the caller's
/// responsibility.
pub unsafe extern "C" fn bu_dkls23_import_secrets(
    curve: u32,
    secrets: *const u8,
    n: usize,
    out: *mut u8,
    out_len: *mut usize,
    out_cap: usize,
) -> i32 {
    if out_len.is_null() || n == 0 {
        return BU_DKLS23_ERR_LEN;
    }
    let id = match parse_curve(curve) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let share_len = 4 + 4 + 4 + 4 + 32 + 33 + n * 33;
    let need = n * (4 + share_len);
    if out.is_null() || out_cap < need {
        unsafe { *out_len = need };
        return BU_DKLS23_ERR_LEN;
    }
    if secrets.is_null() {
        return BU_DKLS23_ERR_LEN;
    }
    let raw = slice::from_raw_parts(secrets, n * 32);
    let mut list = alloc::vec::Vec::with_capacity(n);
    for i in 0..n {
        let mut s = [0u8; 32];
        s.copy_from_slice(&raw[i * 32..(i + 1) * 32]);
        list.push(s);
    }
    match crate::dkls23::session::import_secrets(id, &list) {
        Ok(shares) => {
            let frames: alloc::vec::Vec<alloc::vec::Vec<u8>> =
                shares.iter().map(keyshare_bytes).collect();
            let blob = crate::dkls23::codec::frame(&frames);
            if blob.len() > out_cap {
                return BU_DKLS23_ERR_LEN;
            }
            slice::from_raw_parts_mut(out, blob.len()).copy_from_slice(&blob);
            unsafe { *out_len = blob.len() };
            BU_DKLS23_OK
        }
        Err(e) => map_err(e),
    }
}

/// Threshold sign: framed shares + `seeds(n*32)` + `msg_hash(32)` →
/// compact signature (64 B).
#[no_mangle]
/// # Safety
/// Pointers must reference readable/writable memory of the documented
/// lengths. Null pointers are rejected; short buffers are the caller's
/// responsibility.
pub unsafe extern "C" fn bu_dkls23_sign(
    curve: u32,
    sid: *const u8,
    sid_len: usize,
    msg_hash: *const u8,
    shares_blob: *const u8,
    shares_blob_len: usize,
    seeds: *const u8,
    sig_out: *mut u8,
    sig_len: usize,
) -> i32 {
    if msg_hash.is_null()
        || shares_blob.is_null()
        || sig_out.is_null()
        || shares_blob_len == 0
        || sig_len < 64
    {
        return BU_DKLS23_ERR_LEN;
    }
    if sid.is_null() && sid_len > 0 {
        return BU_DKLS23_ERR_LEN;
    }
    if sid_len == 0 {
        // Empty session ids would replay transcripts across ceremonies.
        return BU_DKLS23_ERR_LEN;
    }
    let id = match parse_curve(curve) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let mut h = [0u8; 32];
    h.copy_from_slice(slice::from_raw_parts(msg_hash, 32));
    let sid_bytes =
        if sid_len == 0 { &[][..] } else { slice::from_raw_parts(sid, sid_len) };
    let raw_shares = slice::from_raw_parts(shares_blob, shares_blob_len);
    let list = match parse_shares_blob(raw_shares) {
        Ok(l) => l,
        Err(e) => return e,
    };
    if list[0].curve != id {
        return BU_DKLS23_ERR_KEY;
    }
    let seed_list = match parse_seeds(seeds, list.len()) {
        Ok(s) => s,
        Err(e) => return e,
    };
    match sign_oneshot(&list, sid_bytes, &h, &seed_list) {
        Ok(sig) => {
            slice::from_raw_parts_mut(sig_out, 64).copy_from_slice(&sig.to_bytes());
            BU_DKLS23_OK
        }
        Err(e) => map_err(e),
    }
}

/// Refresh shares: framed shares in → framed shares out (same framing).
#[no_mangle]
/// # Safety
/// Pointers must reference readable/writable memory of the documented
/// lengths. Null pointers are rejected; short buffers are the caller's
/// responsibility.
pub unsafe extern "C" fn bu_dkls23_refresh(
    sid: *const u8,
    sid_len: usize,
    shares_blob: *const u8,
    shares_blob_len: usize,
    seeds: *const u8,
    out: *mut u8,
    out_len: *mut usize,
    out_cap: usize,
) -> i32 {
    if shares_blob.is_null() || out_len.is_null() || shares_blob_len == 0 {
        return BU_DKLS23_ERR_LEN;
    }
    if sid.is_null() && sid_len > 0 {
        return BU_DKLS23_ERR_LEN;
    }
    if sid_len == 0 {
        // Empty session ids would replay transcripts across ceremonies.
        return BU_DKLS23_ERR_LEN;
    }
    // Output framing matches the input framing exactly (same `n`), so a
    // length probe is answered without running the ceremony.
    if out.is_null() || out_cap < shares_blob_len {
        unsafe { *out_len = shares_blob_len };
        return BU_DKLS23_ERR_LEN;
    }
    let sid_bytes =
        if sid_len == 0 { &[][..] } else { slice::from_raw_parts(sid, sid_len) };
    let raw_shares = slice::from_raw_parts(shares_blob, shares_blob_len);
    let list = match parse_shares_blob(raw_shares) {
        Ok(l) => l,
        Err(e) => return e,
    };
    let seed_list = match parse_seeds(seeds, list.len()) {
        Ok(s) => s,
        Err(e) => return e,
    };
    match refresh_oneshot(&list, sid_bytes, &seed_list) {
        Ok(shares) => {
            let frames: alloc::vec::Vec<alloc::vec::Vec<u8>> =
                shares.iter().map(keyshare_bytes).collect();
            let blob = crate::dkls23::codec::frame(&frames);
            if blob.len() > out_cap {
                return BU_DKLS23_ERR_LEN;
            }
            slice::from_raw_parts_mut(out, blob.len()).copy_from_slice(&blob);
            *out_len = blob.len();
            BU_DKLS23_OK
        }
        Err(e) => map_err(e),
    }
}

/// Verify a compact signature (64 B) against a 33-byte group key.
/// Returns OK / VERIFY / error.
#[no_mangle]
/// # Safety
/// Pointers must reference readable/writable memory of the documented
/// lengths. Null pointers are rejected; short buffers are the caller's
/// responsibility.
pub unsafe extern "C" fn bu_dkls23_verify(
    curve: u32,
    group_pk: *const u8,
    msg_hash: *const u8,
    sig: *const u8,
) -> i32 {
    if group_pk.is_null() || msg_hash.is_null() || sig.is_null() {
        return BU_DKLS23_ERR_LEN;
    }
    let id = match parse_curve(curve) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let mut pk = [0u8; 33];
    let mut h = [0u8; 32];
    let mut raw = [0u8; 64];
    pk.copy_from_slice(slice::from_raw_parts(group_pk, 33));
    h.copy_from_slice(slice::from_raw_parts(msg_hash, 32));
    raw.copy_from_slice(slice::from_raw_parts(sig, 64));
    let cs = match CompactSig::from_bytes(&raw) {
        Ok(s) => s,
        Err(e) => return map_err(e),
    };
    let ok = match id {
        CurveId::K1 => {
            let (Ok(p), Ok(s)) = (
                crate::signature::ecdsa::PublicKey::from_bytes(&pk),
                crate::signature::ecdsa::Signature::from_compact(&cs.to_bytes()),
            ) else {
                return BU_DKLS23_ERR_KEY;
            };
            crate::signature::ecdsa::verify(&p, &h, &s).is_ok()
        }
        CurveId::R1 => {
            let (Ok(p), Ok(s)) = (
                crate::signature::ecdsa_p256::PublicKey::from_bytes(&pk),
                crate::signature::ecdsa_p256::Signature::from_compact(&cs.to_bytes()),
            ) else {
                return BU_DKLS23_ERR_KEY;
            };
            crate::signature::ecdsa_p256::verify(&p, &h, &s).is_ok()
        }
    };
    if ok {
        BU_DKLS23_OK
    } else {
        BU_DKLS23_ERR_VERIFY
    }
}

/// Aggregate member public keys (`members(n*33)`) → group key (33 B).
#[no_mangle]
/// # Safety
/// Pointers must reference readable/writable memory of the documented
/// lengths. Null pointers are rejected; short buffers are the caller's
/// responsibility.
pub unsafe extern "C" fn bu_dkls23_agg_keys(
    curve: u32,
    members: *const u8,
    n: usize,
    agg_out: *mut u8,
    agg_len: usize,
) -> i32 {
    if members.is_null() || agg_out.is_null() || n == 0 || agg_len < 33 {
        return BU_DKLS23_ERR_LEN;
    }
    let id = match parse_curve(curve) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let raw = slice::from_raw_parts(members, n * 33);
    let mut list = alloc::vec::Vec::with_capacity(n);
    for i in 0..n {
        let mut m = [0u8; 33];
        m.copy_from_slice(&raw[i * 33..(i + 1) * 33]);
        list.push(m);
    }
    match crate::dkls23::keys::DklsAggregatePublicKey::agg_public_keys(id, &list) {
        Ok(agg) => {
            slice::from_raw_parts_mut(agg_out, 33).copy_from_slice(agg.group_key());
            BU_DKLS23_OK
        }
        Err(e) => map_err(e),
    }
}

/// X-only form of a group key: `group_pk(33)` → `x(32)`.
#[no_mangle]
/// # Safety
/// Pointers must reference readable/writable memory of the documented
/// lengths. Null pointers are rejected; short buffers are the caller's
/// responsibility.
pub unsafe extern "C" fn bu_dkls23_x_only(
    curve: u32,
    group_pk: *const u8,
    x_out: *mut u8,
    x_len: usize,
) -> i32 {
    if group_pk.is_null() || x_out.is_null() || x_len < 32 {
        return BU_DKLS23_ERR_LEN;
    }
    let id = match parse_curve(curve) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let mut pk = [0u8; 33];
    pk.copy_from_slice(slice::from_raw_parts(group_pk, 33));
    let x: [u8; 32] = match crate::dkls23::keys::group_x_only(id, &pk) {
        Ok(v) => v,
        Err(e) => return map_err(e),
    };
    slice::from_raw_parts_mut(x_out, 32).copy_from_slice(&x);
    BU_DKLS23_OK
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seeds<const N: usize>(base: u8) -> [[u8; 32]; N] {
        let mut out = [[0u8; 32]; N];
        for (i, s) in out.iter_mut().enumerate() {
            for b in s.iter_mut() {
                *b = base.wrapping_add(i as u8);
            }
        }
        out
    }

    /// End-to-end DKG → sign → verify through the raw C boundary.
    #[test]
    fn ffi_dkg_sign_verify_k1() {
        let sid = b"ffi-dkls23-k1";
        let dkg_seeds = seeds::<2>(0xA0);
        let mut blob = [0u8; 4096];
        let mut blob_len = 0usize;
        let mut flat_seeds = [0u8; 64];
        flat_seeds[..32].copy_from_slice(&dkg_seeds[0]);
        flat_seeds[32..].copy_from_slice(&dkg_seeds[1]);
        unsafe {
            assert_eq!(
                bu_dkls23_dkg(
                    0,
                    sid.as_ptr(),
                    sid.len(),
                    2,
                    2,
                    flat_seeds.as_ptr(),
                    blob.as_mut_ptr(),
                    &mut blob_len,
                    blob.len()
                ),
                BU_DKLS23_OK
            );
        }
        assert!(blob_len > 0);
        let h = crate::hash::sha256::sha256(b"ffi threshold").unwrap();
        let sign_seeds = seeds::<2>(0xB0);
        let mut flat_sign = [0u8; 64];
        flat_sign[..32].copy_from_slice(&sign_seeds[0]);
        flat_sign[32..].copy_from_slice(&sign_seeds[1]);
        let mut sig = [0u8; 64];
        unsafe {
            // Wrong-length sig buffer must fail loudly.
            assert_eq!(
                bu_dkls23_sign(
                    0,
                    sid.as_ptr(),
                    sid.len(),
                    h.as_ptr(),
                    blob.as_ptr(),
                    blob_len,
                    flat_sign.as_ptr(),
                    sig.as_mut_ptr(),
                    63
                ),
                BU_DKLS23_ERR_LEN
            );
            assert_eq!(
                bu_dkls23_sign(
                    0,
                    sid.as_ptr(),
                    sid.len(),
                    h.as_ptr(),
                    blob.as_ptr(),
                    blob_len,
                    flat_sign.as_ptr(),
                    sig.as_mut_ptr(),
                    64
                ),
                BU_DKLS23_OK
            );
        }
        let frames = crate::dkls23::codec::unframe(&blob[..blob_len]).unwrap();
        let first = parse_keyshare(&frames[0]).unwrap();
        unsafe {
            assert_eq!(
                bu_dkls23_verify(0, first.pk.as_ptr(), h.as_ptr(), sig.as_ptr()),
                BU_DKLS23_OK
            );
            let bad = crate::hash::sha256::sha256(b"nope").unwrap();
            assert_eq!(
                bu_dkls23_verify(0, first.pk.as_ptr(), bad.as_ptr(), sig.as_ptr()),
                BU_DKLS23_ERR_VERIFY
            );
            // Unknown curve rejected.
            assert_eq!(
                bu_dkls23_verify(9, first.pk.as_ptr(), h.as_ptr(), sig.as_ptr()),
                BU_DKLS23_ERR_KEY
            );
        }
    }

    /// Aggregate + x-only through the C boundary.
    #[test]
    fn ffi_agg_and_xonly() {
        use crate::dkls23::curve_id::{CurveId, DklsPoint};
        let g = DklsPoint::generator(CurveId::K1).to_array_compressed().unwrap();
        let mut members = [0u8; 66];
        members[..33].copy_from_slice(&g);
        members[33..].copy_from_slice(&g);
        let mut agg = [0u8; 33];
        unsafe {
            assert_eq!(
                bu_dkls23_agg_keys(0, members.as_ptr(), 2, agg.as_mut_ptr(), 33),
                BU_DKLS23_OK
            );
            // Singleton rejected.
            assert_eq!(
                bu_dkls23_agg_keys(0, members.as_ptr(), 1, agg.as_mut_ptr(), 33),
                BU_DKLS23_ERR_LEN
            );
            // Unknown curve rejected.
            assert_eq!(
                bu_dkls23_agg_keys(9, members.as_ptr(), 2, agg.as_mut_ptr(), 33),
                BU_DKLS23_ERR_KEY
            );
        }
        let expect = DklsPoint::generator(CurveId::K1)
            .add(&DklsPoint::generator(CurveId::K1))
            .to_array_compressed()
            .unwrap();
        assert_eq!(agg, expect);
        let mut x = [0u8; 32];
        unsafe {
            assert_eq!(bu_dkls23_x_only(0, agg.as_ptr(), x.as_mut_ptr(), 32), BU_DKLS23_OK);
        }
        assert_eq!(&x, &agg[1..33]);
    }

    /// Refresh through the C boundary keeps the group key.
    #[test]
    fn ffi_refresh_r1() {
        let sid = b"ffi-dkls23-r1";
        let dkg_seeds = seeds::<2>(0xC0);
        let mut blob = [0u8; 4096];
        let mut blob_len = 0usize;
        let mut flat = [0u8; 64];
        flat[..32].copy_from_slice(&dkg_seeds[0]);
        flat[32..].copy_from_slice(&dkg_seeds[1]);
        unsafe {
            assert_eq!(
                bu_dkls23_dkg(
                    1,
                    sid.as_ptr(),
                    sid.len(),
                    2,
                    2,
                    flat.as_ptr(),
                    blob.as_mut_ptr(),
                    &mut blob_len,
                    blob.len()
                ),
                BU_DKLS23_OK
            );
            let rseeds = seeds::<2>(0xD0);
            let mut rflat = [0u8; 64];
            rflat[..32].copy_from_slice(&rseeds[0]);
            rflat[32..].copy_from_slice(&rseeds[1]);
            let mut out = [0u8; 4096];
            let mut out_len = 0usize;
            assert_eq!(
                bu_dkls23_refresh(
                    b"r1".as_ptr(),
                    2,
                    blob.as_ptr(),
                    blob_len,
                    rflat.as_ptr(),
                    out.as_mut_ptr(),
                    &mut out_len,
                    out.len()
                ),
                BU_DKLS23_OK
            );
            let before = parse_keyshare(&crate::dkls23::codec::unframe(&blob[..blob_len]).unwrap()[0])
                .unwrap();
            let after =
                parse_keyshare(&crate::dkls23::codec::unframe(&out[..out_len]).unwrap()[0])
                    .unwrap();
            assert_eq!(before.pk, after.pk);
            assert_ne!(before.x, after.x);
        }
    }
}
