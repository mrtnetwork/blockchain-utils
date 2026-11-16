//! PBKDF2 + scrypt + HKDF C ABI.
//!
//! HKDF accepts any HMAC-capable hash algo id (`BU_HASH_*`), same set as HMAC.

use alloc::vec::Vec;
use core::slice;

use super::hash::{
    algo_digest_len, algo_hmac_supported, hmac_oneshot, BU_HASH_SHA256, BU_HASH_SHA512,
};
use crate::hash::pbkdf2::{pbkdf2_hmac_sha256, pbkdf2_hmac_sha512};
use crate::hash::scrypt::{scrypt, ScryptParams};

pub const BU_PBKDF2_SHA256: u32 = 1;
pub const BU_PBKDF2_SHA512: u32 = 2;

/// Legacy aliases (SHA-256 / SHA-512) — prefer passing `BU_HASH_*` directly.
pub const BU_HKDF_SHA256: u32 = BU_HASH_SHA256;
pub const BU_HKDF_SHA512: u32 = BU_HASH_SHA512;

/// PBKDF2-HMAC. Returns 0 on success.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_pbkdf2(
    prf: u32,
    password: *const u8,
    password_len: usize,
    salt: *const u8,
    salt_len: usize,
    iterations: u32,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if out.is_null() || out_len == 0 || iterations == 0 {
        return -1;
    }
    let password = if password.is_null() || password_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(password, password_len)
    };
    let salt = if salt.is_null() || salt_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(salt, salt_len)
    };
    let out = slice::from_raw_parts_mut(out, out_len);
    // Accept legacy KDF ids (1/2) and BuHashAlgo ids (sha256=1, sha512=3).
    let res = match prf {
        1 => {
            // BU_PBKDF2_SHA256 and BU_HASH_SHA256 (both 1)
            pbkdf2_hmac_sha256(password, salt, iterations, out)
        }
        BU_PBKDF2_SHA512 | BU_HASH_SHA512 => pbkdf2_hmac_sha512(password, salt, iterations, out),
        _ => return -2,
    };
    match res {
        Ok(()) => 0,
        Err(_) => -3,
    }
}

/// scrypt (RFC 7914). Returns 0 on success.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_scrypt(
    password: *const u8,
    password_len: usize,
    salt: *const u8,
    salt_len: usize,
    n: u32,
    r: u32,
    p: u32,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if out.is_null() || out_len == 0 {
        return -1;
    }
    let password = if password.is_null() || password_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(password, password_len)
    };
    let salt = if salt.is_null() || salt_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(salt, salt_len)
    };
    let out = slice::from_raw_parts_mut(out, out_len);
    let params = ScryptParams { n, r, p };
    match scrypt(password, salt, params, out) {
        Ok(()) => 0,
        Err(_) => -3,
    }
}

/// HKDF-Extract + Expand (RFC 5869) with any HMAC-capable hash.
///
/// `prf` is a `BU_HASH_*` algorithm id (same as HMAC). Legacy `BU_HKDF_SHA256`
/// / `BU_HKDF_SHA512` equal `BU_HASH_SHA256` / `BU_HASH_SHA512`.
/// The legacy connector KDF id `2` also maps to SHA-512 (it collides with
/// `BU_HASH_SHA224`, which is therefore not addressable here — HKDF-SHA224
/// is non-standard anyway).
///
/// Empty salt → HashLen zero bytes. `info` may be empty.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hkdf(
    prf: u32,
    ikm: *const u8,
    ikm_len: usize,
    salt: *const u8,
    salt_len: usize,
    info: *const u8,
    info_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if out.is_null() || out_len == 0 {
        return -1;
    }
    if ikm_len > 0 && ikm.is_null() {
        return -1;
    }
    // Legacy connector KDF ids (1 = SHA-256, 2 = SHA-512); anything else
    // passes through as a BU_HASH_* id.
    let prf = match prf {
        2 => BU_HASH_SHA512,
        x => x,
    };
    if !algo_hmac_supported(prf) {
        return -2;
    }
    let hash_len = match algo_digest_len(prf) {
        Some(n) => n,
        None => return -2,
    };
    let ikm = if ikm_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(ikm, ikm_len)
    };
    let salt_owned: Vec<u8>;
    let salt = if salt.is_null() || salt_len == 0 {
        salt_owned = alloc::vec![0u8; hash_len];
        salt_owned.as_slice()
    } else {
        slice::from_raw_parts(salt, salt_len)
    };
    let info = if info.is_null() || info_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(info, info_len)
    };
    let out = slice::from_raw_parts_mut(out, out_len);

    // Extract: PRK = HMAC(salt, IKM)
    let mut prk = alloc::vec![0u8; hash_len];
    if !hmac_oneshot(prf, salt, ikm, &mut prk) {
        return -3;
    }

    // Expand
    let n = out_len.div_ceil(hash_len);
    if n > 255 {
        return -4;
    }
    let mut t = alloc::vec![0u8; hash_len];
    let mut t_len = 0usize;
    let mut offset = 0usize;
    for i in 1..=n {
        // msg = T(i-1) || info || i
        let mut msg = Vec::with_capacity(t_len + info.len() + 1);
        if t_len > 0 {
            msg.extend_from_slice(&t[..t_len]);
        }
        msg.extend_from_slice(info);
        msg.push(i as u8);
        if !hmac_oneshot(prf, &prk, &msg, &mut t) {
            return -3;
        }
        t_len = hash_len;
        let take = core::cmp::min(hash_len, out_len - offset);
        out[offset..offset + take].copy_from_slice(&t[..take]);
        offset += take;
    }
    // wipe
    for b in prk.iter_mut().chain(t.iter_mut()) {
        *b = 0;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connector::ffi::hash::{BU_HASH_SHA1, BU_HASH_SHA256, BU_HASH_SHA512};

    #[test]
    fn pbkdf2_sha256_basic() {
        let pass = b"password";
        let salt = b"salt";
        let mut out = [0u8; 32];
        let rc = unsafe {
            bu_pbkdf2(
                BU_PBKDF2_SHA256,
                pass.as_ptr(),
                pass.len(),
                salt.as_ptr(),
                salt.len(),
                1,
                out.as_mut_ptr(),
                out.len(),
            )
        };
        assert_eq!(rc, 0);
        assert!(out.iter().any(|&b| b != 0));
    }

    #[test]
    fn hkdf_sha256_basic() {
        let ikm = b"input key material";
        let mut out = [0u8; 42];
        let rc = unsafe {
            bu_hkdf(
                BU_HASH_SHA256,
                ikm.as_ptr(),
                ikm.len(),
                core::ptr::null(),
                0,
                core::ptr::null(),
                0,
                out.as_mut_ptr(),
                out.len(),
            )
        };
        assert_eq!(rc, 0);
        assert!(out.iter().any(|&b| b != 0));
    }

    #[test]

    fn pbkdf2_accepts_hash_algo_sha512_id() {
        // BuKdfPrf.sha512 == BuHashAlgo.sha512 == 3
        let password = b"password";
        let salt = b"salt";
        let mut out = [0u8; 32];
        unsafe {
            let rc = bu_pbkdf2(
                3, // BuHashAlgo.sha512
                password.as_ptr(),
                password.len(),
                salt.as_ptr(),
                salt.len(),
                2,
                out.as_mut_ptr(),
                out.len(),
            );
            assert_eq!(rc, 0, "prf=3 must be accepted");
            assert!(out.iter().any(|&b| b != 0));
        }
        let mut out_legacy = [0u8; 32];
        unsafe {
            let rc = bu_pbkdf2(
                BU_PBKDF2_SHA512, // 2
                password.as_ptr(),
                password.len(),
                salt.as_ptr(),
                salt.len(),
                2,
                out_legacy.as_mut_ptr(),
                out_legacy.len(),
            );
            assert_eq!(rc, 0);
        }
        assert_eq!(out, out_legacy);
    }

    #[test]
    fn hkdf_sha512_and_sha1() {
        let ikm = b"ikm-data";
        let mut out512 = [0u8; 64];
        let mut out1 = [0u8; 20];
        unsafe {
            assert_eq!(
                bu_hkdf(
                    BU_HASH_SHA512,
                    ikm.as_ptr(),
                    ikm.len(),
                    core::ptr::null(),
                    0,
                    b"info".as_ptr(),
                    4,
                    out512.as_mut_ptr(),
                    out512.len(),
                ),
                0
            );
            assert_eq!(
                bu_hkdf(
                    BU_HASH_SHA1,
                    ikm.as_ptr(),
                    ikm.len(),
                    core::ptr::null(),
                    0,
                    core::ptr::null(),
                    0,
                    out1.as_mut_ptr(),
                    out1.len(),
                ),
                0
            );
        }
        assert!(out512.iter().any(|&b| b != 0));
        assert!(out1.iter().any(|&b| b != 0));
    }

    #[test]
    fn hmac_oneshot_matches_ffi_hmac() {
        use crate::connector::ffi::hash::{
            bu_hash_finish, bu_hash_free, bu_hash_new, bu_hash_update, BuHashConfig,
            BU_HASH_FLAG_HMAC,
        };
        let key = b"key";
        let data = b"data";
        let mut oneshot = [0u8; 32];
        assert!(hmac_oneshot(BU_HASH_SHA256, key, data, &mut oneshot));

        let cfg = BuHashConfig {
            algo: BU_HASH_SHA256,
            digest_len: 32,
            flags: BU_HASH_FLAG_HMAC,
            key: key.as_ptr(),
            key_len: key.len(),
            salt: core::ptr::null(),
            salt_len: 0,
            personal: core::ptr::null(),
            personal_len: 0,
            seed: 0,
            fanout: 0,
            max_depth: 0,
            leaf_size: 0,
            node_offset: 0,
            node_depth: 0,
            inner_digest_length: 0,
            last_node: 0,
            _pad: [0; 5],
        };
        unsafe {
            let h = bu_hash_new(&cfg);
            bu_hash_update(h, data.as_ptr(), data.len());
            let mut stream = [0u8; 32];
            bu_hash_finish(h, stream.as_mut_ptr());
            bu_hash_free(h);
            assert_eq!(oneshot, stream);
        }
    }
}
