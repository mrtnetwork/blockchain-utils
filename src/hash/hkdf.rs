//! HKDF (RFC 5869) – Extract and Expand.
//!
//! Built on HMAC-SHA256 / HMAC-SHA512. Pure `no_std`, zero-dependency.

use super::error::{HashError, HashResult};
use super::hmac::{hmac_sha256, hmac_sha512, Hmac};
use super::sha256::{Sha256, SHA256_LEN};
use super::sha512::{Sha512, BLOCK_SIZE as SHA512_BLOCK, SHA512_LEN};

/// HKDF-Extract with SHA-256.
///
/// `prk` must be at least 32 bytes.
pub fn hkdf_extract_sha256(salt: &[u8], ikm: &[u8], prk: &mut [u8]) -> crate::hash::HashResult<()> {
    if prk.len() < SHA256_LEN {
        return Err(crate::hash::HashError::OutputTooSmall);
    }
    let salt = if salt.is_empty() {
        &[0u8; SHA256_LEN][..]
    } else {
        salt
    };
    let tag = hmac_sha256(salt, ikm)?;
    prk[..SHA256_LEN].copy_from_slice(&tag);
    Ok(())
}

/// HKDF-Expand with SHA-256.
///
/// `okm` length must be <= 255 * 32.
pub fn hkdf_expand_sha256(prk: &[u8], info: &[u8], okm: &mut [u8]) -> HashResult<()> {
    let hash_len = SHA256_LEN;
    if okm.is_empty() {
        return Ok(());
    }
    let n = okm.len().div_ceil(hash_len);
    if n > 255 {
        return Err(HashError::InvalidLength);
    }

    let mut t = [0u8; SHA256_LEN];
    let mut t_len = 0;
    let mut offset = 0;

    for i in 1..=n {
        // T(i) = HMAC(PRK, T(i-1) | info | i), fed incrementally:
        // no input-size limit, O(1) stack.
        let mut mac = Hmac::<Sha256>::new(prk)?;
        if t_len > 0 {
            mac.update(&t[..t_len]);
        }
        mac.update(info);
        mac.update(&[i as u8]);
        let full = mac.finalize_array()?;
        t[..hash_len].copy_from_slice(&full[..hash_len]);
        t_len = hash_len;

        let take = core::cmp::min(hash_len, okm.len() - offset);
        okm[offset..offset + take].copy_from_slice(&t[..take]);
        offset += take;
    }
    Ok(())
}

/// Convenience: Extract + Expand with SHA-256.
pub fn hkdf_sha256(
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    okm: &mut [u8],
) -> crate::hash::HashResult<()> {
    let mut prk = [0u8; SHA256_LEN];
    hkdf_extract_sha256(salt, ikm, &mut prk)?;
    hkdf_expand_sha256(&prk, info, okm)
}

/// Convenience: Extract + Expand with SHA-512.
pub fn hkdf_sha512(
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    okm: &mut [u8],
) -> crate::hash::HashResult<()> {
    let mut prk = [0u8; SHA512_LEN];
    hkdf_extract_sha512(salt, ikm, &mut prk)?;
    hkdf_expand_sha512(&prk, info, okm)
}

/// HKDF-Extract with SHA-512.
pub fn hkdf_extract_sha512(salt: &[u8], ikm: &[u8], prk: &mut [u8]) -> crate::hash::HashResult<()> {
    if prk.len() < SHA512_LEN {
        return Err(crate::hash::HashError::OutputTooSmall);
    }
    let salt = if salt.is_empty() {
        &[0u8; SHA512_LEN][..]
    } else {
        salt
    };
    let tag = hmac_sha512(salt, ikm)?;
    prk[..SHA512_LEN].copy_from_slice(&tag);
    Ok(())
}

/// HKDF-Expand with SHA-512.
pub fn hkdf_expand_sha512(prk: &[u8], info: &[u8], okm: &mut [u8]) -> HashResult<()> {
    let hash_len = SHA512_LEN;
    if okm.is_empty() {
        return Ok(());
    }
    let n = okm.len().div_ceil(hash_len);
    if n > 255 {
        return Err(HashError::InvalidLength);
    }

    let mut t = [0u8; SHA512_LEN];
    let mut t_len = 0;
    let mut offset = 0;

    for i in 1..=n {
        // T(i) = HMAC-SHA512(PRK, T(i-1) | info | i), fed incrementally:
        // no input-size limit, O(1) stack. (`Sha512` has no `Digest` impl,
        // so the pads are handled explicitly instead of via `Hmac<H>`.)
        let (ipad, opad) = hmac_sha512_pads(prk)?;
        let mut inner = Sha512::new();
        inner.update(&ipad);
        if t_len > 0 {
            inner.update(&t[..t_len]);
        }
        inner.update(info);
        inner.update(&[i as u8]);
        let inner_hash = inner.finalize();
        let mut outer = Sha512::new();
        outer.update(&opad);
        outer.update(&inner_hash);
        let tag = outer.finalize();
        t[..hash_len].copy_from_slice(&tag[..hash_len]);
        t_len = hash_len;

        let take = core::cmp::min(hash_len, okm.len() - offset);
        okm[offset..offset + take].copy_from_slice(&t[..take]);
        offset += take;
    }
    Ok(())
}

/// HMAC-SHA512 ipad/opad for `key` (long keys are hashed first, per RFC 2104).
fn hmac_sha512_pads(key: &[u8]) -> HashResult<([u8; SHA512_BLOCK], [u8; SHA512_BLOCK])> {
    let mut k = [0u8; SHA512_BLOCK];
    if key.len() > SHA512_BLOCK {
        let h = super::sha512::sha512(key)?;
        k[..SHA512_LEN].copy_from_slice(&h);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; SHA512_BLOCK];
    let mut opad = [0x5cu8; SHA512_BLOCK];
    for i in 0..SHA512_BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    Ok((ipad, opad))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc5869_case1() {
        // RFC 5869 Test Case 1 (SHA-256)
        let ikm = [0x0bu8; 22];
        let salt = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let mut okm = [0u8; 42];
        hkdf_sha256(&salt, &ikm, &info, &mut okm).unwrap();
        assert_eq!(
            &okm[..],
            &[
                0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
                0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
                0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65
            ]
        );
    }

    #[test]
    fn rfc5869_case2_long() {
        // RFC 5869 Test Case 2 (SHA-256, 80-byte IKM/salt/info, L=82).
        let ikm: Vec<u8> = (0x00u8..=0x4fu8).collect();
        let salt: Vec<u8> = (0x60u8..=0xafu8).collect();
        let info: Vec<u8> = (0xb0u8..=0xffu8).collect();
        let mut okm = [0u8; 82];
        hkdf_sha256(&salt, &ikm, &info, &mut okm).unwrap();
        assert_eq!(
            &okm[..],
            &[
                0xb1, 0x1e, 0x39, 0x8d, 0xc8, 0x03, 0x27, 0xa1, 0xc8, 0xe7, 0xf7, 0x8c, 0x59, 0x6a,
                0x49, 0x34, 0x4f, 0x01, 0x2e, 0xda, 0x2d, 0x4e, 0xfa, 0xd8, 0xa0, 0x50, 0xcc, 0x4c,
                0x19, 0xaf, 0xa9, 0x7c, 0x59, 0x04, 0x5a, 0x99, 0xca, 0xc7, 0x82, 0x72, 0x71, 0xcb,
                0x41, 0xc6, 0x5e, 0x59, 0x0e, 0x09, 0xda, 0x32, 0x75, 0x60, 0x0c, 0x2f, 0x09, 0xb8,
                0x36, 0x77, 0x93, 0xa9, 0xac, 0xa3, 0xdb, 0x71, 0xcc, 0x30, 0xc5, 0x81, 0x79, 0xec,
                0x3e, 0x87, 0xc1, 0x4c, 0x01, 0xd5, 0xc1, 0xf3, 0x43, 0x4f, 0x1d, 0x87
            ]
        );
    }

    #[test]
    fn rfc5869_case3_empty_salt_info() {
        // RFC 5869 Test Case 3 (SHA-256, empty salt/info → 32 zero salt).
        let ikm = [0x0bu8; 22];
        let mut okm = [0u8; 42];
        hkdf_sha256(&[], &ikm, &[], &mut okm).unwrap();
        assert_eq!(
            &okm[..],
            &[
                0x8d, 0xa4, 0xe7, 0x75, 0xa5, 0x63, 0xc1, 0x8f, 0x71, 0x5f, 0x80, 0x2a, 0x06, 0x3c,
                0x5a, 0x31, 0xb8, 0xa1, 0x1f, 0x5c, 0x5e, 0xe1, 0x87, 0x9e, 0xc3, 0x45, 0x4e, 0x5f,
                0x3c, 0x73, 0x8d, 0x2d, 0x9d, 0x20, 0x13, 0x95, 0xfa, 0xa4, 0xb6, 0x1a, 0x96, 0xc8
            ]
        );
    }

    #[test]
    fn sha512_self_consistent() {
        // No RFC 5869 vectors exist for SHA-512; lock determinism, length
        // handling and domain separation instead (cross-backend equality is
        // asserted by the reference FFI suite).
        let ikm = [0x0bu8; 22];
        let salt: Vec<u8> = (0x00u8..0x0du8).collect();
        let info: Vec<u8> = (0xf0u8..0xfau8).collect();
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        hkdf_sha512(&salt, &ikm, &info, &mut a).unwrap();
        hkdf_sha512(&salt, &ikm, &info, &mut b).unwrap();
        assert_eq!(a, b);
        let mut empty = [0u8; 42];
        hkdf_sha512(&[], &ikm, &[], &mut empty).unwrap();
        assert_ne!(&a[..42], &empty[..]);
        // Over-limit length still fails (RFC 5869 §3.1: N <= 255).
        let mut too_long = alloc::vec![0u8; 255 * 64 + 1];
        assert!(hkdf_sha512(&salt, &ikm, &info, &mut too_long).is_err());
    }

    #[test]
    fn long_info_sizes() {
        // Formerly capped by 512B (SHA-256) / 1024B (SHA-512) stack buffers.
        let ikm = [0x0bu8; 22];
        let salt: Vec<u8> = (0x00u8..0x0du8).collect();
        for len in [0usize, 10, 10 * 1024] {
            let info: Vec<u8> = (0..len).map(|i| ((i * 5 + 1) & 0xff) as u8).collect();
            let mut okm256 = [0u8; 64];
            hkdf_sha256(&salt, &ikm, &info, &mut okm256).unwrap();
            let mut okm256b = [0u8; 64];
            hkdf_sha256(&salt, &ikm, &info, &mut okm256b).unwrap();
            assert_eq!(okm256, okm256b, "sha256 info len={len}");
            let mut okm512 = [0u8; 64];
            hkdf_sha512(&salt, &ikm, &info, &mut okm512).unwrap();
            let mut okm512b = [0u8; 64];
            hkdf_sha512(&salt, &ikm, &info, &mut okm512b).unwrap();
            assert_eq!(okm512, okm512b, "sha512 info len={len}");
            // Different info lengths give different outputs.
            if len > 0 {
                let mut empty = [0u8; 64];
                hkdf_sha256(&salt, &ikm, &[], &mut empty).unwrap();
                assert_ne!(okm256, empty, "sha256 len={len}");
            }
        }
    }
}
