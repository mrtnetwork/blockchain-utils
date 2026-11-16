//! PBKDF2 (RFC 8018 / PKCS #5 v2.1).
//!
//! Implemented with HMAC-SHA256 and HMAC-SHA512.
//! Pure `no_std` (+ `alloc` when salt is large, e.g. scrypt’s second PBKDF2).

use super::error::{HashError, HashResult};
use super::hmac::{hmac_sha256, hmac_sha512};
use super::sha256::SHA256_LEN;
use super::sha512::SHA512_LEN;

/// PBKDF2-HMAC-SHA256.
///
/// `dk` is the derived key output buffer.
/// `iterations` must be >= 1.
pub fn pbkdf2_hmac_sha256(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    dk: &mut [u8],
) -> HashResult<()> {
    if iterations == 0 {
        return Err(HashError::InvalidIterations);
    }
    pbkdf2_sha256(password, salt, iterations, dk)
}

/// PBKDF2-HMAC-SHA512.
pub fn pbkdf2_hmac_sha512(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    dk: &mut [u8],
) -> HashResult<()> {
    if iterations == 0 {
        return Err(HashError::InvalidIterations);
    }
    pbkdf2_sha512(password, salt, iterations, dk)
}

fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32, dk: &mut [u8]) -> HashResult<()> {
    let hlen = SHA256_LEN;
    let mut block = 1u32;
    let mut offset = 0;

    // salt || INT(i) — support large salts (scrypt second stage)
    #[cfg(feature = "alloc")]
    let mut msg_owned: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    let mut msg_stack = [0u8; 256];

    while offset < dk.len() {
        let msg: &[u8] = {
            let need = salt.len().checked_add(4).ok_or(HashError::InvalidLength)?;
            #[cfg(feature = "alloc")]
            {
                if need > msg_stack.len() {
                    msg_owned.resize(need, 0);
                    msg_owned[..salt.len()].copy_from_slice(salt);
                    msg_owned[salt.len()..need].copy_from_slice(&block.to_be_bytes());
                    &msg_owned[..need]
                } else {
                    msg_stack[..salt.len()].copy_from_slice(salt);
                    msg_stack[salt.len()..need].copy_from_slice(&block.to_be_bytes());
                    &msg_stack[..need]
                }
            }
            #[cfg(not(feature = "alloc"))]
            {
                if need > msg_stack.len() {
                    return Err(HashError::InvalidLength);
                }
                msg_stack[..salt.len()].copy_from_slice(salt);
                msg_stack[salt.len()..need].copy_from_slice(&block.to_be_bytes());
                &msg_stack[..need]
            }
        };

        let mut u = hmac_sha256(password, msg).map_err(|_| HashError::InvalidLength)?;
        let mut t = u;
        for _ in 1..iterations {
            u = hmac_sha256(password, &u).map_err(|_| HashError::InvalidLength)?;
            for i in 0..hlen {
                t[i] ^= u[i];
            }
        }

        let take = core::cmp::min(hlen, dk.len() - offset);
        dk[offset..offset + take].copy_from_slice(&t[..take]);
        offset += take;
        block = block.wrapping_add(1);
    }
    Ok(())
}

fn pbkdf2_sha512(password: &[u8], salt: &[u8], iterations: u32, dk: &mut [u8]) -> HashResult<()> {
    let hlen = SHA512_LEN;
    let mut block = 1u32;
    let mut offset = 0;

    #[cfg(feature = "alloc")]
    let mut msg_owned: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    let mut msg_stack = [0u8; 512];

    while offset < dk.len() {
        let msg: &[u8] = {
            let need = salt.len().checked_add(4).ok_or(HashError::InvalidLength)?;
            #[cfg(feature = "alloc")]
            {
                if need > msg_stack.len() {
                    msg_owned.resize(need, 0);
                    msg_owned[..salt.len()].copy_from_slice(salt);
                    msg_owned[salt.len()..need].copy_from_slice(&block.to_be_bytes());
                    &msg_owned[..need]
                } else {
                    msg_stack[..salt.len()].copy_from_slice(salt);
                    msg_stack[salt.len()..need].copy_from_slice(&block.to_be_bytes());
                    &msg_stack[..need]
                }
            }
            #[cfg(not(feature = "alloc"))]
            {
                if need > msg_stack.len() {
                    return Err(HashError::InvalidLength);
                }
                msg_stack[..salt.len()].copy_from_slice(salt);
                msg_stack[salt.len()..need].copy_from_slice(&block.to_be_bytes());
                &msg_stack[..need]
            }
        };

        let mut u = hmac_sha512(password, msg).map_err(|_| HashError::InvalidLength)?;
        let mut t = u;
        for _ in 1..iterations {
            u = hmac_sha512(password, &u).map_err(|_| HashError::InvalidLength)?;
            for i in 0..hlen {
                t[i] ^= u[i];
            }
        }

        let take = core::cmp::min(hlen, dk.len() - offset);
        dk[offset..offset + take].copy_from_slice(&t[..take]);
        offset += take;
        block = block.wrapping_add(1);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_salt_16384() {
        let salt: alloc::vec::Vec<u8> = (0..16384u32).map(|i| (i % 256) as u8).collect();
        let mut dk = [0u8; 64];
        pbkdf2_hmac_sha256(b"password", &salt, 1, &mut dk).unwrap();
        let h = "bd046a29e5279d7468ac899b318104b1047ad9ef5a6043e59ec3591649578f99a7025b2f2cd01c6ff5d8eb353424690272339288e45cbdd49567c4d095e4fbd0";
        let mut exp = [0u8; 64];
        for i in 0..64 {
            exp[i] = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap();
        }
        assert_eq!(dk, exp);
    }

    #[test]
    fn pbkdf2_sha256_rfc6070() {
        // RFC 6070-style (password/salt/c=1/dkLen=20) for SHA-256
        // (RFC 6070 itself publishes SHA-1 vectors; SHA-256 value matches hashlib)
        let mut dk = [0u8; 20];
        pbkdf2_hmac_sha256(b"password", b"salt", 1, &mut dk).unwrap();
        assert_eq!(
            dk,
            [
                0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c, 0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4,
                0xf8, 0x37, 0xa8, 0x65, 0x48, 0xc9,
            ]
        );
        // c=4096, dkLen=20
        let mut dk2 = [0u8; 20];
        pbkdf2_hmac_sha256(b"password", b"salt", 4096, &mut dk2).unwrap();
        assert_eq!(
            dk2,
            [
                0xc5, 0xe4, 0x78, 0xd5, 0x92, 0x88, 0xc8, 0x41, 0xaa, 0x53, 0x0d, 0xb6, 0x84, 0x5c,
                0x4c, 0x8d, 0x96, 0x28, 0x93, 0xa0,
            ]
        );
    }
}
