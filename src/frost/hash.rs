//! Hash helpers for the FROST ciphersuites (RFC 9591 Sections 6.1, 6.5).
//!
//! - secp256k1/SHA-256: `H1`/`H2`/`H3` via `hash_to_field` (RFC 9380
//!   Section 5.2) with `expand_message_xmd` (SHA-256, `L = 48`).
//! - Ed25519/SHA-512: `H1`/`H2`/`H3` via a single SHA-512 call reduced
//!   mod `L` (little-endian); `H4`/`H5` are raw digests in both suites.
//!
//! Secret inputs (nonces, shares) only enter SHA-256/SHA-512 and the
//! constant-time scalar backend; no branching on secret data here.

use super::error::{FrostError, FrostResult};
use alloc::vec::Vec;

/// One-shot SHA-256.
pub fn sha256(data: &[u8]) -> FrostResult<[u8; 32]> {
    crate::hash::sha256::sha256(data).map_err(|_| FrostError::Internal)
}

/// One-shot SHA-512.
pub fn sha512(data: &[u8]) -> FrostResult<[u8; 64]> {
    crate::hash::sha512::sha512(data).map_err(|_| FrostError::Internal)
}

/// `expand_message_xmd` (RFC 9380 Section 5.3) with SHA-256.
///
/// `b_in_bytes = 32`, `s_in_bytes = 64`.
pub fn expand_message_xmd_sha256(
    msg: &[u8],
    dst: &[u8],
    len_in_bytes: usize,
) -> FrostResult<Vec<u8>> {
    const B_IN: usize = 32;
    const S_IN: usize = 64;
    if len_in_bytes > 255 * B_IN || dst.len() > 255 {
        return Err(FrostError::InvalidLength);
    }
    if len_in_bytes == 0 {
        return Ok(Vec::new());
    }
    let ell = len_in_bytes.div_ceil(B_IN);

    let mut dst_prime = Vec::with_capacity(dst.len() + 1);
    dst_prime.extend_from_slice(dst);
    dst_prime.push(dst.len() as u8);

    let z_pad = [0u8; S_IN];
    let l_i_b = [(len_in_bytes >> 8) as u8, (len_in_bytes & 0xff) as u8];

    // b_0 = H(Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime)
    let mut pre = Vec::with_capacity(S_IN + msg.len() + 2 + 1 + dst_prime.len());
    pre.extend_from_slice(&z_pad);
    pre.extend_from_slice(msg);
    pre.extend_from_slice(&l_i_b);
    pre.push(0u8);
    pre.extend_from_slice(&dst_prime);
    let b0 = sha256(&pre)?;

    // b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
    let mut b1_in = Vec::with_capacity(B_IN + 1 + dst_prime.len());
    b1_in.extend_from_slice(&b0);
    b1_in.push(1u8);
    b1_in.extend_from_slice(&dst_prime);
    let mut bi = sha256(&b1_in)?;

    let mut uniform = Vec::with_capacity(ell * B_IN);
    uniform.extend_from_slice(&bi);
    let mut i: u8 = 2;
    while uniform.len() < ell * B_IN {
        let mut xored = [0u8; B_IN];
        for j in 0..B_IN {
            xored[j] = b0[j] ^ bi[j];
        }
        let mut bin = Vec::with_capacity(B_IN + 1 + dst_prime.len());
        bin.extend_from_slice(&xored);
        bin.push(i);
        bin.extend_from_slice(&dst_prime);
        bi = sha256(&bin)?;
        uniform.extend_from_slice(&bi);
        i = i.wrapping_add(1);
    }
    uniform.truncate(len_in_bytes);
    Ok(uniform)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn xmd_rfc9380_vector() {
        // RFC 9380 Appendix H.4: expand_message_xmd(SHA-256),
        // DST = "QUUX-V01-CS02-with-expander-SHA256-128", len 32.
        let dst = b"QUUX-V01-CS02-with-expander-SHA256-128";
        let out = expand_message_xmd_sha256(b"", dst, 0x20).unwrap();
        // RFC 9380 Appendix K vector (also pinned in curve::bls tests).
        let expected: [u8; 32] = [
            0x68, 0xa9, 0x85, 0xb8, 0x7e, 0xb6, 0xb4, 0x69, 0x52, 0x12, 0x89, 0x11, 0xf2, 0xa4,
            0x41, 0x2b, 0xbc, 0x30, 0x2a, 0x9d, 0x75, 0x96, 0x67, 0xf8, 0x7f, 0x7a, 0x21, 0xd8,
            0x03, 0xf0, 0x72, 0x35,
        ];
        assert_eq!(out.as_slice(), &expected[..]);
        let _ = vec![0u8; 1];
    }

    #[test]
    fn xmd_lengths() {
        let out = expand_message_xmd_sha256(b"abc", b"DST", 48).unwrap();
        assert_eq!(out.len(), 48);
        let out2 = expand_message_xmd_sha256(b"abc", b"DST", 48).unwrap();
        assert_eq!(out, out2);
        let out3 = expand_message_xmd_sha256(b"abd", b"DST", 48).unwrap();
        assert_ne!(out, out3);
    }
}
