//! ChaCha20-Poly1305 AEAD.
//!
//! Compatible with RFC 8439 (12-byte nonce) and the original layout
//! that also accepts 8-byte (and up to 16-byte) nonces.
//!
//! Nonce layout (matches `blockchain_utils` reference):
//! ```text
//! nc = [0u8; 16]
//! nc[(16 - nonce.len())..] = nonce
//! // first 4 bytes = little-endian block counter
//! ```
//! Block 0 → Poly1305 one-time key; encryption starts at counter 1.

use super::Aead;
use crate::cipher::chacha20::chacha20_block_nc;
use crate::cipher::error::{CipherError, CipherResult};
use crate::cipher::poly1305::Poly1305;
use crate::ct::{ct_eq, ct_zeroize};

/// ChaCha20-Poly1305 marker type implementing [`Aead`].
///
/// `NONCE_LEN` is the IETF default (12). The free functions also accept 8..=16.
pub struct ChaCha20Poly1305;

impl Aead for ChaCha20Poly1305 {
    const KEY_LEN: usize = 32;
    const NONCE_LEN: usize = 12;
    const TAG_LEN: usize = 16;

    fn encrypt(
        key: &[u8],
        nonce: &[u8],
        plaintext: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> CipherResult<()> {
        chacha20_poly1305_encrypt(key, nonce, plaintext, aad, out)
    }

    fn decrypt(
        key: &[u8],
        nonce: &[u8],
        ciphertext_and_tag: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> CipherResult<()> {
        chacha20_poly1305_decrypt(key, nonce, ciphertext_and_tag, aad, out)
    }
}

/// Build the 16-byte nonce/counter block: zeros, nonce at the end.
fn build_nc(nonce: &[u8]) -> CipherResult<[u8; 16]> {
    if nonce.is_empty() || nonce.len() > 16 {
        return Err(CipherError::InvalidNonceLength);
    }
    let mut nc = [0u8; 16];
    nc[16 - nonce.len()..].copy_from_slice(nonce);
    Ok(nc)
}

/// Increment the first 4 bytes of `nc` as a little-endian u32 (reference counter).
fn inc_counter4(nc: &mut [u8; 16]) {
    let mut n = u32::from_le_bytes([nc[0], nc[1], nc[2], nc[3]]);
    n = n.wrapping_add(1);
    let b = n.to_le_bytes();
    nc[0] = b[0];
    nc[1] = b[1];
    nc[2] = b[2];
    nc[3] = b[3];
}

/// Encrypt with ChaCha20-Poly1305.
///
/// * `key` — 32 bytes
/// * `nonce` — 8..=16 bytes (12 = IETF RFC 8439)
/// * `out` — `plaintext.len() + 16` (ciphertext \|\| tag)
pub fn chacha20_poly1305_encrypt(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
    out: &mut [u8],
) -> CipherResult<()> {
    if key.len() != 32 {
        return Err(CipherError::InvalidKeyLength);
    }
    if out.len() != plaintext.len() + 16 {
        return Err(CipherError::InvalidLength);
    }

    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(key);
    let mut nc = build_nc(nonce)?;

    // Block 0 → Poly1305 one-time key (first 32 bytes)
    let otk_block = chacha20_block_nc(&key_arr, &nc);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&otk_block[..32]);
    inc_counter4(&mut nc); // now counter = 1

    // Encrypt with subsequent blocks
    let (ct, tag_out) = out.split_at_mut(plaintext.len());
    chacha20_xor_nc(&key_arr, &mut nc, plaintext, ct);

    let tag = compute_tag(&otk, aad, ct)?;
    tag_out.copy_from_slice(&tag);
    ct_zeroize(&mut otk);
    ct_zeroize(&mut nc);
    Ok(())
}

/// Decrypt with ChaCha20-Poly1305.
///
/// On authentication failure returns `AuthenticationFailed` and zeroizes `out`.
pub fn chacha20_poly1305_decrypt(
    key: &[u8],
    nonce: &[u8],
    ciphertext_and_tag: &[u8],
    aad: &[u8],
    out: &mut [u8],
) -> CipherResult<()> {
    if key.len() != 32 {
        return Err(CipherError::InvalidKeyLength);
    }
    if ciphertext_and_tag.len() < 16 {
        return Err(CipherError::InvalidLength);
    }
    let ct_len = ciphertext_and_tag.len() - 16;
    if out.len() != ct_len {
        return Err(CipherError::InvalidLength);
    }

    let (ct, tag) = ciphertext_and_tag.split_at(ct_len);

    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(key);
    let mut nc = build_nc(nonce)?;

    let otk_block = chacha20_block_nc(&key_arr, &nc);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&otk_block[..32]);
    inc_counter4(&mut nc);

    let expected = compute_tag(&otk, aad, ct)?;
    ct_zeroize(&mut otk);

    if ct_eq(&expected, tag) != 1 {
        ct_zeroize(out);
        ct_zeroize(&mut nc);
        return Err(CipherError::AuthenticationFailed);
    }

    chacha20_xor_nc(&key_arr, &mut nc, ct, out);
    ct_zeroize(&mut nc);
    Ok(())
}

/// XOR keystream from successive ChaCha20 blocks using a mutable 16-byte nc.
fn chacha20_xor_nc(key: &[u8; 32], nc: &mut [u8; 16], data: &[u8], out: &mut [u8]) {
    let mut offset = 0;
    while offset < data.len() {
        let block = chacha20_block_nc(key, nc);
        let take = core::cmp::min(64, data.len() - offset);
        for i in 0..take {
            out[offset + i] = data[offset + i] ^ block[i];
        }
        offset += take;
        inc_counter4(nc);
    }
}

fn compute_tag(otk: &[u8; 32], aad: &[u8], ciphertext: &[u8]) -> CipherResult<[u8; 16]> {
    // Streaming MAC over pad16(aad) || pad16(ciphertext) || le64(aad_len) ||
    // le64(ct_len) — no input-size limit, O(1) stack.
    const ZEROS: [u8; 16] = [0u8; 16];
    let mut mac = Poly1305::new(otk)?;
    mac.update(aad);
    let aad_pad = (16 - (aad.len() % 16)) % 16;
    if aad_pad > 0 {
        mac.update(&ZEROS[..aad_pad]);
    }
    mac.update(ciphertext);
    let ct_pad = (16 - (ciphertext.len() % 16)) % 16;
    if ct_pad > 0 {
        mac.update(&ZEROS[..ct_pad]);
    }
    let mut lens = [0u8; 16];
    lens[..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    lens[8..].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    mac.update(&lens);
    Ok(mac.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc8439_aead_12byte_nonce() {
        // RFC 8439 §2.8.2
        let key = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ];
        let nonce = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ];
        let aad = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let mut out = [0u8; 114 + 16];
        chacha20_poly1305_encrypt(&key, &nonce, plaintext, &aad, &mut out).unwrap();

        assert_eq!(
            &out[..114],
            &[
                0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef,
                0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7,
                0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa,
                0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
                0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77,
                0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4,
                0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4,
                0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
                0x61, 0x16,
            ]
        );
        assert_eq!(
            &out[114..],
            &[
                0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60,
                0x06, 0x91
            ]
        );

        let mut plain = [0u8; 114];
        chacha20_poly1305_decrypt(&key, &nonce, &out, &aad, &mut plain).unwrap();
        assert_eq!(&plain, plaintext);
    }

    #[test]
    fn eight_byte_nonce_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let aad = b"header";
        let pt = b"secret message with 8-byte nonce";
        let mut out = [0u8; 32 + 16];
        chacha20_poly1305_encrypt(&key, &nonce, pt, aad, &mut out).unwrap();
        let mut plain = [0u8; 32];
        chacha20_poly1305_decrypt(&key, &nonce, &out, aad, &mut plain).unwrap();
        assert_eq!(&plain, pt);
        // Different from zero-nonce
        let mut out2 = [0u8; 32 + 16];
        chacha20_poly1305_encrypt(&key, &[0u8; 8], pt, aad, &mut out2).unwrap();
        assert_ne!(out, out2);
    }

    #[test]
    fn bad_tag_fails() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let mut out = [0u8; 21];
        chacha20_poly1305_encrypt(&key, &nonce, b"hello", b"", &mut out).unwrap();
        out[20] ^= 1;
        let mut plain = [0u8; 5];
        assert_eq!(
            chacha20_poly1305_decrypt(&key, &nonce, &out, b"", &mut plain),
            Err(CipherError::AuthenticationFailed)
        );
    }

    #[test]
    fn large_payload_roundtrip() {
        // Formerly failed with `Failure("aad+ciphertext too large ...")`
        // once aad+ciphertext exceeded the 4KiB stack buffer.
        let key = [0x42u8; 32];
        let nonce = [0x07u8; 12];
        let pt: alloc::vec::Vec<u8> = (0..5000).map(|i| (i & 0xff) as u8).collect();
        let aad: alloc::vec::Vec<u8> = (0..300).map(|i| ((i * 3 + 9) & 0xff) as u8).collect();
        let mut out = alloc::vec![0u8; 5000 + 16];
        chacha20_poly1305_encrypt(&key, &nonce, &pt, &aad, &mut out).unwrap();
        let mut plain = alloc::vec![0u8; 5000];
        chacha20_poly1305_decrypt(&key, &nonce, &out, &aad, &mut plain).unwrap();
        assert_eq!(plain, pt);
        // Tamper fails even at large sizes.
        out[100] ^= 1;
        assert_eq!(
            chacha20_poly1305_decrypt(&key, &nonce, &out, &aad, &mut plain),
            Err(CipherError::AuthenticationFailed)
        );
    }

    #[test]
    fn boundary_4080_4081_roundtrip() {
        // With empty aad, MAC input = pt + pad16(pt) + 16: 4080 pads to
        // exactly 4096 (old limit), 4081 exceeds it.
        let key = [0x11u8; 32];
        let nonce = [0x22u8; 12];
        for len in [4080usize, 4081] {
            let pt: alloc::vec::Vec<u8> = (0..len).map(|i| (i & 0xff) as u8).collect();
            let mut out = alloc::vec![0u8; len + 16];
            chacha20_poly1305_encrypt(&key, &nonce, &pt, b"", &mut out).unwrap();
            let mut plain = alloc::vec![0u8; len];
            chacha20_poly1305_decrypt(&key, &nonce, &out, b"", &mut plain).unwrap();
            assert_eq!(plain, pt, "len={len}");
        }
    }

    #[test]
    fn empty_roundtrip() {
        let key = [0x33u8; 32];
        let nonce = [0x44u8; 12];
        let mut out = [0u8; 16];
        chacha20_poly1305_encrypt(&key, &nonce, b"", b"", &mut out).unwrap();
        let mut plain = [0u8; 0];
        chacha20_poly1305_decrypt(&key, &nonce, &out, b"", &mut plain).unwrap();
    }

    #[test]
    fn invalid_nonce_len() {
        let key = [0u8; 32];
        let mut out = [0u8; 16];
        assert!(chacha20_poly1305_encrypt(&key, &[], b"", b"", &mut out).is_err());
        assert!(chacha20_poly1305_encrypt(&key, &[0u8; 17], b"", b"", &mut out).is_err());
    }
}
