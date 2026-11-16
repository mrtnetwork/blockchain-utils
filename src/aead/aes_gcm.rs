//! AES-GCM AEAD (NIST SP 800-38D).
//!
//! Supports 128/192/256-bit keys, 12-byte nonces, 16-byte tags.
//! Pure `no_std`, zero-dependency.

use super::Aead;
use crate::cipher::aes::Aes;
use crate::cipher::block::BlockCipher;
use crate::cipher::error::{CipherError, CipherResult};
use crate::ct::{ct_eq, ct_zeroize};

/// AES-GCM with 12-byte nonce and 16-byte tag.
pub struct AesGcm;

impl Aead for AesGcm {
    const KEY_LEN: usize = 16; // minimum; 24/32 also accepted by free functions
    const NONCE_LEN: usize = 12;
    const TAG_LEN: usize = 16;

    fn encrypt(
        key: &[u8],
        nonce: &[u8],
        plaintext: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> CipherResult<()> {
        aes_gcm_encrypt(key, nonce, plaintext, aad, out)
    }

    fn decrypt(
        key: &[u8],
        nonce: &[u8],
        ciphertext_and_tag: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> CipherResult<()> {
        aes_gcm_decrypt(key, nonce, ciphertext_and_tag, aad, out)
    }
}

/// Encrypt with AES-GCM.
///
/// * `key` — 16, 24, or 32 bytes
/// * `nonce` — 12 bytes (96-bit; other lengths not supported in this API)
/// * `out` — must be `plaintext.len() + 16` (ciphertext \|\| tag)
pub fn aes_gcm_encrypt(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
    out: &mut [u8],
) -> CipherResult<()> {
    if ![16, 24, 32].contains(&key.len()) {
        return Err(CipherError::InvalidKeyLength);
    }
    if nonce.len() != 12 {
        return Err(CipherError::InvalidNonceLength);
    }
    if out.len() != plaintext.len() + 16 {
        return Err(CipherError::InvalidLength);
    }

    let aes = Aes::new(key)?;
    let mut h = [0u8; 16];
    aes.encrypt_block(&mut h)?; // H = E(K, 0^128)

    // J0 = nonce || 0x00000001
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 1;

    // Encrypt: CTR starting at inc32(J0)
    let mut counter = j0;
    inc32(&mut counter);
    let (ct, tag_out) = out.split_at_mut(plaintext.len());
    gctr(&aes, &counter, plaintext, ct)?;

    // S = GHASH(H, AAD, C)
    let s = ghash(&h, aad, ct);
    // T = MSB_128(GCTR(K, J0, S))
    let mut tag_block = [0u8; 16];
    gctr(&aes, &j0, &s, &mut tag_block)?;
    tag_out.copy_from_slice(&tag_block);
    Ok(())
}

/// Decrypt with AES-GCM. Tag is the last 16 bytes of `ciphertext_and_tag`.
///
/// On auth failure returns `AuthenticationFailed` and zeroizes `out`.
pub fn aes_gcm_decrypt(
    key: &[u8],
    nonce: &[u8],
    ciphertext_and_tag: &[u8],
    aad: &[u8],
    out: &mut [u8],
) -> CipherResult<()> {
    if ![16, 24, 32].contains(&key.len()) {
        return Err(CipherError::InvalidKeyLength);
    }
    if nonce.len() != 12 {
        return Err(CipherError::InvalidNonceLength);
    }
    if ciphertext_and_tag.len() < 16 {
        return Err(CipherError::InvalidLength);
    }
    let ct_len = ciphertext_and_tag.len() - 16;
    if out.len() != ct_len {
        return Err(CipherError::InvalidLength);
    }
    let (ct, tag) = ciphertext_and_tag.split_at(ct_len);

    let aes = Aes::new(key)?;
    let mut h = [0u8; 16];
    aes.encrypt_block(&mut h)?;

    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 1;

    let s = ghash(&h, aad, ct);
    let mut expected = [0u8; 16];
    gctr(&aes, &j0, &s, &mut expected)?;

    if ct_eq(&expected, tag) != 1 {
        ct_zeroize(out);
        return Err(CipherError::AuthenticationFailed);
    }

    let mut counter = j0;
    inc32(&mut counter);
    gctr(&aes, &counter, ct, out)?;
    Ok(())
}

/// GCTR: AES-CTR with 32-bit big-endian counter increment on the last 4 bytes.
fn gctr(aes: &Aes, icb: &[u8; 16], data: &[u8], out: &mut [u8]) -> CipherResult<()> {
    if out.len() != data.len() {
        return Err(CipherError::InvalidLength);
    }
    if data.is_empty() {
        return Ok(());
    }
    let mut counter = *icb;
    let mut offset = 0;
    while offset < data.len() {
        let mut block = counter;
        aes.encrypt_block(&mut block)?;
        let take = core::cmp::min(16, data.len() - offset);
        for i in 0..take {
            out[offset + i] = data[offset + i] ^ block[i];
        }
        offset += take;
        inc32(&mut counter);
    }
    Ok(())
}

fn inc32(block: &mut [u8; 16]) {
    // Increment last 4 bytes as big-endian u32
    let mut n = u32::from_be_bytes([block[12], block[13], block[14], block[15]]);
    n = n.wrapping_add(1);
    let b = n.to_be_bytes();
    block[12] = b[0];
    block[13] = b[1];
    block[14] = b[2];
    block[15] = b[3];
}

/// GHASH over AAD and ciphertext with length block.
fn ghash(h: &[u8; 16], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let mut y = [0u8; 16];

    // Process AAD in 16-byte blocks
    let mut offset = 0;
    while offset + 16 <= aad.len() {
        xor_block(&mut y, &aad[offset..offset + 16]);
        y = gfmul(&y, h);
        offset += 16;
    }
    if offset < aad.len() {
        let mut block = [0u8; 16];
        block[..aad.len() - offset].copy_from_slice(&aad[offset..]);
        xor_block(&mut y, &block);
        y = gfmul(&y, h);
    }

    // Process ciphertext
    offset = 0;
    while offset + 16 <= ciphertext.len() {
        xor_block(&mut y, &ciphertext[offset..offset + 16]);
        y = gfmul(&y, h);
        offset += 16;
    }
    if offset < ciphertext.len() {
        let mut block = [0u8; 16];
        block[..ciphertext.len() - offset].copy_from_slice(&ciphertext[offset..]);
        xor_block(&mut y, &block);
        y = gfmul(&y, h);
    }

    // Length block: [len(AAD) in bits (64-bit BE)] || [len(C) in bits (64-bit BE)]
    let mut len_block = [0u8; 16];
    let aad_bits = (aad.len() as u64).wrapping_mul(8);
    let ct_bits = (ciphertext.len() as u64).wrapping_mul(8);
    len_block[0..8].copy_from_slice(&aad_bits.to_be_bytes());
    len_block[8..16].copy_from_slice(&ct_bits.to_be_bytes());
    xor_block(&mut y, &len_block);
    y = gfmul(&y, h);
    y
}

fn xor_block(dst: &mut [u8; 16], src: &[u8]) {
    for i in 0..16 {
        dst[i] ^= src[i];
    }
}

/// Multiply two elements in GF(2^128) with the GCM polynomial
/// x^128 + x^7 + x^2 + x + 1 (bit-reflected representation).
fn gfmul(x: &[u8; 16], y: &[u8; 16]) -> [u8; 16] {
    // Bit-by-bit multiplication in reflected representation
    let mut z = [0u8; 16];
    let mut v = *y;
    for i in 0..128 {
        let byte = x[i / 8];
        let bit = (byte >> (7 - (i % 8))) & 1;
        if bit != 0 {
            for j in 0..16 {
                z[j] ^= v[j];
            }
        }
        // v = v >> 1 (reflected: right shift, reduce if LSB was 1)
        let lsb = v[15] & 1;
        // right-shift entire 128-bit value by 1
        let mut new_v = [0u8; 16];
        for j in (1..16).rev() {
            new_v[j] = (v[j] >> 1) | (v[j - 1] << 7);
        }
        new_v[0] = v[0] >> 1;
        v = new_v;
        if lsb != 0 {
            // R = 0xe1 || 0^120
            v[0] ^= 0xe1;
        }
    }
    z
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nist_gcm_aes128_case1() {
        // SP 800-38D test case 1: empty plaintext, empty AAD
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let mut out = [0u8; 16]; // tag only
        aes_gcm_encrypt(&key, &nonce, b"", b"", &mut out).unwrap();
        assert_eq!(
            out,
            [
                0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61, 0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7,
                0x45, 0x5a
            ]
        );
        let mut plain = [];
        aes_gcm_decrypt(&key, &nonce, &out, b"", &mut plain).unwrap();
    }

    #[test]
    fn nist_gcm_aes128_case2() {
        // SP 800-38D test case 2: 16-byte plaintext, empty AAD
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let plaintext = [0u8; 16];
        let mut out = [0u8; 32];
        aes_gcm_encrypt(&key, &nonce, &plaintext, b"", &mut out).unwrap();
        assert_eq!(
            &out[..16],
            &[
                0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2,
                0xfe, 0x78
            ]
        );
        assert_eq!(
            &out[16..],
            &[
                0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd, 0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57,
                0xbd, 0xdf
            ]
        );
        let mut plain = [0u8; 16];
        aes_gcm_decrypt(&key, &nonce, &out, b"", &mut plain).unwrap();
        assert_eq!(plain, plaintext);
    }

    #[test]
    fn nist_gcm_aes128_case4() {
        // Non-empty AAD + plaintext
        let key = [
            0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30,
            0x83, 0x08,
        ];
        let nonce = [
            0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
        ];
        let plaintext = [
            0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5,
            0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d,
            0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf,
            0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
            0xba, 0x63, 0x7b, 0x39,
        ];
        let aad = [
            0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad,
            0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2,
        ];
        let mut out = [0u8; 76];
        aes_gcm_encrypt(&key, &nonce, &plaintext, &aad, &mut out).unwrap();
        assert_eq!(
            &out[60..],
            &[
                0x5b, 0xc9, 0x4f, 0xbc, 0x32, 0x21, 0xa5, 0xdb, 0x94, 0xfa, 0xe9, 0x5a, 0xe7, 0x12,
                0x1a, 0x47
            ]
        );
        let mut plain = [0u8; 60];
        aes_gcm_decrypt(&key, &nonce, &out, &aad, &mut plain).unwrap();
        assert_eq!(plain, plaintext);
    }

    #[test]
    fn bad_tag_fails() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let mut out = [0u8; 32];
        aes_gcm_encrypt(&key, &nonce, &[0u8; 16], b"", &mut out).unwrap();
        out[31] ^= 1;
        let mut plain = [0u8; 16];
        assert_eq!(
            aes_gcm_decrypt(&key, &nonce, &out, b"", &mut plain),
            Err(CipherError::AuthenticationFailed)
        );
    }
}
