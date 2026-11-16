//! AES-CBC mode (NIST SP 800-38A) with PKCS#7 padding helpers.

use crate::cipher::aes::Aes;
use crate::cipher::block::BlockCipher;
use crate::cipher::error::{CipherError, CipherResult};
use crate::cipher::padding::{pkcs7_padded_len, pkcs7_unpad};

/// AES-CBC encrypt (no padding). `data.len()` must be a multiple of 16.
///
/// `iv` is the 16-byte initialization vector (copied, not advanced for caller).
/// `out.len()` must equal `data.len()`.
pub fn aes_cbc_encrypt(key: &[u8], iv: &[u8; 16], data: &[u8], out: &mut [u8]) -> CipherResult<()> {
    if !data.len().is_multiple_of(16) || out.len() != data.len() {
        return Err(CipherError::InvalidLength);
    }
    let aes = Aes::new(key)?;
    let mut prev = *iv;
    let mut offset = 0;
    while offset < data.len() {
        let mut block = [0u8; 16];
        for i in 0..16 {
            block[i] = data[offset + i] ^ prev[i];
        }
        aes.encrypt_block(&mut block)?;
        out[offset..offset + 16].copy_from_slice(&block);
        prev = block;
        offset += 16;
    }
    Ok(())
}

/// AES-CBC decrypt (no padding). `data.len()` must be a multiple of 16.
pub fn aes_cbc_decrypt(key: &[u8], iv: &[u8; 16], data: &[u8], out: &mut [u8]) -> CipherResult<()> {
    if !data.len().is_multiple_of(16) || out.len() != data.len() {
        return Err(CipherError::InvalidLength);
    }
    let aes = Aes::new(key)?;
    let mut prev = *iv;
    let mut offset = 0;
    while offset < data.len() {
        let mut block = [0u8; 16];
        block.copy_from_slice(&data[offset..offset + 16]);
        let ciphertext = block;
        aes.decrypt_block(&mut block)?;
        for i in 0..16 {
            out[offset + i] = block[i] ^ prev[i];
        }
        prev = ciphertext;
        offset += 16;
    }
    Ok(())
}

/// AES-CBC encrypt with PKCS#7 padding.
///
/// `out.len()` must equal `pkcs7_padded_len(plaintext.len(), 16)`.
/// Streams full input blocks straight into `out`; only the final padded
/// block needs a stack buffer — no input-size limit, O(1) stack.
pub fn aes_cbc_encrypt_padded(
    key: &[u8],
    iv: &[u8; 16],
    plaintext: &[u8],
    out: &mut [u8],
) -> CipherResult<()> {
    let need = pkcs7_padded_len(plaintext.len(), 16)?;
    if out.len() != need {
        return Err(CipherError::InvalidLength);
    }
    let aes = Aes::new(key)?;
    let mut prev = *iv;
    let full = plaintext.len() / 16;
    for i in 0..full {
        let mut block = [0u8; 16];
        for j in 0..16 {
            block[j] = plaintext[i * 16 + j] ^ prev[j];
        }
        aes.encrypt_block(&mut block)?;
        out[i * 16..(i + 1) * 16].copy_from_slice(&block);
        prev = block;
    }
    // Final block: remaining tail bytes + PKCS#7 padding.
    let rem = plaintext.len() % 16;
    let pad_len = 16 - rem;
    let mut last = [0u8; 16];
    last[..rem].copy_from_slice(&plaintext[full * 16..]);
    for b in &mut last[rem..] {
        *b = pad_len as u8;
    }
    for j in 0..16 {
        last[j] ^= prev[j];
    }
    aes.encrypt_block(&mut last)?;
    out[full * 16..full * 16 + 16].copy_from_slice(&last);
    Ok(())
}

/// AES-CBC decrypt with PKCS#7 unpadding.
///
/// Returns the unpadded plaintext length written to `out`.
/// `out.len()` must be at least `ciphertext.len()` (padding is stripped in place conceptually).
/// The last block's padding is validated *before* anything is written to
/// `out`, so `out` stays untouched on authentication-style padding failure —
/// no input-size limit, O(1) stack.
pub fn aes_cbc_decrypt_padded(
    key: &[u8],
    iv: &[u8; 16],
    ciphertext: &[u8],
    out: &mut [u8],
) -> CipherResult<usize> {
    if !ciphertext.len().is_multiple_of(16) || ciphertext.is_empty() {
        return Err(CipherError::InvalidLength);
    }
    if out.len() < ciphertext.len() {
        return Err(CipherError::InvalidLength);
    }
    let aes = Aes::new(key)?;
    // Validate the padding on the last block first (all PKCS#7 pad bytes
    // live in the last block, so this is the complete padding check).
    let mut last = [0u8; 16];
    last.copy_from_slice(&ciphertext[ciphertext.len() - 16..]);
    let prev_last = if ciphertext.len() == 16 {
        *iv
    } else {
        let mut p = [0u8; 16];
        p.copy_from_slice(&ciphertext[ciphertext.len() - 32..ciphertext.len() - 16]);
        p
    };
    aes.decrypt_block(&mut last)?;
    for j in 0..16 {
        last[j] ^= prev_last[j];
    }
    let n_last = pkcs7_unpad(&last, 16)?;
    // Padding is valid: decrypt everything into `out`.
    aes_cbc_decrypt(key, iv, ciphertext, &mut out[..ciphertext.len()])?;
    Ok(ciphertext.len() - 16 + n_last)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nist_sp800_38a_aes128_cbc() {
        // SP 800-38A F.2.1 AES-128 CBC
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let iv = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let plaintext = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac,
            0x45, 0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb,
            0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
            0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
        ];
        let expected = [
            0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9,
            0x19, 0x7d, 0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a,
            0x91, 0x76, 0x78, 0xb2, 0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16,
            0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16, 0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09,
            0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7,
        ];
        let mut out = [0u8; 64];
        aes_cbc_encrypt(&key, &iv, &plaintext, &mut out).unwrap();
        assert_eq!(out, expected);
        let mut plain = [0u8; 64];
        aes_cbc_decrypt(&key, &iv, &out, &mut plain).unwrap();
        assert_eq!(plain, plaintext);
    }

    #[test]
    fn cbc_padded_roundtrip() {
        let key = [0u8; 16];
        let iv = [1u8; 16];
        let pt = b"hello CBC world!";
        let need = pkcs7_padded_len(pt.len(), 16).unwrap();
        let mut ct = [0u8; 32];
        assert_eq!(need, 32);
        aes_cbc_encrypt_padded(&key, &iv, pt, &mut ct[..need]).unwrap();
        let mut out = [0u8; 32];
        let n = aes_cbc_decrypt_padded(&key, &iv, &ct[..need], &mut out).unwrap();
        assert_eq!(&out[..n], pt);
    }

    #[test]
    fn cbc_padded_sizes_roundtrip() {
        // Formerly capped at 2048 bytes of stack padding buffer.
        let key = [0x2bu8; 16];
        let iv = [0xabu8; 16];
        for len in [0usize, 10, 10 * 1024] {
            let pt: alloc::vec::Vec<u8> = (0..len).map(|i| (i & 0xff) as u8).collect();
            let need = pkcs7_padded_len(len, 16).unwrap();
            let mut ct = alloc::vec![0u8; need];
            aes_cbc_encrypt_padded(&key, &iv, &pt, &mut ct).unwrap();
            let mut out = alloc::vec![0u8; need];
            let n = aes_cbc_decrypt_padded(&key, &iv, &ct, &mut out).unwrap();
            assert_eq!(&out[..n], &pt[..], "len={len}");
        }
    }

    #[test]
    fn cbc_padded_bad_padding_leaves_out_untouched() {
        let key = [0u8; 16];
        let iv = [1u8; 16];
        let pt = b"hello CBC world!";
        let need = pkcs7_padded_len(pt.len(), 16).unwrap();
        let mut ct = [0u8; 32];
        aes_cbc_encrypt_padded(&key, &iv, pt, &mut ct[..need]).unwrap();
        ct[need - 1] ^= 0x01; // corrupt padding
        let mut out = [0x55u8; 32];
        assert!(aes_cbc_decrypt_padded(&key, &iv, &ct[..need], &mut out).is_err());
        assert!(out.iter().all(|&b| b == 0x55));
    }
}
