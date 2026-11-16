//! AES-ECB mode (SP 800-38A) with optional padding.

use crate::cipher::aes::Aes;
use crate::cipher::block::BlockCipher;
use crate::cipher::error::{CipherError, CipherResult};
use crate::cipher::padding::{self, PaddingAlgorithm};

const BS: usize = 16;

/// AES-ECB encrypt without padding (length must be a multiple of 16).
pub fn aes_ecb_encrypt(key: &[u8], data: &[u8], out: &mut [u8]) -> CipherResult<()> {
    if !data.len().is_multiple_of(BS) || out.len() != data.len() {
        return Err(CipherError::InvalidLength);
    }
    let aes = Aes::new(key)?;
    for (i, chunk) in data.chunks(BS).enumerate() {
        let mut block = [0u8; BS];
        block.copy_from_slice(chunk);
        aes.encrypt_block(&mut block)?;
        out[i * BS..(i + 1) * BS].copy_from_slice(&block);
    }
    Ok(())
}

/// AES-ECB decrypt without padding (length must be a multiple of 16).
pub fn aes_ecb_decrypt(key: &[u8], data: &[u8], out: &mut [u8]) -> CipherResult<()> {
    if !data.len().is_multiple_of(BS) || out.len() != data.len() {
        return Err(CipherError::InvalidLength);
    }
    let aes = Aes::new(key)?;
    for (i, chunk) in data.chunks(BS).enumerate() {
        let mut block = [0u8; BS];
        block.copy_from_slice(chunk);
        aes.decrypt_block(&mut block)?;
        out[i * BS..(i + 1) * BS].copy_from_slice(&block);
    }
    Ok(())
}

/// AES-ECB encrypt with padding. `out` must be [`padding::padded_len`] size.
pub fn aes_ecb_encrypt_padded(
    key: &[u8],
    data: &[u8],
    pad: PaddingAlgorithm,
    out: &mut [u8],
) -> CipherResult<()> {
    let need = padding::padded_len(data.len(), BS, pad)?;
    if out.len() != need {
        return Err(CipherError::InvalidLength);
    }
    #[cfg(feature = "alloc")]
    {
        let mut buf = alloc::vec![0u8; need];
        padding::pad(data, BS, pad, &mut buf)?;
        aes_ecb_encrypt(key, &buf, out)
    }
    #[cfg(not(feature = "alloc"))]
    {
        // No heap: stream full input blocks straight into `out`; only the
        // final (possibly partial) block needs a stack pad buffer.
        // No input-size limit, O(1) stack.
        if pad == PaddingAlgorithm::None {
            return aes_ecb_encrypt(key, data, out);
        }
        let aes = Aes::new(key)?;
        let full = data.len() / BS;
        for i in 0..full {
            let mut block = [0u8; BS];
            block.copy_from_slice(&data[i * BS..(i + 1) * BS]);
            aes.encrypt_block(&mut block)?;
            out[i * BS..(i + 1) * BS].copy_from_slice(&block);
        }
        let rem = data.len() % BS;
        let pad_len = BS - rem;
        let mut last = [0u8; BS];
        last[..rem].copy_from_slice(&data[full * BS..]);
        match pad {
            PaddingAlgorithm::Pkcs7 => {
                for b in &mut last[rem..] {
                    *b = pad_len as u8;
                }
            }
            PaddingAlgorithm::Iso7816 => {
                last[rem] = 0x80;
            }
            PaddingAlgorithm::X923 => {
                last[BS - 1] = pad_len as u8;
            }
            PaddingAlgorithm::None => unreachable!("handled above"),
        }
        aes.encrypt_block(&mut last)?;
        out[full * BS..full * BS + BS].copy_from_slice(&last);
        Ok(())
    }
}

/// AES-ECB decrypt with padding. Writes unpadded plaintext length via return; `out` ≥ ciphertext len.
pub fn aes_ecb_decrypt_padded(
    key: &[u8],
    data: &[u8],
    pad: PaddingAlgorithm,
    out: &mut [u8],
) -> CipherResult<usize> {
    if !data.len().is_multiple_of(BS) || out.len() < data.len() {
        return Err(CipherError::InvalidLength);
    }
    // decrypt into out[..data.len()], then unpad
    aes_ecb_decrypt(key, data, &mut out[..data.len()])?;
    let n = padding::unpad(&out[..data.len()], BS, pad)?;
    // shift is already in place
    Ok(n)
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;
    use crate::cipher::padding::PaddingAlgorithm;

    #[test]
    fn ecb_pkcs7_roundtrip() {
        let key = [0u8; 16];
        let pt = b"hello AES-ECB pad";
        let need =
            crate::cipher::padding::padded_len(pt.len(), 16, PaddingAlgorithm::Pkcs7).unwrap();
        let mut ct = alloc::vec![0u8; need];
        aes_ecb_encrypt_padded(&key, pt, PaddingAlgorithm::Pkcs7, &mut ct).unwrap();
        let mut out = alloc::vec![0u8; ct.len()];
        let n = aes_ecb_decrypt_padded(&key, &ct, PaddingAlgorithm::Pkcs7, &mut out).unwrap();
        assert_eq!(&out[..n], pt);
    }

    #[test]
    fn ecb_iso7816_roundtrip() {
        let key = [1u8; 16];
        let pt = b"iso7816 test data!";
        let need =
            crate::cipher::padding::padded_len(pt.len(), 16, PaddingAlgorithm::Iso7816).unwrap();
        let mut ct = alloc::vec![0u8; need];
        aes_ecb_encrypt_padded(&key, pt, PaddingAlgorithm::Iso7816, &mut ct).unwrap();
        let mut out = alloc::vec![0u8; ct.len()];
        let n = aes_ecb_decrypt_padded(&key, &ct, PaddingAlgorithm::Iso7816, &mut out).unwrap();
        assert_eq!(&out[..n], pt);
    }

    #[test]
    fn ecb_x923_roundtrip() {
        let key = [2u8; 16];
        let pt = b"x923";
        let need =
            crate::cipher::padding::padded_len(pt.len(), 16, PaddingAlgorithm::X923).unwrap();
        let mut ct = alloc::vec![0u8; need];
        aes_ecb_encrypt_padded(&key, pt, PaddingAlgorithm::X923, &mut ct).unwrap();
        let mut out = alloc::vec![0u8; ct.len()];
        let n = aes_ecb_decrypt_padded(&key, &ct, PaddingAlgorithm::X923, &mut out).unwrap();
        assert_eq!(&out[..n], pt);
    }

    #[test]
    fn ecb_padded_sizes_roundtrip() {
        // Formerly capped at 4096 bytes on no-alloc builds.
        for pad in [
            PaddingAlgorithm::Pkcs7,
            PaddingAlgorithm::Iso7816,
            PaddingAlgorithm::X923,
        ] {
            for len in [0usize, 10, 10 * 1024] {
                let pt: alloc::vec::Vec<u8> =
                    (0..len).map(|i| ((i * 17 + 4) & 0xff) as u8).collect();
                let need =
                    crate::cipher::padding::padded_len(len, 16, pad).unwrap();
                let mut ct = alloc::vec![0u8; need];
                aes_ecb_encrypt_padded(&key_of(pad), &pt, pad, &mut ct).unwrap();
                let mut out = alloc::vec![0u8; need];
                let n = aes_ecb_decrypt_padded(&key_of(pad), &ct, pad, &mut out).unwrap();
                assert_eq!(&out[..n], &pt[..], "pad={pad:?} len={len}");
            }
        }
        // PaddingAlgorithm::None stays strict: unaligned input errors.
        let key = [9u8; 32];
        assert!(aes_ecb_encrypt_padded(&key, &[1u8; 10], PaddingAlgorithm::None, &mut [0u8; 10]).is_err());
        let mut ct = [0u8; 32];
        aes_ecb_encrypt_padded(&key, &[7u8; 32], PaddingAlgorithm::None, &mut ct).unwrap();
        let mut out = [0u8; 32];
        let n = aes_ecb_decrypt_padded(&key, &ct, PaddingAlgorithm::None, &mut out).unwrap();
        assert_eq!(n, 32);
    }

    fn key_of(pad: PaddingAlgorithm) -> [u8; 16] {
        // Distinct key per padding style so cross-style mixups can't pass.
        [pad as u8; 16]
    }

    #[test]
    fn ecb_none_aligned() {
        let key = [3u8; 16];
        let pt = [9u8; 32];
        let mut ct = [0u8; 32];
        aes_ecb_encrypt_padded(&key, &pt, PaddingAlgorithm::None, &mut ct).unwrap();
        let mut out = [0u8; 32];
        let n = aes_ecb_decrypt_padded(&key, &ct, PaddingAlgorithm::None, &mut out).unwrap();
        assert_eq!(n, 32);
        assert_eq!(out, pt);
    }
}
