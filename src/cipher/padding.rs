//! Block padding schemes for ECB/CBC-style modes.
//!
//! - PKCS#7 (RFC 5652)
//! - ISO/IEC 7816-4 (0x80 followed by zeros)
//! - ANSI X9.23 (zeros then length byte)
//! - None (data must already be block-aligned)

use super::error::{CipherError, CipherResult};

/// Padding algorithm for block-cipher modes that require aligned blocks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PaddingAlgorithm {
    /// No padding; length must be a multiple of the block size.
    None = 0,
    /// PKCS#7: each pad byte equals the pad length (1..=block_size).
    Pkcs7 = 1,
    /// ISO/IEC 7816-4: `0x80` then zero bytes.
    Iso7816 = 2,
    /// ANSI X9.23: zeros then last byte = pad length.
    X923 = 3,
}

impl PaddingAlgorithm {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::None),
            1 => Some(Self::Pkcs7),
            2 => Some(Self::Iso7816),
            3 => Some(Self::X923),
            _ => None,
        }
    }
}

/// Output length after padding.
pub fn padded_len(
    data_len: usize,
    block_size: usize,
    pad: PaddingAlgorithm,
) -> CipherResult<usize> {
    if block_size == 0 || block_size > 255 {
        return Err(CipherError::Unsupported);
    }
    match pad {
        PaddingAlgorithm::None => {
            if !data_len.is_multiple_of(block_size) {
                return Err(CipherError::InvalidLength);
            }
            Ok(data_len)
        }
        PaddingAlgorithm::Pkcs7 | PaddingAlgorithm::Iso7816 | PaddingAlgorithm::X923 => {
            let pad_len = block_size - (data_len % block_size);
            Ok(data_len + pad_len)
        }
    }
}

/// Apply padding into `out` (must be exactly [`padded_len`]).
pub fn pad(
    data: &[u8],
    block_size: usize,
    pad: PaddingAlgorithm,
    out: &mut [u8],
) -> CipherResult<()> {
    let need = padded_len(data.len(), block_size, pad)?;
    if out.len() != need {
        return Err(CipherError::InvalidLength);
    }
    match pad {
        PaddingAlgorithm::None => {
            out.copy_from_slice(data);
            Ok(())
        }
        PaddingAlgorithm::Pkcs7 => pkcs7_pad(data, block_size, out),
        PaddingAlgorithm::Iso7816 => iso7816_pad(data, block_size, out),
        PaddingAlgorithm::X923 => x923_pad(data, block_size, out),
    }
}

/// Remove padding; returns unpadded length.
pub fn unpad(data: &[u8], block_size: usize, pad: PaddingAlgorithm) -> CipherResult<usize> {
    match pad {
        PaddingAlgorithm::None => {
            if block_size == 0 || !data.len().is_multiple_of(block_size) {
                return Err(CipherError::InvalidLength);
            }
            Ok(data.len())
        }
        PaddingAlgorithm::Pkcs7 => pkcs7_unpad(data, block_size),
        PaddingAlgorithm::Iso7816 => iso7816_unpad(data, block_size),
        PaddingAlgorithm::X923 => x923_unpad(data, block_size),
    }
}

/// Copy unpadded bytes into `out` (must be ≥ unpadded length).
pub fn unpad_into(
    data: &[u8],
    block_size: usize,
    pad: PaddingAlgorithm,
    out: &mut [u8],
) -> CipherResult<usize> {
    let n = unpad(data, block_size, pad)?;
    if out.len() < n {
        return Err(CipherError::InvalidLength);
    }
    out[..n].copy_from_slice(&data[..n]);
    Ok(n)
}

// ---- PKCS#7 ----

pub fn pkcs7_pad(data: &[u8], block_size: usize, out: &mut [u8]) -> CipherResult<()> {
    if block_size == 0 || block_size > 255 {
        return Err(CipherError::Unsupported);
    }
    let pad_len = block_size - (data.len() % block_size);
    let need = data.len() + pad_len;
    if out.len() != need {
        return Err(CipherError::InvalidLength);
    }
    out[..data.len()].copy_from_slice(data);
    let p = pad_len as u8;
    for b in &mut out[data.len()..] {
        *b = p;
    }
    Ok(())
}

pub fn pkcs7_padded_len(data_len: usize, block_size: usize) -> CipherResult<usize> {
    padded_len(data_len, block_size, PaddingAlgorithm::Pkcs7)
}

pub fn pkcs7_unpad(data: &[u8], block_size: usize) -> CipherResult<usize> {
    if block_size == 0 || block_size > 255 || data.is_empty() || !data.len().is_multiple_of(block_size) {
        return Err(CipherError::InvalidPadding);
    }
    let pad_len = data[data.len() - 1] as usize;
    if pad_len == 0 || pad_len > block_size || pad_len > data.len() {
        return Err(CipherError::InvalidPadding);
    }
    let start = data.len() - pad_len;
    for &b in &data[start..] {
        if b as usize != pad_len {
            return Err(CipherError::InvalidPadding);
        }
    }
    Ok(start)
}

pub fn pkcs7_unpad_into(data: &[u8], block_size: usize, out: &mut [u8]) -> CipherResult<()> {
    let n = pkcs7_unpad(data, block_size)?;
    if out.len() < n {
        return Err(CipherError::InvalidLength);
    }
    out[..n].copy_from_slice(&data[..n]);
    Ok(())
}

// ---- ISO/IEC 7816-4 ----

fn iso7816_pad(data: &[u8], block_size: usize, out: &mut [u8]) -> CipherResult<()> {
    let pad_len = block_size - (data.len() % block_size);
    let need = data.len() + pad_len;
    if out.len() != need {
        return Err(CipherError::InvalidLength);
    }
    out[..data.len()].copy_from_slice(data);
    out[data.len()] = 0x80;
    for b in &mut out[data.len() + 1..] {
        *b = 0;
    }
    Ok(())
}

fn iso7816_unpad(data: &[u8], block_size: usize) -> CipherResult<usize> {
    if data.is_empty() || !data.len().is_multiple_of(block_size) {
        return Err(CipherError::InvalidPadding);
    }
    // Scan backward for 0x80; trailing must be zeros
    let mut i = data.len();
    while i > 0 {
        i -= 1;
        if data[i] == 0x80 {
            return Ok(i);
        }
        if data[i] != 0 {
            return Err(CipherError::InvalidPadding);
        }
    }
    Err(CipherError::InvalidPadding)
}

// ---- ANSI X9.23 ----

fn x923_pad(data: &[u8], block_size: usize, out: &mut [u8]) -> CipherResult<()> {
    let pad_len = block_size - (data.len() % block_size);
    let need = data.len() + pad_len;
    if out.len() != need {
        return Err(CipherError::InvalidLength);
    }
    out[..data.len()].copy_from_slice(data);
    for b in &mut out[data.len()..need - 1] {
        *b = 0;
    }
    out[need - 1] = pad_len as u8;
    Ok(())
}

fn x923_unpad(data: &[u8], block_size: usize) -> CipherResult<usize> {
    if data.is_empty() || !data.len().is_multiple_of(block_size) {
        return Err(CipherError::InvalidPadding);
    }
    let pad_len = data[data.len() - 1] as usize;
    if pad_len == 0 || pad_len > block_size || pad_len > data.len() {
        return Err(CipherError::InvalidPadding);
    }
    let start = data.len() - pad_len;
    for &b in &data[start..data.len() - 1] {
        if b != 0 {
            return Err(CipherError::InvalidPadding);
        }
    }
    Ok(start)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkcs7_roundtrip() {
        let data = b"hello";
        let bs = 16;
        let need = padded_len(data.len(), bs, PaddingAlgorithm::Pkcs7).unwrap();
        let mut padded = [0u8; 32];
        pad(data, bs, PaddingAlgorithm::Pkcs7, &mut padded[..need]).unwrap();
        assert_eq!(
            unpad(&padded[..need], bs, PaddingAlgorithm::Pkcs7).unwrap(),
            5
        );
    }

    #[test]
    fn iso7816_roundtrip() {
        let data = b"hello world!!"; // 13 bytes
        let bs = 16;
        let need = padded_len(data.len(), bs, PaddingAlgorithm::Iso7816).unwrap();
        let mut out = [0u8; 32];
        pad(data, bs, PaddingAlgorithm::Iso7816, &mut out[..need]).unwrap();
        assert_eq!(out[13], 0x80);
        assert_eq!(
            unpad(&out[..need], bs, PaddingAlgorithm::Iso7816).unwrap(),
            13
        );
    }

    #[test]
    fn x923_roundtrip() {
        let data = b"abc";
        let bs = 8;
        let need = padded_len(data.len(), bs, PaddingAlgorithm::X923).unwrap();
        let mut out = [0u8; 16];
        pad(data, bs, PaddingAlgorithm::X923, &mut out[..need]).unwrap();
        assert_eq!(out[need - 1], 5);
        assert_eq!(unpad(&out[..need], bs, PaddingAlgorithm::X923).unwrap(), 3);
    }

    #[test]
    fn none_requires_aligned() {
        assert!(padded_len(15, 16, PaddingAlgorithm::None).is_err());
        assert_eq!(padded_len(16, 16, PaddingAlgorithm::None).unwrap(), 16);
    }

    #[test]
    fn pkcs7_full_block() {
        let data = [0u8; 16];
        let need = pkcs7_padded_len(16, 16).unwrap();
        assert_eq!(need, 32);
        let mut out = [0u8; 32];
        pkcs7_pad(&data, 16, &mut out).unwrap();
        assert_eq!(out[16], 16);
        assert_eq!(pkcs7_unpad(&out, 16).unwrap(), 16);
    }

    #[test]
    fn invalid_padding() {
        // last byte claims 5 pad bytes but prior bytes are not 5
        let mut data = [0u8; 16];
        data[15] = 5;
        data[14] = 4; // mismatch
        assert!(pkcs7_unpad(&data, 16).is_err());
        // pad length 0 invalid
        data = [0u8; 16];
        assert!(pkcs7_unpad(&data, 16).is_err());
    }
}
