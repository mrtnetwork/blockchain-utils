//! Hex encoding / decoding (lowercase by default).
//!
//! Pure `no_std`. With the `alloc` feature, convenience `String` / `Vec` APIs
//! are available.

use crate::error::Error;

/// Decode a hex string into `out`.
///
/// Accepts upper or lower case. Ignores nothing — length must be even and
/// every character must be a hex digit. `out.len()` must equal `hex.len() / 2`.
pub fn decode_to_slice(hex: &str, out: &mut [u8]) -> Result<(), Error> {
    let bytes = hex.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(Error::InvalidEncoding);
    }
    if out.len() != bytes.len() / 2 {
        return Err(Error::InvalidLength);
    }
    for (i, chunk) in bytes.as_chunks::<2>().0.iter().enumerate() {
        let hi = from_digit(chunk[0]).ok_or(Error::InvalidEncoding)?;
        let lo = from_digit(chunk[1]).ok_or(Error::InvalidEncoding)?;
        out[i] = (hi << 4) | lo;
    }
    Ok(())
}

/// Required output length for decoding `hex`.
pub fn decoded_len(hex: &str) -> Result<usize, Error> {
    if !hex.len().is_multiple_of(2) {
        return Err(Error::InvalidEncoding);
    }
    Ok(hex.len() / 2)
}

/// Encode `data` as lowercase hex into `out`.
///
/// `out.len()` must equal `data.len() * 2`.
pub fn encode_to_slice(data: &[u8], out: &mut [u8]) -> Result<(), Error> {
    if out.len() != data.len() * 2 {
        return Err(Error::InvalidLength);
    }
    const LUT: &[u8; 16] = b"0123456789abcdef";
    for (i, &b) in data.iter().enumerate() {
        out[i * 2] = LUT[(b >> 4) as usize];
        out[i * 2 + 1] = LUT[(b & 0xf) as usize];
    }
    Ok(())
}

#[inline]
fn from_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(feature = "alloc")]
mod alloc_api {
    use super::*;
    extern crate alloc;
    use alloc::string::String;
    use alloc::vec;
    use alloc::vec::Vec;

    /// Decode hex string to a new `Vec<u8>`.
    pub fn decode(hex: &str) -> Result<Vec<u8>, Error> {
        let n = decoded_len(hex)?;
        let mut out = vec![0u8; n];
        decode_to_slice(hex, &mut out)?;
        Ok(out)
    }

    /// Encode bytes as a lowercase hex `String`.
    pub fn encode(data: &[u8]) -> String {
        let mut out = vec![0u8; data.len() * 2];
        encode_to_slice(data, &mut out).expect("length checked");
        // SAFETY: only ASCII hex digits written
        String::from_utf8(out).expect("ascii")
    }

    /// Encode bytes as uppercase hex `String`.
    pub fn encode_upper(data: &[u8]) -> String {
        let mut s = encode(data);
        s.make_ascii_uppercase();
        s
    }
}

#[cfg(feature = "alloc")]
pub use alloc_api::{decode, encode, encode_upper};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let data = [0x00u8, 0x0f, 0x10, 0xff, 0xab, 0xcd];
        let mut hex = [0u8; 12];
        encode_to_slice(&data, &mut hex).unwrap();
        assert_eq!(&hex, b"000f10ffabcd");
        let mut out = [0u8; 6];
        decode_to_slice(core::str::from_utf8(&hex).unwrap(), &mut out).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn upper_lower() {
        let mut out = [0u8; 1];
        decode_to_slice("aB", &mut out).unwrap();
        assert_eq!(out, [0xab]);
    }

    #[test]
    fn odd_length_fails() {
        let mut out = [0u8; 1];
        assert!(decode_to_slice("abc", &mut out).is_err());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn alloc_api() {
        assert_eq!(encode(&[0xde, 0xad]), "dead");
        assert_eq!(decode("DEAD").unwrap(), alloc::vec![0xde, 0xad]);
    }
}
