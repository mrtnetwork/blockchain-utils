//! Byte-slice utilities used throughout the crate.
//!
//! All functions are `no_std` and allocation-free unless the `alloc` feature
//! is enabled and the caller explicitly requests owned data.

use crate::error::{Error, Result};

/// Copy bytes from `src` into `dst`. Lengths must match.
#[inline]
pub fn copy(dst: &mut [u8], src: &[u8]) -> Result<()> {
    if dst.len() != src.len() {
        return Err(Error::InvalidLength);
    }
    dst.copy_from_slice(src);
    Ok(())
}

/// Zero a mutable byte slice (best-effort; not guaranteed to be zeroized
/// against aggressive compiler optimisations without additional support).
#[inline]
pub fn zeroize(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        *b = 0;
    }
}

/// Securely compare two byte slices in constant time.
/// Returns `true` only if they have the same length and content.
#[inline]
pub fn secure_eq(a: &[u8], b: &[u8]) -> bool {
    crate::ct::ct_eq(a, b) == 1
}

/// Convert a byte slice to a fixed-size array.
#[inline]
pub fn try_into_array<const N: usize>(slice: &[u8]) -> Result<[u8; N]> {
    if slice.len() != N {
        return Err(Error::InvalidLength);
    }
    let mut arr = [0u8; N];
    arr.copy_from_slice(slice);
    Ok(arr)
}

/// Pad a buffer on the right with zeros up to `len`.
/// Returns an error if `data.len() > len`.
#[cfg(feature = "alloc")]
pub fn pad_right(data: &[u8], len: usize) -> Result<alloc::vec::Vec<u8>> {
    if data.len() > len {
        return Err(Error::InvalidLength);
    }
    let mut out = alloc::vec![0u8; len];
    out[..data.len()].copy_from_slice(data);
    Ok(out)
}

/// XOR two equal-length slices into `out`.
#[inline]
pub fn xor(out: &mut [u8], a: &[u8], b: &[u8]) -> Result<()> {
    if out.len() != a.len() || a.len() != b.len() {
        return Err(Error::InvalidLength);
    }
    for i in 0..out.len() {
        out[i] = a[i] ^ b[i];
    }
    Ok(())
}

/// XOR `src` into `dst` in place (lengths must match).
#[inline]
pub fn xor_assign(dst: &mut [u8], src: &[u8]) -> Result<()> {
    if dst.len() != src.len() {
        return Err(Error::InvalidLength);
    }
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d ^= *s;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_ok() {
        let src = [1u8, 2, 3];
        let mut dst = [0u8; 3];
        copy(&mut dst, &src).unwrap();
        assert_eq!(dst, src);
    }

    #[test]
    fn copy_len_mismatch() {
        let mut dst = [0u8; 2];
        assert!(copy(&mut dst, &[1, 2, 3]).is_err());
    }

    #[test]
    fn secure_eq_works() {
        assert!(secure_eq(&[1, 2, 3], &[1, 2, 3]));
        assert!(!secure_eq(&[1, 2, 3], &[1, 2, 4]));
        assert!(!secure_eq(&[1, 2], &[1, 2, 3]));
    }

    #[test]
    fn try_into_array() {
        let a: [u8; 4] = super::try_into_array(&[9, 8, 7, 6]).unwrap();
        assert_eq!(a, [9, 8, 7, 6]);
        assert!(super::try_into_array::<4>(&[1, 2]).is_err());
    }

    #[test]
    fn xor_works() {
        let a = [0x0F, 0xF0];
        let b = [0xFF, 0x00];
        let mut out = [0u8; 2];
        xor(&mut out, &a, &b).unwrap();
        assert_eq!(out, [0xF0, 0xF0]);
    }
}
