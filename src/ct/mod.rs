//! Constant-time primitives.
//!
//! These helpers reduce timing side-channels when handling secret data.
//! They are not a complete constant-time library, but provide the building
//! blocks used throughout the crate.
//!
//! # Guarantees
//!
//! * Equality / comparison helpers always examine every byte / limb.
//! * Selection / assignment use bitwise masks (no data-dependent branches
//!   on the secret values themselves).
//! * Length mismatches still short-circuit on the *public* length, which is
//!   intentional and standard practice.

/// Constant-time equality of two byte slices of equal length.
///
/// Returns `1u8` if equal, `0u8` otherwise.
/// Always examines every byte when lengths match.
#[inline]
pub fn ct_eq(a: &[u8], b: &[u8]) -> u8 {
    if a.len() != b.len() {
        return 0;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    ct_is_zero(diff)
}

/// Returns `true` if the slices are equal (constant-time on content).
#[inline]
pub fn ct_eq_bool(a: &[u8], b: &[u8]) -> bool {
    ct_eq(a, b) == 1
}

/// Returns `1u8` if `x == 0`, otherwise `0u8`, in constant time.
#[inline]
pub fn ct_is_zero(x: u8) -> u8 {
    let y = x as u16;
    (((y.wrapping_sub(1)) >> 8) & 1) as u8
}

/// Returns `1u8` if `x != 0`, otherwise `0u8`.
#[inline]
pub fn ct_is_nonzero(x: u8) -> u8 {
    1u8 ^ ct_is_zero(x)
}

/// Constant-time equality of two `u8` values.
#[inline]
pub fn ct_eq_u8(a: u8, b: u8) -> u8 {
    ct_is_zero(a ^ b)
}

/// Constant-time equality of two `u64` values.
#[inline]
pub fn ct_eq_u64(a: u64, b: u64) -> u8 {
    let x = a ^ b;
    let x = x | x.wrapping_shr(32);
    let x = x | x.wrapping_shr(16);
    let x = x | x.wrapping_shr(8);
    ct_is_zero(x as u8)
}

/// Constant-time less-than for `u8`. Returns `1` if `a < b`.
#[inline]
pub fn ct_lt_u8(a: u8, b: u8) -> u8 {
    let diff = (a as u16).wrapping_sub(b as u16);
    ((diff >> 8) & 1) as u8
}

/// Constant-time selection between two bytes.
/// `choice` must be 0 or 1. Returns `a` if 1, `b` if 0.
#[inline]
pub fn ct_select_u8(choice: u8, a: u8, b: u8) -> u8 {
    // black_box on choice reduces risk of the optimizer turning this into a branch
    let choice = core::hint::black_box(choice) & 1;
    let mask = (choice as i8).wrapping_neg() as u8;
    (a & mask) | (b & !mask)
}

/// Constant-time selection between two `u64` values.
#[inline]
pub fn ct_select_u64(choice: u8, a: u64, b: u64) -> u64 {
    let choice = core::hint::black_box(choice) & 1;
    let mask = (choice as i8).wrapping_neg() as u64;
    (a & mask) | (b & !mask)
}

/// Constant-time conditional assignment: `dst = choice ? src : dst`.
#[inline]
pub fn ct_assign_u8(choice: u8, dst: &mut u8, src: u8) {
    *dst = ct_select_u8(choice, src, *dst);
}

/// Constant-time conditional copy of equal-length slices.
/// If `choice == 1` copies `src` into `dst`, otherwise leaves `dst` unchanged.
/// `choice` must be 0 or 1; any other value is masked to a single bit so the
/// result stays branchless (no secret-dependent branch on the choice).
#[inline]
pub fn ct_assign_bytes(choice: u8, dst: &mut [u8], src: &[u8]) {
    debug_assert_eq!(dst.len(), src.len());
    let choice = core::hint::black_box(choice) & 1;
    let mask = (choice as i8).wrapping_neg() as u8;
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d = (*d & !mask) | (*s & mask);
    }
}

/// Constant-time copy: always copies, but useful as a building block.
#[inline]
pub fn ct_copy(dst: &mut [u8], src: &[u8]) {
    debug_assert_eq!(dst.len(), src.len());
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d = *s;
    }
}

/// Best-effort zeroization of a byte slice.
///
/// Writes zeros through a volatile-style loop. Without compiler support
/// (`compiler_fence` / `black_box`) a sufficiently aggressive optimizer might
/// still eliminate this; call sites that need stronger guarantees should use
/// platform-specific secure zeroization when available.
#[inline(never)]
pub fn ct_zeroize(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        *b = 0;
    }
    // Prevent the optimizer from eliminating the zeroing writes.
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    core::hint::black_box(buf.as_ptr());
}

/// Constant-time check that all bytes are zero. Returns `1` if all zero.
#[inline]
pub fn ct_is_zero_slice(buf: &[u8]) -> u8 {
    let mut acc: u8 = 0;
    for b in buf {
        acc |= *b;
    }
    ct_is_zero(acc)
}

/// Verify a MAC / digest in constant time.
///
/// Returns `Ok(())` if equal, `Err` otherwise. Always examines every byte
/// when lengths match.
#[inline]
pub fn ct_verify(a: &[u8], b: &[u8]) -> Result<(), crate::error::Error> {
    if ct_eq(a, b) == 1 {
        Ok(())
    } else {
        Err(crate::error::Error::VerificationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ct_eq_equal() {
        assert_eq!(ct_eq(&[1, 2, 3, 4], &[1, 2, 3, 4]), 1);
        assert!(ct_eq_bool(&[1, 2, 3], &[1, 2, 3]));
    }

    #[test]
    fn test_ct_eq_diff() {
        assert_eq!(ct_eq(&[1, 2, 3, 4], &[1, 2, 3, 5]), 0);
        assert!(!ct_eq_bool(&[1, 2, 3], &[1, 2, 4]));
    }

    #[test]
    fn test_ct_eq_len_mismatch() {
        assert_eq!(ct_eq(&[1, 2], &[1, 2, 3]), 0);
    }

    #[test]
    fn test_ct_is_zero() {
        assert_eq!(ct_is_zero(0), 1);
        assert_eq!(ct_is_zero(1), 0);
        assert_eq!(ct_is_zero(255), 0);
    }

    #[test]
    fn test_ct_select() {
        assert_eq!(ct_select_u8(1, 0xAA, 0xBB), 0xAA);
        assert_eq!(ct_select_u8(0, 0xAA, 0xBB), 0xBB);
        assert_eq!(ct_select_u64(1, 0x1111, 0x2222), 0x1111);
        assert_eq!(ct_select_u64(0, 0x1111, 0x2222), 0x2222);
    }

    #[test]
    fn test_ct_assign_bytes() {
        let mut dst = [0u8; 4];
        let src = [9u8, 8, 7, 6];
        ct_assign_bytes(0, &mut dst, &src);
        assert_eq!(dst, [0, 0, 0, 0]);
        ct_assign_bytes(1, &mut dst, &src);
        assert_eq!(dst, [9, 8, 7, 6]);
    }

    #[test]
    fn test_ct_eq_u64() {
        assert_eq!(ct_eq_u64(0xdeadbeef, 0xdeadbeef), 1);
        assert_eq!(ct_eq_u64(0xdeadbeef, 0xdeadbeef + 1), 0);
    }

    #[test]
    fn test_ct_zeroize() {
        let mut buf = [1u8, 2, 3, 4, 5];
        ct_zeroize(&mut buf);
        assert_eq!(buf, [0, 0, 0, 0, 0]);
        assert_eq!(ct_is_zero_slice(&buf), 1);
    }

    #[test]
    fn test_ct_verify() {
        assert!(ct_verify(&[1, 2, 3], &[1, 2, 3]).is_ok());
        assert!(ct_verify(&[1, 2, 3], &[1, 2, 4]).is_err());
    }

    #[test]
    fn test_ct_is_zero_slice() {
        assert_eq!(ct_is_zero_slice(&[0, 0, 0]), 1);
        assert_eq!(ct_is_zero_slice(&[0, 1, 0]), 0);
    }
}
