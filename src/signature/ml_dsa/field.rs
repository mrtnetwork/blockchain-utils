//! ℤ_q arithmetic for ML-DSA (q = 8380417). Prefer branch-free paths on secrets.

use super::params::Q;

#[inline]
pub fn reduce(a: i64) -> i32 {
    let mut r = (a % Q as i64) as i32;
    // CT-ish: add q if negative without secret-dependent panic
    let mask = r >> 31; // -1 if neg
    r = r.wrapping_add(mask & Q);
    r
}

#[inline]
pub fn reduce_i32(a: i32) -> i32 {
    reduce(a as i64)
}

#[inline]
pub fn add(a: i32, b: i32) -> i32 {
    let mut r = a + b;
    // r in (-2q, 2q)
    r -= Q & -((r >= Q) as i32);
    r += Q & -((r < 0) as i32);
    r
}

#[inline]
pub fn sub(a: i32, b: i32) -> i32 {
    let mut r = a - b;
    r += Q & -((r < 0) as i32);
    r -= Q & -((r >= Q) as i32);
    r
}

#[inline]
pub fn mul(a: i32, b: i32) -> i32 {
    reduce(a as i64 * b as i64)
}

#[inline]
pub fn center(a: i32) -> i32 {
    let r = reduce_i32(a);
    if r > Q / 2 {
        r - Q
    } else {
        r
    }
}
