//! Monero / CryptoNote helpers on Ed25519.
//!
//! - [`check_key_vartime`] — `ge_frombytes_vartime`-style on-curve check (public keys)
//! - [`from_fe_bytes_vartime`] — full `ge_fromfe_frombytes_vartime` Elligator map (public `u`)
//! - [`mul_by_cofactor`] / [`scalarmult_key_image`]

use super::fe::Fe;
use super::point::{Ed25519Point, Extended};
use super::scalar::Scalar;
use crate::curve::error::CurveResult;
use crate::curve::traits::{CurvePoint, FieldElement};

/// √(-1) mod p (same as Ristretto / RFC 8032).
const SQRT_M1_LE: [u8; 32] = [
    0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4, 0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18, 0x43, 0x2f,
    0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b, 0x0b, 0xdf, 0xc1, 0x4f, 0x80, 0x24, 0x83, 0x2b,
];

fn sqrt_m1() -> Fe {
    Fe::from_bytes_le(&SQRT_M1_LE).expect("SQRT_M1")
}

/// −A where A = 486662 (Curve25519 Montgomery).
fn fe_ma() -> Fe {
    Fe::from_bytes_le(&[
        0xe7, 0x92, 0xf8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ])
    .expect("ma")
}

/// −A² (Monero fe_ma2).
fn fe_ma2() -> Fe {
    Fe::from_bytes_le(&[
        0xc9, 0xe3, 0x3d, 0xdb, 0xc8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ])
    .expect("ma2")
}

fn fe_fffb1() -> Fe {
    Fe::from_bytes_le(&[
        0xee, 0x41, 0x1c, 0x32, 0x75, 0x69, 0xa7, 0x22, 0x8d, 0x73, 0x2a, 0xb9, 0xa8, 0x04, 0x94,
        0xd1, 0xe3, 0x19, 0xfb, 0x41, 0x37, 0xc5, 0xa9, 0x20, 0x17, 0x1b, 0xd6, 0xda, 0xef, 0xfb,
        0x71, 0x7e,
    ])
    .expect("fffb1")
}
fn fe_fffb2() -> Fe {
    Fe::from_bytes_le(&[
        0xe0, 0x9a, 0x7c, 0x60, 0x83, 0x64, 0xde, 0xd2, 0xdf, 0xf7, 0x56, 0x04, 0x46, 0x03, 0xde,
        0x51, 0xbe, 0x5f, 0x16, 0xc0, 0xb7, 0x51, 0xd4, 0x91, 0xf6, 0x2c, 0x5a, 0x04, 0x0a, 0x1e,
        0x06, 0x4d,
    ])
    .expect("fffb2")
}
fn fe_fffb3() -> Fe {
    Fe::from_bytes_le(&[
        0x66, 0x2c, 0x30, 0x17, 0x87, 0x7d, 0x1b, 0x58, 0x29, 0x42, 0x96, 0xa5, 0x4e, 0xff, 0x24,
        0x40, 0xed, 0xa2, 0x0d, 0x3f, 0x40, 0x46, 0x95, 0xb8, 0xef, 0x08, 0xc2, 0x14, 0x0d, 0x11,
        0x4a, 0x67,
    ])
    .expect("fffb3")
}
fn fe_fffb4() -> Fe {
    Fe::from_bytes_le(&[
        0x86, 0x91, 0xb3, 0xb6, 0x03, 0x19, 0x3d, 0x85, 0x49, 0x4a, 0x3f, 0xa1, 0x08, 0xfc, 0x46,
        0xee, 0x2e, 0x43, 0xf7, 0x7e, 0x88, 0xf4, 0xc0, 0x26, 0xf9, 0xdb, 0x67, 0x10, 0x03, 0xf3,
        0x43, 0x1a,
    ])
    .expect("fffb4")
}

/// Exact Monero/ref10 `fe_divpowm1(r, u, v)` using the fe_pow22523 ladder.
fn fe_divpowm1(u: &Fe, v: &Fe) -> Fe {
    let v3 = v.square().mul(v);
    let uv7 = v3.square().mul(v).mul(u);

    let mut t0 = uv7.square();
    let mut t1 = t0.square().square().mul(&uv7);
    t0 = t0.mul(&t1).square().mul(&t1);
    t1 = t0.square();
    for _ in 0..4 {
        t1 = t1.square();
    }
    t0 = t1.mul(&t0);
    t1 = t0.square();
    for _ in 0..9 {
        t1 = t1.square();
    }
    t1 = t1.mul(&t0);
    let mut t2 = t1.square();
    for _ in 0..19 {
        t2 = t2.square();
    }
    t1 = t2.mul(&t1);
    for _ in 0..10 {
        t1 = t1.square();
    }
    t0 = t1.mul(&t0);
    t1 = t0.square();
    for _ in 0..49 {
        t1 = t1.square();
    }
    t1 = t1.mul(&t0);
    t2 = t1.square();
    for _ in 0..99 {
        t2 = t2.square();
    }
    t1 = t2.mul(&t1);
    for _ in 0..50 {
        t1 = t1.square();
    }
    t0 = t1.mul(&t0).square().square().mul(&uv7);
    t0.mul(&v3).mul(u)
}

/// Variable-time on-curve check (public keys only).
pub fn check_key_vartime(bytes: &[u8; 32]) -> bool {
    Ed25519Point::from_bytes(bytes).is_ok()
}

/// Alias — prefer [`check_key_vartime`].
pub fn check_key(bytes: &[u8; 32]) -> bool {
    check_key_vartime(bytes)
}

pub fn from_bytes(bytes: &[u8; 32]) -> CurveResult<Ed25519Point> {
    Ed25519Point::from_bytes(bytes)
}

fn affine_from_proj(x: Fe, y: Fe, z: Fe) -> CurveResult<Ed25519Point> {
    let zinv = z.invert()?;
    let xa = x.mul(&zinv);
    let ya = y.mul(&zinv);
    Ok(Ed25519Point::from_extended(Extended {
        x: xa,
        y: ya,
        z: Fe::one(),
        t: xa.mul(&ya),
    }))
}

/// Full Monero / CryptoNote `ge_fromfe_frombytes_vartime`.
///
/// **Variable-time.** Feed only public field elements (e.g. hash-to-point
/// from a public message). Never pass secret scalars or secret field data.
///
/// Control flow mirrors monero `crypto-ops.c` ge_fromfe_frombytes_vartime.
pub fn from_fe_bytes_vartime(bytes: &[u8; 32]) -> CurveResult<Ed25519Point> {
    // NOTE: full-width parse (no top-bit clearing) — matches Monero
    // `fe_frombytes` inside `ge_fromfe_frombytes_vartime`.
    let u = Fe::from_bytes_full(bytes);

    let two = Fe::one().add(&Fe::one());
    let v = two.mul(&u.square());
    let w = v.add(&Fe::one());
    let x = w.square().add(&fe_ma2().mul(&v));

    let mut rx = fe_divpowm1(&w, &x);
    let mut y = w.sub(&rx.square().mul(&x));
    let mut z = fe_ma();
    #[allow(unused_assignments)]
    let mut sign: u8 = 0;

    if y.ct_eq(&Fe::zero()) == 0 {
        y = w.add(&rx.square().mul(&x));
        if y.ct_eq(&Fe::zero()) == 0 {
            // negative:
            // C: fe_mul(x, x, fe_sqrtm1) where x was already (rx² * old_x)
            // i.e. x := rx² * old_x * sqrtm1, then y := w - x
            let x_chk = rx.square().mul(&x).mul(&sqrt_m1());
            y = w.sub(&x_chk);
            if y.ct_eq(&Fe::zero()) == 0 {
                rx = rx.mul(&fe_fffb3());
            } else {
                rx = rx.mul(&fe_fffb4());
            }
            sign = 1;
            // z remains -A (not multiplied by v)
            if (rx.is_odd() != 0) != (sign != 0) {
                rx = rx.negate();
            }
            let rz = z.add(&w);
            let ry = z.sub(&w);
            let rx = rx.mul(&rz);
            return affine_from_proj(rx, ry, rz);
        } else {
            rx = rx.mul(&fe_fffb1());
        }
    } else {
        rx = rx.mul(&fe_fffb2());
    }

    rx = rx.mul(&u);
    z = z.mul(&v);
    sign = 0;

    if (rx.is_odd() != 0) != (sign != 0) {
        rx = rx.negate();
    }
    let rz = z.add(&w);
    let ry = z.sub(&w);
    let rx = rx.mul(&rz);
    affine_from_proj(rx, ry, rz)
}

/// Hash-to-point then clear cofactor: `[8] Hp(u)` — typical Monero key-image prep.
/// Variable-time Elligator + cofactor clear. Public inputs only.
pub fn from_fe_bytes_clear_cofactor_vartime(bytes: &[u8; 32]) -> CurveResult<Ed25519Point> {
    Ok(mul_by_cofactor(&from_fe_bytes_vartime(bytes)?))
}

/// Alias — prefer [`from_fe_bytes_vartime`].
pub fn from_fe_bytes(bytes: &[u8; 32]) -> CurveResult<Ed25519Point> {
    from_fe_bytes_vartime(bytes)
}

/// Alias — prefer [`from_fe_bytes_clear_cofactor_vartime`].
pub fn from_fe_bytes_clear_cofactor(bytes: &[u8; 32]) -> CurveResult<Ed25519Point> {
    from_fe_bytes_clear_cofactor_vartime(bytes)
}

pub fn mul_by_cofactor(p: &Ed25519Point) -> Ed25519Point {
    p.double().double().double()
}

/// Fused `8 * (s * P)` on live points: no intermediate encoding.
/// `s` is secret (uses CT `mul`); `P` may be any on-curve point.
/// This is Monero `generate_key_derivation` without the compress/decompress
/// round-trip of `mul_by_cofactor(mul(s, P))`.
pub fn scalarmult8(p: &Ed25519Point, s: &Scalar) -> Ed25519Point {
    mul_by_cofactor(&p.mul(s))
}

/// Key-image style scalar mult: `I = a · Hp`.
///
/// **`a` is secret** (e.g. Monero private spend key). This is **not** a
/// variable-time helper — it uses `Ed25519Point::mul` (`mul_ct`).
pub fn scalarmult_key_image(hp: &Ed25519Point, a: &Scalar) -> Ed25519Point {
    hp.mul(a)
}

/// Same as [`scalarmult_key_image`], taking a [`SecretScalar`] (preferred for spend keys).
pub fn scalarmult_key_image_secret(
    hp: &Ed25519Point,
    a: &crate::curve::ed25519::SecretScalar,
) -> Ed25519Point {
    hp.mul(a.as_scalar())
}

// ---------------------------------------------------------------------------
// Variable-time multi-scalar mult (Monero / crypto-ops style, matches the reference
// `CryptoOps.ge*PointVar`.
//
// Precomp tables hold odd multiples: [P, 3P, 5P, …, 15P] (8 entries).
// Scalars are 32-byte little-endian (Monero convention).
// ---------------------------------------------------------------------------

/// Signed radix-16 "slide" of a 32-byte LE scalar into 256 digits in `[-15, 15]`.
/// Same algorithm as Monero `slide` / `CryptoOps.slide`.
pub fn slide(r: &mut [i8; 256], a: &[u8; 32]) {
    for i in 0..256 {
        r[i] = ((a[i >> 3] >> (i & 7)) & 1) as i8;
    }
    for i in 0..256 {
        if r[i] == 0 {
            continue;
        }
        let mut b = 1;
        while b <= 6 && i + b < 256 {
            if r[i + b] != 0 {
                let shifted = r[i + b] << b;
                if r[i] + shifted <= 15 {
                    r[i] += shifted;
                    r[i + b] = 0;
                } else if r[i] - shifted >= -15 {
                    r[i] -= shifted;
                    for rk in r.iter_mut().skip(i + b) {
                        if *rk == 0 {
                            *rk = 1;
                            break;
                        }
                        *rk = 0;
                    }
                } else {
                    break;
                }
            }
            b += 1;
        }
    }
}

/// Build odd-multiples table `[P, 3P, …, 15P]` (`geDsmPrecompVar`).
pub fn ge_dsm_precomp_var(point: &Ed25519Point) -> [Ed25519Point; 8] {
    let two_p = point.double();
    let mut current = *point;
    let mut out = [Ed25519Point::identity(); 8];
    for o in out.iter_mut() {
        *o = current;
        current = current.add(&two_p);
    }
    out
}

/// Basepoint odd multiples `[B, 3B, …, 15B]` (`geBiPointBytes`).
fn base_odd_multiples() -> [Ed25519Point; 8] {
    ge_dsm_precomp_var(&Ed25519Point::generator())
}

#[inline]
fn table_pick(table: &[Ed25519Point; 8], val: i8) -> Option<Ed25519Point> {
    if val == 0 {
        return None;
    }
    let idx = ((val.unsigned_abs() as usize) - 1) / 2;
    if idx >= 8 {
        return None;
    }
    let p = table[idx];
    Some(if val > 0 { p } else { p.neg() })
}

#[inline]
fn acc_add(r: &mut Option<Ed25519Point>, p: Option<Ed25519Point>) {
    if let Some(p) = p {
        *r = Some(match *r {
            None => p,
            Some(r0) => r0.add(&p),
        });
    }
}

/// `a·A + b·B` with precomputed odd-multiples tables for both points.
///
/// Ref: `geDoubleScalarMultPrecompPointVar(a, aI, b, bI)`.
pub fn ge_double_scalar_mult_precomp_point_var(
    a: &[u8; 32],
    a_i: &[Ed25519Point; 8],
    b: &[u8; 32],
    b_i: &[Ed25519Point; 8],
) -> Ed25519Point {
    let mut aslide = [0i8; 256];
    let mut bslide = [0i8; 256];
    slide(&mut aslide, a);
    slide(&mut bslide, b);

    let mut r: Option<Ed25519Point> = None;
    for i in (0..256).rev() {
        let a_val = aslide[i];
        let b_val = bslide[i];
        if r.is_none() {
            if a_val == 0 && b_val == 0 {
                continue;
            }
            acc_add(&mut r, table_pick(a_i, a_val));
            acc_add(&mut r, table_pick(b_i, b_val));
        } else {
            r = Some(r.unwrap().double());
            acc_add(&mut r, table_pick(a_i, a_val));
            acc_add(&mut r, table_pick(b_i, b_val));
        }
    }
    r.unwrap_or_else(Ed25519Point::identity)
}

/// `a·B + b·P + c·Q` where `B` is the basepoint (uses base odd-multiples table),
/// and `b_i` / `c_i` are precomp tables for `P` / `Q`.
///
/// Ref: `geTripleScalarMultBasePointVar(a:, b:, bI:, c:, cI:)`.
pub fn ge_triple_scalar_mult_base_point_var(
    a: &[u8; 32],
    b: &[u8; 32],
    b_i: &[Ed25519Point; 8],
    c: &[u8; 32],
    c_i: &[Ed25519Point; 8],
) -> Ed25519Point {
    let mut aslide = [0i8; 256];
    let mut bslide = [0i8; 256];
    let mut cslide = [0i8; 256];
    slide(&mut aslide, a);
    slide(&mut bslide, b);
    slide(&mut cslide, c);
    let base_i = base_odd_multiples();

    let mut r: Option<Ed25519Point> = None;
    for i in (0..256).rev() {
        let a_val = aslide[i];
        let b_val = bslide[i];
        let c_val = cslide[i];
        if r.is_none() {
            if a_val == 0 && b_val == 0 && c_val == 0 {
                continue;
            }
            acc_add(&mut r, table_pick(&base_i, a_val));
            acc_add(&mut r, table_pick(b_i, b_val));
            acc_add(&mut r, table_pick(c_i, c_val));
        } else {
            r = Some(r.unwrap().double());
            acc_add(&mut r, table_pick(&base_i, a_val));
            acc_add(&mut r, table_pick(b_i, b_val));
            acc_add(&mut r, table_pick(c_i, c_val));
        }
    }
    r.unwrap_or_else(Ed25519Point::identity)
}

/// `a·A + b·B` where `B` is the basepoint and `A = g_a` (precomp built inside).
///
/// Ref: `geDoubleScalarMultBasePointVar(a:, gA:, b:)`.
pub fn ge_double_scalar_mult_base_point_var(
    a: &[u8; 32],
    g_a: &Ed25519Point,
    b: &[u8; 32],
) -> Ed25519Point {
    let a_i = ge_dsm_precomp_var(g_a);
    let mut aslide = [0i8; 256];
    let mut bslide = [0i8; 256];
    slide(&mut aslide, a);
    slide(&mut bslide, b);
    let base_i = base_odd_multiples();

    let mut r: Option<Ed25519Point> = None;
    for i in (0..256).rev() {
        let a_val = aslide[i];
        let b_val = bslide[i];
        if r.is_none() {
            if a_val == 0 && b_val == 0 {
                continue;
            }
            // Note: reference uses a for A-table and b for base table
            acc_add(&mut r, table_pick(&a_i, a_val));
            acc_add(&mut r, table_pick(&base_i, b_val));
        } else {
            r = Some(r.unwrap().double());
            acc_add(&mut r, table_pick(&a_i, a_val));
            acc_add(&mut r, table_pick(&base_i, b_val));
        }
    }
    r.unwrap_or_else(Ed25519Point::identity)
}

/// `a·A + b·B + c·C` with precomputed odd-multiples tables for all three points.
///
/// Ref: `geTripleScalarMultPrecompPointVar(a, aI, b, bI, c, cI)`.
pub fn ge_triple_scalar_mult_precomp_point_var(
    a: &[u8; 32],
    a_i: &[Ed25519Point; 8],
    b: &[u8; 32],
    b_i: &[Ed25519Point; 8],
    c: &[u8; 32],
    c_i: &[Ed25519Point; 8],
) -> Ed25519Point {
    let mut aslide = [0i8; 256];
    let mut bslide = [0i8; 256];
    let mut cslide = [0i8; 256];
    slide(&mut aslide, a);
    slide(&mut bslide, b);
    slide(&mut cslide, c);

    let mut r: Option<Ed25519Point> = None;
    for i in (0..256).rev() {
        let a_val = aslide[i];
        let b_val = bslide[i];
        let c_val = cslide[i];
        if r.is_none() {
            if a_val == 0 && b_val == 0 && c_val == 0 {
                continue;
            }
            acc_add(&mut r, table_pick(a_i, a_val));
            acc_add(&mut r, table_pick(b_i, b_val));
            acc_add(&mut r, table_pick(c_i, c_val));
        } else {
            r = Some(r.unwrap().double());
            acc_add(&mut r, table_pick(a_i, a_val));
            acc_add(&mut r, table_pick(b_i, b_val));
            acc_add(&mut r, table_pick(c_i, c_val));
        }
    }
    r.unwrap_or_else(Ed25519Point::identity)
}

#[cfg(test)]
mod mult_var_tests {
    use super::*;
    use crate::curve::ed25519::Scalar;
    use crate::curve::traits::CurvePoint;

    fn le32(n: u8) -> [u8; 32] {
        let mut s = [0u8; 32];
        s[0] = n;
        s
    }

    #[test]
    fn double_base_matches_naive() {
        let g = Ed25519Point::generator();
        let a = le32(5);
        let b = le32(7);
        // 5*G + 7*B = 12*G when A=G
        let got = ge_double_scalar_mult_base_point_var(&a, &g, &b);
        let s = Scalar::from_bytes_le(&{
            let mut t = [0u8; 32];
            t[0] = 12;
            t
        })
        .unwrap();
        let exp = g.mul(&s);
        let mut gb = [0u8; 32];
        let mut eb = [0u8; 32];
        got.to_bytes_compressed(&mut gb).unwrap();
        exp.to_bytes_compressed(&mut eb).unwrap();
        assert_eq!(gb, eb);
    }

    #[test]
    fn precomp_double_matches_naive() {
        let g = Ed25519Point::generator();
        let p = g.double();
        let a_i = ge_dsm_precomp_var(&p);
        let b_i = ge_dsm_precomp_var(&g);
        let a = le32(3);
        let b = le32(4);
        let got = ge_double_scalar_mult_precomp_point_var(&a, &a_i, &b, &b_i);
        // 3*(2G) + 4*G = 10*G
        let s = Scalar::from_bytes_le(&{
            let mut t = [0u8; 32];
            t[0] = 10;
            t
        })
        .unwrap();
        let exp = g.mul(&s);
        let mut gb = [0u8; 32];
        let mut eb = [0u8; 32];
        got.to_bytes_compressed(&mut gb).unwrap();
        exp.to_bytes_compressed(&mut eb).unwrap();
        assert_eq!(gb, eb);
    }

    #[test]
    fn triple_precomp_matches_naive() {
        let g = Ed25519Point::generator();
        let a_i = ge_dsm_precomp_var(&g);
        let b_i = ge_dsm_precomp_var(&g.double());
        let c_i = ge_dsm_precomp_var(&g.double().double());
        let a = le32(2);
        let b = le32(3);
        let c = le32(1);
        let got = ge_triple_scalar_mult_precomp_point_var(&a, &a_i, &b, &b_i, &c, &c_i);
        // 2*G + 3*(2G) + 1*(4G) = 2+6+4 = 12*G
        let s = Scalar::from_bytes_le(&{
            let mut t = [0u8; 32];
            t[0] = 12;
            t
        })
        .unwrap();
        let exp = g.mul(&s);
        let mut gb = [0u8; 32];
        let mut eb = [0u8; 32];
        got.to_bytes_compressed(&mut gb).unwrap();
        exp.to_bytes_compressed(&mut eb).unwrap();
        assert_eq!(gb, eb);
    }

    #[test]
    fn zero_scalars_yield_identity() {
        let z = [0u8; 32];
        let g = Ed25519Point::generator();
        let t = ge_dsm_precomp_var(&g);
        let r = ge_double_scalar_mult_precomp_point_var(&z, &t, &z, &t);
        assert_eq!(r.ct_is_identity(), 1);
    }

    #[test]
    fn base_odd_table_first_is_generator() {
        let t = base_odd_multiples();
        let g = Ed25519Point::generator();
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        t[0].to_bytes_compressed(&mut a).unwrap();
        g.to_bytes_compressed(&mut b).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn hash_to_ec_deterministic_and_on_curve() {
        let p1 = hash_to_ec(b"monero-hash-to-ec").unwrap();
        let p2 = hash_to_ec(b"monero-hash-to-ec").unwrap();
        assert_eq!(p1, p2);
        assert!(check_key(&p1));
        let q = hash_to_ec(b"other").unwrap();
        assert_ne!(p1, q);
    }
}

/// Monero `hash_to_ec`: Keccak-256(data) as field element → Elligator map → `[8]P`.
///
/// Matches Ref:
/// ```
/// Keccak(32)..update(data).digest() → geFromfeFrombytesVartime → geMul8 → compressed
/// ```
pub fn hash_to_ec(data: &[u8]) -> CurveResult<[u8; 32]> {
    use crate::hash::keccak::Keccak;
    let mut k = Keccak::keccak256();
    k.update(data);
    let fe = k.finalize();
    let p = from_fe_bytes_clear_cofactor_vartime(&fe)?;
    let mut out = [0u8; 32];
    p.to_bytes_compressed(&mut out)
        .map_err(|_| crate::curve::error::CurveError::InvalidPoint)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generator_is_valid_key() {
        let g = Ed25519Point::generator();
        let mut out = [0u8; 32];
        g.to_bytes_compressed(&mut out).unwrap();
        // RFC 8032 basepoint encoding
        const G: [u8; 32] = [
            0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66,
        ];
        assert_eq!(out, G, "Ed25519 basepoint compress");
        assert!(check_key(&out));
    }

    #[test]
    fn cofactor_mul_eight_g() {
        let g = Ed25519Point::generator();
        let g8 = mul_by_cofactor(&g);
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        g8.to_bytes_compressed(&mut a).unwrap();
        // Scalar 8
        let _s = Scalar::zero();
        // one+one ... eight via bit
        let eight = {
            let mut e = [0u8; 32];
            e[0] = 8;
            Scalar::from_bytes_le(&e).unwrap()
        };
        g.mul(&eight).to_bytes_compressed(&mut b).unwrap();
        assert_eq!(a, b, "[8]G via double^3 == [8]G via scalar");
        // non-identity
        assert_ne!(a, [0u8; 32]);
    }

    #[test]
    fn from_fe_produces_on_curve() {
        // Fixed field element u = 7 (LE)
        let mut u = [0u8; 32];
        u[0] = 7;
        let p = from_fe_bytes(&u).expect("from_fe");
        let mut out = [0u8; 32];
        p.to_bytes_compressed(&mut out).unwrap();
        assert!(check_key(&out), "from_fe result must pass check_key");
        assert_ne!(out, [0u8; 32]);
        // Deterministic
        let p2 = from_fe_bytes(&u).unwrap();
        let mut out2 = [0u8; 32];
        p2.to_bytes_compressed(&mut out2).unwrap();
        assert_eq!(out, out2);
    }

    #[test]
    fn from_fe_clear_cofactor_on_curve() {
        let mut u = [0u8; 32];
        u[0] = 42;
        let p = from_fe_bytes_clear_cofactor(&u).unwrap();
        let mut out = [0u8; 32];
        p.to_bytes_compressed(&mut out).unwrap();
        assert!(check_key(&out));
        // [8]P should still be on curve and equal to 8 * from_fe
        let p0 = from_fe_bytes(&u).unwrap();
        let mut eight = [0u8; 32];
        eight[0] = 8;
        let s = Scalar::from_bytes_le(&eight).unwrap();
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        p.to_bytes_compressed(&mut a).unwrap();
        p0.mul(&s).to_bytes_compressed(&mut b).unwrap();
        assert_eq!(a, b, "clear_cofactor == [8] * from_fe");
    }

    #[test]
    fn from_fe_zero_u() {
        let u = [0u8; 32];
        let p = from_fe_bytes(&u).expect("from_fe zero");
        let mut out = [0u8; 32];
        p.to_bytes_compressed(&mut out).unwrap();
        assert!(check_key(&out));
    }

    #[test]
    fn key_image_identity() {
        let mut u = [0u8; 32];
        u[0] = 0x42;
        let hp = from_fe_bytes_clear_cofactor(&u).unwrap();
        let a = Scalar::one();
        let i = scalarmult_key_image(&hp, &a);
        let mut ia = [0u8; 32];
        let mut hb = [0u8; 32];
        i.to_bytes_compressed(&mut ia).unwrap();
        hp.to_bytes_compressed(&mut hb).unwrap();
        assert_eq!(ia, hb, "1 · Hp == Hp");
    }

    #[test]
    fn key_image_determinism() {
        let mut u = [0u8; 32];
        u[1] = 0x11;
        let hp = from_fe_bytes_clear_cofactor(&u).unwrap();
        let mut a_bytes = [0u8; 32];
        a_bytes[0] = 9;
        let a = Scalar::from_bytes_mod_order(&a_bytes);
        let i1 = scalarmult_key_image(&hp, &a);
        let i2 = scalarmult_key_image(&hp, &a);
        let mut b1 = [0u8; 32];
        let mut b2 = [0u8; 32];
        i1.to_bytes_compressed(&mut b1).unwrap();
        i2.to_bytes_compressed(&mut b2).unwrap();
        assert_eq!(b1, b2);
    }

    #[test]
    fn key_image_homomorphism() {
        // (2a) · Hp == a · (2 · Hp)
        let mut u = [0u8; 32];
        u[2] = 0xab;
        let hp = from_fe_bytes_clear_cofactor(&u).unwrap();
        let mut a_bytes = [0u8; 32];
        a_bytes[0] = 5;
        let a = Scalar::from_bytes_mod_order(&a_bytes);
        let two = Scalar::one().add(&Scalar::one());
        let a2 = a.mul(&two);
        let left = scalarmult_key_image(&hp, &a2);
        let two_hp = hp.mul(&two);
        let right = scalarmult_key_image(&two_hp, &a);
        let mut lb = [0u8; 32];
        let mut rb = [0u8; 32];
        left.to_bytes_compressed(&mut lb).unwrap();
        right.to_bytes_compressed(&mut rb).unwrap();
        assert_eq!(lb, rb, "(2a)·Hp == a·(2·Hp)");
    }

    #[test]
    fn key_image_secret_matches_plain() {
        let mut u = [0u8; 32];
        u[3] = 0x7e;
        let hp = from_fe_bytes_clear_cofactor(&u).unwrap();
        let mut a_bytes = [0u8; 32];
        a_bytes[0] = 13;
        let a = Scalar::from_bytes_mod_order(&a_bytes);
        let sk = crate::curve::ed25519::SecretScalar::from_scalar(a);
        let i1 = scalarmult_key_image(&hp, &a);
        let i2 = scalarmult_key_image_secret(&hp, &sk);
        let mut b1 = [0u8; 32];
        let mut b2 = [0u8; 32];
        i1.to_bytes_compressed(&mut b1).unwrap();
        i2.to_bytes_compressed(&mut b2).unwrap();
        assert_eq!(b1, b2, "SecretScalar path matches Scalar path");
    }

    #[test]
    fn key_image_independent_of_hp_rebuild() {
        let mut u = [0u8; 32];
        for (i, uj) in u.iter_mut().enumerate() {
            *uj = (i as u8).wrapping_mul(17).wrapping_add(3);
        }
        let mut a_bytes = [0u8; 32];
        a_bytes[0] = 0x21;
        a_bytes[15] = 0x43;
        let a = Scalar::from_bytes_mod_order(&a_bytes);
        let hp1 = from_fe_bytes_clear_cofactor(&u).unwrap();
        let hp2 = from_fe_bytes_clear_cofactor(&u).unwrap();
        let i1 = scalarmult_key_image(&hp1, &a);
        let i2 = scalarmult_key_image(&hp2, &a);
        let mut b1 = [0u8; 32];
        let mut b2 = [0u8; 32];
        i1.to_bytes_compressed(&mut b1).unwrap();
        i2.to_bytes_compressed(&mut b2).unwrap();
        assert_eq!(b1, b2);
    }
}
