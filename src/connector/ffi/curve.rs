//! Unified elliptic-curve FFI.
//!
//! Stateless byte-oriented API: inputs/outputs are compressed points / scalars.
//! Errors are integer codes; Callers map them to [CurveErrorCode].

use core::slice;

use crate::curve::bls::{hash_to_g1, hash_to_g2, G1Point, G2Point};
use crate::curve::bn254::{G1Point as Bn254G1Point, G2Point as Bn254G2Point};
use crate::curve::pallas::{self as pallas, hash_to_curve_pasta, to_bytes_pasta};
use crate::curve::traits::{CurvePoint, Scalar as ScalarTrait};
use crate::curve::vesta::{self as vesta};
use crate::curve::Secp256r1Scalar;
use crate::curve::{
    Ed25519Point, Ed25519Scalar, JubJubPoint, PallasPoint, RistrettoPoint, Secp256k1Point,
    Secp256k1Scalar, Secp256r1Point, VestaPoint,
};

use crate::hash::sha256;

// ---------------------------------------------------------------------------
// Curve ids
// ---------------------------------------------------------------------------

pub const BU_CURVE_SECP256K1: u32 = 1;
pub const BU_CURVE_SECP256R1: u32 = 2;
pub const BU_CURVE_ED25519: u32 = 3;
pub const BU_CURVE_RISTRETTO: u32 = 4;
pub const BU_CURVE_PALLAS: u32 = 5;
pub const BU_CURVE_VESTA: u32 = 6;
pub const BU_CURVE_JUBJUB: u32 = 7;
pub const BU_CURVE_BLS12_G1: u32 = 8;
pub const BU_CURVE_BLS12_G2: u32 = 9;
pub const BU_CURVE_BN254_G1: u32 = 10;
pub const BU_CURVE_BN254_G2: u32 = 11;

// ---------------------------------------------------------------------------
// Error codes (CurveErrorCode)
// ---------------------------------------------------------------------------

pub const BU_CURVE_OK: i32 = 0;
pub const BU_CURVE_ERR_NULL: i32 = 1;
pub const BU_CURVE_ERR_INVALID_CURVE: i32 = 2;
pub const BU_CURVE_ERR_INVALID_POINT: i32 = 3;
pub const BU_CURVE_ERR_INVALID_SCALAR: i32 = 4;
pub const BU_CURVE_ERR_BUFFER: i32 = 5;
pub const BU_CURVE_ERR_UNSUPPORTED: i32 = 6;

fn map_point_err<T>(r: crate::curve::CurveResult<T>) -> Result<T, i32> {
    r.map_err(|_| BU_CURVE_ERR_INVALID_POINT)
}

fn map_scalar_err<T>(r: crate::curve::CurveResult<T>) -> Result<T, i32> {
    r.map_err(|_| BU_CURVE_ERR_INVALID_SCALAR)
}

// NOTE: BLS Fr on the FFI wire is **big-endian**, matching the core API and
// the external connector contract (IETF encoding). There are no LE wire
// conversions: earlier `bls_scalar_{from,to}_wire` LE helpers were removed
// as dead code contradicting the live BE behavior.

/// Compressed point length for `curve`.
#[no_mangle]
pub extern "C" fn bu_curve_point_len(curve: u32) -> usize {
    match curve {
        BU_CURVE_SECP256K1 => Secp256k1Point::COMPRESSED_BYTES,
        BU_CURVE_SECP256R1 => Secp256r1Point::COMPRESSED_BYTES,
        BU_CURVE_ED25519 => Ed25519Point::COMPRESSED_BYTES,
        BU_CURVE_RISTRETTO => RistrettoPoint::COMPRESSED_BYTES,
        BU_CURVE_PALLAS => PallasPoint::COMPRESSED_BYTES,
        BU_CURVE_VESTA => VestaPoint::COMPRESSED_BYTES,
        BU_CURVE_JUBJUB => JubJubPoint::COMPRESSED_BYTES,
        BU_CURVE_BLS12_G1 => G1Point::COMPRESSED_BYTES,
        BU_CURVE_BLS12_G2 => G2Point::COMPRESSED_BYTES,
        BU_CURVE_BN254_G1 => Bn254G1Point::COMPRESSED_BYTES,
        BU_CURVE_BN254_G2 => Bn254G2Point::COMPRESSED_BYTES,
        _ => 0,
    }
}

/// Scalar length for `curve`.
#[no_mangle]
pub extern "C" fn bu_curve_scalar_len(curve: u32) -> usize {
    match curve {
        BU_CURVE_SECP256K1 => Secp256k1Scalar::BYTES,
        BU_CURVE_SECP256R1 => Secp256r1Scalar::BYTES,
        BU_CURVE_ED25519 => Ed25519Scalar::BYTES,
        BU_CURVE_RISTRETTO => <RistrettoPoint as CurvePoint>::Scalar::BYTES,
        BU_CURVE_PALLAS => <PallasPoint as CurvePoint>::Scalar::BYTES,
        BU_CURVE_VESTA => <VestaPoint as CurvePoint>::Scalar::BYTES,
        BU_CURVE_JUBJUB => <JubJubPoint as CurvePoint>::Scalar::BYTES,
        BU_CURVE_BLS12_G1 | BU_CURVE_BLS12_G2 => <G1Point as CurvePoint>::Scalar::BYTES,
        BU_CURVE_BN254_G1 | BU_CURVE_BN254_G2 => <Bn254G1Point as CurvePoint>::Scalar::BYTES,
        _ => 0,
    }
}

macro_rules! with_point {
    ($curve:expr, $body:ident) => {
        match $curve {
            BU_CURVE_SECP256K1 => $body!(Secp256k1Point),
            BU_CURVE_SECP256R1 => $body!(Secp256r1Point),
            BU_CURVE_ED25519 => $body!(Ed25519Point),
            BU_CURVE_RISTRETTO => $body!(RistrettoPoint),
            BU_CURVE_PALLAS => $body!(PallasPoint),
            BU_CURVE_VESTA => $body!(VestaPoint),
            BU_CURVE_JUBJUB => $body!(JubJubPoint),
            BU_CURVE_BLS12_G1 => $body!(G1Point),
            BU_CURVE_BLS12_G2 => $body!(G2Point),
            BU_CURVE_BN254_G1 => $body!(Bn254G1Point),
            BU_CURVE_BN254_G2 => $body!(Bn254G2Point),
            _ => BU_CURVE_ERR_INVALID_CURVE,
        }
    };
}

fn write_point<P: CurvePoint>(p: &P, out: &mut [u8]) -> i32 {
    if out.len() < P::COMPRESSED_BYTES {
        return BU_CURVE_ERR_BUFFER;
    }
    match p.to_bytes_compressed(out) {
        Ok(()) => BU_CURVE_OK,
        Err(_) => BU_CURVE_ERR_INVALID_POINT,
    }
}

/// Write generator (compressed) into `out`.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_curve_generator(curve: u32, out: *mut u8, out_len: usize) -> i32 {
    if out.is_null() {
        return BU_CURVE_ERR_NULL;
    }
    let out = slice::from_raw_parts_mut(out, out_len);
    match curve {
        BU_CURVE_SECP256K1 => write_point(&Secp256k1Point::generator(), out),
        BU_CURVE_SECP256R1 => write_point(&Secp256r1Point::generator(), out),
        BU_CURVE_ED25519 => write_point(&Ed25519Point::generator(), out),
        BU_CURVE_RISTRETTO => write_point(&RistrettoPoint::generator(), out),
        BU_CURVE_PALLAS => write_point(&PallasPoint::generator(), out),
        BU_CURVE_VESTA => write_point(&VestaPoint::generator(), out),
        BU_CURVE_JUBJUB => write_point(&JubJubPoint::generator(), out),
        BU_CURVE_BLS12_G1 => write_point(&G1Point::generator(), out),
        BU_CURVE_BLS12_G2 => write_point(&G2Point::generator(), out),
        BU_CURVE_BN254_G1 => write_point(&Bn254G1Point::generator(), out),
        BU_CURVE_BN254_G2 => write_point(&Bn254G2Point::generator(), out),
        _ => BU_CURVE_ERR_INVALID_CURVE,
    }
}

/// Write identity into `out`.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_curve_identity(curve: u32, out: *mut u8, out_len: usize) -> i32 {
    if out.is_null() {
        return BU_CURVE_ERR_NULL;
    }
    let out = slice::from_raw_parts_mut(out, out_len);
    macro_rules! id {
        ($P:ty) => {{
            write_point(&<$P>::identity(), out)
        }};
    }
    with_point!(curve, id)
}

/// Uncompressed point length for `curve` (0 = unknown curve id).
/// k1/r1: 65, ed25519/ristretto: 32, pallas/vesta: 64, jubjub: 64,
/// BLS G1: 96, G2: 192, BN254 G1: 64, G2: 128.
#[no_mangle]
pub extern "C" fn bu_curve_point_len_uncomp(curve: u32) -> usize {
    match curve {
        BU_CURVE_SECP256K1 => Secp256k1Point::UNCOMPRESSED_BYTES,
        BU_CURVE_SECP256R1 => Secp256r1Point::UNCOMPRESSED_BYTES,
        BU_CURVE_ED25519 => Ed25519Point::UNCOMPRESSED_BYTES,
        BU_CURVE_RISTRETTO => RistrettoPoint::UNCOMPRESSED_BYTES,
        BU_CURVE_PALLAS => PallasPoint::UNCOMPRESSED_BYTES,
        BU_CURVE_VESTA => VestaPoint::UNCOMPRESSED_BYTES,
        BU_CURVE_JUBJUB => JubJubPoint::UNCOMPRESSED_BYTES,
        BU_CURVE_BLS12_G1 => G1Point::UNCOMPRESSED_BYTES,
        BU_CURVE_BLS12_G2 => G2Point::UNCOMPRESSED_BYTES,
        BU_CURVE_BN254_G1 => Bn254G1Point::UNCOMPRESSED_BYTES,
        BU_CURVE_BN254_G2 => Bn254G2Point::UNCOMPRESSED_BYTES,
        _ => 0,
    }
}

/// Re-encode any accepted point form (compressed or uncompressed) as
/// compressed. This is also strict validation: decode enforces canonical
/// encoding, on-curve (all curves) and subgroup (BLS G1/G2) membership.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_curve_compress(
    curve: u32,
    p: *const u8,
    p_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if p.is_null() || out.is_null() {
        return BU_CURVE_ERR_NULL;
    }
    let p = slice::from_raw_parts(p, p_len);
    let out = slice::from_raw_parts_mut(out, out_len);
    macro_rules! op {
        ($P:ty) => {{
            let pt = match map_point_err(<$P>::from_bytes(p)) {
                Ok(v) => v,
                Err(e) => return e,
            };
            write_point(&pt, out)
        }};
    }
    with_point!(curve, op)
}

/// Re-encode any accepted point form as uncompressed (`out` needs
/// [`bu_curve_point_len_uncomp`] bytes). Same strict validation as
/// [`bu_curve_compress`]. Identity encodings are curve-specific
/// (k1/r1: zeros, BLS: zeros, ed25519: canonical base point encoding).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_curve_uncompress(
    curve: u32,
    p: *const u8,
    p_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if p.is_null() || out.is_null() {
        return BU_CURVE_ERR_NULL;
    }
    let p = slice::from_raw_parts(p, p_len);
    let out = slice::from_raw_parts_mut(out, out_len);
    macro_rules! op {
        ($P:ty) => {{
            let pt = match map_point_err(<$P>::from_bytes(p)) {
                Ok(v) => v,
                Err(e) => return e,
            };
            if out.len() < <$P>::UNCOMPRESSED_BYTES {
                return BU_CURVE_ERR_BUFFER;
            }
            // Trait dispatch (inherent fns take fixed arrays per curve).
            match CurvePoint::to_bytes_uncompressed(&pt, &mut out[..<$P>::UNCOMPRESSED_BYTES]) {
                Ok(()) => BU_CURVE_OK,
                Err(_) => BU_CURVE_ERR_INVALID_POINT,
            }
        }};
    }
    with_point!(curve, op)
}

/// Validate any accepted point form and re-encode it as compressed
/// (`out` needs [`bu_curve_point_len`] bytes). Same strict validation as
/// [`bu_curve_compress`], plus rejection of the point at infinity: this is
/// the key-domain check used by public-key constructors (a valid encoding
/// of infinity is still an invalid *key*).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_curve_normalize_pubkey(
    curve: u32,
    p: *const u8,
    p_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if p.is_null() || out.is_null() {
        return BU_CURVE_ERR_NULL;
    }
    let p = slice::from_raw_parts(p, p_len);
    let out = slice::from_raw_parts_mut(out, out_len);
    macro_rules! op {
        ($P:ty) => {{
            let pt = match map_point_err(<$P>::from_bytes(p)) {
                Ok(v) => v,
                Err(e) => return e,
            };
            if pt.is_identity() {
                return BU_CURVE_ERR_INVALID_POINT;
            }
            write_point(&pt, out)
        }};
    }
    with_point!(curve, op)
}

/// 1 = point at infinity, 0 = finite point, negative = decode error.
/// Accepts strict SEC1 lone `0x00` and the fixed-buffer `0x00‖zeros` form.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_curve_is_infinity(curve: u32, p: *const u8, p_len: usize) -> i32 {
    if p.is_null() {
        return BU_CURVE_ERR_NULL;
    }
    let p = slice::from_raw_parts(p, p_len);
    macro_rules! op {
        ($P:ty) => {{
            match <$P>::from_bytes(p) {
                Ok(pt) => {
                    if pt.is_identity() {
                        1
                    } else {
                        0
                    }
                }
                Err(_) => BU_CURVE_ERR_INVALID_POINT,
            }
        }};
    }
    with_point!(curve, op)
}

/// `out = a + b`
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_curve_add(
    curve: u32,
    a: *const u8,
    a_len: usize,
    b: *const u8,
    b_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if a.is_null() || b.is_null() || out.is_null() {
        return BU_CURVE_ERR_NULL;
    }
    let a = slice::from_raw_parts(a, a_len);
    let b = slice::from_raw_parts(b, b_len);
    let out = slice::from_raw_parts_mut(out, out_len);
    macro_rules! op {
        ($P:ty) => {{
            let pa = match map_point_err(<$P>::from_bytes(a)) {
                Ok(p) => p,
                Err(e) => return e,
            };
            let pb = match map_point_err(<$P>::from_bytes(b)) {
                Ok(p) => p,
                Err(e) => return e,
            };
            write_point(&pa.add(&pb), out)
        }};
    }
    with_point!(curve, op)
}

/// `out = a - b` (= a + neg(b))
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_curve_sub(
    curve: u32,
    a: *const u8,
    a_len: usize,
    b: *const u8,
    b_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if a.is_null() || b.is_null() || out.is_null() {
        return BU_CURVE_ERR_NULL;
    }
    let a = slice::from_raw_parts(a, a_len);
    let b = slice::from_raw_parts(b, b_len);
    let out = slice::from_raw_parts_mut(out, out_len);
    macro_rules! op {
        ($P:ty) => {{
            let pa = match map_point_err(<$P>::from_bytes(a)) {
                Ok(p) => p,
                Err(e) => return e,
            };
            let pb = match map_point_err(<$P>::from_bytes(b)) {
                Ok(p) => p,
                Err(e) => return e,
            };
            write_point(&pa.add(&pb.neg()), out)
        }};
    }
    with_point!(curve, op)
}

/// `out = -a`
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_curve_neg(
    curve: u32,
    a: *const u8,
    a_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if a.is_null() || out.is_null() {
        return BU_CURVE_ERR_NULL;
    }
    let a = slice::from_raw_parts(a, a_len);
    let out = slice::from_raw_parts_mut(out, out_len);
    macro_rules! op {
        ($P:ty) => {{
            let pa = match map_point_err(<$P>::from_bytes(a)) {
                Ok(p) => p,
                Err(e) => return e,
            };
            write_point(&pa.neg(), out)
        }};
    }
    with_point!(curve, op)
}

/// `out = scalar * point`
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_curve_mul(
    curve: u32,
    point: *const u8,
    point_len: usize,
    scalar: *const u8,
    scalar_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if point.is_null() || scalar.is_null() || out.is_null() {
        return BU_CURVE_ERR_NULL;
    }
    let point = slice::from_raw_parts(point, point_len);
    let scalar = slice::from_raw_parts(scalar, scalar_len);
    let out = slice::from_raw_parts_mut(out, out_len);
    macro_rules! op {
        ($P:ty) => {{
            let p = match map_point_err(<$P>::from_bytes(point)) {
                Ok(p) => p,
                Err(e) => return e,
            };
            let s = match map_scalar_err(<<$P as CurvePoint>::Scalar>::from_bytes(scalar)) {
                Ok(s) => s,
                Err(e) => return e,
            };
            write_point(&p.mul(&s), out)
        }};
    }
    with_point!(curve, op)
}

/// `out = scalar * G` (base-point multiply)
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_curve_mul_base(
    curve: u32,
    scalar: *const u8,
    scalar_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if scalar.is_null() || out.is_null() {
        return BU_CURVE_ERR_NULL;
    }
    let scalar = slice::from_raw_parts(scalar, scalar_len);
    let out = slice::from_raw_parts_mut(out, out_len);

    fn mul_base_gen<P: CurvePoint>(gen: P, scalar: &[u8], out: &mut [u8]) -> i32 {
        let s = match map_scalar_err(P::Scalar::from_bytes(scalar)) {
            Ok(s) => s,
            Err(e) => return e,
        };
        write_point(&gen.mul(&s), out)
    }

    match curve {
        BU_CURVE_SECP256K1 => mul_base_gen(Secp256k1Point::generator(), scalar, out),
        BU_CURVE_SECP256R1 => mul_base_gen(Secp256r1Point::generator(), scalar, out),
        BU_CURVE_ED25519 => mul_base_gen(Ed25519Point::generator(), scalar, out),
        BU_CURVE_RISTRETTO => mul_base_gen(RistrettoPoint::generator(), scalar, out),
        BU_CURVE_PALLAS => mul_base_gen(PallasPoint::generator(), scalar, out),
        BU_CURVE_VESTA => mul_base_gen(VestaPoint::generator(), scalar, out),
        BU_CURVE_JUBJUB => mul_base_gen(JubJubPoint::generator(), scalar, out),
        BU_CURVE_BLS12_G1 => mul_base_gen(G1Point::generator(), scalar, out),
        BU_CURVE_BLS12_G2 => mul_base_gen(G2Point::generator(), scalar, out),
        BU_CURVE_BN254_G1 => mul_base_gen(Bn254G1Point::generator(), scalar, out),
        BU_CURVE_BN254_G2 => mul_base_gen(Bn254G2Point::generator(), scalar, out),
        _ => BU_CURVE_ERR_INVALID_CURVE,
    }
}

/// `out = s1 * p1 + s2 * p2` (useful for verification-style linear combinations)
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_curve_mul_add(
    curve: u32,
    p1: *const u8,
    p1_len: usize,
    s1: *const u8,
    s1_len: usize,
    p2: *const u8,
    p2_len: usize,
    s2: *const u8,
    s2_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if p1.is_null() || s1.is_null() || p2.is_null() || s2.is_null() || out.is_null() {
        return BU_CURVE_ERR_NULL;
    }
    let p1 = slice::from_raw_parts(p1, p1_len);
    let s1 = slice::from_raw_parts(s1, s1_len);
    let p2 = slice::from_raw_parts(p2, p2_len);
    let s2 = slice::from_raw_parts(s2, s2_len);
    let out = slice::from_raw_parts_mut(out, out_len);
    macro_rules! op {
        ($P:ty) => {{
            let a = match map_point_err(<$P>::from_bytes(p1)) {
                Ok(p) => p,
                Err(e) => return e,
            };
            let b = match map_point_err(<$P>::from_bytes(p2)) {
                Ok(p) => p,
                Err(e) => return e,
            };
            let sa = match map_scalar_err(<<$P as CurvePoint>::Scalar>::from_bytes(s1)) {
                Ok(s) => s,
                Err(e) => return e,
            };
            let sb = match map_scalar_err(<<$P as CurvePoint>::Scalar>::from_bytes(s2)) {
                Ok(s) => s,
                Err(e) => return e,
            };
            let r = a.mul(&sa).add(&b.mul(&sb));
            write_point(&r, out)
        }};
    }
    with_point!(curve, op)
}

/// Derive a secret scalar from `seed` (SHA-256 then parse; one rehash if needed).
///
/// Writes `bu_curve_scalar_len(curve)` bytes into `out`.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_curve_generate_secret(
    curve: u32,
    seed: *const u8,
    seed_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if seed.is_null() || out.is_null() || seed_len == 0 {
        return BU_CURVE_ERR_NULL;
    }
    let seed = slice::from_raw_parts(seed, seed_len);
    let out = slice::from_raw_parts_mut(out, out_len);
    let need = bu_curve_scalar_len(curve);
    if need == 0 {
        return BU_CURVE_ERR_INVALID_CURVE;
    }
    if out.len() < need {
        return BU_CURVE_ERR_BUFFER;
    }

    // Hash seed → try as scalar; if invalid, hash again with domain byte.
    let mut h = match sha256::sha256(seed) {
        Ok(x) => x,
        Err(_) => return BU_CURVE_ERR_UNSUPPORTED,
    };
    for attempt in 0u8..8 {
        if attempt > 0 {
            let mut buf = [0u8; 33];
            buf[..32].copy_from_slice(&h);
            buf[32] = attempt;
            h = match sha256::sha256(&buf) {
                Ok(x) => x,
                Err(_) => return BU_CURVE_ERR_UNSUPPORTED,
            };
        }
        // Use first `need` bytes (pad/truncate)
        let mut candidate = [0u8; 64];
        let n = need.min(32);
        candidate[..n].copy_from_slice(&h[..n]);

        macro_rules! try_scalar {
            ($P:ty) => {{
                match <<$P as CurvePoint>::Scalar>::from_bytes(&candidate[..need]) {
                    Ok(s) => match s.to_bytes(&mut out[..need]) {
                        Ok(()) => return BU_CURVE_OK,
                        Err(_) => return BU_CURVE_ERR_INVALID_SCALAR,
                    },
                    Err(_) => continue,
                }
            }};
        }
        let rc = with_point!(curve, try_scalar);
        if rc == BU_CURVE_OK {
            return BU_CURVE_OK;
        }
        // continue attempts
        let _ = rc;
    }
    BU_CURVE_ERR_INVALID_SCALAR
}

/// Hash message to BLS12-381 G1 (RFC 9380 style). Output 48 bytes compressed.
///
/// `dst` is the domain separation tag (e.g. BLS_SIG_..._G1_...).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_bls_hash_to_g1(
    msg: *const u8,
    msg_len: usize,
    dst: *const u8,
    dst_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if msg.is_null() || out.is_null() {
        return BU_CURVE_ERR_NULL;
    }
    if out_len < G1Point::COMPRESSED_BYTES {
        return BU_CURVE_ERR_BUFFER;
    }
    let msg = if msg_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(msg, msg_len)
    };
    let dst = if dst.is_null() || dst_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(dst, dst_len)
    };
    let p = hash_to_g1(msg, dst);
    let out = slice::from_raw_parts_mut(out, out_len);
    write_point(&p, out)
}

/// Hash message to BLS12-381 G2 (RFC 9380 style). Output 96 bytes compressed.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_bls_hash_to_g2(
    msg: *const u8,
    msg_len: usize,
    dst: *const u8,
    dst_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if msg.is_null() || out.is_null() {
        return BU_CURVE_ERR_NULL;
    }
    if out_len < G2Point::COMPRESSED_BYTES {
        return BU_CURVE_ERR_BUFFER;
    }
    let msg = if msg_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(msg, msg_len)
    };
    let dst = if dst.is_null() || dst_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(dst, dst_len)
    };
    let p = hash_to_g2(msg, dst);
    let out = slice::from_raw_parts_mut(out, out_len);
    write_point(&p, out)
}

/// Pallas hash-to-curve (RFC 9380 XMD:SHA-256_SSWU_RO).
/// `out` must be ≥ 32 bytes (Pasta compressed).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_pallas_hash_to_curve(
    msg: *const u8,
    msg_len: usize,
    dst: *const u8,
    dst_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if out.is_null() || out_len < 32 {
        return BU_CURVE_ERR_BUFFER;
    }
    if msg_len > 0 && msg.is_null() {
        return BU_CURVE_ERR_NULL;
    }
    if dst_len > 0 && dst.is_null() {
        return BU_CURVE_ERR_NULL;
    }
    let m = if msg_len == 0 {
        &[][..]
    } else {
        unsafe { core::slice::from_raw_parts(msg, msg_len) }
    };
    let d = if dst_len == 0 {
        &[][..]
    } else {
        unsafe { core::slice::from_raw_parts(dst, dst_len) }
    };
    let p = pallas::hash_to_curve(m, d);
    let bytes = to_bytes_pasta(&p);
    unsafe {
        core::slice::from_raw_parts_mut(out, 32).copy_from_slice(&bytes);
    }
    BU_CURVE_OK
}

/// Pallas Pasta/Halo2 hash-to-curve: domain_prefix UTF-8 + message → Pasta compressed.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_pallas_hash_to_curve_pasta(
    domain: *const u8,
    domain_len: usize,
    msg: *const u8,
    msg_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if out.is_null() || out_len < 32 {
        return BU_CURVE_ERR_BUFFER;
    }
    if domain_len > 0 && domain.is_null() {
        return BU_CURVE_ERR_NULL;
    }
    if msg_len > 0 && msg.is_null() {
        return BU_CURVE_ERR_NULL;
    }
    let dom = if domain_len == 0 {
        ""
    } else {
        match unsafe { core::str::from_utf8(core::slice::from_raw_parts(domain, domain_len)) } {
            Ok(s) => s,
            Err(_) => return BU_CURVE_ERR_INVALID_POINT,
        }
    };
    let m = if msg_len == 0 {
        &[][..]
    } else {
        unsafe { core::slice::from_raw_parts(msg, msg_len) }
    };
    let p = hash_to_curve_pasta(dom, m);
    let bytes = to_bytes_pasta(&p);
    unsafe {
        core::slice::from_raw_parts_mut(out, 32).copy_from_slice(&bytes);
    }
    BU_CURVE_OK
}

/// Vesta hash-to-curve (RFC 9380 style). Output 32-byte compressed.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_vesta_hash_to_curve(
    msg: *const u8,
    msg_len: usize,
    dst: *const u8,
    dst_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if out.is_null() || out_len < 32 {
        return BU_CURVE_ERR_BUFFER;
    }
    if msg_len > 0 && msg.is_null() {
        return BU_CURVE_ERR_NULL;
    }
    if dst_len > 0 && dst.is_null() {
        return BU_CURVE_ERR_NULL;
    }
    let m = if msg_len == 0 {
        &[][..]
    } else {
        unsafe { core::slice::from_raw_parts(msg, msg_len) }
    };
    let d = if dst_len == 0 {
        &[][..]
    } else {
        unsafe { core::slice::from_raw_parts(dst, dst_len) }
    };
    let p = vesta::hash_to_curve(m, d);
    let mut buf = [0u8; 32];
    if p.to_bytes_compressed(&mut buf).is_err() {
        return BU_CURVE_ERR_INVALID_POINT;
    }
    unsafe {
        core::slice::from_raw_parts_mut(out, 32).copy_from_slice(&buf);
    }
    BU_CURVE_OK
}

// ---------------------------------------------------------------------------
// Scalar arithmetic (sc_*)
// ---------------------------------------------------------------------------

/// Returns 1 if `scalar` is a valid canonical encoding, 0 otherwise.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_curve_sc_check(
    curve: u32,
    scalar: *const u8,
    scalar_len: usize,
) -> i32 {
    if scalar.is_null() {
        return 0;
    }
    let scalar = slice::from_raw_parts(scalar, scalar_len);
    macro_rules! check {
        ($P:ty) => {{
            match <<$P as CurvePoint>::Scalar>::from_bytes(scalar) {
                Ok(_) => 1,
                Err(_) => 0,
            }
        }};
    }
    match curve {
        BU_CURVE_SECP256K1 => check!(Secp256k1Point),
        BU_CURVE_SECP256R1 => check!(Secp256r1Point),
        BU_CURVE_ED25519 => check!(Ed25519Point),
        BU_CURVE_RISTRETTO => check!(RistrettoPoint),
        BU_CURVE_PALLAS => check!(PallasPoint),
        BU_CURVE_VESTA => check!(VestaPoint),
        BU_CURVE_JUBJUB => check!(JubJubPoint),
        BU_CURVE_BLS12_G1 => check!(G1Point),
        BU_CURVE_BLS12_G2 => check!(G2Point),
        BU_CURVE_BN254_G1 => check!(Bn254G1Point),
        BU_CURVE_BN254_G2 => check!(Bn254G2Point),
        _ => 0,
    }
}

#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_curve_sc_add(
    curve: u32,
    a: *const u8,
    a_len: usize,
    b: *const u8,
    b_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if a.is_null() || b.is_null() || out.is_null() {
        return BU_CURVE_ERR_NULL;
    }
    let a = slice::from_raw_parts(a, a_len);
    let b = slice::from_raw_parts(b, b_len);
    let out = slice::from_raw_parts_mut(out, out_len);
    macro_rules! op {
        ($P:ty) => {{
            let sa = match map_scalar_err(<<$P as CurvePoint>::Scalar>::from_bytes(a)) {
                Ok(s) => s,
                Err(e) => return e,
            };
            let sb = match map_scalar_err(<<$P as CurvePoint>::Scalar>::from_bytes(b)) {
                Ok(s) => s,
                Err(e) => return e,
            };
            match sa.add(&sb).to_bytes(out) {
                Ok(()) => BU_CURVE_OK,
                Err(_) => BU_CURVE_ERR_BUFFER,
            }
        }};
    }
    with_point!(curve, op)
}

#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_curve_sc_sub(
    curve: u32,
    a: *const u8,
    a_len: usize,
    b: *const u8,
    b_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if a.is_null() || b.is_null() || out.is_null() {
        return BU_CURVE_ERR_NULL;
    }
    let a = slice::from_raw_parts(a, a_len);
    let b = slice::from_raw_parts(b, b_len);
    let out = slice::from_raw_parts_mut(out, out_len);
    macro_rules! op {
        ($P:ty) => {{
            let sa = match map_scalar_err(<<$P as CurvePoint>::Scalar>::from_bytes(a)) {
                Ok(s) => s,
                Err(e) => return e,
            };
            let sb = match map_scalar_err(<<$P as CurvePoint>::Scalar>::from_bytes(b)) {
                Ok(s) => s,
                Err(e) => return e,
            };
            // a + (-b)
            match sa.add(&sb.neg()).to_bytes(out) {
                Ok(()) => BU_CURVE_OK,
                Err(_) => BU_CURVE_ERR_BUFFER,
            }
        }};
    }
    with_point!(curve, op)
}

#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_curve_sc_mul(
    curve: u32,
    a: *const u8,
    a_len: usize,
    b: *const u8,
    b_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if a.is_null() || b.is_null() || out.is_null() {
        return BU_CURVE_ERR_NULL;
    }
    let a = slice::from_raw_parts(a, a_len);
    let b = slice::from_raw_parts(b, b_len);
    let out = slice::from_raw_parts_mut(out, out_len);
    macro_rules! op {
        ($P:ty) => {{
            let sa = match map_scalar_err(<<$P as CurvePoint>::Scalar>::from_bytes(a)) {
                Ok(s) => s,
                Err(e) => return e,
            };
            let sb = match map_scalar_err(<<$P as CurvePoint>::Scalar>::from_bytes(b)) {
                Ok(s) => s,
                Err(e) => return e,
            };
            match sa.mul(&sb).to_bytes(out) {
                Ok(()) => BU_CURVE_OK,
                Err(_) => BU_CURVE_ERR_BUFFER,
            }
        }};
    }
    with_point!(curve, op)
}

#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_curve_sc_neg(
    curve: u32,
    scalar: *const u8,
    scalar_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if scalar.is_null() || out.is_null() {
        return BU_CURVE_ERR_NULL;
    }
    let scalar = slice::from_raw_parts(scalar, scalar_len);
    let out = slice::from_raw_parts_mut(out, out_len);
    macro_rules! op {
        ($P:ty) => {{
            let s = match map_scalar_err(<<$P as CurvePoint>::Scalar>::from_bytes(scalar)) {
                Ok(s) => s,
                Err(e) => return e,
            };
            match s.neg().to_bytes(out) {
                Ok(()) => BU_CURVE_OK,
                Err(_) => BU_CURVE_ERR_BUFFER,
            }
        }};
    }
    with_point!(curve, op)
}

/// Reduce a scalar encoding modulo the curve order.
///
/// Unlike the other `bu_curve_sc_*` ops (which require canonical input),
/// reduce accepts any 32-byte integer and always succeeds, mirroring the
/// `CurveApi.scReduce` contract (idempotent, canonical output).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_curve_sc_reduce(
    curve: u32,
    scalar: *const u8,
    scalar_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if scalar.is_null() || out.is_null() {
        return BU_CURVE_ERR_NULL;
    }
    let scalar = slice::from_raw_parts(scalar, scalar_len);
    let out = slice::from_raw_parts_mut(out, out_len);
    // Ed25519 / Ristretto (shared Ed25519 scalar field): 64-byte →
    // sc_reduce64; 32-byte non-canonical → sc_reduce32. (Ristretto needs
    // the 64-byte path for sr25519 nonce reduction, mirroring the reference.)
    if curve == BU_CURVE_ED25519 || curve == BU_CURVE_RISTRETTO {
        if out_len < 32 {
            return BU_CURVE_ERR_BUFFER;
        }
        if scalar_len == 64 {
            let mut inn = [0u8; 64];
            inn.copy_from_slice(scalar);
            let s = crate::curve::ed25519::Scalar::sc_reduce64(&inn);
            let mut o = [0u8; 32];
            s.to_bytes_le(&mut o);
            out[..32].copy_from_slice(&o);
            return BU_CURVE_OK;
        }
        if scalar_len == 32 {
            let mut inn = [0u8; 32];
            inn.copy_from_slice(scalar);
            let s = crate::curve::ed25519::Scalar::sc_reduce32(&inn);
            let mut o = [0u8; 32];
            s.to_bytes_le(&mut o);
            out[..32].copy_from_slice(&o);
            return BU_CURVE_OK;
        }
        return BU_CURVE_ERR_BUFFER;
    }
    if out_len < 32 || scalar_len != 32 {
        return BU_CURVE_ERR_BUFFER;
    }
    let mut inn = [0u8; 32];
    inn.copy_from_slice(scalar);
    match curve {
        BU_CURVE_SECP256K1 => {
            let s = Secp256k1Scalar::from_bytes_mod_order(&inn);
            let mut o = [0u8; 32];
            s.to_bytes_be(&mut o);
            out[..32].copy_from_slice(&o);
            BU_CURVE_OK
        }
        BU_CURVE_SECP256R1 => {
            let s = Secp256r1Scalar::from_bytes_mod_order(&inn);
            let mut o = [0u8; 32];
            s.to_bytes_be(&mut o);
            out[..32].copy_from_slice(&o);
            BU_CURVE_OK
        }
        BU_CURVE_JUBJUB => {
            let mut wide = [0u8; 64];
            wide[..32].copy_from_slice(&inn);
            let s = crate::curve::jubjub::Scalar::sc_reduce64_le(&wide);
            let mut o = [0u8; 32];
            s.to_bytes_le(&mut o);
            out[..32].copy_from_slice(&o);
            BU_CURVE_OK
        }
        BU_CURVE_PALLAS => {
            let mut wide = [0u8; 64];
            wide[..32].copy_from_slice(&inn);
            let s = crate::curve::pallas::Scalar::sc_reduce64_le(&wide);
            let mut o = [0u8; 32];
            s.to_bytes_le(&mut o);
            out[..32].copy_from_slice(&o);
            BU_CURVE_OK
        }
        BU_CURVE_VESTA => {
            let mut wide = [0u8; 64];
            wide[..32].copy_from_slice(&inn);
            let s = crate::curve::vesta::Scalar::sc_reduce64_le(&wide);
            let mut o = [0u8; 32];
            s.to_bytes_le(&mut o);
            out[..32].copy_from_slice(&o);
            BU_CURVE_OK
        }
        BU_CURVE_BLS12_G1 | BU_CURVE_BLS12_G2 => {
            // No wide reduce available: Horner mod r over BE bytes.
            let b256 = crate::curve::bls::Scalar::from_u64(256);
            let mut acc = crate::curve::bls::Scalar::zero();
            for &byte in inn.iter() {
                acc = acc
                    .mul(&b256)
                    .add(&crate::curve::bls::Scalar::from_u64(byte as u64));
            }
            let mut o = [0u8; 32];
            acc.to_bytes_be(&mut o);
            out[..32].copy_from_slice(&o);
            BU_CURVE_OK
        }
        BU_CURVE_BN254_G1 | BU_CURVE_BN254_G2 => {
            // Same Horner mod-r over BE bytes for the BN254 scalar field.
            use crate::curve::bn254::Scalar as Bn254Scalar;
            let b256 = Bn254Scalar::from_u64(256);
            let mut acc = Bn254Scalar::zero();
            for &byte in inn.iter() {
                acc = acc.mul(&b256).add(&Bn254Scalar::from_u64(byte as u64));
            }
            let mut o = [0u8; 32];
            acc.to_bytes_be(&mut o);
            out[..32].copy_from_slice(&o);
            BU_CURVE_OK
        }
        _ => BU_CURVE_ERR_INVALID_CURVE,
    }
}

/// Monero / Ed25519 `sc_reduce32`: 32-byte LE integer → 32-byte scalar mod L.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_ed25519_sc_reduce32(
    scalar: *const u8,
    scalar_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if scalar.is_null() || out.is_null() {
        return BU_CURVE_ERR_NULL;
    }
    if scalar_len != 32 || out_len < 32 {
        return BU_CURVE_ERR_BUFFER;
    }
    let mut inn = [0u8; 32];
    inn.copy_from_slice(core::slice::from_raw_parts(scalar, 32));
    let s = crate::curve::ed25519::Scalar::sc_reduce32(&inn);
    let mut o = [0u8; 32];
    s.to_bytes_le(&mut o);
    core::slice::from_raw_parts_mut(out, 32).copy_from_slice(&o);
    BU_CURVE_OK
}

/// Monero / Ed25519 `sc_reduce` / `sc_reduce64`: 64-byte LE integer → 32-byte scalar mod L.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_ed25519_sc_reduce64(
    scalar: *const u8,
    scalar_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if scalar.is_null() || out.is_null() {
        return BU_CURVE_ERR_NULL;
    }
    if scalar_len != 64 || out_len < 32 {
        return BU_CURVE_ERR_BUFFER;
    }
    let mut inn = [0u8; 64];
    inn.copy_from_slice(core::slice::from_raw_parts(scalar, 64));
    let s = crate::curve::ed25519::Scalar::sc_reduce64(&inn);
    let mut o = [0u8; 32];
    s.to_bytes_le(&mut o);
    core::slice::from_raw_parts_mut(out, 32).copy_from_slice(&o);
    BU_CURVE_OK
}

/// Monero `ge_fromfe_frombytes_vartime`: map 32-byte field element → Ed25519 point (compressed).
/// Variable-time; for public inputs only (e.g. hash-to-point).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_ed25519_from_fe_bytes(
    fe32: *const u8,
    fe_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if fe32.is_null() || out.is_null() || fe_len != 32 || out_len < 32 {
        return BU_CURVE_ERR_BUFFER;
    }
    let mut inn = [0u8; 32];
    inn.copy_from_slice(slice::from_raw_parts(fe32, 32));
    match crate::curve::ed25519::from_fe_bytes(&inn) {
        Ok(p) => {
            let out_s = slice::from_raw_parts_mut(out, 32);
            match p.to_bytes_compressed(out_s) {
                Ok(()) => BU_CURVE_OK,
                Err(_) => BU_CURVE_ERR_INVALID_POINT,
            }
        }
        Err(_) => BU_CURVE_ERR_INVALID_POINT,
    }
}

/// Monero hash-to-point then clear cofactor: `[8] Hp(u)` (key-image style).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_ed25519_from_fe_bytes_clear_cofactor(
    fe32: *const u8,
    fe_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if fe32.is_null() || out.is_null() || fe_len != 32 || out_len < 32 {
        return BU_CURVE_ERR_BUFFER;
    }
    let mut inn = [0u8; 32];
    inn.copy_from_slice(slice::from_raw_parts(fe32, 32));
    match crate::curve::ed25519::from_fe_bytes_clear_cofactor(&inn) {
        Ok(p) => {
            let out_s = slice::from_raw_parts_mut(out, 32);
            match p.to_bytes_compressed(out_s) {
                Ok(()) => BU_CURVE_OK,
                Err(_) => BU_CURVE_ERR_INVALID_POINT,
            }
        }
        Err(_) => BU_CURVE_ERR_INVALID_POINT,
    }
}

// ---------------------------------------------------------------------------
// Monero Ed25519 helpers
// ---------------------------------------------------------------------------

fn read32(p: *const u8) -> [u8; 32] {
    let mut a = [0u8; 32];
    a.copy_from_slice(unsafe { core::slice::from_raw_parts(p, 32) });
    a
}

fn write32(out: *mut u8, b: &[u8; 32]) {
    unsafe {
        core::slice::from_raw_parts_mut(out, 32).copy_from_slice(b);
    }
}

/// Monero `hash_to_ec`: Keccak-256(data) → from_fe → ×8 → compressed point.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_ed25519_hash_to_ec(
    data: *const u8,
    data_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if out.is_null() || out_len < 32 {
        return BU_CURVE_ERR_BUFFER;
    }
    if data_len > 0 && data.is_null() {
        return BU_CURVE_ERR_NULL;
    }
    let slice = if data_len == 0 {
        &[][..]
    } else {
        core::slice::from_raw_parts(data, data_len)
    };
    match crate::curve::ed25519::hash_to_ec(slice) {
        Ok(p) => {
            write32(out, &p);
            BU_CURVE_OK
        }
        Err(_) => BU_CURVE_ERR_INVALID_POINT,
    }
}

/// `check_key` — on-curve public key check (variable-time).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_ed25519_check_key(pk: *const u8, pk_len: usize) -> i32 {
    if pk.is_null() || pk_len != 32 {
        return 0;
    }
    if crate::curve::ed25519::check_key(&read32(pk)) {
        1
    } else {
        0
    }
}

/// Multiply point by cofactor 8.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_ed25519_mul_by_cofactor(
    point: *const u8,
    point_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if point.is_null() || out.is_null() || point_len != 32 || out_len < 32 {
        return BU_CURVE_ERR_BUFFER;
    }
    match crate::curve::ed25519::Ed25519Point::from_bytes(&read32(point)[..]) {
        Ok(p) => {
            let q = crate::curve::ed25519::mul_by_cofactor(&p);
            let mut o = [0u8; 32];
            match q.to_bytes_compressed(&mut o) {
                Ok(()) => {
                    write32(out, &o);
                    BU_CURVE_OK
                }
                Err(_) => BU_CURVE_ERR_INVALID_POINT,
            }
        }
        Err(_) => BU_CURVE_ERR_INVALID_POINT,
    }
}

/// Key image: `I = a · Hp` (constant-time scalar mul).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_ed25519_scalarmult_key_image(
    hp: *const u8,
    hp_len: usize,
    a: *const u8,
    a_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if hp.is_null() || a.is_null() || out.is_null() || hp_len != 32 || a_len != 32 || out_len < 32 {
        return BU_CURVE_ERR_BUFFER;
    }
    let hp_p = match crate::curve::ed25519::Ed25519Point::from_bytes(&read32(hp)[..]) {
        Ok(p) => p,
        Err(_) => return BU_CURVE_ERR_INVALID_POINT,
    };
    let sc = match crate::curve::ed25519::Scalar::from_bytes_le(&read32(a)) {
        Ok(s) => s,
        Err(_) => return BU_CURVE_ERR_INVALID_SCALAR,
    };
    let q = crate::curve::ed25519::scalarmult_key_image(&hp_p, &sc);
    let mut o = [0u8; 32];
    match q.to_bytes_compressed(&mut o) {
        Ok(()) => {
            write32(out, &o);
            BU_CURVE_OK
        }
        Err(_) => BU_CURVE_ERR_INVALID_POINT,
    }
}

/// Fused `8 * (s * P)` (constant-time on secret `s`, e.g. Monero key derivation).
/// Single decode + single encode; no intermediate `to_bytes`/`from_bytes`.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_ed25519_mul8_mult(
    s: *const u8,
    s_len: usize,
    p: *const u8,
    p_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if s.is_null() || p.is_null() || out.is_null() || s_len != 32 || p_len != 32 || out_len < 32 {
        return BU_CURVE_ERR_BUFFER;
    }
    let pp = match crate::curve::ed25519::Ed25519Point::from_bytes(&read32(p)[..]) {
        Ok(v) => v,
        Err(_) => return BU_CURVE_ERR_INVALID_POINT,
    };
    let sc = match crate::curve::ed25519::Scalar::from_bytes_le(&read32(s)) {
        Ok(v) => v,
        Err(_) => return BU_CURVE_ERR_INVALID_SCALAR,
    };
    let q = crate::curve::ed25519::scalarmult8(&pp, &sc);
    let mut o = [0u8; 32];
    match q.to_bytes_compressed(&mut o) {
        Ok(()) => {
            write32(out, &o);
            BU_CURVE_OK
        }
        Err(_) => BU_CURVE_ERR_INVALID_POINT,
    }
}

fn parse_precomp(table: *const u8) -> Result<[crate::curve::ed25519::Ed25519Point; 8], i32> {
    let bytes = unsafe { core::slice::from_raw_parts(table, 256) };
    let mut out = [crate::curve::ed25519::Ed25519Point::identity(); 8];
    for i in 0..8 {
        let mut b = [0u8; 32];
        b.copy_from_slice(&bytes[i * 32..(i + 1) * 32]);
        out[i] = crate::curve::ed25519::Ed25519Point::from_bytes(&b[..])
            .map_err(|_| BU_CURVE_ERR_INVALID_POINT)?;
    }
    Ok(out)
}

fn write_precomp(out: *mut u8, table: &[crate::curve::ed25519::Ed25519Point; 8]) -> i32 {
    for (i, pt) in table.iter().enumerate() {
        let mut b = [0u8; 32];
        if pt.to_bytes_compressed(&mut b).is_err() {
            return BU_CURVE_ERR_INVALID_POINT;
        }
        unsafe {
            core::slice::from_raw_parts_mut(out.add(i * 32), 32).copy_from_slice(&b);
        }
    }
    BU_CURVE_OK
}

/// Build odd-multiples precomp table (8 × 32 = 256 bytes out).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_ed25519_ge_dsm_precomp(
    point: *const u8,
    point_len: usize,
    out256: *mut u8,
    out_len: usize,
) -> i32 {
    if point.is_null() || out256.is_null() || point_len != 32 || out_len < 256 {
        return BU_CURVE_ERR_BUFFER;
    }
    match crate::curve::ed25519::Ed25519Point::from_bytes(&read32(point)[..]) {
        Ok(p) => {
            let t = crate::curve::ed25519::ge_dsm_precomp_var(&p);
            write_precomp(out256, &t)
        }
        Err(_) => BU_CURVE_ERR_INVALID_POINT,
    }
}

/// `a·A + b·B` with precomp tables (each 256 bytes).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_ed25519_ge_double_scalar_mult_precomp(
    a: *const u8,
    a_i: *const u8,
    b: *const u8,
    b_i: *const u8,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if a.is_null() || a_i.is_null() || b.is_null() || b_i.is_null() || out.is_null() || out_len < 32
    {
        return BU_CURVE_ERR_BUFFER;
    }
    let ai = match parse_precomp(a_i) {
        Ok(t) => t,
        Err(e) => return e,
    };
    let bi = match parse_precomp(b_i) {
        Ok(t) => t,
        Err(e) => return e,
    };
    let r = crate::curve::ed25519::ge_double_scalar_mult_precomp_point_var(
        &read32(a),
        &ai,
        &read32(b),
        &bi,
    );
    let mut o = [0u8; 32];
    match r.to_bytes_compressed(&mut o) {
        Ok(()) => {
            write32(out, &o);
            BU_CURVE_OK
        }
        Err(_) => BU_CURVE_ERR_INVALID_POINT,
    }
}

/// `a·A + b·B` with B = basepoint (A given as point bytes).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_ed25519_ge_double_scalar_mult_base(
    a: *const u8,
    g_a: *const u8,
    b: *const u8,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if a.is_null() || g_a.is_null() || b.is_null() || out.is_null() || out_len < 32 {
        return BU_CURVE_ERR_BUFFER;
    }
    let ga = match crate::curve::ed25519::Ed25519Point::from_bytes(&read32(g_a)[..]) {
        Ok(p) => p,
        Err(_) => return BU_CURVE_ERR_INVALID_POINT,
    };
    let r =
        crate::curve::ed25519::ge_double_scalar_mult_base_point_var(&read32(a), &ga, &read32(b));
    let mut o = [0u8; 32];
    match r.to_bytes_compressed(&mut o) {
        Ok(()) => {
            write32(out, &o);
            BU_CURVE_OK
        }
        Err(_) => BU_CURVE_ERR_INVALID_POINT,
    }
}

/// `a·B + b·P + c·Q` with B = base, b_i/c_i precomp tables (256 bytes each).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_ed25519_ge_triple_scalar_mult_base(
    a: *const u8,
    b: *const u8,
    b_i: *const u8,
    c: *const u8,
    c_i: *const u8,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if a.is_null()
        || b.is_null()
        || b_i.is_null()
        || c.is_null()
        || c_i.is_null()
        || out.is_null()
        || out_len < 32
    {
        return BU_CURVE_ERR_BUFFER;
    }
    let bi = match parse_precomp(b_i) {
        Ok(t) => t,
        Err(e) => return e,
    };
    let ci = match parse_precomp(c_i) {
        Ok(t) => t,
        Err(e) => return e,
    };
    let r = crate::curve::ed25519::ge_triple_scalar_mult_base_point_var(
        &read32(a),
        &read32(b),
        &bi,
        &read32(c),
        &ci,
    );
    let mut o = [0u8; 32];
    match r.to_bytes_compressed(&mut o) {
        Ok(()) => {
            write32(out, &o);
            BU_CURVE_OK
        }
        Err(_) => BU_CURVE_ERR_INVALID_POINT,
    }
}

/// `a·A + b·B + c·C` with three precomp tables.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_ed25519_ge_triple_scalar_mult_precomp(
    a: *const u8,
    a_i: *const u8,
    b: *const u8,
    b_i: *const u8,
    c: *const u8,
    c_i: *const u8,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if a.is_null()
        || a_i.is_null()
        || b.is_null()
        || b_i.is_null()
        || c.is_null()
        || c_i.is_null()
        || out.is_null()
        || out_len < 32
    {
        return BU_CURVE_ERR_BUFFER;
    }
    let ai = match parse_precomp(a_i) {
        Ok(t) => t,
        Err(e) => return e,
    };
    let bi = match parse_precomp(b_i) {
        Ok(t) => t,
        Err(e) => return e,
    };
    let ci = match parse_precomp(c_i) {
        Ok(t) => t,
        Err(e) => return e,
    };
    let r = crate::curve::ed25519::ge_triple_scalar_mult_precomp_point_var(
        &read32(a),
        &ai,
        &read32(b),
        &bi,
        &read32(c),
        &ci,
    );
    let mut o = [0u8; 32];
    match r.to_bytes_compressed(&mut o) {
        Ok(()) => {
            write32(out, &o);
            BU_CURVE_OK
        }
        Err(_) => BU_CURVE_ERR_INVALID_POINT,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one_scalar() -> [u8; 32] {
        let mut s = [0u8; 32];
        s[31] = 1;
        s
    }

    #[test]
    fn point_scalar_lens() {
        assert_eq!(bu_curve_point_len(BU_CURVE_SECP256K1), 33);
        assert_eq!(bu_curve_scalar_len(BU_CURVE_SECP256K1), 32);
        assert_eq!(bu_curve_point_len(BU_CURVE_ED25519), 32);
        assert_eq!(bu_curve_point_len(BU_CURVE_RISTRETTO), 32);
        assert_eq!(bu_curve_point_len(BU_CURVE_BLS12_G1), 48);
        assert_eq!(bu_curve_point_len(BU_CURVE_BLS12_G2), 96);
        assert_eq!(bu_curve_point_len(9999), 0);
    }

    #[test]
    fn secp256k1_mul_base_one() {
        let mut g = [0u8; 33];
        assert_eq!(
            unsafe { bu_curve_generator(BU_CURVE_SECP256K1, g.as_mut_ptr(), g.len()) },
            BU_CURVE_OK
        );
        let one = one_scalar();
        let mut out = [0u8; 33];
        assert_eq!(
            unsafe {
                bu_curve_mul_base(
                    BU_CURVE_SECP256K1,
                    one.as_ptr(),
                    one.len(),
                    out.as_mut_ptr(),
                    out.len(),
                )
            },
            BU_CURVE_OK
        );
        assert_eq!(out, g);
    }

    #[test]
    fn secp256k1_add_sub_neg() {
        let mut g = [0u8; 33];
        unsafe {
            assert_eq!(
                bu_curve_generator(BU_CURVE_SECP256K1, g.as_mut_ptr(), 33),
                BU_CURVE_OK
            );
            let mut ng = [0u8; 33];
            assert_eq!(
                bu_curve_neg(BU_CURVE_SECP256K1, g.as_ptr(), 33, ng.as_mut_ptr(), 33),
                BU_CURVE_OK
            );
            // -(-G) = G
            let mut g2 = [0u8; 33];
            assert_eq!(
                bu_curve_neg(BU_CURVE_SECP256K1, ng.as_ptr(), 33, g2.as_mut_ptr(), 33),
                BU_CURVE_OK
            );
            assert_eq!(g, g2);
            // G + (-G) is identity; infinity encodes as all-zero fixed
            // buffer (BIP327 zeroPK round-trip convention).
            let mut sum = [0u8; 33];
            assert_eq!(
                bu_curve_add(
                    BU_CURVE_SECP256K1,
                    g.as_ptr(),
                    33,
                    ng.as_ptr(),
                    33,
                    sum.as_mut_ptr(),
                    33,
                ),
                BU_CURVE_OK
            );
            assert_eq!(sum, [0u8; 33]);
            // same for G - G
            assert_eq!(
                bu_curve_sub(
                    BU_CURVE_SECP256K1,
                    g.as_ptr(),
                    33,
                    g.as_ptr(),
                    33,
                    sum.as_mut_ptr(),
                    33,
                ),
                BU_CURVE_OK
            );
            assert_eq!(sum, [0u8; 33]);
        }
    }

    #[test]
    fn secp256k1_mul_add() {
        let mut g = [0u8; 33];
        let one = one_scalar();
        let mut two = [0u8; 32];
        two[31] = 2;
        unsafe {
            assert_eq!(
                bu_curve_generator(BU_CURVE_SECP256K1, g.as_mut_ptr(), 33),
                BU_CURVE_OK
            );
            // 1*G + 1*G = 2*G
            let mut left = [0u8; 33];
            assert_eq!(
                bu_curve_mul_add(
                    BU_CURVE_SECP256K1,
                    g.as_ptr(),
                    33,
                    one.as_ptr(),
                    32,
                    g.as_ptr(),
                    33,
                    one.as_ptr(),
                    32,
                    left.as_mut_ptr(),
                    33,
                ),
                BU_CURVE_OK
            );
            let mut right = [0u8; 33];
            assert_eq!(
                bu_curve_mul_base(BU_CURVE_SECP256K1, two.as_ptr(), 32, right.as_mut_ptr(), 33,),
                BU_CURVE_OK
            );
            assert_eq!(left, right);
        }
    }

    #[test]
    fn ed25519_add_neg() {
        let mut g = [0u8; 32];
        unsafe {
            assert_eq!(
                bu_curve_generator(BU_CURVE_ED25519, g.as_mut_ptr(), 32),
                BU_CURVE_OK
            );
            let mut ng = [0u8; 32];
            assert_eq!(
                bu_curve_neg(BU_CURVE_ED25519, g.as_ptr(), 32, ng.as_mut_ptr(), 32),
                BU_CURVE_OK
            );
            let mut sum = [0u8; 32];
            assert_eq!(
                bu_curve_add(
                    BU_CURVE_ED25519,
                    g.as_ptr(),
                    32,
                    ng.as_ptr(),
                    32,
                    sum.as_mut_ptr(),
                    32,
                ),
                BU_CURVE_OK
            );
            let mut id = [0u8; 32];
            assert_eq!(
                bu_curve_identity(BU_CURVE_ED25519, id.as_mut_ptr(), 32),
                BU_CURVE_OK
            );
            assert_eq!(sum, id);
        }
    }

    #[test]
    fn ristretto_mul_base() {
        // Ed25519/Ristretto scalars are little-endian
        let mut one_le = [0u8; 32];
        one_le[0] = 1;
        let mut out = [0u8; 32];
        assert_eq!(
            unsafe {
                bu_curve_mul_base(
                    BU_CURVE_RISTRETTO,
                    one_le.as_ptr(),
                    32,
                    out.as_mut_ptr(),
                    32,
                )
            },
            BU_CURVE_OK
        );
        let mut g = [0u8; 32];
        unsafe {
            assert_eq!(
                bu_curve_generator(BU_CURVE_RISTRETTO, g.as_mut_ptr(), 32),
                BU_CURVE_OK
            );
        }
        assert_eq!(out, g);
    }

    #[test]
    fn pallas_vesta_jubjub_generators() {
        for curve in [BU_CURVE_PALLAS, BU_CURVE_VESTA, BU_CURVE_JUBJUB] {
            let len = bu_curve_point_len(curve);
            assert!(len > 0);
            let mut g = alloc::vec![0u8; len];
            assert_eq!(
                unsafe { bu_curve_generator(curve, g.as_mut_ptr(), len) },
                BU_CURVE_OK
            );
        }
    }

    #[test]
    fn bls_g1_g2_mul_base() {
        let one = one_scalar();
        let mut g1 = [0u8; 48];
        let mut o1 = [0u8; 48];
        unsafe {
            assert_eq!(
                bu_curve_generator(BU_CURVE_BLS12_G1, g1.as_mut_ptr(), 48),
                BU_CURVE_OK
            );
            assert_eq!(
                bu_curve_mul_base(BU_CURVE_BLS12_G1, one.as_ptr(), 32, o1.as_mut_ptr(), 48,),
                BU_CURVE_OK
            );
        }
        assert_eq!(g1, o1);
    }

    #[test]
    fn bn254_g1_g2_ids() {
        assert_eq!(bu_curve_point_len(BU_CURVE_BN254_G1), 64);
        assert_eq!(bu_curve_point_len(BU_CURVE_BN254_G2), 128);
        assert_eq!(bu_curve_scalar_len(BU_CURVE_BN254_G1), 32);
        assert_eq!(bu_curve_scalar_len(BU_CURVE_BN254_G2), 32);
        // EIP-197 G1 generator (1, 2).
        let mut g1 = [0u8; 64];
        unsafe {
            assert_eq!(
                bu_curve_generator(BU_CURVE_BN254_G1, g1.as_mut_ptr(), 64),
                BU_CURVE_OK
            );
        }
        assert_eq!(g1[31], 1, "G1.x == 1");
        assert_eq!(g1[63], 2, "G1.y == 2");
        // EIP-197 G2 generator starts with x1 = 0x198e....
        let mut g2 = [0u8; 128];
        unsafe {
            assert_eq!(
                bu_curve_generator(BU_CURVE_BN254_G2, g2.as_mut_ptr(), 128),
                BU_CURVE_OK
            );
        }
        assert_eq!(&g2[..4], &[0x19, 0x8e, 0x93, 0x93], "G2.x1 head");
        // mul_base(1) == generator on both groups.
        let one = one_scalar();
        let mut o1 = [0u8; 64];
        let mut o2 = [0u8; 128];
        unsafe {
            assert_eq!(
                bu_curve_mul_base(BU_CURVE_BN254_G1, one.as_ptr(), 32, o1.as_mut_ptr(), 64,),
                BU_CURVE_OK
            );
            assert_eq!(
                bu_curve_mul_base(BU_CURVE_BN254_G2, one.as_ptr(), 32, o2.as_mut_ptr(), 128,),
                BU_CURVE_OK
            );
        }
        assert_eq!(g1, o1);
        assert_eq!(g2, o2);
    }

    #[test]
    fn hash_to_g1_g2() {
        let msg = b"abc";
        let dst1 = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
        let dst2 = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
        let mut o1 = [0u8; 48];
        let mut o2 = [0u8; 96];
        unsafe {
            assert_eq!(
                bu_bls_hash_to_g1(
                    msg.as_ptr(),
                    msg.len(),
                    dst1.as_ptr(),
                    dst1.len(),
                    o1.as_mut_ptr(),
                    48,
                ),
                BU_CURVE_OK
            );
            assert_eq!(
                bu_bls_hash_to_g2(
                    msg.as_ptr(),
                    msg.len(),
                    dst2.as_ptr(),
                    dst2.len(),
                    o2.as_mut_ptr(),
                    96,
                ),
                BU_CURVE_OK
            );
        }
        assert_ne!(o1, [0u8; 48]);
        assert_ne!(o2, [0u8; 96]);
    }

    #[test]
    fn generate_secret_secp() {
        let seed = b"deterministic-seed-for-test!!!!";
        let mut sk = [0u8; 32];
        assert_eq!(
            unsafe {
                bu_curve_generate_secret(
                    BU_CURVE_SECP256K1,
                    seed.as_ptr(),
                    seed.len(),
                    sk.as_mut_ptr(),
                    sk.len(),
                )
            },
            BU_CURVE_OK
        );
        assert_ne!(sk, [0u8; 32]);
        // mul_base with generated secret should succeed
        let mut pk = [0u8; 33];
        assert_eq!(
            unsafe { bu_curve_mul_base(BU_CURVE_SECP256K1, sk.as_ptr(), 32, pk.as_mut_ptr(), 33,) },
            BU_CURVE_OK
        );
    }

    #[test]
    fn error_codes() {
        assert_eq!(
            unsafe { bu_curve_generator(9999, core::ptr::null_mut(), 0) },
            BU_CURVE_ERR_NULL
        );
        let mut buf = [0u8; 4];
        assert_eq!(
            unsafe { bu_curve_generator(9999, buf.as_mut_ptr(), 4) },
            BU_CURVE_ERR_INVALID_CURVE
        );
        assert_eq!(
            unsafe { bu_curve_generator(BU_CURVE_SECP256K1, buf.as_mut_ptr(), 4) },
            BU_CURVE_ERR_BUFFER
        );
        // All-zero fixed buffer decodes as infinity (BIP327 zeroPK
        // round-trip convention) and negates to itself.
        let bad = [0u8; 33];
        let mut out = [0u8; 33];
        assert_eq!(
            unsafe { bu_curve_neg(BU_CURVE_SECP256K1, bad.as_ptr(), 33, out.as_mut_ptr(), 33,) },
            BU_CURVE_OK
        );
        assert_eq!(out, [0u8; 33]);
        // Genuinely invalid encoding (prefix 0x02, x = 0 off curve).
        let mut garbage = [0u8; 33];
        garbage[0] = 0x02;
        assert_eq!(
            unsafe {
                bu_curve_neg(
                    BU_CURVE_SECP256K1,
                    garbage.as_ptr(),
                    33,
                    out.as_mut_ptr(),
                    33,
                )
            },
            BU_CURVE_ERR_INVALID_POINT
        );
    }
}

/// Jubjub `sc_reduce64`: 64-byte LE integer → 32-byte LE scalar mod r.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_jubjub_sc_reduce64(
    scalar64: *const u8,
    scalar_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if scalar64.is_null() || out.is_null() || scalar_len != 64 || out_len < 32 {
        return BU_CURVE_ERR_BUFFER;
    }
    let mut inn = [0u8; 64];
    inn.copy_from_slice(slice::from_raw_parts(scalar64, 64));
    let s = crate::curve::jubjub::Scalar::sc_reduce64_le(&inn);
    let mut le = [0u8; 32];
    s.to_bytes_le(&mut le);
    slice::from_raw_parts_mut(out, 32).copy_from_slice(&le);
    BU_CURVE_OK
}

/// Pallas `sc_reduce64`: 64-byte LE integer → 32-byte LE scalar mod r.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_pallas_sc_reduce64(
    scalar64: *const u8,
    scalar_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if scalar64.is_null() || out.is_null() || scalar_len != 64 || out_len < 32 {
        return BU_CURVE_ERR_BUFFER;
    }
    let mut inn = [0u8; 64];
    inn.copy_from_slice(slice::from_raw_parts(scalar64, 64));
    let s = crate::curve::pallas::Scalar::sc_reduce64_le(&inn);
    let mut le = [0u8; 32];
    s.to_bytes_le(&mut le);
    slice::from_raw_parts_mut(out, 32).copy_from_slice(&le);
    BU_CURVE_OK
}

/// Vesta `sc_reduce64`: 64-byte LE integer → 32-byte LE scalar mod r.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_vesta_sc_reduce64(
    scalar64: *const u8,
    scalar_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if scalar64.is_null() || out.is_null() || scalar_len != 64 || out_len < 32 {
        return BU_CURVE_ERR_BUFFER;
    }
    let mut inn = [0u8; 64];
    inn.copy_from_slice(slice::from_raw_parts(scalar64, 64));
    let s = crate::curve::vesta::Scalar::sc_reduce64_le(&inn);
    let mut le = [0u8; 32];
    s.to_bytes_le(&mut le);
    slice::from_raw_parts_mut(out, 32).copy_from_slice(&le);
    BU_CURVE_OK
}

// ---------------------------------------------------------------------------
// Ed25519 variable-time operators (public scalars / points only)
// ---------------------------------------------------------------------------

/// Variable-time [s]P. `scalar` 32 LE, `point` 32 compressed, `out` 32.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_ed25519_mul_vartime(
    scalar: *const u8,
    point: *const u8,
    out: *mut u8,
) -> i32 {
    if scalar.is_null() || point.is_null() || out.is_null() {
        return BU_CURVE_ERR_NULL;
    }
    use crate::curve::traits::CurvePoint;
    let sc = match crate::curve::ed25519::Scalar::from_bytes_le(&read32(scalar)) {
        Ok(s) => s,
        Err(_) => return BU_CURVE_ERR_INVALID_SCALAR,
    };
    let p = match crate::curve::ed25519::Ed25519Point::from_bytes(&read32(point)[..]) {
        Ok(p) => p,
        Err(_) => return BU_CURVE_ERR_INVALID_POINT,
    };
    let r = p.mul_vartime(&sc);
    match r.to_bytes_compressed(core::slice::from_raw_parts_mut(out, 32)) {
        Ok(()) => BU_CURVE_OK,
        Err(_) => BU_CURVE_ERR_UNSUPPORTED,
    }
}

/// Variable-time [s]B (base point).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_ed25519_mul_base_vartime(scalar: *const u8, out: *mut u8) -> i32 {
    if scalar.is_null() || out.is_null() {
        return BU_CURVE_ERR_NULL;
    }
    use crate::curve::traits::CurvePoint;
    let sc = match crate::curve::ed25519::Scalar::from_bytes_le(&read32(scalar)) {
        Ok(s) => s,
        Err(_) => return BU_CURVE_ERR_INVALID_SCALAR,
    };
    let r = crate::curve::ed25519::Ed25519Point::mul_vartime_base(&sc);
    match r.to_bytes_compressed(core::slice::from_raw_parts_mut(out, 32)) {
        Ok(()) => BU_CURVE_OK,
        Err(_) => BU_CURVE_ERR_UNSUPPORTED,
    }
}

/// Variable-time s1*P1 + s2*P2.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_ed25519_mul_add_vartime(
    s1: *const u8,
    p1: *const u8,
    s2: *const u8,
    p2: *const u8,
    out: *mut u8,
) -> i32 {
    if s1.is_null() || p1.is_null() || s2.is_null() || p2.is_null() || out.is_null() {
        return BU_CURVE_ERR_NULL;
    }
    use crate::curve::traits::CurvePoint;
    let a = match crate::curve::ed25519::Scalar::from_bytes_le(&read32(s1)) {
        Ok(s) => s,
        Err(_) => return BU_CURVE_ERR_INVALID_SCALAR,
    };
    let b = match crate::curve::ed25519::Scalar::from_bytes_le(&read32(s2)) {
        Ok(s) => s,
        Err(_) => return BU_CURVE_ERR_INVALID_SCALAR,
    };
    let ap = match crate::curve::ed25519::Ed25519Point::from_bytes(&read32(p1)[..]) {
        Ok(p) => p,
        Err(_) => return BU_CURVE_ERR_INVALID_POINT,
    };
    let bp = match crate::curve::ed25519::Ed25519Point::from_bytes(&read32(p2)[..]) {
        Ok(p) => p,
        Err(_) => return BU_CURVE_ERR_INVALID_POINT,
    };
    let r = crate::curve::ed25519::Ed25519Point::mul_vartime_add(&a, &ap, &b, &bp);
    match r.to_bytes_compressed(core::slice::from_raw_parts_mut(out, 32)) {
        Ok(()) => BU_CURVE_OK,
        Err(_) => BU_CURVE_ERR_UNSUPPORTED,
    }
}

/// Variable-time point add (public points).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_ed25519_add_vartime(a: *const u8, b: *const u8, out: *mut u8) -> i32 {
    if a.is_null() || b.is_null() || out.is_null() {
        return BU_CURVE_ERR_NULL;
    }
    use crate::curve::traits::CurvePoint;
    let pa = match crate::curve::ed25519::Ed25519Point::from_bytes(&read32(a)[..]) {
        Ok(p) => p,
        Err(_) => return BU_CURVE_ERR_INVALID_POINT,
    };
    let pb = match crate::curve::ed25519::Ed25519Point::from_bytes(&read32(b)[..]) {
        Ok(p) => p,
        Err(_) => return BU_CURVE_ERR_INVALID_POINT,
    };
    match pa
        .add(&pb)
        .to_bytes_compressed(core::slice::from_raw_parts_mut(out, 32))
    {
        Ok(()) => BU_CURVE_OK,
        Err(_) => BU_CURVE_ERR_UNSUPPORTED,
    }
}

/// Variable-time point sub.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_ed25519_sub_vartime(a: *const u8, b: *const u8, out: *mut u8) -> i32 {
    if a.is_null() || b.is_null() || out.is_null() {
        return BU_CURVE_ERR_NULL;
    }
    use crate::curve::traits::CurvePoint;
    let pa = match crate::curve::ed25519::Ed25519Point::from_bytes(&read32(a)[..]) {
        Ok(p) => p,
        Err(_) => return BU_CURVE_ERR_INVALID_POINT,
    };
    let pb = match crate::curve::ed25519::Ed25519Point::from_bytes(&read32(b)[..]) {
        Ok(p) => p,
        Err(_) => return BU_CURVE_ERR_INVALID_POINT,
    };
    match pa
        .add(&pb.neg())
        .to_bytes_compressed(core::slice::from_raw_parts_mut(out, 32))
    {
        Ok(()) => BU_CURVE_OK,
        Err(_) => BU_CURVE_ERR_UNSUPPORTED,
    }
}

/// Variable-time point negate.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_ed25519_neg_vartime(p: *const u8, out: *mut u8) -> i32 {
    if p.is_null() || out.is_null() {
        return BU_CURVE_ERR_NULL;
    }
    use crate::curve::traits::CurvePoint;
    let pa = match crate::curve::ed25519::Ed25519Point::from_bytes(&read32(p)[..]) {
        Ok(p) => p,
        Err(_) => return BU_CURVE_ERR_INVALID_POINT,
    };
    match pa
        .neg()
        .to_bytes_compressed(core::slice::from_raw_parts_mut(out, 32))
    {
        Ok(()) => BU_CURVE_OK,
        Err(_) => BU_CURVE_ERR_UNSUPPORTED,
    }
}

/// Variable-time double.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_ed25519_double_vartime(p: *const u8, out: *mut u8) -> i32 {
    if p.is_null() || out.is_null() {
        return BU_CURVE_ERR_NULL;
    }
    use crate::curve::traits::CurvePoint;
    let pa = match crate::curve::ed25519::Ed25519Point::from_bytes(&read32(p)[..]) {
        Ok(p) => p,
        Err(_) => return BU_CURVE_ERR_INVALID_POINT,
    };
    match pa
        .double()
        .to_bytes_compressed(core::slice::from_raw_parts_mut(out, 32))
    {
        Ok(()) => BU_CURVE_OK,
        Err(_) => BU_CURVE_ERR_UNSUPPORTED,
    }
}

// ---------------------------------------------------------------------------
// Ristretto ↔ Edwards encoding
// ---------------------------------------------------------------------------

/// Edwards compressed (32) → Ristretto compressed (32).
/// Wraps the Edwards point and Ristretto-encodes it (`fromEdwardBytes`).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_ristretto_from_edwards(
    ed: *const u8,
    ed_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if ed.is_null() || out.is_null() {
        return BU_CURVE_ERR_NULL;
    }
    if ed_len != 32 || out_len < 32 {
        return BU_CURVE_ERR_BUFFER;
    }
    let mut eb = [0u8; 32];
    eb.copy_from_slice(slice::from_raw_parts(ed, 32));
    let ed_pt = match Ed25519Point::from_bytes(&eb) {
        Ok(p) => p,
        Err(_) => return BU_CURVE_ERR_INVALID_POINT,
    };
    let r = RistrettoPoint::from_ed25519(ed_pt);
    let mut ob = [0u8; 32];
    if r.encode(&mut ob).is_err() {
        return BU_CURVE_ERR_INVALID_POINT;
    }
    slice::from_raw_parts_mut(out, 32).copy_from_slice(&ob);
    BU_CURVE_OK
}

/// Ristretto compressed (32) → Edwards compressed (32).
/// Decodes Ristretto, exports underlying Edwards encoding (`toEdwardBytes`).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_ristretto_to_edwards(
    ristretto: *const u8,
    ristretto_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if ristretto.is_null() || out.is_null() {
        return BU_CURVE_ERR_NULL;
    }
    if ristretto_len != 32 || out_len < 32 {
        return BU_CURVE_ERR_BUFFER;
    }
    let mut rb = [0u8; 32];
    rb.copy_from_slice(slice::from_raw_parts(ristretto, 32));
    let r = match RistrettoPoint::decode(&rb) {
        Ok(p) => p,
        Err(_) => return BU_CURVE_ERR_INVALID_POINT,
    };
    match r
        .as_ed25519()
        .to_bytes_compressed(slice::from_raw_parts_mut(out, 32))
    {
        Ok(()) => BU_CURVE_OK,
        Err(_) => BU_CURVE_ERR_INVALID_POINT,
    }
}

#[cfg(test)]
mod ristretto_edwards_tests {
    use super::*;

    #[test]
    fn ristretto_edwards_roundtrip() {
        unsafe {
            let mut g = [0u8; 32];
            assert_eq!(
                bu_curve_generator(BU_CURVE_RISTRETTO, g.as_mut_ptr(), 32),
                BU_CURVE_OK
            );
            let mut ed = [0u8; 32];
            assert_eq!(
                bu_ristretto_to_edwards(g.as_ptr(), 32, ed.as_mut_ptr(), 32),
                BU_CURVE_OK
            );
            let mut r2 = [0u8; 32];
            assert_eq!(
                bu_ristretto_from_edwards(ed.as_ptr(), 32, r2.as_mut_ptr(), 32),
                BU_CURVE_OK
            );
            assert_ne!(ed, [0u8; 32]);
        }
    }
}
