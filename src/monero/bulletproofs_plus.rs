//! Bulletproofs+ prove and verify (Monero RingCT).
//!
//! Port of the Monero reference implementation `BulletproofsPlusGenerator` (adapted from Monero
//! C++ `rct::bulletproof_PLUS_PROVE` / `bulletproof_PLUS_VERIFY`):
//! range proofs over ed25519 with `N = 64` value bits and up to `M = 16`
//! outputs per proof.
//!
//! Wire format of one proof blob (all integers little-endian):
//! ```text
//! m: u8 (1..=16) | V[m][32] | A A1 B R1 S1 D1 (6x32)
//! | n_lr: u8 (= 6 + log2(ceil_pow2(m))) | L[n_lr][32] | R[n_lr][32]
//! ```
//! A batch ("packed") is `n: u32 LE` followed by `n` entries of
//! `len: u32 LE | blob[len]`.

#![cfg(feature = "monero")]

use super::multiexp::MultiexpPair;
use super::{
    h_point, hash_to_scalar, pt_decode, pt_encode, sc_bytes, sc_from_bytes, Ed25519Point,
    GeneratorCache, MoneroError, MoneroResult, ProveRng, Scalar, BP_INIT_TRANSCRIPT, S32,
    SCALAR_INV_EIGHT, SCALAR_MINUS_INV_EIGHT, SCALAR_MINUS_ONE, SCALAR_ONE, SCALAR_TWO,
    SCALAR_TWO64M1, SCALAR_ZERO,
};
use crate::curve::ed25519::monero as ed_mono;
use crate::curve::traits::CurvePoint;
use alloc::vec::Vec;

/// Maximum value bits per output (`N = 64`).
pub const BP_N: usize = 64;
/// Log2 of N.
pub const BP_LOG_N: usize = 6;
/// Maximum outputs per proof.
pub const BP_MAX_M: usize = 16;

/// Encoded ed25519 identity point (`01 || 0*31`).
pub const IDENTITY_BYTES: S32 = [
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// A Bulletproofs+ proof (decoded form).
#[derive(Clone, Debug)]
pub struct BpPlusProof {
    /// Commitments (M points).
    pub v: Vec<S32>,
    /// Commitment to bit vectors.
    pub a: S32,
    /// Masked inner-product commitment.
    pub a1: S32,
    /// Blinding commitment.
    pub b: S32,
    /// Response scalars.
    pub r1: S32,
    /// Response scalars.
    pub s1: S32,
    /// Response scalars.
    pub d1: S32,
    /// Fold points (left).
    pub l: Vec<S32>,
    /// Fold points (right).
    pub r: Vec<S32>,
}

fn take32(data: &[u8], off: &mut usize) -> MoneroResult<S32> {
    if *off + 32 > data.len() {
        return Err(MoneroError::InvalidLength);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&data[*off..*off + 32]);
    *off += 32;
    Ok(out)
}

/// Decode one proof blob.
pub fn parse_proof(blob: &[u8]) -> MoneroResult<BpPlusProof> {
    // Assigned below before first read.
    let mut off: usize;
    if blob.is_empty() {
        return Err(MoneroError::InvalidLength);
    }
    let m = blob[0] as usize;
    off = 1;
    if m == 0 || m > BP_MAX_M {
        return Err(MoneroError::InvalidProof);
    }
    let mut v = Vec::with_capacity(m);
    for _ in 0..m {
        v.push(take32(blob, &mut off)?);
    }
    let a = take32(blob, &mut off)?;
    let a1 = take32(blob, &mut off)?;
    let b = take32(blob, &mut off)?;
    let r1 = take32(blob, &mut off)?;
    let s1 = take32(blob, &mut off)?;
    let d1 = take32(blob, &mut off)?;
    if off >= blob.len() {
        return Err(MoneroError::InvalidLength);
    }
    let n_lr = blob[off] as usize;
    off += 1;
    let mut l = Vec::with_capacity(n_lr);
    for _ in 0..n_lr {
        l.push(take32(blob, &mut off)?);
    }
    let mut r = Vec::with_capacity(n_lr);
    for _ in 0..n_lr {
        r.push(take32(blob, &mut off)?);
    }
    if off != blob.len() {
        return Err(MoneroError::InvalidLength);
    }
    // logM from output count; rounds must be 6 + logM.
    let mut log_m = 0usize;
    let mut mm = 1usize;
    while mm < m {
        mm <<= 1;
        log_m += 1;
    }
    if n_lr != BP_LOG_N + log_m || l.len() != r.len() || l.is_empty() {
        return Err(MoneroError::InvalidProof);
    }
    Ok(BpPlusProof {
        v,
        a,
        a1,
        b,
        r1,
        s1,
        d1,
        l,
        r,
    })
}

/// Encode one proof blob.
pub fn emit_proof(p: &BpPlusProof) -> MoneroResult<Vec<u8>> {
    if p.v.is_empty() || p.v.len() > BP_MAX_M {
        return Err(MoneroError::InvalidProof);
    }
    if p.l.len() != p.r.len() || p.l.is_empty() {
        return Err(MoneroError::InvalidProof);
    }
    let mut out = Vec::new();
    out.push(p.v.len() as u8);
    for x in &p.v {
        out.extend_from_slice(x);
    }
    out.extend_from_slice(&p.a);
    out.extend_from_slice(&p.a1);
    out.extend_from_slice(&p.b);
    out.extend_from_slice(&p.r1);
    out.extend_from_slice(&p.s1);
    out.extend_from_slice(&p.d1);
    out.push(p.l.len() as u8);
    for x in &p.l {
        out.extend_from_slice(x);
    }
    for x in &p.r {
        out.extend_from_slice(x);
    }
    Ok(out)
}

fn put_u32le(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn get_u32le(data: &[u8], off: &mut usize) -> MoneroResult<u32> {
    if *off + 4 > data.len() {
        return Err(MoneroError::InvalidLength);
    }
    let mut b = [0u8; 4];
    b.copy_from_slice(&data[*off..*off + 4]);
    *off += 4;
    Ok(u32::from_le_bytes(b))
}

/// Decode a packed batch (`n: u32 LE | len: u32 LE | blob * n`).
pub fn unpack_proofs(packed: &[u8]) -> MoneroResult<Vec<BpPlusProof>> {
    let mut off = 0usize;
    let n = get_u32le(packed, &mut off)? as usize;
    if n == 0 || n > 256 {
        return Err(MoneroError::InvalidProof);
    }
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let len = get_u32le(packed, &mut off)? as usize;
        if off + len > packed.len() {
            return Err(MoneroError::InvalidLength);
        }
        out.push(parse_proof(&packed[off..off + len])?);
        off += len;
    }
    if off != packed.len() {
        return Err(MoneroError::InvalidLength);
    }
    Ok(out)
}

/// Encode a packed batch.
pub fn pack_proofs(proofs: &[BpPlusProof]) -> MoneroResult<Vec<u8>> {
    let mut out = Vec::new();
    put_u32le(&mut out, proofs.len() as u32);
    for p in proofs {
        let blob = emit_proof(p)?;
        put_u32le(&mut out, blob.len() as u32);
        out.extend_from_slice(&blob);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Scalar helpers (all mod L, LE bytes).
// ---------------------------------------------------------------------------

fn sc_add(a: &Scalar, b: &Scalar) -> Scalar {
    a.add(b)
}

fn sc_sub(a: &Scalar, b: &Scalar) -> Scalar {
    a.add(&b.neg())
}

fn sc_mul(a: &Scalar, b: &Scalar) -> Scalar {
    a.mul(b)
}

/// `a*b + c`.
fn sc_muladd(a: &Scalar, b: &Scalar, c: &Scalar) -> Scalar {
    sc_add(&sc_mul(a, b), c)
}

fn s_const(bytes: &S32) -> Scalar {
    Scalar::from_bytes_mod_order(bytes)
}

// ---------------------------------------------------------------------------
// Point helpers.
// ---------------------------------------------------------------------------

fn pt_add(a: &Ed25519Point, b: &Ed25519Point) -> Ed25519Point {
    a.add(b)
}

/// `G * scalar` (base-point multiply).
fn scalarmult_base(s: &Scalar) -> Ed25519Point {
    Ed25519Point::generator().mul_vartime(s)
}

/// `8 * P` for an encoded point.
fn scalarmult8(enc: &S32) -> MoneroResult<Ed25519Point> {
    let p = pt_decode(enc)?;
    Ok(p.double().double().double())
}

// ---------------------------------------------------------------------------
// Multiexp selection (mirrors the reference implementation
// ---------------------------------------------------------------------------

fn multiexp_select(pairs: &[MultiexpPair], higi_size: usize) -> MoneroResult<Ed25519Point> {
    if higi_size > 0 {
        if higi_size <= 232 && pairs.len() == higi_size {
            return super::multiexp::straus(pairs, 192);
        }
        let c = super::multiexp::pippenger_c(pairs.len());
        return super::multiexp::pippenger(pairs, higi_size, c);
    }
    if pairs.len() <= 95 {
        return super::multiexp::straus(pairs, 192);
    }
    let c = super::multiexp::pippenger_c(pairs.len());
    super::multiexp::pippenger(pairs, 0, c)
}

// ---------------------------------------------------------------------------
// Inner-product argument helpers.
// ---------------------------------------------------------------------------

/// `y^(0..n)`.
fn vector_of_scalar_powers(x: &Scalar, n: usize) -> MoneroResult<Vec<Scalar>> {
    if n == 0 {
        return Err(MoneroError::InvalidProof);
    }
    let one = s_const(&SCALAR_ONE);
    let mut res = Vec::with_capacity(n);
    res.push(one);
    if n == 1 {
        return Ok(res);
    }
    res.push(*x);
    for _ in 2..n {
        let prev = *res.last().ok_or(MoneroError::InvalidProof)?;
        res.push(sc_mul(&prev, x));
    }
    Ok(res)
}

/// `x^2 + x^4 + ...` for `n` a power of two (mirrors `_sumOfEvenPowers`).
fn sum_of_even_powers(x: &Scalar, mut n: usize) -> MoneroResult<Scalar> {
    if n == 0 || (n & (n - 1)) != 0 {
        return Err(MoneroError::InvalidProof);
    }
    let mut x1 = sc_mul(x, x);
    let mut res = x1;
    while n > 2 {
        res = sc_muladd(&x1, &res, &res);
        x1 = sc_mul(&x1, &x1);
        n /= 2;
    }
    Ok(res)
}

/// `x + x^2 + ... + x^n` (mirrors `_sumOfScalarPowers`).
fn sum_of_scalar_powers(x: &Scalar, mut n: usize) -> MoneroResult<Scalar> {
    if n == 0 {
        return Err(MoneroError::InvalidProof);
    }
    let one = s_const(&SCALAR_ONE);
    if n == 1 {
        return Ok(*x);
    }
    n += 1;
    let mut x1 = *x;
    let mut res;
    if (n & (n - 1)) == 0 {
        res = sc_add(&one, &x1);
        while n > 2 {
            x1 = sc_mul(&x1, &x1);
            res = sc_muladd(&x1, &res, &res);
            n /= 2;
        }
    } else {
        let mut prev = x1;
        res = one;
        for i in 1..n {
            if i > 1 {
                prev = sc_mul(&prev, &x1);
            }
            res = sc_add(&res, &prev);
        }
    }
    Ok(sc_sub(&res, &one))
}

/// Weighted inner product `sum a[i]*b[i]*y^(i+1)`.
fn weighted_inner_product(a: &[Scalar], b: &[Scalar], y: &Scalar) -> MoneroResult<Scalar> {
    if a.len() != b.len() {
        return Err(MoneroError::InvalidProof);
    }
    let zero = s_const(&SCALAR_ZERO);
    let mut res = zero;
    let mut ypow = s_const(&SCALAR_ONE);
    for (ai, bi) in a.iter().zip(b.iter()) {
        let t = sc_mul(ai, bi);
        ypow = sc_mul(&ypow, y);
        res = sc_muladd(&t, &ypow, &res);
    }
    Ok(res)
}

/// Long addition-chain inversion mod L (mirrors the reference implementation
fn invert(x: &Scalar) -> MoneroResult<Scalar> {
    if x.is_zero() {
        return Err(MoneroError::ZeroScalar);
    }
    let a1 = *x;
    let a10 = sc_mul(&a1, &a1);
    let a100 = sc_mul(&a10, &a10);
    let a11 = sc_mul(&a10, &a1);
    let a101 = sc_mul(&a10, &a11);
    let a111 = sc_mul(&a10, &a101);
    let a1001 = sc_mul(&a10, &a111);
    let a1011 = sc_mul(&a10, &a1001);
    let a1111 = sc_mul(&a100, &a1011);
    let sm = |mut y: Scalar, n: usize, x: &Scalar| -> Scalar {
        let mut k = n;
        while k != 0 {
            y = sc_mul(&y, &y);
            k -= 1;
        }
        sc_mul(&y, x)
    };
    let mut inv = sc_mul(&a1111, &a1);
    inv = sm(inv, 123 + 3, &a101);
    inv = sm(inv, 2 + 2, &a11);
    inv = sm(inv, 1 + 4, &a1111);
    inv = sm(inv, 1 + 4, &a1111);
    inv = sm(inv, 4, &a1001);
    inv = sm(inv, 2, &a11);
    inv = sm(inv, 1 + 4, &a1111);
    inv = sm(inv, 1 + 3, &a101);
    inv = sm(inv, 3 + 3, &a101);
    inv = sm(inv, 3, &a111);
    inv = sm(inv, 1 + 4, &a1111);
    inv = sm(inv, 2 + 3, &a111);
    inv = sm(inv, 2 + 2, &a11);
    inv = sm(inv, 1 + 4, &a1011);
    inv = sm(inv, 2 + 4, &a1011);
    inv = sm(inv, 6 + 4, &a1001);
    inv = sm(inv, 2 + 2, &a11);
    inv = sm(inv, 3 + 2, &a11);
    inv = sm(inv, 3 + 2, &a11);
    inv = sm(inv, 1 + 4, &a1001);
    inv = sm(inv, 1 + 3, &a111);
    inv = sm(inv, 2 + 4, &a1111);
    inv = sm(inv, 1 + 4, &a1011);
    inv = sm(inv, 3, &a101);
    inv = sm(inv, 2 + 4, &a1111);
    inv = sm(inv, 3, &a101);
    inv = sm(inv, 1 + 2, &a11);
    Ok(inv)
}

/// Batch inversion (mirrors the reference implementation
fn invert_batch(xs: &mut [Scalar]) -> MoneroResult<()> {
    for x in xs.iter() {
        if x.is_zero() {
            return Err(MoneroError::ZeroScalar);
        }
    }
    let one = s_const(&SCALAR_ONE);
    let mut scratch = Vec::with_capacity(xs.len());
    let mut acc = one;
    for (n, x) in xs.iter().enumerate() {
        scratch.push(acc);
        if n == 0 {
            acc = *x;
        } else {
            acc = sc_mul(&acc, x);
        }
    }
    acc = invert(&acc)?;
    for i in (0..xs.len()).rev() {
        let tmp = sc_mul(&acc, &xs[i]);
        xs[i] = sc_mul(&acc, &scratch[i]);
        acc = tmp;
    }
    Ok(())
}

fn transcript2(transcript: &[u8], update: &[u8]) -> MoneroResult<Scalar> {
    let mut data = Vec::with_capacity(transcript.len() + update.len());
    data.extend_from_slice(transcript);
    data.extend_from_slice(update);
    hash_to_scalar(&data)
}

fn transcript3(transcript: &[u8], u0: &[u8], u1: &[u8]) -> MoneroResult<Scalar> {
    let mut data = Vec::with_capacity(transcript.len() + u0.len() + u1.len());
    data.extend_from_slice(transcript);
    data.extend_from_slice(u0);
    data.extend_from_slice(u1);
    hash_to_scalar(&data)
}

fn is_zero_scalar(s: &Scalar) -> bool {
    s.is_zero()
}

// ---------------------------------------------------------------------------
// Prove.
// ---------------------------------------------------------------------------

/// Prove state shared across the retry loop.
struct ProveCtx<'a> {
    rng: &'a mut ProveRng,
    gens: &'a GeneratorCache,
    h_point: Ed25519Point,
    g_point: Ed25519Point,
    inv_eight: Scalar,
}

fn vector_exponent(ctx: &ProveCtx<'_>, a: &[Scalar], b: &[Scalar]) -> MoneroResult<Ed25519Point> {
    if a.len() != b.len() || a.len() > BP_N * BP_MAX_M {
        return Err(MoneroError::InvalidProof);
    }
    let mut pairs = Vec::with_capacity(a.len() * 2);
    for (i, (ai, bi)) in a.iter().zip(b.iter()).enumerate() {
        pairs.push(MultiexpPair::new(sc_bytes(ai), ctx.gens.gi(i)?));
        pairs.push(MultiexpPair::new(sc_bytes(bi), ctx.gens.hi(i)?));
    }
    multiexp_select(&pairs, a.len() * 2)
}

#[allow(clippy::too_many_arguments)]
fn compute_lr(
    ctx: &ProveCtx<'_>,
    size: usize,
    y: &Scalar,
    g_vec: &[Ed25519Point],
    g0: usize,
    h_vec: &[Ed25519Point],
    h0: usize,
    a: &[Scalar],
    a0: usize,
    b: &[Scalar],
    b0: usize,
    c: &Scalar,
    d: &Scalar,
) -> MoneroResult<Ed25519Point> {
    if size + g0 > g_vec.len()
        || size + h0 > h_vec.len()
        || size + a0 > a.len()
        || size + b0 > b.len()
        || size > BP_N * BP_MAX_M
    {
        return Err(MoneroError::InvalidProof);
    }
    let inv8 = ctx.inv_eight;
    let mut pairs = Vec::with_capacity(size * 2 + 2);
    for i in 0..size {
        let s1 = sc_mul(&sc_mul(&a[a0 + i], y), &inv8);
        pairs.push(MultiexpPair::new(sc_bytes(&s1), g_vec[g0 + i]));
        let s2 = sc_mul(&b[b0 + i], &inv8);
        pairs.push(MultiexpPair::new(sc_bytes(&s2), h_vec[h0 + i]));
    }
    pairs.push(MultiexpPair::new(sc_bytes(&sc_mul(c, &inv8)), ctx.h_point));
    pairs.push(MultiexpPair::new(sc_bytes(&sc_mul(d, &inv8)), ctx.g_point));
    multiexp_select(&pairs, 0)
}

fn hadamard_fold(v: &[Ed25519Point], a: &Scalar, b: &Scalar) -> MoneroResult<Vec<Ed25519Point>> {
    if !v.len().is_multiple_of(2) {
        return Err(MoneroError::InvalidProof);
    }
    let size = v.len() / 2;
    let mut out = Vec::with_capacity(size);
    let ab = sc_bytes(a);
    let bb = sc_bytes(b);
    for n in 0..size {
        let ta = ed_mono::ge_dsm_precomp_var(&v[n]);
        let tb = ed_mono::ge_dsm_precomp_var(&v[size + n]);
        out.push(ed_mono::ge_double_scalar_mult_precomp_point_var(
            &ab, &ta, &bb, &tb,
        ));
    }
    Ok(out)
}

/// Core prove over bit-scalar vectors (`sv`) and masks (`gamma`).
fn prove_inner(ctx: &mut ProveCtx<'_>, sv: &[S32], gamma: &[S32]) -> MoneroResult<BpPlusProof> {
    if sv.len() != gamma.len() || sv.is_empty() {
        return Err(MoneroError::InvalidProof);
    }
    let one = s_const(&SCALAR_ONE);
    let two = s_const(&SCALAR_TWO);
    let inv8 = ctx.inv_eight;
    // Decode + range-check inputs.
    let mut sv_s = Vec::with_capacity(sv.len());
    for s in sv {
        sv_s.push(sc_from_bytes(s)?);
    }
    let mut gamma_s = Vec::with_capacity(gamma.len());
    for g in gamma {
        gamma_s.push(sc_from_bytes(g)?);
    }
    // Output count M (power of two >= len, capped at 16).
    let mut m = 1usize;
    let mut log_m = 0usize;
    while m <= BP_MAX_M && m < sv.len() {
        m <<= 1;
        log_m += 1;
    }
    if m > BP_MAX_M {
        return Err(MoneroError::InvalidProof);
    }
    let log_mn = log_m + BP_LOG_N;
    let mn = m * BP_N;
    // Commitments V[i] = gamma8*G + sv8*H.
    let mut v_pts = Vec::with_capacity(sv.len());
    let mut v_enc = Vec::with_capacity(sv.len());
    for (svi, gi) in sv_s.iter().zip(gamma_s.iter()) {
        let g8 = sc_mul(gi, &inv8);
        let s8 = sc_mul(svi, &inv8);
        let p = pt_add(&scalarmult_base(&g8), &ctx.h_point.mul_vartime(&s8));
        v_enc.push(pt_encode(&p)?);
        v_pts.push(p);
    }
    // Bit vectors aL/aR (+ /8 variants).
    let minus_one = s_const(&SCALAR_MINUS_ONE);
    let minus_inv8 = s_const(&SCALAR_MINUS_INV_EIGHT);
    let zero = s_const(&SCALAR_ZERO);
    let mut a_l = vec![zero; mn];
    let mut a_r = vec![zero; mn];
    let mut a_l8 = vec![zero; mn];
    let mut a_r8 = vec![zero; mn];
    for j in 0..m {
        let active = j < sv.len();
        for i in (0..BP_N).rev() {
            let idx = j * BP_N + i;
            // NOTE: padding slots (j >= sv.len()) take the zero-bit branch,
            // exactly like reference (aR = -1, aR8 = -1/8).
            let bit = active && ((sv[j][i / 8] >> (i % 8)) & 1 != 0);
            if bit {
                a_l[idx] = one;
                a_l8[idx] = inv8;
            } else {
                a_r[idx] = minus_one;
                a_r8[idx] = minus_inv8;
            }
        }
    }

    // Retry loop (zero challenges).
    loop {
        // transcript = H(init || H(V...)).
        let mut vcat = Vec::with_capacity(32 * v_enc.len());
        for x in &v_enc {
            vcat.extend_from_slice(x);
        }
        let mut transcript = transcript2(&BP_INIT_TRANSCRIPT, &sc_bytes(&hash_to_scalar(&vcat)?))?;
        let alpha = ctx.rng.sk_gen();
        // preA = <aL8, G> + <aR8, H>.
        let pre_a = vector_exponent(ctx, &a_l8, &a_r8)?;
        let a_pt = pt_add(&pre_a, &scalarmult_base(&sc_mul(&alpha, &inv8)));
        let a_enc = pt_encode(&a_pt)?;
        let y = transcript2(&sc_bytes(&transcript), &a_enc)?;
        if is_zero_scalar(&y) {
            continue;
        }
        transcript = hash_to_scalar(&sc_bytes(&y))?;
        if is_zero_scalar(&transcript) {
            continue;
        }
        let z2 = sc_mul(&transcript, &transcript);
        // d vector.
        let mut d = vec![zero; mn];
        d[0] = z2;
        for i in 1..BP_N {
            d[i] = sc_mul(&d[i - 1], &two);
        }
        for j in 1..m {
            for i in 0..BP_N {
                d[j * BP_N + i] = sc_mul(&d[(j - 1) * BP_N + i], &z2);
            }
        }
        let y_powers = vector_of_scalar_powers(&y, mn + 2)?;
        // aL1 = aL - z; aR1 = aR + z; dy; aR1 += dy.
        let mut a_l1 = Vec::with_capacity(mn);
        for x in &a_l {
            a_l1.push(sc_sub(x, &transcript));
        }
        let mut dy = Vec::with_capacity(mn);
        for i in 0..mn {
            dy.push(sc_mul(&d[i], &y_powers[mn - i]));
        }
        let mut a_r1 = Vec::with_capacity(mn);
        for (i, x) in a_r.iter().enumerate() {
            a_r1.push(sc_add(&sc_add(x, &transcript), &dy[i]));
        }
        // alpha1 = alpha + sum_j y^(mn+1) * z^(2j) * gamma[j].
        let mut alpha1 = alpha;
        let mut temp = one;
        for g in gamma_s.iter().take(sv.len()) {
            temp = sc_mul(&temp, &z2);
            let t2 = sc_mul(&y_powers[mn + 1], &temp);
            alpha1 = sc_add(&sc_mul(&t2, g), &alpha1);
        }
        // Fold setup.
        let mut nprime = mn;
        let mut g_prime = Vec::with_capacity(mn);
        let mut h_prime = Vec::with_capacity(mn);
        let mut aprime = vec![zero; mn];
        let mut bprime = vec![zero; mn];
        let yinv = invert(&y)?;
        let mut yinvpow = vec![zero; mn];
        yinvpow[0] = one;
        for i in 0..mn {
            g_prime.push(ctx.gens.gi(i)?);
            h_prime.push(ctx.gens.hi(i)?);
            if i > 0 {
                yinvpow[i] = sc_mul(&yinvpow[i - 1], &yinv);
            }
            aprime[i] = a_l1[i];
            bprime[i] = a_r1[i];
        }
        let mut l_enc = vec![SCALAR_ZERO; log_mn];
        let mut r_enc = vec![SCALAR_ZERO; log_mn];
        let mut round = 0usize;
        let mut ok = true;
        while nprime > 1 {
            nprime /= 2;
            let c_l = weighted_inner_product(&aprime[0..nprime], &bprime[nprime..], &y)?;
            let mut a2 = Vec::with_capacity(nprime);
            for x in aprime.iter().skip(nprime) {
                a2.push(sc_mul(x, &y_powers[nprime]));
            }
            let c_r = weighted_inner_product(&a2, &bprime[0..nprime], &y)?;
            let d_l = ctx.rng.sk_gen();
            let d_r = ctx.rng.sk_gen();
            let l_pt = compute_lr(
                ctx,
                nprime,
                &yinvpow[nprime],
                &g_prime,
                nprime,
                &h_prime,
                0,
                &aprime,
                0,
                &bprime,
                nprime,
                &c_l,
                &d_l,
            )?;
            let r_pt = compute_lr(
                ctx,
                nprime,
                &y_powers[nprime],
                &g_prime,
                0,
                &h_prime,
                nprime,
                &aprime,
                nprime,
                &bprime,
                0,
                &c_r,
                &d_r,
            )?;
            l_enc[round] = pt_encode(&l_pt)?;
            r_enc[round] = pt_encode(&r_pt)?;
            let challenge = transcript3(&sc_bytes(&transcript), &l_enc[round], &r_enc[round])?;
            transcript = challenge;
            if is_zero_scalar(&challenge) {
                ok = false;
                break;
            }
            let c_inv = invert(&challenge)?;
            let t = sc_mul(&yinvpow[nprime], &challenge);
            g_prime = hadamard_fold(&g_prime, &c_inv, &t)?;
            h_prime = hadamard_fold(&h_prime, &challenge, &c_inv)?;
            let t = sc_mul(&c_inv, &y_powers[nprime]);
            let mut na = Vec::with_capacity(nprime);
            let mut nb = Vec::with_capacity(nprime);
            for i in 0..nprime {
                na.push(sc_add(
                    &sc_mul(&aprime[i], &challenge),
                    &sc_mul(&aprime[nprime + i], &t),
                ));
                nb.push(sc_add(
                    &sc_mul(&bprime[i], &c_inv),
                    &sc_mul(&bprime[nprime + i], &challenge),
                ));
            }
            aprime = na;
            bprime = nb;
            let c_sq = sc_mul(&challenge, &challenge);
            let c_sq_inv = sc_mul(&c_inv, &c_inv);
            alpha1 = sc_muladd(&d_l, &c_sq, &alpha1);
            alpha1 = sc_muladd(&d_r, &c_sq_inv, &alpha1);
            round += 1;
        }
        if !ok {
            continue;
        }
        let r_ = ctx.rng.sk_gen();
        let s_ = ctx.rng.sk_gen();
        let d_ = ctx.rng.sk_gen();
        let eta = ctx.rng.sk_gen();
        let mut pairs = Vec::with_capacity(4);
        pairs.push(MultiexpPair::new(sc_bytes(&sc_mul(&r_, &inv8)), g_prime[0]));
        pairs.push(MultiexpPair::new(sc_bytes(&sc_mul(&s_, &inv8)), h_prime[0]));
        pairs.push(MultiexpPair::new(
            sc_bytes(&sc_mul(&d_, &inv8)),
            ctx.g_point,
        ));
        let mut t = sc_mul(&sc_mul(&r_, &y), &bprime[0]);
        let t2 = sc_mul(&sc_mul(&s_, &y), &aprime[0]);
        t = sc_add(&t, &t2);
        pairs.push(MultiexpPair::new(sc_bytes(&sc_mul(&t, &inv8)), ctx.h_point));
        let a1_pt = multiexp_select(&pairs, 0)?;
        let a1_enc = pt_encode(&a1_pt)?;
        let t = sc_mul(&sc_mul(&r_, &y), &s_);
        let t = sc_mul(&t, &inv8);
        let t2 = sc_mul(&eta, &inv8);
        let b_pt = pt_add(&scalarmult_base(&t2), &ctx.h_point.mul_vartime(&t));
        let b_enc = pt_encode(&b_pt)?;
        let e = transcript3(&sc_bytes(&transcript), &a1_enc, &b_enc)?;
        if is_zero_scalar(&e) {
            continue;
        }
        let e_sq = sc_mul(&e, &e);
        let r1 = sc_muladd(&aprime[0], &e, &r_);
        let s1 = sc_muladd(&bprime[0], &e, &s_);
        let mut d1 = sc_muladd(&d_, &e, &eta);
        d1 = sc_muladd(&alpha1, &e_sq, &d1);
        return Ok(BpPlusProof {
            v: v_enc,
            a: a_enc,
            a1: a1_enc,
            b: b_enc,
            r1: sc_bytes(&r1),
            s1: sc_bytes(&s1),
            d1: sc_bytes(&d1),
            l: l_enc,
            r: r_enc,
        });
    }
}

/// Prove for raw bit-scalar vectors (`sv`, `gamma` as 32-byte LE scalars).
pub fn bp_plus_prove_scalars(
    sv: &[S32],
    gamma: &[S32],
    rng_seed: &S32,
) -> MoneroResult<BpPlusProof> {
    let gens = GeneratorCache::new(2 * BP_N * BP_MAX_M)?;
    let h_point = h_point()?;
    let g_point = Ed25519Point::generator();
    let mut rng = ProveRng::new(rng_seed);
    let mut ctx = ProveCtx {
        rng: &mut rng,
        gens: &gens,
        h_point,
        g_point,
        inv_eight: s_const(&SCALAR_INV_EIGHT),
    };
    prove_inner(&mut ctx, sv, gamma)
}

/// Prove for amounts (`v` as u64) with masks (`gamma`).
pub fn bp_plus_prove_amounts(
    amounts: &[u64],
    gamma: &[S32],
    rng_seed: &S32,
) -> MoneroResult<BpPlusProof> {
    if amounts.len() != gamma.len() || amounts.is_empty() {
        return Err(MoneroError::InvalidProof);
    }
    let mut sv = Vec::with_capacity(amounts.len());
    for a in amounts {
        let mut b = [0u8; 32];
        b[0..8].copy_from_slice(&a.to_le_bytes());
        sv.push(b);
    }
    bp_plus_prove_scalars(&sv, gamma, rng_seed)
}

// ---------------------------------------------------------------------------
// Verify.
// ---------------------------------------------------------------------------

struct ProofData {
    y: Scalar,
    z: Scalar,
    e: Scalar,
    challenges: Vec<Scalar>,
    log_m: usize,
    inv_offset: usize,
}

/// Batch-verify decoded proofs. Returns `Ok(true)` on success,
/// `Ok(false)` on arithmetic failure, `Err` on malformed input.
pub fn bp_plus_verify(proofs: &[BpPlusProof], rng_seed: &S32) -> MoneroResult<bool> {
    if proofs.is_empty() || proofs.len() > 256 {
        return Err(MoneroError::InvalidProof);
    }
    let _one = s_const(&SCALAR_ONE);
    let _two = s_const(&SCALAR_TWO);
    let zero = s_const(&SCALAR_ZERO);
    let minus_one = s_const(&SCALAR_MINUS_ONE);
    let _inv8 = s_const(&SCALAR_INV_EIGHT);
    let two64m1 = s_const(&SCALAR_TWO64M1);
    let h_point = h_point()?;
    let g_point = Ed25519Point::generator();

    let mut max_length = 0usize;
    let mut inv_offset = 0usize;
    let mut max_log_m = 0usize;
    let mut datas: Vec<ProofData> = Vec::with_capacity(proofs.len());
    let mut to_invert: Vec<Scalar> = Vec::new();

    for p in proofs {
        let r1 = sc_from_bytes(&p.r1)?;
        let s1 = sc_from_bytes(&p.s1)?;
        let d1 = sc_from_bytes(&p.d1)?;
        if p.v.is_empty() {
            return Err(MoneroError::InvalidProof);
        }
        if p.l.len() != p.r.len() || p.l.is_empty() {
            return Err(MoneroError::InvalidProof);
        }
        if p.l.len() > max_length {
            max_length = p.l.len();
        }
        // transcript = H(init || H(V...)).
        let mut vcat = Vec::with_capacity(32 * p.v.len());
        for x in &p.v {
            pt_decode(x)?;
            vcat.extend_from_slice(x);
        }
        let mut transcript = transcript2(&BP_INIT_TRANSCRIPT, &sc_bytes(&hash_to_scalar(&vcat)?))?;
        let y = transcript2(&sc_bytes(&transcript), &p.a)?;
        if is_zero_scalar(&y) {
            return Err(MoneroError::ZeroChallenge);
        }
        let z = hash_to_scalar(&sc_bytes(&y))?;
        transcript = z;
        if is_zero_scalar(&z) {
            return Err(MoneroError::ZeroChallenge);
        }
        // M / logM from output count.
        let mut m = 1usize;
        let mut log_m = 0usize;
        while m <= BP_MAX_M && m < p.v.len() {
            m <<= 1;
            log_m += 1;
        }
        if p.l.len() != BP_LOG_N + log_m {
            return Err(MoneroError::InvalidProof);
        }
        if log_m > max_log_m {
            max_log_m = log_m;
        }
        let rounds = log_m + BP_LOG_N;
        if rounds == 0 {
            return Err(MoneroError::InvalidProof);
        }
        let mut challenges = vec![zero; rounds];
        for (c, (l, r)) in challenges.iter_mut().zip(p.l.iter().zip(p.r.iter())) {
            transcript = transcript3(&sc_bytes(&transcript), l, r)?;
            *c = transcript;
            if is_zero_scalar(c) {
                return Err(MoneroError::ZeroChallenge);
            }
        }
        let e = transcript3(&sc_bytes(&transcript), &p.a1, &p.b)?;
        if is_zero_scalar(&e) {
            return Err(MoneroError::ZeroChallenge);
        }
        for c in &challenges {
            to_invert.push(*c);
        }
        to_invert.push(y);
        datas.push(ProofData {
            y,
            z,
            e,
            challenges,
            log_m,
            inv_offset,
        });
        inv_offset += rounds + 1;
        let _ = (r1, s1, d1);
    }
    if max_length >= 32 {
        return Err(MoneroError::InvalidProof);
    }
    let max_mn = 1usize << max_length;
    invert_batch(&mut to_invert)?;

    let gens = GeneratorCache::new(2 * max_mn)?;
    let mut rng = ProveRng::new(rng_seed);
    let mut pairs: Vec<MultiexpPair> = Vec::new();
    let mut g_scalar = zero;
    let mut h_scalar = zero;
    let mut gi_scalars = vec![zero; max_mn];
    let mut hi_scalars = vec![zero; max_mn];

    for (di, p) in proofs.iter().enumerate() {
        let pd = &datas[di];
        let m = 1usize << pd.log_m;
        let mn = m * BP_N;
        // Random nonzero weight.
        let mut weight = zero;
        while is_zero_scalar(&weight) {
            weight = rng.sk_gen();
        }
        // 8x points.
        let mut v8 = Vec::with_capacity(p.v.len());
        for x in &p.v {
            v8.push(scalarmult8(x)?);
        }
        let mut l8 = Vec::with_capacity(p.l.len());
        for x in &p.l {
            l8.push(scalarmult8(x)?);
        }
        let mut r8 = Vec::with_capacity(p.r.len());
        for x in &p.r {
            r8.push(scalarmult8(x)?);
        }
        let a1_8 = scalarmult8(&p.a1)?;
        let b_8 = scalarmult8(&p.b)?;
        let a_8 = scalarmult8(&p.a)?;
        // y^mn, y^(mn+1).
        let mut y_mn = pd.y;
        let mut tmp_mn = mn;
        while tmp_mn > 1 {
            y_mn = sc_mul(&y_mn, &y_mn);
            tmp_mn /= 2;
        }
        let y_mn1 = sc_mul(&y_mn, &pd.y);
        let e_sq = sc_mul(&pd.e, &pd.e);
        let z_sq = sc_mul(&pd.z, &pd.z);
        // V terms: weight * y^(mn+1) * (1 - e^2) * z^(2j) ...
        let mut temp = sc_mul(&sc_sub(&zero, &e_sq), &y_mn1);
        temp = sc_mul(&temp, &weight);
        for pt in v8.iter() {
            temp = sc_mul(&temp, &z_sq);
            pairs.push(MultiexpPair::new(sc_bytes(&temp), *pt));
        }
        let mut temp = sc_mul(&minus_one, &weight);
        pairs.push(MultiexpPair::new(sc_bytes(&temp), b_8));
        temp = sc_mul(&temp, &pd.e);
        pairs.push(MultiexpPair::new(sc_bytes(&temp), a1_8));
        let m_weight_e2 = sc_mul(&temp, &pd.e);
        pairs.push(MultiexpPair::new(sc_bytes(&m_weight_e2), a_8));
        g_scalar = sc_muladd(&weight, &sc_from_bytes(&p.d1)?, &g_scalar);
        // d vector + sums.
        let mut d = vec![zero; mn];
        d[0] = z_sq;
        for i in 1..BP_N {
            d[i] = sc_add(&d[i - 1], &d[i - 1]);
        }
        for j in 1..m {
            for i in 0..BP_N {
                d[j * BP_N + i] = sc_mul(&d[(j - 1) * BP_N + i], &z_sq);
            }
        }
        let sum_d = sc_mul(&two64m1, &sum_of_even_powers(&pd.z, 2 * m)?);
        let sum_y = sum_of_scalar_powers(&pd.y, mn)?;
        let mut temp = sc_mul(&sc_sub(&z_sq, &pd.z), &sum_y);
        let mut temp2 = sc_mul(&sc_mul(&y_mn1, &pd.z), &sum_d);
        temp = sc_add(&temp, &temp2);
        temp = sc_mul(&temp, &e_sq);
        let r1s = sc_from_bytes(&p.r1)?;
        let s1s = sc_from_bytes(&p.s1)?;
        temp2 = sc_mul(&sc_mul(&r1s, &pd.y), &s1s);
        temp = sc_add(&temp, &temp2);
        h_scalar = sc_muladd(&temp, &weight, &h_scalar);
        let rounds = pd.log_m + BP_LOG_N;
        let c_inv_all = &to_invert[pd.inv_offset..pd.inv_offset + rounds];
        let yinv = to_invert[pd.inv_offset + rounds];
        let mut c_cache = vec![zero; 1usize << rounds];
        c_cache[0] = c_inv_all[0];
        c_cache[1] = pd.challenges[0];
        for (j, (ch, ci)) in pd.challenges.iter().zip(c_inv_all.iter()).enumerate().skip(1) {
            let slots = 1usize << (j + 1);
            // NOTE: mirrors the reference implementation
            // double-decrements, visiting odd s = slots-1 .. 1 only.
            let mut s = slots - 1;
            loop {
                let half = c_cache[s / 2];
                c_cache[s] = sc_mul(&half, ch);
                c_cache[s - 1] = sc_mul(&half, ci);
                if s <= 1 {
                    break;
                }
                s -= 2;
            }
        }
        let mut e_r1_w = sc_mul(&sc_mul(&pd.e, &r1s), &weight);
        let e_s1_w = sc_mul(&sc_mul(&pd.e, &s1s), &weight);
        let e2_z_w = sc_mul(&sc_mul(&e_sq, &pd.z), &weight);
        let minus_e2_z_w = sc_sub(&zero, &e2_z_w);
        let mut minus_e2_w_y = sc_mul(&sc_sub(&zero, &e_sq), &weight);
        minus_e2_w_y = sc_mul(&minus_e2_w_y, &y_mn);
        for i in 0..mn {
            let mut g_sc = e_r1_w;
            g_sc = sc_muladd(&g_sc, &c_cache[i], &e2_z_w);
            let mut h_sc = sc_muladd(&e_s1_w, &c_cache[(!i) & (mn - 1)], &minus_e2_z_w);
            gi_scalars[i] = sc_add(&gi_scalars[i], &g_sc);
            h_sc = sc_muladd(&minus_e2_w_y, &d[i], &h_sc);
            hi_scalars[i] = sc_add(&hi_scalars[i], &h_sc);
            e_r1_w = sc_mul(&e_r1_w, &yinv);
            minus_e2_w_y = sc_mul(&minus_e2_w_y, &yinv);
        }
        for j in 0..rounds {
            let mut temp = sc_mul(&pd.challenges[j], &pd.challenges[j]);
            temp = sc_mul(&temp, &m_weight_e2);
            pairs.push(MultiexpPair::new(sc_bytes(&temp), l8[j]));
            let mut temp = sc_mul(&c_inv_all[j], &c_inv_all[j]);
            temp = sc_mul(&temp, &m_weight_e2);
            pairs.push(MultiexpPair::new(sc_bytes(&temp), r8[j]));
        }
    }

    pairs.push(MultiexpPair::new(sc_bytes(&g_scalar), g_point));
    pairs.push(MultiexpPair::new(sc_bytes(&h_scalar), h_point));
    // Prepend Gi/Hi terms.
    let mut full = Vec::with_capacity(2 * max_mn + pairs.len());
    for i in 0..max_mn {
        full.push(MultiexpPair::new(sc_bytes(&gi_scalars[i]), gens.gi(i)?));
        full.push(MultiexpPair::new(sc_bytes(&hi_scalars[i]), gens.hi(i)?));
    }
    full.extend_from_slice(&pairs);
    let mp = multiexp_select(&full, 2 * max_mn)?;
    Ok(pt_encode(&mp)? == IDENTITY_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gamma1() -> S32 {
        let mut g = [0u8; 32];
        g[0] = 7;
        g
    }

    #[test]
    fn prove_verify_roundtrip_single() {
        let seed = [9u8; 32];
        let p = bp_plus_prove_amounts(&[0], &[gamma1()], &seed).expect("prove");
        assert_eq!(p.v.len(), 1);
        assert_eq!(p.l.len(), 6);
        assert!(bp_plus_verify(&[p], &seed).expect("verify"));
    }

    #[test]
    fn prove_verify_roundtrip_multi() {
        let seed = [11u8; 32];
        let g2 = [5u8; 32];
        let p = bp_plus_prove_amounts(&[0, 5, 123456789], &[gamma1(), g2, gamma1()], &seed)
            .expect("prove");
        assert_eq!(p.v.len(), 3);
        assert!(bp_plus_verify(&[p], &seed).expect("verify"));
    }

    #[test]
    fn blob_codec_roundtrip() {
        let seed = [13u8; 32];
        let p = bp_plus_prove_amounts(&[42], &[gamma1()], &seed).expect("prove");
        let blob = emit_proof(&p).expect("emit");
        let q = parse_proof(&blob).expect("parse");
        assert_eq!(q.v, p.v);
        assert_eq!(q.l, p.l);
        let packed = pack_proofs(&[p]).expect("pack");
        let u = unpack_proofs(&packed).expect("unpack");
        assert_eq!(u.len(), 1);
        assert!(bp_plus_verify(&u, &seed).expect("verify"));
    }

    #[test]
    fn tampered_proof_fails() {
        let seed = [17u8; 32];
        let mut p = bp_plus_prove_amounts(&[1], &[gamma1()], &seed).expect("prove");
        p.d1[0] ^= 1;
        // d1 tamper keeps canonical scalar; verification must fail.
        assert!(!bp_plus_verify(&[p], &seed).expect("verify runs"));
    }

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        let s = s.trim();
        assert!(s.len().is_multiple_of(2));
        let mut out = Vec::with_capacity(s.len() / 2);
        let b = s.as_bytes();
        for i in (0..b.len()).step_by(2) {
            let hi = (b[i] as char).to_digit(16).expect("hex") as u8;
            let lo = (b[i + 1] as char).to_digit(16).expect("hex") as u8;
            out.push(hi << 4 | lo);
        }
        out
    }

    /// Cross-validation against Monero reference implementation-generated proofs
    /// (`tests/vectors/bp_plus.txt`: M = 1, 2, 4 outputs).
    #[test]
    fn vectors_verify() {
        let raw = include_str!("../../tests/vectors/bp_plus.txt");
        let seed = [0u8; 32];
        let mut n = 0;
        for line in raw.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let blob = hex_to_bytes(line);
            let p = parse_proof(&blob).expect("parse reference proof");
            let ok = bp_plus_verify(core::slice::from_ref(&p), &seed).expect("verify runs");
            assert!(ok, "reference proof #{n} (m={}) failed verify", p.v.len());
            n += 1;
        }
        assert_eq!(n, 3);
    }
    fn hex_of(b: &[u8]) -> alloc::string::String {
        use core::fmt::Write;
        let mut s = alloc::string::String::new();
        for x in b {
            let _ = write!(s, "{:02x}", x);
        }
        s
    }

    /// Differential Straus vs Pippenger agreement on pseudo-random inputs.
    #[test]
    fn straus_pippenger_agree() {
        use crate::monero::multiexp::{pippenger, pippenger_c, straus, MultiexpPair};
        let h = h_point().unwrap();
        let g = Ed25519Point::generator();
        for &n in &[3usize, 33, 66, 95, 96, 128, 146, 258, 512] {
            // xorshift pseudo-random scalars (deterministic).
            let mut st: u64 = 0x123456789abcdef;
            let mut next = || {
                st ^= st << 13;
                st ^= st >> 7;
                st ^= st << 17;
                st
            };
            let mut pairs = Vec::new();
            for _ in 0..n {
                let mut s = [0u8; 32];
                for w in s.chunks_mut(8) {
                    w.copy_from_slice(&next().to_le_bytes());
                }
                let pt = if next() & 1 == 0 { g } else { h };
                pairs.push(MultiexpPair::new(s, pt));
            }
            let a = straus(&pairs, 192).unwrap();
            let b = pippenger(&pairs, 0, pippenger_c(n)).unwrap();
            assert_eq!(
                pt_encode(&a).unwrap(),
                pt_encode(&b).unwrap(),
                "straus/pippenger mismatch at n={n}"
            );
        }
    }

    /// Generator points must match the monero reference cached exponents.
    #[test]
    fn generators_match_reference_cache() {
        use crate::monero::{keccak256, varint, BP_HASH_KEY, MONERO_H};
        let mut data = Vec::from(MONERO_H);
        data.extend_from_slice(BP_HASH_KEY);
        data.extend_from_slice(&varint(0));
        assert_eq!(data.len(), 49);
        let h = keccak256(&data).unwrap();
        assert_eq!(
            hex_of(&h),
            "d76df7e68bc32eba02f368668444a48f7cfb50357b5c2d0dc9da49c34ef91fe3"
        );
        let g = GeneratorCache::new(4).expect("gens");
        assert_eq!(
            hex_of(&pt_encode(&g.hi(0).unwrap()).unwrap()),
            "48628df380a5016d25451aaa501731a11b72bf66dc41d81f719abd35ce92b0ed"
        );
        assert_eq!(
            hex_of(&pt_encode(&g.gi(0).unwrap()).unwrap()),
            "38c5d4db53aeb86f5a80def9be4953f2288ed5a44c66af723f463d0170829010"
        );
    }
}
