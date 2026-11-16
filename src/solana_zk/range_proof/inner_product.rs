//! Inner-product argument (zero-dep port of Bulletproofs Protocol 2).
//!
//! /// Byte-compatible port of
//! `zk-sdk/src/range_proof/inner_product.rs`: recursive `L`/`R` argument with
//! per-round `G`/`H` factor folding (first round unrolled). Transcript labels
//! (`inner-product` dom-sep + `n`, `L`, `R`, `u`) match upstream exactly.

use super::generators::RangeError;
use super::util;
use crate::curve::ed25519::Scalar;
use crate::curve::traits::CurvePoint;
use crate::curve::RistrettoPoint;
use crate::solana_zk::sigma_proofs::ZkTranscript;

/// Inner-product proof: `log(n)` L/R point pairs + scalars.
#[derive(Clone)]
pub struct InnerProductProof {
    /// L points (compressed).
    pub l_vec: Vec<[u8; 32]>,
    /// R points (compressed).
    pub r_vec: Vec<[u8; 32]>,
    /// Final `a` scalar.
    pub a: Scalar,
    /// Final `b` scalar.
    pub b: Scalar,
}

/// Sequential multiscalar mul (sums `s_i * P_i`).
pub fn ms_mul(scalars: &[Scalar], points: &[RistrettoPoint]) -> RistrettoPoint {
    let mut acc = RistrettoPoint::identity();
    for (s, p) in scalars.iter().zip(points.iter()) {
        acc = acc.add(&p.mul(s));
    }
    acc
}

/// Montgomery batch inversion (in place). Returns the inverse
/// of the total product. Errors on a zero input.
fn batch_invert(xs: &mut [Scalar]) -> Result<Scalar, RangeError> {
    let n = xs.len();
    let mut prod = vec![Scalar::one(); n];
    let mut acc = Scalar::one();
    for (i, x) in xs.iter().enumerate() {
        prod[i] = acc;
        acc = acc.mul(x);
    }
    let allinv = acc.invert().map_err(|_| RangeError::InvalidProof)?;
    let mut inv = allinv;
    for i in (0..n).rev() {
        let tmp = inv.mul(&prod[i]);
        inv = inv.mul(&xs[i]);
        xs[i] = tmp;
    }
    Ok(allinv)
}

/// Encode a point (compressed, canonical).
fn enc(p: &RistrettoPoint) -> Result<[u8; 32], RangeError> {
    let mut out = [0u8; 32];
    p.to_bytes_compressed(&mut out)
        .map_err(|_| RangeError::Internal)?;
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
/// Prove `<a, b> = c` (Protocol 2). Vectors are consumed.
pub fn ipp_prove(
    q: &RistrettoPoint,
    g_factors: &[Scalar],
    h_factors: &[Scalar],
    g_vec: Vec<RistrettoPoint>,
    h_vec: Vec<RistrettoPoint>,
    a_vec: Vec<Scalar>,
    b_vec: Vec<Scalar>,
    transcript: &mut ZkTranscript,
) -> Result<InnerProductProof, RangeError> {
    let mut n = g_vec.len();
    if h_vec.len() != n
        || a_vec.len() != n
        || b_vec.len() != n
        || g_factors.len() != n
        || h_factors.len() != n
    {
        return Err(RangeError::VectorLengthMismatch);
    }
    if !n.is_power_of_two() || n == 0 {
        return Err(RangeError::InvalidBitSize);
    }
    transcript.inner_product_domain_separator(n as u64);
    let lg_n = n.trailing_zeros() as usize;

    // Explicit round loop (uniform for all rounds, factor-aware).
    let mut g = g_vec;
    let mut h = h_vec;
    let mut a = a_vec;
    let mut b = b_vec;
    let mut gf: Vec<Scalar> = g_factors.to_vec();
    let mut hf: Vec<Scalar> = h_factors.to_vec();
    let mut l_out: Vec<[u8; 32]> = Vec::with_capacity(lg_n);
    let mut r_out: Vec<[u8; 32]> = Vec::with_capacity(lg_n);
    while n != 1 {
        n /= 2;
        let (a_l, a_r) = a.split_at_mut(n);
        let (b_l, b_r) = b.split_at_mut(n);
        let (g_l, g_r) = g.split_at_mut(n);
        let (h_l, h_r) = h.split_at_mut(n);
        let (gf_l, gf_r) = gf.split_at_mut(n);
        let (hf_l, hf_r) = hf.split_at_mut(n);
        let c_l =
            util::inner_product(a_l, b_r).ok_or(RangeError::InnerProductLengthMismatch)?;
        let c_r =
            util::inner_product(a_r, b_l).ok_or(RangeError::InnerProductLengthMismatch)?;
        let mut l_scalars = Vec::with_capacity(2 * n + 1);
        let mut l_points = Vec::with_capacity(2 * n + 1);
        for i in 0..n {
            l_scalars.push(a_l[i].mul(&gf_r[i]));
            l_points.push(g_r[i]);
            l_scalars.push(b_r[i].mul(&hf_l[i]));
            l_points.push(h_l[i]);
        }
        l_scalars.push(c_l);
        l_points.push(*q);
        let l_pt = ms_mul(&l_scalars, &l_points);
        let mut r_scalars = Vec::with_capacity(2 * n + 1);
        let mut r_points = Vec::with_capacity(2 * n + 1);
        for i in 0..n {
            r_scalars.push(a_r[i].mul(&gf_l[i]));
            r_points.push(g_l[i]);
            r_scalars.push(b_l[i].mul(&hf_r[i]));
            r_points.push(h_r[i]);
        }
        r_scalars.push(c_r);
        r_points.push(*q);
        let r_pt = ms_mul(&r_scalars, &r_points);
        let l_enc = enc(&l_pt)?;
        let r_enc = enc(&r_pt)?;
        l_out.push(l_enc);
        r_out.push(r_enc);
        transcript.append_point(b"L", &l_enc);
        transcript.append_point(b"R", &r_enc);
        let u = transcript.challenge_scalar(b"u");
        let u_inv = u.invert().map_err(|_| RangeError::Internal)?;
        for i in 0..n {
            a_l[i] = a_l[i].mul(&u).add(&u_inv.mul(&a_r[i]));
            b_l[i] = b_l[i].mul(&u_inv).add(&u.mul(&b_r[i]));
            g_l[i] = ms_mul(
                &[u_inv.mul(&gf_l[i]), u.mul(&gf_r[i])],
                &[g_l[i], g_r[i]],
            );
            h_l[i] = ms_mul(
                &[u.mul(&hf_l[i]), u_inv.mul(&hf_r[i])],
                &[h_l[i], h_r[i]],
            );
            // NOTE: upstream folds the G/H factors into the points in the
            // first round only; subsequent rounds use unit factors. The
            // truncation + reset below mirrors exactly that.
        }
        // Truncate to the reduced (folded) problem with unit factors,
        // exactly like upstream (`a = a_L; G = G_L; ...` then loop).
        // Upstream keeps G_factors/H_factors only for the FIRST round;
        // subsequent rounds use unit factors because factors were folded
        // into G/H. Our loop folds points the same way, so reset factors.
        let mut g2 = Vec::with_capacity(n);
        let mut h2 = Vec::with_capacity(n);
        for i in 0..n {
            g2.push(g_l[i]);
            h2.push(h_l[i]);
        }
        g = g2;
        h = h2;
        let mut a2 = Vec::with_capacity(n);
        let mut b2 = Vec::with_capacity(n);
        for i in 0..n {
            a2.push(a_l[i]);
            b2.push(b_l[i]);
        }
        a = a2;
        b = b2;
        gf = vec![Scalar::one(); n];
        hf = vec![Scalar::one(); n];
    }
    Ok(InnerProductProof {
        l_vec: l_out,
        r_vec: r_out,
        a: a[0],
        b: b[0],
    })
}

/// Verification scalars (u_i^2, u_i^-2, s) for the mega-check.
// Tuple order `(u_sq, u_sq_inv, s_vec)` is fixed by the verification
// equation; naming it keeps the return type readable for clippy.
pub type VerificationScalars = (Vec<Scalar>, Vec<Scalar>, Vec<Scalar>);

pub fn verification_scalars(
    l_vec: &[[u8; 32]],
    r_vec: &[[u8; 32]],
    n: usize,
    transcript: &mut ZkTranscript,
) -> Result<VerificationScalars, RangeError> {
    let lg_n = l_vec.len();
    if lg_n != r_vec.len() || lg_n == 0 || lg_n >= 32 {
        return Err(RangeError::InvalidBitSize);
    }
    if n != (1usize << lg_n) {
        return Err(RangeError::InvalidBitSize);
    }
    transcript.inner_product_domain_separator(n as u64);
    let mut challenges = Vec::with_capacity(lg_n);
    for (l, r) in l_vec.iter().zip(r_vec.iter()) {
        transcript.validate_and_append_point(b"L", l)?;
        transcript.validate_and_append_point(b"R", r)?;
        challenges.push(transcript.challenge_scalar(b"u"));
    }
    let mut challenges_inv = challenges.clone();
    let allinv = batch_invert(&mut challenges_inv)?;
    for i in 0..lg_n {
        challenges[i] = challenges[i].mul(&challenges[i]);
        challenges_inv[i] = challenges_inv[i].mul(&challenges_inv[i]);
    }
    let mut s = Vec::with_capacity(n);
    s.push(allinv);
    for i in 1..n {
        let lg_i = (31 - (i as u32).leading_zeros()) as usize;
        let k = 1usize << lg_i;
        let u_idx = (lg_n - 1) - lg_i;
        s.push(s[i - k].mul(&challenges[u_idx]));
    }
    Ok((challenges, challenges_inv, s))
}

/// Serialized size for length-`n` vectors.
pub fn serialized_size(lg_n: usize) -> usize {
    (lg_n * 2 + 2) * 32
}

/// Serialize L/R pairs + a + b.
pub fn to_bytes(
    l_vec: &[[u8; 32]],
    r_vec: &[[u8; 32]],
    a: &Scalar,
    b: &Scalar,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(serialized_size(l_vec.len()));
    for (l, r) in l_vec.iter().zip(r_vec.iter()) {
        buf.extend_from_slice(l);
        buf.extend_from_slice(r);
    }
    let mut ab = [0u8; 32];
    a.to_bytes_le(&mut ab);
    buf.extend_from_slice(&ab);
    b.to_bytes_le(&mut ab);
    buf.extend_from_slice(&ab);
    buf
}

/// Parse an IPP blob (length/shape/canonical-scalar checks).
pub fn ipp_from_bytes(
    slice: &[u8],
) -> Result<InnerProductProof, RangeError> {
    if !slice.len().is_multiple_of(32) {
        return Err(RangeError::Deserialization);
    }
    let num = slice.len() / 32;
    if num < 2 || !(num - 2).is_multiple_of(2) {
        return Err(RangeError::Deserialization);
    }
    let lg_n = (num - 2) / 2;
    if lg_n == 0 || lg_n >= 32 {
        return Err(RangeError::Deserialization);
    }
    let mut l_vec = Vec::with_capacity(lg_n);
    let mut r_vec = Vec::with_capacity(lg_n);
    for i in 0..lg_n {
        let mut l = [0u8; 32];
        let mut r = [0u8; 32];
        l.copy_from_slice(&slice[2 * i * 32..2 * i * 32 + 32]);
        r.copy_from_slice(&slice[2 * i * 32 + 32..2 * i * 32 + 64]);
        // Points are validated on decompress at verify time (upstream).
        l_vec.push(l);
        r_vec.push(r);
    }
    let pos = 2 * lg_n * 32;
    let mut ab = [0u8; 32];
    ab.copy_from_slice(&slice[pos..pos + 32]);
    let a = Scalar::from_bytes_le(&ab).map_err(|_| RangeError::Deserialization)?;
    ab.copy_from_slice(&slice[pos + 32..pos + 64]);
    let b = Scalar::from_bytes_le(&ab).map_err(|_| RangeError::Deserialization)?;
    Ok(InnerProductProof {
        l_vec,
        r_vec,
        a,
        b,
    })
}
