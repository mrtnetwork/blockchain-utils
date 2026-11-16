//! Aggregated Bulletproof range proof (zero-dep port).
//!
//! /// Byte-compatible port of
//! `zk-sdk/src/range_proof/range.rs`: aggregated proof that committed values
//! lie in range. Transcript labels (`range-proof` dom-sep, `A`, `S`, `y`,
//! `z`, `T_1`, `T_2`, `x`, `t_x`, `t_x_blinding`, `e_blinding`, `w`, `c`,
//! `ipp_a`, `ipp_b`, `d`) and wire layout match upstream exactly.
//! Randomness from a caller-supplied 32-byte seed driving ChaCha20.

use super::generators::{RangeError, RangeProofGens, CACHED_GENERATOR_LENGTH};
use super::inner_product::{self, InnerProductProof};
use super::util;
use crate::curve::ed25519::Scalar;
use crate::curve::traits::CurvePoint;
use crate::curve::RistrettoPoint;
use crate::rng::ChaCha20Rng;
use crate::solana_zk::sigma_proofs::{is_identity_enc, ZkTranscript, CTX_BATCHED_RANGE_PROOF};

/// A range proof (header + inner-product proof).
#[derive(Clone)]
pub struct RangeProof {
    /// Commitment to bit vectors.
    pub a_commit: [u8; 32],
    /// Blinding-vector commitment.
    pub s_commit: [u8; 32],
    /// `t_1` coefficient commitment.
    pub t1_commit: [u8; 32],
    /// `t_2` coefficient commitment.
    pub t2_commit: [u8; 32],
    /// `t(x)` evaluation.
    pub t_x: Scalar,
    /// `t(x)` blinding.
    pub t_x_blinding: Scalar,
    /// Blinding for `A + x*S`.
    pub e_blinding: Scalar,
    /// Inner-product proof.
    pub ipp: InnerProductProof,
}

/// Draw a nonzero masking scalar from a seeded ChaCha20 stream.
fn masking_scalar(rng: &mut ChaCha20Rng) -> Scalar {
    loop {
        let mut b = [0u8; 32];
        rng.next_bytes(32, &mut b);
        let s = Scalar::from_bytes_mod_order(&b);
        if !s.is_zero() {
            return s;
        }
    }
}

/// Prove each `amounts[i]` fits in `bit_lengths[i]` bits.
/// `openings` are the Pedersen blinding factors. `nm` must be a power of two.
#[allow(clippy::too_many_arguments)]
pub fn prove_range(
    amounts: &[u64],
    bit_lengths: &[usize],
    openings: &[[u8; 32]],
    seed: &[u8; 32],
    context: &[u8],
) -> Result<Vec<u8>, RangeError> {
    let mut transcript = ZkTranscript::new(context);
    prove_range_inner(amounts, bit_lengths, openings, seed, &mut transcript)
}

/// Core aggregated prove on an open transcript (caller hashes
/// instruction context first; this appends the `range-proof` dom-sep).
#[allow(clippy::too_many_arguments)]
pub fn prove_range_inner(
    amounts: &[u64],
    bit_lengths: &[usize],
    openings: &[[u8; 32]],
    seed: &[u8; 32],
    transcript: &mut ZkTranscript,
) -> Result<Vec<u8>, RangeError> {
    let m = amounts.len();
    if bit_lengths.len() != m || openings.len() != m {
        return Err(RangeError::VectorLengthMismatch);
    }
    for n in bit_lengths {
        if *n == 0 || *n > 64 {
            return Err(RangeError::InvalidBitSize);
        }
    }
    let nm: usize = bit_lengths.iter().sum();
    if !nm.is_power_of_two() || nm == 0 {
        return Err(RangeError::VectorLengthMismatch);
    }
    let gens = RangeProofGens::new(nm.max(CACHED_GENERATOR_LENGTH))?;
    let mut rng = ChaCha20Rng::from_seed(seed);
    transcript.range_proof_domain_separator(nm as u64);

    // A: commitment to bit vectors.
    let mut a_blinding = masking_scalar(&mut rng);
    let mut a_pt = crate::solana_zk::h_point()?;
    a_pt = a_pt.mul(&a_blinding);
    let mut i = 0usize;
    for (amount, n) in amounts.iter().zip(bit_lengths.iter()) {
        for j in 0..*n {
            let bit = ((amount >> (j as u32)) & 1) as u8;
            let g_ij = gens.g_vec[i];
            let h_ij = gens.h_vec[i];
            // A += bit ? G_ij : -H_ij  (a_R = a_L - 1)
            if bit == 1 {
                a_pt = a_pt.add(&g_ij);
            } else {
                a_pt = a_pt.add(&h_ij.neg());
            }
            i += 1;
        }
    }
    let mut a_enc = [0u8; 32];
    a_pt.to_bytes_compressed(&mut a_enc)
        .map_err(|_| RangeError::Internal)?;

    // S: blinding-vector commitment.
    let mut s_l = Vec::with_capacity(nm);
    let mut s_r = Vec::with_capacity(nm);
    for _ in 0..nm {
        s_l.push(masking_scalar(&mut rng));
        s_r.push(masking_scalar(&mut rng));
    }
    let s_blinding = masking_scalar(&mut rng);
    let h_base = crate::solana_zk::h_point()?;
    let mut s_pt = h_base.mul(&s_blinding);
    for k in 0..nm {
        s_pt = s_pt.add(&gens.g_vec[k].mul(&s_l[k]));
        s_pt = s_pt.add(&gens.h_vec[k].mul(&s_r[k]));
    }
    let mut s_enc = [0u8; 32];
    s_pt.to_bytes_compressed(&mut s_enc)
        .map_err(|_| RangeError::Internal)?;

    transcript.append_point(b"A", &a_enc);
    transcript.append_point(b"S", &s_enc);
    let y = transcript.challenge_scalar(b"y");
    let z = transcript.challenge_scalar(b"z");

    // l(x), r(x) vector polynomials.
    let mut l0 = Vec::with_capacity(nm);
    let mut l1 = Vec::with_capacity(nm);
    let mut r0 = Vec::with_capacity(nm);
    let mut r1 = Vec::with_capacity(nm);
    let mut exp_y = Scalar::one();
    let mut exp_z = z.mul(&z);
    i = 0;
    for (amount, n) in amounts.iter().zip(bit_lengths.iter()) {
        let mut exp_2 = Scalar::one();
        for j in 0..*n {
            let bit = (amount >> (j as u32)) & 1;
            let a_l = util::scalar_u64(bit);
            let a_r = util::scalar_u64(bit).add(&Scalar::one().neg());
            l0.push(a_l.add(&z.neg()));
            l1.push(s_l[i]);
            r0.push(exp_y.mul(&a_r.add(&z)).add(&exp_z.mul(&exp_2)));
            r1.push(exp_y.mul(&s_r[i]));
            exp_y = exp_y.mul(&y);
            exp_2 = exp_2.add(&exp_2);
            i += 1;
        }
        exp_z = exp_z.mul(&z);
    }
    let l_poly = util::VecPoly1(l0, l1);
    let r_poly = util::VecPoly1(r0, r1);
    let t_poly = l_poly
        .inner_product(&r_poly)
        .ok_or(RangeError::InnerProductLengthMismatch)?;

    // T_1, T_2 commitments.
    let t1_blinding = masking_scalar(&mut rng);
    let t2_blinding = masking_scalar(&mut rng);
    let t1_pt = pedersen_commit_poly(&t_poly.1, &t1_blinding)?;
    let t2_pt = pedersen_commit_poly(&t_poly.2, &t2_blinding)?;
    let mut t1_enc = [0u8; 32];
    let mut t2_enc = [0u8; 32];
    t1_pt
        .to_bytes_compressed(&mut t1_enc)
        .map_err(|_| RangeError::Internal)?;
    t2_pt
        .to_bytes_compressed(&mut t2_enc)
        .map_err(|_| RangeError::Internal)?;
    transcript.append_point(b"T_1", &t1_enc);
    transcript.append_point(b"T_2", &t2_enc);
    let x = transcript.challenge_scalar(b"x");

    // Openings aggregation.
    let mut agg = Scalar::zero();
    let mut ez = z;
    for o in openings {
        ez = ez.mul(&z);
        let r = Scalar::from_bytes_le(o).map_err(|_| RangeError::InvalidScalar)?;
        agg = agg.add(&ez.mul(&r));
    }
    let t_blinding = util::Poly2(agg, t1_blinding, t2_blinding);
    let t_x = t_poly.eval(&x);
    let t_x_blinding = t_blinding.eval(&x);
    let mut txe = [0u8; 32];
    let mut txbe = [0u8; 32];
    t_x.to_bytes_le(&mut txe);
    t_x_blinding.to_bytes_le(&mut txbe);
    transcript.append_scalar(b"t_x", &txe);
    transcript.append_scalar(b"t_x_blinding", &txbe);
    let e_blinding = a_blinding.add(&x.mul(&s_blinding));
    let mut ebe = [0u8; 32];
    e_blinding.to_bytes_le(&mut ebe);
    transcript.append_scalar(b"e_blinding", &ebe);

    let l_vec = l_poly.eval(&x);
    let r_vec = r_poly.eval(&x);
    let w = transcript.challenge_scalar(b"w");
    let g_base = RistrettoPoint::generator();
    let q_pt = g_base.mul(&w);
    let g_factors = vec![Scalar::one(); nm];
    let mut h_factors = Vec::with_capacity(nm);
    let mut ey = Scalar::one();
    let y_inv = y.invert().map_err(|_| RangeError::Internal)?;
    for _ in 0..nm {
        h_factors.push(ey);
        ey = ey.mul(&y_inv);
    }
    let _c = transcript.challenge_scalar(b"c");
    let ipp = inner_product::ipp_prove(
        &q_pt,
        &g_factors,
        &h_factors,
        gens.g_vec[..nm].to_vec(),
        gens.h_vec[..nm].to_vec(),
        l_vec,
        r_vec,
        transcript,
    )?;
    let mut ippe_a = [0u8; 32];
    let mut ippe_b = [0u8; 32];
    ipp.a.to_bytes_le(&mut ippe_a);
    ipp.b.to_bytes_le(&mut ippe_b);
    transcript.append_scalar(b"ipp_a", &ippe_a);
    transcript.append_scalar(b"ipp_b", &ippe_b);
    let _d = transcript.challenge_scalar(b"d");

    a_blinding.zeroize();
    // NOTE: secret scalars (openings, blindings) are short-lived stack values;
    // explicit zeroization is omitted in this port (upstream uses zeroize).

    // Serialize: A S T1 T2 t_x t_x_blinding e_blinding || ipp.
    let mut out = Vec::with_capacity(7 * 32 + ipp.l_vec.len() * 64 + 64);
    out.extend_from_slice(&a_enc);
    out.extend_from_slice(&s_enc);
    out.extend_from_slice(&t1_enc);
    out.extend_from_slice(&t2_enc);
    out.extend_from_slice(&txe);
    out.extend_from_slice(&txbe);
    out.extend_from_slice(&ebe);
    out.extend_from_slice(&inner_product::to_bytes(&ipp.l_vec, &ipp.r_vec, &ipp.a, &ipp.b));
    Ok(out)
}

/// Pedersen commit a scalar coefficient: `t*G + r*H`.
fn pedersen_commit_poly(
    t: &Scalar,
    r: &Scalar,
) -> Result<RistrettoPoint, RangeError> {
    let g = RistrettoPoint::generator();
    let h = crate::solana_zk::h_point()?;
    Ok(g.mul(t).add(&h.mul(r)))
}

/// Verify an aggregated range proof against commitments.
pub fn verify_range(
    proof_bytes: &[u8],
    commitments: &[[u8; 32]],
    bit_lengths: &[usize],
    context: &[u8],
) -> Result<(), RangeError> {
    let mut transcript = ZkTranscript::new(context);
    verify_range_inner(proof_bytes, commitments, bit_lengths, &mut transcript)
}

/// Core aggregated verify on an open transcript.
pub fn verify_range_inner(
    proof_bytes: &[u8],
    commitments: &[[u8; 32]],
    bit_lengths: &[usize],
    transcript: &mut ZkTranscript,
) -> Result<(), RangeError> {
    let m = commitments.len();
    if bit_lengths.len() != m {
        return Err(RangeError::VectorLengthMismatch);
    }
    let nm: usize = bit_lengths.iter().sum();
    if !nm.is_power_of_two() || nm == 0 {
        return Err(RangeError::InvalidBitSize);
    }
    if proof_bytes.len() < 7 * 32 || !(proof_bytes.len() - 7 * 32).is_multiple_of(32) {
        return Err(RangeError::Deserialization);
    }
    let mut a_enc = [0u8; 32];
    let mut s_enc = [0u8; 32];
    let mut t1_enc = [0u8; 32];
    let mut t2_enc = [0u8; 32];
    a_enc.copy_from_slice(&proof_bytes[..32]);
    s_enc.copy_from_slice(&proof_bytes[32..64]);
    t1_enc.copy_from_slice(&proof_bytes[64..96]);
    t2_enc.copy_from_slice(&proof_bytes[96..128]);
    let mut txe = [0u8; 32];
    let mut txbe = [0u8; 32];
    let mut ebe = [0u8; 32];
    txe.copy_from_slice(&proof_bytes[128..160]);
    txbe.copy_from_slice(&proof_bytes[160..192]);
    ebe.copy_from_slice(&proof_bytes[192..224]);
    let t_x = Scalar::from_bytes_le(&txe).map_err(|_| RangeError::Deserialization)?;
    let t_x_blinding =
        Scalar::from_bytes_le(&txbe).map_err(|_| RangeError::Deserialization)?;
    let e_blinding =
        Scalar::from_bytes_le(&ebe).map_err(|_| RangeError::Deserialization)?;
    let ipp = inner_product::ipp_from_bytes(&proof_bytes[7 * 32..])?;
    let lg_n = ipp.l_vec.len();
    if lg_n * 2 + 2 != (proof_bytes.len() / 32) - 7 {
        return Err(RangeError::Deserialization);
    }
    if (1usize << lg_n) != nm {
        return Err(RangeError::InvalidBitSize);
    }

    // Reject identity commitments (explicit upstream rule).
    let mut comm_pts = Vec::with_capacity(m);
    for c in commitments {
        let p = RistrettoPoint::from_bytes(c).map_err(|_| RangeError::Deserialization)?;
        if is_identity_enc(&p) {
            return Err(RangeError::AlgebraicRelation);
        }
        comm_pts.push(p);
    }

    let gens = RangeProofGens::new(nm.max(CACHED_GENERATOR_LENGTH))?;
    transcript.range_proof_domain_separator(nm as u64);
    transcript.validate_and_append_point(b"A", &a_enc)?;
    transcript.validate_and_append_point(b"S", &s_enc)?;
    let y = transcript.challenge_scalar(b"y");
    let z = transcript.challenge_scalar(b"z");
    let zz = z.mul(&z);
    transcript.validate_and_append_point(b"T_1", &t1_enc)?;
    transcript.validate_and_append_point(b"T_2", &t2_enc)?;
    let x = transcript.challenge_scalar(b"x");
    transcript.append_scalar(b"t_x", &txe);
    transcript.append_scalar(b"t_x_blinding", &txbe);
    transcript.append_scalar(b"e_blinding", &ebe);
    let w = transcript.challenge_scalar(b"w");
    let _c = transcript.challenge_scalar(b"c");

    let (u_sq, u_inv_sq, s_vec) =
        inner_product::verification_scalars(&ipp.l_vec, &ipp.r_vec, nm, transcript)?;
    let s_inv: Vec<Scalar> = s_vec.iter().rev().cloned().collect();
    let a = ipp.a;
    let b = ipp.b;
    transcript.append_scalar(b"ipp_a", &{
        let mut o = [0u8; 32];
        a.to_bytes_le(&mut o);
        o
    });
    transcript.append_scalar(b"ipp_b", &{
        let mut o = [0u8; 32];
        b.to_bytes_le(&mut o);
        o
    });
    let d = transcript.challenge_scalar(b"d");

    // concat_z_and_2 = z^0*2^n_0 || z^1*2^n_1 || ...
    let mut concat_z_and_2 = Vec::with_capacity(nm);
    let mut exp_z = Scalar::one();
    for n_i in bit_lengths {
        let mut exp_2 = Scalar::one();
        let two = util::scalar_u64(2);
        for _ in 0..*n_i {
            concat_z_and_2.push(exp_z.mul(&exp_2));
            exp_2 = exp_2.mul(&two);
        }
        exp_z = exp_z.mul(&z);
    }
    // gs[i] = -z - a*s[i]; hs[i] = z + y^-i * (zz*z_and_2[i] - b/s[i]).
    let y_inv = y.invert().map_err(|_| RangeError::Internal)?;
    let mut y_inv_pows = Vec::with_capacity(nm);
    let mut ey = Scalar::one();
    for _ in 0..nm {
        y_inv_pows.push(ey);
        ey = ey.mul(&y_inv);
    }
    let g_base = RistrettoPoint::generator();
    let h_base = crate::solana_zk::h_point()?;
    let mut mega_scalars: Vec<Scalar> = Vec::new();
    let mut mega_points: Vec<RistrettoPoint> = Vec::new();
    // A, S, T_1, T_2 with scalars 1, x, d*x, d*x^2.
    let a_pt = RistrettoPoint::from_bytes(&a_enc).map_err(|_| RangeError::Deserialization)?;
    let s_pt = RistrettoPoint::from_bytes(&s_enc).map_err(|_| RangeError::Deserialization)?;
    let t1_pt = RistrettoPoint::from_bytes(&t1_enc).map_err(|_| RangeError::Deserialization)?;
    let t2_pt = RistrettoPoint::from_bytes(&t2_enc).map_err(|_| RangeError::Deserialization)?;
    let xx = x.mul(&x);
    mega_scalars.push(Scalar::one());
    mega_points.push(a_pt);
    mega_scalars.push(x);
    mega_points.push(s_pt);
    mega_scalars.push(d.mul(&x));
    mega_points.push(t1_pt);
    mega_scalars.push(d.mul(&xx));
    mega_points.push(t2_pt);
    // -e_blinding - d*t_x_blinding at H.
    mega_scalars.push(e_blinding.neg().add(&d.mul(&t_x_blinding).neg()));
    mega_points.push(h_base);
    // basepoint term: w*(t_x - a*b) + d*(delta - t_x).
    let delta = range_delta(bit_lengths, &y, &z);
    let base = w.mul(&t_x.add(&a.mul(&b).neg())).add(&d.mul(&delta.add(&t_x.neg())));
    mega_scalars.push(base);
    mega_points.push(g_base);
    // L/R terms (positive u^2 / u^-2 — matches upstream mega-check exactly).
    for (u2, l_enc) in u_sq.iter().zip(ipp.l_vec.iter()) {
        mega_scalars.push(*u2);
        mega_points.push(RistrettoPoint::from_bytes(l_enc).map_err(|_| RangeError::Deserialization)?);
    }
    for (u2, r_enc) in u_inv_sq.iter().zip(ipp.r_vec.iter()) {
        mega_scalars.push(*u2);
        mega_points.push(RistrettoPoint::from_bytes(r_enc).map_err(|_| RangeError::Deserialization)?);
    }
    // G/H terms.
    for i in 0..nm {
        let gs = z.neg().add(&a.mul(&s_vec[i]).neg());
        mega_scalars.push(gs);
        mega_points.push(gens.g_vec[i]);
        let hs = z.add(
            &y_inv_pows[i].mul(&zz.mul(&concat_z_and_2[i]).add(&b.mul(&s_inv[i]).neg())),
        );
        mega_scalars.push(hs);
        mega_points.push(gens.h_vec[i]);
    }
    // Value commitments: d*zz*z^j at each V_j.
    let mut z_pow = Scalar::one();
    for v in comm_pts.iter() {
        mega_scalars.push(d.mul(&zz).mul(&z_pow));
        mega_points.push(*v);
        z_pow = z_pow.mul(&z);
    }
    // Q (= w*G) needs no separate term: it is absorbed into the basepoint
    // term, exactly like upstream (Q's coefficient side is carried by the
    // value terms through the basepoint scalar).
    let check = inner_product::ms_mul(&mega_scalars, &mega_points);
    if is_identity_enc(&check) {
        Ok(())
    } else {
        Err(RangeError::AlgebraicRelation)
    }
}

/// delta(y, z) aggregation term for the mega-check.
fn range_delta(bit_lengths: &[usize], y: &Scalar, z: &Scalar) -> Scalar {
    let nm: usize = bit_lengths.iter().sum();
    let sum_y = util::sum_of_powers(y, nm);
    let mut agg = z.add(&z.mul(z).neg()).mul(&sum_y);
    let mut exp_z = z.mul(z).mul(z);
    for n_i in bit_lengths {
        let sum_2 = util::sum_of_powers(&util::scalar_u64(2), *n_i);
        agg = agg.add(&exp_z.mul(&sum_2).neg());
        exp_z = exp_z.mul(z);
    }
    agg
}


/// Maximum commitments per batched range instruction (matches
/// the on-chain `BatchedRangeProofContext`: 8 padded commitment slots).
pub const MAX_RANGE_COMMITMENTS: usize = 8;

/// Pedersen commitment `m*G + r*H` (instruction-context helper).
fn pedersen_commit_point(m: u64, r: &Scalar) -> Result<RistrettoPoint, RangeError> {
    let g = RistrettoPoint::generator();
    let h = crate::solana_zk::h_point()?;
    Ok(g.mul(&util::scalar_u64(m)).add(&h.mul(r)))
}

/// Prove with the exact on-chain instruction transcript:
///
/// Range instruction proof: `(proof_bytes, padded_commitments, padded_bit_lengths)`.
pub type RangeInstructionProof = (Vec<u8>, [u8; 256], [u8; 8]);

/// base `batched-range-proof-instruction` + 256-byte padded commitments +
/// 8-byte padded bit-lengths, then the standard aggregated prove flow.
/// `bit_lengths` entries must be in `1..=64`; `nm` (their sum) must be a
/// power of two. Rejects identity commitments (they encode unused slots).
pub fn prove_range_instruction(
    amounts: &[u64],
    bit_lengths: &[usize],
    openings: &[[u8; 32]],
    seed: &[u8; 32],
) -> Result<RangeInstructionProof, RangeError> {
    let m = amounts.len();
    if bit_lengths.len() != m || openings.len() != m
        || m == 0 || m > MAX_RANGE_COMMITMENTS
    {
        return Err(RangeError::VectorLengthMismatch);
    }
    for n in bit_lengths {
        if *n == 0 || *n > 64 {
            return Err(RangeError::InvalidBitSize);
        }
    }
    // Pedersen commitments (identity rejected: it marks unused slots).
    let mut comm_pts = Vec::with_capacity(m);
    for (a, o) in amounts.iter().zip(openings.iter()) {
        let r = Scalar::from_bytes_le(o).map_err(|_| RangeError::InvalidScalar)?;
        let p = pedersen_commit_point(*a, &r)?;
        if is_identity_enc(&p) {
            return Err(RangeError::IdentityCommitment);
        }
        comm_pts.push(p);
    }
    // Pod context: zero-padded commitments + bit lengths.
    let mut pod_commitments = [0u8; 256];
    let mut pod_bit_lengths = [0u8; 8];
    for (i, p) in comm_pts.iter().enumerate() {
        let mut enc = [0u8; 32];
        p.to_bytes_compressed(&mut enc).map_err(|_| RangeError::Internal)?;
        pod_commitments[i * 32..i * 32 + 32].copy_from_slice(&enc);
        pod_bit_lengths[i] = bit_lengths[i] as u8;
    }
    let mut transcript = ZkTranscript::new(CTX_BATCHED_RANGE_PROOF);
    transcript.append_message(b"commitments", &pod_commitments);
    transcript.append_message(b"bit-lengths", &pod_bit_lengths);
    let proof = prove_range_inner(amounts, bit_lengths, openings, seed, &mut transcript)?;
    Ok((proof, pod_commitments, pod_bit_lengths))
}

/// Verify against the on-chain instruction transcript. Active
/// slots are the nonzero 32-byte commitment encodings (1..=8 required).
pub fn verify_range_instruction(
    proof_bytes: &[u8],
    pod_commitments: &[u8; 256],
    pod_bit_lengths: &[u8; 8],
) -> Result<(), RangeError> {
    let mut commitments = Vec::new();
    let mut bit_lengths = Vec::new();
    for i in 0..MAX_RANGE_COMMITMENTS {
        let mut slot = [0u8; 32];
        slot.copy_from_slice(&pod_commitments[i * 32..i * 32 + 32]);
        if slot == [0u8; 32] {
            continue;
        }
        let n = pod_bit_lengths[i] as usize;
        if n == 0 || n > 64 {
            return Err(RangeError::InvalidBitSize);
        }
        commitments.push(slot);
        bit_lengths.push(n);
    }
    if commitments.is_empty() {
        return Err(RangeError::VectorLengthMismatch);
    }
    let mut transcript = ZkTranscript::new(CTX_BATCHED_RANGE_PROOF);
    transcript.append_message(b"commitments", pod_commitments);
    transcript.append_message(b"bit-lengths", pod_bit_lengths);
    verify_range_inner(proof_bytes, &commitments, &bit_lengths, &mut transcript)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Single 64-bit roundtrip.
    #[test]
    fn roundtrip_single_u64() {
        let opening = [3u8; 32];
        let comm = pedersen_commit_test(55, &opening);
        let proof = prove_range(&[55], &[64], &[opening], &[9u8; 32], b"Test").unwrap();
        assert_eq!(proof.len(), 7 * 32 + (2 * 6 + 2) * 32);
        verify_range(&proof, &[comm], &[64], b"Test").unwrap();
        let mut bad = proof.clone();
        bad[300] ^= 1;
        assert!(verify_range(&bad, &[comm], &[64], b"Test").is_err());
    }

    /// Aggregated [64, 32, 32] roundtrip.
    #[test]
    fn roundtrip_aggregated() {
        let o1 = [3u8; 32];
        let o2 = [4u8; 32];
        let o3 = [5u8; 32];
        let c1 = pedersen_commit_test(55, &o1);
        let c2 = pedersen_commit_test(77, &o2);
        let c3 = pedersen_commit_test(99, &o3);
        let proof = prove_range(
            &[55, 77, 99],
            &[64, 32, 32],
            &[o1, o2, o3],
            &[9u8; 32],
            b"Test",
        )
        .unwrap();
        assert_eq!(proof.len(), 7 * 32 + (2 * 7 + 2) * 32);
        verify_range(&proof, &[c1, c2, c3], &[64, 32, 32], b"Test").unwrap();
    }

    /// Upstream golden vector (U128 [64, 32, 32]).
    #[test]
    fn golden_vector_verifies() {
        let c1: [u8; 32] = [
            170, 217, 24, 79, 243, 186, 109, 34, 125, 203, 185, 173, 171, 24, 217,
            237, 211, 170, 150, 130, 112, 44, 100, 220, 77, 167, 134, 251, 145, 165,
            5, 106,
        ];
        let c2: [u8; 32] = [
            164, 39, 71, 96, 84, 141, 239, 35, 4, 43, 210, 226, 211, 83, 53,
            195, 83, 158, 71, 54, 218, 86, 4, 60, 197, 129, 229, 196, 244, 212,
            180, 93,
        ];
        let c3: [u8; 32] = [
            130, 171, 55, 128, 14, 130, 169, 61, 212, 190, 150, 246, 120, 37, 191,
            150, 142, 166, 252, 13, 145, 196, 116, 146, 162, 147, 155, 66, 75, 247,
            12, 37,
        ];
        let proof: [u8; 736] = [
            148, 176, 233, 122, 143, 123, 108, 117, 60, 3, 126, 43, 185, 127, 240,
            41, 70, 56, 72, 152, 2, 40, 182, 95, 236, 120, 129, 203, 164, 243,
            229, 31, 4, 25, 210, 208, 186, 169, 94, 58, 97, 150, 90, 223, 173,
            88, 239, 87, 50, 172, 48, 214, 240, 77, 13, 32, 3, 21, 51, 14,
            52, 181, 172, 52, 186, 236, 2, 178, 209, 216, 2, 241, 166, 165, 18,
            163, 242, 176, 244, 177, 183, 128, 127, 152, 2, 148, 153, 146, 197, 171,
            98, 233, 59, 68, 109, 74, 208, 155, 85, 158, 222, 163, 246, 22, 18,
            160, 184, 174, 138, 121, 8, 155, 120, 150, 79, 39, 235, 85, 154, 40,
            137, 125, 69, 50, 132, 64, 156, 62, 82, 200, 246, 13, 39, 21, 120,
            123, 131, 206, 111, 165, 169, 38, 249, 32, 93, 86, 110, 53, 64, 185,
            12, 93, 18, 43, 108, 149, 138, 17, 166, 6, 237, 57, 126, 145, 188,
            120, 120, 76, 113, 233, 18, 61, 71, 200, 86, 51, 95, 73, 2, 38,
            39, 79, 88, 189, 85, 32, 84, 155, 198, 1, 192, 10, 4, 134, 193,
            252, 189, 155, 57, 245, 28, 153, 23, 43, 186, 127, 197, 241, 195, 167,
            87, 147, 46, 72, 157, 8, 205, 135, 37, 245, 41, 4, 62, 1, 10,
            136, 46, 106, 191, 138, 30, 167, 103, 214, 131, 128, 161, 209, 21, 12,
            246, 229, 129, 196, 143, 133, 93, 179, 63, 197, 235, 29, 189, 60, 223,
            11, 118, 200, 134, 123, 111, 194, 207, 31, 228, 19, 141, 234, 25, 191,
            234, 183, 150, 71, 254, 201, 251, 63, 188, 173, 35, 52, 165, 186, 69,
            13, 169, 90, 88, 181, 216, 196, 206, 238, 74, 110, 44, 31, 59, 217,
            181, 79, 153, 235, 247, 131, 190, 153, 141, 39, 37, 66, 124, 86, 228,
            112, 68, 208, 177, 15, 206, 51, 54, 175, 12, 6, 225, 165, 187, 47,
            112, 227, 199, 34, 4, 226, 122, 195, 173, 128, 49, 65, 97, 102, 171,
            37, 42, 214, 74, 103, 36, 113, 170, 144, 213, 177, 31, 181, 164, 164,
            7, 226, 155, 179, 172, 239, 125, 205, 15, 151, 66, 223, 59, 46, 115,
            183, 118, 183, 54, 168, 116, 107, 144, 112, 128, 81, 30, 174, 137, 65,
            130, 239, 217, 95, 155, 41, 182, 52, 231, 187, 106, 108, 190, 0, 79,
            15, 51, 172, 81, 139, 81, 42, 22, 53, 177, 115, 242, 131, 107, 125,
            42, 17, 85, 39, 244, 98, 195, 95, 128, 150, 116, 46, 0, 189, 6,
            37, 128, 133, 61, 69, 82, 144, 149, 246, 117, 21, 115, 29, 14, 53,
            145, 219, 98, 234, 147, 44, 78, 31, 226, 124, 18, 203, 149, 39, 249,
            1, 137, 61, 142, 38, 30, 30, 77, 71, 10, 137, 1, 33, 55, 48,
            92, 189, 250, 156, 141, 193, 212, 116, 37, 234, 13, 255, 158, 204, 127,
            252, 151, 123, 195, 94, 225, 38, 235, 136, 98, 67, 161, 54, 236, 251,
            137, 59, 98, 178, 249, 194, 53, 151, 98, 14, 65, 92, 78, 76, 188,
            201, 175, 40, 36, 19, 53, 144, 154, 221, 106, 71, 94, 177, 43, 86,
            77, 124, 201, 58, 242, 159, 179, 152, 212, 174, 94, 114, 86, 75, 42,
            248, 79, 227, 51, 250, 20, 211, 215, 24, 74, 135, 172, 81, 3, 49,
            2, 1, 234, 38, 105, 47, 138, 148, 101, 199, 189, 126, 253, 136, 11,
            215, 126, 61, 91, 140, 9, 222, 131, 221, 234, 73, 24, 199, 70, 21,
            192, 65, 227, 170, 38, 83, 190, 114, 68, 87, 37, 47, 67, 23, 58,
            95, 71, 93, 82, 147, 65, 174, 55, 209, 196, 162, 121, 57, 95, 154,
            196, 230, 179, 239, 164, 182, 216, 250, 36, 38, 30, 139, 53, 188, 26,
            236, 69, 21, 19, 5, 86, 208, 18, 0, 7, 43, 77, 245, 243, 158,
            239, 47, 182, 195, 143, 164, 239, 116, 60, 46, 225, 68, 229, 2, 26,
            169, 197, 151, 255, 210, 17, 29, 236, 185, 192, 70, 202, 180, 94, 0,
            68, 62, 169, 162, 223, 118, 158, 165, 217, 47, 21, 15, 215, 8, 111,
            172, 198, 13, 149, 177, 94, 96, 177, 129, 95, 164, 250, 39, 159, 187,
            143, 119, 55, 124, 120, 2, 100, 8, 76, 89, 37, 62, 48, 219, 134,
            5,
        ];
        verify_range(&proof, &[c1, c2, c3], &[64, 32, 32], b"Test").unwrap();
    }

    /// Test-only Pedersen commitment helper.
    fn pedersen_commit_test(m: u64, r: &[u8; 32]) -> [u8; 32] {
        let g = RistrettoPoint::generator();
        let h = crate::solana_zk::h_point().unwrap();
        let rs = crate::curve::ed25519::Scalar::from_bytes_le(r).unwrap();
        let mut out = [0u8; 32];
        g.mul(&util::scalar_u64(m))
            .add(&h.mul(&rs))
            .to_bytes_compressed(&mut out)
            .unwrap();
        out
    }
}
