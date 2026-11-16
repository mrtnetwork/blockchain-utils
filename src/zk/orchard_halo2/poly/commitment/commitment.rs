//! Implements poly/commitment/commitment logic (IPA `PolyCommitment`).
//! Randomness comes from an explicit `FieldRng` (no globals). `assert!` on
//! vector lengths become `Halo2Result`. Points cross the transcript in
//! compressed 32-byte LE form.

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

use crate::zk::orchard_halo2::curve::{VestaAffine, VestaProjective, VestaScalar};
use crate::zk::orchard_halo2::error::{Halo2Error, Halo2Result};
use crate::zk::orchard_halo2::field::PallasFp;
use crate::zk::orchard_halo2::poly::commitment::msm::Msm;
use crate::zk::orchard_halo2::poly::params::PolyParams;
use crate::zk::orchard_halo2::poly::poly::{Basis, Polynomial};
use crate::zk::orchard_halo2::rng::BlindRng;
use crate::zk::orchard_halo2::transcript::transcript::{TranscriptReader, TranscriptWriter};
use crate::zk::orchard_halo2::utility::utils::{
    batch_invert, compute_inner_product, eval_polynomial,
};

pub struct PolyCommitment;

impl PolyCommitment {
    pub fn create_proof(
        params: &PolyParams,
        transcript: &mut TranscriptWriter,
        p_poly: &Polynomial<PallasFp>,
        p_blind: PallasFp,
        x3: PallasFp,
        rng: &mut dyn BlindRng,
    ) -> Halo2Result<()> {
        if p_poly.values.len() != params.n {
            return Err(Halo2Error::operation_failed(
                "ipa::create",
                "poly length mismatch",
            ));
        }
        // Random s(X) with root at x3: s[0] -= s(x3).
        let mut s_vals: Vec<PallasFp> = Vec::with_capacity(params.n);
        for _ in 0..params.n {
            s_vals.push(rng.next_pallas());
        }
        let s_at_x3 = eval_polynomial(&s_vals, x3);
        s_vals[0] = s_vals[0].sub_vartime(&s_at_x3);
        let s_poly = Polynomial::new(s_vals, Basis::Coeff);
        let s_blind = rng.next_pallas();

        let s_commit = params.commit(&s_poly, s_blind)?;
        transcript.write_point(&s_commit.to_compressed()?)?;

        let xi = transcript.squeeze_challenge()?;
        let z = transcript.squeeze_challenge()?;

        // P' = P + xi * S, then force P'(x3) = 0 via constant shift.
        let mut p_prime_vals: Vec<PallasFp> = Vec::with_capacity(params.n);
        for (p, s) in p_poly.values.iter().zip(s_poly.values.iter()) {
            p_prime_vals.push(p.add_vartime(&s.mul_vartime(&xi)));
        }
        let v = eval_polynomial(&p_prime_vals, x3);
        p_prime_vals[0] = p_prime_vals[0].sub_vartime(&v);
        let mut p_prime = p_prime_vals;
        let p_prime_blind = s_blind.mul_vartime(&xi).add_vartime(&p_blind);

        // b = [1, x3, x3², ...].
        let mut b_vals: Vec<PallasFp> = Vec::with_capacity(params.n);
        {
            let mut cur = PallasFp::one();
            for _ in 0..params.n {
                b_vals.push(cur);
                cur = cur.mul_vartime(&x3);
            }
        }
        let mut g_prime: Vec<VestaAffine> = params.g.clone();
        let mut f = p_prime_blind;

        for _ in 0..params.k {
            let expected = p_prime.len();
            if b_vals.len() != expected || g_prime.len() != expected || !expected.is_multiple_of(2) {
                return Err(Halo2Error::operation_failed(
                    "ipa::create",
                    "length mismatch",
                ));
            }
            let half = expected / 2;
            let l_j = ipa_commit(&p_prime[half..], &g_prime[..half], params)?;
            let r_j = ipa_commit(&p_prime[..half], &g_prime[half..], params)?;
            let value_lj = compute_inner_product(&p_prime[half..], &b_vals[..half])?;
            let value_rj = compute_inner_product(&p_prime[..half], &b_vals[half..])?;
            let lj_rand = rng.next_pallas();
            let rj_rand = rng.next_pallas();
            let lj_final = l_j.add_vartime(&ipa_commit(
                &[value_lj.mul_vartime(&z), lj_rand],
                &[params.u, params.w],
                params,
            )?);
            let rj_final = r_j.add_vartime(&ipa_commit(
                &[value_rj.mul_vartime(&z), rj_rand],
                &[params.u, params.w],
                params,
            )?);
            transcript.write_point(&lj_final.to_compressed()?)?;
            transcript.write_point(&rj_final.to_compressed()?)?;

            let uj = transcript.squeeze_challenge()?;
            let uj_inv = uj.invert()?;
            for i in 0..half {
                p_prime[i] = p_prime[i].add_vartime(&p_prime[i + half].mul_vartime(&uj_inv));
                b_vals[i] = b_vals[i].add_vartime(&b_vals[i + half].mul_vartime(&uj));
            }
            p_prime.truncate(half);
            b_vals.truncate(half);
            generator_collapse(&mut g_prime, &uj)?;
            g_prime.truncate(half);

            f = f
                .add_vartime(&lj_rand.mul_vartime(&uj_inv))
                .add_vartime(&rj_rand.mul_vartime(&uj));
        }
        if p_prime.len() != 1 {
            return Err(Halo2Error::operation_failed(
                "ipa::create",
                "final length mismatch",
            ));
        }
        let c = p_prime[0];
        transcript.write_scalar_le(&c.to_le_bytes())?;
        transcript.write_scalar_le(&f.to_le_bytes())?;
        Ok(())
    }

    pub fn verify_proof<'a>(
        params: &PolyParams,
        mut msm: Msm<'a>,
        transcript: &mut TranscriptReader<'_>,
        x: PallasFp,
        v: PallasFp,
    ) -> Halo2Result<(Msm<'a>, PolyGuard)> {
        let k = params.k as usize;
        msm.add_constant_term(v.neg())?;
        let s_commit = transcript.read_point()?;
        let s_aff = VestaAffine::from_compressed(&s_commit)?;
        let xi = transcript.squeeze_challenge()?;
        msm.append_term(xi, &s_aff)?;
        let z = transcript.squeeze_challenge()?;
        let _ = z;

        let mut rounds: Vec<(VestaAffine, VestaAffine, PallasFp)> = Vec::with_capacity(k);
        for _ in 0..k {
            let l = VestaAffine::from_compressed(&transcript.read_point()?)?;
            let r = VestaAffine::from_compressed(&transcript.read_point()?)?;
            let u = transcript.squeeze_challenge()?;
            rounds.push((l, r, u));
        }
        let mut inverses: Vec<PallasFp> = rounds.iter().map(|r| r.2).collect();
        batch_invert(&mut inverses)?;
        let mut u_list: Vec<PallasFp> = Vec::with_capacity(k);
        for (i, (l, r, uj)) in rounds.iter().enumerate() {
            let uj_inv = inverses[i];
            msm.append_term(uj_inv, l)?;
            msm.append_term(*uj, r)?;
            u_list.push(*uj);
        }
        let c = PallasFp::from_le_array(&transcript.read_scalar_le()?)?;
        let neg_c = c.neg();
        let f = PallasFp::from_le_array(&transcript.read_scalar_le()?)?;
        let b = Self::compute_b(x, &u_list);
        msm.add_to_u_scalar(neg_c.mul_vartime(&b).mul_vartime(&z));
        msm.add_to_w_scalar(f.neg());
        Ok((msm, PolyGuard { neg_c, u: u_list }))
    }

    pub fn compute_s(u: &[PallasFp], init: PallasFp) -> Halo2Result<Vec<PallasFp>> {
        if u.is_empty() {
            return Err(Halo2Error::operation_failed("ipa::compute_s", "empty u"));
        }
        let size = 1usize << u.len();
        let mut v = vec![PallasFp::zero(); size];
        v[0] = init;
        for i in 0..u.len() {
            let uj = u[u.len() - 1 - i];
            let len = 1usize << i;
            for j in 0..len {
                v[j + len] = v[j].mul_vartime(&uj);
            }
        }
        Ok(v)
    }

    pub fn compute_b(x: PallasFp, u: &[PallasFp]) -> PallasFp {
        let mut tmp = PallasFp::one();
        let mut cur = x;
        for uj in u.iter().rev() {
            tmp = tmp.mul_vartime(&PallasFp::one().add_vartime(&uj.mul_vartime(&cur)));
            cur = cur.square_vartime();
        }
        tmp
    }

    pub fn generator_collapse(g: &mut [VestaAffine], challenge: &PallasFp) -> Halo2Result<()> {
        if !g.len().is_multiple_of(2) {
            return Err(Halo2Error::operation_failed("ipa::collapse", "odd length"));
        }
        // Keep folds projective (no per-point affine normalization: saves an
        // inversion + re-validation per point). Downstream MSM (`pippenger_msm`)
        // auto-selects the general add path for non-affine bases; compressed
        // outputs normalize at encode time, so proof bytes are unchanged.
        let ch = VestaScalar::from_bytes_le(&challenge.to_le_bytes())?;
        let half = g.len() / 2;
        for i in 0..half {
            let hi = g[i + half].mul_vartime(&ch);
            g[i] = g[i].add_vartime(&hi);
        }
        Ok(())
    }

    #[cfg(feature = "alloc")]
    pub fn to_debug_string() -> String {
        alloc::string::String::from("PolyCommitment")
    }
}

fn ipa_commit(
    coeffs: &[PallasFp],
    bases: &[VestaAffine],
    _params: &PolyParams,
) -> Halo2Result<VestaProjective> {
    crate::zk::orchard_halo2::curve::msm_vesta(coeffs, bases)
}

#[allow(clippy::ptr_arg)] // `&mut Vec` is part of the public commitment API; callers pass owned vectors.
pub fn generator_collapse(g: &mut Vec<VestaAffine>, challenge: &PallasFp) -> Halo2Result<()> {
    PolyCommitment::generator_collapse(g, challenge)
}

#[derive(Clone)]
pub enum CommitmentReference<'a> {
    Commitment(VestaAffine),
    Msm(Msm<'a>),
}

/// Key equality for intermediate sets. Affine commitments compare by value;
/// MSM accumulators use reference semantics (always distinct keys), matching
/// object-identity map keys.
pub fn commitment_key_eq(a: &CommitmentReference<'_>, b: &CommitmentReference<'_>) -> bool {
    match (a, b) {
        (CommitmentReference::Commitment(x), CommitmentReference::Commitment(y)) => x == y,
        _ => false,
    }
}

pub struct PolyGuard {
    pub neg_c: PallasFp,
    pub u: Vec<PallasFp>,
}

impl PolyGuard {
    /// Apply challenges into the caller's MSM: s = computeS(u, negC).
    pub fn use_challenges<'a>(&self, msm: &mut Msm<'a>) -> Halo2Result<()> {
        let s = PolyCommitment::compute_s(&self.u, self.neg_c)?;
        msm.add_to_g_scalars(&s)
    }
}

pub struct CommitmentData<C, F> {
    pub commitment: C,
    pub set_index: usize,
    pub point_indices: Vec<usize>,
    pub evals: Vec<F>,
}

impl<C, F> CommitmentData<C, F> {
    pub fn default_value(commitment: C) -> Self {
        Self {
            commitment,
            set_index: 0,
            point_indices: Vec::new(),
            evals: Vec::new(),
        }
    }
}
