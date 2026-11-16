//! Implements poly/multiopen logic (`PolyMultiopen`, queries).
//! Deduplication uses linear key search (`commitment_key_eq` for verifier
//! refs; structural compare for prover polys). All mismatches are `Err`.
//! Points/evals cross as LE field bytes; debug via `format!`.

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

use crate::zk::orchard_halo2::curve::VestaAffine;
use crate::zk::orchard_halo2::error::{Halo2Error, Halo2Result};
use crate::zk::orchard_halo2::field::PallasFp;
use crate::zk::orchard_halo2::poly::commitment::commitment::{CommitmentReference, PolyCommitment};
use crate::zk::orchard_halo2::poly::commitment::msm::Msm;
use crate::zk::orchard_halo2::poly::params::PolyParams;
use crate::zk::orchard_halo2::poly::poly::{Basis, Polynomial};
use crate::zk::orchard_halo2::rng::BlindRng;
use crate::zk::orchard_halo2::transcript::transcript::{TranscriptReader, TranscriptWriter};
use crate::zk::orchard_halo2::utility::utils::{
    eval_polynomial, kate_division, lagrange_interpolate,
};

#[derive(Clone)]
pub struct PolynomialPointer {
    pub poly: Polynomial<PallasFp>,
    pub blind: PallasFp,
}

#[derive(Clone)]
pub struct ProverQuery {
    pub point: PallasFp,
    pub poly: Polynomial<PallasFp>,
    pub blind: PallasFp,
}

impl ProverQuery {
    pub fn commitment(&self) -> PolynomialPointer {
        PolynomialPointer {
            poly: self.poly.clone(),
            blind: self.blind,
        }
    }
}

#[derive(Clone)]
pub struct VerifierQuery<'a> {
    pub point: PallasFp,
    pub commitment: CommitmentReference<'a>,
    pub eval: PallasFp,
}

pub struct PolyMultiopen;

impl PolyMultiopen {
    pub fn create_proof(
        params: &PolyParams,
        transcript: &mut TranscriptWriter,
        queries: &[ProverQuery],
        rng: &mut dyn BlindRng,
    ) -> Halo2Result<()> {
        let x1 = transcript.squeeze_challenge()?;
        let x2 = transcript.squeeze_challenge()?;
        let (poly_map, point_sets) = construct_prover_sets(queries)?;
        let mut q_polys: Vec<Option<Polynomial<PallasFp>>> = vec![None; point_sets.len()];
        let mut q_blinds: Vec<PallasFp> = vec![PallasFp::zero(); point_sets.len()];

        for data in poly_map.iter() {
            let idx = data.set_index;
            let new_poly = data.commitment.poly.clone();
            let blind = data.commitment.blind;
            match &mut q_polys[idx] {
                Some(existing) => {
                    if existing.values.len() != new_poly.values.len() {
                        return Err(Halo2Error::operation_failed(
                            "multiopen::acc",
                            "length mismatch",
                        ));
                    }
                    for (e, n) in existing.values.iter_mut().zip(new_poly.values.iter()) {
                        *e = e.mul_vartime(&x1).add_vartime(n);
                    }
                }
                slot => {
                    *slot = Some(new_poly);
                }
            }
            q_blinds[idx] = q_blinds[idx].mul_vartime(&x1).add_vartime(&blind);
        }

        let mut q_prime: Option<Polynomial<PallasFp>> = None;
        for (i, points) in point_sets.iter().enumerate() {
            let qp = q_polys[i].as_ref().ok_or_else(|| {
                Halo2Error::operation_failed("multiopen::qprime", "missing set poly")
            })?;
            let mut poly_vals = qp.values.clone();
            for point in points.iter() {
                poly_vals = kate_division(&poly_vals, *point)?;
            }
            while poly_vals.len() < params.n {
                poly_vals.push(PallasFp::zero());
            }
            match &mut q_prime {
                Some(old) => {
                    if old.values.len() != poly_vals.len() {
                        return Err(Halo2Error::operation_failed(
                            "multiopen::qprime",
                            "length mismatch",
                        ));
                    }
                    for (o, n) in old.values.iter_mut().zip(poly_vals.iter()) {
                        *o = o.mul_vartime(&x2).add_vartime(n);
                    }
                }
                slot => {
                    *slot = Some(Polynomial::new(poly_vals, Basis::Coeff));
                }
            }
        }
        let q_prime_poly = q_prime
            .ok_or_else(|| Halo2Error::operation_failed("multiopen::qprime", "no point sets"))?;
        let q_prime_blind = rng.next_pallas();
        let q_prime_commit = params.commit(&q_prime_poly, q_prime_blind)?;
        transcript.write_point(&q_prime_commit.to_compressed()?)?;

        let x3 = transcript.squeeze_challenge()?;
        for qp in q_polys.iter() {
            let qp = qp.as_ref().ok_or_else(|| {
                Halo2Error::operation_failed("multiopen::eval", "missing set poly")
            })?;
            let eval = eval_polynomial(&qp.values, x3);
            transcript.write_scalar_le(&eval.to_le_bytes())?;
        }

        let x4 = transcript.squeeze_challenge()?;
        let mut p_poly = q_prime_poly;
        let mut p_blind = q_prime_blind;
        for (i, qp) in q_polys.iter().enumerate() {
            let qp = qp.as_ref().ok_or_else(|| {
                Halo2Error::operation_failed("multiopen::fold", "missing set poly")
            })?;
            if p_poly.values.len() != qp.values.len() {
                return Err(Halo2Error::operation_failed(
                    "multiopen::fold",
                    "length mismatch",
                ));
            }
            for (p, q) in p_poly.values.iter_mut().zip(qp.values.iter()) {
                *p = p.mul_vartime(&x4).add_vartime(q);
            }
            p_blind = p_blind.mul_vartime(&x4).add_vartime(&q_blinds[i]);
        }
        PolyCommitment::create_proof(params, transcript, &p_poly, p_blind, x3, rng)
    }

    pub fn verify_proof<'a>(
        params: &'a PolyParams,
        transcript: &mut TranscriptReader<'_>,
        queries: &[VerifierQuery<'a>],
        msm: Msm<'a>,
    ) -> Halo2Result<(
        Msm<'a>,
        crate::zk::orchard_halo2::poly::commitment::commitment::PolyGuard,
    )> {
        let x1 = transcript.squeeze_challenge()?;
        let x2 = transcript.squeeze_challenge()?;
        let (commitment_map, point_sets) = construct_verifier_sets(queries)?;

        let mut q_commitments: Vec<(Msm<'a>, PallasFp)> = Vec::with_capacity(point_sets.len());
        for _ in 0..point_sets.len() {
            q_commitments.push((Msm::new(params), PallasFp::one()));
        }
        let mut q_eval_sets: Vec<Vec<PallasFp>> = point_sets
            .iter()
            .map(|s| vec![PallasFp::zero(); s.len()])
            .collect();

        // Reverse order (matches Rust `.rev()`).
        for data in commitment_map.iter().rev() {
            let (qc, power) = &mut q_commitments[data.set_index];
            match &data.commitment {
                CommitmentReference::Commitment(inner) => {
                    qc.append_term(*power, inner)?;
                }
                CommitmentReference::Msm(inner) => {
                    let mut c = inner.clone();
                    c.scale(*power);
                    qc.add_msm(&c)?;
                }
            }
            for (i, e) in data.evals.iter().enumerate() {
                let slot = q_eval_sets[data.set_index].get_mut(i).ok_or_else(|| {
                    Halo2Error::operation_failed("multiopen::verify", "eval overflow")
                })?;
                *slot = slot.add_vartime(&e.mul_vartime(power));
            }
            *power = power.mul_vartime(&x1);
        }

        let q_prime_commit = transcript.read_point()?;
        let x3 = transcript.squeeze_challenge()?;
        let mut u: Vec<PallasFp> = Vec::with_capacity(q_eval_sets.len());
        for _ in 0..q_eval_sets.len() {
            u.push(PallasFp::from_le_array(&transcript.read_scalar_le()?)?);
        }

        let mut msm_eval = PallasFp::zero();
        for (i, points) in point_sets.iter().enumerate() {
            let evals = &q_eval_sets[i];
            let proof_eval = u[i];
            let r_poly = lagrange_interpolate(points, evals)?;
            let r_eval = eval_polynomial(&r_poly, x3);
            let mut eval = proof_eval.sub_vartime(&r_eval);
            for point in points.iter() {
                let inv = x3.sub_vartime(point).invert()?;
                eval = eval.mul_vartime(&inv);
            }
            msm_eval = msm_eval.mul_vartime(&x2).add_vartime(&eval);
        }

        let x4 = transcript.squeeze_challenge()?;
        let q_aff = VestaAffine::from_compressed(&q_prime_commit)?;
        let mut msm_acc = msm;
        msm_acc.append_term(PallasFp::one(), &q_aff)?;
        let mut v = msm_eval;
        for (i, (qc, _)) in q_commitments.into_iter().enumerate() {
            msm_acc.scale(x4);
            msm_acc.add_msm(&qc)?;
            v = v.mul_vartime(&x4).add_vartime(&u[i]);
        }
        PolyCommitment::verify_proof(params, msm_acc, transcript, x3, v)
    }

    #[cfg(feature = "alloc")]
    pub fn to_debug_string() -> String {
        alloc::string::String::from("PolyMultiopen")
    }
}

struct ProverSetData {
    set_index: usize,
    commitment: PolynomialPointer,
}

fn construct_prover_sets(
    queries: &[ProverQuery],
) -> Halo2Result<(Vec<ProverSetData>, Vec<Vec<PallasFp>>)> {
    // point index per unique point (LE bytes compare).
    let mut point_index: Vec<([u8; 32], usize)> = Vec::new();
    // commitment entries: (poly values LE concat key, blind) — structural.
    let mut commits: Vec<(Vec<u8>, PolynomialPointer, Vec<usize>)> = Vec::new();
    for q in queries.iter() {
        let ple = q.point.to_le_bytes();
        let pi = match point_index.iter().find(|(b, _)| *b == ple) {
            Some((_, i)) => *i,
            None => {
                let i = point_index.len();
                point_index.push((ple, i));
                i
            }
        };
        // Structural key: poly values + blind.
        let mut key: Vec<u8> = Vec::new();
        for v in q.poly.values.iter() {
            key.extend_from_slice(&v.to_le_bytes());
        }
        key.extend_from_slice(&q.blind.to_le_bytes());
        match commits.iter_mut().find(|(k, _, _)| *k == key) {
            Some((_, _, idxs)) => idxs.push(pi),
            None => commits.push((key, q.commitment(), vec![pi])),
        }
    }
    // Canonical set index per commitment (sorted point-index set key).
    let mut set_keys: Vec<Vec<usize>> = Vec::new();
    let mut commit_set: Vec<usize> = Vec::with_capacity(commits.len());
    for (_, _, idxs) in commits.iter() {
        let mut s = idxs.clone();
        s.sort_unstable();
        s.dedup();
        match set_keys.iter().position(|k| *k == s) {
            Some(i) => commit_set.push(i),
            None => {
                commit_set.push(set_keys.len());
                set_keys.push(s);
            }
        }
    }
    // Evals are None on prover side; set index assigned; point sets built.
    let mut point_sets: Vec<Vec<PallasFp>> = vec![Vec::new(); set_keys.len()];
    let mut le_to_fp: Vec<([u8; 32], PallasFp)> = Vec::new();
    for q in queries.iter() {
        le_to_fp.push((q.point.to_le_bytes(), q.point));
    }
    for (si, set) in set_keys.iter().enumerate() {
        for pi in set.iter() {
            let le = point_index[*pi].0;
            let fp = le_to_fp
                .iter()
                .find(|(b, _)| *b == le)
                .map(|(_, f)| *f)
                .ok_or_else(|| Halo2Error::operation_failed("multiopen::sets", "missing point"))?;
            point_sets[si].push(fp);
        }
    }
    let mut out = Vec::with_capacity(commits.len());
    for (i, (_, ptr, _)) in commits.into_iter().enumerate() {
        out.push(ProverSetData {
            set_index: commit_set[i],
            commitment: ptr,
        });
    }
    Ok((out, point_sets))
}

struct VerifierSetData<'a> {
    set_index: usize,
    commitment: CommitmentReference<'a>,
    evals: Vec<PallasFp>,
}

#[allow(clippy::unnecessary_cast)] // Extending to `*const Msm<'static>` is load-bearing: `EntryKey` keys live MSMs by pointer identity.
fn construct_verifier_sets<'a>(
    queries: &[VerifierQuery<'a>],
) -> Halo2Result<(Vec<VerifierSetData<'a>>, Vec<Vec<PallasFp>>)> {
    let mut point_index: Vec<([u8; 32], PallasFp, usize)> = Vec::new();
    // Single insertion-ordered entry list (mirrors the reference implementation
    // affine commitments dedup by value (64-byte LE coord key, computed once
    // per query — no per-compare inversions), MSM by pointer identity.
    enum EntryKey {
        Aff([u8; 64]),
        Msm(*const Msm<'static>),
    }
    // Canonical 64-byte key for an affine commitment (x_le ++ y_le).
    // All verifier commitments are affine; the fast path avoids inversion.
    fn aff_key(aff: &VestaAffine) -> Halo2Result<[u8; 64]> {
        let (x, y) = aff.to_affine_coords()?;
        let xb = x.to_le_bytes();
        let yb = y.to_le_bytes();
        let mut k = [0u8; 64];
        k[..32].copy_from_slice(&xb);
        k[32..].copy_from_slice(&yb);
        Ok(k)
    }
    let mut keys: Vec<EntryKey> = Vec::new();
    let mut entry_points: Vec<Vec<usize>> = Vec::new();
    let mut entry_crefs: Vec<CommitmentReference<'a>> = Vec::new();

    for q in queries.iter() {
        let ple = q.point.to_le_bytes();
        let pi = match point_index.iter().find(|(b, _, _)| *b == ple) {
            Some((_, _, i)) => *i,
            None => {
                let i = point_index.len();
                point_index.push((ple, q.point, i));
                i
            }
        };
        let found = match &q.commitment {
            CommitmentReference::Commitment(aff) => {
                let kb = aff_key(aff)?;
                keys.iter()
                    .position(|k| matches!(k, EntryKey::Aff(a) if *a == kb))
            }
            CommitmentReference::Msm(m) => {
                let ptr = (m as *const Msm<'a>) as *const Msm<'static>;
                keys.iter()
                    .position(|k| matches!(k, EntryKey::Msm(p) if *p == ptr))
            }
        };
        match found {
            Some(i) => entry_points[i].push(pi),
            None => {
                let key = match &q.commitment {
                    CommitmentReference::Commitment(aff) => EntryKey::Aff(aff_key(aff)?),
                    CommitmentReference::Msm(m) => {
                        EntryKey::Msm((m as *const Msm<'a>) as *const Msm<'static>)
                    }
                };
                keys.push(key);
                entry_points.push(vec![pi]);
                entry_crefs.push(q.commitment.clone());
            }
        }
    }
    // Canonical set index per entry in global first-seen order.
    let mut set_keys: Vec<Vec<usize>> = Vec::new();
    let mut entry_sets: Vec<usize> = Vec::with_capacity(entry_points.len());
    for idxs in entry_points.iter_mut() {
        let mut s = idxs.clone();
        s.sort_unstable();
        s.dedup();
        *idxs = s.clone();
        match set_keys.iter().position(|k| *k == s) {
            Some(i) => entry_sets.push(i),
            None => {
                entry_sets.push(set_keys.len());
                set_keys.push(s);
            }
        }
    }
    // Size eval slots.
    let mut entry_evals: Vec<Vec<Option<PallasFp>>> = entry_points
        .iter()
        .map(|idxs| vec![None; idxs.len()])
        .collect();
    // Populate evals; conflicting eval → Err (mirrors the reference implementation
    for q in queries.iter() {
        let ple = q.point.to_le_bytes();
        let pi = point_index
            .iter()
            .find(|(b, _, _)| *b == ple)
            .map(|(_, _, i)| *i)
            .ok_or_else(|| Halo2Error::operation_failed("multiopen::sets", "missing point"))?;
        let ei = match &q.commitment {
            CommitmentReference::Commitment(aff) => {
                let kb = aff_key(aff)?;
                keys.iter()
                    .position(|k| matches!(k, EntryKey::Aff(a) if *a == kb))
                    .ok_or_else(|| {
                        Halo2Error::operation_failed("multiopen::sets", "missing commitment")
                    })?
            }
            CommitmentReference::Msm(m) => {
                let ptr = (m as *const Msm<'a>) as *const Msm<'static>;
                keys.iter()
                    .position(|k| matches!(k, EntryKey::Msm(p) if *p == ptr))
                    .ok_or_else(|| {
                        Halo2Error::operation_failed("multiopen::sets", "missing commitment")
                    })?
            }
        };
        let pos = entry_points[ei]
            .iter()
            .position(|x| *x == pi)
            .ok_or_else(|| Halo2Error::operation_failed("multiopen::sets", "bad point index"))?;
        let slot = entry_evals[ei]
            .get_mut(pos)
            .ok_or_else(|| Halo2Error::operation_failed("multiopen::sets", "eval overflow"))?;
        if slot.is_some() {
            return Err(Halo2Error::operation_failed(
                "multiopen::sets",
                "conflicting eval",
            ));
        }
        *slot = Some(q.eval);
    }
    let mut point_sets: Vec<Vec<PallasFp>> = vec![Vec::new(); set_keys.len()];
    for (si, set) in set_keys.iter().enumerate() {
        for pi in set.iter() {
            point_sets[si].push(point_index[*pi].1);
        }
    }
    let mut out: Vec<VerifierSetData<'a>> = Vec::new();
    for (i, cref) in entry_crefs.into_iter().enumerate() {
        let ev: Vec<PallasFp> = entry_evals[i]
            .iter()
            .copied()
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| Halo2Error::operation_failed("multiopen::sets", "missing eval"))?;
        out.push(VerifierSetData {
            set_index: entry_sets[i],
            commitment: cref,
            evals: ev,
        });
    }
    Ok((out, point_sets))
}
