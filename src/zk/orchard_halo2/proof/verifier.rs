//! Implements proof/verifier logic (`PlonkVerifier`).
//! Instance bounds and selector checks are `Err`, never throws/`assert!`.

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

use crate::zk::orchard_halo2::crypto_context::DefaultCryptoContext;
use crate::zk::orchard_halo2::curve::VestaAffine;
use crate::zk::orchard_halo2::error::{Halo2Error, Halo2Result};
use crate::zk::orchard_halo2::field::PallasFp;
use crate::zk::orchard_halo2::orchard::circuit::{OrchardCircuit, OrchardProtocolVersion};
use crate::zk::orchard_halo2::plonk::key::{keygen_vk, PlonkVerifyingKey};
use crate::zk::orchard_halo2::plonk::lookup::LookupVerifyEvaluated;
use crate::zk::orchard_halo2::plonk::permutation::PermutationVerifyEvaluated;
use crate::zk::orchard_halo2::poly::commitment::commitment::CommitmentReference;
use crate::zk::orchard_halo2::poly::commitment::msm::Msm;
use crate::zk::orchard_halo2::poly::multiopen::{PolyMultiopen, VerifierQuery};
use crate::zk::orchard_halo2::poly::params::PolyParams;
use crate::zk::orchard_halo2::transcript::transcript::TranscriptReader;

pub struct PlonkVerifier {
    pub params: PolyParams,
    pub vk: PlonkVerifyingKey,
}

impl PlonkVerifier {
    pub fn build(
        context: &DefaultCryptoContext,
        version: OrchardProtocolVersion,
        k: u32,
    ) -> Halo2Result<Self> {
        let params = PolyParams::new_params(k)?;
        let circuit = OrchardCircuit::default_config(version);
        let vk = keygen_vk(&circuit, context, k, &params)?;
        Ok(Self { params, vk })
    }

    pub fn with_keys(params: PolyParams, vk: PlonkVerifyingKey) -> Self {
        Self { params, vk }
    }

    pub fn verify_sync(
        &self,
        proof_bytes: &[u8],
        instances: &[Vec<Vec<PallasFp>>],
    ) -> Halo2Result<bool> {
        for columns in instances.iter() {
            if columns.len() != self.vk.cs.num_instance_columns() {
                return Err(Halo2Error::operation_failed(
                    "verify::instances",
                    "column count",
                ));
            }
        }
        let mut transcript = TranscriptReader::new(proof_bytes)?;
        let queries = self.build_queries_sync(&mut transcript, instances)?;
        let msm = Msm::new(&self.params);
        let (mut msm, guard) =
            PolyMultiopen::verify_proof(&self.params, &mut transcript, &queries, msm)?;
        guard.use_challenges(&mut msm)?;
        // The proof must be consumed exactly. This validates the proof length
        // for any number of actions in the batch (the transcript grows with
        // the batch size), instead of assuming a single-action proof.
        if transcript.consumed() != proof_bytes.len() {
            return Err(Halo2Error::operation_failed(
                "verify::proof_length",
                "trailing or missing bytes",
            ));
        }
        msm.eval()
    }

    fn build_queries_sync(
        &self,
        transcript: &mut TranscriptReader<'_>,
        instances: &[Vec<Vec<PallasFp>>],
    ) -> Halo2Result<Vec<VerifierQuery<'_>>> {
        // Instance commitments (padded to n).
        let usable = self.params.n - (self.vk.cs.blinding_factors() + 1);
        let mut instance_commitments: Vec<Vec<VestaAffine>> = Vec::with_capacity(instances.len());
        for columns in instances.iter() {
            let mut per_proof = Vec::with_capacity(columns.len());
            for column in columns.iter() {
                if column.len() > usable {
                    return Err(Halo2Error::operation_failed("verify::instance", "too long"));
                }
                let mut coeffs = column.clone();
                coeffs.resize(self.params.n, PallasFp::zero());
                let poly = self.vk.domain.lagrange_from_vec(coeffs)?;
                let c = self.params.commit_lagrange(&poly, PallasFp::one())?;
                let (x, y, ident) = c.to_affine_le()?;
                per_proof.push(if ident {
                    VestaAffine::identity()
                } else {
                    VestaAffine::from_le_xy(x, y)?
                });
            }
            instance_commitments.push(per_proof);
        }

        self.vk.hash_into_transcript(transcript)?;
        for per_proof in instance_commitments.iter() {
            for commitment in per_proof.iter() {
                transcript.common_point_affine(commitment)?;
            }
        }
        let num_proofs = instance_commitments.len();

        let mut advice_commitments: Vec<Vec<VestaAffine>> = Vec::with_capacity(num_proofs);
        for _ in 0..num_proofs {
            let mut per_proof = Vec::with_capacity(self.vk.cs.num_advice_columns());
            for _ in 0..self.vk.cs.num_advice_columns() {
                per_proof.push(VestaAffine::from_compressed(&transcript.read_point()?)?);
            }
            advice_commitments.push(per_proof);
        }

        let theta = transcript.squeeze_challenge()?;

        let mut lookups_permuted = Vec::with_capacity(num_proofs);
        for _ in 0..num_proofs {
            let mut per_proof = Vec::new();
            for argument in self.vk.cs.lookups.iter() {
                per_proof.push(argument.read_permuted_commitments(transcript)?);
            }
            lookups_permuted.push(per_proof);
        }

        let beta = transcript.squeeze_challenge()?;
        let gamma = transcript.squeeze_challenge()?;

        let mut permutations_committed = Vec::with_capacity(num_proofs);
        for _ in 0..num_proofs {
            permutations_committed.push(
                self.vk
                    .cs
                    .permutation
                    .read_product_commitments(&self.vk, transcript)?,
            );
        }

        let mut lookups_committed = Vec::with_capacity(num_proofs);
        for per_proof in lookups_permuted.iter() {
            let mut inner = Vec::new();
            for commitments in per_proof.iter() {
                inner.push(commitments.read_product_commitment(transcript)?);
            }
            lookups_committed.push(inner);
        }

        let vanishing_read =
            crate::zk::orchard_halo2::plonk::vanishing::VanishingReadCommitted::read_before_y(
                transcript,
            )?;
        let y = transcript.squeeze_challenge()?;
        let vp = vanishing_read.read_after_y(&self.vk, transcript)?;
        let x = transcript.squeeze_challenge()?;

        let mut instance_evals = Vec::with_capacity(num_proofs);
        for _ in 0..num_proofs {
            let mut row = Vec::with_capacity(self.vk.cs.instance_queries.len());
            for _ in 0..self.vk.cs.instance_queries.len() {
                row.push(PallasFp::from_le_array(&transcript.read_scalar_le()?)?);
            }
            instance_evals.push(row);
        }
        let mut advice_evals = Vec::with_capacity(num_proofs);
        for _ in 0..num_proofs {
            let mut row = Vec::with_capacity(self.vk.cs.advice_queries.len());
            for _ in 0..self.vk.cs.advice_queries.len() {
                row.push(PallasFp::from_le_array(&transcript.read_scalar_le()?)?);
            }
            advice_evals.push(row);
        }
        let mut fixed_evals = Vec::with_capacity(self.vk.cs.fixed_queries.len());
        for _ in 0..self.vk.cs.fixed_queries.len() {
            fixed_evals.push(PallasFp::from_le_array(&transcript.read_scalar_le()?)?);
        }
        let vanishing_partial = vp.evaluate_after_x(transcript)?;
        let permutations_common = self.vk.permutation.evaluate(transcript)?;
        let mut permutations_evaluated = Vec::with_capacity(num_proofs);
        for committed in permutations_committed.iter() {
            permutations_evaluated.push(committed.evaluate(transcript)?);
        }
        let mut lookups_evaluated: Vec<Vec<LookupVerifyEvaluated>> = Vec::with_capacity(num_proofs);
        for per_proof in lookups_committed.iter() {
            let mut inner = Vec::new();
            for committed in per_proof.iter() {
                inner.push(committed.evaluate(transcript)?);
            }
            lookups_evaluated.push(inner);
        }

        let vanishing = self.vanishing_sync(
            x,
            gamma,
            beta,
            theta,
            y,
            &advice_evals,
            &instance_evals,
            &permutations_evaluated,
            &lookups_evaluated,
            &fixed_evals,
            &permutations_common,
            &vanishing_partial,
        )?;

        // Queries.
        let mut queries: Vec<VerifierQuery<'_>> = Vec::new();
        for i in 0..num_proofs {
            for (qi, entry) in self.vk.cs.instance_queries.iter().enumerate() {
                queries.push(VerifierQuery {
                    point: self.vk.domain.rotate_omega(x, entry.1),
                    commitment: CommitmentReference::Commitment(
                        instance_commitments[i][entry.0.index],
                    ),
                    eval: instance_evals[i][qi],
                });
            }
            for (qi, entry) in self.vk.cs.advice_queries.iter().enumerate() {
                queries.push(VerifierQuery {
                    point: self.vk.domain.rotate_omega(x, entry.1),
                    commitment: CommitmentReference::Commitment(
                        advice_commitments[i][entry.0.index],
                    ),
                    eval: advice_evals[i][qi],
                });
            }
            queries.extend(permutations_evaluated[i].clone().queries(&self.vk, x));
            for p in lookups_evaluated[i].iter() {
                queries.extend(p.queries(&self.vk, x));
            }
        }
        for (qi, entry) in self.vk.cs.fixed_queries.iter().enumerate() {
            queries.push(VerifierQuery {
                point: self.vk.domain.rotate_omega(x, entry.1),
                commitment: CommitmentReference::Commitment(
                    self.vk.fixed_commitments[entry.0.index],
                ),
                eval: fixed_evals[qi],
            });
        }
        queries.extend(permutations_common.queries(&self.vk.permutation, x));
        queries.extend(vanishing.into_queries(x));
        Ok(queries)
    }

    #[allow(clippy::too_many_arguments)]
    fn vanishing_sync(
        &self,
        x: PallasFp,
        gamma: PallasFp,
        beta: PallasFp,
        theta: PallasFp,
        y: PallasFp,
        advice_evals: &[Vec<PallasFp>],
        instance_evals: &[Vec<PallasFp>],
        permutations_evaluated: &[PermutationVerifyEvaluated],
        lookups_evaluated: &[Vec<LookupVerifyEvaluated>],
        fixed_evals: &[PallasFp],
        permutations_common: &crate::zk::orchard_halo2::plonk::permutation::PermutationVerifyCommonEvaluated,
        vanishing: &crate::zk::orchard_halo2::plonk::vanishing::VanishingPartiallyEvaluated,
    ) -> Halo2Result<crate::zk::orchard_halo2::plonk::vanishing::VanishingVerifyEvaluated<'_>> {
        let xn = pow_n(x, self.params.n);
        let blinding = self.vk.cs.blinding_factors();
        let mut rotations: Vec<i32> = Vec::with_capacity(blinding + 2);
        for i in 0..blinding + 2 {
            rotations.push(-(blinding as i32) - 1 + i as i32);
        }
        let l_evals = self.vk.domain.lagrange_range(x, xn, &rotations)?;
        if l_evals.len() != blinding + 2 {
            return Err(Halo2Error::operation_failed(
                "verify::l_range",
                "length mismatch",
            ));
        }
        let l_last = l_evals[0];
        let mut l_blind = PallasFp::zero();
        for v in l_evals[1..1 + blinding].iter() {
            l_blind = l_blind.add_vartime(v);
        }
        let l0 = l_evals[1 + blinding];

        let mut expressions: Vec<PallasFp> = Vec::new();
        for proof_idx in 0..advice_evals.len() {
            let advice_eval = &advice_evals[proof_idx];
            let instance_eval = &instance_evals[proof_idx];
            for gate in self.vk.cs.gates.iter() {
                for poly in gate.polys.iter() {
                    if poly.contains_simple_selector() {
                        return Err(Halo2Error::operation_failed(
                            "verify::gate",
                            "simple selector present",
                        ));
                    }
                    expressions.push(poly.evaluate(
                        &|s| s,
                        &|_| PallasFp::zero(),
                        &|q| {
                            fixed_evals
                                .get(q.index)
                                .copied()
                                .unwrap_or(PallasFp::zero())
                        },
                        &|q| {
                            advice_eval
                                .get(q.index)
                                .copied()
                                .unwrap_or(PallasFp::zero())
                        },
                        &|q| {
                            instance_eval
                                .get(q.index)
                                .copied()
                                .unwrap_or(PallasFp::zero())
                        },
                        &|a| a.neg(),
                        &|a, b| a.add_vartime(&b),
                        &|a, b| a.mul_vartime(&b),
                        &|a, s| a.mul_vartime(&s),
                    ));
                }
            }
            expressions.extend(permutations_evaluated[proof_idx].expressions(
                &self.vk,
                &self.vk.cs.permutation,
                permutations_common,
                advice_eval,
                fixed_evals,
                instance_eval,
                l0,
                l_last,
                l_blind,
                beta,
                gamma,
                x,
            )?);
            for (i, p) in lookups_evaluated[proof_idx].iter().enumerate() {
                let argument = &self.vk.cs.lookups[i];
                expressions.extend(p.expressions(
                    l0,
                    l_last,
                    l_blind,
                    argument,
                    theta,
                    beta,
                    gamma,
                    advice_eval,
                    fixed_evals,
                    instance_eval,
                )?);
            }
        }
        vanishing.verify(&self.params, &expressions, y, xn)
    }

    #[cfg(feature = "alloc")]
    pub fn to_debug_string(&self) -> String {
        alloc::string::String::from("PlonkVerifier")
    }
}

fn pow_n(x: PallasFp, n: usize) -> PallasFp {
    let mut acc = PallasFp::one();
    let mut b = x;
    let mut e = n;
    while e > 0 {
        if (e & 1) == 1 {
            acc = acc.mul_vartime(&b);
        }
        b = b.square_vartime();
        e >>= 1;
    }
    acc
}
