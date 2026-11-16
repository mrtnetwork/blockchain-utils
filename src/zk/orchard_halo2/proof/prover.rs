//! Implements proof/prover logic (`PlonkProver`).
//! The duplicated multi-open/commitment rounds delegate to the shared
//! `poly` modules. One ChaCha `BlindRng` (caller-seeded, deterministic
//! stream) is threaded through all stages. No `assert!`.

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

use crate::zk::orchard_halo2::crypto_context::DefaultCryptoContext;
use crate::zk::orchard_halo2::error::{Halo2Error, Halo2Result};
use crate::zk::orchard_halo2::field::PallasFp;
use crate::zk::orchard_halo2::floor_planner::v1::v1_synthesize;
use crate::zk::orchard_halo2::orchard::circuit::{
    OrchardCircuit, OrchardCircuitConfig, OrchardProtocolVersion,
};
use crate::zk::orchard_halo2::plonk::assignment::UsableRows;
use crate::zk::orchard_halo2::plonk::constraint::ConstraintSystem;
use crate::zk::orchard_halo2::plonk::expression::Expression;
use crate::zk::orchard_halo2::plonk::key::{keygen_pk, keygen_vk, PlonkProvingKey};
use crate::zk::orchard_halo2::plonk::lookup::{
    LookupCommitted, LookupConstructed, LookupEvaluated, LookupPermuted,
};
use crate::zk::orchard_halo2::plonk::permutation::PermutationCommitted;
use crate::zk::orchard_halo2::plonk::proof::{
    AstLeaves, PlonkWitnessCollection, PolyAdviceSingle, PolyInstanceSingle,
};
use crate::zk::orchard_halo2::plonk::vanishing::VanishingCommitted;
use crate::zk::orchard_halo2::poly::evaluator::{Ast, AstLeaf};
use crate::zk::orchard_halo2::poly::multiopen::{PolyMultiopen, ProverQuery};
use crate::zk::orchard_halo2::poly::params::PolyParams;
use crate::zk::orchard_halo2::poly::poly::Polynomial;
use crate::zk::orchard_halo2::rng::{BlindRng, ChaChaBlindRng};

use crate::zk::orchard_halo2::transcript::transcript::TranscriptWriter;
use crate::zk::orchard_halo2::utility::utils::eval_polynomial;

pub struct PlonkProver {
    pub params: PolyParams,
    pub proving_key: PlonkProvingKey,
    pub config: OrchardCircuitConfig,
    pub context: DefaultCryptoContext,
}

impl PlonkProver {
    pub fn build(
        context: &DefaultCryptoContext,
        version: OrchardProtocolVersion,
        k: u32,
    ) -> Halo2Result<Self> {
        let circuit = OrchardCircuit::default_config(version);
        let params = PolyParams::new_params(k)?;
        let vk = keygen_vk(&circuit, context, k, &params)?;
        let pk = keygen_pk(&circuit, &params, vk, context)?;
        let mut cs = ConstraintSystem::default_config();
        let config = OrchardCircuitConfig::configure(&mut cs, context)?;
        Ok(Self {
            params,
            proving_key: pk,
            config,
            context: *context,
        })
    }

    pub fn with_keys(
        params: PolyParams,
        proving_key: PlonkProvingKey,
        config: OrchardCircuitConfig,
        context: DefaultCryptoContext,
    ) -> Self {
        Self {
            params,
            proving_key,
            config,
            context,
        }
    }

    pub fn to_verifier_params(
        &self,
    ) -> (
        &PolyParams,
        &crate::zk::orchard_halo2::plonk::key::PlonkVerifyingKey,
    ) {
        (&self.params, &self.proving_key.vk)
    }

    /// ChaCha blinding RNG from an explicit 32-byte seed (deterministic
    /// stream). Callers seeking bit-identical proofs fast-forward past any
    /// witness-generation draws before proving.
    pub fn chacha_rng(seed: &[u8; 32]) -> ChaChaBlindRng {
        ChaChaBlindRng::from_seed(seed)
    }

    pub fn create_proof(
        &self,
        circuits: &[OrchardCircuit],
        instances: &[Vec<Vec<PallasFp>>],
        rng: &mut dyn BlindRng,
    ) -> Halo2Result<Vec<u8>> {
        if circuits.is_empty() || circuits.len() != instances.len() {
            return Err(Halo2Error::operation_failed(
                "prover::create",
                "circuit/instance mismatch",
            ));
        }
        let mut transcript = TranscriptWriter::new()?;
        let queries = self.build_queries_sync(circuits, instances, &mut transcript, &mut *rng)?;
        PolyMultiopen::create_proof(&self.params, &mut transcript, &queries, &mut *rng)?;
        Ok(transcript.into_bytes())
    }

    fn build_queries_sync(
        &self,
        circuits: &[OrchardCircuit],
        instances: &[Vec<Vec<PallasFp>>],
        transcript: &mut TranscriptWriter,
        rng: &mut dyn BlindRng,
    ) -> Halo2Result<Vec<ProverQuery>> {
        let pk = &self.proving_key;
        pk.vk.hash_into(transcript)?;
        let instance = self.build_instances_sync(instances, transcript)?;
        let advice = self.build_advice_sync(circuits, instances, transcript, rng)?;
        let mut leaves = AstLeaves::build(pk, advice, instance);
        let theta = transcript.squeeze_challenge()?;

        // Lookups (permuted).
        let mut lookups: Vec<Vec<LookupPermuted>> = Vec::with_capacity(leaves.instance.len());
        {
            let fixed_values = leaves.fixed_values.clone();
            let fixed_cosets = leaves.fixed_cosets.clone();
            for pi in 0..leaves.instance.len() {
                let adv_vals = leaves.advice_values[pi].clone();
                let inst_vals = leaves.instance_values[pi].clone();
                let adv_cos = leaves.advice_cosets[pi].clone();
                let inst_cos = leaves.instance_cosets[pi].clone();
                let mut per_proof = Vec::with_capacity(pk.vk.cs.lookups.len());
                for argument in pk.vk.cs.lookups.iter() {
                    per_proof.push(argument.commit_permuted(
                        pk,
                        &self.params,
                        &pk.vk.domain,
                        &mut leaves.value_evaluator,
                        &mut leaves.coset_evaluator,
                        theta,
                        &adv_vals,
                        &fixed_values,
                        &inst_vals,
                        &adv_cos,
                        &fixed_cosets,
                        &inst_cos,
                        transcript,
                        rng,
                    )?);
                }
                lookups.push(per_proof);
            }
        }

        let beta = transcript.squeeze_challenge()?;
        let gamma = transcript.squeeze_challenge()?;

        // Permutations (committed).
        let mut permutations: Vec<PermutationCommitted> = Vec::with_capacity(leaves.instance.len());
        for pi in 0..leaves.instance.len() {
            let adv = leaves.advice[pi].advice_values.clone();
            let inst = leaves.instance[pi].instance_values.clone();
            permutations.push(pk.vk.cs.permutation.commit(
                &self.params,
                pk,
                &pk.permutation,
                &adv,
                &pk.fixed_values,
                &inst,
                beta,
                gamma,
                &mut leaves.coset_evaluator,
                transcript,
                rng,
            )?);
        }

        // Lookup products (committed).
        let mut lookups_committed: Vec<Vec<LookupCommitted>> = Vec::with_capacity(lookups.len());
        for group in lookups.iter() {
            let mut inner = Vec::with_capacity(group.len());
            for lookup in group.iter() {
                inner.push(lookup.commit_product(
                    pk,
                    &self.params,
                    beta,
                    gamma,
                    &mut leaves.coset_evaluator,
                    transcript,
                    rng,
                )?);
            }
            lookups_committed.push(inner);
        }

        let vanishing = VanishingCommitted::commit(&self.params, &pk.vk.domain, transcript, rng)?;
        let y = transcript.squeeze_challenge()?;

        // Permutation expressions.
        let mut perm_constructed = Vec::with_capacity(permutations.len());
        let mut perm_exprs: Vec<Vec<Ast>> = Vec::with_capacity(permutations.len());
        for (pi, perm) in permutations.iter().enumerate() {
            let adv_cos = leaves.advice_cosets[pi].clone();
            let inst_cos = leaves.instance_cosets[pi].clone();
            let fixed_cosets = leaves.fixed_cosets.clone();
            let perm_cos = leaves.permutation_cosets.clone();
            let (constructed, exprs) = perm.construct(
                pk,
                &pk.vk.cs.permutation,
                &adv_cos,
                &fixed_cosets,
                &inst_cos,
                &perm_cos,
                &leaves.l0,
                &leaves.l_blind,
                &leaves.l_last,
                beta,
                gamma,
            )?;
            perm_constructed.push(constructed);
            perm_exprs.push(exprs);
        }

        // Lookup expressions.
        let mut lookup_constructed: Vec<Vec<LookupConstructed>> =
            Vec::with_capacity(lookups_committed.len());
        let mut lookup_exprs: Vec<Vec<Vec<Ast>>> = Vec::with_capacity(lookups_committed.len());
        for group in lookups_committed.iter() {
            let mut cs = Vec::with_capacity(group.len());
            let mut es = Vec::with_capacity(group.len());
            for lookup in group.iter() {
                let (c, e) =
                    lookup.construct(beta, gamma, &leaves.l0, &leaves.l_blind, &leaves.l_last);
                cs.push(c);
                es.push(e);
            }
            lookup_constructed.push(cs);
            lookup_exprs.push(es);
        }

        // Gate expressions (per proof).
        let mut expressions: Vec<Ast> = Vec::new();
        for pi in 0..leaves.advice_cosets.len() {
            let advice = leaves.advice_cosets[pi].clone();
            let instance = leaves.instance_cosets[pi].clone();
            let fixed = leaves.fixed_cosets.clone();
            for gate in pk.vk.cs.gates.iter() {
                for poly in gate.polys.iter() {
                    expressions.push(expr_to_extended_ast(poly, &fixed, &advice, &instance)?);
                }
            }
            expressions.extend(perm_exprs[pi].iter().cloned());
            for group in lookup_exprs[pi].iter() {
                expressions.extend(group.iter().cloned());
            }
        }

        let constructed_vanishing = vanishing.construct(
            &self.params,
            &pk.vk.domain,
            &leaves.coset_evaluator,
            expressions,
            y,
            transcript,
            rng,
            None,
        )?;
        let x = transcript.squeeze_challenge()?;

        // Evaluations at x.
        let xn = pow_n(x, self.params.n);
        for inst in leaves.instance.iter() {
            for q in pk.vk.cs.instance_queries.iter() {
                let eval = eval_polynomial(
                    &inst.instance_polys[q.0.index].values,
                    pk.vk.domain.rotate_omega(x, q.1),
                );
                transcript.write_scalar_le(&eval.to_le_bytes())?;
            }
        }
        for adv in leaves.advice.iter() {
            for q in pk.vk.cs.advice_queries.iter() {
                let eval = eval_polynomial(
                    &adv.advice_polys[q.0.index].values,
                    pk.vk.domain.rotate_omega(x, q.1),
                );
                transcript.write_scalar_le(&eval.to_le_bytes())?;
            }
        }
        for q in pk.vk.cs.fixed_queries.iter() {
            let eval = eval_polynomial(
                &pk.fixed_polys[q.0.index].values,
                pk.vk.domain.rotate_omega(x, q.1),
            );
            transcript.write_scalar_le(&eval.to_le_bytes())?;
        }
        let evaluated_vanishing =
            constructed_vanishing.evaluate(x, xn, &pk.vk.domain, transcript)?;

        pk.permutation.evaluate(x, transcript)?;
        let mut evaluated_permutations = Vec::with_capacity(perm_constructed.len());
        for c in perm_constructed.into_iter() {
            evaluated_permutations.push(c.evaluate(pk, x, transcript)?);
        }
        let mut evaluated_lookups: Vec<Vec<LookupEvaluated>> =
            Vec::with_capacity(lookup_constructed.len());
        for group in lookup_constructed.into_iter() {
            let mut inner = Vec::with_capacity(group.len());
            for c in group.into_iter() {
                inner.push(c.evaluate(pk, x, transcript)?);
            }
            evaluated_lookups.push(inner);
        }

        // Queries.
        let mut prover_queries: Vec<ProverQuery> = Vec::new();
        for i in 0..leaves.instance.len() {
            for q in pk.vk.cs.instance_queries.iter() {
                prover_queries.push(ProverQuery {
                    point: pk.vk.domain.rotate_omega(x, q.1),
                    poly: leaves.instance[i].instance_polys[q.0.index].clone(),
                    blind: PallasFp::one(),
                });
            }
            for q in pk.vk.cs.advice_queries.iter() {
                prover_queries.push(ProverQuery {
                    point: pk.vk.domain.rotate_omega(x, q.1),
                    poly: leaves.advice[i].advice_polys[q.0.index].clone(),
                    blind: leaves.advice[i].advice_blinds[q.0.index],
                });
            }
            prover_queries.extend(evaluated_permutations[i].open(pk, x));
            for p in evaluated_lookups[i].iter() {
                prover_queries.extend(p.open(pk, x));
            }
        }
        for q in pk.vk.cs.fixed_queries.iter() {
            prover_queries.push(ProverQuery {
                point: pk.vk.domain.rotate_omega(x, q.1),
                poly: pk.fixed_polys[q.0.index].clone(),
                blind: PallasFp::one(),
            });
        }
        prover_queries.extend(pk.permutation.open(x));
        prover_queries.extend(evaluated_vanishing.open(x));
        Ok(prover_queries)
    }

    fn build_instances_sync(
        &self,
        instances: &[Vec<Vec<PallasFp>>],
        transcript: &mut TranscriptWriter,
    ) -> Halo2Result<Vec<PolyInstanceSingle>> {
        let pk = &self.proving_key;
        let mut out = Vec::with_capacity(instances.len());
        for instance in instances.iter() {
            let mut values = Vec::with_capacity(instance.len());
            for column in instance.iter() {
                let mut poly = pk.vk.domain.empty_lagrange();
                if column.len()
                    > poly
                        .values
                        .len()
                        .saturating_sub(pk.vk.cs.blinding_factors() + 1)
                {
                    return Err(Halo2Error::operation_failed(
                        "prover::instance",
                        "too many values",
                    ));
                }
                for (i, v) in column.iter().enumerate() {
                    poly.values[i] = *v;
                }
                values.push(poly);
            }
            for poly in values.iter() {
                let commitment = self.params.commit_lagrange(poly, PallasFp::one())?;
                let cc = commitment.to_compressed()?;
                transcript.absorb_point(&cc)?;
            }
            let mut polys = Vec::with_capacity(values.len());
            let mut cosets = Vec::with_capacity(values.len());
            for poly in values.iter() {
                let coeff = pk.vk.domain.lagrange_to_coeff(poly.clone())?;
                cosets.push(pk.vk.domain.coeff_to_extended(coeff.clone())?);
                polys.push(coeff);
            }
            out.push(PolyInstanceSingle {
                instance_values: values,
                instance_polys: polys,
                instance_cosets: cosets,
            });
        }
        Ok(out)
    }

    fn build_advice_sync(
        &self,
        circuits: &[OrchardCircuit],
        instances: &[Vec<Vec<PallasFp>>],
        transcript: &mut TranscriptWriter,
        rng: &mut dyn BlindRng,
    ) -> Halo2Result<Vec<PolyAdviceSingle>> {
        let pk = &self.proving_key;
        let unusable = self.params.n - (pk.vk.cs.blinding_factors() + 1);
        let mut out = Vec::with_capacity(circuits.len());
        for (ci, circuit) in circuits.iter().enumerate() {
            let instance = instances.get(ci).ok_or_else(|| {
                Halo2Error::operation_failed("prover::advice", "missing instance")
            })?;
            let mut advice_cols = Vec::with_capacity(pk.vk.cs.num_advice_columns());
            for _ in 0..pk.vk.cs.num_advice_columns() {
                advice_cols.push(pk.vk.domain.empty_lagrange_assigned());
            }
            let mut witness = PlonkWitnessCollection {
                k: self.params.k,
                advice: advice_cols,
                instances: instance.clone(),
                usable_rows: UsableRows {
                    start: 0,
                    end: unusable,
                },
            };
            v1_synthesize(
                &mut witness,
                circuit,
                &self.config,
                pk.vk.cs.constants.clone(),
                &self.context,
            )?;
            let mut values = Polynomial::batch_invert_assigned(&witness.advice)?;
            for col in values.iter_mut() {
                for i in unusable..col.values.len() {
                    col.values[i] = rng.next_pallas();
                }
            }
            let mut blinds = Vec::with_capacity(values.len());
            for _ in 0..values.len() {
                blinds.push(rng.next_pallas());
            }
            for (poly, blind) in values.iter().zip(blinds.iter()) {
                let c = self.params.commit_lagrange(poly, *blind)?;
                transcript.write_point(&c.to_compressed()?)?;
            }

            let mut polys = Vec::with_capacity(values.len());
            let mut cosets = Vec::with_capacity(values.len());
            for poly in values.iter() {
                let coeff = pk.vk.domain.lagrange_to_coeff(poly.clone())?;
                cosets.push(pk.vk.domain.coeff_to_extended(coeff.clone())?);
                polys.push(coeff);
            }
            out.push(PolyAdviceSingle {
                advice_values: values,
                advice_polys: polys,
                advice_cosets: cosets,
                advice_blinds: blinds,
            });
        }
        Ok(out)
    }

    #[cfg(feature = "alloc")]
    pub fn to_debug_string(&self) -> String {
        alloc::string::String::from("PlonkProver")
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

fn expr_to_extended_ast(
    e: &Expression,
    fixed: &[AstLeaf],
    advice: &[AstLeaf],
    instance: &[AstLeaf],
) -> Halo2Result<Ast> {
    if e.contains_simple_selector() {
        return Err(Halo2Error::operation_failed(
            "prover::expr",
            "simple selector",
        ));
    }
    match e {
        Expression::Constant(v) => Ok(Ast::ConstantTerm(*v)),
        Expression::Selector(_) => Err(Halo2Error::operation_failed("prover::expr", "selector")),
        Expression::Fixed(q) => {
            let leaf = fixed
                .get(q.column_index)
                .copied()
                .ok_or_else(|| Halo2Error::operation_failed("prover::expr", "bad column"))?;
            Ok(Ast::Poly(leaf.with_rotation(q.rotation)))
        }
        Expression::Advice(q) => {
            let leaf = advice
                .get(q.column_index)
                .copied()
                .ok_or_else(|| Halo2Error::operation_failed("prover::expr", "bad column"))?;
            Ok(Ast::Poly(leaf.with_rotation(q.rotation)))
        }
        Expression::Instance(q) => {
            let leaf = instance
                .get(q.column_index)
                .copied()
                .ok_or_else(|| Halo2Error::operation_failed("prover::expr", "bad column"))?;
            Ok(Ast::Poly(leaf.with_rotation(q.rotation)))
        }
        Expression::Negated(p) => Ok(expr_to_extended_ast(p, fixed, advice, instance)?.neg()),
        Expression::Sum(a, b) => Ok(expr_to_extended_ast(a, fixed, advice, instance)?
            .add(&expr_to_extended_ast(b, fixed, advice, instance)?)),
        Expression::Product(a, b) => Ok(expr_to_extended_ast(a, fixed, advice, instance)?
            .mul(&expr_to_extended_ast(b, fixed, advice, instance)?)),
        Expression::Scaled(p, f) => Ok(expr_to_extended_ast(p, fixed, advice, instance)?.scale(*f)),
    }
}
