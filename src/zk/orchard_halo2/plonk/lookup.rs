//! Implements plonk/lookup logic — full lookup argument.
//! Expression→AST uses `evaluate` after a `contains_simple_selector` guard
//! (post-compress circuits carry none); the unreachable selector arm yields a
//! zero constant. Randomness via explicit `FieldRng`. No `assert!`.

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

use crate::zk::orchard_halo2::curve::VestaAffine;
use crate::zk::orchard_halo2::error::{Halo2Error, Halo2Result};
use crate::zk::orchard_halo2::field::PallasFp;
use crate::zk::orchard_halo2::plonk::expression::{Expression, Query};
use crate::zk::orchard_halo2::plonk::key::{PlonkProvingKey, PlonkVerifyingKey};
use crate::zk::orchard_halo2::poly::domain::EvaluationDomain;
use crate::zk::orchard_halo2::poly::evaluator::{Ast, AstLeaf, Evaluator};
use crate::zk::orchard_halo2::poly::multiopen::{ProverQuery, VerifierQuery};
use crate::zk::orchard_halo2::poly::params::PolyParams;
use crate::zk::orchard_halo2::poly::poly::{Polynomial, Rotation};
use crate::zk::orchard_halo2::rng::BlindRng;

use crate::zk::orchard_halo2::transcript::transcript::{TranscriptReader, TranscriptWriter};
use crate::zk::orchard_halo2::utility::utils::{batch_invert, eval_polynomial};

#[derive(Clone, PartialEq, Eq)]
pub struct LookupArgument {
    pub input_expressions: Vec<Expression>,
    pub table_expressions: Vec<Expression>,
}

impl LookupArgument {
    pub fn new(inputs: Vec<Expression>, tables: Vec<Expression>) -> Self {
        Self {
            input_expressions: inputs,
            table_expressions: tables,
        }
    }

    #[cfg(feature = "alloc")]
    pub fn to_debug_string(&self) -> String {
        let ins: Vec<String> = self
            .input_expressions
            .iter()
            .map(|e| e.to_debug_string())
            .collect();
        let tab: Vec<String> = self
            .table_expressions
            .iter()
            .map(|e| e.to_debug_string())
            .collect();
        alloc::format!(
            "Argument {{ input_expressions: [{}], table_expressions: [{}] }}",
            ins.join(", "),
            tab.join(", ")
        )
    }

    pub fn required_degree(&self) -> Halo2Result<usize> {
        if self.input_expressions.len() != self.table_expressions.len() {
            return Err(Halo2Error::operation_failed(
                "lookup::degree",
                "length mismatch",
            ));
        }
        let mut input_degree = 1usize;
        for e in self.input_expressions.iter() {
            input_degree = core::cmp::max(input_degree, e.degree());
        }
        let mut table_degree = 1usize;
        for e in self.table_expressions.iter() {
            table_degree = core::cmp::max(table_degree, e.degree());
        }
        let computed = 2 + input_degree + table_degree;
        Ok(if computed > 4 { computed } else { 4 })
    }

    pub fn read_permuted_commitments(
        &self,
        transcript: &mut TranscriptReader<'_>,
    ) -> Halo2Result<LookPermutationCommitments> {
        Ok(LookPermutationCommitments {
            input_commitment: VestaAffine::from_compressed(&transcript.read_point()?)?,
            table_commitment: VestaAffine::from_compressed(&transcript.read_point()?)?,
        })
    }

    /// Compress + permute + commit (prover side).
    #[allow(clippy::too_many_arguments)]
    pub fn commit_permuted(
        &self,
        pk: &PlonkProvingKey,
        params: &PolyParams,
        domain: &EvaluationDomain,
        value_evaluator: &mut Evaluator,
        coset_evaluator: &mut Evaluator,
        theta: PallasFp,
        advice_values: &[AstLeaf],
        fixed_values: &[AstLeaf],
        instance_values: &[AstLeaf],
        advice_cosets: &[AstLeaf],
        fixed_cosets: &[AstLeaf],
        instance_cosets: &[AstLeaf],
        transcript: &mut TranscriptWriter,
        rng: &mut dyn BlindRng,
    ) -> Halo2Result<LookupPermuted> {
        for e in self
            .input_expressions
            .iter()
            .chain(self.table_expressions.iter())
        {
            if e.contains_simple_selector() {
                return Err(Halo2Error::operation_failed(
                    "lookup::compress",
                    "simple selector present",
                ));
            }
        }
        let input_c = compress_expressions(
            &self.input_expressions,
            fixed_values,
            advice_values,
            instance_values,
            fixed_cosets,
            advice_cosets,
            instance_cosets,
            theta,
            value_evaluator,
            coset_evaluator,
            domain,
        )?;
        let table_c = compress_expressions(
            &self.table_expressions,
            fixed_values,
            advice_values,
            instance_values,
            fixed_cosets,
            advice_cosets,
            instance_cosets,
            theta,
            value_evaluator,
            coset_evaluator,
            domain,
        )?;
        let (permuted_input_expr, permuted_table_expr) =
            Self::permute_expression_pair(pk, params, domain, &input_c.0, &table_c.0, rng)?;

        let mut commit_values = |values: Polynomial<PallasFp>| -> Halo2Result<(Polynomial<PallasFp>, PallasFp, VestaAffine)> {
            let poly = domain.lagrange_to_coeff(values.clone())?;
            let blind = rng.next_pallas();
            let commitment = params.commit_lagrange(&values, blind)?;
            let (x, y, ident) = commitment.to_affine_le()?;
            Ok((
                poly,
                blind,
                if ident { VestaAffine::identity() } else { VestaAffine::from_le_xy(x, y)? },
            ))
        };
        let (in_poly, in_blind, in_commit) = commit_values(permuted_input_expr.clone())?;
        let (tab_poly, tab_blind, tab_commit) = commit_values(permuted_table_expr.clone())?;
        transcript.write_point(&in_commit.to_compressed()?)?;
        transcript.write_point(&tab_commit.to_compressed()?)?;
        let in_coset = coset_evaluator.register_poly(domain.coeff_to_extended(in_poly.clone())?);
        let tab_coset = coset_evaluator.register_poly(domain.coeff_to_extended(tab_poly.clone())?);
        Ok(LookupPermuted {
            compressed_input_expression: input_c.0,
            compressed_input_coset: input_c.1,
            permuted_input_expression: permuted_input_expr,
            permuted_input_poly: in_poly,
            permuted_input_coset: in_coset,
            permuted_input_blind: in_blind,
            compressed_table_expression: table_c.0,
            compressed_table_coset: table_c.1,
            permuted_table_expression: permuted_table_expr,
            permuted_table_poly: tab_poly,
            permuted_table_coset: tab_coset,
            permuted_table_blind: tab_blind,
        })
    }

    pub fn permute_expression_pair(
        pk: &PlonkProvingKey,
        params: &PolyParams,
        domain: &EvaluationDomain,
        input_expression: &Polynomial<PallasFp>,
        table_expression: &Polynomial<PallasFp>,
        rng: &mut dyn BlindRng,
    ) -> Halo2Result<(Polynomial<PallasFp>, Polynomial<PallasFp>)> {
        let blinding = pk.vk.cs.blinding_factors();
        let usable = params.n.saturating_sub(blinding + 1);
        if input_expression.values.len() < usable || table_expression.values.len() < usable {
            return Err(Halo2Error::operation_failed(
                "lookup::permute",
                "short poly",
            ));
        }
        let mut permuted_input: Vec<PallasFp> = input_expression.values[..usable].to_vec();
        permuted_input.sort();
        // Leftover table multiset (value → count), iterated smallest-first
        // (mirrors the reference implementation
        // O(log n) ops instead of linear scans with field compares.
        let mut leftover: alloc::collections::BTreeMap<PallasFp, usize> =
            alloc::collections::BTreeMap::new();
        for v in table_expression.values[..usable].iter() {
            *leftover.entry(*v).or_insert(0) += 1;
        }
        let mut permuted_table = vec![PallasFp::zero(); usable];
        let mut repeated: Vec<usize> = Vec::new();
        for (row, input_value) in permuted_input.iter().enumerate() {
            if row == 0 || *input_value != permuted_input[row - 1] {
                permuted_table[row] = *input_value;
                let entry = leftover
                    .get_mut(input_value)
                    .ok_or_else(|| Halo2Error::operation_failed("lookup::permute", "table miss"))?;
                if *entry == 0 {
                    return Err(Halo2Error::operation_failed(
                        "lookup::permute",
                        "table miss",
                    ));
                }
                *entry -= 1;
                if *entry == 0 {
                    leftover.remove(input_value);
                }
            } else {
                repeated.push(row);
            }
        }
        for (coeff, count) in leftover.into_iter() {
            for _ in 0..count {
                let row = repeated.pop().ok_or_else(|| {
                    Halo2Error::operation_failed("lookup::permute", "leftover overflow")
                })?;
                permuted_table[row] = coeff;
            }
        }
        if !repeated.is_empty() {
            return Err(Halo2Error::operation_failed(
                "lookup::permute",
                "repeated remain",
            ));
        }
        for _ in 0..blinding + 1 {
            permuted_input.push(rng.next_pallas());
        }
        for _ in 0..blinding + 1 {
            permuted_table.push(rng.next_pallas());
        }
        if permuted_input.len() != params.n || permuted_table.len() != params.n {
            return Err(Halo2Error::operation_failed(
                "lookup::permute",
                "length mismatch",
            ));
        }
        Ok((
            domain.lagrange_from_vec(permuted_input)?,
            domain.lagrange_from_vec(permuted_table)?,
        ))
    }
}

#[allow(clippy::too_many_arguments)] // Gate API mirrors upstream halo2 circuit signatures; regrouping args would churn call sites.
fn compress_expressions(
    expressions: &[Expression],
    fixed_values: &[AstLeaf],
    advice_values: &[AstLeaf],
    instance_values: &[AstLeaf],
    fixed_cosets: &[AstLeaf],
    advice_cosets: &[AstLeaf],
    instance_cosets: &[AstLeaf],
    theta: PallasFp,
    value_evaluator: &mut Evaluator,
    coset_evaluator: &mut Evaluator,
    domain: &EvaluationDomain,
) -> Halo2Result<(Polynomial<PallasFp>, Ast)> {
    let mut value_asts: Vec<Ast> = Vec::with_capacity(expressions.len());
    let mut coset_asts: Vec<Ast> = Vec::with_capacity(expressions.len());
    for e in expressions.iter() {
        value_asts.push(expr_to_value_ast(
            e,
            fixed_values,
            advice_values,
            instance_values,
        )?);
        coset_asts.push(expr_to_coset_ast(
            e,
            fixed_cosets,
            advice_cosets,
            instance_cosets,
        )?);
    }
    let mut compressed_expr = Ast::ConstantTerm(PallasFp::zero());
    for expr in value_asts.into_iter() {
        compressed_expr = compressed_expr.mul(&Ast::ConstantTerm(theta)).add(&expr);
    }
    let mut compressed_coset = Ast::ConstantTerm(PallasFp::zero());
    for expr in coset_asts.into_iter() {
        compressed_coset = compressed_coset.mul(&Ast::ConstantTerm(theta)).add(&expr);
    }
    let poly = value_evaluator.evaluate(&compressed_expr, domain)?;
    let _ = coset_evaluator;
    Ok((poly, compressed_coset))
}

fn expr_to_value_ast(
    e: &Expression,
    fixed_values: &[AstLeaf],
    advice_values: &[AstLeaf],
    instance_values: &[AstLeaf],
) -> Halo2Result<Ast> {
    match e {
        Expression::Constant(v) => Ok(Ast::ConstantTerm(*v)),
        Expression::Selector(_) => {
            Err(Halo2Error::operation_failed("lookup::compress", "selector"))
        }
        Expression::Fixed(q) => {
            let leaf = fixed_values
                .get(q.column_index)
                .copied()
                .ok_or_else(|| Halo2Error::operation_failed("lookup::compress", "bad column"))?;
            Ok(Ast::Poly(leaf.with_rotation(q.rotation)))
        }
        Expression::Advice(q) => {
            let leaf = advice_values
                .get(q.column_index)
                .copied()
                .ok_or_else(|| Halo2Error::operation_failed("lookup::compress", "bad column"))?;
            Ok(Ast::Poly(leaf.with_rotation(q.rotation)))
        }
        Expression::Instance(q) => {
            let leaf = instance_values
                .get(q.column_index)
                .copied()
                .ok_or_else(|| Halo2Error::operation_failed("lookup::compress", "bad column"))?;
            Ok(Ast::Poly(leaf.with_rotation(q.rotation)))
        }
        Expression::Negated(p) => {
            Ok(expr_to_value_ast(p, fixed_values, advice_values, instance_values)?.neg())
        }
        Expression::Sum(a, b) => {
            Ok(
                expr_to_value_ast(a, fixed_values, advice_values, instance_values)?.add(
                    &expr_to_value_ast(b, fixed_values, advice_values, instance_values)?,
                ),
            )
        }
        Expression::Product(a, b) => {
            Ok(
                expr_to_value_ast(a, fixed_values, advice_values, instance_values)?.mul(
                    &expr_to_value_ast(b, fixed_values, advice_values, instance_values)?,
                ),
            )
        }
        Expression::Scaled(p, f) => {
            Ok(expr_to_value_ast(p, fixed_values, advice_values, instance_values)?.scale(*f))
        }
    }
}

fn expr_to_coset_ast(
    e: &Expression,
    fixed_cosets: &[AstLeaf],
    advice_cosets: &[AstLeaf],
    instance_cosets: &[AstLeaf],
) -> Halo2Result<Ast> {
    match e {
        Expression::Constant(v) => Ok(Ast::ConstantTerm(*v)),
        Expression::Selector(_) => {
            Err(Halo2Error::operation_failed("lookup::compress", "selector"))
        }
        Expression::Fixed(q) => {
            let leaf = fixed_cosets
                .get(q.column_index)
                .copied()
                .ok_or_else(|| Halo2Error::operation_failed("lookup::compress", "bad column"))?;
            Ok(Ast::Poly(leaf.with_rotation(q.rotation)))
        }
        Expression::Advice(q) => {
            let leaf = advice_cosets
                .get(q.column_index)
                .copied()
                .ok_or_else(|| Halo2Error::operation_failed("lookup::compress", "bad column"))?;
            Ok(Ast::Poly(leaf.with_rotation(q.rotation)))
        }
        Expression::Instance(q) => {
            let leaf = instance_cosets
                .get(q.column_index)
                .copied()
                .ok_or_else(|| Halo2Error::operation_failed("lookup::compress", "bad column"))?;
            Ok(Ast::Poly(leaf.with_rotation(q.rotation)))
        }
        Expression::Negated(p) => {
            Ok(expr_to_coset_ast(p, fixed_cosets, advice_cosets, instance_cosets)?.neg())
        }
        Expression::Sum(a, b) => {
            Ok(
                expr_to_coset_ast(a, fixed_cosets, advice_cosets, instance_cosets)?.add(
                    &expr_to_coset_ast(b, fixed_cosets, advice_cosets, instance_cosets)?,
                ),
            )
        }
        Expression::Product(a, b) => {
            Ok(
                expr_to_coset_ast(a, fixed_cosets, advice_cosets, instance_cosets)?.mul(
                    &expr_to_coset_ast(b, fixed_cosets, advice_cosets, instance_cosets)?,
                ),
            )
        }
        Expression::Scaled(p, f) => {
            Ok(expr_to_coset_ast(p, fixed_cosets, advice_cosets, instance_cosets)?.scale(*f))
        }
    }
}

#[derive(Clone)]
pub struct LookupPermuted {
    pub compressed_input_expression: Polynomial<PallasFp>,
    pub permuted_input_expression: Polynomial<PallasFp>,
    pub compressed_input_coset: Ast,
    pub permuted_input_poly: Polynomial<PallasFp>,
    pub permuted_input_coset: AstLeaf,
    pub permuted_input_blind: PallasFp,
    pub compressed_table_expression: Polynomial<PallasFp>,
    pub compressed_table_coset: Ast,
    pub permuted_table_expression: Polynomial<PallasFp>,
    pub permuted_table_poly: Polynomial<PallasFp>,
    pub permuted_table_coset: AstLeaf,
    pub permuted_table_blind: PallasFp,
}

impl LookupPermuted {
    #[allow(clippy::too_many_arguments)] // Gate API mirrors upstream halo2 circuit signatures; regrouping args would churn call sites.
    pub fn commit_product(
        &self,
        pk: &PlonkProvingKey,
        params: &PolyParams,
        beta: PallasFp,
        gamma: PallasFp,
        evaluator: &mut Evaluator,
        transcript: &mut TranscriptWriter,
        rng: &mut dyn BlindRng,
    ) -> Halo2Result<LookupCommitted> {
        let blinding = pk.vk.cs.blinding_factors();
        let mut product: Vec<PallasFp> = Vec::with_capacity(params.n);
        for start in 0..params.n {
            let iv = self.permuted_input_expression.values[start];
            let tv = self.permuted_table_expression.values[start];
            product.push(beta.add_vartime(&iv).mul_vartime(&gamma.add_vartime(&tv)));
        }
        batch_invert(&mut product)?;
        for (i, v) in product.iter_mut().enumerate() {
            let it = self.compressed_input_expression.values[i];
            let tt = self.compressed_table_expression.values[i];
            *v = v.mul_vartime(&it.add_vartime(&beta).mul_vartime(&tt.add_vartime(&gamma)));
        }
        let mut z_list: Vec<PallasFp> = Vec::with_capacity(params.n + 1);
        z_list.push(PallasFp::one());
        let mut state = PallasFp::one();
        for cur in product.into_iter() {
            state = state.mul_vartime(&cur);
            z_list.push(state);
        }
        let usable = params.n.saturating_sub(blinding);
        let mut z_final: Vec<PallasFp> = z_list.into_iter().take(usable).collect();
        for _ in 0..blinding {
            z_final.push(rng.next_pallas());
        }
        let z = pk.vk.domain.lagrange_from_vec(z_final)?;
        let blind = rng.next_pallas();
        let commitment = params.commit_lagrange(&z, blind)?;
        let z_coeff = pk.vk.domain.lagrange_to_coeff(z)?;
        let coset = evaluator.register_poly(pk.vk.domain.coeff_to_extended(z_coeff.clone())?);
        transcript.write_point(&commitment.to_compressed()?)?;
        Ok(LookupCommitted {
            permuted: self.clone(),
            product_poly: z_coeff,
            product_coset: coset,
            product_blind: blind,
        })
    }
}

#[derive(Clone)]
pub struct LookupConstructed {
    pub permuted_input_poly: Polynomial<PallasFp>,
    pub permuted_input_blind: PallasFp,
    pub permuted_table_poly: Polynomial<PallasFp>,
    pub permuted_table_blind: PallasFp,
    pub product_poly: Polynomial<PallasFp>,
    pub product_blind: PallasFp,
}

impl LookupConstructed {
    pub fn evaluate(
        &self,
        pk: &PlonkProvingKey,
        x: PallasFp,
        transcript: &mut TranscriptWriter,
    ) -> Halo2Result<LookupEvaluated> {
        let domain = &pk.vk.domain;
        let x_inv = domain.rotate_omega(x, Rotation { location: -1 });
        let x_next = domain.rotate_omega(x, Rotation::next());
        let vals = [
            eval_polynomial(&self.product_poly.values, x),
            eval_polynomial(&self.product_poly.values, x_next),
            eval_polynomial(&self.permuted_input_poly.values, x),
            eval_polynomial(&self.permuted_input_poly.values, x_inv),
            eval_polynomial(&self.permuted_table_poly.values, x),
        ];
        for v in vals.iter() {
            transcript.write_scalar_le(&v.to_le_bytes())?;
        }
        Ok(LookupEvaluated {
            constructed: self.clone_for_eval(),
        })
    }

    fn clone_for_eval(&self) -> LookupConstructedEval {
        LookupConstructedEval {
            permuted_input_poly: self.permuted_input_poly.clone(),
            permuted_input_blind: self.permuted_input_blind,
            permuted_table_poly: self.permuted_table_poly.clone(),
            permuted_table_blind: self.permuted_table_blind,
            product_poly: self.product_poly.clone(),
            product_blind: self.product_blind,
        }
    }
}

#[derive(Clone)]
pub struct LookupConstructedEval {
    pub permuted_input_poly: Polynomial<PallasFp>,
    pub permuted_input_blind: PallasFp,
    pub permuted_table_poly: Polynomial<PallasFp>,
    pub permuted_table_blind: PallasFp,
    pub product_poly: Polynomial<PallasFp>,
    pub product_blind: PallasFp,
}

#[derive(Clone)]
pub struct LookupEvaluated {
    pub constructed: LookupConstructedEval,
}

impl LookupEvaluated {
    pub fn open(&self, pk: &PlonkProvingKey, x: PallasFp) -> Vec<ProverQuery> {
        let x_inv = pk.vk.domain.rotate_omega(x, Rotation { location: -1 });
        let x_next = pk.vk.domain.rotate_omega(x, Rotation::next());
        let c = &self.constructed;
        vec![
            ProverQuery {
                point: x,
                poly: c.product_poly.clone(),
                blind: c.product_blind,
            },
            ProverQuery {
                point: x,
                poly: c.permuted_input_poly.clone(),
                blind: c.permuted_input_blind,
            },
            ProverQuery {
                point: x,
                poly: c.permuted_table_poly.clone(),
                blind: c.permuted_table_blind,
            },
            ProverQuery {
                point: x_inv,
                poly: c.permuted_input_poly.clone(),
                blind: c.permuted_input_blind,
            },
            ProverQuery {
                point: x_next,
                poly: c.product_poly.clone(),
                blind: c.product_blind,
            },
        ]
    }
}

#[derive(Clone)]
pub struct LookupCommitted {
    pub permuted: LookupPermuted,
    pub product_poly: Polynomial<PallasFp>,
    pub product_coset: AstLeaf,
    pub product_blind: PallasFp,
}

impl LookupCommitted {
    pub fn construct(
        &self,
        beta: PallasFp,
        gamma: PallasFp,
        l0: &AstLeaf,
        l_blind: &AstLeaf,
        l_last: &AstLeaf,
    ) -> (LookupConstructed, Vec<Ast>) {
        let one = || Ast::ConstantTerm(PallasFp::one());
        let beta_ast = Ast::ConstantTerm(beta);
        let gamma_ast = Ast::ConstantTerm(gamma);
        let mut expressions = Vec::new();
        expressions.push(
            one()
                .sub(&Ast::Poly(self.product_coset))
                .mul(&Ast::Poly(*l0)),
        );
        expressions.push(
            Ast::Poly(self.product_coset)
                .mul(&Ast::Poly(self.product_coset))
                .sub(&Ast::Poly(self.product_coset))
                .mul(&Ast::Poly(*l_last)),
        );
        let left = Ast::Poly(self.product_coset.with_rotation(Rotation::next()))
            .mul(&Ast::Poly(self.permuted.permuted_input_coset).add(&beta_ast))
            .mul(&Ast::Poly(self.permuted.permuted_table_coset).add(&gamma_ast));
        let right = Ast::Poly(self.product_coset)
            .mul(&self.permuted.compressed_input_coset.add(&beta_ast))
            .mul(&self.permuted.compressed_table_coset.add(&gamma_ast));
        let active = one().sub(&Ast::Poly(*l_last).add(&Ast::Poly(*l_blind)));
        expressions.push(left.sub(&right).mul(&active));
        expressions.push(
            Ast::Poly(self.permuted.permuted_input_coset)
                .sub(&Ast::Poly(self.permuted.permuted_table_coset))
                .mul(&Ast::Poly(*l0)),
        );
        expressions.push(
            Ast::Poly(self.permuted.permuted_input_coset)
                .sub(&Ast::Poly(self.permuted.permuted_table_coset))
                .mul(
                    &Ast::Poly(self.permuted.permuted_input_coset).sub(&Ast::Poly(
                        self.permuted
                            .permuted_input_coset
                            .with_rotation(Rotation { location: -1 }),
                    )),
                )
                .mul(&active),
        );
        (
            LookupConstructed {
                permuted_input_poly: self.permuted.permuted_input_poly.clone(),
                permuted_input_blind: self.permuted.permuted_input_blind,
                permuted_table_poly: self.permuted.permuted_table_poly.clone(),
                permuted_table_blind: self.permuted.permuted_table_blind,
                product_poly: self.product_poly.clone(),
                product_blind: self.product_blind,
            },
            expressions,
        )
    }
}

#[derive(Clone, Copy)]
pub struct LookPermutationCommitments {
    pub input_commitment: VestaAffine,
    pub table_commitment: VestaAffine,
}

impl LookPermutationCommitments {
    pub fn read_product_commitment(
        &self,
        transcript: &mut TranscriptReader<'_>,
    ) -> Halo2Result<LookupVerifyCommitted> {
        Ok(LookupVerifyCommitted {
            commitment: VestaAffine::from_compressed(&transcript.read_point()?)?,
            permuted: *self,
        })
    }
}

#[derive(Clone, Copy)]
pub struct LookupVerifyCommitted {
    pub commitment: VestaAffine,
    pub permuted: LookPermutationCommitments,
}

impl LookupVerifyCommitted {
    pub fn evaluate(
        &self,
        transcript: &mut TranscriptReader<'_>,
    ) -> Halo2Result<LookupVerifyEvaluated> {
        let mut scalars = Vec::with_capacity(5);
        for _ in 0..5 {
            scalars.push(PallasFp::from_le_array(&transcript.read_scalar_le()?)?);
        }
        Ok(LookupVerifyEvaluated {
            committed: *self,
            eval: scalars[0],
            next_eval: scalars[1],
            input_eval: scalars[2],
            input_inv_eval: scalars[3],
            table_eval: scalars[4],
        })
    }
}

#[derive(Clone, Copy)]
pub struct LookupVerifyEvaluated {
    pub committed: LookupVerifyCommitted,
    pub eval: PallasFp,
    pub next_eval: PallasFp,
    pub input_eval: PallasFp,
    pub input_inv_eval: PallasFp,
    pub table_eval: PallasFp,
}

impl LookupVerifyEvaluated {
    #[allow(clippy::too_many_arguments)] // Gate API mirrors upstream halo2 circuit signatures; regrouping args would churn call sites.
    pub fn expressions(
        &self,
        l0: PallasFp,
        l_last: PallasFp,
        l_blind: PallasFp,
        argument: &LookupArgument,
        theta: PallasFp,
        beta: PallasFp,
        gamma: PallasFp,
        advice_evals: &[PallasFp],
        fixed_evals: &[PallasFp],
        instance_evals: &[PallasFp],
    ) -> Halo2Result<Vec<PallasFp>> {
        for e in argument
            .input_expressions
            .iter()
            .chain(argument.table_expressions.iter())
        {
            if e.contains_simple_selector() {
                return Err(Halo2Error::operation_failed(
                    "lookup_verify::expr",
                    "selector",
                ));
            }
        }
        let compress = |exprs: &[Expression]| -> Halo2Result<PallasFp> {
            let mut acc = PallasFp::zero();
            for e in exprs.iter() {
                let v = e.evaluate(
                    &|s| s,
                    &|_| PallasFp::zero(),
                    &|q: Query| {
                        fixed_evals
                            .get(q.index)
                            .copied()
                            .unwrap_or(PallasFp::zero())
                    },
                    &|q: Query| {
                        advice_evals
                            .get(q.index)
                            .copied()
                            .unwrap_or(PallasFp::zero())
                    },
                    &|q: Query| {
                        instance_evals
                            .get(q.index)
                            .copied()
                            .unwrap_or(PallasFp::zero())
                    },
                    &|a| a.neg(),
                    &|a, b| a.add_vartime(&b),
                    &|a, b| a.mul_vartime(&b),
                    &|a, s| a.mul_vartime(&s),
                );
                acc = acc.mul_vartime(&theta).add_vartime(&v);
            }
            Ok(acc)
        };
        let active = PallasFp::one().sub_vartime(&l_last.add_vartime(&l_blind));
        let mut out = Vec::with_capacity(5);
        out.push(l0.mul_vartime(&PallasFp::one().sub_vartime(&self.eval)));
        out.push(l_last.mul_vartime(&self.eval.square_vartime().sub_vartime(&self.eval)));
        let left = self
            .next_eval
            .mul_vartime(&self.input_eval.add_vartime(&beta))
            .mul_vartime(&self.table_eval.add_vartime(&gamma));
        let right = self
            .eval
            .mul_vartime(&compress(&argument.input_expressions)?.add_vartime(&beta))
            .mul_vartime(&compress(&argument.table_expressions)?.add_vartime(&gamma));
        out.push(left.sub_vartime(&right).mul_vartime(&active));
        out.push(l0.mul_vartime(&self.input_eval.sub_vartime(&self.table_eval)));
        out.push(
            self.input_eval
                .sub_vartime(&self.table_eval)
                .mul_vartime(&self.input_eval.sub_vartime(&self.input_inv_eval))
                .mul_vartime(&active),
        );
        Ok(out)
    }

    pub fn queries(self, vk: &PlonkVerifyingKey, x: PallasFp) -> Vec<VerifierQuery<'_>> {
        use crate::zk::orchard_halo2::poly::commitment::commitment::CommitmentReference;
        let x_inv = vk.domain.rotate_omega(x, Rotation { location: -1 });
        let x_next = vk.domain.rotate_omega(x, Rotation::next());
        let c = |aff: VestaAffine, point: PallasFp, eval: PallasFp| VerifierQuery {
            point,
            commitment: CommitmentReference::Commitment(aff),
            eval,
        };
        vec![
            c(self.committed.commitment, x, self.eval),
            c(self.committed.permuted.input_commitment, x, self.input_eval),
            c(self.committed.permuted.table_commitment, x, self.table_eval),
            c(
                self.committed.permuted.input_commitment,
                x_inv,
                self.input_inv_eval,
            ),
            c(self.committed.commitment, x_next, self.next_eval),
        ]
    }
}
