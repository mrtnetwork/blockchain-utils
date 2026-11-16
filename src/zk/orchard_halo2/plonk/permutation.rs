//! Implements plonk/permutation logic (full: assembly, commit rounds,
//! construction, verification expressions).
//! Randomness via explicit `FieldRng`. `assert!` on `cs_degree` becomes
//! `Err`. Column chunking mirrors `CompareUtils.chunk`.

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

use crate::zk::orchard_halo2::curve::{msm_vesta, VestaAffine};
use crate::zk::orchard_halo2::error::{Halo2Error, Halo2Result};
use crate::zk::orchard_halo2::field::PallasFp;
use crate::zk::orchard_halo2::plonk::column::{AnyAssignmentColumn, AnyColumn};
use crate::zk::orchard_halo2::plonk::key::{PlonkProvingKey, PlonkVerifyingKey};
use crate::zk::orchard_halo2::poly::domain::EvaluationDomain;
use crate::zk::orchard_halo2::poly::evaluator::{Ast, AstLeaf, Evaluator};
use crate::zk::orchard_halo2::poly::multiopen::{ProverQuery, VerifierQuery};
use crate::zk::orchard_halo2::poly::params::PolyParams;
use crate::zk::orchard_halo2::poly::poly::{Polynomial, Rotation};
use crate::zk::orchard_halo2::rng::BlindRng;
use crate::zk::orchard_halo2::transcript::transcript::{TranscriptReader, TranscriptWriter};
use crate::zk::orchard_halo2::utility::utils::{batch_invert, eval_polynomial};

fn chunk_of<T: Clone>(v: &[T], size: usize) -> Vec<Vec<T>> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < v.len() {
        let end = core::cmp::min(i + size.max(1), v.len());
        out.push(v[i..end].to_vec());
        i = end;
    }
    out
}

fn pow_u64_field(base: PallasFp, mut e: u64) -> PallasFp {
    let mut acc = PallasFp::one();
    let mut b = base;
    while e > 0 {
        if (e & 1) == 1 {
            acc = acc.mul_vartime(&b);
        }
        b = b.square_vartime();
        e >>= 1;
    }
    acc
}

// —— assembly ——

pub struct PermutationAssembly {
    pub columns: Vec<AnyAssignmentColumn>,
    mapping: Vec<Vec<(usize, usize)>>,
    aux: Vec<Vec<(usize, usize)>>,
    sizes: Vec<Vec<usize>>,
}

impl PermutationAssembly {
    pub fn new_assembly(n: usize, p: &PermutationArgument) -> Self {
        let mut columns_list: Vec<Vec<(usize, usize)>> = Vec::new();
        for i in 0..p.columns.len() {
            columns_list.push((0..n).map(|j| (i, j)).collect());
        }
        Self {
            columns: p.get_columns(),
            mapping: columns_list.clone(),
            aux: columns_list,
            sizes: vec![vec![1usize; n]; p.columns.len()],
        }
    }

    pub fn copy(
        &mut self,
        left_column: AnyAssignmentColumn,
        left_row: usize,
        right_column: AnyAssignmentColumn,
        right_row: usize,
    ) -> Halo2Result<()> {
        let li = self
            .columns
            .iter()
            .position(|c| *c == left_column)
            .ok_or_else(|| {
                Halo2Error::operation_failed("permutation::copy", "column not in permutation")
            })?;
        let ri = self
            .columns
            .iter()
            .position(|c| *c == right_column)
            .ok_or_else(|| {
                Halo2Error::operation_failed("permutation::copy", "column not in permutation")
            })?;
        if left_row >= self.mapping[li].len() || right_row >= self.mapping[ri].len() {
            return Err(Halo2Error::operation_failed(
                "permutation::copy",
                "row out of range",
            ));
        }
        let mut left_cycle = self.aux[li][left_row];
        let mut right_cycle = self.aux[ri][right_row];
        if left_cycle == right_cycle {
            return Ok(());
        }
        if self.sizes[left_cycle.0][left_cycle.1] < self.sizes[right_cycle.0][right_cycle.1] {
            core::mem::swap(&mut left_cycle, &mut right_cycle);
        }
        self.sizes[left_cycle.0][left_cycle.1] += self.sizes[right_cycle.0][right_cycle.1];
        let mut i = right_cycle;
        loop {
            self.aux[i.0][i.1] = left_cycle;
            i = self.mapping[i.0][i.1];
            if i == right_cycle {
                break;
            }
        }
        let tmp = self.mapping[li][left_row];
        self.mapping[li][left_row] = self.mapping[ri][right_row];
        self.mapping[ri][right_row] = tmp;
        Ok(())
    }

    fn delta_omega(&self, domain: &EvaluationDomain, n: usize, cols: usize) -> Vec<Vec<PallasFp>> {
        let mut omega_powers = vec![PallasFp::zero(); n];
        let mut cur = PallasFp::one();
        for v in omega_powers.iter_mut() {
            *v = cur;
            cur = cur.mul_vartime(&domain.omega);
        }
        let mut out = Vec::with_capacity(cols);
        let mut d = PallasFp::one();
        for _ in 0..cols {
            out.push(omega_powers.iter().map(|v| v.mul_vartime(&d)).collect());
            d = d.mul_vartime(&PallasFp::delta());
        }
        out
    }

    pub fn build_vk(
        &self,
        params: &PolyParams,
        domain: &EvaluationDomain,
        p: &PermutationArgument,
    ) -> Halo2Result<PermutationVerifyingKey> {
        let delta_omega = self.delta_omega(domain, params.n, p.columns.len());
        let mut commitments = Vec::with_capacity(p.columns.len());
        for i in 0..p.columns.len() {
            let mut poly = domain.empty_lagrange();
            for (j, v) in poly.values.iter_mut().enumerate() {
                let (pi, pj) = self.mapping[i][j];
                *v = delta_omega[pi][pj];
            }
            let c = params.commit_lagrange(&poly, PallasFp::one())?;
            let (x, y, ident) = c.to_affine_le()?;
            commitments.push(if ident {
                VestaAffine::identity()
            } else {
                VestaAffine::from_le_xy(x, y)?
            });
        }
        Ok(PermutationVerifyingKey { commitments })
    }

    pub fn build_pk(
        &self,
        params: &PolyParams,
        domain: &EvaluationDomain,
        p: &PermutationArgument,
    ) -> Halo2Result<PermutationProvingKey> {
        let delta_omega = self.delta_omega(domain, params.n, p.columns.len());
        let mut permutations = Vec::with_capacity(p.columns.len());
        let mut polys = Vec::with_capacity(p.columns.len());
        let mut cosets = Vec::with_capacity(p.columns.len());
        for i in 0..p.columns.len() {
            let mut poly = domain.empty_lagrange();
            for (j, v) in poly.values.iter_mut().enumerate() {
                let (pi, pj) = self.mapping[i][j];
                *v = delta_omega[pi][pj];
            }
            permutations.push(poly.clone());
            let coeff = domain.lagrange_to_coeff(poly)?;
            let coset = domain.coeff_to_extended(coeff.clone())?;
            polys.push(coeff);
            cosets.push(coset);
        }
        Ok(PermutationProvingKey {
            permutations,
            polys,
            cosets,
        })
    }

    #[cfg(feature = "alloc")]
    pub fn to_debug_string(&self) -> String {
        alloc::format!("PermutationAssembly(columns: {})", self.columns.len())
    }
}

// —— keys ——

#[derive(Clone)]
pub struct PermutationVerifyingKey {
    pub commitments: Vec<VestaAffine>,
}

impl PermutationVerifyingKey {
    #[cfg(feature = "alloc")]
    pub fn to_debug_string(&self) -> String {
        let cs: Vec<String> = self
            .commitments
            .iter()
            .map(|e| {
                let (xb, yb) = match e.to_affine_le() {
                    Ok((x, y, _)) => (x, y),
                    Err(_) => ([0u8; 32], [0u8; 32]),
                };
                alloc::format!(
                    "({}, {})",
                    crate::zk::orchard_halo2::bytes::to_hex_be_prefixed_alloc(&xb),
                    crate::zk::orchard_halo2::bytes::to_hex_be_prefixed_alloc(&yb)
                )
            })
            .collect();
        alloc::format!("VerifyingKey {{ commitments: [{}] }}", cs.join(", "))
    }

    pub fn evaluate(
        &self,
        transcript: &mut TranscriptReader<'_>,
    ) -> Halo2Result<PermutationVerifyCommonEvaluated> {
        let mut evals = Vec::with_capacity(self.commitments.len());
        for _ in 0..self.commitments.len() {
            evals.push(PallasFp::from_le_array(&transcript.read_scalar_le()?)?);
        }
        Ok(PermutationVerifyCommonEvaluated { evals })
    }
}

#[derive(Clone)]
pub struct PermutationProvingKey {
    pub permutations: Vec<Polynomial<PallasFp>>,
    pub polys: Vec<Polynomial<PallasFp>>,
    pub cosets: Vec<Polynomial<PallasFp>>,
}

impl PermutationProvingKey {
    pub fn evaluate(&self, x: PallasFp, transcript: &mut TranscriptWriter) -> Halo2Result<()> {
        for poly in self.polys.iter() {
            transcript.write_scalar_le(&eval_polynomial(&poly.values, x).to_le_bytes())?;
        }
        Ok(())
    }

    pub fn open(&self, x: PallasFp) -> Vec<ProverQuery> {
        self.polys
            .iter()
            .map(|e| ProverQuery {
                point: x,
                poly: e.clone(),
                blind: PallasFp::one(),
            })
            .collect()
    }
}

// —— argument ——

#[derive(Clone, PartialEq, Eq)]
pub struct PermutationArgument {
    columns: Vec<AnyAssignmentColumn>,
}

impl PermutationArgument {
    pub fn new() -> Self {
        Self {
            columns: Vec::new(),
        }
    }

    pub fn columns(&self) -> &[AnyAssignmentColumn] {
        &self.columns
    }

    pub fn get_columns(&self) -> Vec<AnyAssignmentColumn> {
        self.columns.clone()
    }

    pub fn add_column(&mut self, column: AnyAssignmentColumn) {
        if !self.columns.contains(&column) {
            self.columns.push(column);
        }
    }

    pub fn required_degree(&self) -> usize {
        3
    }

    #[cfg(feature = "alloc")]
    pub fn to_debug_string(&self) -> String {
        let cols: Vec<String> = self
            .columns
            .iter()
            .map(|c| {
                alloc::format!(
                    "Column {{ index: {}, column_type: {} }}",
                    c.index,
                    c.column_type.to_debug_string()
                )
            })
            .collect();
        alloc::format!("Argument {{ columns: [{}] }}", cols.join(", "))
    }

    /// Commit round (grand-product z per chunk). `cs_degree >= 3` enforced.
    #[allow(clippy::too_many_arguments)]
    pub fn commit(
        &self,
        params: &PolyParams,
        pk: &PlonkProvingKey,
        pkey: &PermutationProvingKey,
        advice: &[Polynomial<PallasFp>],
        fixed: &[Polynomial<PallasFp>],
        instance: &[Polynomial<PallasFp>],
        beta: PallasFp,
        gamma: PallasFp,
        evaluator: &mut Evaluator,
        transcript: &mut TranscriptWriter,
        rng: &mut dyn BlindRng,
    ) -> Halo2Result<PermutationCommitted> {
        if pk.vk.cs_degree < 3 {
            return Err(Halo2Error::operation_failed(
                "permutation::commit",
                "degree too small",
            ));
        }
        let chunk_len = pk.vk.cs_degree - 2;
        let blinding = pk.vk.cs.blinding_factors();
        let mut delta_omega = PallasFp::one();
        let mut last_z = PallasFp::one();
        let mut sets = Vec::new();
        for (columns, perms) in chunk_of(&self.columns, chunk_len)
            .into_iter()
            .zip(chunk_of(&pkey.permutations, chunk_len))
        {
            let mut modified = vec![PallasFp::one(); params.n];
            for (col, perm_col) in columns.iter().zip(perms.iter()) {
                let values = pick_polys(col, advice, fixed, instance)?;
                for (j, m) in modified.iter_mut().enumerate() {
                    let value = values.get(j).ok_or_else(|| {
                        Halo2Error::operation_failed("permutation::commit", "row overflow")
                    })?;
                    let permuted = perm_col.values.get(j).ok_or_else(|| {
                        Halo2Error::operation_failed("permutation::commit", "row overflow")
                    })?;
                    *m = m.mul_vartime(
                        &beta
                            .mul_vartime(permuted)
                            .add_vartime(&gamma)
                            .add_vartime(value),
                    );
                }
            }
            batch_invert(&mut modified)?;
            for col in columns.iter() {
                let omega = pk.vk.domain.omega;
                let values = pick_polys(col, advice, fixed, instance)?;
                let mut local = delta_omega;
                for (j, m) in modified.iter_mut().enumerate() {
                    let value = values.get(j).ok_or_else(|| {
                        Halo2Error::operation_failed("permutation::commit", "row overflow")
                    })?;
                    *m = m.mul_vartime(
                        &local
                            .mul_vartime(&beta)
                            .add_vartime(&gamma)
                            .add_vartime(value),
                    );
                    local = local.mul_vartime(&omega);
                }
                delta_omega = delta_omega.mul_vartime(&PallasFp::delta());
            }
            let mut z_values = Vec::with_capacity(params.n);
            z_values.push(last_z);
            for row in 1..params.n {
                let prev = z_values[row - 1];
                z_values.push(prev.mul_vartime(&modified[row - 1]));
            }
            let mut z = pk.vk.domain.lagrange_from_vec(z_values)?;
            for i in (params.n - blinding)..params.n {
                let slot = z.values.get_mut(i).ok_or_else(|| {
                    Halo2Error::operation_failed("permutation::commit", "blind overflow")
                })?;
                *slot = rng.next_pallas();
            }
            last_z = z.values[params.n - (blinding + 1)];
            let blind = rng.next_pallas();
            let commitment = params.commit_lagrange(&z, blind)?;
            let coeff_poly = pk.vk.domain.lagrange_to_coeff(z)?;
            let coset =
                evaluator.register_poly(pk.vk.domain.coeff_to_extended(coeff_poly.clone())?);
            transcript.write_point(&commitment.to_compressed()?)?;
            sets.push(PermutationCommittedSet {
                permutation_product_poly: coeff_poly,
                permutation_product_coset: coset,
                permutation_product_blind: blind,
            });
        }
        Ok(PermutationCommitted { sets })
    }

    pub fn read_product_commitments(
        &self,
        vk: &PlonkVerifyingKey,
        transcript: &mut TranscriptReader<'_>,
    ) -> Halo2Result<PermutationVerifyCommitted> {
        let chunk_len = vk.cs_degree.saturating_sub(2).max(1);
        let mut commitments = Vec::new();
        let mut i = 0usize;
        while i < self.columns.len() {
            commitments.push(VestaAffine::from_compressed(&transcript.read_point()?)?);
            i += chunk_len;
        }
        Ok(PermutationVerifyCommitted {
            product_commitments: commitments,
        })
    }
}

impl Default for PermutationArgument {
    fn default() -> Self {
        Self::new()
    }
}

fn pick_polys<'b>(
    col: &AnyAssignmentColumn,
    advice: &'b [Polynomial<PallasFp>],
    fixed: &'b [Polynomial<PallasFp>],
    instance: &'b [Polynomial<PallasFp>],
) -> Halo2Result<&'b [PallasFp]> {
    let poly = match col.column_type {
        AnyColumn::Advice => advice.get(col.index),
        AnyColumn::Fixed => fixed.get(col.index),
        AnyColumn::Instance => instance.get(col.index),
    }
    .ok_or_else(|| Halo2Error::operation_failed("permutation::pick", "column overflow"))?;
    Ok(&poly.values)
}

// —— committed / constructed / evaluated ——

pub struct PermutationCommittedSet {
    pub permutation_product_poly: Polynomial<PallasFp>,
    pub permutation_product_coset: AstLeaf,
    pub permutation_product_blind: PallasFp,
}

pub struct PermutationCommitted {
    pub sets: Vec<PermutationCommittedSet>,
}

impl PermutationCommitted {
    #[allow(clippy::too_many_arguments)] // Gate API mirrors upstream halo2 circuit signatures; regrouping args would churn call sites.
    pub fn construct(
        &self,
        pk: &PlonkProvingKey,
        p: &PermutationArgument,
        advice_cosets: &[AstLeaf],
        fixed_cosets: &[AstLeaf],
        instance_cosets: &[AstLeaf],
        permutation_cosets: &[AstLeaf],
        l0: &AstLeaf,
        l_blind: &AstLeaf,
        l_last: &AstLeaf,
        beta: PallasFp,
        gamma: PallasFp,
    ) -> Halo2Result<(PermutationConstructed, Vec<Ast>)> {
        let chunk_len = pk.vk.cs_degree.saturating_sub(2).max(1);
        let blinding = pk.vk.cs.blinding_factors();
        let last_rotation = Rotation {
            location: -((blinding + 1) as i32),
        };
        let constructed = PermutationConstructed {
            sets: self
                .sets
                .iter()
                .map(|s| PermutationConstructedSet {
                    permutation_product_poly: s.permutation_product_poly.clone(),
                    permutation_product_blind: s.permutation_product_blind,
                })
                .collect(),
        };
        let mut expressions: Vec<Ast> = Vec::new();
        if !self.sets.is_empty() {
            let one = Ast::ConstantTerm(PallasFp::one());
            let first = Ast::Poly(self.sets[0].permutation_product_coset);
            expressions.push(one.sub(&first).mul(&Ast::Poly(*l0)));
        }
        if !self.sets.is_empty() {
            let last = &self.sets[self.sets.len() - 1];
            let z = Ast::Poly(last.permutation_product_coset);
            expressions.push(z.mul(&z).sub(&z).mul(&Ast::Poly(*l_last)));
        }
        for i in 1..self.sets.len() {
            let zi = Ast::Poly(self.sets[i].permutation_product_coset);
            let prev = Ast::Poly(
                self.sets[i - 1]
                    .permutation_product_coset
                    .with_rotation(last_rotation),
            );
            expressions.push(zi.sub(&prev).mul(&Ast::Poly(*l0)));
        }
        let letends = |len: usize| len.div_ceil(chunk_len);
        let loop_count = core::cmp::min(
            self.sets.len(),
            core::cmp::min(letends(p.columns.len()), letends(permutation_cosets.len())),
        );
        for chunk_index in 0..loop_count {
            let start = chunk_index * chunk_len;
            let end_cols = core::cmp::min(start + chunk_len, p.columns.len());
            let end_cos = core::cmp::min(start + chunk_len, permutation_cosets.len());
            let columns = &p.columns[start..end_cols];
            let cosets = &permutation_cosets[start..end_cos];
            let set = &self.sets[chunk_index];
            let mut left = Ast::Poly(
                set.permutation_product_coset
                    .with_rotation(Rotation::next()),
            );
            for (j, column) in columns.iter().enumerate() {
                let values = match column.column_type {
                    AnyColumn::Advice => advice_cosets.get(column.index),
                    AnyColumn::Fixed => fixed_cosets.get(column.index),
                    AnyColumn::Instance => instance_cosets.get(column.index),
                }
                .ok_or_else(|| {
                    Halo2Error::operation_failed("permutation::left", "coset overflow")
                })?;
                let term = Ast::Poly(*values)
                    .add(&Ast::ConstantTerm(beta).mul(&Ast::Poly(cosets[j])))
                    .add(&Ast::ConstantTerm(gamma));
                left = left.mul(&term);
            }
            let mut right = Ast::Poly(set.permutation_product_coset);
            let mut current_delta = beta.mul_vartime(&pow_u64_field(
                PallasFp::delta(),
                (chunk_index * chunk_len) as u64,
            ));
            for column in columns.iter() {
                let values = match column.column_type {
                    AnyColumn::Advice => advice_cosets.get(column.index),
                    AnyColumn::Fixed => fixed_cosets.get(column.index),
                    AnyColumn::Instance => instance_cosets.get(column.index),
                }
                .ok_or_else(|| {
                    Halo2Error::operation_failed("permutation::right", "coset overflow")
                })?;
                let term = Ast::Poly(*values)
                    .add(&Ast::LinearTerm(current_delta))
                    .add(&Ast::ConstantTerm(gamma));
                right = right.mul(&term);
                current_delta = current_delta.mul_vartime(&PallasFp::delta());
            }
            let one = Ast::ConstantTerm(PallasFp::one());
            let gate = left
                .sub(&right)
                .mul(&one.sub(&Ast::Poly(*l_last).add(&Ast::Poly(*l_blind))));
            expressions.push(gate);
        }
        Ok((constructed, expressions))
    }
}

pub struct PermutationConstructedSet {
    pub permutation_product_poly: Polynomial<PallasFp>,
    pub permutation_product_blind: PallasFp,
}

pub struct PermutationConstructed {
    pub sets: Vec<PermutationConstructedSet>,
}

impl PermutationConstructed {
    pub fn evaluate(
        &self,
        pk: &PlonkProvingKey,
        x: PallasFp,
        transcript: &mut TranscriptWriter,
    ) -> Halo2Result<PermutationEvaluated> {
        let blinding = pk.vk.cs.blinding_factors();
        for (index, set) in self.sets.iter().enumerate() {
            let eval = eval_polynomial(&set.permutation_product_poly.values, x);
            let next = eval_polynomial(
                &set.permutation_product_poly.values,
                pk.vk.domain.rotate_omega(x, Rotation::next()),
            );
            transcript.write_scalar_le(&eval.to_le_bytes())?;
            transcript.write_scalar_le(&next.to_le_bytes())?;
            if index + 1 < self.sets.len() {
                let rot = Rotation {
                    location: -((blinding + 1) as i32),
                };
                let last = eval_polynomial(
                    &set.permutation_product_poly.values,
                    pk.vk.domain.rotate_omega(x, rot),
                );
                transcript.write_scalar_le(&last.to_le_bytes())?;
            }
        }
        Ok(PermutationEvaluated {
            sets: self
                .sets
                .iter()
                .map(|s| PermutationEvaluatedLink {
                    poly: s.permutation_product_poly.clone(),
                    blind: s.permutation_product_blind,
                })
                .collect(),
        })
    }
}

struct PermutationEvaluatedLink {
    poly: Polynomial<PallasFp>,
    blind: PallasFp,
}

pub struct PermutationEvaluated {
    sets: Vec<PermutationEvaluatedLink>,
}

impl PermutationEvaluated {
    pub fn open(&self, pk: &PlonkProvingKey, x: PallasFp) -> Vec<ProverQuery> {
        let blinding = pk.vk.cs.blinding_factors();
        let x_next = pk.vk.domain.rotate_omega(x, Rotation::next());
        let x_last = pk.vk.domain.rotate_omega(
            x,
            Rotation {
                location: -((blinding + 1) as i32),
            },
        );
        let mut queries = Vec::new();
        for set in self.sets.iter() {
            queries.push(ProverQuery {
                point: x,
                poly: set.poly.clone(),
                blind: set.blind,
            });
            queries.push(ProverQuery {
                point: x_next,
                poly: set.poly.clone(),
                blind: set.blind,
            });
        }
        for i in (0..self.sets.len().saturating_sub(1)).rev() {
            let set = &self.sets[i];
            queries.push(ProverQuery {
                point: x_last,
                poly: set.poly.clone(),
                blind: set.blind,
            });
        }
        queries
    }
}

// —— verification ——

#[derive(Clone, Copy)]
pub struct PermutationVerifyEvaluatedSet {
    pub product_commitment: VestaAffine,
    pub product_eval: PallasFp,
    pub product_next_eval: PallasFp,
    pub product_last_eval: Option<PallasFp>,
}

#[derive(Clone)]
pub struct PermutationVerifyEvaluated {
    pub sets: Vec<PermutationVerifyEvaluatedSet>,
}

impl PermutationVerifyEvaluated {
    #[allow(clippy::too_many_arguments)] // Gate API mirrors upstream halo2 circuit signatures; regrouping args would churn call sites.
    pub fn expressions(
        &self,
        vk: &PlonkVerifyingKey,
        p: &PermutationArgument,
        common: &PermutationVerifyCommonEvaluated,
        advice_evals: &[PallasFp],
        fixed_evals: &[PallasFp],
        instance_evals: &[PallasFp],
        l0: PallasFp,
        l_last: PallasFp,
        l_blind: PallasFp,
        beta: PallasFp,
        gamma: PallasFp,
        x: PallasFp,
    ) -> Halo2Result<Vec<PallasFp>> {
        let chunk_len = vk.cs_degree.saturating_sub(2).max(1);
        let mut out = Vec::new();
        if !self.sets.is_empty() {
            out.push(l0.mul_vartime(&PallasFp::one().sub_vartime(&self.sets[0].product_eval)));
        }
        if !self.sets.is_empty() {
            let last = &self.sets[self.sets.len() - 1];
            out.push(
                last.product_eval
                    .square_vartime()
                    .sub_vartime(&last.product_eval)
                    .mul_vartime(&l_last),
            );
        }
        for i in 1..self.sets.len() {
            let prev_last = self.sets[i - 1].product_last_eval.ok_or_else(|| {
                Halo2Error::operation_failed("perm_verify::expr", "missing last eval")
            })?;
            out.push(
                self.sets[i]
                    .product_eval
                    .sub_vartime(&prev_last)
                    .mul_vartime(&l0),
            );
        }
        for (chunk_index, set) in self.sets.iter().enumerate() {
            let start = chunk_index * chunk_len;
            let end = core::cmp::min(start + chunk_len, p.columns.len());
            let columns = &p.columns[start..end];
            let perm_evals =
                &common.evals[start..core::cmp::min(start + chunk_len, common.evals.len())];
            let mut left = set.product_next_eval;
            for (j, column) in columns.iter().enumerate() {
                let eval = pick_eval(vk, column, advice_evals, fixed_evals, instance_evals)?;
                left = left.mul_vartime(
                    &eval
                        .add_vartime(&beta.mul_vartime(&perm_evals[j]))
                        .add_vartime(&gamma),
                );
            }
            let mut right = set.product_eval;
            let mut current_delta = beta.mul_vartime(&x).mul_vartime(&pow_u64_field(
                PallasFp::delta(),
                (chunk_index * chunk_len) as u64,
            ));
            for column in columns.iter() {
                let eval = pick_eval(vk, column, advice_evals, fixed_evals, instance_evals)?;
                right = right.mul_vartime(&eval.add_vartime(&current_delta).add_vartime(&gamma));
                current_delta = current_delta.mul_vartime(&PallasFp::delta());
            }
            out.push(
                left.sub_vartime(&right)
                    .mul_vartime(&PallasFp::one().sub_vartime(&l_last.add_vartime(&l_blind))),
            );
        }
        Ok(out)
    }

    pub fn queries(self, vk: &PlonkVerifyingKey, x: PallasFp) -> Vec<VerifierQuery<'_>> {
        let blinding = vk.cs.blinding_factors();
        let x_next = vk.domain.rotate_omega(x, Rotation::next());
        let x_last = vk.domain.rotate_omega(
            x,
            Rotation {
                location: -((blinding + 1) as i32),
            },
        );
        let mut out = Vec::new();
        for set in self.sets.iter() {
            out.push(VerifierQuery {
                point: x,
                commitment: crate::zk::orchard_halo2::poly::commitment::commitment::CommitmentReference::Commitment(
                    set.product_commitment,
                ),
                eval: set.product_eval,
            });
            out.push(VerifierQuery {
                point: x_next,
                commitment: crate::zk::orchard_halo2::poly::commitment::commitment::CommitmentReference::Commitment(
                    set.product_commitment,
                ),
                eval: set.product_next_eval,
            });
        }
        for i in (0..self.sets.len().saturating_sub(1)).rev() {
            let set = &self.sets[i];
            if let Some(last) = set.product_last_eval {
                out.push(VerifierQuery {
                    point: x_last,
                    commitment: crate::zk::orchard_halo2::poly::commitment::commitment::CommitmentReference::Commitment(
                        set.product_commitment,
                    ),
                    eval: last,
                });
            }
        }
        out
    }
}

fn pick_eval(
    vk: &PlonkVerifyingKey,
    column: &AnyAssignmentColumn,
    advice: &[PallasFp],
    fixed: &[PallasFp],
    instance: &[PallasFp],
) -> Halo2Result<PallasFp> {
    let idx = vk.cs.get_any_query_index(*column)?;
    match column.column_type {
        AnyColumn::Advice => advice.get(idx).copied(),
        AnyColumn::Fixed => fixed.get(idx).copied(),
        AnyColumn::Instance => instance.get(idx).copied(),
    }
    .ok_or_else(|| Halo2Error::operation_failed("perm_verify::eval", "eval overflow"))
}

pub struct PermutationVerifyCommitted {
    pub product_commitments: Vec<VestaAffine>,
}

impl PermutationVerifyCommitted {
    pub fn evaluate(
        &self,
        transcript: &mut TranscriptReader<'_>,
    ) -> Halo2Result<PermutationVerifyEvaluated> {
        let mut iter = self.product_commitments.iter();
        let mut sets = Vec::new();
        while let Some(c) = iter.next() {
            let eval = PallasFp::from_le_array(&transcript.read_scalar_le()?)?;
            let next = PallasFp::from_le_array(&transcript.read_scalar_le()?)?;
            let last = if iter.len() > 0 {
                Some(PallasFp::from_le_array(&transcript.read_scalar_le()?)?)
            } else {
                None
            };
            sets.push(PermutationVerifyEvaluatedSet {
                product_commitment: *c,
                product_eval: eval,
                product_next_eval: next,
                product_last_eval: last,
            });
        }
        Ok(PermutationVerifyEvaluated { sets })
    }
}

pub struct PermutationVerifyCommonEvaluated {
    pub evals: Vec<PallasFp>,
}

impl PermutationVerifyCommonEvaluated {
    pub fn queries<'a>(
        &self,
        vkey: &PermutationVerifyingKey,
        x: PallasFp,
    ) -> Vec<VerifierQuery<'a>> {
        let mut out = Vec::new();
        for (i, c) in vkey.commitments.iter().enumerate() {
            if let Some(e) = self.evals.get(i) {
                out.push(VerifierQuery {
                    point: x,
                    commitment: crate::zk::orchard_halo2::poly::commitment::commitment::CommitmentReference::Commitment(*c),
                    eval: *e,
                });
            }
        }
        out
    }
}

/// Placeholder MSM import check (keeps `msm_vesta` linked for later passes).
#[allow(dead_code)]
fn _link_msm(coeffs: &[PallasFp], bases: &[VestaAffine]) -> Halo2Result<()> {
    let _ = msm_vesta(coeffs, bases)?;
    Ok(())
}
