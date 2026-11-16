//! Groth16 prover over BLS12-381 (Zcash / Bellman equation).
//!
//! Feature `groth16-prover`.
//! - Synthetic trapdoor setup (tests).
//! - Query-based QAP prove: FFT `h(X)`, MSM over proving-key tables.

#![cfg(feature = "groth16-prover")]

use super::fft_bls::DomainBls;
use super::verify::{Groth16Error, Groth16Result, Proof, VerifyingKey};
use crate::curve::bls::{G1Point, G2Point, Scalar};
use crate::curve::traits::{CurvePoint, Scalar as ScalarTrait};
use alloc::vec;
use alloc::vec::Vec;

type ProveResult<T> = Groth16Result<T>;

#[derive(Clone, Debug)]
struct Trapdoor {
    tau: Scalar,
    alpha: Scalar,
    beta: Scalar,
    gamma: Scalar,
    delta: Scalar,
    delta_inv: Scalar,
    gamma_inv: Scalar,
}

/// BLS12 proving key with query tables for QAP prove.
#[derive(Clone, Debug)]
pub struct ProvingKey {
    pub vk: VerifyingKey,
    pub domain_size: usize,
    /// δ · G1 (needed for A and C; not in VK)
    pub delta_g1: G1Point,
    /// β · G1 (needed for B_g1 in C cross terms)
    pub beta_g1: G1Point,
    pub a_query: Vec<G1Point>,
    pub b_g1_query: Vec<G1Point>,
    pub b_g2_query: Vec<G2Point>,
    pub h_query: Vec<G1Point>,
    pub l_query: Vec<G1Point>,
    trapdoor: Option<Trapdoor>,
}

impl ProvingKey {
    /// Build a production-style proving key (no trapdoor) from query tables.
    /// Used when loading Zcash / Bellman `Parameters`.
    #[allow(clippy::too_many_arguments)] // Gate API mirrors upstream halo2 circuit signatures; regrouping args would churn call sites.
    pub fn from_queries(
        vk: VerifyingKey,
        domain_size: usize,
        delta_g1: G1Point,
        beta_g1: G1Point,
        a_query: Vec<G1Point>,
        b_g1_query: Vec<G1Point>,
        b_g2_query: Vec<G2Point>,
        h_query: Vec<G1Point>,
        l_query: Vec<G1Point>,
    ) -> Self {
        Self {
            vk,
            domain_size,
            delta_g1,
            beta_g1,
            a_query,
            b_g1_query,
            b_g2_query,
            h_query,
            l_query,
            trapdoor: None,
        }
    }

    /// Drop toxic waste so prove uses the query/QAP path only.
    pub fn clear_trapdoor(&mut self) {
        self.trapdoor = None;
    }
}

#[derive(Clone, Debug, Default)]
pub struct LinearCombinationBls {
    pub terms: Vec<(usize, Scalar)>,
}

impl LinearCombinationBls {
    pub fn new() -> Self {
        Self { terms: Vec::new() }
    }
    pub fn add_term(&mut self, var: usize, coeff: Scalar) {
        self.terms.push((var, coeff));
    }
    pub fn eval(&self, assignment: &[Scalar]) -> Scalar {
        let mut acc = Scalar::zero();
        for &(i, ref c) in &self.terms {
            acc = acc.add(&c.mul(&assignment[i]));
        }
        acc
    }
    pub fn coeff(&self, var: usize) -> Scalar {
        let mut acc = Scalar::zero();
        for &(i, ref c) in &self.terms {
            if i == var {
                acc = acc.add(c);
            }
        }
        acc
    }
}

#[derive(Clone, Debug)]
pub struct ConstraintBls {
    pub a: LinearCombinationBls,
    pub b: LinearCombinationBls,
    pub c: LinearCombinationBls,
}

#[derive(Clone, Debug)]
pub struct R1csBls {
    pub num_public: usize,
    pub num_variables: usize,
    pub constraints: Vec<ConstraintBls>,
}

impl R1csBls {
    /// Public `out`, private `a,b` with `a * b = out`. Vars `[1, out, a, b]`.
    pub fn mult_circuit() -> Self {
        let mut a = LinearCombinationBls::new();
        a.add_term(2, Scalar::one());
        let mut b = LinearCombinationBls::new();
        b.add_term(3, Scalar::one());
        let mut c = LinearCombinationBls::new();
        c.add_term(1, Scalar::one());
        Self {
            num_public: 1,
            num_variables: 4,
            constraints: vec![ConstraintBls { a, b, c }],
        }
    }

    pub fn is_satisfied(&self, assignment: &[Scalar]) -> bool {
        if assignment.len() != self.num_variables {
            return false;
        }
        if ScalarTrait::ct_eq(&assignment[0], &Scalar::one()) == 0 {
            return false;
        }
        for c in &self.constraints {
            let av = c.a.eval(assignment);
            let bv = c.b.eval(assignment);
            let cv = c.c.eval(assignment);
            if ScalarTrait::ct_eq(&av.mul(&bv), &cv) == 0 {
                return false;
            }
        }
        true
    }
}

fn lagrange_at_tau(domain: &DomainBls, i: usize, tau: &Scalar) -> Scalar {
    let n = domain.size;
    let omega_i = domain.omega.pow_u64(i as u64);
    let numer = tau.pow_u64(n as u64).sub(&Scalar::one());
    let denom = tau.sub(&omega_i);
    if denom.is_zero() {
        return Scalar::one();
    }
    // L_i(τ) = (τ^n − 1) · ω^i / (n · (τ − ω^i))
    numer
        .mul(&denom.invert().unwrap())
        .mul(&omega_i)
        .mul(&domain.size_inv)
}

/// Synthetic setup for mult circuit with full query tables.
pub fn setup_mult_circuit_synthetic() -> (ProvingKey, R1csBls) {
    let cs = R1csBls::mult_circuit();
    let delta = Scalar::from_u64(13);
    let gamma = Scalar::from_u64(11);
    let trap = Trapdoor {
        tau: Scalar::from_u64(7),
        alpha: Scalar::from_u64(3),
        beta: Scalar::from_u64(5),
        gamma,
        delta,
        delta_inv: delta.invert().expect("delta inv"),
        gamma_inv: gamma.invert().expect("gamma inv"),
    };
    let g1 = G1Point::generator();
    let g2 = G2Point::generator();
    let n = 4usize; // pad constraints to power of two
    let domain = DomainBls::new(n).expect("domain");

    // A_i(τ), B_i(τ), C_i(τ) via lagrange at constraint rows (row 0 only used).
    let l0 = lagrange_at_tau(&domain, 0, &trap.tau);

    let mut a_query = vec![G1Point::identity(); cs.num_variables];
    let mut b_g1_query = vec![G1Point::identity(); cs.num_variables];
    let mut b_g2_query = vec![G2Point::identity(); cs.num_variables];
    let mut c_query = vec![G1Point::identity(); cs.num_variables];

    // var2 in A, var3 in B, var1 in C
    a_query[2] = g1.mul(&l0);
    b_g1_query[3] = g1.mul(&l0);
    b_g2_query[3] = g2.mul(&l0);
    c_query[1] = g1.mul(&l0);

    // IC_i = (β A_i + α B_i + C_i)/γ · G1  (public + const)
    // const i=0: all zero → IC0 = O
    // public i=1: C_1 = L0 → IC1 = L0/γ · G1
    let ic = vec![G1Point::identity(), g1.mul(&l0.mul(&trap.gamma_inv))];

    // L_query for private vars (indices after public): (β A_i + α B_i + C_i)/δ
    let private_start = 1 + cs.num_public;
    let mut l_query = Vec::new();
    for i in private_start..cs.num_variables {
        let mut val = Scalar::zero();
        // A_2 = L0, B_3 = L0
        if i == 2 {
            val = trap.beta.mul(&l0);
        } else if i == 3 {
            val = trap.alpha.mul(&l0);
        }
        l_query.push(g1.mul(&val.mul(&trap.delta_inv)));
    }

    // H query: [τ^j · Z_H(τ)/δ] G1 for j = 0..n-1, Z_H = τ^n - 1
    let z_h = trap.tau.pow_u64(n as u64).sub(&Scalar::one());
    let mut h_query = Vec::new();
    let mut tp = Scalar::one();
    for _ in 0..n {
        h_query.push(g1.mul(&z_h.mul(&tp).mul(&trap.delta_inv)));
        tp = tp.mul(&trap.tau);
    }

    let vk = VerifyingKey::new(
        g1.mul(&trap.alpha),
        g2.mul(&trap.beta),
        g2.mul(&trap.gamma),
        g2.mul(&trap.delta),
        ic,
    );

    let pk = ProvingKey {
        vk,
        domain_size: n,
        delta_g1: g1.mul(&trap.delta),
        beta_g1: g1.mul(&trap.beta),
        a_query,
        b_g1_query,
        b_g2_query,
        h_query,
        l_query,
        trapdoor: Some(trap),
    };
    (pk, cs)
}

/// Synthetic trapdoor setup for an arbitrary R1CS (power-of-two domain ≥ #constraints).
///
/// Builds full A/B/C query tables and IC/L/H so [prove] can run without toxic waste
/// at prove-time (trapdoor retained only for debugging).
pub fn setup_from_r1cs_synthetic(cs: &R1csBls) -> ProvingKey {
    let delta = Scalar::from_u64(13);
    let gamma = Scalar::from_u64(11);
    let trap = Trapdoor {
        tau: Scalar::from_u64(7),
        alpha: Scalar::from_u64(3),
        beta: Scalar::from_u64(5),
        gamma,
        delta,
        delta_inv: delta.invert().expect("delta inv"),
        gamma_inv: gamma.invert().expect("gamma inv"),
    };
    let g1 = G1Point::generator();
    let g2 = G2Point::generator();

    let mut n = 1usize;
    while n < cs.constraints.len().max(1) {
        n <<= 1;
    }
    if n < 4 {
        n = 4;
    }
    let domain = DomainBls::new(n).expect("domain");

    // A_i(τ) = Σ_row L_row(τ) * A_{row,i}
    let mut a_at = vec![Scalar::zero(); cs.num_variables];
    let mut b_at = vec![Scalar::zero(); cs.num_variables];
    let mut c_at = vec![Scalar::zero(); cs.num_variables];
    for (row, cons) in cs.constraints.iter().enumerate() {
        let lr = lagrange_at_tau(&domain, row, &trap.tau);
        for &(i, ref coeff) in &cons.a.terms {
            if i < a_at.len() {
                a_at[i] = a_at[i].add(&lr.mul(coeff));
            }
        }
        for &(i, ref coeff) in &cons.b.terms {
            if i < b_at.len() {
                b_at[i] = b_at[i].add(&lr.mul(coeff));
            }
        }
        for &(i, ref coeff) in &cons.c.terms {
            if i < c_at.len() {
                c_at[i] = c_at[i].add(&lr.mul(coeff));
            }
        }
    }

    let mut a_query = Vec::with_capacity(cs.num_variables);
    let mut b_g1_query = Vec::with_capacity(cs.num_variables);
    let mut b_g2_query = Vec::with_capacity(cs.num_variables);
    for i in 0..cs.num_variables {
        a_query.push(g1.mul(&a_at[i]));
        b_g1_query.push(g1.mul(&b_at[i]));
        b_g2_query.push(g2.mul(&b_at[i]));
    }

    // IC_i = (β A_i + α B_i + C_i) / γ · G1  for i = 0..num_public (incl const)
    let mut ic = Vec::with_capacity(1 + cs.num_public);
    for i in 0..=cs.num_public {
        let val = trap
            .beta
            .mul(&a_at[i])
            .add(&trap.alpha.mul(&b_at[i]))
            .add(&c_at[i])
            .mul(&trap.gamma_inv);
        ic.push(g1.mul(&val));
    }

    // L_query for private vars
    let private_start = 1 + cs.num_public;
    let mut l_query = Vec::new();
    for i in private_start..cs.num_variables {
        let val = trap
            .beta
            .mul(&a_at[i])
            .add(&trap.alpha.mul(&b_at[i]))
            .add(&c_at[i])
            .mul(&trap.delta_inv);
        l_query.push(g1.mul(&val));
    }

    let z_h = trap.tau.pow_u64(n as u64).sub(&Scalar::one());
    let mut h_query = Vec::new();
    let mut tp = Scalar::one();
    for _ in 0..n {
        h_query.push(g1.mul(&z_h.mul(&tp).mul(&trap.delta_inv)));
        tp = tp.mul(&trap.tau);
    }

    let vk = VerifyingKey::new(
        g1.mul(&trap.alpha),
        g2.mul(&trap.beta),
        g2.mul(&trap.gamma),
        g2.mul(&trap.delta),
        ic,
    );

    ProvingKey {
        vk,
        domain_size: n,
        delta_g1: g1.mul(&trap.delta),
        beta_g1: g1.mul(&trap.beta),
        a_query,
        b_g1_query,
        b_g2_query,
        h_query,
        l_query,
        trapdoor: Some(trap),
    }
}

/// Prove under [ProvingKey]. Prefers query/QAP path; trapdoor only if queries empty.
pub fn prove(pk: &ProvingKey, cs: &R1csBls, assignment: &[Scalar]) -> ProveResult<Proof> {
    prove_with_randomness(
        pk,
        cs,
        assignment,
        &Scalar::from_u64(11),
        &Scalar::from_u64(13),
    )
}

/// Same as [prove] with explicit prover randomness `(r, s)`.
pub fn prove_with_randomness(
    pk: &ProvingKey,
    cs: &R1csBls,
    assignment: &[Scalar],
    r: &Scalar,
    s: &Scalar,
) -> ProveResult<Proof> {
    if assignment.len() != cs.num_variables {
        return Err(Groth16Error::InputLength);
    }
    if !cs.is_satisfied(assignment) {
        return Err(Groth16Error::VerificationFailed);
    }
    // Production path: query/QAP when tables present and no trapdoor.
    // Accepts dense (self-params) or sparse (ceremony) A/B queries.
    if pk.trapdoor.is_none() && !pk.h_query.is_empty() && !pk.a_query.is_empty() {
        return prove_qap(pk, cs, assignment, r, s);
    }
    if let Some(ref trap) = pk.trapdoor {
        return prove_with_trapdoor(pk, cs, assignment, trap, r, s);
    }
    if !pk.h_query.is_empty() && !pk.a_query.is_empty() {
        return prove_qap(pk, cs, assignment, r, s);
    }
    Err(Groth16Error::VerificationFailed)
}

/// Variables that appear with non-zero coefficient on the A (resp. B) side of
/// any constraint. Order is ascending variable index — matches Bellman's
/// `DensityTracker` filter used when building sparse `a` / `b_g*` queries.
pub fn a_density(cs: &R1csBls) -> Vec<usize> {
    // Bellman: inputs have *full* A density (dummy x*0=0); aux dens tracked from A LCs.
    // Resulting sparse query order: [0..n_inputs) then increasing aux indices on A.
    let n_inputs = 1 + cs.num_public;
    let mut aux_present = vec![false; cs.num_variables.saturating_sub(n_inputs)];
    for cons in &cs.constraints {
        for &(i, ref c) in &cons.a.terms {
            if ScalarTrait::ct_eq(c, &Scalar::zero()) != 0 {
                continue;
            }
            if i >= n_inputs {
                let ai = i - n_inputs;
                if ai < aux_present.len() {
                    aux_present[ai] = true;
                }
            }
        }
    }
    let mut dens = Vec::with_capacity(n_inputs + aux_present.iter().filter(|&&x| x).count());
    dens.extend(0..n_inputs);
    for (ai, p) in aux_present.into_iter().enumerate() {
        if p {
            dens.push(n_inputs + ai);
        }
    }
    dens
}

pub fn b_density(cs: &R1csBls) -> Vec<usize> {
    // Bellman: separate b_input_density + b_aux_density; params layout is
    // [dense inputs in input order][dense aux in aux order] = sorted global dens on B.
    let n_inputs = 1 + cs.num_public;
    let mut in_present = vec![false; n_inputs];
    let mut aux_present = vec![false; cs.num_variables.saturating_sub(n_inputs)];
    for cons in &cs.constraints {
        for &(i, ref c) in &cons.b.terms {
            if ScalarTrait::ct_eq(c, &Scalar::zero()) != 0 {
                continue;
            }
            if i < n_inputs {
                in_present[i] = true;
            } else {
                let ai = i - n_inputs;
                if ai < aux_present.len() {
                    aux_present[ai] = true;
                }
            }
        }
    }
    let mut dens = Vec::new();
    for (i, p) in in_present.into_iter().enumerate() {
        if p {
            dens.push(i);
        }
    }
    for (ai, p) in aux_present.into_iter().enumerate() {
        if p {
            dens.push(n_inputs + ai);
        }
    }
    dens
}

/// MSM over a sparse query: `bases[k]` corresponds to dense variable `dense_idx[k]`.
///
/// `no_std`/wasm-only: production (`std`) prove uses the `_le` entry points.
#[cfg(any(not(feature = "std"), target_arch = "wasm32"))]
fn msm_g1_sparse(bases: &[G1Point], dense_idx: &[usize], assignment: &[Scalar]) -> G1Point {
    super::multiexp_bls::multiexp_g1_sparse(bases, dense_idx, assignment)
}

/// `no_std`/wasm-only (see `msm_g1_sparse`).
#[cfg(any(not(feature = "std"), target_arch = "wasm32"))]
fn msm_g2_sparse(bases: &[G2Point], dense_idx: &[usize], assignment: &[Scalar]) -> G2Point {
    super::multiexp_bls::multiexp_g2_sparse(bases, dense_idx, assignment)
}

/// Query-based QAP prove (no toxic waste at prove time).
///
/// Supports both dense queries (`a_query.len() == num_variables`, self-params)
/// and Bellman-style sparse A/B queries (ceremony params filter identity
/// points; density recomputed from the R1CS).
fn prove_qap(
    pk: &ProvingKey,
    cs: &R1csBls,
    assignment: &[Scalar],
    r: &Scalar,
    s: &Scalar,
) -> ProveResult<Proof> {
    let n = pk.domain_size;
    let domain =
        crate::zk::groth16::fft_bls::domain_for_size(n).ok_or(Groth16Error::InvalidLength)?;

    // h(X) coefficients via coset FFT
    let h_coeffs = compute_h(cs, assignment, &domain)?;

    // Precompute dens once (shared by sparse A/B paths)
    let dens_a = a_density(cs);
    let dens_b = b_density(cs);

    // Length checks up front so parallel workers only compute
    if pk.a_query.len() != cs.num_variables && dens_a.len() != pk.a_query.len() {
        return Err(Groth16Error::InputLength);
    }
    if pk.b_g2_query.len() != cs.num_variables && dens_b.len() != pk.b_g2_query.len() {
        return Err(Groth16Error::InputLength);
    }
    if !pk.b_g1_query.is_empty()
        && pk.b_g1_query.len() != cs.num_variables
        && dens_b.len() != pk.b_g1_query.len()
    {
        return Err(Groth16Error::InputLength);
    }
    let private_start = 1 + cs.num_public;
    let private_assign = &assignment[private_start..];
    if !pk.l_query.is_empty() && pk.l_query.len() != private_assign.len() {
        return Err(Groth16Error::InputLength);
    }
    let h_len = pk.h_query.len().min(h_coeffs.len());

    // Precompute LE scalar bytes once (avoids repeated mont→canonical in every MSM).
    let assign_le = scalar_les(assignment);
    let h_le = scalar_les(&h_coeffs[..h_len]);
    // Sparse dens LE views (owned once, shared across workers by ref via scope)
    let a_les_sparse: Vec<[u8; 32]> = if pk.a_query.len() != cs.num_variables {
        dens_a.iter().map(|&i| assign_le[i]).collect()
    } else {
        Vec::new()
    };
    let b_les_sparse: Vec<[u8; 32]> =
        if !pk.b_g1_query.is_empty() && pk.b_g1_query.len() != cs.num_variables {
            dens_b.iter().map(|&i| assign_le[i]).collect()
        } else {
            Vec::new()
        };

    // MSM schedule (bellman-shaped): the 5 query MSMs run SEQUENTIALLY, each
    // internally point-parallel across all cores. Total work ≈ Σ(MSMs)/cores
    // beats the old 5-way scope (wall ≈ max ≈ H single-threaded).
    #[cfg(all(feature = "std", not(target_arch = "wasm32")))]
    let (a_acc, b_acc, b_g1_acc, h, l) = {
        let a_acc = if pk.a_query.len() == cs.num_variables {
            super::multiexp_bls::multiexp_g1_parallel_le(&pk.a_query, &assign_le)
        } else {
            super::multiexp_bls::multiexp_g1_parallel_le(&pk.a_query, &a_les_sparse)
        };
        let b_acc = if pk.b_g2_query.len() == cs.num_variables {
            super::multiexp_bls::multiexp_g2_parallel(&pk.b_g2_query, assignment)
        } else {
            super::multiexp_bls::multiexp_g2_sparse(&pk.b_g2_query, &dens_b, assignment)
        };
        let b_g1_acc = if pk.b_g1_query.is_empty() {
            G1Point::identity()
        } else if pk.b_g1_query.len() == cs.num_variables {
            super::multiexp_bls::multiexp_g1_parallel_le(&pk.b_g1_query, &assign_le)
        } else {
            super::multiexp_bls::multiexp_g1_parallel_le(&pk.b_g1_query, &b_les_sparse)
        };
        let h = super::multiexp_bls::multiexp_g1_parallel_le(&pk.h_query[..h_len], &h_le);
        let l = if pk.l_query.is_empty() {
            G1Point::identity()
        } else {
            super::multiexp_bls::multiexp_g1_parallel_le(
                &pk.l_query,
                &assign_le[private_start..],
            )
        };
        (a_acc, b_acc, b_g1_acc, h, l)
    };
    #[cfg(any(not(feature = "std"), target_arch = "wasm32"))]
    let (a_acc, b_acc, b_g1_acc, h, l) = {
        let a_acc = if pk.a_query.len() == cs.num_variables {
            msm_g1_bls(&pk.a_query, assignment)
        } else {
            msm_g1_sparse(&pk.a_query, &dens_a, assignment)
        };
        let b_acc = if pk.b_g2_query.len() == cs.num_variables {
            msm_g2_bls(&pk.b_g2_query, assignment)
        } else {
            msm_g2_sparse(&pk.b_g2_query, &dens_b, assignment)
        };
        let b_g1_acc = if pk.b_g1_query.is_empty() {
            G1Point::identity()
        } else if pk.b_g1_query.len() == cs.num_variables {
            msm_g1_bls(&pk.b_g1_query, assignment)
        } else {
            msm_g1_sparse(&pk.b_g1_query, &dens_b, assignment)
        };
        let h = msm_g1_bls(&pk.h_query[..h_len], &h_coeffs[..h_len]);
        let l = if pk.l_query.is_empty() {
            G1Point::identity()
        } else {
            msm_g1_bls(&pk.l_query, private_assign)
        };
        (a_acc, b_acc, b_g1_acc, h, l)
    };

    let a = pk.vk.alpha_g1.add(&a_acc).add(&pk.delta_g1.mul(r));
    let b = pk.vk.beta_g2.add(&b_acc).add(&pk.vk.delta_g2.mul(s));
    let b_g1 = pk.beta_g1.add(&b_g1_acc).add(&pk.delta_g1.mul(s));
    let rs = r.mul(s);
    let c = h
        .add(&l)
        .add(&a.mul(s))
        .add(&b_g1.mul(r))
        .add(&pk.delta_g1.mul(&rs).neg());

    Ok(Proof { a, b, c })
}

/// Compute coefficients of h(X) = (a(X)b(X) − c(X)) / Z_H(X) on the domain.
fn compute_h(cs: &R1csBls, assignment: &[Scalar], domain: &DomainBls) -> ProveResult<Vec<Scalar>> {
    let n = domain.size;
    // Evaluate a,b,c on domain: for padded single constraint at row 0,
    // a(ω^k) = δ_{k0} · ⟨A,z⟩, etc.
    let mut a_eval = vec![Scalar::zero(); n];
    let mut b_eval = vec![Scalar::zero(); n];
    let mut c_eval = vec![Scalar::zero(); n];
    for (row, cons) in cs.constraints.iter().enumerate() {
        if row >= n {
            break;
        }
        a_eval[row] = cons.a.eval(assignment);
        b_eval[row] = cons.b.eval(assignment);
        c_eval[row] = cons.c.eval(assignment);
    }

    // Evaluations on H → coefficients → evaluations on coset g·H (single-thread).
    // Vartime Fr ops (prove-side posture, bellman-shaped).
    let g = Scalar::from_u64(7); // BLS12-381 Fr MULTIPLICATIVE_GENERATOR (Bellman coset)
    domain.ifft_vartime(&mut a_eval);
    domain.ifft_vartime(&mut b_eval);
    domain.ifft_vartime(&mut c_eval);
    domain.coset_fft_vartime(&mut a_eval, &g);
    domain.coset_fft_vartime(&mut b_eval, &g);
    domain.coset_fft_vartime(&mut c_eval, &g);

    // (a*b - c) / Z_H on coset. Z_H(g·ω^i) = (g·ω^i)^n − 1 = g^n − 1 (constant).
    // Invert once — was the dominant cost for large domains (Spend n=131072).
    let z_coset = g.pow_u64(n as u64).sub(&Scalar::one());
    let z_inv = z_coset
        .invert()
        .map_err(|_| Groth16Error::VerificationFailed)?;
    let mut h_eval = vec![Scalar::zero(); n];
    {
        use crate::zk::groth16::fft_bls::par_chunks_mut;
        par_chunks_mut(&mut h_eval, |base, slice| {
            for (k, h) in slice.iter_mut().enumerate() {
                let i = base + k;
                let numer = a_eval[i].mul_vartime(&b_eval[i]).sub_vartime(&c_eval[i]);
                *h = numer.mul_vartime(&z_inv);
            }
        });
    }

    domain.coset_ifft_vartime(&mut h_eval, &g);
    Ok(h_eval)
}

/// `no_std`/wasm-only: production (`std`) prove uses the `_le` entry points.
#[cfg(any(not(feature = "std"), target_arch = "wasm32"))]
fn msm_g1_bls(bases: &[G1Point], scalars: &[Scalar]) -> G1Point {
    super::multiexp_bls::multiexp_g1_parallel(bases, scalars)
}

/// `no_std`/wasm-only (see `msm_g1_bls`).
#[cfg(any(not(feature = "std"), target_arch = "wasm32"))]
fn msm_g2_bls(bases: &[G2Point], scalars: &[Scalar]) -> G2Point {
    super::multiexp_bls::multiexp_g2_parallel(bases, scalars)
}

fn scalar_les(scalars: &[Scalar]) -> Vec<[u8; 32]> {
    let mut out = Vec::with_capacity(scalars.len());
    for s in scalars {
        let mut le = [0u8; 32];
        s.to_bytes_le(&mut le);
        out.push(le);
    }
    out
}

/// `no_std`/wasm-only (see `msm_g1_sparse`).
#[cfg(any(not(feature = "std"), target_arch = "wasm32"))]
fn msm_g1_le(bases: &[G1Point], les: &[[u8; 32]]) -> G1Point {
    #[cfg(all(feature = "std", not(target_arch = "wasm32")))]
    {
        super::multiexp_bls::multiexp_g1_parallel_le(bases, les)
    }
    #[cfg(any(not(feature = "std"), target_arch = "wasm32"))]
    {
        super::multiexp_bls::multiexp_g1_with_le(bases, les)
    }
}

fn prove_with_trapdoor(
    pk: &ProvingKey,
    cs: &R1csBls,
    assignment: &[Scalar],
    trap: &Trapdoor,
    r: &Scalar,
    s: &Scalar,
) -> ProveResult<Proof> {
    let g1 = G1Point::generator();
    let g2 = G2Point::generator();
    let domain = DomainBls::new(pk.domain_size).ok_or(Groth16Error::InvalidLength)?;
    let l0 = lagrange_at_tau(&domain, 0, &trap.tau);

    let a_at = assignment[2].mul(&l0);
    let b_at = assignment[3].mul(&l0);
    let _ = cs;

    let a_s = trap.alpha.add(&a_at).add(&r.mul(&trap.delta));
    let b_s = trap.beta.add(&b_at).add(&s.mul(&trap.delta));
    let public = assignment[1];
    // IC1 = (L0/γ)G1 → e(L,γ) contributes public·L0
    let l_exp = public.mul(&l0);
    let ab = a_s.mul(&b_s);
    let alpha_beta = trap.alpha.mul(&trap.beta);
    let numer = ab.sub(&alpha_beta).sub(&l_exp);
    let c_s = numer.mul(&trap.delta_inv);

    Ok(Proof {
        a: g1.mul(&a_s),
        b: g2.mul(&b_s),
        c: g1.mul(&c_s),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    // Test-only: verification is exercised solely by the round-trips below.
    use crate::zk::groth16::verify::verify;

    #[test]
    fn prove_verify_mult_qap() {
        let (pk, cs) = setup_mult_circuit_synthetic();
        let assignment = [
            Scalar::one(),
            Scalar::from_u64(6),
            Scalar::from_u64(2),
            Scalar::from_u64(3),
        ];
        assert!(cs.is_satisfied(&assignment));
        let proof = prove(&pk, &cs, &assignment).expect("prove");
        verify(&pk.vk, &[assignment[1]], &proof).expect("verify");
    }

    #[test]
    fn prove_rejects_unsatisfied() {
        let (pk, cs) = setup_mult_circuit_synthetic();
        let bad = [
            Scalar::one(),
            Scalar::from_u64(7),
            Scalar::from_u64(2),
            Scalar::from_u64(3),
        ];
        assert!(prove(&pk, &cs, &bad).is_err());
    }

    #[test]
    fn fft_domain_for_setup() {
        let d = DomainBls::new(4).expect("n=4");
        assert_eq!(d.size, 4);
    }

    /// Force query-only prove by stripping trapdoor from synthetic PK.
    #[test]
    fn setup_from_r1cs_matches_mult() {
        let cs = R1csBls::mult_circuit();
        let mut pk = setup_from_r1cs_synthetic(&cs);
        pk.clear_trapdoor();
        let assignment = [
            Scalar::one(),
            Scalar::from_u64(6),
            Scalar::from_u64(2),
            Scalar::from_u64(3),
        ];
        let proof = prove(&pk, &cs, &assignment).expect("prove");
        verify(&pk.vk, &[assignment[1]], &proof).expect("verify");
    }

    #[test]
    fn a_b_density_matches_sparse_filter() {
        // mult: A has var 2, B has var 3, C has var 1 → a dens=[0,1,2], b dens=[3]
        // (a forces full input density like Bellman dummy constraints;
        // b tracks actual presence).
        let cs = R1csBls::mult_circuit();
        assert_eq!(a_density(&cs), vec![0, 1, 2]);
        assert_eq!(b_density(&cs), vec![3]);
        // Dense synthetic PK still proves; sparse subset of a_query must align.
        let mut pk = setup_from_r1cs_synthetic(&cs);
        pk.clear_trapdoor();
        let dens_a = a_density(&cs);
        assert_eq!(dens_a.len(), 3);
        // Simulate sparse a by keeping only non-identity-looking slots that density selects.
        let sparse_a: Vec<_> = dens_a.iter().map(|&i| pk.a_query[i]).collect();
        pk.a_query = sparse_a;
        let dens_b = b_density(&cs);
        let sparse_bg1: Vec<_> = dens_b.iter().map(|&i| pk.b_g1_query[i]).collect();
        let sparse_bg2: Vec<_> = dens_b.iter().map(|&i| pk.b_g2_query[i]).collect();
        pk.b_g1_query = sparse_bg1;
        pk.b_g2_query = sparse_bg2;
        let assignment = [
            Scalar::one(),
            Scalar::from_u64(6),
            Scalar::from_u64(2),
            Scalar::from_u64(3),
        ];
        let proof = prove(&pk, &cs, &assignment).expect("sparse prove");
        verify(&pk.vk, &[assignment[1]], &proof).expect("sparse verify");
    }

    #[test]
    fn two_constraint_query() {
        // two equality constraints: p0=p0, p1=p1 via private copies
        let mut constraints = Vec::new();
        for i in 0..2 {
            let pub_i = 1 + i;
            let priv_i = 3 + i; // after 1 + 2 public
            let mut a = LinearCombinationBls::new();
            a.add_term(priv_i, Scalar::one());
            let mut b = LinearCombinationBls::new();
            b.add_term(0, Scalar::one());
            let mut c = LinearCombinationBls::new();
            c.add_term(pub_i, Scalar::one());
            constraints.push(ConstraintBls { a, b, c });
        }
        let cs = R1csBls {
            num_public: 2,
            num_variables: 5, // 1 + 2 pub + 2 priv
            constraints,
        };
        let mut pk = setup_from_r1cs_synthetic(&cs);
        pk.clear_trapdoor();
        let z = [
            Scalar::one(),
            Scalar::from_u64(3),
            Scalar::from_u64(5),
            Scalar::from_u64(3),
            Scalar::from_u64(5),
        ];
        assert!(cs.is_satisfied(&z));
        let proof = prove(&pk, &cs, &z).expect("prove");
        verify(&pk.vk, &[z[1], z[2]], &proof).expect("verify");
    }

    #[test]
    fn prove_verify_mult_query_only() {
        let (mut pk, cs) = setup_mult_circuit_synthetic();
        pk.trapdoor = None; // no toxic waste at prove time
        let assignment = [
            Scalar::one(),
            Scalar::from_u64(6),
            Scalar::from_u64(2),
            Scalar::from_u64(3),
        ];
        assert!(cs.is_satisfied(&assignment));
        let proof = prove(&pk, &cs, &assignment).expect("prove_qap");
        verify(&pk.vk, &[assignment[1]], &proof).expect("verify");
    }
}
