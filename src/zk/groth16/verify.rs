//! Groth16 verification logic (BLS12-381).

use crate::curve::bls::{
    final_exponentiation_vartime, multi_miller_loop_mixed_vartime, G1Point, G2Point,
    G2PreparedVartime, Scalar,
};
use crate::curve::traits::CurvePoint;
use alloc::vec::Vec;

/// Groth16-specific errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Groth16Error {
    /// Public input count does not match verifying key IC length.
    InputLength,
    /// Point encoding invalid or not on curve.
    InvalidPoint,
    /// Scalar encoding invalid.
    InvalidScalar,
    /// Buffer length wrong for proof / VK serialization.
    InvalidLength,
    /// Pairing product check failed.
    VerificationFailed,
}

/// Result alias.
pub type Groth16Result<T> = core::result::Result<T, Groth16Error>;

/// Groth16 proof: `(A ∈ G1, B ∈ G2, C ∈ G1)`.
#[derive(Clone, Debug)]
pub struct Proof {
    /// Proof element A.
    pub a: G1Point,
    /// Proof element B.
    pub b: G2Point,
    /// Proof element C.
    pub c: G1Point,
}

impl Proof {
    /// Compressed Zcash / Bellman layout: `A (48) || B (96) || C (48)` = 192 bytes.
    pub const COMPRESSED_BYTES: usize = 48 + 96 + 48;

    /// Parse compressed proof bytes.
    pub fn from_bytes_compressed(bytes: &[u8]) -> Groth16Result<Self> {
        if bytes.len() != Self::COMPRESSED_BYTES {
            return Err(Groth16Error::InvalidLength);
        }
        let a = G1Point::from_bytes(&bytes[0..48]).map_err(|_| Groth16Error::InvalidPoint)?;
        let b = G2Point::from_bytes(&bytes[48..144]).map_err(|_| Groth16Error::InvalidPoint)?;
        let c = G1Point::from_bytes(&bytes[144..192]).map_err(|_| Groth16Error::InvalidPoint)?;
        Ok(Self { a, b, c })
    }

    /// Write compressed proof into `out` (must be 192 bytes).
    pub fn to_bytes_compressed(&self, out: &mut [u8]) -> Groth16Result<()> {
        if out.len() != Self::COMPRESSED_BYTES {
            return Err(Groth16Error::InvalidLength);
        }
        self.a
            .to_bytes_compressed(&mut out[0..48])
            .map_err(|_| Groth16Error::InvalidPoint)?;
        self.b
            .to_bytes_compressed(&mut out[48..144])
            .map_err(|_| Groth16Error::InvalidPoint)?;
        self.c
            .to_bytes_compressed(&mut out[144..192])
            .map_err(|_| Groth16Error::InvalidPoint)?;
        Ok(())
    }
}

/// Verifying key: `α ∈ G1`, `β,γ,δ ∈ G2`, and IC list in G1.
///
/// `ic.len()` must be `public_inputs.len() + 1`.
#[derive(Clone, Debug)]
pub struct VerifyingKey {
    /// α · G1
    pub alpha_g1: G1Point,
    /// β · G2
    pub beta_g2: G2Point,
    /// γ · G2
    pub gamma_g2: G2Point,
    /// δ · G2
    pub delta_g2: G2Point,
    /// IC₀ … ICₙ (length = #public inputs + 1)
    pub ic: Vec<G1Point>,
    /// Precomputed Miller lines for (−β, −γ, −δ), built by [`VerifyingKey::new`].
    /// Skips G2 stepping on every verify (bellman `G2Prepared` analogue).
    pub prepared_neg: [Option<G2PreparedVartime>; 3],
}

impl VerifyingKey {
    /// Build a verifying key, precomputing negated-G2 Miller lines.
    /// All VK points are public; the prepared lines are verify-only.
    pub fn new(
        alpha_g1: G1Point,
        beta_g2: G2Point,
        gamma_g2: G2Point,
        delta_g2: G2Point,
        ic: Vec<G1Point>,
    ) -> Self {
        use crate::curve::bls::prepare_g2_lines_vartime;
        let prepared_neg = [
            prepare_g2_lines_vartime(&beta_g2.neg()),
            prepare_g2_lines_vartime(&gamma_g2.neg()),
            prepare_g2_lines_vartime(&delta_g2.neg()),
        ];
        Self {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            ic,
            prepared_neg,
        }
    }

    /// Number of public inputs this key expects (`ic.len() - 1`).
    pub fn num_inputs(&self) -> usize {
        self.ic.len().saturating_sub(1)
    }
}

/// Prepare public inputs: `L = IC₀ + Σ public_i · IC_{i+1}`.
pub fn prepare_inputs(vk: &VerifyingKey, public_inputs: &[Scalar]) -> Groth16Result<G1Point> {
    if public_inputs.len() + 1 != vk.ic.len() {
        return Err(Groth16Error::InputLength);
    }
    // Verify path: VK + public inputs always public → shared-doubling MSM.
    let mut points: Vec<G1Point> = Vec::with_capacity(public_inputs.len() + 1);
    points.push(vk.ic[0]);
    let mut scalars: Vec<Scalar> = Vec::with_capacity(public_inputs.len() + 1);
    scalars.push(Scalar::one());
    for (i, x) in public_inputs.iter().enumerate() {
        points.push(vk.ic[i + 1]);
        scalars.push(*x);
    }
    Ok(G1Point::multiexp_vartime(&points, &scalars))
}

/// Verify Groth16 proof (Bellman / Zcash equation).
///
/// Returns `Ok(())` if the pairing product holds; `Err(VerificationFailed)` otherwise.
pub fn verify(vk: &VerifyingKey, public_inputs: &[Scalar], proof: &Proof) -> Groth16Result<()> {
    let prepared = prepare_inputs(vk, public_inputs)?;
    verify_prepared(vk, &prepared, proof)
}

/// Verify with precomputed `L = prepare_inputs(...)`.
pub fn verify_prepared(
    vk: &VerifyingKey,
    prepared_input: &G1Point,
    proof: &Proof,
) -> Groth16Result<()> {
    // e(A, B) ≟ e(α, β) · e(L, γ) · e(C, δ), moved to one side:
    // ML(A,B) · ML(α,−β) · ML(L,−γ) · ML(C,−δ) with ONE shared-square
    // multi-Miller (live proof pair + prepared VK lines) + ONE final exp.
    // Verify path: all pairing inputs public.
    let nb = vk.beta_g2.neg();
    let ng = vk.gamma_g2.neg();
    let nd = vk.delta_g2.neg();
    let mut live: Vec<(&G1Point, &G2Point)> = Vec::with_capacity(4);
    live.push((&proof.a, &proof.b));
    let mut prep: Vec<(&G1Point, &G2PreparedVartime)> = Vec::with_capacity(3);
    for (p, g, n) in [
        (&vk.alpha_g1, &vk.prepared_neg[0], &nb),
        (prepared_input, &vk.prepared_neg[1], &ng),
        (&proof.c, &vk.prepared_neg[2], &nd),
    ] {
        match g {
            Some(c) => prep.push((p, c)),
            None => live.push((p, n)),
        }
    }
    let f = multi_miller_loop_mixed_vartime(&live, &prep);
    let p = final_exponentiation_vartime(&f);

    if p.is_one() {
        Ok(())
    } else {
        Err(Groth16Error::VerificationFailed)
    }
}

/// Helper: multi-pairing product form used by some codebases:
/// `e(A,B) · e(α,-β) · e(L,-γ) · e(C,-δ) = 1`.
#[allow(dead_code)]
pub fn verify_product_one(
    vk: &VerifyingKey,
    prepared_input: &G1Point,
    proof: &Proof,
) -> Groth16Result<()> {
    let nb = vk.beta_g2.neg();
    let ng = vk.gamma_g2.neg();
    let nd = vk.delta_g2.neg();
    let mut live: Vec<(&G1Point, &G2Point)> = Vec::with_capacity(4);
    live.push((&proof.a, &proof.b));
    let mut prep: Vec<(&G1Point, &G2PreparedVartime)> = Vec::with_capacity(3);
    for (p, g, n) in [
        (&vk.alpha_g1, &vk.prepared_neg[0], &nb),
        (prepared_input, &vk.prepared_neg[1], &ng),
        (&proof.c, &vk.prepared_neg[2], &nd),
    ] {
        match g {
            Some(c) => prep.push((p, c)),
            None => live.push((p, n)),
        }
    }
    let f = multi_miller_loop_mixed_vartime(&live, &prep);
    let p = final_exponentiation_vartime(&f);
    if p.is_one() {
        Ok(())
    } else {
        Err(Groth16Error::VerificationFailed)
    }
}
