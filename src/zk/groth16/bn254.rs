//! Groth16 verifier over BN254 (Sui / Aptos / Tezos / Ethereum-style).
//!
//! Same equation as BLS12 path:
//! `e(A,B) = e(α,β) · e(L,γ) · e(C,δ)`.

use crate::curve::bn254::{pairing, G1Point, G2Point, Scalar};
use crate::curve::traits::CurvePoint;
use alloc::vec::Vec;

use super::verify::Groth16Error;
use super::verify::Groth16Result;

/// BN254 Groth16 proof.
#[derive(Clone, Debug)]
pub struct ProofBn254 {
    pub a: G1Point,
    pub b: G2Point,
    pub c: G1Point,
}

/// BN254 verifying key.
#[derive(Clone, Debug)]
pub struct VerifyingKeyBn254 {
    pub alpha_g1: G1Point,
    pub beta_g2: G2Point,
    pub gamma_g2: G2Point,
    pub delta_g2: G2Point,
    pub ic: Vec<G1Point>,
}

impl VerifyingKeyBn254 {
    pub fn num_inputs(&self) -> usize {
        self.ic.len().saturating_sub(1)
    }
}

/// `L = IC₀ + Σ public_i · IC_{i+1}`.
pub fn prepare_inputs_bn254(
    vk: &VerifyingKeyBn254,
    public_inputs: &[Scalar],
) -> Groth16Result<G1Point> {
    if public_inputs.len() + 1 != vk.ic.len() {
        return Err(Groth16Error::InputLength);
    }
    let mut acc = vk.ic[0];
    for (i, x) in public_inputs.iter().enumerate() {
        acc = acc.add(&vk.ic[i + 1].mul(x));
    }
    Ok(acc)
}

/// Verify Groth16 proof over BN254.
pub fn verify_bn254(
    vk: &VerifyingKeyBn254,
    public_inputs: &[Scalar],
    proof: &ProofBn254,
) -> Groth16Result<()> {
    let prepared = prepare_inputs_bn254(vk, public_inputs)?;
    verify_prepared_bn254(vk, &prepared, proof)
}

pub fn verify_prepared_bn254(
    vk: &VerifyingKeyBn254,
    prepared_input: &G1Point,
    proof: &ProofBn254,
) -> Groth16Result<()> {
    let lhs = pairing(&proof.a, &proof.b);
    let rhs = pairing(&vk.alpha_g1, &vk.beta_g2)
        .mul(&pairing(prepared_input, &vk.gamma_g2))
        .mul(&pairing(&proof.c, &vk.delta_g2));
    if lhs.ct_eq(&rhs) == 1 {
        Ok(())
    } else {
        Err(Groth16Error::VerificationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn s(n: u64) -> Scalar {
        Scalar::from_u64(n)
    }

    /// Synthetic valid instance via bilinearity when pairing is identity-friendly:
    /// with L=C=O and β = (r·t)·G2, A=r·G1, B=t·G2, α=G1.
    #[test]
    fn synthetic_structure_and_lengths() {
        let g1 = G1Point::generator();
        let g2 = G2Point::generator();
        let r = s(7);
        let t = s(11);
        let proof = ProofBn254 {
            a: g1.mul(&r),
            b: g2.mul(&t),
            c: G1Point::identity(),
        };
        let vk = VerifyingKeyBn254 {
            alpha_g1: g1,
            beta_g2: g2.mul(&r.mul(&t)),
            gamma_g2: g2,
            delta_g2: g2,
            ic: vec![G1Point::identity()],
        };
        let res = verify_bn254(&vk, &[], &proof);
        assert!(res.is_ok(), "synthetic BN254: {:?}", res);
        assert_eq!(vk.num_inputs(), 0);
        assert_eq!(G1Point::UNCOMPRESSED_BYTES, 64);
        assert_eq!(G2Point::UNCOMPRESSED_BYTES, 128);
    }
}
