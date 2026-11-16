//! Groth16 verifier over BLS12-381 (Bellman / Zcash Sapling equation).
//!
//! Verification equation (same as `bellman::groth16::verify_proof`):
//!
//! ```text
//! e(A, B) = e(α, β) · e(L, γ) · e(C, δ)
//! ```

mod bn254;
mod verify;

#[cfg(feature = "groth16")]
pub mod codec;

pub use bn254::{
    prepare_inputs_bn254, verify_bn254, verify_prepared_bn254, ProofBn254, VerifyingKeyBn254,
};
pub use codec::{
    pack_public_inputs_aptos, pack_public_inputs_sui, pack_public_inputs_tezos,
    pack_public_inputs_zcash, unpack_public_inputs_aptos, unpack_public_inputs_sui,
    unpack_public_inputs_tezos, unpack_public_inputs_zcash, AptosProofBytes, AptosVkBytes,
    BellmanVerifyingKey, SuiProofBytes, SuiVkBytes, TezosProofBytes, TezosVkBytes, ZcashParameters,
    ZcashProofBytes, ZcashVkBytes,
};
pub use verify::{
    prepare_inputs, verify, verify_prepared, verify_product_one, Groth16Error, Groth16Result,
    Proof, VerifyingKey,
};

#[cfg(feature = "groth16-prover")]
mod fft;
#[cfg(feature = "groth16-prover")]
mod fft_bls;
#[cfg(feature = "groth16-prover")]
mod msm;
#[cfg(feature = "groth16-prover")]
mod multiexp_bls;
#[cfg(feature = "groth16-prover")]
mod prove;
#[cfg(feature = "groth16-prover")]
mod prove_bls;
#[cfg(feature = "groth16-prover")]
mod r1cs;
#[cfg(feature = "groth16-prover")]
pub use multiexp_bls::{multiexp_g1_parallel_le, multiexp_g1_with_le, multiexp_g1_with_le_c};

#[cfg(feature = "groth16-prover")]
pub use fft::Domain;
#[cfg(feature = "groth16-prover")]
pub use fft_bls::DomainBls;
#[cfg(feature = "groth16-prover")]
pub use msm::msm_g1;
#[cfg(feature = "groth16-prover")]
pub use prove::{prove_bn254, setup_mult_circuit_synthetic, ProvingKeyBn254};
#[cfg(feature = "groth16-prover")]
pub use prove_bls::{
    a_density, b_density, prove as prove_bls, prove_with_randomness as prove_bls_with_randomness,
    setup_from_r1cs_synthetic, setup_mult_circuit_synthetic as setup_mult_circuit_synthetic_bls,
    ConstraintBls, LinearCombinationBls, ProvingKey as ProvingKeyBls, R1csBls,
};
#[cfg(feature = "groth16-prover")]
pub use r1cs::{Constraint, LinearCombination, R1cs};

#[cfg(test)]
mod tests;
