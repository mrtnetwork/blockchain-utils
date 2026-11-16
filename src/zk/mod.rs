//! Zero-knowledge proof primitives (feature-gated).
//!
//! - `groth16` — Groth16 verifier (BLS12-381 + BN254)
//! - `groth16-prover` — prover + FFT/MSM/R1CS (also pulled by `zcash-sapling`)
//! - `halo2` — Halo2 core (also pulled by `zcash-halo2`)
//! - `zcash-incrementalmerkle` — Frontier-based incremental Merkle trees
//!   (Sapling/Orchard/Ironwood anchor trees) with Sapling/Orchard bridges;
//!   standalone on `alloc`, independent of prover/Halo2.

#[cfg(feature = "groth16")]
pub mod groth16;

#[cfg(any(
    feature = "zcash-incrementalmerkle",
    feature = "groth16-prover",
    feature = "orchard-halo2",
    feature = "groth16"
))]
pub mod incrementalmerkletree;

#[cfg(feature = "groth16-prover")]
pub mod sapling;
#[cfg(feature = "groth16-prover")]
pub use sapling::*;

#[cfg(feature = "groth16")]
pub use groth16::{
    pack_public_inputs_aptos, pack_public_inputs_sui, pack_public_inputs_tezos,
    pack_public_inputs_zcash, prepare_inputs, prepare_inputs_bn254, unpack_public_inputs_aptos,
    unpack_public_inputs_sui, unpack_public_inputs_tezos, unpack_public_inputs_zcash, verify,
    verify_bn254, verify_prepared, verify_prepared_bn254, verify_product_one, AptosProofBytes,
    AptosVkBytes, Groth16Error, Groth16Result, Proof, ProofBn254, SuiProofBytes, SuiVkBytes,
    TezosProofBytes, TezosVkBytes, VerifyingKey, VerifyingKeyBn254, ZcashProofBytes, ZcashVkBytes,
};

#[cfg(feature = "groth16-prover")]
#[cfg(feature = "groth16")]
pub use groth16::{
    msm_g1, prove_bn254, setup_mult_circuit_synthetic, Constraint, Domain, LinearCombination,
    ProvingKeyBn254, R1cs,
};

// Standalone Orchard Halo2 implementation.
// Zero-dep, self-contained.
#[cfg(feature = "orchard-halo2")]
pub mod orchard_halo2;
