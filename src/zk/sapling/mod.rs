//! Sapling (Zcash) Groth16 spend / output — parameter-loaded prove & verify.
//!
//! Fast path: load ceremony params → prove (MSM) → verify.
//! - `prover` — load params, prove_spend/output, verify_spend/output
//! - `circuit_*` / gadgets — Bellman-aligned R1CS synthesis
//! - Multicore MSM: enable crate feature `multicore` (native only; ignored on wasm32)

#![cfg(feature = "groth16-prover")]

mod blake2s_circuit;
mod boolean;
mod builder;
mod circuit_output;
mod circuit_spend;
mod constants;
mod cs;
// Constraint-stream / density analysis scaffolding: unit-test support only,
// never shipped in release builds.
mod api;
mod edwards;
mod gadgets;
mod lookup;
mod merkle_circuit;
mod native;
mod num;
mod pedersen_circuit;
mod prover;
mod spend;
#[cfg(test)]
pub(crate) mod stream_digest;
mod uint32;
mod windows;

pub use api::{
    build_output_witness, build_spend_witness, decode_output_verification,
    decode_spend_verification, parse_input_scalars, prove_output_with_params,
    prove_spend_with_params, verify_output_with_params, verify_spend_with_params,
    SaplingOutputBytes, SaplingOutputVerification, SaplingOutputVerificationBytes,
    SaplingProveOutput, SaplingSpendBytes, SaplingSpendVerification, SaplingSpendVerificationBytes,
    GROTH_PROOF_SIZE, KIND_OUTPUT, KIND_SPEND, MAX_AUTH_PATH, MAX_OUTPUT_VERIFY_INPUTS,
    MAX_SPEND_VERIFY_INPUTS, OUTPUT_WITNESS_PACKED_LEN, SPEND_FULL_DEPTH, SPEND_WITNESS_PACKED_LEN,
};

pub use blake2s_circuit::{blake2s_cs, blake2s_zcash_ivk, blake2s_zcash_nf};
pub use builder::{
    output_public_inputs_from_parts, spend_public_inputs_from_witness,
    spend_public_scalars_from_witness,
};
pub use circuit_spend::{
    spend_circuit_fingerprint, synthesize_spend, synthesize_spend_cv_rk, synthesize_spend_depth,
    CircuitFingerprint, SpendCircuitStats,
};
pub use constants::{
    note_commitment_randomness_generator, nullifier_position_generator,
    proof_generation_key_generator, spending_key_generator, value_commitment_randomness_generator,
    value_commitment_value_generator,
};
pub use gadgets::{
    setup_spend_public_binding_synthetic, spend_public_binding_assignment,
    spend_public_binding_circuit, SPEND_GADGET_STAGES,
};
pub use merkle_circuit::{enforce_anchor, merkle_layer_cs, merkle_path_cs, merkle_path_from_u_cs};
pub use native::{
    compute_ivk, compute_merkle_root, compute_nk, compute_note_commitment, compute_nullifier,
    compute_pk_d, compute_rho, compute_rk, compute_rk_scalar, compute_value_commitment,
    compute_value_commitment_scalar, fe_to_le32, point_repr_bits, point_to_public_uv,
    position_bits_from_path,
};
pub use pedersen_circuit::{note_commitment_cs, pedersen_hash_cs};
pub use prover::{
    load_parameters, load_verifying_key, prove_output, prove_output_synthetic,
    prove_output_under_ceremony_params, prove_output_under_ceremony_params_with_randomness,
    prove_output_zcash_bytes, prove_spend, prove_spend_synthetic,
    prove_spend_under_ceremony_params, prove_spend_under_ceremony_params_with_randomness,
    prove_spend_zcash_bytes, spend_ceremony_gates_ready, spend_gates_ready,
    spend_verify_gates_ready, verify_output, verify_spend, verify_with_scalars,
    SPEND_GATE_CHECKLIST,
};
pub use spend::{
    multipack_bits_le, multipack_bytes_le, pack_output_public_inputs, pack_spend_public_inputs,
    setup_spend_skeleton_synthetic, spend_skeleton_assignment, spend_skeleton_circuit,
    OutputPublicInputs, OutputWitness, SpendPublicInputs, SpendWitness, JUBJUB_FQ_CAPACITY,
    OUTPUT_NUM_PUBLIC, SPEND_NUM_PUBLIC,
};
pub use windows::{
    fixed_base_mul_le_bits, generate_circuit_windows, u64_to_bits_le, CircuitWindows, WindowPoint,
};
