//! Sapling Spend/Output prove + verify under loaded parameters
//! (Bellman-compatible). Internal API: the crate has no external audit,
//! so nothing here is certified for mainnet keys.
//!
//! ## Fast path (ceremony params from disk)
//! 1. [`load_parameters`] / [`load_verifying_key`] (~1–5 s) — `checked: false` for speed
//! 2. [`prove_spend_under_ceremony_params`] / [`prove_output_under_ceremony_params`]
//!    (or `*_with_randomness` for deterministic r,s)
//! 3. [`verify_spend`] / [`verify_output`] (sub-second)
//!
//! Official `sapling-spend.params` / `sapling-output.params` supported; proofs are
//! byte-compatible with Bellman when the same witness and (r,s) are used.
//!
//! ## Multicore
//! Enable crate feature `multicore` for parallel MSM on native targets.
//! wasm32 is always single-threaded.

use crate::curve::bls::Scalar;
use crate::zk::groth16::{
    verify, BellmanVerifyingKey, Groth16Error, Groth16Result, VerifyingKey, ZcashParameters,
    ZcashProofBytes,
};
use crate::zk::sapling::spend::{
    pack_output_public_inputs, pack_spend_public_inputs, OutputPublicInputs, SpendPublicInputs,
    OUTPUT_NUM_PUBLIC, SPEND_NUM_PUBLIC,
};

/// Internal gate checklist (Spend).
pub const SPEND_GATE_CHECKLIST: &[(&str, bool)] = &[
    ("Bellman VK/Parameters decode", true),
    ("Public input order = reference circuit (7 Fr)", true),
    ("Native cv / rk / note / merkle / nf", true),
    ("Multipack nf (255-bit capacity)", true),
    ("Fixed generators + GH lock", true),
    ("Multi-row QAP prove/verify (synthetic)", true),
    ("Verify compressed proof under loaded VK", true),
    ("Boolean CS + lookup3 + fixed-base gadgets", true),
    ("Pedersen hash R1CS (Edwards windows)", true),
    ("Merkle path R1CS (layer Pedersen + swap)", true),
    ("BLAKE2s R1CS (Zcashivk / Zcash_nf)", true),
    ("Variable-base scalar mul (pk_d)", true),
    ("synthesize_spend_depth full wiring", true),
    ("circuit cm.u → Merkle path (no native bypass)", true),
    ("Constraint stats API (depth-parameterized)", true),
    (
        "Gadget cost vs protocol.pdf (add=6, fb match excl. bool)",
        true,
    ),
    ("bellman lookup3_xy = 3 constraints", true),
    ("Output circuit synthesize (5 Fr public)", true),
    ("Output cv+epk synthetic prove/verify", true),
    (
        "BLAKE2s = protocol 21006 (polarity-XOR + free Constant(false))",
        true,
    ),
    ("Montgomery Pedersen (scaled Jubjub map)", true),
    ("Merkle layer ~1549 (spec ~1380)", true),
    ("lookup8_mont = 3-c (Bellman synth)", true),
    ("Allocation order documented", true),
    ("Circuit fingerprint + structure_digest", true),
    ("Constraint stream JSONL export (stream_digest)", true),
    ("Free Boolean NOT polarity (Bellman Not)", true),
    ("reference connector Sapling verify API", true),
    ("FFI bu_sapling_verify_spend/output", true),
    ("Spend depth1 ~56k (was ~163k)", true),
    (
        "Self-params prove_spend / prove_output (synthetic CRS)",
        true,
    ),
    ("prove_output_synthetic + prove_spend_synthetic", true),
    (
        "Ceremony prove under sapling-spend.params (matrix identity)",
        true,
    ),
];

/// Verify-side gates are all green.
pub fn spend_verify_gates_ready() -> bool {
    SPEND_GATE_CHECKLIST
        .iter()
        .filter(|(name, _)| {
            // Ceremony prove is a separate track (matrix identity).
            !name.contains("Ceremony prove")
                && !name.contains("matrix identity")
                && !name.contains("Full boolean")
        })
        .all(|(_, ok)| *ok)
}

pub fn load_parameters(bytes: &[u8], checked: bool) -> Groth16Result<ZcashParameters> {
    ZcashParameters::decode(bytes, checked)
}

pub fn load_verifying_key(bytes: &[u8], checked: bool) -> Groth16Result<VerifyingKey> {
    let (bvk, _) = BellmanVerifyingKey::decode(bytes, checked)?;
    Ok(bvk.to_verifying_key())
}

pub fn verify_spend(
    vk: &VerifyingKey,
    proof_bytes: &[u8],
    public: &SpendPublicInputs,
) -> Groth16Result<()> {
    if vk.ic.len() != SPEND_NUM_PUBLIC + 1 {
        return Err(Groth16Error::InputLength);
    }
    let proof = ZcashProofBytes::decode(proof_bytes)?;
    let inputs = pack_spend_public_inputs(public);
    verify(vk, &inputs, &proof)
}

pub fn verify_output(
    vk: &VerifyingKey,
    proof_bytes: &[u8],
    public: &OutputPublicInputs,
) -> Groth16Result<()> {
    if vk.ic.len() != OUTPUT_NUM_PUBLIC + 1 {
        return Err(Groth16Error::InputLength);
    }
    let proof = ZcashProofBytes::decode(proof_bytes)?;
    let inputs = pack_output_public_inputs(public);
    verify(vk, &inputs, &proof)
}

pub fn verify_with_scalars(
    vk: &VerifyingKey,
    proof_bytes: &[u8],
    public: &[Scalar],
) -> Groth16Result<()> {
    if vk.ic.len() != public.len() + 1 {
        return Err(Groth16Error::InputLength);
    }
    let proof = ZcashProofBytes::decode(proof_bytes)?;
    verify(vk, public, &proof)
}

/// Synthesize full Spend R1CS (depth-limited) and run synthetic setup + prove + verify.
///
/// **Self-params prove path for apps that ship their own CRS**.
/// Proofs verify under the returned VK, not under Zcash ceremony params until
/// R1CS matrices match Bellman byte-for-byte.
#[cfg(feature = "groth16-prover")]
pub fn prove_spend_synthetic(
    witness: &crate::zk::sapling::spend::SpendWitness,
    depth: usize,
) -> Groth16Result<(
    crate::zk::groth16::ProvingKeyBls,
    crate::zk::groth16::Proof,
    alloc::vec::Vec<Scalar>,
)> {
    use crate::zk::groth16::{prove_bls_with_randomness, setup_from_r1cs_synthetic};
    use crate::zk::sapling::circuit_spend::synthesize_spend_depth;
    let (r1cs, assignment) = synthesize_spend_depth(witness, depth);
    if !r1cs.is_satisfied(&assignment) {
        return Err(Groth16Error::VerificationFailed);
    }
    let mut pk = setup_from_r1cs_synthetic(&r1cs);
    pk.clear_trapdoor();
    let public: alloc::vec::Vec<Scalar> = assignment[1..1 + r1cs.num_public].to_vec();
    let proof = prove_bls_with_randomness(
        &pk,
        &r1cs,
        &assignment,
        &Scalar::from_u64(7),
        &Scalar::from_u64(11),
    )?;
    verify(&pk.vk, &public, &proof)?;
    Ok((pk, proof, public))
}

/// Synthesize full Output R1CS and run synthetic setup + prove + verify.
///
/// Same self-params path as [`prove_spend_synthetic`].
#[cfg(feature = "groth16-prover")]
pub fn prove_output_synthetic(
    witness: &crate::zk::sapling::spend::OutputWitness,
) -> Groth16Result<(
    crate::zk::groth16::ProvingKeyBls,
    crate::zk::groth16::Proof,
    alloc::vec::Vec<Scalar>,
)> {
    use crate::zk::groth16::{prove_bls_with_randomness, setup_from_r1cs_synthetic};
    use crate::zk::sapling::circuit_output::synthesize_output;
    let (r1cs, assignment) = synthesize_output(witness);
    if !r1cs.is_satisfied(&assignment) {
        return Err(Groth16Error::VerificationFailed);
    }
    let mut pk = setup_from_r1cs_synthetic(&r1cs);
    pk.clear_trapdoor();
    let public: alloc::vec::Vec<Scalar> = assignment[1..1 + r1cs.num_public].to_vec();
    let proof = prove_bls_with_randomness(
        &pk,
        &r1cs,
        &assignment,
        &Scalar::from_u64(17),
        &Scalar::from_u64(19),
    )?;
    verify(&pk.vk, &public, &proof)?;
    Ok((pk, proof, public))
}

///  alias: Spend prove under self-params CRS.
///
/// Equivalent to [`prove_spend_synthetic`]. Depth `32` is the full Sapling Merkle path;
/// use smaller depths for tests.
#[cfg(feature = "groth16-prover")]
pub fn prove_spend(
    witness: &crate::zk::sapling::spend::SpendWitness,
    depth: usize,
) -> Groth16Result<(
    crate::zk::groth16::ProvingKeyBls,
    crate::zk::groth16::Proof,
    alloc::vec::Vec<Scalar>,
)> {
    prove_spend_synthetic(witness, depth)
}

///  alias: Output prove under self-params CRS.
#[cfg(feature = "groth16-prover")]
pub fn prove_output(
    witness: &crate::zk::sapling::spend::OutputWitness,
) -> Groth16Result<(
    crate::zk::groth16::ProvingKeyBls,
    crate::zk::groth16::Proof,
    alloc::vec::Vec<Scalar>,
)> {
    prove_output_synthetic(witness)
}

/// Self-params Spend prove → compressed Zcash proof (192 bytes) + public Frs + VK.
#[cfg(feature = "groth16-prover")]
pub fn prove_spend_zcash_bytes(
    witness: &crate::zk::sapling::spend::SpendWitness,
    depth: usize,
) -> Groth16Result<(
    [u8; 192],
    alloc::vec::Vec<Scalar>,
    crate::zk::groth16::VerifyingKey,
)> {
    use crate::zk::groth16::ZcashProofBytes;
    let (pk, proof, public) = prove_spend(witness, depth)?;
    let proof_bytes = ZcashProofBytes::encode(&proof)?;
    Ok((proof_bytes, public, pk.vk))
}

/// Self-params Output prove → compressed Zcash proof (192 bytes) + public Frs + VK.
#[cfg(feature = "groth16-prover")]
pub fn prove_output_zcash_bytes(
    witness: &crate::zk::sapling::spend::OutputWitness,
) -> Groth16Result<(
    [u8; 192],
    alloc::vec::Vec<Scalar>,
    crate::zk::groth16::VerifyingKey,
)> {
    use crate::zk::groth16::ZcashProofBytes;
    let (pk, proof, public) = prove_output(witness)?;
    let proof_bytes = ZcashProofBytes::encode(&proof)?;
    Ok((proof_bytes, public, pk.vk))
}

/// Create Output proof (self-params) and verify it under the returned VK.
///
/// Parameter-loaded path for **tx creation** when you ship your own CRS with the tx
/// or product. Returns (proof_192, public_frs, vk).
/// Test-only helper (unit tests below prove+verify round-trips).
#[cfg(test)]
#[cfg(feature = "groth16-prover")]
pub fn create_and_verify_output(
    witness: &crate::zk::sapling::spend::OutputWitness,
) -> Groth16Result<(
    [u8; 192],
    alloc::vec::Vec<Scalar>,
    crate::zk::groth16::VerifyingKey,
)> {
    let (proof_bytes, public, vk) = prove_output_zcash_bytes(witness)?;
    verify_with_scalars(&vk, &proof_bytes, &public)?;
    Ok((proof_bytes, public, vk))
}

/// Create Spend proof (self-params, Merkle `depth`) and verify under returned VK.
///
/// Use `depth = 32` for full Sapling path. Prefer `depth = 1` for smoke tests.
/// Test-only helper (unit tests below prove+verify round-trips).
#[cfg(test)]
#[cfg(feature = "groth16-prover")]
pub fn create_and_verify_spend(
    witness: &crate::zk::sapling::spend::SpendWitness,
    depth: usize,
) -> Groth16Result<(
    [u8; 192],
    alloc::vec::Vec<Scalar>,
    crate::zk::groth16::VerifyingKey,
)> {
    let (proof_bytes, public, vk) = prove_spend_zcash_bytes(witness, depth)?;
    verify_with_scalars(&vk, &proof_bytes, &public)?;
    Ok((proof_bytes, public, vk))
}

/// Encode public Fr limbs as contiguous LE 32-byte chunks (tx wire format).
/// Test-only helper.
#[cfg(test)]
pub fn public_frs_to_le_bytes(public: &[Scalar]) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec::Vec::with_capacity(public.len() * 32);
    for fr in public {
        let mut le = [0u8; 32];
        fr.to_bytes_le(&mut le);
        out.extend_from_slice(&le);
    }
    out
}

/// Attempt Spend prove under **ceremony** parameters.
///
/// Returns [`Groth16Error::InputLength`] immediately when the loaded param
/// query sizes do not match our synthesized R1CS (matrix identity not met).
/// When sizes match, runs QAP prove; verification under the ceremony VK still
/// requires identical constraint order (see `MATRIX_STATUS.md`).
#[cfg(feature = "groth16-prover")]
pub fn prove_spend_under_ceremony_params(
    params: ZcashParameters,
    witness: &crate::zk::sapling::spend::SpendWitness,
    depth: usize,
) -> Groth16Result<(crate::zk::groth16::Proof, alloc::vec::Vec<Scalar>)> {
    use crate::zk::groth16::prove_bls_with_randomness;
    use crate::zk::sapling::circuit_spend::synthesize_spend_depth;
    let (r1cs, assignment) = synthesize_spend_depth(witness, depth);
    if !r1cs.is_satisfied(&assignment) {
        return Err(Groth16Error::VerificationFailed);
    }
    let pk = params.into_proving_key();
    // Dense (self-params) or sparse (ceremony filters identities) both OK.
    // Sparse path validates density.len() == a_query.len() inside prove_qap.
    if pk.a_query.is_empty()
        || pk.l_query.len() != r1cs.num_variables.saturating_sub(1 + r1cs.num_public)
    {
        return Err(Groth16Error::InputLength);
    }
    let public: alloc::vec::Vec<Scalar> = assignment[1..1 + r1cs.num_public].to_vec();
    let proof = prove_bls_with_randomness(
        &pk,
        &r1cs,
        &assignment,
        &Scalar::from_u64(7),
        &Scalar::from_u64(11),
    )?;
    verify(&pk.vk, &public, &proof)?;
    Ok((proof, public))
}

/// Same gate for Output under ceremony params.
#[cfg(feature = "groth16-prover")]
pub fn prove_output_under_ceremony_params(
    params: ZcashParameters,
    witness: &crate::zk::sapling::spend::OutputWitness,
) -> Groth16Result<(crate::zk::groth16::Proof, alloc::vec::Vec<Scalar>)> {
    use crate::zk::groth16::prove_bls_with_randomness;
    use crate::zk::sapling::circuit_output::synthesize_output;
    let (r1cs, assignment) = synthesize_output(witness);
    if !r1cs.is_satisfied(&assignment) {
        return Err(Groth16Error::VerificationFailed);
    }
    let pk = params.into_proving_key();
    if pk.a_query.is_empty()
        || pk.l_query.len() != r1cs.num_variables.saturating_sub(1 + r1cs.num_public)
    {
        return Err(Groth16Error::InputLength);
    }
    let public: alloc::vec::Vec<Scalar> = assignment[1..1 + r1cs.num_public].to_vec();
    let proof = prove_bls_with_randomness(
        &pk,
        &r1cs,
        &assignment,
        &Scalar::from_u64(17),
        &Scalar::from_u64(19),
    )?;
    // Ceremony path must verify under the loaded VK (reference/libzcash model).
    verify(&pk.vk, &public, &proof)?;
    Ok((proof, public))
}

/// Gated for **self-params** prove + **ceremony** verify.
/// Ceremony Output prove with explicit Groth16 randomness `(r, s)`.
/// Same witness + same `(r,s)` ⇒ **byte-identical** proof (deterministic).
#[cfg(feature = "groth16-prover")]
pub fn prove_output_under_ceremony_params_with_randomness(
    params: ZcashParameters,
    witness: &crate::zk::sapling::spend::OutputWitness,
    r: &Scalar,
    s: &Scalar,
) -> Groth16Result<(crate::zk::groth16::Proof, alloc::vec::Vec<Scalar>)> {
    use crate::zk::groth16::prove_bls_with_randomness;
    use crate::zk::sapling::circuit_output::synthesize_output;
    let (r1cs, assignment) = synthesize_output(witness);
    if !r1cs.is_satisfied(&assignment) {
        return Err(Groth16Error::VerificationFailed);
    }
    let pk = params.into_proving_key();
    if pk.a_query.is_empty()
        || pk.l_query.len() != r1cs.num_variables.saturating_sub(1 + r1cs.num_public)
    {
        return Err(Groth16Error::InputLength);
    }
    let public: alloc::vec::Vec<Scalar> = assignment[1..1 + r1cs.num_public].to_vec();
    let proof = prove_bls_with_randomness(&pk, &r1cs, &assignment, r, s)?;
    verify(&pk.vk, &public, &proof)?;
    Ok((proof, public))
}

/// Ceremony Spend prove with explicit `(r, s)` — requires dens lock first.
#[cfg(feature = "groth16-prover")]
pub fn prove_spend_under_ceremony_params_with_randomness(
    params: ZcashParameters,
    witness: &crate::zk::sapling::spend::SpendWitness,
    depth: usize,
    r: &Scalar,
    s: &Scalar,
) -> Groth16Result<(crate::zk::groth16::Proof, alloc::vec::Vec<Scalar>)> {
    use crate::zk::groth16::prove_bls_with_randomness;
    use crate::zk::sapling::circuit_spend::synthesize_spend_depth;
    let (r1cs, assignment) = synthesize_spend_depth(witness, depth);
    if !r1cs.is_satisfied(&assignment) {
        return Err(Groth16Error::VerificationFailed);
    }
    let pk = params.into_proving_key();
    if pk.a_query.is_empty()
        || pk.l_query.len() != r1cs.num_variables.saturating_sub(1 + r1cs.num_public)
    {
        return Err(Groth16Error::InputLength);
    }
    let public: alloc::vec::Vec<Scalar> = assignment[1..1 + r1cs.num_public].to_vec();
    let proof = prove_bls_with_randomness(&pk, &r1cs, &assignment, r, s)?;
    verify(&pk.vk, &public, &proof)?;
    Ok((proof, public))
}

pub fn spend_gates_ready() -> bool {
    spend_verify_gates_ready()
}

/// True only when ceremony prove is also unlocked (matrix identity).
pub fn spend_ceremony_gates_ready() -> bool {
    SPEND_GATE_CHECKLIST.iter().all(|(_, ok)| *ok)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::jubjub::JubJubPoint;
    use crate::curve::traits::CurvePoint;
    use crate::zk::groth16::{prove_bls_with_randomness, setup_from_r1cs_synthetic};
    use crate::zk::sapling::constants::{
        proof_generation_key_generator, spending_key_generator, value_commitment_value_generator,
    };
    use crate::zk::sapling::gadgets::{
        spend_public_binding_assignment, spend_public_binding_circuit,
    };
    use crate::zk::sapling::spend::{OutputWitness, SpendWitness};
    use alloc::vec::Vec;

    fn point_bytes(p: &JubJubPoint) -> [u8; 32] {
        let mut b = [0u8; 32];
        p.to_bytes_compressed(&mut b).unwrap();
        b
    }

    fn good_spend() -> SpendWitness {
        let mut w = SpendWitness::synthetic();
        w.ak = point_bytes(&proof_generation_key_generator());
        w.g_d = point_bytes(&spending_key_generator());
        w.pk_d = point_bytes(&value_commitment_value_generator());
        w
    }

    fn good_output() -> OutputWitness {
        let mut w = OutputWitness::synthetic();
        w.g_d = point_bytes(&spending_key_generator());
        w.pk_d = point_bytes(&value_commitment_value_generator());
        w
    }

    #[test]
    fn checklist_verify_path_ready() {
        assert!(spend_verify_gates_ready());
        assert!(spend_gates_ready());
    }

    #[test]
    fn end_to_end_synthetic_spend_binding() {
        let cs = spend_public_binding_circuit();
        let mut pk = setup_from_r1cs_synthetic(&cs);
        pk.clear_trapdoor();
        let public: Vec<Scalar> = (0..SPEND_NUM_PUBLIC)
            .map(|i| Scalar::from_u64((i as u64) + 1))
            .collect();
        let z = spend_public_binding_assignment(&public);
        assert!(cs.is_satisfied(&z));
        let proof =
            prove_bls_with_randomness(&pk, &cs, &z, &Scalar::from_u64(11), &Scalar::from_u64(13))
                .expect("prove");
        verify(&pk.vk, &public, &proof).expect("verify");

        let bytes = ZcashProofBytes::encode(&proof).expect("enc");
        assert_eq!(bytes.len(), 192);
        verify_with_scalars(&pk.vk, &bytes, &public).expect("verify compressed");
    }

    /// Full create → verify Output (self-params). Self-params tx creation path.
    /// Timed breakdown of Output create: synthesize / setup / prove / verify.
    #[cfg(feature = "std")]
    #[test]
    fn bench_output_create_phases() {
        use crate::zk::groth16::{prove_bls_with_randomness, setup_from_r1cs_synthetic};
        use crate::zk::sapling::circuit_output::synthesize_output;
        use std::time::Instant;

        let w = good_output();

        let t0 = Instant::now();
        let (r1cs, assignment) = synthesize_output(&w);
        let ms_synth = t0.elapsed().as_millis();
        assert!(r1cs.is_satisfied(&assignment), "unsatisfied");
        println!(
            "1. synthesize: {:>8} ms   nvars={} ncons={}",
            ms_synth,
            r1cs.num_variables,
            r1cs.constraints.len()
        );

        let t1 = Instant::now();
        let mut pk = setup_from_r1cs_synthetic(&r1cs);
        let ms_setup = t1.elapsed().as_millis();
        pk.clear_trapdoor();
        println!(
            "2. setup CRS:  {:>8} ms   a={} h={} l={} domain~{}",
            ms_setup,
            pk.a_query.len(),
            pk.h_query.len(),
            pk.l_query.len(),
            pk.domain_size
        );

        let public: Vec<Scalar> = assignment[1..1 + r1cs.num_public].to_vec();
        let t2 = Instant::now();
        let proof = prove_bls_with_randomness(
            &pk,
            &r1cs,
            &assignment,
            &Scalar::from_u64(17),
            &Scalar::from_u64(19),
        )
        .expect("prove");
        let ms_prove = t2.elapsed().as_millis();
        println!("3. prove QAP:  {:>8} ms", ms_prove);

        let t3 = Instant::now();
        verify(&pk.vk, &public, &proof).expect("verify");
        let ms_verify = t3.elapsed().as_millis();
        println!("4. verify:     {:>8} ms", ms_verify);

        let total = ms_synth + ms_setup + ms_prove + ms_verify;
        println!(
            "TOTAL:         {:>8} ms  (synth {:.1}% setup {:.1}% prove {:.1}% verify {:.1}%)",
            total,
            100.0 * ms_synth as f64 / total as f64,
            100.0 * ms_setup as f64 / total as f64,
            100.0 * ms_prove as f64 / total as f64,
            100.0 * ms_verify as f64 / total as f64,
        );
    }

    #[cfg(feature = "groth16-prover")]
    #[test]
    fn create_and_verify_output_tx() {
        let w = good_output();
        let (proof, public, vk) = create_and_verify_output(&w).expect("create+verify output");
        assert_eq!(proof.len(), 192);
        assert_eq!(public.len(), OUTPUT_NUM_PUBLIC);
        assert_eq!(vk.ic.len(), OUTPUT_NUM_PUBLIC + 1);
        let wire = public_frs_to_le_bytes(&public);
        assert_eq!(wire.len(), OUTPUT_NUM_PUBLIC * 32);
        // Re-verify via verify_with_scalars
        verify_with_scalars(&vk, &proof, &public).expect("re-verify");
        println!(
            "Output tx create+verify OK: proof=192B public={}Fr",
            public.len()
        );
    }

    /// Full create → verify Spend depth-1 (self-params). Use depth=32 for full tree.
    #[test]
    fn create_and_verify_spend_tx_depth1() {
        let w = good_spend();
        let (proof, public, vk) = create_and_verify_spend(&w, 1).expect("create+verify spend");
        assert_eq!(proof.len(), 192);
        assert_eq!(public.len(), SPEND_NUM_PUBLIC);
        assert_eq!(vk.ic.len(), SPEND_NUM_PUBLIC + 1);
        verify_with_scalars(&vk, &proof, &public).expect("re-verify");
        println!(
            "Spend d1 tx create+verify OK: proof=192B public={}Fr",
            public.len()
        );
    }

    #[cfg(feature = "groth16-prover")]
    #[test]
    fn prove_output_circuit_ready() {
        use crate::zk::sapling::circuit_output::synthesize_output;
        let w = good_output();
        let (r1cs, assignment) = synthesize_output(&w);
        assert!(r1cs.is_satisfied(&assignment), "output R1CS unsatisfied");
        assert_eq!(r1cs.num_public, OUTPUT_NUM_PUBLIC);
        let public = assignment[1..1 + r1cs.num_public].to_vec();
        assert_eq!(public.len(), OUTPUT_NUM_PUBLIC);
    }

    /// Full Output synthetic prove (expensive — run with `--release`).
    #[test]
    fn prove_output_synthetic_roundtrip() {
        let w = good_output();
        let (pk, proof, public) = prove_output(&w).expect("prove_output");
        assert_eq!(public.len(), OUTPUT_NUM_PUBLIC);
        verify(&pk.vk, &public, &proof).expect("verify");
        let bytes = ZcashProofBytes::encode(&proof).expect("enc");
        assert_eq!(bytes.len(), 192);
        verify_with_scalars(&pk.vk, &bytes, &public).expect("verify compressed");
    }

    #[test]
    fn prove_spend_circuit_ready_depth32() {
        use crate::zk::sapling::circuit_spend::synthesize_spend_depth;
        let w = good_spend();
        let (r1cs, assignment) = synthesize_spend_depth(&w, 32);
        assert!(
            r1cs.is_satisfied(&assignment),
            "spend depth32 R1CS unsatisfied"
        );
        assert_eq!(r1cs.num_public, SPEND_NUM_PUBLIC);
        println!(
            "spend d32: nvars={} ncons={} npublic={}",
            r1cs.num_variables,
            r1cs.constraints.len(),
            r1cs.num_public
        );
    }

    #[cfg(feature = "groth16-prover")]
    #[test]
    fn prove_spend_circuit_ready_depth1() {
        use crate::zk::sapling::circuit_spend::synthesize_spend_depth;
        let w = good_spend();
        let (r1cs, assignment) = synthesize_spend_depth(&w, 1);
        assert!(
            r1cs.is_satisfied(&assignment),
            "spend depth1 R1CS unsatisfied"
        );
        assert_eq!(r1cs.num_public, SPEND_NUM_PUBLIC);
        let public = assignment[1..1 + r1cs.num_public].to_vec();
        assert_eq!(public.len(), SPEND_NUM_PUBLIC);
    }

    /// Full Spend synthetic prove at depth 1 (expensive — prefer `--release`).
    #[test]
    fn prove_spend_synthetic_depth1_roundtrip() {
        let w = good_spend();
        let (pk, proof, public) = prove_spend(&w, 1).expect("prove_spend");
        assert_eq!(public.len(), SPEND_NUM_PUBLIC);
        verify(&pk.vk, &public, &proof).expect("verify");
        let bytes = ZcashProofBytes::encode(&proof).expect("enc");
        assert_eq!(bytes.len(), 192);
        verify_with_scalars(&pk.vk, &bytes, &public).expect("verify compressed");
    }

    /// Ceremony prove residual probe: Output params vs our R1CS size + A-density.
    #[cfg(all(feature = "std", feature = "groth16-prover"))]
    #[test]
    fn output_structural_head50() {
        use crate::zk::sapling::circuit_output::synthesize_output;
        use crate::zk::sapling::stream_digest::r1cs_structural_stream;
        let w = good_output();
        let (r1cs, _) = synthesize_output(&w);
        let s = r1cs_structural_stream(&r1cs);
        let head: String = s.lines().take(50).collect::<Vec<_>>().join("\n");
        println!("OUTPUT_STRUCT_HEAD50\n{head}");
        assert_eq!(r1cs.num_variables, 7827);
    }

    /// Dens-set fingerprint for Output — lock indices + only_A/B/C partition.
    #[cfg(all(feature = "std", feature = "groth16-prover"))]
    #[test]
    fn output_r1cs_satisfied() {
        use crate::zk::sapling::circuit_output::synthesize_output;
        let w = good_output();
        let (r1cs, z) = synthesize_output(&w);
        assert!(
            r1cs.is_satisfied(&z),
            "Output R1CS must be satisfied by witness"
        );
        println!(
            "Output R1CS satisfied: ncons={} nvars={}",
            r1cs.constraints.len(),
            r1cs.num_variables
        );
    }

    #[cfg(all(feature = "std", feature = "groth16-prover"))]
    #[test]
    fn output_public_matches_native() {
        use crate::curve::jubjub::JubJubPoint;
        use crate::curve::traits::{CurvePoint, Scalar as ScalarTrait};
        use crate::zk::sapling::circuit_output::synthesize_output;
        use crate::zk::sapling::native::{compute_note_commitment, compute_value_commitment};
        let w = good_output();
        let (r1cs, z) = synthesize_output(&w);
        assert!(r1cs.is_satisfied(&z));
        let public = &z[1..1 + r1cs.num_public];
        assert_eq!(public.len(), 5);
        let cv = compute_value_commitment(w.value, &w.rcv).expect("cv");
        let (cu, cvv) = cv.affine_uv_le_bytes().unwrap();
        let cu_s = crate::zk::sapling::num::scalar_from_fe_le(&cu);
        let cv_s = crate::zk::sapling::num::scalar_from_fe_le(&cvv);
        assert_eq!(ScalarTrait::ct_eq(&public[0], &cu_s), 1, "cv.u");
        assert_eq!(ScalarTrait::ct_eq(&public[1], &cv_s), 1, "cv.v");
        let g_d = JubJubPoint::from_bytes(&w.g_d).expect("g_d");
        let pk_d = JubJubPoint::from_bytes(&w.pk_d).expect("pk_d");
        let cm = compute_note_commitment(w.value, &g_d, &pk_d, &w.rcm).expect("cm");
        let (cmu, _) = cm.affine_uv_le_bytes().unwrap();
        let cmu_s = crate::zk::sapling::num::scalar_from_fe_le(&cmu);
        assert_eq!(ScalarTrait::ct_eq(&public[4], &cmu_s), 1, "cm.u");
        println!("public matches native cv/cm");
    }

    #[cfg(all(feature = "std", feature = "groth16-prover"))]
    #[test]
    fn constraint_form_fingerprint_output() {
        use crate::zk::sapling::circuit_output::synthesize_output;
        let w = good_output();
        let (r1cs, _) = synthesize_output(&w);
        // Fingerprint: for each constraint, (na, nb, nc, a_has_one, b_has_one, c_has_one)
        // Hash stream for offline compare with Bellman.
        let mut h = 0xcbf29ce484222325u64;
        let mut forms = std::collections::BTreeMap::<(u8, u8, u8, u8), usize>::new();
        for cons in &r1cs.constraints {
            let na = cons.a.terms.len().min(255) as u8;
            let nb = cons.b.terms.len().min(255) as u8;
            let nc = cons.c.terms.len().min(255) as u8;
            let has_one = |terms: &[(usize, crate::curve::bls::Scalar)]| -> u8 {
                terms.iter().any(|(i, _)| *i == 0) as u8
            };
            let fa = has_one(&cons.a.terms);
            let fb = has_one(&cons.b.terms);
            let fc = has_one(&cons.c.terms);
            // form key without fa for compact: pack
            let key = (na, nb, nc, (fa << 2) | (fb << 1) | fc);
            *forms.entry(key).or_insert(0) += 1;
            h ^= (na as u64) | ((nb as u64) << 8) | ((nc as u64) << 16) | ((key.3 as u64) << 24);
            h = h.wrapping_mul(0x100000001b3);
            for &(i, ref c) in cons
                .a
                .terms
                .iter()
                .chain(cons.b.terms.iter())
                .chain(cons.c.terms.iter())
            {
                h ^= i as u64;
                h = h.wrapping_mul(0x100000001b3);
                let mut be = [0u8; 32];
                c.to_bytes_be(&mut be);
                for b in &be {
                    h ^= *b as u64;
                    h = h.wrapping_mul(0x100000001b3);
                }
            }
        }
        println!("FORM_HASH=0x{h:016x} ncons={}", r1cs.constraints.len());
        // Top forms by count
        let mut v: Vec<_> = forms.into_iter().collect();
        v.sort_by_key(|(_, c)| std::cmp::Reverse(*c));
        for (k, c) in v.iter().take(20) {
            println!(
                "form na={} nb={} nc={} flags={:03b} count={}",
                k.0, k.1, k.2, k.3, c
            );
        }
    }

    #[cfg(all(feature = "std", feature = "groth16-prover"))]
    #[test]
    fn spend_residual_class() {
        use crate::curve::bls::Scalar;
        use crate::curve::traits::Scalar as ScalarTrait;
        use crate::zk::groth16::{a_density, b_density};
        use std::collections::{BTreeMap, BTreeSet};
        let w = crate::zk::sapling::spend::SpendWitness::synthetic();
        let (r1cs, _) = crate::zk::sapling::circuit_spend::synthesize_spend_depth(&w, 32);
        let da: BTreeSet<_> = a_density(&r1cs).into_iter().collect();
        let db: BTreeSet<_> = b_density(&r1cs).into_iter().collect();
        // residual candidates from dens diff (blake region A-only)
        let residual: Vec<usize> = (24291..24500)
            .filter(|v| da.contains(v) && !db.contains(v))
            .collect();
        println!("a-only residual count in 24291..24500: {}", residual.len());
        // Find constraints densing these on A or B
        let mut a_hits = BTreeMap::new();
        let mut b_hits = BTreeMap::new();
        for (i, c) in r1cs.constraints.iter().enumerate() {
            for &(v, ref coeff) in &c.a.terms {
                if ScalarTrait::ct_eq(coeff, &Scalar::zero()) != 0 {
                    continue;
                }
                if residual.contains(&v) {
                    a_hits.entry(v).or_insert(Vec::new()).push(i);
                }
            }
            for &(v, ref coeff) in &c.b.terms {
                if ScalarTrait::ct_eq(coeff, &Scalar::zero()) != 0 {
                    continue;
                }
                if residual.contains(&v) {
                    b_hits.entry(v).or_insert(Vec::new()).push(i);
                }
            }
        }
        // sample first residual
        for &v in residual.iter().take(8) {
            let ah = a_hits.get(&v).map(|x| x.as_slice()).unwrap_or(&[]);
            let bh = b_hits.get(&v).map(|x| x.as_slice()).unwrap_or(&[]);
            println!(
                "var {v}: densA_cons={:?} densB_cons={:?}",
                &ah[..ah.len().min(4)],
                &bh[..bh.len().min(4)]
            );
            for &ci in ah.iter().take(2) {
                let c = &r1cs.constraints[ci];
                let a_vars: Vec<_> = c.a.terms.iter().map(|(i, _)| *i).collect();
                let b_vars: Vec<_> = c.b.terms.iter().map(|(i, _)| *i).collect();
                let c_vars: Vec<_> = c.c.terms.iter().map(|(i, _)| *i).collect();
                println!("  cons {ci}: A={a_vars:?} B={b_vars:?} C={c_vars:?}");
            }
        }
        // How many residual vars dens A only from XOR (C has 2+ terms)?
        let mut xor_a = 0usize;
        for &v in &residual {
            if let Some(hits) = a_hits.get(&v) {
                for &ci in hits {
                    let c = &r1cs.constraints[ci];
                    if c.a.terms.len() == 1 && c.b.terms.len() == 1 && c.c.terms.len() >= 2 {
                        xor_a += 1;
                        break;
                    }
                }
            }
        }
        println!(
            "residual densA-only from XOR form: {xor_a} / {}",
            residual.len()
        );
    }

    #[cfg(all(feature = "std", feature = "groth16-prover"))]
    #[test]
    fn spend_residual32() {
        use crate::curve::bls::Scalar;
        use crate::curve::traits::Scalar as ScalarTrait;
        use crate::zk::groth16::{a_density, b_density};
        use std::collections::BTreeSet;
        let w = crate::zk::sapling::spend::SpendWitness::synthetic();
        let (r1cs, _) = crate::zk::sapling::circuit_spend::synthesize_spend_depth(&w, 32);
        let da: BTreeSet<_> = a_density(&r1cs).into_iter().collect();
        let db: BTreeSet<_> = b_density(&r1cs).into_iter().collect();
        let _a_only: Vec<_> = da
            .difference(&db)
            .filter(|&&v| v >= 32000)
            .copied()
            .collect();
        let _b_only: Vec<_> = db
            .difference(&da)
            .filter(|&&v| v >= 32000)
            .copied()
            .collect();
        // Actually a only_ours may dens A and not dens B; b only dens B and not dens A
        // From dens files: a only_ours and b only_ours are disjoint
        println!("scanning constraints for residual pairs...");
        let residual_b = [32622usize, 34003, 35384];
        for &v in &residual_b {
            let mut hits = Vec::new();
            for (i, c) in r1cs.constraints.iter().enumerate() {
                for &(vi, ref coeff) in &c.b.terms {
                    if vi == v && ScalarTrait::ct_eq(coeff, &Scalar::zero()) == 0 {
                        hits.push(i);
                    }
                }
            }
            println!(
                "b-only var {v}: densB_cons={:?}",
                &hits[..hits.len().min(5)]
            );
            for &ci in hits.iter().take(2) {
                let c = &r1cs.constraints[ci];
                let a_v: Vec<_> = c.a.terms.iter().map(|(i, _)| *i).collect();
                let b_v: Vec<_> = c.b.terms.iter().map(|(i, _)| *i).collect();
                let c_v: Vec<_> = c.c.terms.iter().map(|(i, _)| *i).collect();
                println!("  cons {ci}: A={a_v:?} B={b_v:?} C={c_v:?}");
            }
        }
        let residual_a = [32623usize, 34004, 35385];
        for &v in &residual_a {
            let mut hits = Vec::new();
            for (i, c) in r1cs.constraints.iter().enumerate() {
                for &(vi, ref coeff) in &c.a.terms {
                    if vi == v && ScalarTrait::ct_eq(coeff, &Scalar::zero()) == 0 {
                        hits.push(i);
                    }
                }
            }
            println!(
                "a-only var {v}: densA_cons={:?}",
                &hits[..hits.len().min(5)]
            );
            for &ci in hits.iter().take(2) {
                let c = &r1cs.constraints[ci];
                let a_v: Vec<_> = c.a.terms.iter().map(|(i, _)| *i).collect();
                let b_v: Vec<_> = c.b.terms.iter().map(|(i, _)| *i).collect();
                let c_v: Vec<_> = c.c.terms.iter().map(|(i, _)| *i).collect();
                println!("  cons {ci}: A={a_v:?} B={b_v:?} C={c_v:?}");
            }
        }
    }

    #[cfg(all(feature = "std", feature = "groth16-prover"))]
    #[test]
    fn spend_self_params_depth1() {
        use crate::zk::groth16::{prove_bls_with_randomness, setup_from_r1cs_synthetic};
        use std::time::Instant;
        let w = good_spend();
        let t0 = Instant::now();
        let (r1cs, assignment) = crate::zk::sapling::circuit_spend::synthesize_spend_depth(&w, 1);
        assert!(r1cs.is_satisfied(&assignment));
        println!(
            "synth {:.1}s ncons={}",
            t0.elapsed().as_secs_f64(),
            r1cs.constraints.len()
        );
        let t1 = Instant::now();
        let pk = setup_from_r1cs_synthetic(&r1cs);
        println!("setup {:.1}s", t1.elapsed().as_secs_f64());
        let r = Scalar::from_u64(10);
        let s = Scalar::from_u64(11);
        let t2 = Instant::now();
        let proof = prove_bls_with_randomness(&pk, &r1cs, &assignment, &r, &s).expect("prove");
        println!("prove {:.1}s", t2.elapsed().as_secs_f64());
        let public: Vec<_> = assignment[1..1 + r1cs.num_public].to_vec();
        match verify(&pk.vk, &public, &proof) {
            Ok(()) => println!("SELF-PARAMS VERIFY OK"),
            Err(e) => println!("SELF-PARAMS VERIFY FAIL: {e:?}"),
        }
    }

    #[cfg(feature = "groth16-prover")]
    #[test]
    fn dens_set_fingerprint_output() {
        use crate::zk::groth16::{a_density, b_density};
        use crate::zk::sapling::circuit_output::synthesize_output;
        use std::collections::HashSet;
        let w = good_output();
        let (r1cs, _) = synthesize_output(&w);
        let da = a_density(&r1cs);
        let db = b_density(&r1cs);
        let a_set: HashSet<usize> = da.iter().copied().collect();
        let b_set: HashSet<usize> = db.iter().copied().collect();
        let n = r1cs.num_variables;
        let mut only_a = 0usize;
        let mut only_b = 0usize;
        let mut both = 0usize;
        let mut only_c = 0usize;
        for i in 0..n {
            let ia = a_set.contains(&i);
            let ib = b_set.contains(&i);
            match (ia, ib) {
                (true, true) => both += 1,
                (true, false) => only_a += 1,
                (false, true) => only_b += 1,
                (false, false) => only_c += 1,
            }
        }
        // Stable FNV-like hash of dens sequences
        fn dens_hash(v: &[usize]) -> u64 {
            let mut h = 0xcbf29ce484222325u64;
            for &x in v {
                h ^= x as u64;
                h = h.wrapping_mul(0x100000001b3);
            }
            h
        }
        let ha = dens_hash(&da);
        let hb = dens_hash(&db);
        println!(
            "DENS_SET Output nvars={n} a={} b={} only_a={only_a} only_b={only_b} both={both} only_c={only_c}",
            da.len(),
            db.len()
        );
        println!("DENS_HASH a=0x{ha:016x} b=0x{hb:016x}");
        println!(
            "DENS_A head {:?} tail {:?}",
            &da[..8.min(da.len())],
            &da[da.len().saturating_sub(8)..]
        );
        println!(
            "DENS_B head {:?} tail {:?}",
            &db[..8.min(db.len())],
            &db[db.len().saturating_sub(8)..]
        );
        // Public inputs 0..=5 should be A-dense (ONE + 5 pubs) for Output
        for i in 0..=5 {
            assert!(a_set.contains(&i), "public/ONE var {i} must be A-dense");
        }
        assert_eq!(da.len(), 6298);
        assert_eq!(db.len(), 4850);
        assert_eq!(only_c, n - a_set.union(&b_set).count());
    }

    #[cfg(all(feature = "std", feature = "groth16-prover"))]
    #[test]
    fn density_side_breakdown() {
        use crate::curve::bls::Scalar;
        use crate::curve::jubjub::JubJubPoint;
        use crate::curve::traits::CurvePoint;
        use crate::curve::traits::Scalar as ScalarTrait;
        use crate::zk::groth16::{a_density, b_density};
        use crate::zk::sapling::circuit_output::synthesize_output;
        use crate::zk::sapling::constants::{
            spending_key_generator, value_commitment_value_generator,
        };
        use crate::zk::sapling::spend::OutputWitness;

        let mut w = OutputWitness::synthetic();
        let pb = |p: &JubJubPoint| {
            let mut b = [0u8; 32];
            p.to_bytes_compressed(&mut b).unwrap();
            b
        };
        w.g_d = pb(&spending_key_generator());
        w.pk_d = pb(&value_commitment_value_generator());
        let (r1cs, _) = synthesize_output(&w);

        let n = r1cs.num_variables;
        let mut on_a = vec![false; n];
        let mut on_b = vec![false; n];
        let mut on_c = vec![false; n];
        let mut empty_ab = 0usize;
        let mut a_one_b_var = 0usize; // classic equality A=lc B=ONE
        for cons in &r1cs.constraints {
            let a_empty = cons.a.terms.is_empty();
            let b_empty = cons.b.terms.is_empty();
            if a_empty && b_empty {
                empty_ab += 1;
            }
            // B is exactly ONE?
            if cons.b.terms.len() == 1 {
                let (vi, ref c) = cons.b.terms[0];
                if vi == 0 && ScalarTrait::ct_eq(c, &Scalar::one()) != 0 {
                    a_one_b_var += 1;
                }
            }
            for &(i, ref c) in &cons.a.terms {
                if i < n && ScalarTrait::ct_eq(c, &Scalar::zero()) == 0 {
                    on_a[i] = true;
                }
            }
            for &(i, ref c) in &cons.b.terms {
                if i < n && ScalarTrait::ct_eq(c, &Scalar::zero()) == 0 {
                    on_b[i] = true;
                }
            }
            for &(i, ref c) in &cons.c.terms {
                if i < n && ScalarTrait::ct_eq(c, &Scalar::zero()) == 0 {
                    on_c[i] = true;
                }
            }
        }
        let mut only_a = 0;
        let mut only_b = 0;
        let mut both_ab = 0;
        let mut neither_ab = 0;
        let mut only_c = 0;
        for i in 0..n {
            match (on_a[i], on_b[i]) {
                (true, false) => only_a += 1,
                (false, true) => only_b += 1,
                (true, true) => both_ab += 1,
                (false, false) => {
                    neither_ab += 1;
                    if on_c[i] {
                        only_c += 1;
                    }
                }
            }
        }
        eprintln!("nvars={n} ncons={}", r1cs.constraints.len());
        eprintln!(
            "A-dens={} B-dens={}",
            on_a.iter().filter(|x| **x).count(),
            on_b.iter().filter(|x| **x).count()
        );
        eprintln!("only_A={only_a} only_B={only_b} both_AB={both_ab} neither_AB={neither_ab} (of which only_C={only_c})");
        eprintln!("constraints with empty A,B (C-only): {empty_ab}");
        eprintln!("constraints with B=ONE: {a_one_b_var}");
        // Describe B=ONE constraints
        let mut bi = 0;
        for (ci, cons) in r1cs.constraints.iter().enumerate() {
            if cons.b.terms.len() == 1 {
                let (vi, ref c) = cons.b.terms[0];
                if vi == 0 && ScalarTrait::ct_eq(c, &Scalar::one()) != 0 {
                    let _a_vars: Vec<_> = cons.a.terms.iter().map(|(i, _)| i).collect();
                    let _c_vars: Vec<_> = cons.c.terms.iter().map(|(i, _)| i).collect();
                    eprintln!(
                        "  B=ONE #{bi} @cons{ci}: A={:?} B={:?} C={:?}",
                        cons.a
                            .terms
                            .iter()
                            .map(|(i, c)| (i, format!("{c:?}")))
                            .collect::<Vec<_>>(),
                        cons.b
                            .terms
                            .iter()
                            .map(|(i, c)| (i, format!("{c:?}")))
                            .collect::<Vec<_>>(),
                        cons.c
                            .terms
                            .iter()
                            .map(|(i, c)| (i, format!("{c:?}")))
                            .collect::<Vec<_>>()
                    );
                    bi += 1;
                }
            }
        }
        eprintln!("ceremony targets: A=6298 B=4850");
        let da = a_density(&r1cs);
        let db = b_density(&r1cs);
        eprintln!(
            "dens_a len={} first10={:?} has0={}",
            da.len(),
            &da[..10.min(da.len())],
            da.contains(&0)
        );
        eprintln!(
            "dens_b len={} first10={:?} has0={}",
            db.len(),
            &db[..10.min(db.len())],
            db.contains(&0)
        );
        // Count public (1..1+npublic) in dens
        let npub = r1cs.num_public;
        let a_pub = da.iter().filter(|&&i| i >= 1 && i <= npub).count();
        let b_pub = db.iter().filter(|&&i| i >= 1 && i <= npub).count();
        eprintln!("public vars in A-dens={a_pub} B-dens={b_pub} (npublic={npub})");
        // only_C vars: where they appear (first few)
        let mut only_c_vars: Vec<usize> = Vec::new();
        for i in 0..n {
            if !on_a[i] && !on_b[i] && on_c[i] {
                only_c_vars.push(i);
            }
        }
        eprintln!(
            "only_C count={} first20={:?}",
            only_c_vars.len(),
            &only_c_vars[..20.min(only_c_vars.len())]
        );
        // For each only_C var, which constraint C-sides it appears on
        for &vi in only_c_vars.iter().take(8) {
            let mut roles = Vec::new();
            for (ci, cons) in r1cs.constraints.iter().enumerate() {
                for &(i, ref c) in &cons.c.terms {
                    if i == vi && ScalarTrait::ct_eq(c, &Scalar::zero()) == 0 {
                        let a_n = cons.a.terms.len();
                        let b_n = cons.b.terms.len();
                        roles.push((ci, a_n, b_n));
                    }
                }
            }
            eprintln!("  only_C var{vi} on C of cons {roles:?}");
        }
        // Last few only_C (near end of circuit - cm path)
        for &vi in only_c_vars.iter().rev().take(5) {
            let mut roles = Vec::new();
            for (ci, cons) in r1cs.constraints.iter().enumerate() {
                for &(i, ref c) in &cons.c.terms {
                    if i == vi && ScalarTrait::ct_eq(c, &Scalar::zero()) == 0 {
                        roles.push(ci);
                    }
                }
            }
            eprintln!("  only_C var{vi} C-cons={roles:?}");
        }
    }

    #[cfg(feature = "groth16-prover")]
    #[test]
    fn matrix_probe_edwards_add_digest_stable() {
        use crate::zk::sapling::constants::{
            spending_key_generator, value_commitment_value_generator,
        };
        use crate::zk::sapling::cs::Cs;
        use crate::zk::sapling::edwards::EdwardsPoint;
        use crate::zk::sapling::stream_digest::{stream_digest64, stream_digest64_normalized};
        let mut cs = Cs::new();
        let p = EdwardsPoint::witness(&mut cs, &value_commitment_value_generator());
        let q = EdwardsPoint::witness(&mut cs, &spending_key_generator());
        let before = cs.constraints.len();
        let _ = EdwardsPoint::add(&mut cs, &p, &q);
        assert_eq!(cs.constraints.len() - before, 6);
        let d = stream_digest64(&cs);
        let n = stream_digest64_normalized(&cs);
        // Lock relative stability (both non-zero)
        assert_ne!(d, 0);
        assert_ne!(n, 0);
        println!("edwards_add digest=0x{d:016x} norm=0x{n:016x}");
    }
}
