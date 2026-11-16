//! Official Sapling Output byte-compat tests (bellman oracle).
//!
//! Run with: `cargo test --features groth16-prover --test benches groth16_compare`
//!
//! Fixtures in `tests/vectors/` were generated deterministically by
//! `proofgen` (sapling-crypto 0.7.0 + bellman 0.14, fixed seeds):
//! - `output_proof.bin`: 192-byte official Groth16 Output proof
//! - `output_vk.bin`: bellman `VerifyingKey::write` encoding (1444 bytes)
//! - `output_inputs.bin`: 5x32 LE Fr, official order
//!   `[cv_u, cv_v, epk_u, epk_v, cm_u]`
//!
//! These assert OUR verifier accepts OFFICIAL bytes (the production-critical
//! direction). `output_proof.bin` is byte-pinned: any change to these
//! assertions means consensus divergence.

#![cfg(feature = "groth16-prover")]

use blockchain_utils::encoding::hex::decode;
use blockchain_utils::zk::sapling::{load_verifying_key, verify_output, OutputPublicInputs};
use blockchain_utils::zk::ZcashProofBytes;

fn limb(b: &[u8]) -> [u8; 32] {
    let mut a = [0u8; 32];
    a.copy_from_slice(&b[..32]);
    a
}

fn fixtures() -> (Vec<u8>, Vec<u8>, OutputPublicInputs) {
    let proof = std::fs::read("tests/vectors/output_proof.bin").expect("proof fixture");
    let vk = std::fs::read("tests/vectors/output_vk.bin").expect("vk fixture");
    let inp = std::fs::read("tests/vectors/output_inputs.bin").expect("inputs fixture");
    assert_eq!(proof.len(), 192);
    assert_eq!(vk.len(), 1444);
    assert_eq!(inp.len(), 5 * 32);
    let public = OutputPublicInputs {
        cv_u: limb(&inp[0..32]),
        cv_v: limb(&inp[32..64]),
        epk_u: limb(&inp[64..96]),
        epk_v: limb(&inp[96..128]),
        cm_u: limb(&inp[128..160]),
    };
    (proof, vk, public)
}

#[test]
fn official_output_proof_verifies_under_official_vk() {
    let (proof, vk_bytes, public) = fixtures();
    let vk = load_verifying_key(&vk_bytes, true).expect("vk decode");
    assert_eq!(vk.ic.len(), 5 + 1);
    verify_output(&vk, &proof, &public).expect("official proof must verify");
}

#[test]
fn official_output_proof_bytes_decode() {
    let (proof, _, _) = fixtures();
    // Proof decodes through our Zcash codec untouched.
    let _ = ZcashProofBytes::decode(&proof).expect("decode");
}

#[test]
fn official_output_tampered_proof_fails() {
    let (mut proof, vk_bytes, public) = fixtures();
    proof[0] ^= 1;
    let vk = load_verifying_key(&vk_bytes, true).expect("vk decode");
    assert!(verify_output(&vk, &proof, &public).is_err());
}

#[test]
fn official_output_wrong_inputs_fail() {
    let (proof, vk_bytes, mut public) = fixtures();
    public.cm_u[0] ^= 1;
    let vk = load_verifying_key(&vk_bytes, true).expect("vk decode");
    assert!(verify_output(&vk, &proof, &public).is_err());
}

fn ceremony_fixtures() -> (Vec<u8>, Vec<u8>, OutputPublicInputs) {
    let proof = std::fs::read("tests/vectors/output_ceremony_proof.bin").expect("ceremony proof");
    let vk = std::fs::read("tests/vectors/output_ceremony_vk.bin").expect("ceremony vk");
    let inp = std::fs::read("tests/vectors/output_ceremony_inputs.bin").expect("ceremony in");
    assert_eq!(proof.len(), 192);
    assert_eq!(vk.len(), 1444);
    assert_eq!(inp.len(), 5 * 32);
    let public = OutputPublicInputs {
        cv_u: limb(&inp[0..32]),
        cv_v: limb(&inp[32..64]),
        epk_u: limb(&inp[64..96]),
        epk_v: limb(&inp[96..128]),
        cm_u: limb(&inp[128..160]),
    };
    (proof, vk, public)
}

/// Official proof made UNDER THE REAL CEREMONY VK verifies in our code.
/// This is the consensus-critical direction: mainnet-shaped bytes accepted.
#[test]
fn ceremony_output_proof_verifies_under_ceremony_vk() {
    let (proof, vk_bytes, public) = ceremony_fixtures();
    let vk = load_verifying_key(&vk_bytes, true).expect("ceremony vk decode");
    assert_eq!(vk.ic.len(), 5 + 1);
    println!("verify {:#?}",verify_output(&vk, &proof, &public));
    verify_output(&vk, &proof, &public).expect("ceremony proof must verify");
}

#[test]
fn ceremony_output_tampered_proof_fails() {
    let (mut proof, vk_bytes, public) = ceremony_fixtures();
    proof[64] ^= 1;
    let vk = load_verifying_key(&vk_bytes, true).expect("ceremony vk decode");
    assert!(verify_output(&vk, &proof, &public).is_err());
}

fn hex32(s: &str) -> [u8; 32] {
    let v = decode(s).expect("hex");
    assert_eq!(v.len(), 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

fn spend_ceremony_fixtures() -> (Vec<u8>, Vec<u8>, Vec<[u8; 32]>) {
    let proof = std::fs::read("tests/vectors/spend_ceremony_proof.bin").expect("spend proof");
    let vk = std::fs::read("tests/vectors/spend_ceremony_vk.bin").expect("spend vk");
    let inp = std::fs::read("tests/vectors/spend_ceremony_inputs.bin").expect("spend in");
    assert_eq!(proof.len(), 192);
    assert_eq!(vk.len(), 1636);
    assert_eq!(inp.len(), 7 * 32);
    let mut limbs = Vec::with_capacity(7);
    for i in 0..7 {
        let mut a = [0u8; 32];
        a.copy_from_slice(&inp[i * 32..(i + 1) * 32]);
        limbs.push(a);
    }
    // Official order (bellman-verified): rk_u, rk_v, cv_u, cv_v, rt, nf0, nf1.
    (proof, vk, limbs)
}

/// Official Spend proof under the real ceremony VK verifies (positional).
#[test]
fn ceremony_spend_proof_verifies_under_ceremony_vk() {
    use blockchain_utils::curve::bls::Scalar;
    use blockchain_utils::zk::sapling::{load_verifying_key, verify_with_scalars};
    let (proof, vk_bytes, limbs) = spend_ceremony_fixtures();
    let vk = load_verifying_key(&vk_bytes, true).expect("spend vk decode");
    assert_eq!(vk.ic.len(), 7 + 1);
    let scalars: Vec<Scalar> = limbs
        .iter()
        .map(|l| Scalar::from_bytes_le(l).expect("scalar"))
        .collect();
    verify_with_scalars(&vk, &proof, &scalars).expect("ceremony spend must verify");
}

/// Same via the struct path (exercises fixed 254-bit nf multipack).
#[test]
fn ceremony_spend_struct_verify_matches() {
    use blockchain_utils::zk::sapling::{load_verifying_key, verify_spend, SpendPublicInputs};
    let (proof, vk_bytes, limbs) = spend_ceremony_fixtures();
    let vk = load_verifying_key(&vk_bytes, true).expect("spend vk decode");
    let public = SpendPublicInputs {
        cv_u: limbs[2],
        cv_v: limbs[3],
        rk_u: limbs[0],
        rk_v: limbs[1],
        anchor: limbs[4],
        nullifier: hex32("9b3b38218ef9da77ad4186e94249d2721c41b43f9bd4cf9ce2294f26c96a4e85"),
    };
    verify_spend(&vk, &proof, &public).expect("struct spend verify must pass");
}

#[test]
fn ceremony_spend_tampered_fails() {
    use blockchain_utils::curve::bls::Scalar;
    use blockchain_utils::zk::sapling::{load_verifying_key, verify_with_scalars};
    let (mut proof, vk_bytes, limbs) = spend_ceremony_fixtures();
    proof[100] ^= 1;
    let vk = load_verifying_key(&vk_bytes, true).expect("spend vk decode");
    let scalars: Vec<Scalar> = limbs
        .iter()
        .map(|l| Scalar::from_bytes_le(l).expect("scalar"))
        .collect();
    assert!(verify_with_scalars(&vk, &proof, &scalars).is_err());
}
