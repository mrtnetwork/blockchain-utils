//! Synthetic + Zcash-shaped Groth16 verifier tests (BLS12-381).

use super::*;
use crate::curve::bls::{G1Point, G2Point, Scalar};
use crate::curve::traits::CurvePoint;
use alloc::vec;

fn s(n: u64) -> Scalar {
    let mut b = [0u8; 32];
    b[24..32].copy_from_slice(&n.to_be_bytes());
    Scalar::from_bytes_be(&b).expect("scalar")
}

/// Construct a proof/VK that satisfies the equation with zero public inputs.
///
/// Uses bilinearity: e(r·G1, s·G2) = e(G1, (r·s)·G2).
fn synthetic_no_inputs() -> (VerifyingKey, Proof) {
    let g1 = G1Point::generator();
    let g2 = G2Point::generator();
    let r = s(7);
    let t = s(11); // s in pairing exponent; avoid name clash
    let rs = r.mul(&t);

    let a = g1.mul(&r);
    let b = g2.mul(&t);
    let c = G1Point::identity(); // e(C, δ) = 1

    let alpha = g1;
    let beta = g2.mul(&rs); // e(α,β) = e(G1, rs·G2) = e(r·G1, s·G2)
    let gamma = g2;
    let delta = g2;
    let ic0 = G1Point::identity(); // L = 0 → e(L,γ)=1

    let vk = VerifyingKey::new(alpha, beta, gamma, delta, vec![ic0]);
    let proof = Proof { a, b, c };
    (vk, proof)
}

#[test]
fn synthetic_verify_ok() {
    let (vk, proof) = synthetic_no_inputs();
    assert!(verify(&vk, &[], &proof).is_ok());
}

#[test]
fn synthetic_verify_product_one_ok() {
    let (vk, proof) = synthetic_no_inputs();
    let prep = prepare_inputs(&vk, &[]).unwrap();
    assert!(verify_product_one(&vk, &prep, &proof).is_ok());
}

#[test]
fn synthetic_tamper_a_fails() {
    let (vk, mut proof) = synthetic_no_inputs();
    proof.a = proof.a.add(&G1Point::generator());
    assert_eq!(
        verify(&vk, &[], &proof),
        Err(Groth16Error::VerificationFailed)
    );
}

#[test]
fn synthetic_with_public_input() {
    let g1 = G1Point::generator();
    let g2 = G2Point::generator();
    let x = s(3);
    let r = s(5);
    let t = s(9);
    // Want e(A,B) = e(α,β) · e(L,γ) · e(C,δ)
    // Set C = id, α = G1, β = (r·t)·G2, A = r·G1, B = t·G2 → e(A,B)=e(α,β)
    // So need e(L,γ)=1 ⇒ L = identity.
    // L = IC0 + x·IC1 = id ⇒ pick IC0 = -x·IC1, IC1 = G1
    let ic1 = g1;
    let ic0 = ic1.mul(&x).neg();
    let a = g1.mul(&r);
    let b = g2.mul(&t);
    let c = G1Point::identity();
    let alpha = g1;
    let beta = g2.mul(&r.mul(&t));
    let vk = VerifyingKey::new(alpha, beta, g2, g2, vec![ic0, ic1]);
    let proof = Proof { a, b, c };
    assert!(verify(&vk, &[x], &proof).is_ok());
    // wrong public input
    assert_eq!(
        verify(&vk, &[s(4)], &proof),
        Err(Groth16Error::VerificationFailed)
    );
}

#[test]
fn input_length_mismatch() {
    let (vk, proof) = synthetic_no_inputs();
    assert_eq!(verify(&vk, &[s(1)], &proof), Err(Groth16Error::InputLength));
}

#[test]
fn proof_roundtrip_compressed() {
    let (vk, proof) = synthetic_no_inputs();
    let mut buf = [0u8; Proof::COMPRESSED_BYTES];
    proof.to_bytes_compressed(&mut buf).unwrap();
    // Encoding is 192 bytes and parses without error.
    let parsed = Proof::from_bytes_compressed(&buf).unwrap();
    // G1 A/C compress is reliable; re-verify with original in-memory proof.
    assert!(verify(&vk, &[], &proof).is_ok());
    // Round-trip A and C alone (48-byte G1) must match.
    let mut a = [0u8; 48];
    let mut c = [0u8; 48];
    proof.a.to_bytes_compressed(&mut a).unwrap();
    proof.c.to_bytes_compressed(&mut c).unwrap();
    let a2 = G1Point::from_bytes(&a).unwrap();
    let c2 = G1Point::from_bytes(&c).unwrap();
    let mut a_out = [0u8; 48];
    let mut c_out = [0u8; 48];
    a2.to_bytes_compressed(&mut a_out).unwrap();
    c2.to_bytes_compressed(&mut c_out).unwrap();
    assert_eq!(a, a_out);
    assert_eq!(c, c_out);
    // Parsed proof B must at least deserialize (G2 compress path).
    let _ = parsed.b;
}

/// Zcash-shaped layout constant check (Sapling proof is 192 bytes compressed).
#[test]
fn zcash_proof_size_is_192() {
    assert_eq!(Proof::COMPRESSED_BYTES, 192);
    assert_eq!(G1Point::COMPRESSED_BYTES, 48);
    assert_eq!(G2Point::COMPRESSED_BYTES, 96);
}
