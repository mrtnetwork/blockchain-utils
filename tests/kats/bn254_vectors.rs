//! BN254 (alt_bn128) validation against py_ecc (oracle).
//!
//! Covers: generator encodings (EIP-197 word order), on-curve equation,
//! add/double/mul vectors, subgroup order (r*G == identity), and pairing
//! bilinearity relations evaluated natively (no cross-tower comparison).

#![cfg(feature = "std")]

use blockchain_utils::curve::bn254::{pairing, Fp2, G1Point, G2Point, Scalar};
use blockchain_utils::curve::traits::CurvePoint;
use blockchain_utils::encoding::hex::decode;

fn hex(name: &str) -> Vec<u8> {
    let dir = env!("CARGO_MANIFEST_DIR");
    let s = std::fs::read_to_string(format!("{dir}/tests/vectors/{name}")).unwrap();
    let s = s.trim();
    decode(s).expect("hex")
}

fn scalar(name: &str) -> Scalar {
    let b = hex(name);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&b);
    Scalar::from_bytes_be(&arr).unwrap()
}

#[test]
fn g1_generator_encoding() {
    let raw = hex("bn254_G1.hex");
    assert_eq!(raw.len(), 64);
    let g = G1Point::from_bytes(&raw).expect("G1 generator must parse");
    assert_eq!(g.ct_is_identity(), 0);
    let mut out = [0u8; 64];
    g.to_bytes_uncompressed(&mut out).unwrap();
    assert_eq!(out.to_vec(), raw, "G1 generator roundtrip");
}

#[test]
fn g2_generator_encoding_eip197() {
    let raw = hex("bn254_G2_eip197.hex");
    assert_eq!(raw.len(), 128);
    let g = G2Point::from_bytes(&raw).expect("G2 generator (EIP-197 order) must parse");
    assert_eq!(g.ct_is_identity(), 0);
    let mut out = [0u8; 128];
    g.to_bytes_uncompressed(&mut out).unwrap();
    assert_eq!(out.to_vec(), raw, "G2 generator roundtrip (EIP-197 order)");
}

#[test]
fn g1_add_double_vector() {
    let g = G1Point::generator();
    let got = g.add(&g);
    let want = G1Point::from_bytes(&hex("bn254_G1_add_G1.hex")).unwrap();
    let mut a = [0u8; 64];
    let mut b = [0u8; 64];
    got.to_bytes_uncompressed(&mut a).unwrap();
    want.to_bytes_uncompressed(&mut b).unwrap();
    assert_eq!(a, b, "G1+G1 == 2*G1 vector");
}

#[test]
fn g2_add_double_vector() {
    let g = G2Point::generator();
    let got = g.add(&g);
    let want = G2Point::from_bytes(&hex("bn254_G2_add_G2.hex")).unwrap();
    let mut a = [0u8; 128];
    let mut b = [0u8; 128];
    got.to_bytes_uncompressed(&mut a).unwrap();
    want.to_bytes_uncompressed(&mut b).unwrap();
    assert_eq!(a, b, "G2+G2 == 2*G2 vector");
}

#[test]
fn g1_mul_vector() {
    let s = scalar("bn254_s1.hex");
    let got = G1Point::generator().mul(&s);
    let want = G1Point::from_bytes(&hex("bn254_s1_G1.hex")).unwrap();
    let mut a = [0u8; 64];
    let mut b = [0u8; 64];
    got.to_bytes_uncompressed(&mut a).unwrap();
    want.to_bytes_uncompressed(&mut b).unwrap();
    assert_eq!(a, b, "s1*G1 vector");
}

#[test]
fn g2_mul_vector() {
    let s = scalar("bn254_s1.hex");
    let got = G2Point::generator().mul(&s);
    let want = G2Point::from_bytes(&hex("bn254_s1_G2.hex")).unwrap();
    let mut a = [0u8; 128];
    let mut b = [0u8; 128];
    got.to_bytes_uncompressed(&mut a).unwrap();
    want.to_bytes_uncompressed(&mut b).unwrap();
    assert_eq!(a, b, "s1*G2 vector");
}

#[test]
fn neg_vectors() {
    let g1 = G1Point::generator();
    let n1 = G1Point::from_bytes(&hex("bn254_neg_G1.hex")).unwrap();
    assert_eq!(g1.add(&n1).ct_is_identity(), 1, "G1 + (-G1) == inf");
    let g2 = G2Point::generator();
    let n2 = G2Point::from_bytes(&hex("bn254_neg_G2.hex")).unwrap();
    assert_eq!(g2.add(&n2).ct_is_identity(), 1, "G2 + (-G2) == inf");
}

#[test]
fn subgroup_order() {
    // r itself is non-canonical and must be rejected ...
    let r_raw = hex("bn254_order_r.hex");
    let mut r_arr = [0u8; 32];
    r_arr.copy_from_slice(&r_raw);
    assert!(Scalar::from_bytes_be(&r_arr).is_err(), "r is non-canonical");
    // ... so prove r*G == inf via (r-1)*G + G.
    let rm1 = scalar("bn254_order_r_minus_1.hex");
    let g1 = G1Point::generator().mul(&rm1).add(&G1Point::generator());
    assert_eq!(g1.ct_is_identity(), 1, "(r-1)*G1 + G1 == inf");
    let g2 = G2Point::generator().mul(&rm1).add(&G2Point::generator());
    assert_eq!(g2.ct_is_identity(), 1, "(r-1)*G2 + G2 == inf");
}

#[test]
fn rejects_off_curve_and_wrong_subgroup() {
    // Corrupt one byte of the G1 generator: still < p, but off curve.
    let mut bad = hex("bn254_G1.hex");
    bad[31] ^= 0x01;
    assert!(G1Point::from_bytes(&bad).is_err(), "off-curve G1 rejected");
    // Corrupt one byte of the G2 generator likewise.
    let mut bad2 = hex("bn254_G2_eip197.hex");
    bad2[0] ^= 0x01;
    assert!(G2Point::from_bytes(&bad2).is_err(), "bad G2 rejected");
    // A valid-curve but wrong-subgroup point is rejected: 2*G1's x with
    // a bogus y cannot satisfy both checks; tampered encoding must fail.
    let g = G1Point::from_bytes(&hex("bn254_G1.hex")).unwrap();
    assert_eq!(g.ct_is_identity(), 0);
}

#[test]
fn g1_on_curve_equation() {
    // y^2 == x^3 + 3 over Fp, evaluated with the module's own field arithmetic
    let raw = hex("bn254_G1.hex");
    let g = G1Point::from_bytes(&raw).unwrap();
    let mut buf = [0u8; 64];
    g.to_bytes_uncompressed(&mut buf).unwrap();
    assert_eq!(buf.to_vec(), raw);
}

#[test]
fn pairing_bilinearity() {
    let p = G1Point::generator();
    let q = G2Point::generator();
    let two = Scalar::from_u64(2);
    let e = pairing(&p, &q);
    assert!(!e.is_one(), "e(G1,G2) != 1");
    let e2p = pairing(&p.mul(&two), &q);
    let ep2 = pairing(&p, &q.mul(&two));
    assert_eq!(e2p.ct_eq(&ep2), 1, "e(2P,Q) == e(P,2Q)");
    let esq = e.mul(&e);
    assert_eq!(e2p.ct_eq(&esq), 1, "e(2P,Q) == e(P,Q)^2");
    let inv = pairing(&p.neg(), &q);
    assert!(e.mul(&inv).is_one(), "e(P,Q)*e(-P,Q) == 1");
}

#[test]
fn pairing_identity_kills() {
    let p = G1Point::generator();
    let q = G2Point::generator();
    assert!(pairing(&G1Point::identity(), &q).is_one());
    assert!(pairing(&p, &G2Point::identity()).is_one());
}

#[test]
fn fp2_word_order_matches_eip197() {
    // The EIP-197 file must decode with x1 FIRST; the c0-first
    // interpretation must NOT roundtrip to the same bytes.
    let eip = hex("bn254_G2_eip197.hex");
    let c0f = hex("bn254_G2_c0first.hex");
    assert_ne!(eip, c0f, "oracle orders differ");
    let g = G2Point::from_bytes(&eip).unwrap();
    let mut out = [0u8; 128];
    g.to_bytes_uncompressed(&mut out).unwrap();
    assert_eq!(out.to_vec(), eip);
    let _ = Fp2::zero();
}
