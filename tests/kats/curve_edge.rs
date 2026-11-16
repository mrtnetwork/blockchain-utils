//! Edge-case vectors: identity, order, invalid encodings, cofactor spots.
//!
//! Complements `curve_vectors.rs` (generators + RFC vectors). Every case is
//! deterministic and fast (no proving, no files).

use blockchain_utils::curve::traits::CurvePoint;

fn be_add1(n: &[u8; 32]) -> [u8; 32] {
    let mut out = *n;
    for i in (0..32).rev() {
        let (v, c) = out[i].overflowing_add(1);
        out[i] = v;
        if !c {
            break;
        }
    }
    out
}

#[test]
fn secp256k1_order_edges() {
    use blockchain_utils::curve::secp256k1::{scalar::N_BE, Scalar, Secp256k1Point};
    let g = Secp256k1Point::generator();
    let zero = Scalar::from_bytes_be(&[0u8; 32]).unwrap();
    assert_eq!(g.mul(&zero).ct_is_identity(), 1, "[0]G == inf");
    assert!(Scalar::from_bytes_be(&N_BE).is_err(), "n rejects");
    // Reducing decode: [n]G == inf, [n+1]G == G.
    let n0 = Scalar::from_bytes_mod_order(&N_BE);
    assert_eq!(g.mul(&n0).ct_is_identity(), 1, "[n]G == inf");
    let n1 = Scalar::from_bytes_mod_order(&be_add1(&N_BE));
    let g1 = g.mul(&Scalar::one());
    let diff = g.mul(&n1).add(&g1.neg());
    assert_eq!(diff.ct_is_identity(), 1, "[n+1]G == G");
    // Invalid compressed encodings reject.
    let mut x_zero = [0u8; 33];
    x_zero[0] = 0x02;
    assert!(Secp256k1Point::from_bytes(&x_zero).is_err(), "x=0 rejects");
}

#[test]
fn secp256r1_order_edges() {
    use blockchain_utils::curve::secp256r1::{scalar::N_BE, Scalar, Secp256r1Point};
    let g = Secp256r1Point::generator();
    let zero = Scalar::from_bytes_be(&[0u8; 32]).unwrap();
    assert_eq!(g.mul(&zero).ct_is_identity(), 1, "[0]G == inf");
    assert!(Scalar::from_bytes_be(&N_BE).is_err(), "n rejects");
    let n0 = Scalar::from_bytes_mod_order(&N_BE);
    assert_eq!(g.mul(&n0).ct_is_identity(), 1, "[n]G == inf");
    let n1 = Scalar::from_bytes_mod_order(&be_add1(&N_BE));
    let diff = g.mul(&n1).add(&g.mul(&Scalar::one()).neg());
    assert_eq!(diff.ct_is_identity(), 1, "[n+1]G == G");
    let mut x_zero = [0u8; 33];
    x_zero[0] = 0x03;
    // x=0 happens to be a valid P-256 x (b is a residue); use x=p (range).
    let mut x_p = [0u8; 33];
    x_p[0] = 0x03;
    x_p[1..33].copy_from_slice(&[
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF,
    ]);
    assert!(
        Secp256r1Point::from_bytes(&x_zero).is_ok(),
        "x=0 valid on P-256"
    );
    assert!(Secp256r1Point::from_bytes(&x_p).is_err(), "x=p rejects");
}

#[test]
fn ed25519_order_and_identity_edges() {
    use blockchain_utils::curve::ed25519::scalar::L_LE;
    use blockchain_utils::curve::ed25519::{Ed25519Point, Scalar};
    let g = Ed25519Point::generator();
    let zero = Scalar::from_bytes_le(&[0u8; 32]).unwrap();
    assert_eq!(g.mul(&zero).ct_is_identity(), 1, "[0]G == id");
    assert!(Scalar::from_bytes_le(&L_LE).is_err(), "L rejects");
    // Identity encoding (0,1) -> y=1 LE.
    let mut id_enc = [0u8; 32];
    id_enc[0] = 1;
    let id = Ed25519Point::from_bytes(&id_enc).unwrap();
    assert_eq!(id.ct_is_identity(), 1, "identity decodes");
    // Cofactor spot: [8]G is not G and not identity.
    let eight = Scalar::from_bytes_le(&{
        let mut b = [0u8; 32];
        b[0] = 8;
        b
    })
    .unwrap();
    let g8 = g.mul(&eight);
    assert_eq!(g8.ct_is_identity(), 0, "[8]G != id");
    let d8 = g8.add(&g.neg());
    assert_eq!(d8.ct_is_identity(), 0, "[8]G != G");
}

#[test]
fn ristretto_encode_edges() {
    use blockchain_utils::curve::ed25519::Scalar;
    use blockchain_utils::curve::ristretto::RistrettoPoint;
    let g = RistrettoPoint::generator();
    let zero = Scalar::from_bytes_le(&[0u8; 32]).unwrap();
    let inf = g.mul(&zero);
    let mut enc = [0u8; 32];
    assert!(inf.encode(&mut enc).is_ok());
    assert_eq!(enc, [0u8; 32], "identity encodes as zeros");
    assert!(RistrettoPoint::decode(&[0u8; 32]).is_ok(), "zeros decode");
    assert!(
        RistrettoPoint::decode(&[0xffu8; 32]).is_err(),
        "non-canonical rejects"
    );
}

#[test]
fn jubjub_order_edges() {
    use blockchain_utils::curve::jubjub::{JubJubPoint, Scalar, N_BE};
    let g = JubJubPoint::generator();
    let zero = Scalar::from_bytes_be(&[0u8; 32]).unwrap();
    assert_eq!(g.mul(&zero).ct_is_identity(), 1, "[0]G == id");
    assert!(Scalar::from_bytes_be(&N_BE).is_err(), "order rejects");
}

#[test]
fn pallas_vesta_order_edges() {
    use blockchain_utils::curve::pallas::{PallasPoint, Scalar as PScalar, N_BE as PN_BE};
    use blockchain_utils::curve::vesta::{Scalar as VScalar, VestaPoint, N_BE as VN_BE};
    for (name, ok) in [
        ("pallas", {
            let g = PallasPoint::generator();
            let zero = PScalar::from_bytes_be(&[0u8; 32]).unwrap();
            g.mul(&zero).ct_is_identity() == 1 && PScalar::from_bytes_be(&PN_BE).is_err()
        }),
        ("vesta", {
            let g = VestaPoint::generator();
            let zero = VScalar::from_bytes_be(&[0u8; 32]).unwrap();
            g.mul(&zero).ct_is_identity() == 1 && VScalar::from_bytes_be(&VN_BE).is_err()
        }),
    ] {
        assert!(ok, "{name} edges");
    }
}

#[test]
fn bls_g1_g2_zero_and_canonical() {
    use blockchain_utils::curve::bls::{G1Point, G2Point};
    let z1 = <G1Point as CurvePoint>::Scalar::from_bytes_be(&[0u8; 32]).unwrap();
    assert_eq!(G1Point::generator().mul(&z1).ct_is_identity(), 1, "[0]G1");
    let z2 = <G2Point as CurvePoint>::Scalar::from_bytes_be(&[0u8; 32]).unwrap();
    assert_eq!(G2Point::generator().mul(&z2).ct_is_identity(), 1, "[0]G2");
}

#[test]
fn x25519_commutativity_and_zero() {
    use blockchain_utils::curve::x25519::{public_key, x25519};
    // Fixed keys (external anchor: Noise-spec interop in hw_noise_vector.rs).
    let mut a = [0x11u8; 32];
    let mut b = [0x22u8; 32];
    a[0] = 0xa5;
    b[0] = 0x5a;
    let pa = public_key(&a);
    let pb = public_key(&b);
    // Commutativity: dh(a, B) == dh(b, A).
    assert_eq!(x25519(&a, &pb), x25519(&b, &pa), "dh commutes");
    // Determinism.
    assert_eq!(x25519(&a, &pb), x25519(&a, &pb), "dh deterministic");
    // Zero input gives zero output.
    assert_eq!(x25519(&a, &[0u8; 32]), [0u8; 32], "dh(k, 0) == 0");
}
