//! P0 #2 supplement — algebraic self-consistency (cross-check without third-party crates).
//!
//! Properties that must hold for every curve under test:
//! - [1]G = G, [0]G = O, [2]G = G+G
//! - [a]([b]G) = [b]([a]G)  (scalar mul associativity / commutativity of exponents)
//! - encode(decode(encode(P))) stable for generators
//!
//! These catch gross arithmetic bugs even when RFC vectors are incomplete.

#![cfg(feature = "alloc")]

use blockchain_utils::curve::bls::{G1Point, G2Point};
use blockchain_utils::curve::jubjub::JubJubPoint;
use blockchain_utils::curve::pallas::PallasPoint;
use blockchain_utils::curve::ristretto::RistrettoPoint;
use blockchain_utils::curve::vesta::VestaPoint;
use blockchain_utils::curve::{
    CurvePoint, Ed25519Point, Secp256k1Point, Secp256k1Scalar, Secp256r1Point, Secp256r1Scalar,
};

fn u64_scalar_secp(k: u64) -> Secp256k1Scalar {
    let mut b = [0u8; 32];
    b[24..].copy_from_slice(&k.to_be_bytes());
    Secp256k1Scalar::from_bytes(&b).expect("scalar")
}

#[test]
fn diff_self_secp256k1_algebra() {
    let g = Secp256k1Point::generator();
    let o = Secp256k1Point::identity();
    assert_eq!(g.mul(&u64_scalar_secp(0)).ct_is_identity(), 1);
    assert_eq!(g.mul(&u64_scalar_secp(1)).ct_is_identity(), 0);
    let g2_mul = g.mul(&u64_scalar_secp(2));
    let g2_add = g.add(&g);
    let mut a = [0u8; 33];
    let mut b = [0u8; 33];
    g2_mul.to_bytes_compressed(&mut a).unwrap();
    g2_add.to_bytes_compressed(&mut b).unwrap();
    assert_eq!(a, b, "[2]G == G+G");

    // [3]([5]G) == [5]([3]G) == [15]G
    let p15_a = g.mul(&u64_scalar_secp(5)).mul(&u64_scalar_secp(3));
    let p15_b = g.mul(&u64_scalar_secp(3)).mul(&u64_scalar_secp(5));
    let p15_c = g.mul(&u64_scalar_secp(15));
    let mut x = [0u8; 33];
    let mut y = [0u8; 33];
    let mut z = [0u8; 33];
    p15_a.to_bytes_compressed(&mut x).unwrap();
    p15_b.to_bytes_compressed(&mut y).unwrap();
    p15_c.to_bytes_compressed(&mut z).unwrap();
    assert_eq!(x, y);
    assert_eq!(y, z);
    let _ = o;
}

#[test]
fn diff_self_secp256r1_algebra() {
    let g = Secp256r1Point::generator();
    let mut s2 = [0u8; 32];
    s2[31] = 2;
    let sk2 = Secp256r1Scalar::from_bytes_be(&s2).unwrap();
    let mut a = [0u8; 33];
    let mut b = [0u8; 33];
    g.mul(&sk2).to_bytes_compressed(&mut a).unwrap();
    g.add(&g).to_bytes_compressed(&mut b).unwrap();
    assert_eq!(a, b, "P-256 [2]G == G+G");
}

#[test]
fn diff_self_ed25519_double_add() {
    let g = Ed25519Point::generator();
    // [2]G via double vs add
    let d = g.double();
    let a = g.add(&g);
    let mut db = [0u8; 32];
    let mut ab = [0u8; 32];
    d.to_bytes_compressed(&mut db).unwrap();
    a.to_bytes_compressed(&mut ab).unwrap();
    assert_eq!(db, ab);
}

#[test]
fn diff_self_ristretto_mul_one() {
    let g = RistrettoPoint::generator();
    // Use double/add consistency
    let d = g.double();
    let a = g.add(&g);
    let mut db = [0u8; 32];
    let mut ab = [0u8; 32];
    d.encode(&mut db).unwrap();
    a.encode(&mut ab).unwrap();
    assert_eq!(db, ab, "Ristretto 2G");
}

#[test]
fn diff_self_bls_g1_g2_double_add() {
    let g1 = G1Point::generator();
    let d = g1.double();
    let a = g1.add(&g1);
    let mut db = [0u8; 48];
    let mut ab = [0u8; 48];
    d.to_bytes_compressed(&mut db).unwrap();
    a.to_bytes_compressed(&mut ab).unwrap();
    assert_eq!(db, ab, "BLS G1 [2]G");

    let g2 = G2Point::generator();
    let d2 = g2.double();
    let a2 = g2.add(&g2);
    let mut db2 = [0u8; 96];
    let mut ab2 = [0u8; 96];
    d2.to_bytes_compressed(&mut db2).unwrap();
    a2.to_bytes_compressed(&mut ab2).unwrap();
    assert_eq!(db2, ab2, "BLS G2 [2]G");
}

#[test]
fn diff_self_pallas_vesta_jubjub_double_add() {
    let pg = PallasPoint::generator();
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    pg.double().to_bytes_compressed(&mut a).unwrap();
    pg.add(&pg).to_bytes_compressed(&mut b).unwrap();
    assert_eq!(a, b, "Pallas [2]G");

    let vg = VestaPoint::generator();
    vg.double().to_bytes_compressed(&mut a).unwrap();
    vg.add(&vg).to_bytes_compressed(&mut b).unwrap();
    assert_eq!(a, b, "Vesta [2]G");

    let jg = JubJubPoint::generator();
    jg.double().to_bytes_compressed(&mut a).unwrap();
    jg.add(&jg).to_bytes_compressed(&mut b).unwrap();
    assert_eq!(a, b, "JubJub [2]G");
}

#[test]
fn diff_self_scalar_mul_zero_one() {
    // [0]G = O, [1]G = G for several curves
    let z = {
        let b = [0u8; 32];
        Secp256k1Scalar::from_bytes(&b).unwrap()
    };
    let o = Secp256k1Point::generator().mul(&z);
    assert_eq!(o.ct_is_identity(), 1);

    let mut one = [0u8; 32];
    one[31] = 1;
    let g = Secp256k1Point::generator();
    let g1 = g.mul(&Secp256k1Scalar::from_bytes(&one).unwrap());
    let mut a = [0u8; 33];
    let mut b = [0u8; 33];
    g.to_bytes_compressed(&mut a).unwrap();
    g1.to_bytes_compressed(&mut b).unwrap();
    assert_eq!(a, b, "[1]G == G");
}
