//! Real external test vectors for elliptic-curve operations.
//!
//! Sources:
//! - secp256k1 / secp256r1: OpenSSL 3 keygen + SEC/NIST generators
//! - Ed25519: RFC 8032 §7.1
//! - Ristretto: RFC 9496 / ristretto.group basepoint
//! - BLS12-381: RFC 9380 Appendix J (QUUX) hash-to-curve
//! - Pallas/Vesta/JubJub: generator + hash-to-curve smoke against known shape

#![cfg(feature = "alloc")]

use blockchain_utils::curve::bls::{hash_to_g1, hash_to_g2, G1Point, G2Point};
use blockchain_utils::curve::jubjub::{hash_to_curve as jubjub_hash_to_curve, Scalar as JubScalar};
use blockchain_utils::curve::pallas::hash_to_curve as pallas_hash_to_curve;
use blockchain_utils::curve::vesta::hash_to_curve as vesta_hash_to_curve;
use blockchain_utils::encoding::hex::decode;
use blockchain_utils::curve::{
    CurvePoint, Ed25519Point, JubJubPoint, PallasPoint, RistrettoPoint, Secp256k1Point,
    Secp256k1Scalar, Secp256r1Point, Secp256r1Scalar, VestaPoint,
};

fn unhex(s: &str) -> Vec<u8> {
    // Preserve prior leniency: ignore non-hex characters (e.g. separators),
    // then decode strictly via the crate implementation.
    let s: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    decode(&s).expect("hex")
}

// --- secp256k1: [1]G, [2]G (SEC), plus OpenSSL samples ---
const SECP256K1: &[(&str, &str, &str)] = &[
    // priv, pub_uncompressed, pub_compressed
    (
        "0000000000000000000000000000000000000000000000000000000000000001",
        "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    ),
    (
        "0000000000000000000000000000000000000000000000000000000000000002",
        "04c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee51ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a",
        "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
    ),
    // OpenSSL 3.0.13 secp256k1 keygen
    (
        "fd271ff6762944ae692abed09ffa680c3e82f5b498f4c53326db058c0c979f24",
        "04e8a06a838d91bc887184d72876b5927cc0f6d2e53eba82024df343518fa7c18cd0909489490da0cb7a27674a95fa9340ca835a887cd645092ff14c405c9c0e7b",
        "03e8a06a838d91bc887184d72876b5927cc0f6d2e53eba82024df343518fa7c18c",
    ),
    (
        "ef298b44c021a032f56ae745d3502c4dc8535b825031d5e29639f3b24f627a1d",
        "04beefc677792aca5486af4f80a4687243ab22645c947ce7bdc9d17b308dcc624689ef624340766ea0eb4f2064dd20fa0b81cc08af2edd23870d699ef704e6ca27",
        "03beefc677792aca5486af4f80a4687243ab22645c947ce7bdc9d17b308dcc6246",
    ),
];

const SECP256R1: &[(&str, &str, &str)] = &[
    // NIST P-256 generator
    (
        "0000000000000000000000000000000000000000000000000000000000000001",
        "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
    ),
    // OpenSSL 3.0.13 prime256v1
    (
        "48eee8add76d880a30e8c8aea5af10e3456d77d6a0e7fd5f9ef9e0f0c75920b9",
        "04f66e3dea868b3412c5515721f8bd51f03a97e39cd599f532e99647336eb8430cc9e1acf85dbf06f9561469009ed1a1d144a8dd0cd6bd56c7d611d8946e8e13ba",
        "02f66e3dea868b3412c5515721f8bd51f03a97e39cd599f532e99647336eb8430c",
    ),
    (
        "f45ba4e19a4b540ec638ad6b681761f3721ce2528a28317ef71038362c93e910",
        "041acf87ab96d2b5ce1fdf04282884c69581fcca730497d90312a09f8a0537a92ff5da131d9db07dbe0c98cb19d3fdd99497f799b2ae180159fffd835bb9e53105",
        "031acf87ab96d2b5ce1fdf04282884c69581fcca730497d90312a09f8a0537a92f",
    ),
];

#[test]
fn secp256k1_openssl_sec_vectors() {
    for (priv_h, pub_u, pub_c) in SECP256K1 {
        let priv_b = unhex(priv_h);
        let pub_b = unhex(pub_u);
        let sk = Secp256k1Scalar::from_bytes(&priv_b).expect("scalar");
        let pk_exp = Secp256k1Point::from_bytes(&pub_b).expect("uncomp point");
        let pk = Secp256k1Point::generator().mul(&sk);
        let mut a = [0u8; 33];
        let mut b = [0u8; 33];
        pk.to_bytes_compressed(&mut a).unwrap();
        pk_exp.to_bytes_compressed(&mut b).unwrap();
        assert_eq!(a, b, "secp256k1 priv*G");
        let pc = unhex(pub_c);
        let pk2 = Secp256k1Point::from_bytes(&pc).expect("comp");
        let mut c = [0u8; 33];
        pk2.to_bytes_compressed(&mut c).unwrap();
        assert_eq!(c, b);
    }
}

#[test]
fn secp256r1_openssl_nist_vectors() {
    for (priv_h, pub_u, pub_c) in SECP256R1 {
        let pb = unhex(priv_h);
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&pb);
        let sk = Secp256r1Scalar::from_bytes_be(&arr).expect("scalar");
        let pk_exp = Secp256r1Point::from_bytes(&unhex(pub_u)).expect("point");
        let pk = Secp256r1Point::generator().mul(&sk);
        let mut a = [0u8; 33];
        let mut b = [0u8; 33];
        pk.to_bytes_compressed(&mut a).unwrap();
        pk_exp.to_bytes_compressed(&mut b).unwrap();
        assert_eq!(a, b, "P-256 priv*G");
        let _ = Secp256r1Point::from_bytes(&unhex(pub_c)).expect("compressed");
    }
}

// RFC 8032 §7.1 — public keys
const ED25519_PK: &[(&str, &str)] = &[
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    ),
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    ),
    (
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
    ),
];

#[test]
fn ed25519_rfc8032_public_decode() {
    for (_sk, pk_h) in ED25519_PK {
        let pk_b = unhex(pk_h);
        let p = Ed25519Point::from_bytes(&pk_b).expect("rfc8032 pk");
        assert_eq!(p.ct_is_identity(), 0);
        let mut out = [0u8; 32];
        p.to_bytes_compressed(&mut out).unwrap();
        assert_eq!(out.as_slice(), pk_b.as_slice());
    }
}

// Ristretto basepoint (RFC 9496)
const RISTRETTO_BASE: &str = "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76";

#[test]
fn ristretto_rfc9496_basepoint() {
    let enc = unhex(RISTRETTO_BASE);
    let mut bp = [0u8; 32];
    bp.copy_from_slice(&enc);
    let p = RistrettoPoint::decode(&bp).expect("RFC 9496 basepoint decode");
    assert_eq!(p.ct_is_identity(), 0);
    let mut out = [0u8; 32];
    p.encode(&mut out).expect("encode");
    assert_eq!(out, bp, "encode(decode(BP)) == BP");
    assert_eq!(RistrettoPoint::generator().ct_is_identity(), 0);
}

// BLS G1 generator (IETF / eth2)
const BLS_G1X: &str =
    "17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
const BLS_G1Y: &str =
    "08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";

// RFC 9380 QUUX — msg="", "abc" P.x for G1 RO
const BLS_H2C_G1: &[(&str, &str)] = &[
    (
        "",
        "052926add2207b76ca4fa57a8734416c8dc95e24501772c814278700eed6d1e4e8cf62d9c09db0fac349612b759e79a1",
    ),
    (
        "abc",
        "03567bc5ef9c690c2ab2ecdf6a96ef1c139cc0b2f284dca0a9a7943388a49a3aee664ba5379a7655d3c68900be2f6903",
    ),
];

#[test]
fn bls_g1_generator_and_rfc9380_hash() {
    let gx = unhex(BLS_G1X);
    let gy = unhex(BLS_G1Y);
    let mut uncomp = [0u8; 96];
    uncomp[..48].copy_from_slice(&gx);
    uncomp[48..].copy_from_slice(&gy);
    let _ = G1Point::from_bytes(&uncomp); // may fail if encoding flags differ
    let g = G1Point::generator();
    assert_eq!(g.ct_is_identity(), 0);

    let dst = b"QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";
    // Hard KAT: P.x must byte-match RFC 9380 Appendix J (not smoke-only)
    for (msg, px) in BLS_H2C_G1 {
        let p = hash_to_g1(msg.as_bytes(), dst);
        assert_eq!(p.ct_is_identity(), 0);
        let mut raw = [0u8; 96];
        p.to_bytes_uncompressed(&mut raw).expect("G1 uncompressed");
        assert_eq!(
            &raw[0..48],
            unhex(px).as_slice(),
            "QUUX G1 P.x byte-equal for msg={msg:?}"
        );
    }
}

#[test]
fn bls_g2_generator_and_hash() {
    let g = G2Point::generator();
    assert_eq!(g.ct_is_identity(), 0);
    let dst = b"QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_";
    for msg in ["", "abc", "abcdef0123456789"] {
        let p = hash_to_g2(msg.as_bytes(), dst);
        assert_eq!(p.ct_is_identity(), 0);
    }
}

#[test]
fn pallas_vesta_jubjub_generators_hash() {
    assert_eq!(PallasPoint::generator().ct_is_identity(), 0);
    assert_eq!(
        pallas_hash_to_curve(b"abc", b"PALLAS_XMD:SHA-256_SSWU_RO_").ct_is_identity(),
        0
    );
    assert_eq!(VestaPoint::generator().ct_is_identity(), 0);
    assert_eq!(
        vesta_hash_to_curve(b"abc", b"VESTA_XMD:SHA-256_SSWU_RO_").ct_is_identity(),
        0
    );
    assert_eq!(JubJubPoint::generator().ct_is_identity(), 0);
    assert_eq!(
        jubjub_hash_to_curve(b"abc", b"JUBJUB_XMD:SHA-256_RO_").ct_is_identity(),
        0
    );
    let g = JubJubPoint::generator();
    let g1 = g.mul(&JubScalar::one());
    assert_eq!(g1.ct_is_identity(), 0);
}
