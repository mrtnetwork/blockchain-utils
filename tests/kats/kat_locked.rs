//! P0 #5 — Locked known-answer tests (KATs).
//!
//! These tests **hard-fail** on byte mismatch against published vectors.
//! Soft checks (non-identity only) are not enough for the production gate.
//!
//! Sources:
//! - secp256k1 / secp256r1: SEC / NIST generators + OpenSSL 3.0.13 samples
//! - Ed25519: RFC 8032 §7.1 public keys (round-trip)
//! - Ristretto: RFC 9496 basepoint `encode(decode(BP)) == BP`
//! - BLS12-381 G1: RFC 9380 Appendix J.9.1 QUUX RO P.x / P.y
//! - BLS pairing: bilinearity e([2]P,Q) = e(P,[2]Q) = e(P,Q)²
//!
//! Run: `cargo test --test kats kat_locked`
//! Or:  `bash scripts/ci_kats.sh`

#![cfg(feature = "alloc")]

use blockchain_utils::curve::bls::{hash_to_g1, pairing, Fp12, G1Point, G2Point};
use blockchain_utils::curve::ristretto::RistrettoPoint;
use blockchain_utils::curve::{
    CurvePoint, Ed25519Point, Secp256k1Point, Secp256k1Scalar, Secp256r1Point, Secp256r1Scalar,
};
use blockchain_utils::encoding::hex::{decode, encode};

fn unhex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    decode(&s).expect("hex")
}

fn assert_hex_eq(got: &[u8], expect_hex: &str, label: &str) {
    let exp = unhex(expect_hex);
    assert_eq!(
        got,
        exp.as_slice(),
        "{label}: got {} expect {}",
        encode(got),
        expect_hex
    );
}

// ---------------------------------------------------------------------------
// secp256k1 — SEC + OpenSSL (compressed pub must match)
// ---------------------------------------------------------------------------

const SECP256K1_KATS: &[(&str, &str)] = &[
    // priv → compressed pub
    (
        "0000000000000000000000000000000000000000000000000000000000000001",
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    ),
    (
        "0000000000000000000000000000000000000000000000000000000000000002",
        "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
    ),
    (
        "fd271ff6762944ae692abed09ffa680c3e82f5b498f4c53326db058c0c979f24",
        "03e8a06a838d91bc887184d72876b5927cc0f6d2e53eba82024df343518fa7c18c",
    ),
    (
        "ef298b44c021a032f56ae745d3502c4dc8535b825031d5e29639f3b24f627a1d",
        "03beefc677792aca5486af4f80a4687243ab22645c947ce7bdc9d17b308dcc6246",
    ),
];

#[test]
fn kat_secp256k1_priv_times_g_compressed() {
    for (priv_h, pub_c) in SECP256K1_KATS {
        let sk = Secp256k1Scalar::from_bytes(&unhex(priv_h)).expect("scalar");
        let pk = Secp256k1Point::generator().mul(&sk);
        let mut out = [0u8; 33];
        pk.to_bytes_compressed(&mut out).expect("encode");
        assert_hex_eq(&out, pub_c, "secp256k1 [priv]G compressed");
        // Round-trip compressed
        let pk2 = Secp256k1Point::from_bytes(&unhex(pub_c)).expect("decode compressed");
        let mut out2 = [0u8; 33];
        pk2.to_bytes_compressed(&mut out2).unwrap();
        assert_eq!(out, out2);
    }
}

// ---------------------------------------------------------------------------
// secp256r1 (P-256) — NIST + OpenSSL
// ---------------------------------------------------------------------------

const SECP256R1_KATS: &[(&str, &str)] = &[
    (
        "0000000000000000000000000000000000000000000000000000000000000001",
        "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
    ),
    (
        "48eee8add76d880a30e8c8aea5af10e3456d77d6a0e7fd5f9ef9e0f0c75920b9",
        "02f66e3dea868b3412c5515721f8bd51f03a97e39cd599f532e99647336eb8430c",
    ),
    (
        "f45ba4e19a4b540ec638ad6b681761f3721ce2528a28317ef71038362c93e910",
        "031acf87ab96d2b5ce1fdf04282884c69581fcca730497d90312a09f8a0537a92f",
    ),
];

#[test]
fn kat_secp256r1_priv_times_g_compressed() {
    for (priv_h, pub_c) in SECP256R1_KATS {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&unhex(priv_h));
        let sk = Secp256r1Scalar::from_bytes_be(&arr).expect("scalar");
        let pk = Secp256r1Point::generator().mul(&sk);
        let mut out = [0u8; 33];
        pk.to_bytes_compressed(&mut out).expect("encode");
        assert_hex_eq(&out, pub_c, "P-256 [priv]G compressed");
    }
}

// ---------------------------------------------------------------------------
// Ed25519 — RFC 8032 §7.1 public key decode + re-encode
// ---------------------------------------------------------------------------

const ED25519_PK: &[&str] = &[
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
];

#[test]
fn kat_ed25519_rfc8032_public_roundtrip() {
    for pk_h in ED25519_PK {
        let pk_b = unhex(pk_h);
        let p = Ed25519Point::from_bytes(&pk_b).expect("RFC 8032 public decode");
        assert_eq!(p.ct_is_identity(), 0);
        let mut out = [0u8; 32];
        p.to_bytes_compressed(&mut out).unwrap();
        assert_eq!(
            out.as_slice(),
            pk_b.as_slice(),
            "Ed25519 encode(decode(pk))"
        );
    }
}

// ---------------------------------------------------------------------------
// Ristretto — RFC 9496 basepoint hard round-trip
// ---------------------------------------------------------------------------

const RISTRETTO_BP: &str = "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76";

#[test]
fn kat_ristretto_rfc9496_encode_decode_basepoint() {
    let mut bp = [0u8; 32];
    bp.copy_from_slice(&unhex(RISTRETTO_BP));
    let p = RistrettoPoint::decode(&bp).expect("RFC 9496 basepoint decode");
    assert_eq!(p.ct_is_identity(), 0);
    let mut out = [0u8; 32];
    p.encode(&mut out).expect("encode");
    assert_eq!(out, bp, "encode(decode(BP)) == BP (RFC 9496)");
    // Generator must be the same point
    let mut genc = [0u8; 32];
    RistrettoPoint::generator()
        .encode(&mut genc)
        .expect("generator encode");
    assert_eq!(genc, bp, "generator encodes to RFC 9496 basepoint");
}

// ---------------------------------------------------------------------------
// BLS12-381 G1 — RFC 9380 QUUX RO msg="" and msg="abc" P.x / P.y
// ---------------------------------------------------------------------------

const QUUX_DST_G1: &[u8] = b"QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";

/// (msg, P_x hex, P_y hex) — RFC 9380 Appendix J.9.1
const QUUX_G1_RO: &[(&str, &str, &str)] = &[
    (
        "",
        "052926add2207b76ca4fa57a8734416c8dc95e24501772c814278700eed6d1e4e8cf62d9c09db0fac349612b759e79a1",
        "08ba738453bfed09cb546dbb0783dbb3a5f1f566ed67bb6be0e8c67e2e81a4cc68ee29813bb7994998f3eae0c9c6a265",
    ),
    (
        "abc",
        "03567bc5ef9c690c2ab2ecdf6a96ef1c139cc0b2f284dca0a9a7943388a49a3aee664ba5379a7655d3c68900be2f6903",
        "0b9c15f3fe6e5cf4211f346271d7b01c8f3b28be689c8429c85b67af215533311f0b8dfaaa154fa6b88176c229f2885d",
    ),
    (
        "abcdef0123456789",
        "11e0b079dea29a68f0383ee94fed1b940995272407e3bb916bbf268c263ddd57a6a27200a784cbc248e84f357ce82d98",
        "03a87ae2caf14e8ee52e51fa2ed8eefe80f02457004ba4d486d6aa1f517c0889501dc7413753f9599b099ebcbbd2d709",
    ),
];

#[test]
fn kat_bls_g1_quux_px_py_byte_equal() {
    for (msg, px, py) in QUUX_G1_RO {
        let p = hash_to_g1(msg.as_bytes(), QUUX_DST_G1);
        assert_eq!(p.ct_is_identity(), 0, "QUUX G1 identity for msg={msg:?}");
        let mut uncomp = [0u8; 96];
        p.to_bytes_uncompressed(&mut uncomp)
            .expect("G1 uncompressed");
        // Uncompressed is x || y (48 || 48), no compression flags on finite points
        assert_hex_eq(&uncomp[0..48], px, &format!("QUUX G1 P.x msg={msg:?}"));
        assert_hex_eq(&uncomp[48..96], py, &format!("QUUX G1 P.y msg={msg:?}"));
    }
}

// ---------------------------------------------------------------------------
// BLS pairing bilinearity (hard equality, not only ≠ 1)
// ---------------------------------------------------------------------------

#[test]
fn kat_bls_pairing_bilinearity_equality() {
    let p = G1Point::generator();
    let q = G2Point::generator();
    let e = pairing(&p, &q);
    assert!(!e.is_one(), "e(G1,G2) must not be 1");

    let p2 = p.double();
    let q2 = q.add(&q);
    let e1 = pairing(&p2, &q);
    let e2 = pairing(&p, &q2);
    let e_sq = e.square();

    assert_eq!(e1.ct_eq(&e2), 1, "e([2]P,Q) == e(P,[2]Q)");
    assert_eq!(e_sq.ct_eq(&e1), 1, "e(P,Q)^2 == e([2]P,Q)");

    // e(O, Q) = 1, e(P, O) = 1
    let one = Fp12::one();
    assert_eq!(pairing(&G1Point::identity(), &q).ct_eq(&one), 1, "e(O,Q)=1");
    assert_eq!(pairing(&p, &G2Point::identity()).ct_eq(&one), 1, "e(P,O)=1");
}
