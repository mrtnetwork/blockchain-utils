//! secp256k1 / secp256r1 infinity round-trips (fixed-buffer `0x00‖zeros`).
//!
//! Internal Jacobian arithmetic always handled ∞; what was missing was the
//! encode boundary (`to_bytes_*` errored, so `bu_curve_identity` and
//! `P + (-P)` failed). Run: `cargo test --test kats secp_infinity`

use blockchain_utils::curve::CurvePoint;
use blockchain_utils::curve::{Secp256k1Point, Secp256r1Point};

fn enc<P: CurvePoint>(p: &P) -> Vec<u8> {
    let mut out = vec![0xFFu8; P::COMPRESSED_BYTES];
    p.to_bytes_compressed(&mut out).unwrap();
    out
}

fn enc_uncomp<P: CurvePoint>(p: &P) -> Vec<u8> {
    let mut out = vec![0xFFu8; P::UNCOMPRESSED_BYTES];
    p.to_bytes_uncompressed(&mut out).unwrap();
    out
}

fn case<P: CurvePoint>(gen_compressed: &[u8]) {
    let inf = P::identity();
    assert!(inf.is_identity());

    // Encodes as zero buffers (BIP327 `zeroPk` convention).
    assert_eq!(enc(&inf), vec![0u8; P::COMPRESSED_BYTES]);
    assert_eq!(enc_uncomp(&inf), vec![0u8; P::UNCOMPRESSED_BYTES]);

    // Decode: lone 0x00 + zero-padded forms.
    assert!(P::from_bytes(&[0x00]).unwrap().is_identity());
    assert!(P::from_bytes(&vec![0u8; P::COMPRESSED_BYTES])
        .unwrap()
        .is_identity());
    // 0x00 prefix with nonzero tail stays invalid.
    let mut bad = vec![0u8; P::COMPRESSED_BYTES];
    bad[P::COMPRESSED_BYTES - 1] = 1;
    assert!(P::from_bytes(&bad).is_err());

    // Group laws with infinity.
    let g = P::from_bytes(gen_compressed).unwrap();
    assert!(!g.is_identity());
    assert_eq!(enc(&inf.add(&g)), enc(&g));
    assert_eq!(enc(&g.add(&inf)), enc(&g));
    // P + (-P) = ∞
    assert!(g.add(&g.neg()).is_identity());
    assert_eq!(enc(&g.add(&g.neg())), vec![0u8; P::COMPRESSED_BYTES]);
    // 2·∞ = ∞, -∞ = ∞
    assert!(inf.double().is_identity());
    assert!(inf.neg().is_identity());
}

#[test]
fn k1_infinity() {
    case::<Secp256k1Point>(&[
        0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87,
        0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16,
        0xF8, 0x17, 0x98,
    ]);
}

#[test]
fn r1_infinity() {
    case::<Secp256r1Point>(&[
        0x03, 0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4,
        0x40, 0xF2, 0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39, 0x45, 0xD8,
        0x98, 0xC2, 0x96,
    ]);
}
