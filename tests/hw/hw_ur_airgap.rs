//! Airgap tests: multipart animated-QR sharding round-trips.
//! No camera, no display — pure codec: `ur_encode_part` shards go in,
//! `UrAssembler` reassembles. Camera/QR rendering stays app-side;
//! shard encode + reassembly is proven here, including adversarial feeds.
//!
//! NOTE: sharding is uniform indexed (`seq-of-total`), NOT fountain-coded
//! BC-UR: the scanner must collect all N distinct shards (duplicates and
//! any order tolerated, but no redundancy). Large PSBTs simply become
//! more frames — the app cycles them as animated QR.
//!
//! Run: `cargo test --features hw --test hw_ur_airgap`

#![cfg(feature = "hw")]

use blockchain_utils::error::Error;
use blockchain_utils::hw::ur::{ur_decode_single, ur_encode_part, ur_encode_single, UrAssembler};

/// Split `payload` into `n`-byte shards (last may be short).
fn shard(ur_type: &str, payload: &[u8], n: usize) -> Vec<String> {
    let total = payload.len().div_ceil(n) as u32;
    payload
        .chunks(n)
        .enumerate()
        .map(|(i, c)| ur_encode_part(ur_type, i as u32 + 1, total, c).unwrap())
        .collect()
}

#[test]
fn multipart_round_trip_shuffled_with_duplicates() {
    // PSBT-sized payload through 64-byte shards, fed reversed + duplicated.
    let payload: Vec<u8> = (0..2048u32)
        .map(|i| (i.wrapping_mul(2654435761) % 251) as u8)
        .collect();
    let shards = shard("crypto-psbt", &payload, 64);
    assert!(shards.len() > 20);
    let mut asm = UrAssembler::new();
    let rev: Vec<&String> = shards.iter().rev().collect();
    // Interleave duplicates of already-seen shards (must be ignored).
    let mut done = None;
    for (k, s) in rev.iter().enumerate() {
        if k % 5 == 4 {
            assert!(asm.feed(rev[k - 1]).unwrap().is_none()); // duplicate
        }
        if let Some(out) = asm.feed(s).unwrap() {
            done = Some(out);
        }
    }
    assert_eq!(done.unwrap(), payload);
}

#[test]
fn single_part_and_type_checks() {
    let s = ur_encode_single("bytes", b"hello");
    let msg = ur_decode_single(&s).unwrap();
    assert_eq!(msg.payload, b"hello");
    assert!(msg.part.is_none());
    // A single-part QR fed to the assembler is a usage error, not a crash.
    let mut asm = UrAssembler::new();
    assert_eq!(asm.feed(&s).unwrap_err(), Error::InvalidEncoding);
    assert!(asm.is_empty());
}

#[test]
fn mixed_stream_rejected() {
    let a = shard("crypto-psbt", &[1u8; 100], 64);
    let b = shard("crypto-psbt", &[2u8; 100], 40); // different total
    let c = shard("bytes", &[1u8; 100], 64); // different type
    let mut asm = UrAssembler::new();
    assert!(asm.feed(&a[0]).unwrap().is_none());
    assert_eq!(asm.feed(&b[0]).unwrap_err(), Error::InvalidEncoding);
    assert_eq!(asm.feed(&c[0]).unwrap_err(), Error::InvalidEncoding);
    // Original stream still completes after the rejected intruders.
    let mut done = None;
    for s in &a[1..] {
        if let Some(out) = asm.feed(s).unwrap() {
            done = Some(out);
        }
    }
    assert_eq!(done.unwrap(), vec![1u8; 100]);
}

#[test]
fn part_bounds_rejected() {
    assert_eq!(
        ur_encode_part("bytes", 0, 2, b"x").unwrap_err(),
        Error::InvalidLength
    );
    assert_eq!(
        ur_encode_part("bytes", 3, 2, b"x").unwrap_err(),
        Error::InvalidLength
    );
    assert_eq!(
        ur_encode_part("bytes", 1, 0, b"x").unwrap_err(),
        Error::InvalidLength
    );
    assert_eq!(
        ur_encode_part("bytes", 1, 10_001, b"x").unwrap_err(),
        Error::InvalidLength
    );
    // Malformed seq headers decode-side.
    for bad in [
        "ur:bytes/0-of-2/AA",
        "ur:bytes/3-of-2/AA",
        "ur:bytes/1-of-2",
        "ur:bytes/1-of-2/AA/extra",
        "ur:bytes/x-of-2/AA",
        "not-a-ur",
        "",
    ] {
        assert!(ur_decode_single(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn out_of_order_single_shard_completes() {
    // Degenerate 1-of-1 multipart completes immediately.
    let mut asm = UrAssembler::new();
    let s = ur_encode_part("bytes", 1, 1, b"sole").unwrap();
    assert_eq!(asm.feed(&s).unwrap(), Some(b"sole".to_vec()));
}
