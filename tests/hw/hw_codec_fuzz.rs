//! Deterministic codec roundtrip fuzz: a fixed-seed LCG drives
//! encode→decode across every `hw` codec (1000 cases each). No device, no
//! randomness source, no new crates — reproducible by construction.
//!
//! This complements `hw_robust.rs` (garbage-in) with shape-in: random
//! VALID inputs must survive a full round trip byte-identical. For
//! coverage-guided fuzzing of attacker bytes, wire these same entry
//! points to `cargo-fuzz` in CI — the property tested
//! here is the oracle those targets reuse.
//!
//! Run: `cargo test --features hw --test hw_codec_fuzz`

#![cfg(feature = "hw")]

use blockchain_utils::hw::{
    apdu::Apdu,
    hid::{hid_frame, hid_unframe},
    trezor::{proto_decode, proto_encode, trezor_frame, trezor_unframe, ProtoField},
    ur::{ur_decode_single, ur_encode_single},
};

/// SplitMix-style LCG (fixed seed → deterministic stream).
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        // xor-shift mix for better low bits (lengths use `%`).
        let mut z = self.0.wrapping_add(0x9E3779B97F4A7C15);
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % (n as u64).max(1)) as usize
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

const ITERS: usize = 1000;

#[test]
fn hid_frame_roundtrip() {
    let mut rng = Lcg(0x1234_5678);
    for _ in 0..ITERS {
        let len = rng.below(300);
        let payload = rng.bytes(len);
        let channel = rng.next() as u16;
        let tag = rng.next() as u8;
        let reports = hid_frame(&payload, channel, tag);
        assert_eq!(hid_unframe(&reports, channel, tag).unwrap(), payload);
        // Wrong channel/tag must fail, never mis-parse.
        assert!(hid_unframe(&reports, channel.wrapping_add(1), tag).is_err());
    }
}

#[test]
fn trezor_frame_roundtrip() {
    let mut rng = Lcg(0xABCD_EF01);
    for _ in 0..ITERS {
        let msg_type = rng.next() as u16;
        let body_len = rng.below(200);
        let body = rng.bytes(body_len);
        let chunks = trezor_frame(msg_type, &body);
        let (t, b) = trezor_unframe(&chunks).unwrap();
        assert_eq!((t, b), (msg_type, body));
    }
}

#[test]
fn apdu_roundtrip() {
    let mut rng = Lcg(0x0BAD_F00D);
    for _ in 0..ITERS {
        let data_len = rng.below(200); // ≤255 keeps short-Lc form
        let data = rng.bytes(data_len);
        let mut a = Apdu::new(
            rng.next() as u8,
            rng.next() as u8,
            rng.next() as u8,
            rng.next() as u8,
            data,
        );
        if rng.below(2) == 0 {
            a.le = Some(rng.next() as u8);
        }
        let wire = a.to_bytes();
        assert_eq!(Apdu::parse(&wire).unwrap(), a);
    }
}

#[test]
fn proto_roundtrip() {
    let mut rng = Lcg(0xFEED_FACE);
    for _ in 0..ITERS {
        let nfields = rng.below(5);
        let mut nums = Vec::new();
        let mut fields = Vec::new();
        for _ in 0..nfields {
            let num = 1 + rng.below(20) as u32;
            nums.push(num);
            if rng.below(2) == 0 {
                let len = rng.below(40);
                fields.push(ProtoField::Bytes(rng.bytes(len)));
            } else {
                fields.push(ProtoField::Varint(rng.next()));
            }
        }
        let body = proto_encode(&nums, &fields).unwrap();
        let back = proto_decode(&body).unwrap();
        assert_eq!(back.len(), nfields);
        for (i, (num, wt, val)) in back.iter().enumerate() {
            assert_eq!(*num, nums[i]);
            match &fields[i] {
                ProtoField::Bytes(b) => {
                    assert_eq!(*wt, 2);
                    assert_eq!(val, b);
                }
                ProtoField::Varint(v) => {
                    assert_eq!(*wt, 0);
                    let mut enc = Vec::new();
                    blockchain_utils::hw::trezor::varint_encode(*v, &mut enc);
                    assert_eq!(val, &enc);
                }
            }
        }
    }
}

#[test]
fn ur_single_roundtrip() {
    let mut rng = Lcg(0xC0FF_EE00);
    for _ in 0..ITERS {
        let payload_len = rng.below(200);
        let payload = rng.bytes(payload_len);
        let s = ur_encode_single("bytes", &payload);
        assert_eq!(ur_decode_single(&s).unwrap().payload, payload);
    }
}
