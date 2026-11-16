//! Noise_XX INTEROP: our handshake against `snow` (independent implementation).
//! Non-empty handshake payloads on both sides (deterministic): if our XX
//! deviated from the spec anywhere — token order, HKDF layout, nonce
//! encoding, AAD — the two sides would derive different keys and transport
//! would fail. (Empty-payload spec-form is deliberately unsupported: our
//! BitBox-compatible framing elides zero-length payloads instead of
//! mixing them — see `hw::noise` docs. The official vectors in
//! `hw_noise_vector.rs` cover the payload path byte-for-byte.)
//!
//! `snow` is dev-only: it never links into the zero-dep library.
//! Run: `cargo test --features hw --test hw_noise_snow` (needs `std`).

#![cfg(all(feature = "hw", feature = "std"))]

use blockchain_utils::hw::noise::NoiseXX;

const S_US: [u8; 32] = [0x11; 32];
const E_US: [u8; 32] = [0x12; 32];
const S_SNOW: [u8; 32] = [0x21; 32];
const E_SNOW: [u8; 32] = [0x22; 32];

const PARAMS: &str = "Noise_XX_25519_ChaChaPoly_SHA256";

const P1: &[u8] = b"snow-test-payload-1";
const P2: &[u8] = b"snow-test-payload-2";
const P3: &[u8] = b"snow-test-payload-3";

fn snow_responder() -> snow::HandshakeState {
    snow::Builder::new(PARAMS.parse().unwrap())
        .local_private_key(&S_SNOW)
        .unwrap()
        .fixed_ephemeral_key_for_testing_only(&E_SNOW)
        .build_responder()
        .unwrap()
}

fn snow_initiator() -> snow::HandshakeState {
    snow::Builder::new(PARAMS.parse().unwrap())
        .local_private_key(&S_SNOW)
        .unwrap()
        .fixed_ephemeral_key_for_testing_only(&E_SNOW)
        .build_initiator()
        .unwrap()
}

fn finish_transport(us: blockchain_utils::hw::NoiseTransport, snow: snow::HandshakeState) {
    let snow_hash = {
        let mut h = [0u8; 32];
        h.copy_from_slice(snow.get_handshake_hash());
        h
    };
    let mut snow_t = snow.into_transport_mode().unwrap();
    let mut us_t = us;
    assert_eq!(us_t.handshake_hash(), snow_hash);
    // Cross-talk both directions.
    let mut c = [0u8; 1024];
    let cn = snow_t.write_message(b"from-snow", &mut c).unwrap();
    assert_eq!(us_t.decrypt(&c[..cn]).unwrap(), b"from-snow");
    let ours = us_t.encrypt(b"from-us").unwrap();
    let mut p = [0u8; 1024];
    let pn = snow_t.read_message(&ours, &mut p).unwrap();
    assert_eq!(&p[..pn], b"from-us");
}

#[test]
fn our_initiator_vs_snow_responder() {
    let mut us = NoiseXX::new_initiator(S_US, E_US);
    let mut snow = snow_responder();

    // -> e + payload (cleartext).
    let m1 = us.write_message_1(P1).unwrap();
    let mut tmp = [0u8; 1024];
    let n = snow.read_message(&m1, &mut tmp).unwrap();
    assert_eq!(&tmp[..n], P1);
    // <- e, ee, s, es + payload.
    let mut m2 = [0u8; 1024];
    let m2n = snow.write_message(P2, &mut m2).unwrap();
    let payload = us.read_message_2(&m2[..m2n]).unwrap();
    assert_eq!(payload, P2);
    // -> s, se + payload.
    let m3 = us.write_message_3(P3).unwrap();
    let mut out = [0u8; 1024];
    let on = snow.read_message(&m3, &mut out).unwrap();
    assert_eq!(&out[..on], P3);

    finish_transport(us.split().unwrap(), snow);
}

#[test]
fn snow_initiator_vs_our_responder() {
    let mut snow = snow_initiator();
    let mut us = NoiseXX::new_responder(S_US, E_US);

    let mut m1 = [0u8; 1024];
    let m1n = snow.write_message(P1, &mut m1).unwrap();
    assert_eq!(us.read_message_1(&m1[..m1n]).unwrap(), P1);

    let m2 = us.write_message_2(P2).unwrap();
    let mut out = [0u8; 1024];
    let on = snow.read_message(&m2, &mut out).unwrap();
    assert_eq!(&out[..on], P2);

    let mut m3 = [0u8; 1024];
    let m3n = snow.write_message(P3, &mut m3).unwrap();
    assert_eq!(us.read_message_3(&m3[..m3n]).unwrap(), P3);

    // snow checks the peer static it recovered: must be our S_US *public* key.
    assert_eq!(
        snow.get_remote_static().unwrap(),
        &blockchain_utils::curve::x25519::public_key(&S_US)[..]
    );

    finish_transport(us.split().unwrap(), snow);
}
