//! Noise_XX tests: two-party handshake, tamper rejection, transport pair.
//! No device — both roles run in-process with fixed keys (deterministic).
//! Run: `cargo test --features hw --test hw_noise`
//! (`--no-default-features --features hw` also runs: pure `no_std` code.)

#![cfg(feature = "hw")]

use blockchain_utils::curve::x25519::public_key;
use blockchain_utils::error::Error;
use blockchain_utils::hw::{
    mock::MockTransport,
    noise::{NoiseTransportAdapter, NoiseXX, MSG1_LEN, MSG2_LEN, MSG3_LEN},
    transport::Transport,
};

// Fixed roles: initiator (host) + responder (device stand-in).
const S_INIT: [u8; 32] = [0x11; 32];
const E_INIT: [u8; 32] = [0x12; 32];
const S_RESP: [u8; 32] = [0x21; 32];
const E_RESP: [u8; 32] = [0x22; 32];

fn handshake() -> (
    blockchain_utils::hw::NoiseTransport,
    blockchain_utils::hw::NoiseTransport,
) {
    let mut init = NoiseXX::new_initiator(S_INIT, E_INIT);
    let mut resp = NoiseXX::new_responder(S_RESP, E_RESP);
    let m1 = init.write_message_1(b"").unwrap();
    assert_eq!(m1.len(), MSG1_LEN); // e + empty cleartext payload
    assert!(resp.read_message_1(&m1).unwrap().is_empty());
    let m2 = resp.write_message_2(b"").unwrap();
    assert_eq!(m2.len(), MSG2_LEN + 16); // e + enc_s + empty-payload tag
    assert!(init.read_message_2(&m2).unwrap().is_empty());
    assert_eq!(init.peer_static().unwrap(), public_key(&S_RESP));
    let m3 = init.write_message_3(b"").unwrap();
    assert_eq!(m3.len(), MSG3_LEN + 16); // enc_s + empty-payload tag
    assert!(resp.read_message_3(&m3).unwrap().is_empty());
    assert_eq!(resp.peer_static().unwrap(), public_key(&S_INIT));
    let ta = init.split().unwrap();
    let tb = resp.split().unwrap();
    assert_eq!(ta.handshake_hash(), tb.handshake_hash());
    assert_ne!(ta.handshake_hash(), [0u8; 32]);
    (ta, tb)
}

#[test]
fn handshake_agrees_and_binds_statics() {
    let _ = handshake(); // all assertions inside
}

#[test]
fn transport_talks_both_ways() {
    let (mut a, mut b) = handshake();
    let c1 = a.encrypt(b"host->device").unwrap();
    assert_eq!(b.decrypt(&c1).unwrap(), b"host->device");
    let c2 = b.encrypt(b"device->host").unwrap();
    assert_eq!(a.decrypt(&c2).unwrap(), b"device->host");
    // Ciphertexts are randomized-adjacent: same plaintext, advancing nonce.
    let c3 = a.encrypt(b"host->device").unwrap();
    assert_ne!(c1, c3);
    assert_eq!(b.decrypt(&c3).unwrap(), b"host->device");
}

#[test]
fn tampered_handshake_fails() {
    let mut init = NoiseXX::new_initiator(S_INIT, E_INIT);
    let mut resp = NoiseXX::new_responder(S_RESP, E_RESP);
    let m1 = init.write_message_1(b"").unwrap();
    assert!(resp.read_message_1(&m1).unwrap().is_empty());
    let mut m2 = resp.write_message_2(b"").unwrap();
    // Flip a byte inside the encrypted static (not the ephemeral half).
    m2[40] ^= 0x01;
    assert!(init.read_message_2(&m2).is_err());

    // Truncated messages are length errors, not panics.
    let mut resp2 = NoiseXX::new_responder(S_RESP, E_RESP);
    assert_eq!(resp2.read_message_1(&m1[..16]), Err(Error::InvalidLength));
}

#[test]
fn out_of_order_calls_fail() {
    let mut init = NoiseXX::new_initiator(S_INIT, E_INIT);
    assert!(init.write_message_2(b"").is_err());
    assert!(init.write_message_3(b"").is_err());
    assert_eq!(init.peer_static(), None);
    // Split before step 3 fails (checked on a sacrificial instance —
    // `split` consumes).
    assert!(NoiseXX::new_initiator(S_INIT, E_INIT).split().is_err());
    let m1 = init.write_message_1(b"").unwrap();
    assert!(init.write_message_1(b"").is_err()); // replay
    let mut resp = NoiseXX::new_responder(S_RESP, E_RESP);
    assert!(resp.write_message_2(b"").is_err()); // no m1 yet
    assert!(resp.read_message_1(&m1).unwrap().is_empty());
    let m2 = resp.write_message_2(b"").unwrap();
    // Device stand-in answering message 3 with a truncated message 2: rejected.
    assert!(resp.read_message_3(&m2[..MSG3_LEN]).is_err());
}

#[test]
fn transport_rejects_replay_and_reorder() {
    let (mut a, mut b) = handshake();
    let c1 = a.encrypt(b"one").unwrap();
    let c2 = a.encrypt(b"two").unwrap();
    // Out-of-order decrypt: nonce mismatch.
    assert!(b.decrypt(&c2).is_err() || b.decrypt(&c1).is_err());
    // Fresh pair: replay the first ciphertext twice.
    let (mut a2, mut b2) = handshake();
    let c = a2.encrypt(b"ping").unwrap();
    assert_eq!(b2.decrypt(&c).unwrap(), b"ping");
    assert!(b2.decrypt(&c).is_err()); // same nonce twice
    assert_eq!(a2.encrypt(b"").unwrap().len(), 16); // empty ok, tag only
}

#[test]
fn adapter_carries_encrypted_exchange_over_mock() {
    // The mock stands in for the USB wire: it sees ONLY ciphertext, and the
    // canned reply must be a valid peer encryption or decrypt fails.
    let (ta, mut tb) = handshake();
    let want_reply = tb.encrypt(b"paired-ok").unwrap();
    let mut wire = MockTransport::fixed(want_reply);
    let mut app = NoiseTransportAdapter::new(&mut wire, ta);
    let out = app.exchange(b"pair-hello").unwrap();
    assert_eq!(out, b"paired-ok");
    // What crossed the "wire" decrypts under the peer transport...
    let seen = wire.seen()[0].clone();
    assert_eq!(tb.decrypt(&seen).unwrap(), b"pair-hello");
    // ...and is not plaintext on the wire.
    assert!(!seen.windows(10).any(|w| w == b"pair-hello"));

    // A garbage reply from the wire is a transport-level decrypt error.
    // (Fresh handshake: `ta` moved into `app` above.)
    let (ta2, _tb2) = handshake();
    let mut bad_wire = MockTransport::fixed(vec![0xAA; 40]);
    let mut bad_app = NoiseTransportAdapter::new(&mut bad_wire, ta2);
    assert!(bad_app.exchange(b"pair-hello").is_err());
}
