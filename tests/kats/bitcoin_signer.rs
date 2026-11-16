//! Bitcoin-oriented secp256k1 signing tests: ECDSA compact, recover, BIP-340 aux.
//! Run: `cargo test --features alloc --test kats bitcoin_signer`

#![cfg(feature = "alloc")]

use blockchain_utils::hash::sha256::{sha256, sha256d};
use blockchain_utils::signature::ecdsa::{
    recover, recover_and_verify, sign, sign_ex, verify, SecretKey,
};
use blockchain_utils::signature::schnorr::{
    sign_with_aux, tweak_secret, verify as schnorr_verify, SecretKey as SchnorrSk,
};

fn unhex32(s: &str) -> [u8; 32] {
    let s: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    let mut a = [0u8; 32];
    for i in 0..32 {
        a[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    a
}

/// Bitcoin signed-message magic hash (double SHA-256).
fn bitcoin_message_hash(message: &[u8]) -> [u8; 32] {
    // varint length for message < 253
    assert!(message.len() < 253);
    let prefix = b"\x18Bitcoin Signed Message:\n";
    let mut buf = Vec::with_capacity(prefix.len() + 1 + message.len());
    buf.extend_from_slice(prefix);
    buf.push(message.len() as u8);
    buf.extend_from_slice(message);
    sha256d(&buf).expect("sha256d")
}

#[test]
fn ecdsa_sign_verify_and_recover() {
    let d = unhex32("0000000000000000000000000000000000000000000000000000000000000001");
    let sk = SecretKey::from_bytes(&d).unwrap();
    let pk = sk.public_key().unwrap();
    let h = sha256(b"bitcoin ecdsa").unwrap();
    let sig = sign(&sk, &h).unwrap();
    verify(&pk, &h, &sig).unwrap();
    let mut a = [0u8; 33];
    pk.to_bytes_compressed(&mut a).unwrap();
    // Find recovery id that both verifies and matches the signer
    let mut found = false;
    for id in 0u8..4 {
        if let Ok(pk2) = recover(&h, &sig, id) {
            if verify(&pk2, &h, &sig).is_ok() {
                let mut b = [0u8; 33];
                pk2.to_bytes_compressed(&mut b).unwrap();
                if a == b {
                    found = true;
                    break;
                }
            }
        }
    }
    assert!(found, "no recovery id reconstructs the signing public key");
}

#[test]
fn bitcoin_message_hash_sign_recover() {
    // Use sk = 1 (same as recover roundtrip) for stable recovery id match.
    let d = unhex32("0000000000000000000000000000000000000000000000000000000000000001");
    let sk = SecretKey::from_bytes(&d).unwrap();
    let pk = sk.public_key().unwrap();
    let msg = b"hello bitcoin";
    let h = bitcoin_message_hash(msg);
    let sig = sign(&sk, &h).unwrap();
    verify(&pk, &h, &sig).unwrap();
    let (pk2, id) = recover_and_verify(&h, &sig).unwrap();
    assert!(id < 4);
    let mut a = [0u8; 33];
    let mut b = [0u8; 33];
    pk.to_bytes_compressed(&mut a).unwrap();
    pk2.to_bytes_compressed(&mut b).unwrap();
    assert_eq!(a, b, "recovered pubkey must match signer");
}

#[test]
fn bip340_aux_and_tweak_sign_verify() {
    let d = unhex32("0000000000000000000000000000000000000000000000000000000000000001");
    let sk = SchnorrSk::from_bytes(&d).unwrap();
    let pk = sk.public_key().unwrap();
    let aux = [0xAAu8; 32];
    let msg = b"bip340 bitcoin test";
    let sig = sign_with_aux(&sk, msg, Some(&aux)).unwrap();
    schnorr_verify(&pk, msg, &sig).unwrap();

    let mut tweak = [0u8; 32];
    tweak[31] = 5;
    let sk2 = tweak_secret(&sk, &tweak).unwrap();
    let pk2 = sk2.public_key().unwrap();
    let sig2 = sign_with_aux(&sk2, msg, Some(&aux)).unwrap();
    schnorr_verify(&pk2, msg, &sig2).unwrap();
}

#[test]
fn rfc6979_reference_entropy_vector_r31() {
    // From test/signer/bitcoin_test.reference "sign/verify r bytes 31"
    // DER: 3043021f7da924...02206e4805... → r (31-byte) || s
    let sk = unhex32("02cd0537757280e3480f433931dea6457aafa2db7642401522760ed2b3edf4cb");
    let digest = unhex32("d34ff82ed41227bb0e8b3c0a466c699107f7c5658371779ffdb9bf69e65f1967");
    let entropy = unhex32("0000000000000000000000000000000000000000000000000000000000000070");
    let secret = SecretKey::from_bytes(&sk).unwrap();
    let sig = sign_ex(&secret, &digest, Some(&entropy)).expect("sign_ex");
    // Expected r from DER (left-pad 31-byte r to 32)
    let r_exp = unhex32("007da924dfdcd2b34092cd46c49c0c30e33e69abad3278adf8e757b5f9fec36e");
    let s_exp = unhex32("6e480592bb0b23384e97ef64309cc48ea21611038834f2c0278e048fde61580b");
    assert_eq!(sig.r, r_exp, "r mismatch");
    assert_eq!(sig.s, s_exp, "s mismatch");
}

#[test]
fn rfc6979_reference_entropy_vector_s31() {
    let sk = unhex32("02cd0537757280e3480f433931dea6457aafa2db7642401522760ed2b3edf4cb");
    let digest = unhex32("d34ff82ed41227bb0e8b3c0a466c699107f7c5658371779ffdb9bf69e65f1967");
    let entropy = unhex32("0000000000000000000000000000000000000000000000000000000000000075");
    let secret = SecretKey::from_bytes(&sk).unwrap();
    let sig = sign_ex(&secret, &digest, Some(&entropy)).expect("sign_ex");
    let r_exp = unhex32("6dea19e91bbe5d0714b3c09f644829fdb0e6dd5bd5261543f1a2f573cec8bea0");
    let s_exp = unhex32("007e455ddd636ca49159827fc3f5d943ccbaa3464605746ad7b164a1c7d03f16");
    assert_eq!(sig.r, r_exp, "r mismatch");
    assert_eq!(sig.s, s_exp, "s mismatch");
}
