//! Sign-flow tests over scripted transports (no hardware, no emulator).
//!
//! Covers approve + user-reject for Ledger (APDU) and Trezor (`SignMessage`),
//! builder validation, airgap/BitBox refusal contracts, and the `execute_sign`
//! convenience. Real-firmware shape is pinned by `hw_speculos.rs` (ignored).
//!
//! Run: `cargo test --features hw --test hw_sign`

#![cfg(feature = "hw")]

use blockchain_utils::error::Error;
use blockchain_utils::hw::{
    coin::CoinProfile,
    mock::MockTransport,
    path::parse_path,
    trezor::{
        identity_encode, parse_signed_identity, proto_decode, proto_encode, sign_identity_request,
        trezor_frame, trezor_unframe, ProtoField,
    },
    wallet::{DeviceKind, HardwareWallet, Wallet},
};

fn btc_path() -> Vec<u32> {
    parse_path("m/44'/0'/0'/0/0").unwrap()
}

#[test]
fn ledger_sign_is_psbt_only() {
    // app-bitcoin v2 has NO bare-hash sign command (proven live: the old
    // 0xB0/0x48 template matches no shipping firmware). Signing is the PSBT
    // wallet-policy flow; until it lands, this is Unimplemented — never a
    // silently-wrong APDU.
    let w = Wallet::new(DeviceKind::LedgerNanoSPlus);
    let hash = [0xABu8; 32];
    assert_eq!(
        w.sign_request(&CoinProfile::BITCOIN, &btc_path(), &hash),
        Err(Error::Unimplemented)
    );
    assert_eq!(
        w.execute_sign(
            &mut MockTransport::fixed(vec![0x90, 0x00]),
            &CoinProfile::BITCOIN,
            &btc_path(),
            &hash
        ),
        Err(Error::Unimplemented)
    );
}

#[test]
fn trezor_signmessage_approve_and_reject() {
    let w = Wallet::new(DeviceKind::TrezorSafe5);
    let msg_text = b"hello trezor";

    let sig = vec![0x99u8; 65];
    let body = proto_encode(
        &[1, 2],
        &[
            ProtoField::Bytes(b"bc1qtest".to_vec()),
            ProtoField::Bytes(sig.clone()),
        ],
    )
    .unwrap();
    let frame = trezor_frame(blockchain_utils::hw::trezor::msg::MESSAGE_SIGNATURE, &body).concat();
    let mut dev = MockTransport::fixed(frame);
    assert_eq!(
        w.execute_sign(&mut dev, &CoinProfile::BITCOIN, &btc_path(), msg_text)
            .unwrap(),
        sig
    );

    // Wrong message type (e.g. ADDRESS answering a sign) → VerificationFailed.
    let wrong = trezor_frame(
        blockchain_utils::hw::trezor::msg::ADDRESS,
        &proto_encode(&[1], &[ProtoField::Bytes(b"x".to_vec())]).unwrap(),
    )
    .concat();
    let mut dev = MockTransport::fixed(wrong);
    assert_eq!(
        w.execute_sign(&mut dev, &CoinProfile::BITCOIN, &btc_path(), msg_text),
        Err(Error::VerificationFailed)
    );

    // Builder validation: empty and oversized messages rejected host-side.
    assert_eq!(
        w.sign_request(&CoinProfile::BITCOIN, &btc_path(), b""),
        Err(Error::InvalidLength)
    );
    assert_eq!(
        w.sign_request(&CoinProfile::BITCOIN, &btc_path(), &vec![0u8; 1025]),
        Err(Error::InvalidLength)
    );
}

#[test]
fn sign_refusal_contracts() {
    let hash = [0u8; 32];
    // Airgap: signing is qr_request + scan-back, never USB request/response.
    for k in DeviceKind::ALL {
        let w = Wallet::new(*k);
        if k.is_airgap() {
            assert_eq!(
                w.sign_request(&CoinProfile::BITCOIN, &btc_path(), &hash),
                Err(Error::Unsupported)
            );
            assert_eq!(
                w.parse_sign_response(&[0x90, 0x00]),
                Err(Error::Unsupported)
            );
            // ...but the QR leg works for every airgap kind.
            assert!(w.qr_request(&CoinProfile::BITCOIN, &btc_path()).is_ok());
        } else if *k == DeviceKind::BitBox02 {
            assert_eq!(
                w.sign_request(&CoinProfile::BITCOIN, &btc_path(), &hash),
                Err(Error::Unimplemented)
            );
        } else if k.family() == "ledger" {
            // v2 = PSBT wallet flow (see ledger_sign_is_psbt_only), but
            // address requests still build fine.
            assert_eq!(
                w.sign_request(&CoinProfile::BITCOIN, &btc_path(), &hash),
                Err(Error::Unimplemented)
            );
            assert!(w
                .get_address_request(&CoinProfile::BITCOIN, &btc_path())
                .is_ok());
        } else {
            // Every USB family builds a request for a valid hash/message.
            let payload: &[u8] = if k.family() == "ledger" { &hash } else { b"m" };
            assert!(w
                .sign_request(&CoinProfile::BITCOIN, &btc_path(), payload)
                .is_ok());
        }
    }
}

#[test]
fn identity_encode_shape() {
    // IdentityType{proto = 1, user = 2, host = 3}: (1<<3)|2 = 0x0A etc.
    let id = identity_encode("ssh", "alice", "example.com", "", "", 0).unwrap();
    let fields = proto_decode(&id).unwrap();
    let nums: Vec<u32> = fields.iter().map(|(n, _, _)| *n).collect();
    assert_eq!(nums, vec![1, 2, 3, 6]); // + index field (always encoded)
    assert_eq!(fields[0].2, b"ssh");
    assert_eq!(fields[2].2, b"example.com");
    // index != 0 encodes as field 6
    let id2 = identity_encode("gpg", "", "x", "", "", 7).unwrap();
    let nums2: Vec<u32> = proto_decode(&id2)
        .unwrap()
        .iter()
        .map(|(n, _, _)| *n)
        .collect();
    assert_eq!(nums2, vec![1, 3, 6]);
    // index == 0 is still encoded (trezorlib emits field 6 varint 0); the
    // varint decodes back to 0
    let f0 = proto_decode(&id).unwrap();
    assert_eq!(f0[3], (6, 0, vec![0]));
    // validation
    assert!(identity_encode("", "a", "h", "", "", 0).is_err()); // empty proto
    assert!(identity_encode("ssh", &"u".repeat(257), "h", "", "", 0).is_err());
}

#[test]
fn sign_identity_request_shape() {
    let id = identity_encode("https", "bob", "example.com", "", "", 0).unwrap();
    let framed = sign_identity_request(&id, &[0xAA; 32], "2026-10-06", None).unwrap();
    // framed as message type 53
    let chunks: Vec<Vec<u8>> = framed.chunks(63).map(|c| c.to_vec()).collect();
    let (ty, body) = trezor_unframe(&chunks).unwrap();
    assert_eq!(ty, 53);
    let fields = proto_decode(&body).unwrap();
    let nums: Vec<u32> = fields.iter().map(|(n, _, _)| *n).collect();
    assert_eq!(nums, vec![1, 2, 3]); // identity, hidden, visual
    assert_eq!(fields[1].2, vec![0xAA; 32]);
    assert_eq!(fields[2].2, b"2026-10-06");
    // explicit curve encodes as field 4
    let framed2 = sign_identity_request(&id, b"", "", Some("nist256p1")).unwrap();
    let chunks2: Vec<Vec<u8>> = framed2.chunks(63).map(|c| c.to_vec()).collect();
    let (_, body2) = trezor_unframe(&chunks2).unwrap();
    let nums2: Vec<u32> = proto_decode(&body2)
        .unwrap()
        .iter()
        .map(|(n, _, _)| *n)
        .collect();
    assert_eq!(nums2, vec![1, 4]);
    // validation
    assert!(sign_identity_request(b"", b"", "", None).is_err());
    assert!(sign_identity_request(&id, &[0; 129], "", None).is_err());
    assert!(sign_identity_request(&id, b"", "", Some("ed25519")).is_err());
}

#[test]
fn parse_signed_identity_roundtrip() {
    // hand-rolled SignedIdentity{address = 1, public_key = 2, signature = 3}
    let body = proto_encode(
        &[1, 2, 3],
        &[
            ProtoField::Bytes(b"alice@example.com".to_vec()),
            ProtoField::Bytes(vec![0x02; 33]),
            ProtoField::Bytes(vec![0xCC; 65]),
        ],
    )
    .unwrap();
    let r = parse_signed_identity(&body).unwrap();
    assert_eq!(r.address.as_deref(), Some("alice@example.com"));
    assert_eq!(r.public_key, vec![0x02; 33]);
    assert_eq!(r.signature, vec![0xCC; 65]);
    // address optional; key+sig required
    let no_addr = proto_encode(
        &[2, 3],
        &[
            ProtoField::Bytes(vec![0x02; 33]),
            ProtoField::Bytes(vec![0xCC; 65]),
        ],
    )
    .unwrap();
    let r2 = parse_signed_identity(&no_addr).unwrap();
    assert_eq!(r2.address, None);
    assert!(parse_signed_identity(
        &proto_encode(&[2], &[ProtoField::Bytes(vec![0x02; 33])]).unwrap()
    )
    .is_err());
    assert!(parse_signed_identity(&[0xFF; 8]).is_err());
}
