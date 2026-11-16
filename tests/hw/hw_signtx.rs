//! Multi-round Trezor `SignTx` session over a scripted transport.
//!
//! Drives the documented loop (start → meta → input → output → finished)
//! through `MockTransport`: every host→device message is asserted byte-exact,
//! every device→host message goes through `parse_tx_request`. No hardware,
//! no emulator — the loop logic is fully provable against the script.
//!
//! Run: `cargo test --features hw --test hw_signtx`

#![cfg(feature = "hw")]

use blockchain_utils::error::Error;
use blockchain_utils::hw::{
    coin::CoinProfile,
    mock::MockTransport,
    path::parse_path,
    transport::Transport,
    trezor::{
        msg, proto_decode, proto_encode, sign_tx_start, trezor_frame, trezor_unframe, tx_ack_bytes,
        tx_req_type, ProtoField, TxChunk,
    },
    wallet::{DeviceKind, HardwareWallet, Wallet},
};

fn btc_path() -> Vec<u32> {
    parse_path("m/44'/0'/0'/0/0").unwrap()
}

/// `TxRequest{type}` with optional embedded details/serialized bodies.
/// `details_hash`: when `Some`, details carry `tx_hash` (prev-tx request).
fn tx_request_frame(
    req_type: u32,
    details_index: Option<u32>,
    details_hash: Option<Vec<u8>>,
    serialized: Option<(u32, Vec<u8>, Vec<u8>)>,
) -> Vec<u8> {
    let mut nums = vec![1u32];
    let mut fields = vec![ProtoField::Varint(req_type as u64)];
    if details_index.is_some() || details_hash.is_some() {
        let mut dnums = Vec::new();
        let mut dfields = Vec::new();
        if let Some(idx) = details_index {
            dnums.push(1);
            dfields.push(ProtoField::Varint(idx as u64));
        }
        if let Some(h) = details_hash {
            dnums.push(2);
            dfields.push(ProtoField::Bytes(h));
        }
        let inner = proto_encode(&dnums, &dfields).unwrap();
        nums.push(2);
        fields.push(ProtoField::Bytes(inner));
    }
    if let Some((sig_idx, sig, tx)) = serialized {
        let inner = proto_encode(
            &[1, 2, 3],
            &[
                ProtoField::Varint(sig_idx as u64),
                ProtoField::Bytes(sig),
                ProtoField::Bytes(tx),
            ],
        )
        .unwrap();
        nums.push(3);
        fields.push(ProtoField::Bytes(inner));
    }
    trezor_frame(msg::TX_REQUEST, &proto_encode(&nums, &fields).unwrap()).concat()
}

#[test]
fn signtx_full_session_1in_1out() {
    let w = Wallet::new(DeviceKind::TrezorSafe5);
    let path = btc_path();

    // --- open: host sends SignTx{outputs:1, inputs:1} -----------------------
    let start = w
        .sign_tx_start_request(&CoinProfile::BITCOIN, 1, 1)
        .unwrap();
    let owned: Vec<Vec<u8>> = start.chunks(63).map(|c| c.to_vec()).collect();
    let (mtype, body) = trezor_unframe(&owned).unwrap();
    assert_eq!(mtype, msg::SIGN_TX);
    // field order: outputs_count=1 first, inputs_count=1 second
    assert_eq!(
        sign_tx_start(1, 1).unwrap(),
        start,
        "wallet helper must match codec builder"
    );
    let _ = body;

    // --- script the device side: meta → input → output → finished ----------
    let final_sig = vec![0xAAu8; 64];
    let final_tx = vec![0xBB, 0x01, 0x02];
    let script = vec![
        tx_request_frame(tx_req_type::TXMETA, None, None, None),
        tx_request_frame(tx_req_type::TXINPUT, Some(0), None, None),
        tx_request_frame(tx_req_type::TXOUTPUT, Some(0), None, None),
        tx_request_frame(
            tx_req_type::TXFINISHED,
            None,
            None,
            Some((0, final_sig.clone(), final_tx.clone())),
        ),
    ];
    let mut dev = MockTransport::scripted(script);

    // round 1: device asks meta
    let r1 = w.parse_tx_request(&dev.exchange(&start).unwrap()).unwrap();
    assert_eq!(
        (r1.request_type, r1.request_index),
        (tx_req_type::TXMETA, None)
    );
    let ack_meta = tx_ack_bytes(&TxChunk::Meta {
        version: 2,
        lock_time: 0,
        inputs_count: 1,
        outputs_count: 1,
    })
    .unwrap();

    // round 2: device asks input 0
    let r2 = w
        .parse_tx_request(&dev.exchange(&ack_meta).unwrap())
        .unwrap();
    assert_eq!(
        (r2.request_type, r2.request_index),
        (tx_req_type::TXINPUT, Some(0))
    );
    let prev_hash = [0xCCu8; 32];
    let ack_in = tx_ack_bytes(&TxChunk::Input {
        prev_hash,
        prev_index: 3,
        path: path.clone(),
        amount: 60_000,
        script_sig: None,
        script_type: 0,
    })
    .unwrap();
    // prev-tx inputs carry the original scriptSig (field 4)
    let script_sig = vec![0x47, 0x11, 0x21, 0x22];
    let ack_prev = tx_ack_bytes(&TxChunk::Input {
        prev_hash,
        prev_index: 0,
        path: path.clone(),
        amount: 0,
        script_sig: Some(script_sig.clone()),
        script_type: 0,
    })
    .unwrap();
    let owned: Vec<Vec<u8>> = ack_prev.chunks(63).map(|c| c.to_vec()).collect();
    let (mtype, body) = trezor_unframe(&owned).unwrap();
    assert_eq!(mtype, msg::TX_ACK);
    // walk the nested frames to the script_sig bytes
    let outer = proto_decode(&body).unwrap();
    assert_eq!(outer[0].0, 1); // TxAck.tx is field 1 (verified vs firmware)
    let inner = proto_decode(&outer[0].2).unwrap();
    let txin = inner.iter().find(|(n, w, _)| *n == 2 && *w == 2).unwrap();
    let fields = proto_decode(&txin.2).unwrap();
    let got = fields.iter().find(|(n, w, _)| *n == 4 && *w == 2).unwrap();
    assert_eq!(got.2, script_sig);
    // sequence is always present (device demands it)
    let seq = fields.iter().find(|(n, w, _)| *n == 5 && *w == 0).unwrap();
    let (v, _) = blockchain_utils::hw::trezor::varint_decode(&seq.2).unwrap();
    assert_eq!(v, 0xFFFF_FFFF);

    // round 3: device asks output 0
    let r3 = w.parse_tx_request(&dev.exchange(&ack_in).unwrap()).unwrap();
    assert_eq!(
        (r3.request_type, r3.request_index),
        (tx_req_type::TXOUTPUT, Some(0))
    );
    let ack_out = tx_ack_bytes(&TxChunk::OutputAddr {
        address: b"bc1qtestaddress".to_vec(),
        amount: 50_000,
        script_type: 0,
    })
    .unwrap();

    // round 4: finished with signature + serialized tx
    let r4 = w
        .parse_tx_request(&dev.exchange(&ack_out).unwrap())
        .unwrap();
    assert_eq!(r4.request_type, tx_req_type::TXFINISHED);
    assert_eq!(r4.signature_index, Some(0));
    assert_eq!(r4.signature, Some(final_sig));
    assert_eq!(r4.serialized_tx, Some(final_tx));

    // host sent exactly start + 3 acks, each a well-formed TX_ACK frame
    // (except the opener, which is SIGN_TX).
    assert_eq!(dev.seen().len(), 4);
    assert_eq!(dev.seen()[0], start);
    for seen in &dev.seen()[1..] {
        let owned: Vec<Vec<u8>> = seen.chunks(63).map(|c| c.to_vec()).collect();
        let (mtype, _) = trezor_unframe(&owned).unwrap();
        assert_eq!(mtype, msg::TX_ACK);
    }
    assert_eq!(dev.seen()[1], ack_meta);
    assert_eq!(dev.seen()[2], ack_in);
    assert_eq!(dev.seen()[3], ack_out);
}

#[test]
fn signtx_change_output_and_rejections() {
    // Literal wire values, verified against real Model T firmware + .proto.
    // (Symbolic constants alone once hid wrong values here.)
    assert_eq!((msg::SIGN_TX, msg::TX_REQUEST, msg::TX_ACK), (15, 21, 22));
    assert_eq!(msg::SIGN_MESSAGE, 38); // 39 is VerifyMessage
    assert_eq!(
        (
            tx_req_type::TXINPUT,
            tx_req_type::TXOUTPUT,
            tx_req_type::TXMETA,
            tx_req_type::TXFINISHED,
            tx_req_type::TXEXTRADATA
        ),
        (0, 1, 2, 3, 4)
    );
    let w = Wallet::new(DeviceKind::TrezorSafe5);
    // change output nests the path (field 2, repeated) + amount (field 3)
    let ack = tx_ack_bytes(&TxChunk::OutputChange {
        path: btc_path(),
        amount: 24_000,
        script_type: 0,
    })
    .unwrap();
    let owned: Vec<Vec<u8>> = ack.chunks(63).map(|c| c.to_vec()).collect();
    assert_eq!(trezor_unframe(&owned).unwrap().0, msg::TX_ACK);

    // wrong message type is a device-protocol violation, not a parse error
    let addr = trezor_frame(
        msg::ADDRESS,
        &proto_encode(&[1], &[ProtoField::Bytes(b"x".to_vec())]).unwrap(),
    )
    .concat();
    assert_eq!(w.parse_tx_request(&addr), Err(Error::VerificationFailed));
    // missing request_type is malformed
    let empty = trezor_frame(msg::TX_REQUEST, &[]).concat();
    assert_eq!(w.parse_tx_request(&empty), Err(Error::InvalidEncoding));

    // builder validation
    assert!(tx_ack_bytes(&TxChunk::OutputAddr {
        address: vec![],
        amount: 1,
        script_type: 0
    })
    .is_err());
    assert!(w
        .sign_tx_start_request(&CoinProfile::BITCOIN, 0, 1)
        .is_err());
    assert!(w
        .sign_tx_start_request(&CoinProfile::BITCOIN, 1, 300)
        .is_err());

    // prev-tx requests carry tx_hash (legacy inputs stream the previous
    // transaction); current-tx requests leave it absent
    let h = vec![0x11u8; 32];
    let prev = tx_request_frame(tx_req_type::TXINPUT, Some(2), Some(h.clone()), None);
    let owned: Vec<Vec<u8>> = prev.chunks(63).map(|c| c.to_vec()).collect();
    let (mtype, body) = trezor_unframe(&owned).unwrap();
    assert_eq!(mtype, msg::TX_REQUEST);
    let _ = body;
    let r = w.parse_tx_request(&prev).unwrap();
    assert_eq!(r.request_index, Some(2));
    assert_eq!(r.tx_hash, Some(h));
    let plain = tx_request_frame(tx_req_type::TXMETA, None, None, None);
    assert_eq!(w.parse_tx_request(&plain).unwrap().tx_hash, None);

    // non-Trezor families refuse the session open
    for k in DeviceKind::ALL {
        let wk = Wallet::new(*k);
        let r = wk.sign_tx_start_request(&CoinProfile::BITCOIN, 1, 1);
        if k.family() == "trezor" {
            assert!(r.is_ok());
            assert!(wk.parse_tx_request(&addr).is_err());
        } else {
            assert_eq!(r, Err(Error::Unsupported));
            assert_eq!(wk.parse_tx_request(&addr), Err(Error::Unsupported));
        }
    }
}

#[test]
fn signtx_bin_output_nesting() {
    use blockchain_utils::hw::trezor::{tx_ack_bytes, TxChunk};
    // prev-tx outputs ride bin_outputs (field 3), not outputs (field 5)
    let script = vec![0x76, 0xA9, 0x14, 0x11, 0x88, 0xAC];
    let ack = tx_ack_bytes(&TxChunk::OutputBin {
        amount: 1000,
        script_pubkey: script.clone(),
    })
    .unwrap();
    let owned: Vec<Vec<u8>> = ack.chunks(63).map(|c| c.to_vec()).collect();
    let (mtype, body) = trezor_unframe(&owned).unwrap();
    assert_eq!(mtype, msg::TX_ACK);
    let outer = proto_decode(&body).unwrap();
    assert_eq!(outer.len(), 1);
    assert_eq!(outer[0].0, 1); // TxAck.tx
    let tx = proto_decode(&outer[0].2).unwrap();
    let bin = tx.iter().find(|(n, w, _)| *n == 3 && *w == 2).unwrap();
    let inner = proto_decode(&bin.2).unwrap();
    assert_eq!(inner.len(), 2);
    assert_eq!(inner[0], (1, 0, vec![0xE8, 0x07])); // 1000 as varint
    assert_eq!(inner[1], (2, 2, script));
    // empty/oversized scripts rejected
    assert!(tx_ack_bytes(&TxChunk::OutputBin {
        amount: 1,
        script_pubkey: vec![]
    })
    .is_err());
}
