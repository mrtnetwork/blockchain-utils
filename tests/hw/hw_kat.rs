//! HW codec KATs: no device needed. Run with:
//! `cargo test --features hw --test hw_kat`
//! `cargo test --no-default-features --features hw --test hw_kat` (no_std check)

#![cfg(feature = "hw")]

use blockchain_utils::hw::{
    apdu::{encode_bip32_path, Apdu, ApduResponse, SW_OK},
    coin::CoinProfile,
    hid::{hid_frame, hid_unframe, LEDGER_CHANNEL, LEDGER_TAG_APDU},
    mock::MockTransport,
    path::{parse_path, path_to_string, validate_for_coin},
    psbt::Psbt,
    trezor::{msg, proto_decode, proto_encode, trezor_frame, trezor_unframe, ProtoField},
    ur::{ur_decode_single, ur_encode_single, UrAssembler},
    wallet::{DeviceKind, HardwareWallet, Wallet},
};

// ---------------------------------------------------------------- path ---

#[test]
fn path_parse_vectors() {
    assert_eq!(
        parse_path("m/44'/0'/0'/0/0").unwrap(),
        vec![0x8000_002C, 0x8000_0000, 0x8000_0000, 0, 0]
    );
    assert_eq!(
        parse_path("44'/1729'/0'/0'").unwrap(),
        vec![0x8000_002C, 0x8000_06C1, 0x8000_0000, 0x8000_0000]
    );
    assert_eq!(parse_path("m").unwrap(), Vec::<u32>::new());
    assert!(parse_path("m/44'/x'/0").is_err());
    assert!(parse_path("m/44'/2147483648'/0").is_err()); // >= 2^31
    assert!(parse_path("m/44'/").is_err());
    assert!(parse_path("").is_err());
}

#[test]
fn path_roundtrip_string() {
    for s in ["m", "m/44'/0'/0'/0/0", "m/44'/1729'/0'/0'", "m/44'/501'/0'"] {
        let p = parse_path(s).unwrap();
        assert_eq!(path_to_string(&p), s);
    }
}

#[test]
fn path_curve_policy() {
    let btc = parse_path("m/44'/0'/0'/0/0").unwrap();
    assert!(validate_for_coin(&btc, &CoinProfile::BITCOIN).is_ok());
    let tz1 = parse_path("m/44'/1729'/0'/0'").unwrap();
    assert!(validate_for_coin(&tz1, &CoinProfile::TEZOS_TZ1).is_ok());
    // ed25519 must be fully hardened: soft suffix rejected
    let bad = parse_path("m/44'/1729'/0'/0/0").unwrap();
    assert!(validate_for_coin(&bad, &CoinProfile::TEZOS_TZ1).is_err());
    // wrong purpose / coin
    let wrong = parse_path("m/49'/0'/0'/0/0").unwrap();
    assert!(validate_for_coin(&wrong, &CoinProfile::BITCOIN).is_err());
}

// ---------------------------------------------------------------- coin ---

#[test]
fn coin_slip44_matches_reference() {
    assert_eq!(CoinProfile::BITCOIN.slip44, 0);
    assert_eq!(CoinProfile::ETHEREUM.slip44, 60);
    assert_eq!(CoinProfile::TEZOS_TZ1.slip44, 1729);
    assert_eq!(CoinProfile::SOLANA.slip44, 501);
    assert_eq!(CoinProfile::TEZOS_TZ1.suffix(true), "0'/0'");
}

// ---------------------------------------------------------------- apdu ---

#[test]
fn apdu_roundtrip() {
    let a = Apdu::new(0xB0, 0x40, 0, 0, vec![5, 1, 2, 3, 4, 5]);
    let raw = a.to_bytes();
    assert_eq!(Apdu::parse(&raw).unwrap(), a);
    let hdr = Apdu::new(0xE0, 0x01, 0, 0, vec![]);
    assert_eq!(Apdu::parse(&hdr.to_bytes()).unwrap(), hdr);
}

#[test]
fn apdu_response_ok() {
    let r = ApduResponse {
        data: vec![0x04, 0x05],
        sw: SW_OK,
    };
    let raw = r.to_bytes();
    assert!(ApduResponse::parse(&raw).unwrap().is_ok());
    assert_eq!(
        ApduResponse::parse(&raw).unwrap().into_data().unwrap(),
        vec![0x04, 0x05]
    );
    let bad = ApduResponse::parse(&[0x6A, 0x82]).unwrap();
    assert!(bad.into_data().is_err());
}

#[test]
fn bip32_path_encoding() {
    let p = parse_path("m/44'/0'/0'/0/0").unwrap();
    let enc = encode_bip32_path(&p).unwrap();
    assert_eq!(enc[0], 5);
    assert_eq!(&enc[1..5], &[0x80, 0x00, 0x00, 0x2C]);
}

// ---------------------------------------------------------------- hid ---

#[test]
fn hid_roundtrip() {
    let payload: Vec<u8> = (0..200).map(|i| (i % 251) as u8).collect();
    let frames = hid_frame(&payload, LEDGER_CHANNEL, LEDGER_TAG_APDU);
    assert!(frames.iter().all(|f| f.len() == 64));
    assert_eq!(
        hid_unframe(&frames, LEDGER_CHANNEL, LEDGER_TAG_APDU).unwrap(),
        payload
    );
}

// ---------------------------------------------------------------- trezor ---

#[test]
fn trezor_proto_roundtrip() {
    let body = proto_encode(
        &[1, 2],
        &[
            ProtoField::Varint(0x8000_002C),
            ProtoField::Bytes(vec![9, 8]),
        ],
    )
    .unwrap();
    let fields = proto_decode(&body).unwrap();
    assert_eq!(fields[0], (1, 0, vec![0xAC, 0x80, 0x80, 0x80, 0x08]));
    assert_eq!(fields[1], (2, 2, vec![9, 8]));
}

#[test]
fn trezor_frame_roundtrip() {
    let body = vec![7u8; 200];
    let chunks = trezor_frame(msg::GET_ADDRESS, &body);
    assert!(chunks.iter().all(|c| c.len() == 63));
    let (t, back) = trezor_unframe(&chunks).unwrap();
    assert_eq!((t, back), (msg::GET_ADDRESS, body));
}

// ---------------------------------------------------------------- wallet ---

#[test]
fn ledger_get_address_via_mock() {
    let w = Wallet::new(DeviceKind::LedgerNanoSPlus);
    let coin = CoinProfile::BITCOIN;
    let path = parse_path("m/44'/0'/0'/0/0").unwrap();
    assert!(w.supports_coin(&coin));
    let req = w.get_address_request(&coin, &path).unwrap();
    assert_eq!(&req[..4], &[0xE1, 0x00, 0x00, 0x01]);
    // device answers len-prefixed 33B pubkey + 0x9000
    let mut resp = vec![33u8];
    resp.extend_from_slice(&[0x02; 33]);
    resp.extend_from_slice(&[0x90, 0x00]);
    let mut dev = MockTransport::fixed(resp);
    let pk = w.execute_get_address(&mut dev, &coin, &path).unwrap();
    assert_eq!(pk, vec![0x02; 33]);
    assert_eq!(dev.seen().len(), 1);
    // v2 request body: display(0) || path_len(5) || be32(path...)
    assert_eq!(req[5], 0x00); // display
    assert_eq!(req[6], 0x05); // path_len
    assert_eq!(&req[7..11], &[0x80, 0x00, 0x00, 0x2C]); // 44'
}

#[test]
fn ledger_v2_fingerprint_and_xpub_parse() {
    use blockchain_utils::hw::wallet::{ledger_fingerprint_parse, ledger_fingerprint_request};
    // request: E1 05 00 01, no data (case-1 APDU)
    assert_eq!(ledger_fingerprint_request(), vec![0xE1, 0x05, 0x00, 0x01]);
    // 4 bytes + 9000 parse; wrong lengths fail
    let mut resp = vec![0x12, 0x34, 0x56, 0x78, 0x90, 0x00];
    assert_eq!(
        ledger_fingerprint_parse(&resp).unwrap(),
        [0x12, 0x34, 0x56, 0x78]
    );
    resp.pop();
    assert!(ledger_fingerprint_parse(&resp).is_err());
    assert!(ledger_fingerprint_parse(&[0x69, 0x85]).is_err());
    // v2 xpub answers are raw ASCII (no length prefix): kept verbatim
    let w = Wallet::new(DeviceKind::LedgerNanoSPlus);
    let mut ascii = b"tpubDUMMY".to_vec();
    ascii.extend_from_slice(&[0x90, 0x00]);
    assert_eq!(w.parse_address_response(&ascii).unwrap(), b"tpubDUMMY");
}

#[test]
fn trezor_get_address_via_mock() {
    for kind in [
        DeviceKind::TrezorSafe5,
        DeviceKind::TrezorOne,
        DeviceKind::KeepKey,
        DeviceKind::OneKey,
    ] {
        let w = Wallet::new(kind);
        let coin = CoinProfile::ETHEREUM;
        let path = parse_path("m/44'/60'/0'/0/0").unwrap();
        let req = w.get_address_request(&coin, &path).unwrap();
        // request starts with `?##` + GET_ADDRESS
        assert_eq!(&req[..3], b"?##");
        assert_eq!(u16::from_be_bytes([req[3], req[4]]), msg::GET_ADDRESS);
        // script ADDRESS response with field1 = "0xabc"
        let body = proto_encode(&[1], &[ProtoField::Bytes(b"0xabc".to_vec())]).unwrap();
        let scripted = trezor_frame(msg::ADDRESS, &body).concat();
        let mut dev = MockTransport::fixed(scripted);
        assert_eq!(
            w.execute_get_address(&mut dev, &coin, &path).unwrap(),
            b"0xabc"
        );
    }
}

#[test]
fn all_usb_families_share_codec() {
    let path = parse_path("m/44'/0'/0'/0/0").unwrap();
    let r1 = Wallet::new(DeviceKind::LedgerNanoSPlus)
        .get_address_request(&CoinProfile::BITCOIN, &path)
        .unwrap();
    for k in [
        DeviceKind::LedgerNanoX,
        DeviceKind::LedgerFlex,
        DeviceKind::LedgerStax,
    ] {
        assert_eq!(
            Wallet::new(k)
                .get_address_request(&CoinProfile::BITCOIN, &path)
                .unwrap(),
            r1
        );
    }
}

#[test]
fn bitbox_and_bad_curve_are_explicit() {
    let w = Wallet::new(DeviceKind::BitBox02);
    let path = parse_path("m/44'/0'/0'/0/0").unwrap();
    assert_eq!(
        w.get_address_request(&CoinProfile::BITCOIN, &path)
            .unwrap_err(),
        blockchain_utils::error::Error::Unimplemented
    );
    // Cardano kholaw not on generic trezor path in v1
    let ada = Wallet::new(DeviceKind::TrezorSafe5);
    assert!(!ada.supports_coin(&CoinProfile::CARDANO_ICARUS));
}

// ---------------------------------------------------------------- airgap ---

#[test]
fn airgap_qr_roundtrip_no_transport() {
    for k in [
        DeviceKind::Passport,
        DeviceKind::Keystone3,
        DeviceKind::ColdcardQr,
        DeviceKind::JadeQr,
    ] {
        let w = Wallet::new(k);
        assert!(w.kind().is_airgap());
        let path = parse_path("m/44'/1729'/0'/0'").unwrap();
        let qr = w.qr_request(&CoinProfile::TEZOS_TZ1, &path).unwrap();
        assert!(qr.starts_with("ur:bytes/"));
        assert_eq!(w.qr_parse(&qr).unwrap(), w.qr_parse(&qr).unwrap());
        // payload = slip44_be32 || path_be32...
        let payload = w.qr_parse(&qr).unwrap();
        assert_eq!(&payload[..4], &1729u32.to_be_bytes());
        // USB methods must refuse airgap and vice versa
        assert!(w
            .get_address_request(&CoinProfile::TEZOS_TZ1, &path)
            .is_err());
    }
    // USB wallet refuses QR
    let usb = Wallet::new(DeviceKind::LedgerNanoX);
    assert!(usb
        .qr_request(&CoinProfile::BITCOIN, &[0x8000_002C])
        .is_err());
}

#[test]
fn ur_single_and_multipart_vectors() {
    let payload = b"hello-tezos".to_vec();
    let s = ur_encode_single("bytes", &payload);
    let m = ur_decode_single(&s).unwrap();
    assert_eq!(
        (m.ur_type, m.payload, m.part),
        ("bytes".to_string(), payload, None)
    );

    // multipart: split payload in 3, feed out of order + duplicate
    let (a, b, c) = (b"AAA".to_vec(), b"BBBB".to_vec(), b"CC".to_vec());
    let shards = [
        blockchain_utils::hw::ur::ur_encode_part("bytes", 2, 3, &b).unwrap(),
        blockchain_utils::hw::ur::ur_encode_part("bytes", 1, 3, &a).unwrap(),
        blockchain_utils::hw::ur::ur_encode_part("bytes", 2, 3, &b).unwrap(), // dup
        blockchain_utils::hw::ur::ur_encode_part("bytes", 3, 3, &c).unwrap(),
    ];
    let mut asm = UrAssembler::new();
    let mut done = None;
    for sh in &shards {
        if let Some(p) = asm.feed(sh).unwrap() {
            done = Some(p);
        }
    }
    assert_eq!(done.unwrap(), b"AAABBBBCC".to_vec());
}

// ---------------------------------------------------------------- psbt ---

fn tiny_unsigned_tx() -> Vec<u8> {
    let mut tx = vec![1, 0, 0, 0]; // version
    tx.push(1); // 1 input
    tx.extend_from_slice(&[0u8; 32]); // prev txid
    tx.extend_from_slice(&[0, 0, 0, 0]); // vout
    tx.push(0); // empty script
    tx.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]); // seq
    tx.push(1); // 1 output
    tx.extend_from_slice(&1000u64.to_le_bytes());
    tx.push(0); // empty pk
    tx.extend_from_slice(&[0, 0, 0, 0]); // locktime
    tx
}

fn tiny_psbt() -> Vec<u8> {
    let tx = tiny_unsigned_tx();
    let mut out = vec![0x70, 0x73, 0x62, 0x74, 0xFF]; // magic
    out.push(1); // keylen
    out.push(0x00); // UNSIGNED_TX
    out.push(tx.len() as u8);
    out.extend_from_slice(&tx);
    out.push(0); // global separator
    out.push(0); // empty input map
    out.push(0); // empty output map
    out
}

#[test]
fn psbt_minimal_parse() {
    let raw = tiny_psbt();
    let psbt = Psbt::parse(&raw).unwrap();
    assert_eq!((psbt.input_count(), psbt.output_count()), (1, 1));
    assert!(psbt.unsigned_tx.is_some());
    assert!(Psbt::parse(b"notapsbt").is_err());
}

// ---------------------------------------------------------------- matrix ---

#[test]
fn device_matrix_smoke() {
    // every device supports at least one coin and builds one request
    let btc_path = parse_path("m/44'/0'/0'/0/0").unwrap();
    let ed_path = parse_path("m/44'/501'/0'").unwrap();
    for k in DeviceKind::ALL {
        let w = Wallet::new(*k);
        if k.is_airgap() {
            assert!(
                w.qr_request(&CoinProfile::SOLANA, &ed_path).is_ok(),
                "{k:?}"
            );
        } else if *k == DeviceKind::BitBox02 {
            continue; // handshake stub in v1
        } else {
            assert!(
                w.get_address_request(&CoinProfile::BITCOIN, &btc_path)
                    .is_ok(),
                "{k:?}"
            );
        }
    }
}

#[test]
#[cfg(feature = "hw")]
fn trezor_reports_wire_roundtrip() {
    use blockchain_utils::hw::trezor::{
        msg, proto_encode, trezor_frame, trezor_reports_decode, trezor_reports_encode, ProtoField,
    };
    // small (single-report) and large (multi-report) bodies
    for body_len in [0usize, 10, 54, 55, 100, 300] {
        let body: Vec<u8> = (0..body_len).map(|i| (i * 37) as u8).collect();
        let frame = trezor_frame(msg::GET_ADDRESS, &body).concat();
        let reports = trezor_reports_encode(&frame).unwrap();
        // exact firmware layout: 64B, `?` marker, `?##` magic in first
        assert!(reports.iter().all(|r| r.len() == 64 && r[0] == b'?'));
        assert_eq!(&reports[0][0..3], b"?##");
        assert_eq!(&reports[0][3..5], &msg::GET_ADDRESS.to_be_bytes());
        let (t, back) = trezor_reports_decode(&reports).unwrap();
        assert_eq!(t, msg::GET_ADDRESS);
        assert_eq!(back, body);
    }
    // embedded protobuf through the wire format
    let proto = proto_encode(
        &[1, 2],
        &[ProtoField::Varint(9), ProtoField::Bytes(vec![7; 40])],
    )
    .unwrap();
    let frame = trezor_frame(msg::SIGN_TX, &proto).concat();
    let reports = trezor_reports_encode(&frame).unwrap();
    assert_eq!(
        trezor_reports_decode(&reports).unwrap(),
        (msg::SIGN_TX, proto)
    );
    // rejects: empty, bad length, bad marker
    assert!(trezor_reports_decode(&[]).is_err());
    assert!(trezor_reports_decode(&[vec![0u8; 63]]).is_err());
    let mut bad = reports[0].clone();
    bad[0] = b'!';
    let mut reps = reports.clone();
    reps[0] = bad;
    assert!(trezor_reports_decode(&reps).is_err());
    assert!(trezor_reports_encode(b"no-magic").is_err());
}
