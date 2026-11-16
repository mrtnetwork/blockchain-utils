//! Adversarial inputs: every codec must return `Err`, never panic.
//! Run: `cargo test --features hw --test hw_robust`
//! (No device, no network — pure garbage-in/out.)

#![cfg(feature = "hw")]

use blockchain_utils::hw::{
    apdu::{Apdu, ApduResponse},
    coin::CoinProfile,
    discover::{family_for_vid, is_candidate_vid},
    hid::{hid_frame, hid_unframe, LEDGER_CHANNEL, LEDGER_TAG_APDU},
    path::{parse_path, validate_for_coin},
    psbt::Psbt,
    trezor::{proto_decode, trezor_unframe, varint_decode},
    ur::{ur_decode_single, UrAssembler},
    wallet::{DeviceKind, HardwareWallet, Wallet},
};

#[test]
fn garbage_never_panics() {
    let junks: &[&[u8]] = &[
        &[],
        &[0],
        &[0xFF; 3],
        &[0x00; 64],
        &[0xFF; 128],
        b"ur:not-a-real-message",
        b"UR:BYTES/9-of-2/AA",
        b"psbt\xff\x00",
        b"?##",
    ];
    for j in junks {
        let _ = Apdu::parse(j);
        let _ = ApduResponse::parse(j);
        let _ = hid_unframe(&[j.to_vec()], LEDGER_CHANNEL, LEDGER_TAG_APDU);
        let _ = trezor_unframe(&[j.to_vec()]);
        let _ = proto_decode(j);
        let _ = varint_decode(j);
        let _ = Psbt::parse(j);
        let s = String::from_utf8_lossy(j);
        let _ = parse_path(&s);
        let _ = ur_decode_single(&s);
        // truncated frames of every length 0..70
        for n in 0..70usize {
            let cut = &j[..core::cmp::min(n, j.len())];
            let _ = Apdu::parse(cut);
            let _ = ApduResponse::parse(cut);
            let _ = trezor_unframe(&[cut.to_vec()]);
            let _ = Psbt::parse(cut);
        }
    }
    // wrong channel/tag/sequence, short reports
    let payload = vec![1u8; 100];
    let mut frames = hid_frame(&payload, LEDGER_CHANNEL, LEDGER_TAG_APDU);
    assert!(hid_unframe(&frames, 0x1234, LEDGER_TAG_APDU).is_err());
    assert!(hid_unframe(&frames, LEDGER_CHANNEL, 0x07).is_err());
    frames[1][3] ^= 0xFF; // corrupt sequence
    assert!(hid_unframe(&frames, LEDGER_CHANNEL, LEDGER_TAG_APDU).is_err());
    assert!(hid_unframe(&[vec![0u8; 32]], LEDGER_CHANNEL, LEDGER_TAG_APDU).is_err());
    assert!(hid_unframe(&[], LEDGER_CHANNEL, LEDGER_TAG_APDU).is_err());
}

#[test]
fn trezor_padding_and_paths_rejected() {
    // nonzero trailing padding is IGNORED (real firmware sends stale buffer
    // bytes, not zeros — proven vs a Model T emulator; trezorlib slices
    // `buffer[:datalen]` the same way)
    let mut chunks = blockchain_utils::hw::trezor_frame(29, &[1, 2, 3]);
    let last = chunks.len() - 1;
    chunks[last][62] = 1;
    let owned: Vec<Vec<u8>> = chunks.concat().chunks(63).map(|c| c.to_vec()).collect();
    let (mtype, body) = blockchain_utils::hw::trezor_unframe(&owned).unwrap();
    assert_eq!((mtype, body), (29, vec![1, 2, 3]));
    // bad magic
    let mut chunks = blockchain_utils::hw::trezor_frame(29, &[1]);
    chunks[0][0] = b'!';
    assert!(trezor_unframe(&chunks).is_err());
    // unsupported wire type 5 (fixed32)
    assert!(proto_decode(&[0x0D, 1, 2, 3, 4]).is_err());
    // overlong varint
    assert!(varint_decode(&[0x80; 11]).is_err());
    // path out of range / empty component
    assert!(parse_path("m/44'/4294967296'/0").is_err());
    assert!(parse_path("m//0").is_err());
    assert!(parse_path("m/44h'/0").is_err()); // double suffix
    assert_eq!(
        parse_path("m/44h/0").unwrap(),
        parse_path("m/44'/0").unwrap()
    ); // h == '
       // soft ed25519 path rejected for tz1
    let soft = parse_path("m/44'/1729'/0'/0").unwrap();
    assert!(validate_for_coin(&soft, &CoinProfile::TEZOS_TZ1).is_err());
    // short path rejected
    let short = parse_path("m/44'").unwrap();
    assert!(validate_for_coin(&short, &CoinProfile::BITCOIN).is_err());
}

#[test]
fn wallet_refuses_mismatched_families() {
    let btc_path = parse_path("m/44'/0'/0'/0/0").unwrap();
    // airgap has no USB requests; USB has no QR
    for k in DeviceKind::ALL {
        let w = Wallet::new(*k);
        if k.is_airgap() {
            assert!(w
                .get_address_request(&CoinProfile::BITCOIN, &btc_path)
                .is_err());
            assert!(w.parse_address_response(&[0x90, 0x00]).is_err());
        } else {
            assert!(w.qr_request(&CoinProfile::BITCOIN, &btc_path).is_err());
            assert!(w.qr_parse("ur:bytes/AA").is_err());
        }
    }
    // multipart into single-part parser
    let air = Wallet::new(DeviceKind::Passport);
    assert!(air.qr_parse("ur:bytes/1-of-2/AA").is_err());
    // assembler rejects mixed streams
    let mut asm = UrAssembler::new();
    let p1 = blockchain_utils::hw::ur::ur_encode_part("bytes", 1, 2, &[1]).unwrap();
    assert!(asm.feed(&p1).unwrap().is_none());
    assert!(asm.feed("ur:crypto-psbt/2-of-2/AA").is_err());
}

#[test]
fn discover_table_sane() {
    assert_eq!(family_for_vid(0x2C97), Some("ledger"));
    assert_eq!(family_for_vid(0x534C), Some("trezor"));
    assert_eq!(family_for_vid(0x1209), Some("trezor"));
    assert_eq!(family_for_vid(0x2B24), Some("trezor"));
    assert_eq!(family_for_vid(0x03EB), Some("bitbox"));
    assert_eq!(family_for_vid(0x1234), None);
    assert!(is_candidate_vid(0x2C97));
    assert!(!is_candidate_vid(0x046D)); // random Logitech mouse
}

#[test]
fn fuzz_crash_regressions() {
    // --- `fuzz_trezor` crash-9180b0…: field 9 / wire-type 2, then a
    // 10-byte `0xff…0x01` length (≈ u64::MAX). `i + len` wrapped `usize`,
    // passed the length check, and panicked in `body[i..i+len]`. Must be
    // `Err`, on every profile and word size.
    let mut crash = vec![0xCA, 0x00];
    crash.extend_from_slice(&[0xFF; 9]);
    crash.push(0x01);
    crash.extend_from_slice(&[0x00, 0x00, 0x09]);
    crash.extend_from_slice(&[0xFF; 85]);
    crash.extend_from_slice(&[0x00; 7]);
    crash.push(0x08);
    assert_eq!(crash.len(), 108);
    assert!(proto_decode(&crash).is_err());
    // The key varint itself is well-formed (`0xCA 0x00` → key 0x4A, 2 bytes);
    // decoding it must succeed — the `Err` above comes from the length.
    assert_eq!(varint_decode(&crash), Ok((0x4A, 2)));
    let chunks: Vec<Vec<u8>> = crash.chunks(63).map(|c| c.to_vec()).collect();
    assert!(trezor_unframe(&chunks).is_err());

    // Declared-length overflow in `trezor_unframe` (`9 + len` wraps on
    // 32-bit): magic valid, length u32::MAX, body absent.
    let mut big = vec![0u8; 63];
    big[0..3].copy_from_slice(b"?##");
    big[5..9].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(trezor_unframe(&[big]).is_err());

    // PSBT compactsize-huge (`0xFF` + 8×`0xff` length): same wrapping
    // class in `read_bytes`. Magic + one map with a gigantic key length.
    let mut psbt = b"psbt\xff".to_vec();
    psbt.push(0xFF);
    psbt.extend_from_slice(&[0xFF; 8]);
    assert!(Psbt::parse(&psbt).is_err());
    assert!(Psbt::parse(&b"psbt\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"[..]).is_err());

    // PSBT long key-type varint (unbounded continuation run): must be
    // `Err`, never a shift-overflow panic. klen=21, key = `0xFD` +
    // 20 continuation bytes with no terminator.
    let mut psbt2 = b"psbt\xff".to_vec();
    psbt2.push(0x15);
    psbt2.push(0xFD);
    psbt2.extend_from_slice(&[0x80; 20]);
    assert!(Psbt::parse(&psbt2).is_err());

    // UR assembler: hostile first shard declares a gigantic `total`
    // (`ur:bytes/1-of-4294967295/…`) — must be `Err`, never a ~100 GB
    // `parts` allocation.
    let mut asm = UrAssembler::new();
    assert!(asm.feed("ur:bytes/1-of-4294967295/AA").is_err());
    assert!(asm.is_empty());
}
