//! BitBox02 host protocol: codec + full paired session against a REAL
//! responder (independent `NoiseXX` instance plays the device, with OP
//! framing per firmware `hww/noise.rs`). No hardware, no simulator — but
//! real handshake crypto both directions, not loopback.
//!
//! Run: `cargo test --features hw --test hw_bitbox`

#![cfg(feature = "hw")]

use blockchain_utils::error::Error;
use blockchain_utils::hw::{
    bitbox::{
        bitbox_btc_pub_request, bitbox_coin_for, bitbox_pub_parse, bitbox_xpub_type_for,
        BitBoxSession, OP_HANDSHAKE_CONT, OP_HANDSHAKE_INIT, OP_NOISE_MSG, REQ_BTC_PUB, RESP_ERROR,
        RESP_PUB,
    },
    coin::CoinProfile,
    mock::MockTransport,
    noise::{NoiseTransport, NoiseXX},
    transport::Transport,
    trezor::{proto_decode, proto_encode, ProtoField},
};

fn btc_path() -> Vec<u32> {
    vec![0x8000002C, 0x80000000, 0x80000000, 0, 0]
}

#[test]
fn codec_request_shape() {
    let req = bitbox_btc_pub_request(0, &btc_path(), 1, true).unwrap();
    // envelope: field 8 = BTCPubRequest
    let outer = proto_decode(&req).unwrap();
    assert_eq!(outer.len(), 1);
    assert_eq!(outer[0].0, REQ_BTC_PUB);
    assert_eq!(outer[0].1, 2);
    // inner: coin=1:BTC(0), keypath=2 ×5, xpub_type=3:XPUB(1), display=5:true
    let inner = proto_decode(&outer[0].2).unwrap();
    let nums: Vec<u32> = inner.iter().map(|(n, _, _)| *n).collect();
    assert_eq!(nums, vec![1, 2, 2, 2, 2, 2, 3, 5]);
    // validation
    assert!(bitbox_btc_pub_request(5, &btc_path(), 1, false).is_err()); // bad coin
    assert!(bitbox_btc_pub_request(0, &btc_path(), 10, false).is_err()); // bad xpub
    assert!(bitbox_btc_pub_request(0, &[], 1, false).is_err()); // empty path
    assert!(bitbox_btc_pub_request(0, &[0u32; 11], 1, false).is_err());
}

#[test]
fn codec_response_and_mapping() {
    // Response{pub=5: PubResponse{pub=1: "xpub..."}}
    let inner = proto_encode(&[1], &[ProtoField::Bytes(b"xpubDUMMY".to_vec())]).unwrap();
    let resp = proto_encode(&[RESP_PUB], &[ProtoField::Bytes(inner)]).unwrap();
    assert_eq!(bitbox_pub_parse(&resp).unwrap(), "xpubDUMMY");
    // device Error envelope -> VerificationFailed (never Invalid*)
    let err = proto_encode(&[RESP_ERROR], &[ProtoField::Bytes(vec![0x08, 0x01])]).unwrap();
    assert_eq!(bitbox_pub_parse(&err), Err(Error::VerificationFailed));
    // missing pub -> InvalidEncoding
    let empty = proto_encode(&[7], &[ProtoField::Bytes(vec![])]).unwrap();
    assert_eq!(bitbox_pub_parse(&empty), Err(Error::InvalidEncoding));
    // garbage is Err, never panic
    assert!(bitbox_pub_parse(&[0xFF; 24]).is_err());

    assert_eq!(bitbox_coin_for(&CoinProfile::BITCOIN), Ok(0));
    assert_eq!(
        bitbox_coin_for(&CoinProfile::TEZOS_TZ1),
        Err(Error::Unsupported)
    );
    assert_eq!(bitbox_xpub_type_for(44), Ok(1));
    assert_eq!(bitbox_xpub_type_for(49), Ok(2));
    assert_eq!(bitbox_xpub_type_for(84), Ok(3));
    assert_eq!(bitbox_xpub_type_for(86), Ok(4));
    assert_eq!(bitbox_xpub_type_for(0), Err(Error::Unsupported));
}

/// Fake BitBox02: a real responder that speaks the post-HWW-framing OP
/// layer exactly like firmware (`hww.rs::process_packet`): every reply is
/// `[OP_STATUS_SUCCESS] + payload` — `[h]`→`[0]`, `[H]+m1`→`[0]+m2`,
/// `[H]+m3`→`[0, pairing]`, `[n]+ct`→`[0]+ct`.
struct FakeDevice {
    hs: Option<NoiseXX>,
    noise: Option<NoiseTransport>,
    xpub: Vec<u8>,
    pairing_byte: u8,
    seen_ops: Vec<u8>,
    got_m1: bool,
    /// Optional scripted HWW replies (plaintext BTCResponse frames) served
    /// in order for post-handshake messages instead of the canned pub.
    sign_script: Vec<Vec<u8>>,
}

impl FakeDevice {
    fn new(xpub: &[u8], pairing_byte: u8) -> Self {
        Self {
            // Device side of the BitBox profile: protocol-name prologue.
            // This literal must equal `BITBOX_NOISE_PROLOGUE` (kept
            // crate-internal); a responder on the generic empty prologue
            // must NOT complete against `BitBoxSession` (see
            // `prologue_mismatch_fails`).
            hs: Some(NoiseXX::new_responder_with_prologue(
                [0x21; 32],
                [0x22; 32],
                b"Noise_XX_25519_ChaChaPoly_SHA256",
            )),
            noise: None,
            xpub: xpub.to_vec(),
            pairing_byte,
            seen_ops: Vec::new(),
            got_m1: false,
            sign_script: Vec::new(),
        }
    }

    fn canned_pub_response(&self) -> Vec<u8> {
        let inner = proto_encode(&[1], &[ProtoField::Bytes(self.xpub.clone())]).unwrap();
        proto_encode(&[RESP_PUB], &[ProtoField::Bytes(inner)]).unwrap()
    }
}

impl Transport for FakeDevice {
    fn exchange(&mut self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        if msg.is_empty() {
            return Err(Error::InvalidLength);
        }
        self.seen_ops.push(msg[0]);
        match msg[0] {
            OP_HANDSHAKE_INIT => {
                if msg.len() != 1 {
                    return Err(Error::InvalidEncoding);
                }
                Ok(vec![0]) // OP_STATUS_SUCCESS, empty payload
            }
            OP_HANDSHAKE_CONT => {
                if !self.got_m1 {
                    // first continuation carries m1 (initiator's ephemeral)
                    let hs = self.hs.as_mut().ok_or(Error::InvalidEncoding)?;
                    hs.read_message_1(&msg[1..])
                        .map_err(|_| Error::VerificationFailed)?;
                    self.got_m1 = true;
                    let mut out = vec![0]; // OP_STATUS_SUCCESS
                    out.extend_from_slice(
                        &hs.write_message_2(b"")
                            .map_err(|_| Error::InvalidEncoding)?,
                    );
                    Ok(out)
                } else {
                    // second continuation carries m3 -> status + done byte
                    let mut hs = self.hs.take().ok_or(Error::InvalidEncoding)?;
                    hs.read_message_3(&msg[1..])
                        .map_err(|_| Error::VerificationFailed)?;
                    self.noise = Some(hs.split().map_err(|_| Error::InvalidEncoding)?);
                    Ok(vec![0, self.pairing_byte])
                }
            }
            OP_NOISE_MSG => {
                let _plain = {
                    let noise = self.noise.as_mut().ok_or(Error::InvalidEncoding)?;
                    noise
                        .decrypt(&msg[1..])
                        .map_err(|_| Error::VerificationFailed)?
                };
                // scripted sign flow takes precedence over the canned pub
                let reply = if self.sign_script.is_empty() {
                    self.canned_pub_response()
                } else {
                    self.sign_script.remove(0)
                };
                let noise = self.noise.as_mut().ok_or(Error::InvalidEncoding)?;
                let mut out = vec![0]; // OP_STATUS_SUCCESS
                out.extend_from_slice(&noise.encrypt(&reply).map_err(|_| Error::InvalidEncoding)?);
                Ok(out)
            }
            _ => Err(Error::InvalidEncoding),
        }
    }
}

#[test]
fn session_handshake_and_btc_pub() {
    // host static (pairing key) + fresh ephemeral, as the app would hold them
    let mut sess =
        BitBoxSession::establish(FakeDevice::new(b"xpubTEST", 1), [0x11; 32], [0x12; 32]).unwrap();
    assert!(sess.pairing_needed());
    assert_ne!(sess.handshake_hash(), [0u8; 32]);

    let xpub = sess
        .execute_btc_pub(&CoinProfile::BITCOIN, &btc_path(), 1, false)
        .unwrap();
    assert_eq!(xpub, "xpubTEST");
}

#[test]
fn prologue_mismatch_fails() {
    // The BitBox profile (protocol-name prologue) must NOT interoperate
    // with the generic empty-prologue profile: m1 is cleartext so it parses,
    // but m2's AEAD fails at the first decrypt.
    let mut init = NoiseXX::new_initiator_with_prologue(
        [0x11; 32],
        [0x12; 32],
        b"Noise_XX_25519_ChaChaPoly_SHA256",
    );
    let mut resp = NoiseXX::new_responder([0x21; 32], [0x22; 32]);
    let m1 = init.write_message_1(b"").unwrap();
    resp.read_message_1(&m1).unwrap();
    let m2 = resp.write_message_2(b"").unwrap();
    assert!(init.read_message_2(&m2).is_err());
}

/// Transparent wrapper recording OP bytes (unit-test helper, not a device).
struct DevIntercept<'a, T: Transport> {
    inner: &'a mut T,
    ops: &'a mut Vec<u8>,
}

fn dev_intercept<'a, T: Transport>(inner: &'a mut T, ops: &'a mut Vec<u8>) -> DevIntercept<'a, T> {
    DevIntercept { inner, ops }
}

impl<T: Transport> Transport for DevIntercept<'_, T> {
    fn exchange(&mut self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        if !msg.is_empty() {
            self.ops.push(msg[0]);
        }
        self.inner.exchange(msg)
    }
}

#[test]
fn session_op_framing_and_pairing_flag() {
    // fresh device that reports "already verified": pairing_needed == false
    let mut ops_seen: Vec<u8> = Vec::new();
    {
        let mut dev = FakeDevice::new(b"x", 0);
        let mut sess = BitBoxSession::establish(
            dev_intercept(&mut dev, &mut ops_seen),
            [0x11; 32],
            [0x12; 32],
        )
        .unwrap();
        assert!(!sess.pairing_needed());
        let _ = sess
            .execute_btc_pub(&CoinProfile::BITCOIN, &btc_path(), 1, false)
            .unwrap();
    }
    // OP sequence: init, cont(m1), cont(m3), noise, ...
    assert!(ops_seen.len() >= 4);
    assert_eq!(
        &ops_seen[..4],
        &[
            OP_HANDSHAKE_INIT,
            OP_HANDSHAKE_CONT,
            OP_HANDSHAKE_CONT,
            OP_NOISE_MSG
        ]
    );
}

#[test]
fn session_rejects_garbage_handshake() {
    // wedged device (scripted junk): establish must fail, never panic
    let junk = MockTransport::fixed(vec![0xFF; 16]);
    assert!(BitBoxSession::establish(junk, [0x11; 32], [0x12; 32]).is_err());
}

/// Hand-rolled DIRECT `Response{btc_sign_next}` frame (independent of
/// `proto_encode` — the parser must handle real wire bytes, not our echo).
fn bb_sign_next_frame(ty: u32, index: Option<u32>, sig: Option<Vec<u8>>) -> Vec<u8> {
    fn varint(mut v: u64, out: &mut Vec<u8>) {
        loop {
            let b = (v & 0x7F) as u8;
            v >>= 7;
            if v == 0 {
                out.push(b);
                break;
            }
            out.push(b | 0x80);
        }
    }
    // sign_next{type, index?, signature?}
    let mut sn = Vec::new();
    sn.push(0x08);
    varint(ty as u64, &mut sn);
    if let Some(ix) = index {
        sn.push(0x10);
        varint(ix as u64, &mut sn);
    }
    if let Some(s) = sig {
        sn.push(0x18);
        varint(1, &mut sn); // has_signature = true
        sn.push(0x22);
        varint(s.len() as u64, &mut sn);
        sn.extend_from_slice(&s);
    }
    let mut outer = Vec::new();
    // DIRECT envelope (what firmware sends for the simple single-sig flow):
    // Response.btc_sign_next = field 6, length-delimited: (6 << 3) | 2.
    outer.push(0x32);
    varint(sn.len() as u64, &mut outer);
    outer.extend_from_slice(&sn);
    outer
}

/// The same `sign_next` in the WRAPPED envelope
/// (`Response{btc: BTCResponse{sign_next}}`, used e.g. in prev-tx passes).
fn bb_sign_next_frame_wrapped(ty: u32, index: Option<u32>, sig: Option<Vec<u8>>) -> Vec<u8> {
    fn varint(mut v: u64, out: &mut Vec<u8>) {
        loop {
            let b = (v & 0x7F) as u8;
            v >>= 7;
            if v == 0 {
                out.push(b);
                break;
            }
            out.push(b | 0x80);
        }
    }
    let mut sn = Vec::new();
    sn.push(0x08);
    varint(ty as u64, &mut sn);
    if let Some(ix) = index {
        sn.push(0x10);
        varint(ix as u64, &mut sn);
    }
    if let Some(s) = sig {
        sn.push(0x18);
        varint(1, &mut sn);
        sn.push(0x22);
        varint(s.len() as u64, &mut sn);
        sn.extend_from_slice(&s);
    }
    let mut btc = Vec::new();
    btc.push(0x1A);
    varint(sn.len() as u64, &mut btc);
    btc.extend_from_slice(&sn);
    let mut outer = Vec::new();
    outer.push(0x6A); // Response.btc = field 13: (13 << 3) | 2
    varint(btc.len() as u64, &mut outer);
    outer.extend_from_slice(&btc);
    outer
}

#[test]
fn bitbox_sign_flow_mock() {
    use blockchain_utils::hw::bitbox::{
        bitbox_sign_ack_bytes, bitbox_sign_init_request, bitbox_sign_next_parse, bitbox_sign_type,
        BitBoxTxChunk,
    };

    // init request shape: Request{9: {...}}; envelope tag = (9<<3)|2 = 0x4A
    let init = bitbox_sign_init_request(0, &btc_path(), 1, 1, 1, 1, 0).unwrap();
    assert_eq!(init[0], 0x4A);
    assert!(bitbox_sign_init_request(0, &btc_path(), 1, 0, 1, 1, 0).is_err()); // version 0
    assert!(bitbox_sign_init_request(0, &btc_path(), 1, 1, 0, 1, 0).is_err()); // 0 inputs
    assert!(bitbox_sign_init_request(0, &btc_path(), 9, 1, 1, 1, 0).is_err()); // bad simple type

    // full loop through a real encrypted session
    let mut dev = FakeDevice::new(b"x", 0);
    dev.sign_script = vec![
        bb_sign_next_frame(bitbox_sign_type::INPUT, Some(0), None),
        bb_sign_next_frame(bitbox_sign_type::OUTPUT, Some(0), None),
        bb_sign_next_frame(bitbox_sign_type::DONE, Some(0), Some(vec![0xAA; 64])),
    ];
    let mut sess = BitBoxSession::establish(dev, [0x11; 32], [0x12; 32]).unwrap();
    // NOTE: establish consumed a FakeDevice by value; drive via exchange_encrypted
    // on BitBoxSession directly (it owns its transport).
    let r1 = sess.exchange_encrypted(&init).unwrap();
    let q1 = bitbox_sign_next_parse(&r1).unwrap();
    assert_eq!(
        (q1.request_type, q1.index),
        (bitbox_sign_type::INPUT, Some(0))
    );
    let ack_in = bitbox_sign_ack_bytes(&BitBoxTxChunk::Input {
        prev_hash: [0x11; 32],
        prev_index: 0,
        amount: 60000,
        sequence: 0xFFFF_FFFF,
        path: btc_path(),
        script_config_index: 0,
    })
    .unwrap();
    let r2 = sess.exchange_encrypted(&ack_in).unwrap();
    let q2 = bitbox_sign_next_parse(&r2).unwrap();
    assert_eq!(
        (q2.request_type, q2.index),
        (bitbox_sign_type::OUTPUT, Some(0))
    );
    let ack_out = bitbox_sign_ack_bytes(&BitBoxTxChunk::OutputChange {
        path: btc_path(),
        amount: 40000,
        script_config_index: 0,
    })
    .unwrap();
    let r3 = sess.exchange_encrypted(&ack_out).unwrap();
    let q3 = bitbox_sign_next_parse(&r3).unwrap();
    assert_eq!(q3.request_type, bitbox_sign_type::DONE);
    assert_eq!(q3.signature, Some(vec![0xAA; 64]));
}

#[test]
fn sign_next_accepts_both_envelopes() {
    use blockchain_utils::hw::bitbox::{bitbox_sign_next_parse, bitbox_sign_type};
    // DIRECT (firmware simple-flow) and WRAPPED (prev-tx passes) must parse
    // identically — the live device sent DIRECT first and the old parser
    // rejected it.
    for frame in [
        bb_sign_next_frame(bitbox_sign_type::INPUT, Some(0), None),
        bb_sign_next_frame_wrapped(bitbox_sign_type::INPUT, Some(0), None),
    ] {
        let q = bitbox_sign_next_parse(&frame).unwrap();
        assert_eq!(
            (q.request_type, q.index),
            (bitbox_sign_type::INPUT, Some(0))
        );
    }
    for frame in [
        bb_sign_next_frame(bitbox_sign_type::DONE, Some(0), Some(vec![0xBB; 64])),
        bb_sign_next_frame_wrapped(bitbox_sign_type::DONE, Some(0), Some(vec![0xBB; 64])),
    ] {
        let q = bitbox_sign_next_parse(&frame).unwrap();
        assert_eq!(q.request_type, bitbox_sign_type::DONE);
        assert_eq!(q.signature, Some(vec![0xBB; 64]));
    }
    // empty sign_next (device asking for input 0 with defaults) parses as
    // INPUT/None rather than failing.
    let q = bitbox_sign_next_parse(&[0x32, 0x00]).unwrap();
    assert_eq!((q.request_type, q.index), (bitbox_sign_type::INPUT, None));
}
