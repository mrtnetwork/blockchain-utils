//! Trezor protocol: minimal protobuf codec + `?##` USB framing.
//!
//! Covers Model One / T / Safe 3 / 5 / 7, plus KeepKey / OneKey forks
//! (same wire format). Only `varint` + `length-delimited` wire types are
//! needed for `GetAddress`-class messages; full `.proto` reflection is out
//! of scope for zero-dep v1.
//!
//! Framing over HID (from `trezor-common` `transport.py`):
//! `? ## msgtype_be16 datalen_be32 protobuf...`, chunked in 63-byte payloads.

use crate::error::{Error, Result};

use alloc::vec::Vec;

/// Trezor USB magic prefix.
pub const TREZOR_MAGIC: [u8; 3] = *b"?##";
/// HID payload per chunk after the 1-byte report id.
pub const TREZOR_CHUNK: usize = 63;

/// One protobuf field (enough for address flows).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProtoField {
    Varint(u64),
    Bytes(Vec<u8>),
}

/// Encode `u64` as protobuf varint.
pub fn varint_encode(mut v: u64, out: &mut Vec<u8>) {
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

/// Decode varint from `buf`, returning `(value, bytes_consumed)`.
pub fn varint_decode(buf: &[u8]) -> Result<(u64, usize)> {
    let mut v: u64 = 0;
    let mut shift = 0u32;
    for (i, b) in buf.iter().enumerate() {
        if shift >= 64 {
            return Err(Error::InvalidEncoding);
        }
        v |= ((*b as u64) & 0x7F) << shift;
        if b & 0x80 == 0 {
            return Ok((v, i + 1));
        }
        shift += 7;
        if i >= 9 {
            return Err(Error::InvalidEncoding);
        }
    }
    Err(Error::InvalidLength)
}

/// Encode fields as `tag || value` sequence.
/// `number`: field number, `fields[i]` corresponds to `numbers[i]`.
pub fn proto_encode(numbers: &[u32], fields: &[ProtoField]) -> Result<Vec<u8>> {
    if numbers.len() != fields.len() {
        return Err(Error::InvalidLength);
    }
    let mut out = Vec::new();
    for (n, f) in numbers.iter().zip(fields.iter()) {
        match f {
            ProtoField::Varint(v) => {
                varint_encode((*n as u64) << 3, &mut out);
                varint_encode(*v, &mut out);
            }
            ProtoField::Bytes(b) => {
                varint_encode(((*n as u64) << 3) | 2, &mut out);
                varint_encode(b.len() as u64, &mut out);
                out.extend_from_slice(b);
            }
        }
    }
    Ok(out)
}

/// Decode a flat protobuf body into `(field_number, wire_type, raw_value)`.
/// `raw_value` is the varint bytes or the length-delimited bytes.
pub fn proto_decode(body: &[u8]) -> Result<Vec<(u32, u8, Vec<u8>)>> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < body.len() {
        let (key, n) = varint_decode(&body[i..])?;
        i += n;
        let num = (key >> 3) as u32;
        let wt = (key & 7) as u8;
        match wt {
            0 => {
                let start = i;
                let (_, m) = varint_decode(&body[i..])?;
                out.push((num, wt, body[start..start + m].to_vec()));
                i += m;
            }
            2 => {
                let (len, m) = varint_decode(&body[i..])?;
                i += m;
                // `len` is attacker-controlled (up to u64::MAX): a plain
                // `i + len` can wrap `usize`, pass the length check, and
                // panic in the slice below. Found by `fuzz_trezor`
                // (crash-9180b0…: 10-byte `0xff…0x01` length ≈ u64::MAX).
                let end = i.checked_add(len as usize).ok_or(Error::InvalidLength)?;
                if body.len() < end {
                    return Err(Error::InvalidLength);
                }
                out.push((num, wt, body[i..end].to_vec()));
                i = end;
            }
            _ => return Err(Error::Unsupported),
        }
    }
    Ok(out)
}

/// Encode a BIP32 path as repeated `uint32 address_n` (field 1), like
/// `GetAddress(address_n=[h(44),h(coin),...])`.
pub fn encode_bip32_fields(path: &[u32]) -> (Vec<u32>, Vec<ProtoField>) {
    let nums = alloc::vec![1u32; path.len()];
    let fields = path
        .iter()
        .map(|i| ProtoField::Varint(*i as u64))
        .collect::<Vec<_>>();
    (nums, fields)
}

/// Frame `msg_type + protobuf` into 63-byte HID chunks with `?##` header.
pub fn trezor_frame(msg_type: u16, protobuf: &[u8]) -> Vec<Vec<u8>> {
    let mut header = Vec::with_capacity(3 + 2 + 4 + protobuf.len());
    header.extend_from_slice(&TREZOR_MAGIC);
    header.extend_from_slice(&msg_type.to_be_bytes());
    header.extend_from_slice(&(protobuf.len() as u32).to_be_bytes());
    header.extend_from_slice(protobuf);
    header
        .chunks(TREZOR_CHUNK)
        .map(|c| {
            let mut blk = c.to_vec();
            while blk.len() < TREZOR_CHUNK {
                blk.push(0);
            }
            blk
        })
        .collect()
}

/// Inverse of [`trezor_frame`]: validate magic, length, trailing padding.
pub fn trezor_unframe(chunks: &[Vec<u8>]) -> Result<(u16, Vec<u8>)> {
    let mut raw = Vec::new();
    for c in chunks {
        raw.extend_from_slice(c);
    }
    if raw.len() < 9 {
        return Err(Error::InvalidLength);
    }
    if raw[0..3] != TREZOR_MAGIC {
        return Err(Error::InvalidEncoding);
    }
    let msg_type = u16::from_be_bytes([raw[3], raw[4]]);
    let len = u32::from_be_bytes([raw[5], raw[6], raw[7], raw[8]]) as usize;
    // `len` is attacker-controlled: plain `9 + len` can wrap `usize` on
    // 32-bit targets and bypass the check below (same class as the
    // `proto_decode` fuzz crash).
    let end = 9usize.checked_add(len).ok_or(Error::InvalidLength)?;
    if raw.len() < end {
        return Err(Error::InvalidLength);
    }
    let body = raw[9..end].to_vec();
    // Trailing bytes are IGNORED (not validated): real firmware does not
    // zero-pad the last report — it sends stale buffer bytes. Proven against
    // a Model T emulator: a 247-byte Features reply ended in nonzero padding
    // (`...01900301e8030080`). trezorlib behaves the same (`buffer[:datalen]`).
    // The declared length fully determines the body; anything past it is
    // transport framing, not protocol.
    Ok((msg_type, body))
}

/// Well-known Trezor message types (subset).
pub mod msg {
    pub const GET_ADDRESS: u16 = 29;
    pub const ADDRESS: u16 = 30;
    pub const GET_PUBLIC_KEY: u16 = 11;
    pub const PUBLIC_KEY: u16 = 12;
    /// Sign a text message (single round-trip; tx signing streams
    /// `SignTx` inputs/outputs via the loop below).
    /// NOTE: 39 is `VerifyMessage`, 38 is `SignMessage` — verified against
    /// real Model T firmware (a wrong type fails decode on-device).
    pub const SIGN_MESSAGE: u16 = 38;
    pub const MESSAGE_SIGNATURE: u16 = 40;
    /// Multi-round transaction signing (`SignTx` → `TxRequest`/`TxAck` loop).
    pub const SIGN_TX: u16 = 15;
    pub const TX_REQUEST: u16 = 21;
    pub const TX_ACK: u16 = 22;
    /// Identity signing (`SignIdentity` → `SignedIdentity`, SLIP-13; SSH/GPG
    /// agents and challenge-response logins — no value transfer involved).
    pub const SIGN_IDENTITY: u16 = 53;
    pub const SIGNED_IDENTITY: u16 = 54;
}

/// `TxRequest.request_type` values (`messages-bitcoin.proto` `RequestType`).
/// Verified against real firmware — an earlier revision had these wrong
/// (TXMETA=0/...); the device is the oracle.
pub mod tx_req_type {
    pub const TXINPUT: u32 = 0;
    pub const TXOUTPUT: u32 = 1;
    pub const TXMETA: u32 = 2;
    pub const TXFINISHED: u32 = 3;
    pub const TXEXTRADATA: u32 = 4;
    pub const TXORIGINPUT: u32 = 5;
    pub const TXORIGOUTPUT: u32 = 6;
    pub const TXPAYMENTREQ: u32 = 7;
}

// ---------------------------------------------------------------------------
// Multi-round transaction signing (`SignTx` → `TxRequest`/`TxAck` loop).
//
// Field numbers follow `messages-bitcoin.proto`. The flat `proto_encode`
// handles nesting by pre-encoding the inner message and wrapping it as
// `ProtoField::Bytes` (protobuf embedded messages ARE length-delimited
// fields). `coin_name` is omitted everywhere (optional on the wire; the
// device default — Bitcoin — applies; alt-coin signing passes it explicitly.)
// ---------------------------------------------------------------------------

/// One parsed `TxRequest`: what the device asks for next.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxRequest {
    /// One of `tx_req_type::*`.
    pub request_type: u32,
    /// Which input/output the device wants (`details.request_index`).
    pub request_index: Option<u32>,
    /// `details.tx_hash`: present when the device wants data from a
    /// PREVIOUS transaction (legacy inputs) rather than the tx being
    /// signed — answer with that transaction's chunks, not the current ones.
    pub tx_hash: Option<Vec<u8>>,
    /// Present on `TXFINISHED`: signature for `signature_index`-th input.
    pub signature_index: Option<u32>,
    /// Present on `TXFINISHED`.
    pub signature: Option<Vec<u8>>,
    /// Present on `TXFINISHED`: consensus-serialized signed transaction.
    pub serialized_tx: Option<Vec<u8>>,
}

/// Build the loop-opening `SignTx` frame (device answers `TxRequest`,
/// typically TXINPUT#0 first — the app must follow whatever comes).
/// Explicit coin (`Bitcoin`), version, lock_time, amount_unit, and serialize
/// are always encoded (matching trezorlib byte-for-byte, not just
/// semantically): real firmware silently refuses to sign without them even
/// though collection succeeds.
pub fn sign_tx_start(inputs_count: u32, outputs_count: u32) -> Result<Vec<u8>> {
    let body = proto_encode(
        &[1, 2, 3, 4, 5, 11, 13],
        &[
            ProtoField::Varint(outputs_count as u64),
            ProtoField::Varint(inputs_count as u64),
            ProtoField::Bytes(b"Bitcoin".to_vec()),
            ProtoField::Varint(1),
            ProtoField::Varint(0),
            ProtoField::Varint(0),
            ProtoField::Varint(1),
        ],
    )?;
    Ok(trezor_frame(msg::SIGN_TX, &body).concat())
}

/// One `TxAck` payload the host sends back per `TxRequest`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TxChunk {
    /// Answer to `TXMETA`: chain parameters + counts.
    Meta {
        version: u32,
        lock_time: u32,
        inputs_count: u32,
        outputs_count: u32,
    },
    /// Answer to `TXINPUT`: the requested input's outpoint + our path.
    /// `amount` (field 8) is the previous output's value in sats — the
    /// device rejects the chunk without it ("Missing required field. amount"
    /// on real firmware), segwit or not.
    /// `script_sig` (field 4): `None` omits it (the input being signed —
    /// the device fills the hash); `Some` includes it verbatim (previous
    /// transactions' inputs, where the device demands the field present —
    /// "Missing required field. script_sig" on real firmware).
    /// `script_type` (field 6, explicit: SPENDADDRESS = 0, SPENDMULTISIG = 1,
    /// EXTERNAL = 2, SPENDWITNESS = 3, SPENDP2SHWITNESS = 4) — always
    /// encoded, like trezorlib (omitting it stalls the signing pass on real
    /// firmware even though collection succeeds).
    Input {
        prev_hash: [u8; 32],
        prev_index: u32,
        path: Vec<u32>,
        amount: u64,
        script_sig: Option<Vec<u8>>,
        script_type: u32,
    },
    /// Answer to `TXOUTPUT`: pay-to-address output.
    /// `script_type` (field 4, explicit: PAYTOADDRESS = 0, …) — always
    /// encoded; omitting it stalls signing on real firmware (collection
    /// still succeeds), same lesson as inputs.
    OutputAddr {
        address: Vec<u8>,
        amount: u64,
        script_type: u32,
    },
    /// Answer to `TXOUTPUT`: change output back to our path.
    OutputChange {
        path: Vec<u32>,
        amount: u64,
        script_type: u32,
    },
    /// Answer to `TXOUTPUT` for a PREVIOUS transaction: raw
    /// `TxOutputBinType` (`bin_outputs`, field 3 — amount=1, script_pubkey=2).
    /// Previous transactions are chain data: the device wants scripts, not
    /// addresses ("Missing required field. output" on real firmware when
    /// field-5 outputs are sent for prev-tx).
    OutputBin { amount: u64, script_pubkey: Vec<u8> },
}

/// Build one `TxAck` frame answering a `TxRequest` (field 1 = embedded
/// `TransactionType`: version=1, inputs=2, lock_time=4, outputs=5,
/// inputs_cnt=6, outputs_cnt=7; field numbers per `messages-bitcoin.proto`,
/// verified against real firmware).
pub fn tx_ack_bytes(chunk: &TxChunk) -> Result<Vec<u8>> {
    let inner = match chunk {
        TxChunk::Meta {
            version,
            lock_time,
            inputs_count,
            outputs_count,
        } => proto_encode(
            &[1, 4, 6, 7],
            &[
                ProtoField::Varint(*version as u64),
                ProtoField::Varint(*lock_time as u64),
                ProtoField::Varint(*inputs_count as u64),
                ProtoField::Varint(*outputs_count as u64),
            ],
        )?,
        TxChunk::Input {
            prev_hash,
            prev_index,
            path,
            amount,
            script_sig,
            script_type,
        } => {
            if path.len() > 10 {
                return Err(Error::InvalidPath);
            }
            if *script_type > 4 {
                return Err(Error::InvalidEncoding);
            }
            let mut nums = alloc::vec![1u32; path.len()];
            let mut fields: Vec<ProtoField> =
                path.iter().map(|i| ProtoField::Varint(*i as u64)).collect();
            // address_n=1, prev_hash=2, prev_index=3, [script_sig=4],
            // sequence=5 (always 0xFFFFFFFF: the device rejects the chunk
            // without it — "Missing required field. sequence" on real
            // firmware; RBF is not signaled), script_type=6,
            // amount=8.
            nums.extend_from_slice(&[2, 3]);
            fields.push(ProtoField::Bytes(prev_hash.to_vec()));
            fields.push(ProtoField::Varint(*prev_index as u64));
            if let Some(sig) = script_sig {
                nums.push(4);
                fields.push(ProtoField::Bytes(sig.clone()));
            }
            nums.extend_from_slice(&[5, 6, 8]);
            fields.push(ProtoField::Varint(0xFFFF_FFFF));
            fields.push(ProtoField::Varint(*script_type as u64));
            fields.push(ProtoField::Varint(*amount));
            let input = proto_encode(&nums, &fields)?;
            proto_encode(&[2], &[ProtoField::Bytes(input)])?
        }
        TxChunk::OutputAddr {
            address,
            amount,
            script_type,
        } => {
            if address.is_empty() || address.len() > 128 {
                return Err(Error::InvalidLength);
            }
            let output = proto_encode(
                &[1, 3, 4],
                &[
                    ProtoField::Bytes(address.clone()),
                    ProtoField::Varint(*amount),
                    ProtoField::Varint(*script_type as u64),
                ],
            )?;
            proto_encode(&[5], &[ProtoField::Bytes(output)])?
        }
        TxChunk::OutputChange {
            path,
            amount,
            script_type,
        } => {
            if path.len() > 10 {
                return Err(Error::InvalidPath);
            }
            let mut nums = alloc::vec![2u32; path.len()];
            let mut fields: Vec<ProtoField> =
                path.iter().map(|i| ProtoField::Varint(*i as u64)).collect();
            nums.extend_from_slice(&[3, 4]);
            fields.push(ProtoField::Varint(*amount));
            fields.push(ProtoField::Varint(*script_type as u64));
            let output = proto_encode(&nums, &fields)?;
            proto_encode(&[5], &[ProtoField::Bytes(output)])?
        }
        TxChunk::OutputBin {
            amount,
            script_pubkey,
        } => {
            if script_pubkey.is_empty() || script_pubkey.len() > 1000 {
                return Err(Error::InvalidLength);
            }
            let output = proto_encode(
                &[1, 2],
                &[
                    ProtoField::Varint(*amount),
                    ProtoField::Bytes(script_pubkey.clone()),
                ],
            )?;
            proto_encode(&[3], &[ProtoField::Bytes(output)])?
        }
    };
    let body = proto_encode(&[1], &[ProtoField::Bytes(inner)])?;
    Ok(trezor_frame(msg::TX_ACK, &body).concat())
}

/// Parse one `TxRequest` frame (concatenated 63-byte chunks, as produced by
/// scripted transports and HID report reassembly).
pub fn tx_request_parse(resp: &[u8]) -> Result<TxRequest> {
    let owned: Vec<Vec<u8>> = resp.chunks(63).map(|c| c.to_vec()).collect();
    let (mtype, body) = trezor_unframe(&owned)?;
    if mtype != msg::TX_REQUEST {
        return Err(Error::VerificationFailed);
    }
    let mut out = TxRequest {
        request_type: 0,
        request_index: None,
        tx_hash: None,
        signature_index: None,
        signature: None,
        serialized_tx: None,
    };
    let mut saw_type = false;
    for (num, wt, val) in proto_decode(&body)? {
        match (num, wt) {
            (1, 0) => {
                let (v, _) = varint_decode(&val)?;
                out.request_type = v as u32;
                saw_type = true;
            }
            (2, 2) => {
                for (n, w, v) in proto_decode(&val)? {
                    if n == 1 && w == 0 {
                        let (idx, _) = varint_decode(&v)?;
                        out.request_index = Some(idx as u32);
                    } else if n == 2 && w == 2 {
                        out.tx_hash = Some(v);
                    }
                }
            }
            (3, 2) => {
                for (n, w, v) in proto_decode(&val)? {
                    match (n, w) {
                        (1, 0) => {
                            let (idx, _) = varint_decode(&v)?;
                            out.signature_index = Some(idx as u32);
                        }
                        (2, 2) => out.signature = Some(v),
                        (3, 2) => out.serialized_tx = Some(v),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    if !saw_type {
        return Err(Error::InvalidEncoding);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// 64-byte wire reports for real HID/UDP transports.
//
// `trezor_frame` emits 63-byte codec units starting with the full `?##`
// magic; real transports move 64-byte reports (`?` + 63 stream bytes, see
// firmware `codec_v1.py`: initial `[?][#][#][type2][len4][55 data]`,
// continuation `[?][63 data]`). The mapping is a pure re-chunking:
// reports carry `?` + slices of `frame[1..]` — the frame's leading `?` IS
// the first report's marker. Scripted/mock transports keep using the
// 63-byte codec units directly; anything touching USB/UDP uses these.
// ---------------------------------------------------------------------------

/// Encode a concatenated frame (`trezor_frame(..).concat()`) into 64-byte
/// wire reports (each starting with `?`, zero-padded tail).
pub fn trezor_reports_encode(frame_concat: &[u8]) -> Result<Vec<Vec<u8>>> {
    if frame_concat.first().copied() != Some(b'?') {
        return Err(Error::InvalidEncoding);
    }
    let stream = &frame_concat[1..];
    if stream.is_empty() {
        return Err(Error::InvalidLength);
    }
    let mut out = Vec::new();
    for piece in stream.chunks(63) {
        let mut report = Vec::with_capacity(64);
        report.push(b'?');
        report.extend_from_slice(piece);
        while report.len() < 64 {
            report.push(0);
        }
        out.push(report);
    }
    Ok(out)
}

/// Inverse of [`trezor_reports_encode`]: 64-byte `?`-led reports back to
/// `(msg_type, body)`. Reports with a bad marker or length are rejected.
pub fn trezor_reports_decode(reports: &[Vec<u8>]) -> Result<(u16, Vec<u8>)> {
    if reports.is_empty() {
        return Err(Error::InvalidLength);
    }
    let mut stream = Vec::new();
    for r in reports {
        if r.len() != 64 || r[0] != b'?' {
            return Err(Error::InvalidEncoding);
        }
        stream.extend_from_slice(&r[1..]);
    }
    let mut frame = Vec::with_capacity(1 + stream.len());
    frame.push(b'?');
    frame.extend_from_slice(&stream);
    let chunks: Vec<Vec<u8>> = frame.chunks(63).map(|c| c.to_vec()).collect();
    trezor_unframe(&chunks)
}

// ---------------------------------------------------------------------------
// Identity signing (`SignIdentity` → `SignedIdentity`, SLIP-13).
//
// Field numbers from `messages-crypto.proto` (verified in-tree):
// `IdentityType{proto = 1, user = 2, host = 3, port = 4, path = 5,
// index = 6}`, `SignIdentity{identity = 1, challenge_hidden = 2,
// challenge_visual = 3, ecdsa_curve_name = 4}`,
// `SignedIdentity{address = 1, public_key = 2, signature = 3}`.
//
// This is the legitimate "raw signing" flow: SSH/GPG agents and
// challenge-response logins sign a challenge tied to an identity — there is
// no amount or recipient, so nothing to hide from the user. It must NEVER be
// used for value transfer (the device shows only the identity + visual
// challenge, never a spend).
// ---------------------------------------------------------------------------

/// Curves the firmware accepts for identity keys (`secp256k1` default when
/// the field is omitted; `nist256p1` since fw 1.3.4).
pub mod identity_curve {
    pub const SECP256K1: &str = "secp256k1";
    pub const NIST256P1: &str = "nist256p1";
}

/// Encode `IdentityType`. Empty parts are omitted (proto3 defaults);
/// `index` is ALWAYS encoded — even 0 — matching trezorlib byte-for-byte
/// (verified live: the reference host emits field 6 with varint 0).
/// `proto` is required (it selects the derivation namespace).
pub fn identity_encode(
    proto: &str,
    user: &str,
    host: &str,
    port: &str,
    path: &str,
    index: u32,
) -> Result<Vec<u8>> {
    if proto.is_empty() || proto.len() > 256 {
        return Err(Error::InvalidEncoding);
    }
    for part in [user, host, port, path] {
        if part.len() > 256 {
            return Err(Error::InvalidEncoding);
        }
    }
    let mut nums = alloc::vec![1u32];
    let mut fields = alloc::vec![ProtoField::Bytes(proto.as_bytes().to_vec())];
    for (n, part) in [(2u32, user), (3, host), (4, port), (5, path)] {
        if !part.is_empty() {
            nums.push(n);
            fields.push(ProtoField::Bytes(part.as_bytes().to_vec()));
        }
    }
    nums.push(6);
    fields.push(ProtoField::Varint(index as u64));
    proto_encode(&nums, &fields)
}

/// Build a framed `SignIdentity` request. `identity` is a prebuilt
/// [`identity_encode`] payload; `challenge_hidden` rides into the signature
/// unseen (cap 128 B); `challenge_visual` is shown on-device (cap 128 B);
/// `curve_name`: `None` omits the field (device default `secp256k1`), or one
/// of `identity_curve::*`.
pub fn sign_identity_request(
    identity: &[u8],
    challenge_hidden: &[u8],
    challenge_visual: &str,
    curve_name: Option<&str>,
) -> Result<Vec<u8>> {
    if identity.is_empty() || identity.len() > 1024 {
        return Err(Error::InvalidEncoding);
    }
    if challenge_hidden.len() > 128 || challenge_visual.len() > 128 {
        return Err(Error::InvalidEncoding);
    }
    if let Some(c) = curve_name {
        if c != identity_curve::SECP256K1 && c != identity_curve::NIST256P1 {
            return Err(Error::InvalidEncoding);
        }
    }
    let mut nums = alloc::vec![1u32];
    let mut fields = alloc::vec![ProtoField::Bytes(identity.to_vec())];
    if !challenge_hidden.is_empty() {
        nums.push(2);
        fields.push(ProtoField::Bytes(challenge_hidden.to_vec()));
    }
    if !challenge_visual.is_empty() {
        nums.push(3);
        fields.push(ProtoField::Bytes(challenge_visual.as_bytes().to_vec()));
    }
    if let Some(c) = curve_name {
        nums.push(4);
        fields.push(ProtoField::Bytes(c.as_bytes().to_vec()));
    }
    let body = proto_encode(&nums, &fields)?;
    Ok(trezor_frame(msg::SIGN_IDENTITY, &body).concat())
}

/// One parsed `SignedIdentity` response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedIdentity {
    /// Human-readable identity address (optional on the wire).
    pub address: Option<alloc::string::String>,
    /// Identity public key (33 B compressed / 65 B uncompressed).
    pub public_key: Vec<u8>,
    /// Signature over the identity data (65 B with recovery byte for
    /// secp256k1 — verify with the message-hashing rules of SLIP-13, not raw
    /// ECDSA over the challenge).
    pub signature: Vec<u8>,
}

/// Parse a `SignedIdentity` body (deframed). A device-side refusal arrives as
/// `Failure`, not here — anything without both key and signature is an
/// encoding error.
pub fn parse_signed_identity(body: &[u8]) -> Result<SignedIdentity> {
    let mut out = SignedIdentity {
        address: None,
        public_key: Vec::new(),
        signature: Vec::new(),
    };
    for (num, wt, val) in proto_decode(body)? {
        match (num, wt) {
            (1, 2) => {
                let s = core::str::from_utf8(&val).map_err(|_| Error::InvalidEncoding)?;
                out.address = Some(s.into());
            }
            (2, 2) => out.public_key = val,
            (3, 2) => out.signature = val,
            _ => {}
        }
    }
    if out.public_key.is_empty() || out.signature.is_empty() {
        return Err(Error::InvalidEncoding);
    }
    Ok(out)
}
