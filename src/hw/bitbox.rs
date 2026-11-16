//! BitBox02 host protocol: Noise_XX handshake + protobuf HWW messages.
//!
//! Field numbers are authoritative from `bitbox02-firmware`
//! (`messages/hww.proto`, `messages/btc.proto`, `messages/common.proto`):
//! `Request{btc_pub = 8}`, `BTCPubRequest{coin = 1, keypath = 2,
//! xpub_type = 3 | script_config = 4, display = 5}`, `Response{pub = 5}`,
//! `PubResponse{pub = 1}`. BTCCoin: BTC = 0, TBTC = 1, LTC = 2, TLTC = 3,
//! RBTC = 4. XPubType: TPUB = 0, XPUB = 1, YPUB = 2, ZPUB = 3, VPUB = 4,
//! UPUB = 5 (capitals 6-9 for testnet variants).
//!
//! USB framing (OP bytes) is session business, not codec business: `'h'`
//! opens the handshake, `'H' + msg` continues it, `'n' + ciphertext` carries
//! post-handshake protobuf (see `BitBoxSession`). The flat protobuf core is
//! shared with `trezor::` (varint + length-delimited only — everything these
//! messages need; nesting = pre-encoded `Bytes`).
//!
//! v1 scope: XPUB retrieval (`xpub_type` variant) with the same envelope pattern.

use crate::error::{Error, Result};
use crate::hw::coin::CoinProfile;
use crate::hw::noise::{NoiseTransport, NoiseXX, BITBOX_NOISE_PROLOGUE};
use crate::hw::transport::Transport;
use crate::hw::trezor::{proto_decode, proto_encode, varint_decode, ProtoField};

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

/// OP bytes on the USB wire (firmware `hww/noise.rs`).
pub const OP_HANDSHAKE_INIT: u8 = b'h';
pub const OP_HANDSHAKE_CONT: u8 = b'H';
pub const OP_PAIRING_VERIFY: u8 = b'v';
pub const OP_NOISE_MSG: u8 = b'n';

/// Envelope field: `Request.btc_pub`.
pub const REQ_BTC_PUB: u32 = 8;
/// Envelope field: `Response.pub`.
pub const RESP_PUB: u32 = 5;
/// Envelope field: `Response.error` (any device-side refusal).
pub const RESP_ERROR: u32 = 2;

/// BTCCoin ids (`messages/btc.proto`).
pub mod bitbox_coin {
    pub const BTC: u32 = 0;
    pub const TBTC: u32 = 1;
    pub const LTC: u32 = 2;
    pub const TLTC: u32 = 3;
    pub const RBTC: u32 = 4;
}

/// `BTCPubRequest.XPubType` ids.
pub mod bitbox_xpub {
    pub const TPUB: u32 = 0;
    pub const XPUB: u32 = 1;
    pub const YPUB: u32 = 2;
    pub const ZPUB: u32 = 3;
    pub const VPUB: u32 = 4;
    pub const UPUB: u32 = 5;
}

/// Map a coin profile to `BTCCoin` (slip44 0 → BTC, 1 → TBTC).
pub fn bitbox_coin_for(coin: &CoinProfile) -> Result<u32> {
    match coin.slip44 {
        0 => Ok(bitbox_coin::BTC),
        1 => Ok(bitbox_coin::TBTC),
        _ => Err(Error::Unsupported),
    }
}

/// Map a BIP purpose to the natural `XPubType`
/// (44 → XPUB, 49 → YPUB, 84 → ZPUB, 86 → VPUB).
pub fn bitbox_xpub_type_for(purpose: u32) -> Result<u32> {
    match purpose {
        44 => Ok(bitbox_xpub::XPUB),
        49 => Ok(bitbox_xpub::YPUB),
        84 => Ok(bitbox_xpub::ZPUB),
        86 => Ok(bitbox_xpub::VPUB),
        _ => Err(Error::Unsupported),
    }
}

/// Build a `Request{btc_pub}` frame (UNENCRYPTED plaintext — encrypt via the
/// finished [`NoiseTransportAdapter`] or [`BitBoxSession`]).
/// `xpub_type`: one of `bitbox_xpub::*` (≤ 9); `display` shows the xpub on
/// the device screen for user verification.
pub fn bitbox_btc_pub_request(
    coin: u32,
    path: &[u32],
    xpub_type: u32,
    display: bool,
) -> Result<Vec<u8>> {
    if coin > bitbox_coin::RBTC || xpub_type > 9 {
        return Err(Error::InvalidEncoding);
    }
    if path.is_empty() || path.len() > 10 {
        return Err(Error::InvalidPath);
    }
    let mut nums = alloc::vec![1u32];
    let mut fields = alloc::vec![ProtoField::Varint(coin as u64)];
    for i in path {
        nums.push(2);
        fields.push(ProtoField::Varint(*i as u64));
    }
    nums.push(3);
    fields.push(ProtoField::Varint(xpub_type as u64));
    nums.push(5);
    fields.push(ProtoField::Varint(display as u64));
    let inner = proto_encode(&nums, &fields)?;
    proto_encode(&[REQ_BTC_PUB], &[ProtoField::Bytes(inner)])
}

/// Parse a `Response` frame into the xpub string.
/// A device-side `Error` response surfaces as `VerificationFailed`
/// (user-reject and device-refusal share this bucket, as with
/// `parse_sign_response`); malformed bytes are `Invalid*`.
pub fn bitbox_pub_parse(resp: &[u8]) -> Result<String> {
    let mut xpub = None;
    for (num, wt, val) in proto_decode(resp)? {
        match (num, wt) {
            (RESP_ERROR, _) => return Err(Error::VerificationFailed),
            (RESP_PUB, 2) => {
                let inner = proto_decode(&val)?;
                for (n, w, v) in inner {
                    if n == 1 && w == 2 {
                        let s = core::str::from_utf8(&v).map_err(|_| Error::InvalidEncoding)?;
                        xpub = Some(s.into());
                    }
                }
            }
            _ => {}
        }
    }
    xpub.ok_or(Error::InvalidEncoding)
}

/// Decode a `u32` varint field value (helper for tests/app code).
pub fn bitbox_varint_field(body: &[u8], number: u32) -> Result<u64> {
    for (num, wt, val) in proto_decode(body)? {
        if num == number && wt == 0 {
            let (v, _) = varint_decode(&val)?;
            return Ok(v);
        }
    }
    Err(Error::InvalidEncoding)
}

/// A paired BitBox02 session over any [`Transport`]: Noise_XX handshake
/// (host is initiator; caller supplies static + fresh ephemeral keys per
/// the crate's randomness policy) then encrypted HWW exchanges.
///
/// TRANSPORT CONTRACT (proven live against firmware v9.28.0): `T::exchange`
/// speaks the post-HWW-framing OP layer. The backend (external HID/WebHID, never
/// this crate) owns U2F-HID reports PLUS the HWW arbitration layer per
/// message: send `[REQ_NEW=0x00] + op_msg`, poll `[REQ_RETRY]` while the
/// device answers `RSP_NOT_READY` (sleep app-side, ~200ms), back off on
/// `RSP_BUSY`, fail on `RSP_NACK`, and hand `exchange` the `RSP_ACK` payload.
/// This session then sends OP messages (`[b'h']`, `[b'H'] + msg`, `[b'n'] +
/// ciphertext`, `[b'v']`) and requires every reply to start with
/// `OP_STATUS_SUCCESS (0x00)` — any other status fails the exchange.
/// `FakeDevice` in `tests/hw_bitbox.rs` emulates exactly this post-framing
/// layer, not raw USB.
/// The OP byte stays OUTSIDE the encryption (firmware splits it before
/// decrypting, so this does not reuse [`NoiseTransportAdapter`], which
/// encrypts its whole input). U2F-HID reports + HWW arbitration stay in the
/// backend `Transport`, as everywhere in `hw`.
pub struct BitBoxSession<T: Transport> {
    inner: T,
    noise: NoiseTransport,
    pairing_needed: bool,
}

/// OP status on the wire (firmware `hww.rs::process_packet`): every OP
/// reply is `[0x00] + payload`; any other first byte is a device-side
/// refusal. Strips and returns the payload.
fn take_op_payload(reply: Vec<u8>) -> Result<Vec<u8>> {
    match reply.split_first() {
        Some((0, rest)) => Ok(rest.to_vec()),
        Some(_) => Err(Error::VerificationFailed), // device refused
        None => Err(Error::InvalidLength),
    }
}

impl<T: Transport> BitBoxSession<T> {
    /// Run the 3-message handshake as initiator. Returns the session plus
    /// whether the device wants pairing-code verification
    /// (`handshake_hash()` feeds the app's pairing-code display; the actual
    /// `'v'` verify tap is app UI). Noise profile: protocol-name prologue
    /// (firmware + host mix exactly `Noise_XX_25519_ChaChaPoly_SHA256`).
    pub fn establish(mut t: T, s_priv: [u8; 32], e_priv: [u8; 32]) -> Result<Self> {
        let mut hs = NoiseXX::new_initiator_with_prologue(s_priv, e_priv, BITBOX_NOISE_PROLOGUE);
        // Every OP reply is `[OP_STATUS_SUCCESS] + payload` (firmware
        // `hww.rs::process_packet`); anything else fails the exchange.
        let probe = vec![OP_HANDSHAKE_INIT];
        let init_reply = take_op_payload(t.exchange(&probe)?)?;
        if !init_reply.is_empty() {
            return Err(Error::InvalidEncoding);
        }
        // `H(message)` framing helper: prepend OP, exchange, strip status.
        let m1 = hs.write_message_1(b"")?;
        let mut init = Vec::with_capacity(1 + m1.len());
        init.push(OP_HANDSHAKE_CONT);
        init.extend_from_slice(&m1);
        let m2 = take_op_payload(t.exchange(&init)?)?;
        let _ = hs.read_message_2(&m2)?;
        let m3 = hs.write_message_3(b"")?;
        let mut third = Vec::with_capacity(1 + m3.len());
        third.push(OP_HANDSHAKE_CONT);
        third.extend_from_slice(&m3);
        let done = take_op_payload(t.exchange(&third)?)?;
        // Single `0`/`1` payload byte: pairing already verified / needed.
        if done.len() != 1 || done[0] > 1 {
            return Err(Error::InvalidEncoding);
        }
        let pairing_needed = done[0] == 1;
        let noise = hs.split()?;
        Ok(Self {
            inner: t,
            noise,
            pairing_needed,
        })
    }

    /// Whether the device asks for pairing-code verification (display
    /// `handshake_hash()` and run the `'v'` tap in app UI).
    pub fn pairing_needed(&self) -> bool {
        self.pairing_needed
    }

    /// Pairing-code source: base32-format per the BitBox host convention
    /// (app-side; this crate only supplies the bytes).
    pub fn handshake_hash(&self) -> [u8; 32] {
        self.noise.handshake_hash()
    }

    /// One encrypted exchange: `[b'n'] + encrypt(plaintext)` out, then the
    /// reply's OP status is checked and its ciphertext payload decrypted.
    /// The OP byte intentionally stays outside the encryption (firmware
    /// splits it before decrypting).
    pub fn exchange_encrypted(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let enc = self.noise.encrypt(plaintext)?;
        let mut framed = Vec::with_capacity(1 + enc.len());
        framed.push(OP_NOISE_MSG);
        framed.extend_from_slice(&enc);
        let reply = self.inner.exchange(&framed)?;
        self.noise.decrypt(&take_op_payload(reply)?)
    }

    /// Full XPUB retrieval: build → encrypt → exchange → decrypt → parse.
    pub fn execute_btc_pub(
        &mut self,
        coin: &CoinProfile,
        path: &[u32],
        xpub_type: u32,
        display: bool,
    ) -> Result<String> {
        let req = bitbox_btc_pub_request(bitbox_coin_for(coin)?, path, xpub_type, display)?;
        let reply = self.exchange_encrypted(&req)?;
        bitbox_pub_parse(&reply)
    }
}

// ---------------------------------------------------------------------------
// Host-side session slot for transports the crate does not own (external FFI,
// WASM): the same initiator handshake + transport crypto as
// [`BitBoxSession`], but state lives in a module-global single slot and I/O
// stays entirely caller-side (the caller moves m1/m2/m3/ciphertexts over
// its own bearer with OP framing per the docs above).
//
// Safety contract (enforced, fail-closed): handshake calls (`m1`/`m2`/`m3`)
// spend the session on ANY error — retrying crypto with half-mixed state
// would derive wrong keys silently, and an m1 is unrecoverable once
// computed. Post-handshake calls never destroy state. At most one session
// is open; opening while busy fails instead of clobbering.
// ---------------------------------------------------------------------------

enum SlotState {
    Empty,
    Hs(NoiseXX),
    Ready(NoiseTransport),
}

static SLOT: AtomicUsize = AtomicUsize::new(0);

fn take_slot() -> alloc::boxed::Box<SlotState> {
    let raw = SLOT.swap(0, Ordering::AcqRel);
    if raw == 0 {
        alloc::boxed::Box::new(SlotState::Empty)
    } else {
        // SAFETY: only ever stored from a live Box (see put_slot);
        // exclusive access follows from the swap above.
        unsafe { alloc::boxed::Box::from_raw(raw as *mut SlotState) }
    }
}

fn put_slot(slot: alloc::boxed::Box<SlotState>) {
    let prev = SLOT.swap(alloc::boxed::Box::into_raw(slot) as usize, Ordering::AcqRel);
    debug_assert_eq!(prev, 0);
    if prev != 0 {
        // Defensive: never leak on unexpected reentry.
        unsafe {
            drop(alloc::boxed::Box::from_raw(prev as *mut SlotState));
        }
    }
}

/// Open the initiator session with the BitBox Noise profile
/// (protocol-name prologue). Fails if one is already open.
pub fn session_open(s_priv: [u8; 32], e_priv: [u8; 32]) -> Result<()> {
    let slot = take_slot();
    if !matches!(*slot, SlotState::Empty) {
        put_slot(slot);
        return Err(Error::InvalidEncoding); // busy
    }
    put_slot(alloc::boxed::Box::new(SlotState::Hs(
        NoiseXX::new_initiator_with_prologue(s_priv, e_priv, BITBOX_NOISE_PROLOGUE),
    )));
    Ok(())
}

/// Write handshake message 1 (32 B).
pub fn session_m1() -> Result<Vec<u8>> {
    let mut slot = take_slot();
    match slot.as_mut() {
        SlotState::Hs(hs) => match hs.write_message_1(b"") {
            Ok(m) => {
                put_slot(slot);
                Ok(m)
            }
            Err(e) => Err(e), // spent: m1 unrecoverable, reopen
        },
        _ => {
            put_slot(slot);
            Err(Error::InvalidEncoding)
        }
    }
}

/// Ingest handshake message 2 (96 B).
pub fn session_m2(m2: &[u8]) -> Result<()> {
    let mut slot = take_slot();
    match slot.as_mut() {
        SlotState::Hs(hs) => match hs.read_message_2(m2) {
            Ok(_) => {
                put_slot(slot);
                Ok(())
            }
            Err(e) => Err(e), // spent: half-mixed state dropped
        },
        _ => {
            put_slot(slot);
            Err(Error::InvalidEncoding)
        }
    }
}

/// Write handshake message 3 (64 B).
pub fn session_m3() -> Result<Vec<u8>> {
    let mut slot = take_slot();
    match slot.as_mut() {
        SlotState::Hs(hs) => match hs.write_message_3(b"") {
            Ok(m) => {
                put_slot(slot);
                Ok(m)
            }
            Err(e) => Err(e), // spent
        },
        _ => {
            put_slot(slot);
            Err(Error::InvalidEncoding)
        }
    }
}

/// Split into transport keys (Hs → Ready).
pub fn session_split() -> Result<()> {
    let mut slot = take_slot();
    let taken = core::mem::replace(slot.as_mut(), SlotState::Empty);
    match taken {
        SlotState::Hs(hs) => match hs.split() {
            Ok(t) => {
                *slot = SlotState::Ready(t);
                put_slot(slot);
                Ok(())
            }
            Err(e) => Err(e), // spent
        },
        _ => {
            put_slot(slot);
            Err(Error::InvalidEncoding)
        }
    }
}

/// Encrypt one post-handshake message. Never destroys state on error.
pub fn session_encrypt(plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut slot = take_slot();
    let rc = match slot.as_mut() {
        SlotState::Ready(t) => t.encrypt(plaintext),
        _ => Err(Error::InvalidEncoding),
    };
    put_slot(slot);
    rc
}

/// Decrypt one post-handshake message. Never destroys state on error.
pub fn session_decrypt(ciphertext: &[u8]) -> Result<Vec<u8>> {
    let mut slot = take_slot();
    let rc = match slot.as_mut() {
        SlotState::Ready(t) => t.decrypt(ciphertext),
        _ => Err(Error::InvalidEncoding),
    };
    put_slot(slot);
    rc
}

/// Handshake hash (pairing-code source). Needs a split session.
pub fn session_hash() -> Result<[u8; 32]> {
    let mut slot = take_slot();
    let rc = match slot.as_mut() {
        SlotState::Ready(t) => Ok(t.handshake_hash()),
        _ => Err(Error::InvalidEncoding),
    };
    put_slot(slot);
    rc
}

/// Close + wipe. Idempotent.
pub fn session_free() {
    let _spent = take_slot();
    put_slot(alloc::boxed::Box::new(SlotState::Empty));
}

// ---------------------------------------------------------------------------
// BTC transaction signing (`BTCSignInit` → `BTCSignNext` loop).
//
// Authoritative numbers from `messages/{hww,btc}.proto`:
// `Request{btc_sign_init = 9, btc_sign_input = 10, btc_sign_output = 11,
// btc = 25: BTCRequest{prevtx_init = 3, prevtx_input = 4,
// prevtx_output = 5}}`,
// `Response{btc_sign_next = 6}` (direct; the whole simple single-sig flow)
// or `Response{btc = 13: BTCResponse{sign_next = 3}}` (wrapped; prev-tx
// passes),
// `BTCSignNextResponse{type = 1, index = 2, has_signature = 3,
// signature = 4 (64 B R||S, NOT DER), prev_index = 5}`,
// `BTCSignNextResponse.Type{INPUT = 0, OUTPUT = 1, DONE = 2,
// PREVTX_INIT = 3, PREVTX_INPUT = 4, PREVTX_OUTPUT = 5, ...}`,
// `BTCSignInitRequest{coin = 1, script_configs = 2, version = 4,
// num_inputs = 5, num_outputs = 6, locktime = 7, format_unit = 8}`,
// `BTCScriptConfigWithKeypath{script_config = 2, keypath = 3}`,
// `BTCScriptConfig{simple_type = 1}` (SimpleType: P2WPKH_P2SH = 0,
// P2WPKH = 1, P2TR = 2),
// `BTCSignInputRequest{prevOutHash = 1, prevOutIndex = 2, prevOutValue = 3,
// sequence = 4, keypath = 6, script_config_index = 7}` (NO field 5;
// `host_nonce_commitment` omitted → deterministic S2C fallback, documented),
// `BTCSignOutputRequest{ours = 1, type = 2, value = 3, payload = 4,
// keypath = 5, script_config_index = 6}` (BTCOutputType: P2PKH = 1,
// P2WPKH = 3, ...).
//
// The APP drives the loop (same shape as Trezor `SignTx` docs in
// `wallet.rs`): init → answer INPUT/OUTPUT with input/output acks (PREVTX_*
// with prev-tx data selected by `prev_index`) → DONE carries the 64-byte
// signatures (one per input; `has_signature` + `signature`, `index` = which).
// Anti-klepto host-nonce rounds are NOT implemented (omitted field → the
// device falls back to deterministic signatures; noted in
// `BTCSignInputRequest` docs upstream).
// ---------------------------------------------------------------------------

/// `BTCSignNextResponse.Type` ids.
pub mod bitbox_sign_type {
    pub const INPUT: u32 = 0;
    pub const OUTPUT: u32 = 1;
    pub const DONE: u32 = 2;
    pub const PREVTX_INIT: u32 = 3;
    pub const PREVTX_INPUT: u32 = 4;
    pub const PREVTX_OUTPUT: u32 = 5;
}

/// `BTCOutputType` ids (for external outputs).
pub mod bitbox_output_type {
    pub const P2PKH: u32 = 1;
    pub const P2SH: u32 = 2;
    pub const P2WPKH: u32 = 3;
    pub const P2WSH: u32 = 4;
    pub const P2TR: u32 = 5;
}

/// `BTCScriptConfig.SimpleType` ids.
pub mod bitbox_simple_type {
    pub const P2WPKH_P2SH: u32 = 0;
    pub const P2WPKH: u32 = 1;
    pub const P2TR: u32 = 2;
}

/// Envelope fields: `Request.btc_sign_{init,input,output}`.
pub const REQ_BTC_SIGN_INIT: u32 = 9;
pub const REQ_BTC_SIGN_INPUT: u32 = 10;
pub const REQ_BTC_SIGN_OUTPUT: u32 = 11;
/// Envelope field: `Request.btc` (prev-tx streaming + misc BTC calls).
pub const REQ_BTC: u32 = 25;
/// `BTCRequest` fields for prev-tx streaming.
pub const BTCREQ_PREVTX_INIT: u32 = 3;
pub const BTCREQ_PREVTX_INPUT: u32 = 4;
pub const BTCREQ_PREVTX_OUTPUT: u32 = 5;
/// Envelope field: `Response.btc_sign_next` (DIRECT first reply and every
/// reply while `wrap` is false — the whole simple single-sig flow).
pub const RESP_BTC_SIGN_NEXT: u32 = 6;
/// Envelope fields: `Response.btc` → `BTCResponse.sign_next` (WRAPPED
/// replies, e.g. prev-tx streaming and later passes).
pub const RESP_BTC: u32 = 13;
pub const BTCRESP_SIGN_NEXT: u32 = 3;

/// One parsed `BTCSignNextResponse`: what the device wants next.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BitBoxSignNext {
    /// One of `bitbox_sign_type::*`.
    pub request_type: u32,
    /// Which input/output (or prev-tx record) it wants.
    pub index: Option<u32>,
    /// `prev_index` for PREVTX_INPUT/PREVTX_OUTPUT (which prev-tx record).
    pub prev_index: Option<u32>,
    /// Present with `has_signature` on DONE: 64-byte R||S for `index`-th input.
    pub signature: Option<Vec<u8>>,
}

/// Build `Request{btc_sign_init}` (UNENCRYPTED — encrypt via the session).
/// `simple_type`: one of `bitbox_simple_type::*` for the single script
/// config at `path`; `version` must be 1 or 2.
pub fn bitbox_sign_init_request(
    coin: u32,
    path: &[u32],
    simple_type: u32,
    version: u32,
    num_inputs: u32,
    num_outputs: u32,
    locktime: u32,
) -> Result<Vec<u8>> {
    if coin > bitbox_coin::RBTC || simple_type > bitbox_simple_type::P2TR {
        return Err(Error::InvalidEncoding);
    }
    if path.is_empty() || path.len() > 10 {
        return Err(Error::InvalidPath);
    }
    if version == 0
        || version > 2
        || num_inputs == 0
        || num_inputs > 256
        || num_outputs == 0
        || num_outputs > 256
    {
        return Err(Error::InvalidLength);
    }
    // BTCScriptConfig{simple_type = 1}
    let script_config = proto_encode(&[1], &[ProtoField::Varint(simple_type as u64)])?;
    // BTCScriptConfigWithKeypath{script_config = 2, keypath = 3}
    let mut sc_nums = alloc::vec![2u32];
    let mut sc_fields = alloc::vec![ProtoField::Bytes(script_config)];
    for i in path {
        sc_nums.push(3);
        sc_fields.push(ProtoField::Varint(*i as u64));
    }
    let sc = proto_encode(&sc_nums, &sc_fields)?;
    // BTCSignInitRequest{coin = 1, script_configs = 2, version = 4,
    // num_inputs = 5, num_outputs = 6, locktime = 7}
    let inner = proto_encode(
        &[1, 2, 4, 5, 6, 7],
        &[
            ProtoField::Varint(coin as u64),
            ProtoField::Bytes(sc),
            ProtoField::Varint(version as u64),
            ProtoField::Varint(num_inputs as u64),
            ProtoField::Varint(num_outputs as u64),
            ProtoField::Varint(locktime as u64),
        ],
    )?;
    proto_encode(&[REQ_BTC_SIGN_INIT], &[ProtoField::Bytes(inner)])
}

/// Parse a `BTCSignNextResponse` into [`BitBoxSignNext`]. Accepts BOTH
/// wire envelopes (proven live against firmware v9.28.0): the DIRECT
/// `Response{btc_sign_next = 6}` (first reply, and every reply while the
/// device's `wrap` flag is false — the entire simple single-sig flow) and
/// the WRAPPED `Response{btc = 13: BTCResponse{sign_next = 3}}`.
/// Proto3 omits zero-valued fields, so an EMPTY sign_next is a real
/// `INPUT` request with defaults (`type = INPUT`, no index) — only a
/// missing envelope is an error.
/// A device `Error` envelope → `VerificationFailed`, like `bitbox_pub_parse`.
pub fn bitbox_sign_next_parse(resp: &[u8]) -> Result<BitBoxSignNext> {
    fn parse_sign_next(val: &[u8], out: &mut BitBoxSignNext) -> Result<()> {
        for (n3, w3, v3) in proto_decode(val)? {
            match (n3, w3) {
                (1, 0) => {
                    let (v, _) = varint_decode(&v3)?;
                    out.request_type = v as u32;
                }
                (2, 0) => {
                    let (v, _) = varint_decode(&v3)?;
                    out.index = Some(v as u32);
                }
                (4, 2) => out.signature = Some(v3),
                (5, 0) => {
                    let (v, _) = varint_decode(&v3)?;
                    out.prev_index = Some(v as u32);
                }
                _ => {}
            }
        }
        Ok(())
    }
    let mut out = BitBoxSignNext {
        request_type: 0, // INPUT is the proto3 default, like the device sends
        index: None,
        prev_index: None,
        signature: None,
    };
    let mut saw_response = false;
    for (num, wt, val) in proto_decode(resp)? {
        if num == RESP_ERROR {
            return Err(Error::VerificationFailed);
        }
        if num == RESP_BTC_SIGN_NEXT && wt == 2 {
            parse_sign_next(&val, &mut out)?;
            saw_response = true;
        } else if num == RESP_BTC && wt == 2 {
            for (n2, w2, v2) in proto_decode(&val)? {
                if n2 == BTCRESP_SIGN_NEXT && w2 == 2 {
                    parse_sign_next(&v2, &mut out)?;
                    saw_response = true;
                }
            }
        }
    }
    if !saw_response {
        return Err(Error::InvalidEncoding);
    }
    Ok(out)
}

/// One `BTCSignInput`/`BTCSignOutput` payload the host sends per `sign_next`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BitBoxTxChunk {
    /// Answer to INPUT: outpoint + value + sequence + our keypath.
    Input {
        prev_hash: [u8; 32],
        prev_index: u32,
        amount: u64,
        sequence: u32,
        path: Vec<u32>,
        script_config_index: u32,
    },
    /// Answer to OUTPUT (external): type + value + payload hash.
    OutputExternal {
        output_type: u32,
        amount: u64,
        payload: Vec<u8>,
    },
    /// Answer to OUTPUT (change back to our path).
    OutputChange {
        path: Vec<u32>,
        amount: u64,
        script_config_index: u32,
    },
    /// Answer to PREVTX_INIT: the previous transaction's header.
    PrevtxInit {
        version: u32,
        num_inputs: u32,
        num_outputs: u32,
        locktime: u32,
    },
    /// Answer to PREVTX_INPUT: one input of the previous transaction.
    PrevtxInput {
        prev_hash: [u8; 32],
        prev_index: u32,
        script_sig: Vec<u8>,
        sequence: u32,
    },
    /// Answer to PREVTX_OUTPUT: one output of the previous transaction.
    PrevtxOutput { amount: u64, script: Vec<u8> },
}

/// Build one `Request{btc_sign_input | btc_sign_output}` frame (UNENCRYPTED).
pub fn bitbox_sign_ack_bytes(chunk: &BitBoxTxChunk) -> Result<Vec<u8>> {
    let (env_field, inner) = match chunk {
        BitBoxTxChunk::Input {
            prev_hash,
            prev_index,
            amount,
            sequence,
            path,
            script_config_index,
        } => {
            if path.is_empty() || path.len() > 10 {
                return Err(Error::InvalidPath);
            }
            if *sequence < 0xFFFF_FFFD {
                return Err(Error::InvalidEncoding);
            }
            let mut nums = alloc::vec![1u32, 2, 3, 4];
            let mut fields = alloc::vec![
                ProtoField::Bytes(prev_hash.to_vec()),
                ProtoField::Varint(*prev_index as u64),
                ProtoField::Varint(*amount),
                ProtoField::Varint(*sequence as u64),
            ];
            for i in path {
                nums.push(6);
                fields.push(ProtoField::Varint(*i as u64));
            }
            nums.push(7);
            fields.push(ProtoField::Varint(*script_config_index as u64));
            (REQ_BTC_SIGN_INPUT, proto_encode(&nums, &fields)?)
        }
        BitBoxTxChunk::OutputExternal {
            output_type,
            amount,
            payload,
        } => {
            if *output_type == 0 || *output_type > 6 || payload.is_empty() || payload.len() > 64 {
                return Err(Error::InvalidEncoding);
            }
            let inner = proto_encode(
                &[1, 2, 3, 4],
                &[
                    ProtoField::Varint(0), // ours = false
                    ProtoField::Varint(*output_type as u64),
                    ProtoField::Varint(*amount),
                    ProtoField::Bytes(payload.clone()),
                ],
            )?;
            (REQ_BTC_SIGN_OUTPUT, inner)
        }
        BitBoxTxChunk::OutputChange {
            path,
            amount,
            script_config_index,
        } => {
            if path.is_empty() || path.len() > 10 {
                return Err(Error::InvalidPath);
            }
            // ours = 1, value = 3, keypath = 5 (repeated), script_config = 6
            let mut cnums = alloc::vec![1u32, 3];
            let mut cfields = alloc::vec![ProtoField::Varint(1), ProtoField::Varint(*amount)];
            for i in path {
                cnums.push(5);
                cfields.push(ProtoField::Varint(*i as u64));
            }
            cnums.push(6);
            cfields.push(ProtoField::Varint(*script_config_index as u64));
            (REQ_BTC_SIGN_OUTPUT, proto_encode(&cnums, &cfields)?)
        }
        BitBoxTxChunk::PrevtxInit {
            version,
            num_inputs,
            num_outputs,
            locktime,
        } => {
            if *version == 0 || *version > 2 || *num_inputs == 0 || *num_outputs == 0 {
                return Err(Error::InvalidLength);
            }
            let inner = proto_encode(
                &[1, 2, 3, 4],
                &[
                    ProtoField::Varint(*version as u64),
                    ProtoField::Varint(*num_inputs as u64),
                    ProtoField::Varint(*num_outputs as u64),
                    ProtoField::Varint(*locktime as u64),
                ],
            )?;
            let btc = proto_encode(&[BTCREQ_PREVTX_INIT], &[ProtoField::Bytes(inner)])?;
            (REQ_BTC, btc)
        }
        BitBoxTxChunk::PrevtxInput {
            prev_hash,
            prev_index,
            script_sig,
            sequence,
        } => {
            if script_sig.len() > 10000 {
                return Err(Error::InvalidLength);
            }
            let inner = proto_encode(
                &[1, 2, 3, 4],
                &[
                    ProtoField::Bytes(prev_hash.to_vec()),
                    ProtoField::Varint(*prev_index as u64),
                    ProtoField::Bytes(script_sig.clone()),
                    ProtoField::Varint(*sequence as u64),
                ],
            )?;
            let btc = proto_encode(&[BTCREQ_PREVTX_INPUT], &[ProtoField::Bytes(inner)])?;
            (REQ_BTC, btc)
        }
        BitBoxTxChunk::PrevtxOutput { amount, script } => {
            if script.is_empty() || script.len() > 10000 {
                return Err(Error::InvalidLength);
            }
            let inner = proto_encode(
                &[1, 2],
                &[
                    ProtoField::Varint(*amount),
                    ProtoField::Bytes(script.clone()),
                ],
            )?;
            let btc = proto_encode(&[BTCREQ_PREVTX_OUTPUT], &[ProtoField::Bytes(inner)])?;
            (REQ_BTC, btc)
        }
    };
    proto_encode(&[env_field], &[ProtoField::Bytes(inner)])
}
