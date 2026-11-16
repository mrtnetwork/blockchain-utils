//! ONE interaction interface for every supported device.
//!
//! ```ignore
//! let w = Wallet::new(DeviceKind::LedgerNanoSPlus);
//! let path = parse_path("m/44'/0'/0'/0/0")?;
//! let req = w.get_address_request(&CoinProfile::BITCOIN, &path)?;
//! let mut dev: MockTransport = ...;
//! let pubkey = w.execute_get_address(&mut dev, &CoinProfile::BITCOIN, &path)?;
//! // airgap:
//! let qr = w.qr_request(&CoinProfile::TEZOS_TZ1, &path)?; // show as QR
//! ```
//!
//! Ledger Nano S Plus / X / Flex / Stax share one APDU implementation;
//! Trezor One / T / Safe 3 / 5 / 7 (+ KeepKey / OneKey) share one protobuf
//! implementation; Passport / Keystone / Coldcard-QR / Jade-QR share UR.

use crate::error::{Error, Result};
use crate::hw::apdu::{Apdu, ApduResponse};
use crate::hw::coin::{CoinProfile, HwCurve};
use crate::hw::path::validate_for_coin;
use crate::hw::transport::Transport;
use crate::hw::trezor::{
    encode_bip32_fields, msg, proto_decode, proto_encode, trezor_frame, trezor_unframe,
    tx_request_parse, ProtoField, TxRequest,
};
use crate::hw::ur::{ur_decode_single, ur_encode_single};

use alloc::string::String;
use alloc::vec::Vec;

/// app-bitcoin v2 APDU constants (verified live against 2.5.1 `commands.h`).
/// CLA 0xE1 = app commands; INS 0x00 = GET_EXTENDED_PUBKEY,
/// 0x05 = GET_MASTER_FINGERPRINT; P2 carries the protocol version (1).
pub const LEDGER_BTC_CLA: u8 = 0xE1;
pub const LEDGER_INS_EXT_PUBKEY: u8 = 0x00;
pub const LEDGER_INS_FINGERPRINT: u8 = 0x05;
pub const LEDGER_BTC_PROTOCOL: u8 = 0x01;

/// `GET_MASTER_FINGERPRINT`: no input; 4-byte root fingerprint + SW.
/// No UI, no wallet needed — the cheapest live-firmware probe.
pub fn ledger_fingerprint_request() -> Vec<u8> {
    Apdu::new(
        LEDGER_BTC_CLA,
        LEDGER_INS_FINGERPRINT,
        0x00,
        LEDGER_BTC_PROTOCOL,
        Vec::new(),
    )
    .to_bytes()
}

/// Parse the fingerprint response (exactly 4 data bytes + `0x9000`).
pub fn ledger_fingerprint_parse(resp: &[u8]) -> Result<[u8; 4]> {
    let data = ApduResponse::parse(resp)?.into_data()?;
    if data.len() != 4 {
        return Err(Error::InvalidLength);
    }
    Ok([data[0], data[1], data[2], data[3]])
}

/// Every device this crate can talk to.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum DeviceKind {
    // Ledger family — same APDU.
    LedgerNanoSPlus,
    LedgerNanoX,
    LedgerFlex,
    LedgerStax,
    // Trezor family — same protobuf framing.
    TrezorOne,
    TrezorModelT,
    TrezorSafe3,
    TrezorSafe5,
    TrezorSafe7,
    KeepKey,
    OneKey,
    // Noise-channel USB.
    BitBox02,
    // Airgap QR (no `Transport`).
    Passport,
    Keystone3,
    KeystonePro,
    ColdcardQr,
    JadeQr,
}

impl DeviceKind {
    /// Short family name (`"ledger"`, `"trezor"`, `"bitbox"`, `"airgap"`).
    pub fn family(self) -> &'static str {
        match self {
            Self::LedgerNanoSPlus | Self::LedgerNanoX | Self::LedgerFlex | Self::LedgerStax => {
                "ledger"
            }
            Self::TrezorOne
            | Self::TrezorModelT
            | Self::TrezorSafe3
            | Self::TrezorSafe5
            | Self::TrezorSafe7
            | Self::KeepKey
            | Self::OneKey => "trezor",
            Self::BitBox02 => "bitbox",
            Self::Passport
            | Self::Keystone3
            | Self::KeystonePro
            | Self::ColdcardQr
            | Self::JadeQr => "airgap",
        }
    }

    /// True for QR/SD-only devices (never use `Transport`).
    pub const fn is_airgap(self) -> bool {
        matches!(
            self,
            Self::Passport | Self::Keystone3 | Self::KeystonePro | Self::ColdcardQr | Self::JadeQr
        )
    }

    /// Curves this device family can derive in v1.
    pub fn supports_curve(self, curve: HwCurve) -> bool {
        match self.family() {
            "ledger" => matches!(
                curve,
                HwCurve::Secp256k1
                    | HwCurve::Secp256k1Slip10
                    | HwCurve::Ed25519
                    | HwCurve::Nist256p1
            ),
            "trezor" => matches!(
                curve,
                HwCurve::Secp256k1 | HwCurve::Ed25519 | HwCurve::Nist256p1
            ),
            "bitbox" => matches!(curve, HwCurve::Secp256k1 | HwCurve::Ed25519),
            "airgap" => true, // host-side codec only; device signs what it supports
            _ => false,
        }
    }

    /// All device kinds (for matrix tests).
    pub const ALL: &[DeviceKind] = &[
        DeviceKind::LedgerNanoSPlus,
        DeviceKind::LedgerNanoX,
        DeviceKind::LedgerFlex,
        DeviceKind::LedgerStax,
        DeviceKind::TrezorOne,
        DeviceKind::TrezorModelT,
        DeviceKind::TrezorSafe3,
        DeviceKind::TrezorSafe5,
        DeviceKind::TrezorSafe7,
        DeviceKind::KeepKey,
        DeviceKind::OneKey,
        DeviceKind::BitBox02,
        DeviceKind::Passport,
        DeviceKind::Keystone3,
        DeviceKind::KeystonePro,
        DeviceKind::ColdcardQr,
        DeviceKind::JadeQr,
    ];
}

/// The single interface every wallet implements.
pub trait HardwareWallet {
    fn kind(&self) -> DeviceKind;

    fn supports_coin(&self, coin: &CoinProfile) -> bool {
        self.kind().supports_curve(coin.curve)
    }

    /// Build the request bytes to send via `Transport`
    /// (APDU for Ledger, `?##` frame for Trezor).
    /// Airgap wallets MUST return `Err(Unsupported)` — use `qr_request`.
    fn get_address_request(&self, coin: &CoinProfile, path: &[u32]) -> Result<Vec<u8>>;

    /// Parse the device response into raw pubkey/address bytes.
    fn parse_address_response(&self, resp: &[u8]) -> Result<Vec<u8>>;

    /// Build the QR string to display for airgap wallets.
    /// USB wallets MUST return `Err(Unsupported)`.
    fn qr_request(&self, coin: &CoinProfile, path: &[u32]) -> Result<String>;

    /// Parse a scanned QR response back into payload bytes (airgap only).
    fn qr_parse(&self, qr: &str) -> Result<Vec<u8>>;

    /// Build a "sign this payload" request (USB only).
    /// Trezor `SignMessage` takes the raw message (1..=1024 bytes). Ledger
    /// app-bitcoin v2 has no bare-hash command (`Unimplemented` — signing is
    /// the PSBT wallet-policy flow).
    /// Airgap wallets MUST return `Err(Unsupported)` — signing there is
    /// `qr_request` (display the unsigned payload) + `UrAssembler` /
    /// `qr_parse` (scan the signed payload back).
    fn sign_request(&self, coin: &CoinProfile, path: &[u32], payload: &[u8]) -> Result<Vec<u8>>;

    /// Parse the device sign response into raw signature bytes
    /// (DER for Ledger, 65-byte recoverable sig for Trezor).
    /// A device-side rejection surfaces as `VerificationFailed`
    /// (non-`0x9000` status / wrong message type), never as a transport error.
    fn parse_sign_response(&self, resp: &[u8]) -> Result<Vec<u8>>;

    /// Open a multi-round Trezor `SignTx` session (Trezor family only;
    /// Ledger uses the single-round `sign_request` template, airgap uses QR,
    /// BitBox02 is `Unimplemented`).
    ///
    /// Transport note: signing flows require an ESTABLISHED session on the
    /// device (`Initialize` + root-fingerprint `GetPublicKey` handshake;
    /// the device answers sessionless signing with "Invalid session").
    /// `GetAddress` works sessionless. Live-validated against Model T
    /// firmware (unix emulator): full legacy 1-in/1-out loop driven to the
    /// final hold, every request/response in both directions.
    ///
    /// The APP drives the loop — this crate only builds/parses:
    /// 1. send `sign_tx_start_request` → expect `TxRequest{TXMETA}`;
    /// 2. send `tx_ack_bytes(TxChunk::Meta{..})` → expect `TXINPUT{index}`;
    /// 3. send `tx_ack_bytes(TxChunk::Input{..})` per input → `TXOUTPUT{index}`;
    /// 4. send `tx_ack_bytes(TxChunk::Output*{..})` per output → `TXFINISHED`;
    /// 5. read `signature`/`serialized_tx` off the final `TxRequest`.
    ///    (`TXEXTRADATA` appears for non-segwit prev-tx streaming; answering it
    ///    needs the previous transactions and stays app-layer.)
    fn sign_tx_start_request(
        &self,
        coin: &CoinProfile,
        inputs_count: u32,
        outputs_count: u32,
    ) -> Result<Vec<u8>>;

    /// Parse one `TxRequest` frame inside a `SignTx` session (Trezor only).
    fn parse_tx_request(&self, resp: &[u8]) -> Result<TxRequest>;
}

/// Concrete wallet handle. One struct, `DeviceKind` selects the codec.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Wallet {
    kind: DeviceKind,
}

impl Wallet {
    pub const fn new(kind: DeviceKind) -> Self {
        Self { kind }
    }

    /// Convenience: build request + exchange + parse in one call (USB only).
    pub fn execute_get_address<T: Transport>(
        &self,
        t: &mut T,
        coin: &CoinProfile,
        path: &[u32],
    ) -> Result<Vec<u8>> {
        let req = self.get_address_request(coin, path)?;
        let resp = t.exchange(&req)?;
        self.parse_address_response(&resp)
    }

    /// Convenience: sign request + exchange + parse in one call (USB only).
    pub fn execute_sign<T: Transport>(
        &self,
        t: &mut T,
        coin: &CoinProfile,
        path: &[u32],
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        let req = self.sign_request(coin, path, payload)?;
        let resp = t.exchange(&req)?;
        self.parse_sign_response(&resp)
    }
}

impl HardwareWallet for Wallet {
    fn kind(&self) -> DeviceKind {
        self.kind
    }

    fn get_address_request(&self, coin: &CoinProfile, path: &[u32]) -> Result<Vec<u8>> {
        if self.kind.is_airgap() {
            return Err(Error::Unsupported);
        }
        if !self.supports_coin(coin) {
            return Err(Error::Unsupported);
        }
        validate_for_coin(path, coin)?;
        match self.kind.family() {
            "ledger" => {
                // app-bitcoin v2 `GET_EXTENDED_PUBKEY` (verified live against
                // 2.5.1: CLA 0xE1, INS 0x00, P2 = protocol v1; data =
                // `display(1) || path_len(1) || be32(path...)`). display = 0
                // (no on-device prompt); unsafe paths are then refused by
                // the app. The legacy 0xB0/0x40 template matched NO shipping
                // firmware and was removed.
                if path.len() > 10 {
                    return Err(Error::InvalidPath);
                }
                let mut data = alloc::vec![0u8, path.len() as u8];
                for i in path {
                    data.extend_from_slice(&i.to_be_bytes());
                }
                Ok(Apdu::new(
                    LEDGER_BTC_CLA,
                    LEDGER_INS_EXT_PUBKEY,
                    0x00,
                    LEDGER_BTC_PROTOCOL,
                    data,
                )
                .to_bytes())
            }
            "trezor" => {
                let (nums, fields) = encode_bip32_fields(path);
                let body = proto_encode(&nums, &fields)?;
                // single-chunk concatenation is enough for tests; HID report
                // splitting happens in the `Transport` impl.
                let chunks = trezor_frame(msg::GET_ADDRESS, &body);
                Ok(chunks.concat())
            }
            "bitbox" => Err(Error::Unimplemented), // Noise_XX handshake first
            _ => Err(Error::Unsupported),
        }
    }

    fn parse_address_response(&self, resp: &[u8]) -> Result<Vec<u8>> {
        if self.kind.is_airgap() {
            return Err(Error::Unsupported);
        }
        match self.kind.family() {
            "ledger" => {
                let r = ApduResponse::parse(resp)?.into_data()?;
                // Ledger apps prefix variable-length answers with their length
                // (`len || pubkey...`); strip when consistent, else raw.
                if !r.is_empty() && r[0] as usize + 1 == r.len() {
                    Ok(r[1..].to_vec())
                } else {
                    Ok(r)
                }
            }
            "trezor" => {
                // `resp` is concatenated 63B chunks.
                let owned: Vec<Vec<u8>> = resp.chunks(63).map(|c| c.to_vec()).collect();
                let (mtype, body) = trezor_unframe(&owned)?;
                if mtype != msg::ADDRESS {
                    return Err(Error::VerificationFailed);
                }
                let fields = proto_decode(&body)?;
                for (num, wt, val) in fields {
                    if num == 1 && wt == 2 {
                        return Ok(val);
                    }
                }
                Err(Error::InvalidEncoding)
            }
            _ => Err(Error::Unimplemented),
        }
    }

    fn qr_request(&self, coin: &CoinProfile, path: &[u32]) -> Result<String> {
        if !self.kind.is_airgap() {
            return Err(Error::Unsupported);
        }
        validate_for_coin(path, coin)?;
        // v1 payload: `slip44_be32 || path_be32...` (CBOR upgrade later).
        let mut payload = Vec::with_capacity(4 + 4 * path.len());
        payload.extend_from_slice(&coin.slip44.to_be_bytes());
        for i in path {
            payload.extend_from_slice(&i.to_be_bytes());
        }
        Ok(ur_encode_single("bytes", &payload))
    }

    fn qr_parse(&self, qr: &str) -> Result<Vec<u8>> {
        if !self.kind.is_airgap() {
            return Err(Error::Unsupported);
        }
        let msg = ur_decode_single(qr)?;
        if msg.part.is_some() {
            return Err(Error::Unsupported); // use `UrAssembler` for multipart
        }
        Ok(msg.payload)
    }

    fn sign_request(&self, coin: &CoinProfile, path: &[u32], payload: &[u8]) -> Result<Vec<u8>> {
        if self.kind.is_airgap() {
            return Err(Error::Unsupported);
        }
        if !self.supports_coin(coin) {
            return Err(Error::Unsupported);
        }
        validate_for_coin(path, coin)?;
        match self.kind.family() {
            "ledger" => {
                // app-bitcoin v2 signs PSBTs through a wallet-policy flow
                // (`REGISTER_WALLET` + `SIGN_PSBT` streaming) — there is NO
                // bare-hash sign command. The old 0xB0/0x48 template matched
                // no shipping firmware and was removed (use PSBT flow next).
                Err(Error::Unimplemented)
            }
            "trezor" => {
                // Real single-round `SignMessage`: `address_n` (field 1,
                // repeated) + `message` (field 2). `coin_name` (field 3) is
                // optional on the wire and omitted — the device default
                // applies. Multi-round `SignTx` streaming stays app-layer.
                if payload.is_empty() || payload.len() > 1024 {
                    return Err(Error::InvalidLength);
                }
                let (mut nums, mut fields) = encode_bip32_fields(path);
                nums.push(2);
                fields.push(ProtoField::Bytes(payload.to_vec()));
                let body = proto_encode(&nums, &fields)?;
                Ok(trezor_frame(msg::SIGN_MESSAGE, &body).concat())
            }
            "bitbox" => Err(Error::Unimplemented), // Noise_XX handshake first
            _ => Err(Error::Unsupported),
        }
    }

    fn parse_sign_response(&self, resp: &[u8]) -> Result<Vec<u8>> {
        if self.kind.is_airgap() {
            return Err(Error::Unsupported);
        }
        match self.kind.family() {
            "ledger" => {
                // `DER || 0x9000` on approve; any other status word
                // (e.g. `0x6985` user-reject) → `VerificationFailed`.
                ApduResponse::parse(resp)?.into_data()
            }
            "trezor" => {
                let owned: Vec<Vec<u8>> = resp.chunks(63).map(|c| c.to_vec()).collect();
                let (mtype, body) = trezor_unframe(&owned)?;
                if mtype != msg::MESSAGE_SIGNATURE {
                    return Err(Error::VerificationFailed);
                }
                let fields = proto_decode(&body)?;
                for (num, wt, val) in fields {
                    if num == 2 && wt == 2 {
                        return Ok(val);
                    }
                }
                Err(Error::InvalidEncoding)
            }
            _ => Err(Error::Unimplemented),
        }
    }

    fn sign_tx_start_request(
        &self,
        coin: &CoinProfile,
        inputs_count: u32,
        outputs_count: u32,
    ) -> Result<Vec<u8>> {
        if self.kind.family() != "trezor" {
            return Err(Error::Unsupported);
        }
        if !self.supports_coin(coin) {
            return Err(Error::Unsupported);
        }
        if inputs_count == 0 || inputs_count > 256 || outputs_count == 0 || outputs_count > 256 {
            return Err(Error::InvalidLength);
        }
        crate::hw::trezor::sign_tx_start(inputs_count, outputs_count)
    }

    fn parse_tx_request(&self, resp: &[u8]) -> Result<TxRequest> {
        if self.kind.family() != "trezor" {
            return Err(Error::Unsupported);
        }
        tx_request_parse(resp)
    }
}
