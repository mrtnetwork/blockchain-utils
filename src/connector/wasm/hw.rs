//! Hardware-wallet codec WASM exports (`BuWasm.hw*`).
//!
//! JS owns the transport (WebHID/WebUSB for Ledger/Trezor/BitBox02, camera
//! for QR). Rust only builds/parses messages — the zero-dep `hw` core.
//! Paths cross the boundary as `<u32 LE>` bytes.

#![cfg(all(feature = "wasm", feature = "hw"))]

use wasm_bindgen::prelude::*;

use crate::hw::coin::WELL_KNOWN_COINS;
use crate::hw::path::{parse_path, validate_for_coin};
use crate::hw::psbt::Psbt;
use crate::hw::ur::{ur_decode_single, ur_encode_single};
use crate::hw::wallet::{DeviceKind, HardwareWallet, Wallet};

fn dev(id: u32) -> Result<DeviceKind, JsValue> {
    DeviceKind::ALL
        .get(id as usize)
        .copied()
        .ok_or_else(|| JsValue::from_str("bad device id"))
}

fn coin(id: u32) -> Result<crate::hw::coin::CoinProfile, JsValue> {
    WELL_KNOWN_COINS
        .get(id as usize)
        .copied()
        .ok_or_else(|| JsValue::from_str("bad coin id"))
}

fn err(e: crate::error::Error) -> JsValue {
    JsValue::from_str(e.as_str())
}

fn path_from_le(raw: &[u8]) -> Result<Vec<u32>, JsValue> {
    if raw.len() % 4 != 0 {
        return Err(JsValue::from_str("path must be u32 LE bytes"));
    }
    Ok(raw
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect())
}

/// Number of known devices.
#[wasm_bindgen(js_name = hwDeviceCount)]
pub fn wasm_hw_device_count() -> u32 {
    DeviceKind::ALL.len() as u32
}

/// Number of known coins.
#[wasm_bindgen(js_name = hwCoinCount)]
pub fn wasm_hw_coin_count() -> u32 {
    WELL_KNOWN_COINS.len() as u32
}

/// True when the device supports the coin's curve.
#[wasm_bindgen(js_name = hwSupportsCoin)]
pub fn wasm_hw_supports_coin(dev_id: u32, coin_id: u32) -> Result<bool, JsValue> {
    Ok(Wallet::new(dev(dev_id)?).supports_coin(&coin(coin_id)?))
}

/// True for QR/SD-only devices.
#[wasm_bindgen(js_name = hwIsAirgap)]
pub fn wasm_hw_is_airgap(dev_id: u32) -> Result<bool, JsValue> {
    Ok(dev(dev_id)?.is_airgap())
}

/// Parse `"m/44'/0'/0'/0/0"` into `<u32 LE>` bytes.
#[wasm_bindgen(js_name = hwParsePath)]
pub fn wasm_hw_parse_path(path: &str) -> Result<Vec<u8>, JsValue> {
    let idx = parse_path(path).map_err(err)?;
    let mut out = Vec::with_capacity(4 * idx.len());
    for v in idx {
        out.extend_from_slice(&v.to_le_bytes());
    }
    Ok(out)
}

/// Validate path shape for device+coin (`path_le`: `<u32 LE>` bytes).
#[wasm_bindgen(js_name = hwValidatePath)]
pub fn wasm_hw_validate_path(dev_id: u32, coin_id: u32, path_le: &[u8]) -> Result<(), JsValue> {
    let d = dev(dev_id)?;
    let c = coin(coin_id)?;
    let path = path_from_le(path_le)?;
    if !Wallet::new(d).supports_coin(&c) {
        return Err(JsValue::from_str("unsupported operation"));
    }
    validate_for_coin(&path, &c).map_err(err)
}

/// Build USB request bytes (APDU / Trezor frame).
#[wasm_bindgen(js_name = hwGetAddressRequest)]
pub fn wasm_hw_get_address_request(
    dev_id: u32,
    coin_id: u32,
    path_le: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let d = dev(dev_id)?;
    let c = coin(coin_id)?;
    let path = path_from_le(path_le)?;
    Wallet::new(d).get_address_request(&c, &path).map_err(err)
}

/// Parse USB response into pubkey/address bytes.
#[wasm_bindgen(js_name = hwParseAddressResponse)]
pub fn wasm_hw_parse_address_response(dev_id: u32, resp: &[u8]) -> Result<Vec<u8>, JsValue> {
    Wallet::new(dev(dev_id)?)
        .parse_address_response(resp)
        .map_err(err)
}

/// Ledger v2 `GET_MASTER_FINGERPRINT` request (no input).
#[wasm_bindgen(js_name = hwLedgerFingerprint)]
pub fn wasm_hw_ledger_fingerprint() -> Vec<u8> {
    use crate::hw::wallet::ledger_fingerprint_request;
    ledger_fingerprint_request()
}

/// Parse the 4-byte fingerprint response.
#[wasm_bindgen(js_name = hwLedgerFingerprintParse)]
pub fn wasm_hw_ledger_fingerprint_parse(resp: &[u8]) -> Result<Vec<u8>, JsValue> {
    use crate::hw::wallet::ledger_fingerprint_parse;
    ledger_fingerprint_parse(resp)
        .map(|f| f.to_vec())
        .map_err(err)
}

/// Build "sign this payload" USB request bytes: Trezor `SignMessage` frame
/// from the raw message (1..=1024 bytes). Ledger errors (v2 = PSBT flow).
#[wasm_bindgen(js_name = hwSignRequest)]
pub fn wasm_hw_sign_request(
    dev_id: u32,
    coin_id: u32,
    path_le: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let d = dev(dev_id)?;
    let c = coin(coin_id)?;
    let path = path_from_le(path_le)?;
    Wallet::new(d).sign_request(&c, &path, payload).map_err(err)
}

/// Parse USB sign response into raw signature bytes.
#[wasm_bindgen(js_name = hwParseSignResponse)]
pub fn wasm_hw_parse_sign_response(dev_id: u32, resp: &[u8]) -> Result<Vec<u8>, JsValue> {
    Wallet::new(dev(dev_id)?)
        .parse_sign_response(resp)
        .map_err(err)
}

// ---------------------------------------------------------------------------
// Trezor identity signing (SLIP-13). Strings cross as UTF-8 bytes, except
// `qr`-style &str where wasm-bindgen gives us text directly.
// ---------------------------------------------------------------------------

/// Encode `IdentityType` (`curve` unused here; identity has no curve).
#[wasm_bindgen(js_name = hwIdentityEncode)]
pub fn wasm_hw_identity_encode(
    proto: &str,
    user: &str,
    host: &str,
    port: &str,
    path: &str,
    index: u32,
) -> Result<Vec<u8>, JsValue> {
    use crate::hw::trezor::identity_encode;
    identity_encode(proto, user, host, port, path, index).map_err(err)
}

/// Build a framed `SignIdentity` request (`curve`: "" = omit, else a
/// `identity_curve::*` name).
#[wasm_bindgen(js_name = hwSignIdentityRequest)]
pub fn wasm_hw_sign_identity_request(
    identity: &[u8],
    hidden: &[u8],
    visual: &str,
    curve: &str,
) -> Result<Vec<u8>, JsValue> {
    use crate::hw::trezor::sign_identity_request;
    let curve_name = match curve {
        "" => None,
        "secp256k1" => Some("secp256k1"),
        "nist256p1" => Some("nist256p1"),
        _ => return Err(JsValue::from_str("unknown curve name")),
    };
    sign_identity_request(identity, hidden, visual, curve_name).map_err(err)
}

/// `SignedIdentity.address` (absent → error, never empty string).
#[wasm_bindgen(js_name = hwSignedIdentityAddress)]
pub fn wasm_hw_signed_identity_address(resp: &[u8]) -> Result<String, JsValue> {
    use crate::hw::trezor::parse_signed_identity;
    parse_signed_identity(resp)
        .map_err(err)?
        .address
        .ok_or_else(|| JsValue::from_str("no address in SignedIdentity"))
}

/// `SignedIdentity.public_key` bytes.
#[wasm_bindgen(js_name = hwSignedIdentityPubkey)]
pub fn wasm_hw_signed_identity_pubkey(resp: &[u8]) -> Result<Vec<u8>, JsValue> {
    use crate::hw::trezor::parse_signed_identity;
    parse_signed_identity(resp)
        .map(|r| r.public_key)
        .map_err(err)
}

/// `SignedIdentity.signature` bytes.
#[wasm_bindgen(js_name = hwSignedIdentitySignature)]
pub fn wasm_hw_signed_identity_signature(resp: &[u8]) -> Result<Vec<u8>, JsValue> {
    use crate::hw::trezor::parse_signed_identity;
    parse_signed_identity(resp)
        .map(|r| r.signature)
        .map_err(err)
}

/// Build airgap QR string (`ur:bytes/...`).
#[wasm_bindgen(js_name = hwQrRequest)]
pub fn wasm_hw_qr_request(dev_id: u32, coin_id: u32, path_le: &[u8]) -> Result<String, JsValue> {
    let d = dev(dev_id)?;
    let c = coin(coin_id)?;
    let path = path_from_le(path_le)?;
    Wallet::new(d).qr_request(&c, &path).map_err(err)
}

/// Parse scanned single-part QR into payload bytes.
#[wasm_bindgen(js_name = hwQrParse)]
pub fn wasm_hw_qr_parse(dev_id: u32, qr: &str) -> Result<Vec<u8>, JsValue> {
    Wallet::new(dev(dev_id)?).qr_parse(qr).map_err(err)
}

/// 8 bytes: `input_count LE u32 || output_count LE u32` for a PSBT.
#[wasm_bindgen(js_name = hwPsbtCounts)]
pub fn wasm_hw_psbt_counts(raw: &[u8]) -> Result<Vec<u8>, JsValue> {
    let p = Psbt::parse(raw).map_err(err)?;
    let mut out = Vec::with_capacity(8);
    out.extend_from_slice(&(p.input_count() as u32).to_le_bytes());
    out.extend_from_slice(&(p.output_count() as u32).to_le_bytes());
    Ok(out)
}

/// Encode `ur:<type>/<body>`.
#[wasm_bindgen(js_name = hwUrEncode)]
pub fn wasm_hw_ur_encode(ur_type: &str, payload: &[u8]) -> String {
    ur_encode_single(ur_type, payload)
}

/// Decode UR payload bytes (shard accepted; reassembly on the host side).
#[wasm_bindgen(js_name = hwUrDecodePayload)]
pub fn wasm_hw_ur_decode_payload(ur: &str) -> Result<Vec<u8>, JsValue> {
    ur_decode_single(ur).map(|m| m.payload).map_err(err)
}

/// Decode UR type string.
#[wasm_bindgen(js_name = hwUrDecodeType)]
pub fn wasm_hw_ur_decode_type(ur: &str) -> Result<String, JsValue> {
    ur_decode_single(ur).map(|m| m.ur_type).map_err(err)
}

/// Chunk `payload` into concatenated 64-byte HID reports (Ledger framing).
/// `channel` default `0x0101`, `tag` `0x05` (APDU).
#[wasm_bindgen(js_name = hwHidFrame)]
pub fn wasm_hw_hid_frame(payload: &[u8], channel: u32, tag: u32) -> Result<Vec<u8>, JsValue> {
    if channel > 0xFFFF || tag > 0xFF {
        return Err(JsValue::from_str("bad channel/tag"));
    }
    use crate::hw::hid::hid_frame;
    Ok(hid_frame(payload, channel as u16, tag as u8).concat())
}

/// Reassemble concatenated 64-byte HID reports (`reports.len()` % 64 == 0).
#[wasm_bindgen(js_name = hwHidUnframe)]
pub fn wasm_hw_hid_unframe(reports: &[u8], channel: u32, tag: u32) -> Result<Vec<u8>, JsValue> {
    if channel > 0xFFFF || tag > 0xFF {
        return Err(JsValue::from_str("bad channel/tag"));
    }
    use crate::hw::hid::{hid_unframe, HID_REPORT_LEN};
    if reports.len() % HID_REPORT_LEN != 0 {
        return Err(JsValue::from_str("reports must be 64-byte aligned"));
    }
    let frames: Vec<Vec<u8>> = reports
        .chunks_exact(HID_REPORT_LEN)
        .map(|c| c.to_vec())
        .collect();
    hid_unframe(&frames, channel as u16, tag as u8).map_err(err)
}

// ---------------------------------------------------------------------------
// Multi-round Trezor `SignTx`. Amounts cross as `(hi, lo)` u32 pairs —
// exact for all real values, no BigInt marshaling. Parse packs
// `type LE32 || index LE32` (`0xFFFFFFFF` = absent) into 8 bytes.
// ---------------------------------------------------------------------------

/// Open a `SignTx` session.
#[wasm_bindgen(js_name = hwSignTxStart)]
pub fn wasm_hw_sign_tx_start(
    dev_id: u32,
    coin_id: u32,
    inputs_count: u32,
    outputs_count: u32,
) -> Result<Vec<u8>, JsValue> {
    let d = dev(dev_id)?;
    let c = coin(coin_id)?;
    Wallet::new(d)
        .sign_tx_start_request(&c, inputs_count, outputs_count)
        .map_err(err)
}

/// Parse one `TxRequest` into 8 bytes (`type LE32 || index LE32`,
/// `0xFFFFFFFF` = absent). The caller repacks to `type<<32 | index`,
/// matching the native packed form (always non-negative).
#[wasm_bindgen(js_name = hwParseTxRequest)]
pub fn wasm_hw_parse_tx_request(dev_id: u32, resp: &[u8]) -> Result<Vec<u8>, JsValue> {
    let r = Wallet::new(dev(dev_id)?)
        .parse_tx_request(resp)
        .map_err(err)?;
    let mut out = Vec::with_capacity(8);
    out.extend_from_slice(&r.request_type.to_le_bytes());
    out.extend_from_slice(&r.request_index.unwrap_or(0xFFFF_FFFF).to_le_bytes());
    Ok(out)
}

/// `TXFINISHED` signature bytes.
#[wasm_bindgen(js_name = hwTxRequestSignature)]
pub fn wasm_hw_tx_request_signature(dev_id: u32, resp: &[u8]) -> Result<Vec<u8>, JsValue> {
    Wallet::new(dev(dev_id)?)
        .parse_tx_request(resp)
        .map_err(err)?
        .signature
        .ok_or_else(|| JsValue::from_str("no signature in TxRequest"))
}

/// `TXFINISHED` serialized transaction.
#[wasm_bindgen(js_name = hwTxRequestSerialized)]
pub fn wasm_hw_tx_request_serialized(dev_id: u32, resp: &[u8]) -> Result<Vec<u8>, JsValue> {
    Wallet::new(dev(dev_id)?)
        .parse_tx_request(resp)
        .map_err(err)?
        .serialized_tx
        .ok_or_else(|| JsValue::from_str("no serialized_tx in TxRequest"))
}

use crate::hw::trezor::{tx_ack_bytes, TxChunk};

/// `TxAck` answering `TXMETA`.
#[wasm_bindgen(js_name = hwTxAckMeta)]
pub fn wasm_hw_tx_ack_meta(
    version: u32,
    lock_time: u32,
    inputs_count: u32,
    outputs_count: u32,
) -> Result<Vec<u8>, JsValue> {
    tx_ack_bytes(&TxChunk::Meta {
        version,
        lock_time,
        inputs_count,
        outputs_count,
    })
    .map_err(err)
}

/// `TxAck` answering `TXINPUT` (`amount` as exact `(hi, lo)` u32 pair;
/// empty `script_sig` omits field 4 — for the input being signed).
#[wasm_bindgen(js_name = hwTxAckInput)]
pub fn wasm_hw_tx_ack_input(
    prev_hash: &[u8],
    prev_index: u32,
    path_le: &[u8],
    amount_hi: u32,
    amount_lo: u32,
    script_sig: &[u8],
    script_type: u32,
) -> Result<Vec<u8>, JsValue> {
    if prev_hash.len() != 32 {
        return Err(JsValue::from_str("prev_hash must be 32 bytes"));
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(prev_hash);
    let path = path_from_le(path_le)?;
    let amount = ((amount_hi as u64) << 32) | (amount_lo as u64);
    let script_sig = if script_sig.is_empty() {
        None
    } else {
        Some(script_sig.to_vec())
    };
    tx_ack_bytes(&TxChunk::Input {
        prev_hash: hash,
        prev_index,
        path,
        amount,
        script_sig,
        script_type,
    })
    .map_err(err)
}

/// `TxAck` answering `TXOUTPUT` (pay to address).
#[wasm_bindgen(js_name = hwTxAckOutput)]
pub fn wasm_hw_tx_ack_output(
    address: &str,
    amount_hi: u32,
    amount_lo: u32,
    script_type: u32,
) -> Result<Vec<u8>, JsValue> {
    let amount = ((amount_hi as u64) << 32) | (amount_lo as u64);
    tx_ack_bytes(&TxChunk::OutputAddr {
        address: address.as_bytes().to_vec(),
        amount,
        script_type,
    })
    .map_err(err)
}

/// `TxAck` answering `TXOUTPUT` (change back to path).
#[wasm_bindgen(js_name = hwTxAckChange)]
pub fn wasm_hw_tx_ack_change(
    path_le: &[u8],
    amount_hi: u32,
    amount_lo: u32,
    script_type: u32,
) -> Result<Vec<u8>, JsValue> {
    let amount = ((amount_hi as u64) << 32) | (amount_lo as u64);
    let path = path_from_le(path_le)?;
    tx_ack_bytes(&TxChunk::OutputChange {
        path,
        amount,
        script_type,
    })
    .map_err(err)
}

/// `TxRequest` prev-tx hash (32 bytes); errors when the request targets the
/// current tx.
#[wasm_bindgen(js_name = hwTxRequestTxHash)]
pub fn wasm_hw_tx_request_txhash(dev_id: u32, resp: &[u8]) -> Result<Vec<u8>, JsValue> {
    Wallet::new(dev(dev_id)?)
        .parse_tx_request(resp)
        .map_err(err)?
        .tx_hash
        .ok_or_else(|| JsValue::from_str("no tx_hash in TxRequest"))
}

/// `TxAck` answering `TXOUTPUT` for a PREVIOUS transaction
/// (`bin_outputs`, field 3; amount as exact `(hi, lo)` u32 pair).
#[wasm_bindgen(js_name = hwTxAckBinOutput)]
pub fn wasm_hw_tx_ack_bin_output(
    script_pubkey: &[u8],
    amount_hi: u32,
    amount_lo: u32,
) -> Result<Vec<u8>, JsValue> {
    let amount = ((amount_hi as u64) << 32) | (amount_lo as u64);
    tx_ack_bytes(&TxChunk::OutputBin {
        amount,
        script_pubkey: script_pubkey.to_vec(),
    })
    .map_err(err)
}

// ---------------------------------------------------------------------------
// BitBox02 session handles: same slot machine as FFI (`hw::bitbox`), thin
// wasm-bindgen skin. I/O stays app-side: U2F-HID reports + HWW arbitration
// (`REQ_NEW`/`RETRY`/`ACK`) + OP messages with `[OP_STATUS] + payload`
// replies (see `hw::bitbox` docs). This skin only moves OP payloads and
// Noise bytes.
// ---------------------------------------------------------------------------

use crate::hw::bitbox as bbsess;

/// Open initiator session from 32-B host static + ephemeral.
#[wasm_bindgen(js_name = hwBitBoxHsNew)]
pub fn wasm_hw_bitbox_hs_new(static_priv: &[u8], ephemeral_priv: &[u8]) -> Result<(), JsValue> {
    if static_priv.len() != 32 || ephemeral_priv.len() != 32 {
        return Err(JsValue::from_str("keys must be 32 bytes"));
    }
    let mut s = [0u8; 32];
    let mut e = [0u8; 32];
    s.copy_from_slice(static_priv);
    e.copy_from_slice(ephemeral_priv);
    bbsess::session_open(s, e).map_err(err)
}

/// Write handshake message 1 (32 B).
#[wasm_bindgen(js_name = hwBitBoxHsM1)]
pub fn wasm_hw_bitbox_hs_m1() -> Result<Vec<u8>, JsValue> {
    bbsess::session_m1().map_err(err)
}

/// Ingest handshake message 2 (96 B).
#[wasm_bindgen(js_name = hwBitBoxHsM2)]
pub fn wasm_hw_bitbox_hs_m2(m2: &[u8]) -> Result<(), JsValue> {
    bbsess::session_m2(m2).map_err(err)
}

/// Write handshake message 3 (64 B).
#[wasm_bindgen(js_name = hwBitBoxHsM3)]
pub fn wasm_hw_bitbox_hs_m3() -> Result<Vec<u8>, JsValue> {
    bbsess::session_m3().map_err(err)
}

/// Split into transport keys.
#[wasm_bindgen(js_name = hwBitBoxHsSplit)]
pub fn wasm_hw_bitbox_hs_split() -> Result<(), JsValue> {
    bbsess::session_split().map_err(err)
}

/// Encrypt one post-handshake message.
#[wasm_bindgen(js_name = hwBitBoxEncrypt)]
pub fn wasm_hw_bitbox_encrypt(plaintext: &[u8]) -> Result<Vec<u8>, JsValue> {
    bbsess::session_encrypt(plaintext).map_err(err)
}

/// Decrypt one post-handshake message.
#[wasm_bindgen(js_name = hwBitBoxDecrypt)]
pub fn wasm_hw_bitbox_decrypt(ciphertext: &[u8]) -> Result<Vec<u8>, JsValue> {
    bbsess::session_decrypt(ciphertext).map_err(err)
}

/// Handshake hash (pairing-code source).
#[wasm_bindgen(js_name = hwBitBoxHsHash)]
pub fn wasm_hw_bitbox_hs_hash() -> Result<Vec<u8>, JsValue> {
    bbsess::session_hash().map(|h| h.to_vec()).map_err(err)
}

/// Close + wipe. Idempotent.
#[wasm_bindgen(js_name = hwBitBoxFree)]
pub fn wasm_hw_bitbox_free() {
    bbsess::session_free()
}

/// Build a `Request{btc_pub}` frame (UNENCRYPTED — encrypt via the session).
#[wasm_bindgen(js_name = hwBitBoxBtcPubRequest)]
pub fn wasm_hw_bitbox_btc_pub_request(
    coin_id: u32,
    path_le: &[u8],
    xpub_type: u32,
    display: bool,
) -> Result<Vec<u8>, JsValue> {
    use crate::hw::bitbox::{bitbox_btc_pub_request, bitbox_coin_for};
    let c = coin(coin_id)?;
    let profile_coin = bitbox_coin_for(&c).map_err(err)?;
    let path = path_from_le(path_le)?;
    bitbox_btc_pub_request(profile_coin, &path, xpub_type, display).map_err(err)
}

/// Parse a `Response` frame into the xpub string.
#[wasm_bindgen(js_name = hwBitBoxPubParse)]
pub fn wasm_hw_bitbox_pub_parse(resp: &[u8]) -> Result<String, JsValue> {
    use crate::hw::bitbox::bitbox_pub_parse;
    bitbox_pub_parse(resp).map_err(err)
}

/// Build `Request{btc_sign_init}` (UNENCRYPTED).
#[wasm_bindgen(js_name = hwBitBoxSignInit)]
pub fn wasm_hw_bitbox_sign_init(
    coin_id: u32,
    path_le: &[u8],
    simple_type: u32,
    version: u32,
    num_inputs: u32,
    num_outputs: u32,
    locktime: u32,
) -> Result<Vec<u8>, JsValue> {
    use crate::hw::bitbox::{bitbox_coin_for, bitbox_sign_init_request};
    let c = coin(coin_id)?;
    let profile_coin = bitbox_coin_for(&c).map_err(err)?;
    let path = path_from_le(path_le)?;
    bitbox_sign_init_request(
        profile_coin,
        &path,
        simple_type,
        version,
        num_inputs,
        num_outputs,
        locktime,
    )
    .map_err(err)
}

/// Parse `Response{btc_sign_next | btc: BTCResponse{sign_next}}` into 8 bytes
/// (`type LE32 || index LE32`, `0xFFFFFFFF` = absent); Callers repack with
/// the top bit like `hwParseTxRequest`.
#[wasm_bindgen(js_name = hwBitBoxSignNextParse)]
pub fn wasm_hw_bitbox_sign_next_parse(resp: &[u8]) -> Result<Vec<u8>, JsValue> {
    use crate::hw::bitbox::bitbox_sign_next_parse;
    let r = bitbox_sign_next_parse(resp).map_err(err)?;
    let mut out = Vec::with_capacity(8);
    out.extend_from_slice(&r.request_type.to_le_bytes());
    out.extend_from_slice(&r.index.unwrap_or(0xFFFF_FFFF).to_le_bytes());
    Ok(out)
}

/// `DONE` signature bytes (64 B R||S).
#[wasm_bindgen(js_name = hwBitBoxSignNextSignature)]
pub fn wasm_hw_bitbox_sign_next_signature(resp: &[u8]) -> Result<Vec<u8>, JsValue> {
    use crate::hw::bitbox::bitbox_sign_next_parse;
    bitbox_sign_next_parse(resp)
        .map_err(err)?
        .signature
        .ok_or_else(|| JsValue::from_str("no signature in sign_next"))
}

/// `prev_index` (4 LE bytes, `0xFFFFFFFF` = absent).
#[wasm_bindgen(js_name = hwBitBoxSignNextPrevIndex)]
pub fn wasm_hw_bitbox_sign_next_prev_index(resp: &[u8]) -> Result<Vec<u8>, JsValue> {
    use crate::hw::bitbox::bitbox_sign_next_parse;
    let r = bitbox_sign_next_parse(resp).map_err(err)?;
    Ok(r.prev_index.unwrap_or(0xFFFF_FFFF).to_le_bytes().to_vec())
}

/// Build `Request{btc_sign_input}` (UNENCRYPTED).
#[wasm_bindgen(js_name = hwBitBoxSignInput)]
pub fn wasm_hw_bitbox_sign_input(
    prev_hash: &[u8],
    prev_index: u32,
    amount_hi: u32,
    amount_lo: u32,
    sequence: u32,
    path_le: &[u8],
    script_config_index: u32,
) -> Result<Vec<u8>, JsValue> {
    use crate::hw::bitbox::{bitbox_sign_ack_bytes, BitBoxTxChunk};
    if prev_hash.len() != 32 {
        return Err(JsValue::from_str("prev_hash must be 32 bytes"));
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(prev_hash);
    let path = path_from_le(path_le)?;
    let amount = ((amount_hi as u64) << 32) | (amount_lo as u64);
    bitbox_sign_ack_bytes(&BitBoxTxChunk::Input {
        prev_hash: hash,
        prev_index,
        amount,
        sequence,
        path,
        script_config_index,
    })
    .map_err(err)
}

/// Build `Request{btc_sign_output}` for an external address.
#[wasm_bindgen(js_name = hwBitBoxSignOutput)]
pub fn wasm_hw_bitbox_sign_output(
    output_type: u32,
    amount_hi: u32,
    amount_lo: u32,
    payload: &[u8],
) -> Result<Vec<u8>, JsValue> {
    use crate::hw::bitbox::{bitbox_sign_ack_bytes, BitBoxTxChunk};
    let amount = ((amount_hi as u64) << 32) | (amount_lo as u64);
    bitbox_sign_ack_bytes(&BitBoxTxChunk::OutputExternal {
        output_type,
        amount,
        payload: payload.to_vec(),
    })
    .map_err(err)
}

/// Build `Request{btc_sign_output}` for change.
#[wasm_bindgen(js_name = hwBitBoxSignChange)]
pub fn wasm_hw_bitbox_sign_change(
    path_le: &[u8],
    amount_hi: u32,
    amount_lo: u32,
    script_config_index: u32,
) -> Result<Vec<u8>, JsValue> {
    use crate::hw::bitbox::{bitbox_sign_ack_bytes, BitBoxTxChunk};
    let path = path_from_le(path_le)?;
    let amount = ((amount_hi as u64) << 32) | (amount_lo as u64);
    bitbox_sign_ack_bytes(&BitBoxTxChunk::OutputChange {
        path,
        amount,
        script_config_index,
    })
    .map_err(err)
}

/// Build `Request{btc: BTCRequest{prevtx_init}}` (UNENCRYPTED).
#[wasm_bindgen(js_name = hwBitBoxSignPrevtxInit)]
pub fn wasm_hw_bitbox_sign_prevtx_init(
    version: u32,
    num_inputs: u32,
    num_outputs: u32,
    locktime: u32,
) -> Result<Vec<u8>, JsValue> {
    use crate::hw::bitbox::{bitbox_sign_ack_bytes, BitBoxTxChunk};
    bitbox_sign_ack_bytes(&BitBoxTxChunk::PrevtxInit {
        version,
        num_inputs,
        num_outputs,
        locktime,
    })
    .map_err(err)
}

/// Build `Request{btc: BTCRequest{prevtx_input}}` (UNENCRYPTED).
#[wasm_bindgen(js_name = hwBitBoxSignPrevtxInput)]
pub fn wasm_hw_bitbox_sign_prevtx_input(
    prev_hash: &[u8],
    prev_index: u32,
    script_sig: &[u8],
    sequence: u32,
) -> Result<Vec<u8>, JsValue> {
    use crate::hw::bitbox::{bitbox_sign_ack_bytes, BitBoxTxChunk};
    if prev_hash.len() != 32 {
        return Err(JsValue::from_str("prev_hash must be 32 bytes"));
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(prev_hash);
    bitbox_sign_ack_bytes(&BitBoxTxChunk::PrevtxInput {
        prev_hash: hash,
        prev_index,
        script_sig: script_sig.to_vec(),
        sequence,
    })
    .map_err(err)
}

/// Build `Request{btc: BTCRequest{prevtx_output}}` (UNENCRYPTED).
#[wasm_bindgen(js_name = hwBitBoxSignPrevtxOutput)]
pub fn wasm_hw_bitbox_sign_prevtx_output(
    amount_hi: u32,
    amount_lo: u32,
    script: &[u8],
) -> Result<Vec<u8>, JsValue> {
    use crate::hw::bitbox::{bitbox_sign_ack_bytes, BitBoxTxChunk};
    let amount = ((amount_hi as u64) << 32) | (amount_lo as u64);
    bitbox_sign_ack_bytes(&BitBoxTxChunk::PrevtxOutput {
        amount,
        script: script.to_vec(),
    })
    .map_err(err)
}
