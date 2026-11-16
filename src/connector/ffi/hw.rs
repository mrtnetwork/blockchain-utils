//! Hardware-wallet codec FFI.
//!
//! The host app owns the USB/BLE/NFC transport (platform channels, `usb` plugins,
//! WebHID/WebUSB on web). Rust only builds/parses messages — the zero-dep
//! `hw` core underneath. No `hidapi`, no new dependencies.
//!
//! Conventions (same as `encoding.rs`):
//! - inputs: `(ptr, len)` byte spans; paths are `<u32 LE>` byte spans.
//! - outputs: caller-sized `out` buffers; success returns bytes written,
//!   failure returns a negative `-BU_HW_*` code.
//! - strings (`path`, `ur_type`, `qr`) are UTF-8 byte spans.
//!
//! Build the cdylib with: `cargo build --features ffi,hw --release`

#![cfg(all(feature = "ffi", feature = "hw"))]

use core::slice;

use crate::hw::coin::WELL_KNOWN_COINS;
use crate::hw::hid::{hid_frame, hid_unframe, HID_REPORT_LEN};
use crate::hw::path::{parse_path, validate_for_coin};
use crate::hw::psbt::Psbt;
use crate::hw::ur::{ur_decode_single, ur_encode_single};
use crate::hw::wallet::{DeviceKind, HardwareWallet, Wallet};

pub const BU_HW_OK: i32 = 0;
pub const BU_HW_ERR_NULL: i32 = 1;
pub const BU_HW_ERR_BUFFER: i32 = 2;
pub const BU_HW_ERR_INVALID: i32 = 3;
pub const BU_HW_ERR_UNSUPPORTED: i32 = 4;
pub const BU_HW_ERR_UNIMPLEMENTED: i32 = 5;

// Device ids — order mirrors `DeviceKind::ALL`.
pub const BU_HW_LEDGER_S_PLUS: u32 = 0;
pub const BU_HW_LEDGER_X: u32 = 1;
pub const BU_HW_LEDGER_FLEX: u32 = 2;
pub const BU_HW_LEDGER_STAX: u32 = 3;
pub const BU_HW_TREZOR_ONE: u32 = 4;
pub const BU_HW_TREZOR_T: u32 = 5;
pub const BU_HW_TREZOR_SAFE3: u32 = 6;
pub const BU_HW_TREZOR_SAFE5: u32 = 7;
pub const BU_HW_TREZOR_SAFE7: u32 = 8;
pub const BU_HW_KEEPKEY: u32 = 9;
pub const BU_HW_ONEKEY: u32 = 10;
pub const BU_HW_BITBOX02: u32 = 11;
pub const BU_HW_PASSPORT: u32 = 12;
pub const BU_HW_KEYSTONE3: u32 = 13;
pub const BU_HW_KEYSTONE_PRO: u32 = 14;
pub const BU_HW_COLDCARD_QR: u32 = 15;
pub const BU_HW_JADE_QR: u32 = 16;

// Coin ids — index into `hw::coin::WELL_KNOWN_COINS`
// (0 btc, 1 btc-segwit, 2 btc-taproot, 3 eth, 4 trx, 5 xrp, 6 atom,
//  7 fil-secp, 8 xtz-tz1, 9 xtz-tz2, 10 xtz-tz3, 11 sol, 12 apt,
//  13 sui-ed, 14 near, 15 xlm, 16 dot-slip, 17 ada-icarus, 18 xmr-slip,
//  19 zec-transparent; shielded Zcash is unsupported on all HW).
pub const BU_HW_COIN_COUNT: u32 = 20;

fn map_err(e: crate::error::Error) -> i32 {
    use crate::error::Error::*;
    -(match e {
        Unsupported => BU_HW_ERR_UNSUPPORTED,
        Unimplemented => BU_HW_ERR_UNIMPLEMENTED,
        _ => BU_HW_ERR_INVALID,
    })
}

fn device(id: u32) -> Result<DeviceKind, i32> {
    Ok(match id {
        BU_HW_LEDGER_S_PLUS => DeviceKind::LedgerNanoSPlus,
        BU_HW_LEDGER_X => DeviceKind::LedgerNanoX,
        BU_HW_LEDGER_FLEX => DeviceKind::LedgerFlex,
        BU_HW_LEDGER_STAX => DeviceKind::LedgerStax,
        BU_HW_TREZOR_ONE => DeviceKind::TrezorOne,
        BU_HW_TREZOR_T => DeviceKind::TrezorModelT,
        BU_HW_TREZOR_SAFE3 => DeviceKind::TrezorSafe3,
        BU_HW_TREZOR_SAFE5 => DeviceKind::TrezorSafe5,
        BU_HW_TREZOR_SAFE7 => DeviceKind::TrezorSafe7,
        BU_HW_KEEPKEY => DeviceKind::KeepKey,
        BU_HW_ONEKEY => DeviceKind::OneKey,
        BU_HW_BITBOX02 => DeviceKind::BitBox02,
        BU_HW_PASSPORT => DeviceKind::Passport,
        BU_HW_KEYSTONE3 => DeviceKind::Keystone3,
        BU_HW_KEYSTONE_PRO => DeviceKind::KeystonePro,
        BU_HW_COLDCARD_QR => DeviceKind::ColdcardQr,
        BU_HW_JADE_QR => DeviceKind::JadeQr,
        _ => return Err(-BU_HW_ERR_INVALID),
    })
}

fn coin(id: u32) -> Result<crate::hw::coin::CoinProfile, i32> {
    WELL_KNOWN_COINS
        .get(id as usize)
        .copied()
        .ok_or(-BU_HW_ERR_INVALID)
}

fn check_in(ptr: *const u8, len: usize) -> Result<(), i32> {
    if len > 0 && ptr.is_null() {
        return Err(-BU_HW_ERR_NULL);
    }
    Ok(())
}

fn check_out(ptr: *mut u8, len: usize) -> Result<(), i32> {
    if len > 0 && ptr.is_null() {
        return Err(-BU_HW_ERR_NULL);
    }
    Ok(())
}

fn in_bytes<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(ptr, len) }
    }
}

/// Decode `<u32 LE>` path bytes into raw indexes.
fn decode_path(ptr: *const u8, len: usize) -> Result<alloc::vec::Vec<u32>, i32> {
    check_in(ptr, len)?;
    if !len.is_multiple_of(4) {
        return Err(-BU_HW_ERR_INVALID);
    }
    let raw = in_bytes(ptr, len);
    let mut out = alloc::vec::Vec::with_capacity(len / 4);
    for c in raw.as_chunks::<4>().0 {
        out.push(u32::from_le_bytes([c[0], c[1], c[2], c[3]]));
    }
    Ok(out)
}

fn write_out(out: *mut u8, out_len: usize, data: &[u8]) -> i32 {
    if data.len() > out_len {
        return -BU_HW_ERR_BUFFER;
    }
    if check_out(out, out_len).is_err() {
        return -BU_HW_ERR_NULL;
    }
    if !data.is_empty() {
        unsafe { slice::from_raw_parts_mut(out, data.len()).copy_from_slice(data) };
    }
    data.len() as i32
}

/// Number of known devices (17).
#[no_mangle]
pub extern "C" fn bu_hw_device_count() -> u32 {
    DeviceKind::ALL.len() as u32
}

/// Number of known coins (19).
#[no_mangle]
pub extern "C" fn bu_hw_coin_count() -> u32 {
    BU_HW_COIN_COUNT
}

/// 1 = device supports coin's curve, 0 = no, negative = bad id.
#[no_mangle]
pub extern "C" fn bu_hw_supports_coin(dev: u32, coin_id: u32) -> i32 {
    let d = match device(dev) {
        Ok(d) => d,
        Err(e) => return e,
    };
    let c = match coin(coin_id) {
        Ok(c) => c,
        Err(e) => return e,
    };
    if Wallet::new(d).supports_coin(&c) {
        1
    } else {
        0
    }
}

/// 1 = QR/SD-only (no transport), 0 = USB, negative = bad id.
#[no_mangle]
pub extern "C" fn bu_hw_is_airgap(dev: u32) -> i32 {
    match device(dev) {
        Ok(d) => {
            if d.is_airgap() {
                1
            } else {
                0
            }
        }
        Err(e) => e,
    }
}

/// Parse `"m/44'/0'/0'/0/0"` into `<u32 LE>` indexes in `out`.
/// Returns index count written, or negative error.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hw_parse_path(
    path_ptr: *const u8,
    path_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if check_in(path_ptr, path_len).is_err() {
        return -BU_HW_ERR_NULL;
    }
    let s = match core::str::from_utf8(in_bytes(path_ptr, path_len)) {
        Ok(s) => s,
        Err(_) => return -BU_HW_ERR_INVALID,
    };
    let idx = match parse_path(s) {
        Ok(v) => v,
        Err(e) => return map_err(e),
    };
    let need = idx.len() * 4;
    if need > out_len {
        return -BU_HW_ERR_BUFFER;
    }
    if check_out(out, out_len).is_err() {
        return -BU_HW_ERR_NULL;
    }
    let dest = unsafe { slice::from_raw_parts_mut(out, need) };
    for (i, v) in idx.iter().enumerate() {
        dest[4 * i..4 * i + 4].copy_from_slice(&v.to_le_bytes());
    }
    idx.len() as i32
}

/// Validate path shape for device+coin. Returns `BU_HW_OK` or negative.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hw_validate_path(
    dev: u32,
    coin_id: u32,
    path_ptr: *const u8,
    path_len: usize,
) -> i32 {
    let d = match device(dev) {
        Ok(d) => d,
        Err(e) => return e,
    };
    let c = match coin(coin_id) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let path = match decode_path(path_ptr, path_len) {
        Ok(p) => p,
        Err(e) => return e,
    };
    if !Wallet::new(d).supports_coin(&c) {
        return -BU_HW_ERR_UNSUPPORTED;
    }
    match validate_for_coin(&path, &c) {
        Ok(()) => BU_HW_OK,
        Err(e) => map_err(e),
    }
}

/// Build USB request bytes (APDU / Trezor frame). Returns bytes written.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hw_get_address_request(
    dev: u32,
    coin_id: u32,
    path_ptr: *const u8,
    path_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    let d = match device(dev) {
        Ok(d) => d,
        Err(e) => return e,
    };
    let c = match coin(coin_id) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let path = match decode_path(path_ptr, path_len) {
        Ok(p) => p,
        Err(e) => return e,
    };
    match Wallet::new(d).get_address_request(&c, &path) {
        Ok(req) => write_out(out, out_len, &req),
        Err(e) => map_err(e),
    }
}

/// Parse USB response into pubkey/address bytes. Returns bytes written.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hw_parse_address_response(
    dev: u32,
    resp_ptr: *const u8,
    resp_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    let d = match device(dev) {
        Ok(d) => d,
        Err(e) => return e,
    };
    if check_in(resp_ptr, resp_len).is_err() {
        return -BU_HW_ERR_NULL;
    }
    match Wallet::new(d).parse_address_response(in_bytes(resp_ptr, resp_len)) {
        Ok(v) => write_out(out, out_len, &v),
        Err(e) => map_err(e),
    }
}

/// Ledger v2 `GET_MASTER_FINGERPRINT` request (no input). Returns bytes written.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hw_ledger_fingerprint_request(out: *mut u8, out_len: usize) -> i32 {
    use crate::hw::wallet::ledger_fingerprint_request;
    write_out(out, out_len, &ledger_fingerprint_request())
}

/// Parse the 4-byte fingerprint response. Returns bytes written (always 4).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hw_ledger_fingerprint_parse(
    resp_ptr: *const u8,
    resp_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    use crate::hw::wallet::ledger_fingerprint_parse;
    if check_in(resp_ptr, resp_len).is_err() {
        return -BU_HW_ERR_NULL;
    }
    match ledger_fingerprint_parse(in_bytes(resp_ptr, resp_len)) {
        Ok(v) => write_out(out, out_len, &v),
        Err(e) => map_err(e),
    }
}

/// Build "sign this payload" USB request bytes (Ledger APDU / Trezor
/// `SignMessage` frame). `payload` is the 32-byte sighash for Ledger, the
/// raw message (1..=1024 bytes) for Trezor. Returns bytes written.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hw_sign_request(
    dev: u32,
    coin_id: u32,
    path_ptr: *const u8,
    path_len: usize,
    payload_ptr: *const u8,
    payload_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    let d = match device(dev) {
        Ok(d) => d,
        Err(e) => return e,
    };
    let c = match coin(coin_id) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let path = match decode_path(path_ptr, path_len) {
        Ok(p) => p,
        Err(e) => return e,
    };
    if check_in(payload_ptr, payload_len).is_err() {
        return -BU_HW_ERR_NULL;
    }
    match Wallet::new(d).sign_request(&c, &path, in_bytes(payload_ptr, payload_len)) {
        Ok(req) => write_out(out, out_len, &req),
        Err(e) => map_err(e),
    }
}

/// Parse USB sign response into raw signature bytes (DER for Ledger,
/// 65-byte recoverable sig for Trezor). Device rejection (non-`0x9000`
/// status / wrong message type) returns a negative code, never a panic.
/// Returns bytes written.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hw_parse_sign_response(
    dev: u32,
    resp_ptr: *const u8,
    resp_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    let d = match device(dev) {
        Ok(d) => d,
        Err(e) => return e,
    };
    if check_in(resp_ptr, resp_len).is_err() {
        return -BU_HW_ERR_NULL;
    }
    match Wallet::new(d).parse_sign_response(in_bytes(resp_ptr, resp_len)) {
        Ok(v) => write_out(out, out_len, &v),
        Err(e) => map_err(e),
    }
}

// ---------------------------------------------------------------------------
// Trezor identity signing (`SignIdentity` → `SignedIdentity`, SLIP-13).
// SSH/GPG agents and challenge-response logins. All strings are UTF-8 bytes.
// Returns bytes written or negative. NEVER for value transfer.
// ---------------------------------------------------------------------------

fn identity_str<'a>(ptr: *const u8, len: usize) -> Result<&'a str, i32> {
    if check_in(ptr, len).is_err() {
        return Err(-BU_HW_ERR_NULL);
    }
    core::str::from_utf8(in_bytes(ptr, len)).map_err(|_| -BU_HW_ERR_INVALID)
}

/// Encode `IdentityType`. Returns bytes written.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hw_identity_encode(
    proto_ptr: *const u8,
    proto_len: usize,
    user_ptr: *const u8,
    user_len: usize,
    host_ptr: *const u8,
    host_len: usize,
    port_ptr: *const u8,
    port_len: usize,
    path_ptr: *const u8,
    path_len: usize,
    index: u32,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    use crate::hw::trezor::identity_encode;
    let (proto, user, host, port, path) = match (
        identity_str(proto_ptr, proto_len),
        identity_str(user_ptr, user_len),
        identity_str(host_ptr, host_len),
        identity_str(port_ptr, port_len),
        identity_str(path_ptr, path_len),
    ) {
        (Ok(a), Ok(b), Ok(c), Ok(d), Ok(e)) => (a, b, c, d, e),
        _ => return -BU_HW_ERR_INVALID,
    };
    match identity_encode(proto, user, host, port, path, index) {
        Ok(v) => write_out(out, out_len, &v),
        Err(e) => map_err(e),
    }
}

/// Build a framed `SignIdentity` request. `curve`: 0 = omit (device default
/// secp256k1), 1 = secp256k1, 2 = nist256p1. Returns bytes written.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hw_sign_identity_request(
    id_ptr: *const u8,
    id_len: usize,
    hidden_ptr: *const u8,
    hidden_len: usize,
    visual_ptr: *const u8,
    visual_len: usize,
    curve: u32,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    use crate::hw::trezor::sign_identity_request;
    if check_in(id_ptr, id_len).is_err()
        || check_in(hidden_ptr, hidden_len).is_err()
        || check_in(visual_ptr, visual_len).is_err()
    {
        return -BU_HW_ERR_NULL;
    }
    let visual = match identity_str(visual_ptr, visual_len) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let curve_name = match curve {
        0 => None,
        1 => Some("secp256k1"),
        2 => Some("nist256p1"),
        _ => return -BU_HW_ERR_INVALID,
    };
    match sign_identity_request(
        in_bytes(id_ptr, id_len),
        in_bytes(hidden_ptr, hidden_len),
        visual,
        curve_name,
    ) {
        Ok(v) => write_out(out, out_len, &v),
        Err(e) => map_err(e),
    }
}

/// `SignedIdentity.address` UTF-8 into `out`. Absent → negative.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hw_signed_identity_address(
    resp_ptr: *const u8,
    resp_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    use crate::hw::trezor::parse_signed_identity;
    if check_in(resp_ptr, resp_len).is_err() {
        return -BU_HW_ERR_NULL;
    }
    match parse_signed_identity(in_bytes(resp_ptr, resp_len)) {
        Ok(r) => match r.address {
            Some(a) => write_out(out, out_len, a.as_bytes()),
            None => -BU_HW_ERR_INVALID,
        },
        Err(e) => map_err(e),
    }
}

/// `SignedIdentity.public_key` bytes into `out`. Returns bytes written.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hw_signed_identity_pubkey(
    resp_ptr: *const u8,
    resp_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    use crate::hw::trezor::parse_signed_identity;
    if check_in(resp_ptr, resp_len).is_err() {
        return -BU_HW_ERR_NULL;
    }
    match parse_signed_identity(in_bytes(resp_ptr, resp_len)) {
        Ok(r) => write_out(out, out_len, &r.public_key),
        Err(e) => map_err(e),
    }
}

/// `SignedIdentity.signature` bytes into `out`. Returns bytes written.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hw_signed_identity_signature(
    resp_ptr: *const u8,
    resp_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    use crate::hw::trezor::parse_signed_identity;
    if check_in(resp_ptr, resp_len).is_err() {
        return -BU_HW_ERR_NULL;
    }
    match parse_signed_identity(in_bytes(resp_ptr, resp_len)) {
        Ok(r) => write_out(out, out_len, &r.signature),
        Err(e) => map_err(e),
    }
}

/// Build airgap QR string (`ur:bytes/...`) as UTF-8. Returns bytes written.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hw_qr_request(
    dev: u32,
    coin_id: u32,
    path_ptr: *const u8,
    path_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    let d = match device(dev) {
        Ok(d) => d,
        Err(e) => return e,
    };
    let c = match coin(coin_id) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let path = match decode_path(path_ptr, path_len) {
        Ok(p) => p,
        Err(e) => return e,
    };
    match Wallet::new(d).qr_request(&c, &path) {
        Ok(s) => write_out(out, out_len, s.as_bytes()),
        Err(e) => map_err(e),
    }
}

/// Parse scanned single-part QR into payload bytes. Returns bytes written.
/// (Multipart: assemble externally with `BuUrAssembler`, then parse.)
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hw_qr_parse(
    dev: u32,
    qr_ptr: *const u8,
    qr_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    let d = match device(dev) {
        Ok(d) => d,
        Err(e) => return e,
    };
    if check_in(qr_ptr, qr_len).is_err() {
        return -BU_HW_ERR_NULL;
    }
    let s = match core::str::from_utf8(in_bytes(qr_ptr, qr_len)) {
        Ok(s) => s,
        Err(_) => return -BU_HW_ERR_INVALID,
    };
    match Wallet::new(d).qr_parse(s) {
        Ok(v) => write_out(out, out_len, &v),
        Err(e) => map_err(e),
    }
}

/// Write `input_count LE u32 || output_count LE u32` (8 bytes) for a PSBT.
/// Returns `BU_HW_OK` or negative.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hw_psbt_counts(
    raw_ptr: *const u8,
    raw_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if check_in(raw_ptr, raw_len).is_err() {
        return -BU_HW_ERR_NULL;
    }
    if out_len < 8 {
        return -BU_HW_ERR_BUFFER;
    }
    if check_out(out, out_len).is_err() {
        return -BU_HW_ERR_NULL;
    }
    match Psbt::parse(in_bytes(raw_ptr, raw_len)) {
        Ok(p) => {
            let dest = unsafe { slice::from_raw_parts_mut(out, 8) };
            dest[..4].copy_from_slice(&(p.input_count() as u32).to_le_bytes());
            dest[4..].copy_from_slice(&(p.output_count() as u32).to_le_bytes());
            BU_HW_OK
        }
        Err(e) => map_err(e),
    }
}

/// Encode `ur:<type>/<body>` as UTF-8. Returns bytes written.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hw_ur_encode(
    type_ptr: *const u8,
    type_len: usize,
    payload_ptr: *const u8,
    payload_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if check_in(type_ptr, type_len).is_err() || check_in(payload_ptr, payload_len).is_err() {
        return -BU_HW_ERR_NULL;
    }
    let t = match core::str::from_utf8(in_bytes(type_ptr, type_len)) {
        Ok(s) => s,
        Err(_) => return -BU_HW_ERR_INVALID,
    };
    write_out(
        out,
        out_len,
        ur_encode_single(t, in_bytes(payload_ptr, payload_len)).as_bytes(),
    )
}

/// Decode UR payload bytes (single- or multi-part shard accepted;
/// multi-part reassembly lives in `BuUrAssembler`). Returns written.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hw_ur_decode_payload(
    ur_ptr: *const u8,
    ur_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if check_in(ur_ptr, ur_len).is_err() {
        return -BU_HW_ERR_NULL;
    }
    let s = match core::str::from_utf8(in_bytes(ur_ptr, ur_len)) {
        Ok(s) => s,
        Err(_) => return -BU_HW_ERR_INVALID,
    };
    match ur_decode_single(s) {
        Ok(m) => write_out(out, out_len, &m.payload),
        Err(e) => map_err(e),
    }
}

/// Decode UR type string as UTF-8. Returns bytes written.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hw_ur_decode_type(
    ur_ptr: *const u8,
    ur_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if check_in(ur_ptr, ur_len).is_err() {
        return -BU_HW_ERR_NULL;
    }
    let s = match core::str::from_utf8(in_bytes(ur_ptr, ur_len)) {
        Ok(s) => s,
        Err(_) => return -BU_HW_ERR_INVALID,
    };
    match ur_decode_single(s) {
        Ok(m) => write_out(out, out_len, m.ur_type.as_bytes()),
        Err(e) => map_err(e),
    }
}

/// Chunk `payload` into 64-byte HID reports (Ledger framing) concatenated
/// in `out`. Needs `64 * reports` bytes; returns bytes written.
/// `channel` ≤ 0xFFFF (default `0x0101`), `tag` ≤ 0xFF (`0x05` = APDU).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hw_hid_frame(
    payload_ptr: *const u8,
    payload_len: usize,
    channel: u32,
    tag: u32,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if check_in(payload_ptr, payload_len).is_err() {
        return -BU_HW_ERR_NULL;
    }
    if channel > 0xFFFF || tag > 0xFF {
        return -BU_HW_ERR_INVALID;
    }
    let frames = hid_frame(
        in_bytes(payload_ptr, payload_len),
        channel as u16,
        tag as u8,
    );
    let need: usize = frames.iter().map(|f| f.len()).sum();
    if need > out_len {
        return -BU_HW_ERR_BUFFER;
    }
    if check_out(out, out_len).is_err() {
        return -BU_HW_ERR_NULL;
    }
    let dest = unsafe { slice::from_raw_parts_mut(out, need) };
    let mut off = 0usize;
    for f in &frames {
        dest[off..off + f.len()].copy_from_slice(f);
        off += f.len();
    }
    need as i32
}

/// Reassemble concatenated 64-byte HID reports (`reports_len` % 64 == 0)
/// into one payload in `out`. Returns bytes written or negative error.
/// App read loop recipe: read one report → total length is at bytes 5..7 →
/// expected reports = 1 + ceil((total - 57) / 59) → read the rest → call this.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hw_hid_unframe(
    reports_ptr: *const u8,
    reports_len: usize,
    channel: u32,
    tag: u32,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if check_in(reports_ptr, reports_len).is_err() {
        return -BU_HW_ERR_NULL;
    }
    if channel > 0xFFFF || tag > 0xFF {
        return -BU_HW_ERR_INVALID;
    }
    if !reports_len.is_multiple_of(HID_REPORT_LEN) {
        return -BU_HW_ERR_INVALID;
    }
    let raw = in_bytes(reports_ptr, reports_len);
    let frames: alloc::vec::Vec<alloc::vec::Vec<u8>> = raw
        .as_chunks::<HID_REPORT_LEN>().0.iter()
        .map(|c| c.to_vec())
        .collect();
    match hid_unframe(&frames, channel as u16, tag as u8) {
        Ok(payload) => write_out(out, out_len, &payload),
        Err(e) => map_err(e),
    }
}

// ---------------------------------------------------------------------------
// Multi-round Trezor `SignTx` (`SignTx` → `TxRequest`/`TxAck` loop).
// The app drives the loop (see `HardwareWallet::sign_tx_start_request`
// docs); these only build/parse single messages.
// ---------------------------------------------------------------------------

/// Open a `SignTx` session. Returns bytes written.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hw_sign_tx_start(
    dev: u32,
    coin_id: u32,
    inputs_count: u32,
    outputs_count: u32,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    let d = match device(dev) {
        Ok(d) => d,
        Err(e) => return e,
    };
    let c = match coin(coin_id) {
        Ok(c) => c,
        Err(e) => return e,
    };
    match Wallet::new(d).sign_tx_start_request(&c, inputs_count, outputs_count) {
        Ok(req) => write_out(out, out_len, &req),
        Err(e) => map_err(e),
    }
}

/// Parse one `TxRequest` into 8 bytes (`type LE32 || index LE32`,
/// `0xFFFFFFFF` = absent) in `out`. Returns 0 or negative — the packed-i64
/// idea is unworkable (any small-negative error collides with a valid pack
/// in two's complement, e.g. TXINPUT#6 packs to exactly 6 = "no-hw").
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hw_parse_tx_request(
    dev: u32,
    resp_ptr: *const u8,
    resp_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    let d = match device(dev) {
        Ok(d) => d,
        Err(e) => return e,
    };
    if check_in(resp_ptr, resp_len).is_err() {
        return -BU_HW_ERR_NULL;
    }
    match Wallet::new(d).parse_tx_request(in_bytes(resp_ptr, resp_len)) {
        Ok(r) => {
            let mut packed = [0u8; 8];
            packed[..4].copy_from_slice(&r.request_type.to_le_bytes());
            packed[4..].copy_from_slice(&r.request_index.unwrap_or(0xFFFF_FFFF).to_le_bytes());
            write_out(out, out_len, &packed)
        }
        Err(e) => map_err(e),
    }
}

/// `TXFINISHED` signature bytes. Absent field → `InvalidLength`.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hw_tx_request_signature(
    dev: u32,
    resp_ptr: *const u8,
    resp_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    let d = match device(dev) {
        Ok(d) => d,
        Err(e) => return e,
    };
    if check_in(resp_ptr, resp_len).is_err() {
        return -BU_HW_ERR_NULL;
    }
    match Wallet::new(d).parse_tx_request(in_bytes(resp_ptr, resp_len)) {
        Ok(r) => match r.signature {
            Some(s) => write_out(out, out_len, &s),
            None => -BU_HW_ERR_INVALID,
        },
        Err(e) => map_err(e),
    }
}

/// `TXFINISHED` consensus-serialized transaction. Absent → `InvalidLength`.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hw_tx_request_serialized(
    dev: u32,
    resp_ptr: *const u8,
    resp_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    let d = match device(dev) {
        Ok(d) => d,
        Err(e) => return e,
    };
    if check_in(resp_ptr, resp_len).is_err() {
        return -BU_HW_ERR_NULL;
    }
    match Wallet::new(d).parse_tx_request(in_bytes(resp_ptr, resp_len)) {
        Ok(r) => match r.serialized_tx {
            Some(s) => write_out(out, out_len, &s),
            None => -BU_HW_ERR_INVALID,
        },
        Err(e) => map_err(e),
    }
}

/// `TxAck` answering `TXMETA`. Returns bytes written.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hw_tx_ack_meta(
    version: u32,
    lock_time: u32,
    inputs_count: u32,
    outputs_count: u32,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    use crate::hw::trezor::{tx_ack_bytes, TxChunk};
    match tx_ack_bytes(&TxChunk::Meta {
        version,
        lock_time,
        inputs_count,
        outputs_count,
    }) {
        Ok(v) => write_out(out, out_len, &v),
        Err(e) => map_err(e),
    }
}

/// `TxAck` answering `TXINPUT` (`prev_hash`: 32 bytes in DISPLAY order
/// (reversed txid, as shown in explorers) — the device re-hashes the
/// streamed previous transaction and compares ("invalid prev_hash"
/// otherwise), `path`: `<u32 LE>`,
/// `amount`: previous output value in sats — required by the device;
/// `script_sig`: original scriptSig for previous transactions' inputs
/// (empty span = omit, for the input being signed);
/// `script_type`: explicit input script type (0 SPENDADDRESS … 4
/// SPENDP2SHWITNESS) — always encoded, like trezorlib.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hw_tx_ack_input(
    prev_hash_ptr: *const u8,
    prev_hash_len: usize,
    prev_index: u32,
    path_ptr: *const u8,
    path_len: usize,
    amount: u64,
    script_sig_ptr: *const u8,
    script_sig_len: usize,
    script_type: u32,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    use crate::hw::trezor::{tx_ack_bytes, TxChunk};
    if check_in(prev_hash_ptr, prev_hash_len).is_err() {
        return -BU_HW_ERR_NULL;
    }
    if prev_hash_len != 32 {
        return -BU_HW_ERR_INVALID;
    }
    let path = match decode_path(path_ptr, path_len) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let mut prev_hash = [0u8; 32];
    prev_hash.copy_from_slice(in_bytes(prev_hash_ptr, 32));
    let script_sig = if script_sig_len == 0 {
        None
    } else {
        if check_in(script_sig_ptr, script_sig_len).is_err() {
            return -BU_HW_ERR_NULL;
        }
        Some(in_bytes(script_sig_ptr, script_sig_len).to_vec())
    };
    match tx_ack_bytes(&TxChunk::Input {
        prev_hash,
        prev_index,
        path,
        amount,
        script_sig,
        script_type,
    }) {
        Ok(v) => write_out(out, out_len, &v),
        Err(e) => map_err(e),
    }
}

/// `TxAck` answering `TXOUTPUT` (pay to `address`, UTF-8, `amount` sats,
/// `script_type` explicit: 0 PAYTOADDRESS …).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hw_tx_ack_output(
    addr_ptr: *const u8,
    addr_len: usize,
    amount: u64,
    script_type: u32,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    use crate::hw::trezor::{tx_ack_bytes, TxChunk};
    if check_in(addr_ptr, addr_len).is_err() {
        return -BU_HW_ERR_NULL;
    }
    let address = in_bytes(addr_ptr, addr_len).to_vec();
    match tx_ack_bytes(&TxChunk::OutputAddr {
        address,
        amount,
        script_type,
    }) {
        Ok(v) => write_out(out, out_len, &v),
        Err(e) => map_err(e),
    }
}

/// `TxAck` answering `TXOUTPUT` (change back to `path`, `<u32 LE>`,
/// `script_type` explicit).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hw_tx_ack_change(
    path_ptr: *const u8,
    path_len: usize,
    amount: u64,
    script_type: u32,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    use crate::hw::trezor::{tx_ack_bytes, TxChunk};
    let path = match decode_path(path_ptr, path_len) {
        Ok(p) => p,
        Err(e) => return e,
    };
    match tx_ack_bytes(&TxChunk::OutputChange {
        path,
        amount,
        script_type,
    }) {
        Ok(v) => write_out(out, out_len, &v),
        Err(e) => map_err(e),
    }
}

/// `TxRequest` prev-tx hash (`details.tx_hash`, 32 bytes). Absent (current-tx
/// request) → `InvalidLength`. Lets the app fetch the right previous tx.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hw_tx_request_txhash(
    dev: u32,
    resp_ptr: *const u8,
    resp_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    let d = match device(dev) {
        Ok(d) => d,
        Err(e) => return e,
    };
    if check_in(resp_ptr, resp_len).is_err() {
        return -BU_HW_ERR_NULL;
    }
    match Wallet::new(d).parse_tx_request(in_bytes(resp_ptr, resp_len)) {
        Ok(r) => match r.tx_hash {
            Some(h) => write_out(out, out_len, &h),
            None => -BU_HW_ERR_INVALID,
        },
        Err(e) => map_err(e),
    }
}

/// `TxAck` answering `TXOUTPUT` for a PREVIOUS transaction
/// (`script_pubkey` bytes + `amount` sats → `bin_outputs`, field 3).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hw_tx_ack_bin_output(
    script_ptr: *const u8,
    script_len: usize,
    amount: u64,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    use crate::hw::trezor::{tx_ack_bytes, TxChunk};
    if check_in(script_ptr, script_len).is_err() {
        return -BU_HW_ERR_NULL;
    }
    let script_pubkey = in_bytes(script_ptr, script_len).to_vec();
    match tx_ack_bytes(&TxChunk::OutputBin {
        amount,
        script_pubkey,
    }) {
        Ok(v) => write_out(out, out_len, &v),
        Err(e) => map_err(e),
    }
}

// ---------------------------------------------------------------------------
// BitBox02 session handles: thin C ABI over `hw::bitbox` session slot.
// State machine + fail-closed semantics live there (shared with the WASM
// backend); here is only buffer/length checking and code mapping.
// Call order: hs_new(s,e) -> hs_m1 -> [app sends [h],[H]+m1] -> hs_m2(m2) ->
// [app sends [H]+m3] -> hs_m3 -> hs_split -> encrypt/decrypt.
// Framing stays app-side (see `hw::bitbox` docs): U2F-HID reports + the HWW
// arbitration layer (`[REQ_NEW] + op_msg`, `RETRY` polling, `ACK` strip),
// then OP messages with their `[OP_STATUS] + payload` replies. This ABI only
// moves the OP payloads and the Noise bytes.
// ---------------------------------------------------------------------------

use crate::hw::bitbox as bb;

fn bitbox_bytes<const N: usize>(ptr: *const u8, len: usize) -> Result<[u8; N], i32> {
    if len != N {
        return Err(-BU_HW_ERR_INVALID);
    }
    if check_in(ptr, len).is_err() {
        return Err(-BU_HW_ERR_NULL);
    }
    let mut out = [0u8; N];
    out.copy_from_slice(in_bytes(ptr, len));
    Ok(out)
}

/// Open a session: store initiator state from host static + fresh ephemeral
/// (both 32 bytes). Returns 1 (the single slot id) or negative.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hw_bitbox_hs_new(
    s_ptr: *const u8,
    s_len: usize,
    e_ptr: *const u8,
    e_len: usize,
) -> i32 {
    let s = match bitbox_bytes::<32>(s_ptr, s_len) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let e = match bitbox_bytes::<32>(e_ptr, e_len) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match bb::session_open(s, e) {
        Ok(()) => 1, // the single slot id
        Err(e) => map_err(e),
    }
}

/// Write handshake message 1 (32 B). Returns bytes written or negative.
/// FAIL-CLOSED: any error spends the session (m1 bytes are unrecoverable
/// once computed — a too-small caller buffer or a double call both mean
/// reopen; handshake setup is cheap, silent state bugs are not).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hw_bitbox_hs_m1(out: *mut u8, out_len: usize) -> i32 {
    match bb::session_m1() {
        Ok(m) => write_out(out, out_len, &m),
        Err(e) => map_err(e),
    }
}

/// Ingest handshake message 2 (96 B). Returns 0 or negative.
/// FAIL-CLOSED: the handshake mutates state before its AEAD check, so any
/// failure spends the session (slot reset to empty) — retrying crypto with
/// half-mixed state would derive wrong keys silently. Reopen on error.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hw_bitbox_hs_m2(m2_ptr: *const u8, m2_len: usize) -> i32 {
    if check_in(m2_ptr, m2_len).is_err() {
        return -BU_HW_ERR_NULL;
    }
    match bb::session_m2(in_bytes(m2_ptr, m2_len)) {
        Ok(()) => BU_HW_OK,
        Err(e) => map_err(e),
    }
}

/// Write handshake message 3 (64 B). Returns bytes written or negative.
/// FAIL-CLOSED like `hs_m2`: any error spends the session (reopen).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hw_bitbox_hs_m3(out: *mut u8, out_len: usize) -> i32 {
    match bb::session_m3() {
        Ok(m) => write_out(out, out_len, &m),
        Err(e) => map_err(e),
    }
}

/// Finish: split into transport keys (Hs → Ready). Returns 0 or negative.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hw_bitbox_hs_split() -> i32 {
    match bb::session_split() {
        Ok(()) => BU_HW_OK,
        Err(e) => map_err(e),
    }
}

/// Encrypt one post-handshake message (plaintext + 16-byte tag).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hw_bitbox_encrypt(
    pt_ptr: *const u8,
    pt_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if check_in(pt_ptr, pt_len).is_err() {
        return -BU_HW_ERR_NULL;
    }
    match bb::session_encrypt(in_bytes(pt_ptr, pt_len)) {
        Ok(v) => write_out(out, out_len, &v),
        Err(e) => map_err(e),
    }
}

/// Decrypt one post-handshake message. Wrong order/tampering/replay → error.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hw_bitbox_decrypt(
    ct_ptr: *const u8,
    ct_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if check_in(ct_ptr, ct_len).is_err() {
        return -BU_HW_ERR_NULL;
    }
    match bb::session_decrypt(in_bytes(ct_ptr, ct_len)) {
        Ok(v) => write_out(out, out_len, &v),
        Err(e) => map_err(e),
    }
}

/// Handshake hash (32 B, pairing-code source). Needs a live session.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hw_bitbox_hs_hash(out: *mut u8, out_len: usize) -> i32 {
    match bb::session_hash() {
        Ok(h) => write_out(out, out_len, &h),
        Err(e) => map_err(e),
    }
}

/// Close + wipe the session. Always succeeds (idempotent).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hw_bitbox_free() -> i32 {
    bb::session_free();
    BU_HW_OK
}

/// Build a `Request{btc_pub}` frame (UNENCRYPTED — encrypt via the session).
/// `path`: `<u32 LE>` bytes; `xpub_type`: explicit (XPUB=1/YPUB=2/ZPUB=3/…;
/// The default derives from the path purpose). Returns bytes written or negative.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hw_bitbox_btc_pub_request(
    coin_id: u32,
    path_ptr: *const u8,
    path_len: usize,
    xpub_type: u32,
    display: u32,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    use crate::hw::bitbox::{bitbox_btc_pub_request, bitbox_coin_for};
    let c = match coin(coin_id) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let profile_coin = match bitbox_coin_for(&c) {
        Ok(v) => v,
        Err(e) => return map_err(e),
    };
    let path = match decode_path(path_ptr, path_len) {
        Ok(p) => p,
        Err(e) => return e,
    };
    match bitbox_btc_pub_request(profile_coin, &path, xpub_type, display != 0) {
        Ok(req) => write_out(out, out_len, &req),
        Err(e) => map_err(e),
    }
}

/// Parse a `Response` frame into the xpub UTF-8 string. Returns bytes written.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hw_bitbox_pub_parse(
    resp_ptr: *const u8,
    resp_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    use crate::hw::bitbox::bitbox_pub_parse;
    if check_in(resp_ptr, resp_len).is_err() {
        return -BU_HW_ERR_NULL;
    }
    match bitbox_pub_parse(in_bytes(resp_ptr, resp_len)) {
        Ok(s) => write_out(out, out_len, s.as_bytes()),
        Err(e) => map_err(e),
    }
}

/// Build `Request{btc_sign_init}` (UNENCRYPTED). `path`: `<u32 LE>` bytes.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hw_bitbox_sign_init(
    coin_id: u32,
    path_ptr: *const u8,
    path_len: usize,
    simple_type: u32,
    version: u32,
    num_inputs: u32,
    num_outputs: u32,
    locktime: u32,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    use crate::hw::bitbox::{bitbox_coin_for, bitbox_sign_init_request};
    let c = match coin(coin_id) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let profile_coin = match bitbox_coin_for(&c) {
        Ok(v) => v,
        Err(e) => return map_err(e),
    };
    let path = match decode_path(path_ptr, path_len) {
        Ok(p) => p,
        Err(e) => return e,
    };
    match bitbox_sign_init_request(
        profile_coin,
        &path,
        simple_type,
        version,
        num_inputs,
        num_outputs,
        locktime,
    ) {
        Ok(req) => write_out(out, out_len, &req),
        Err(e) => map_err(e),
    }
}

/// Parse `Response{btc: BTCResponse{sign_next}}` into packed
/// `(1<<63)|(type<<32)|index` (`index` = `0xFFFFFFFF` when absent).
/// Pure parse (no device needed); top-bit convention shared with
/// `bu_hw_parse_tx_request`.
#[no_mangle]
/// Parse `Response{btc: BTCResponse{sign_next}}` into 8 bytes
/// (`type LE32 || index LE32`, `0xFFFFFFFF` = absent) in `out`.
/// Returns 0 or negative.
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hw_bitbox_sign_next_parse(
    resp_ptr: *const u8,
    resp_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    use crate::hw::bitbox::bitbox_sign_next_parse;
    if check_in(resp_ptr, resp_len).is_err() {
        return -BU_HW_ERR_NULL;
    }
    match bitbox_sign_next_parse(in_bytes(resp_ptr, resp_len)) {
        Ok(r) => {
            let mut packed = [0u8; 8];
            packed[..4].copy_from_slice(&r.request_type.to_le_bytes());
            packed[4..].copy_from_slice(&r.index.unwrap_or(0xFFFF_FFFF).to_le_bytes());
            write_out(out, out_len, &packed)
        }
        Err(e) => map_err(e),
    }
}

/// `DONE` signature bytes (64 B R||S). Absent → `InvalidLength`.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hw_bitbox_sign_next_signature(
    resp_ptr: *const u8,
    resp_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    use crate::hw::bitbox::bitbox_sign_next_parse;
    if check_in(resp_ptr, resp_len).is_err() {
        return -BU_HW_ERR_NULL;
    }
    match bitbox_sign_next_parse(in_bytes(resp_ptr, resp_len)) {
        Ok(r) => match r.signature {
            Some(s) => write_out(out, out_len, &s),
            None => -BU_HW_ERR_INVALID,
        },
        Err(e) => map_err(e),
    }
}

/// `prev_index` for PREVTX_* requests (`0xFFFFFFFF` = absent, negative = error).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hw_bitbox_sign_next_prev_index(
    resp_ptr: *const u8,
    resp_len: usize,
) -> i64 {
    use crate::hw::bitbox::bitbox_sign_next_parse;
    if check_in(resp_ptr, resp_len).is_err() {
        return -BU_HW_ERR_NULL as i64;
    }
    match bitbox_sign_next_parse(in_bytes(resp_ptr, resp_len)) {
        Ok(r) => r.prev_index.unwrap_or(0xFFFF_FFFF) as i64,
        Err(e) => map_err(e) as i64,
    }
}

/// Build `Request{btc_sign_input}` (UNENCRYPTED). `path`: `<u32 LE>` bytes.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hw_bitbox_sign_input(
    prev_hash_ptr: *const u8,
    prev_hash_len: usize,
    prev_index: u32,
    amount: u64,
    sequence: u32,
    path_ptr: *const u8,
    path_len: usize,
    script_config_index: u32,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    use crate::hw::bitbox::{bitbox_sign_ack_bytes, BitBoxTxChunk};
    if check_in(prev_hash_ptr, prev_hash_len).is_err() {
        return -BU_HW_ERR_NULL;
    }
    if prev_hash_len != 32 {
        return -BU_HW_ERR_INVALID;
    }
    let path = match decode_path(path_ptr, path_len) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let mut prev_hash = [0u8; 32];
    prev_hash.copy_from_slice(in_bytes(prev_hash_ptr, 32));
    match bitbox_sign_ack_bytes(&BitBoxTxChunk::Input {
        prev_hash,
        prev_index,
        amount,
        sequence,
        path,
        script_config_index,
    }) {
        Ok(v) => write_out(out, out_len, &v),
        Err(e) => map_err(e),
    }
}

/// Build `Request{btc_sign_output}` for an external address
/// (`output_type`: P2PKH = 1, P2WPKH = 3, …; `payload`: hash bytes).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hw_bitbox_sign_output(
    output_type: u32,
    amount: u64,
    payload_ptr: *const u8,
    payload_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    use crate::hw::bitbox::{bitbox_sign_ack_bytes, BitBoxTxChunk};
    if check_in(payload_ptr, payload_len).is_err() {
        return -BU_HW_ERR_NULL;
    }
    match bitbox_sign_ack_bytes(&BitBoxTxChunk::OutputExternal {
        output_type,
        amount,
        payload: in_bytes(payload_ptr, payload_len).to_vec(),
    }) {
        Ok(v) => write_out(out, out_len, &v),
        Err(e) => map_err(e),
    }
}

/// Build `Request{btc_sign_output}` for change (`path`: `<u32 LE>` bytes).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hw_bitbox_sign_change(
    path_ptr: *const u8,
    path_len: usize,
    amount: u64,
    script_config_index: u32,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    use crate::hw::bitbox::{bitbox_sign_ack_bytes, BitBoxTxChunk};
    let path = match decode_path(path_ptr, path_len) {
        Ok(p) => p,
        Err(e) => return e,
    };
    match bitbox_sign_ack_bytes(&BitBoxTxChunk::OutputChange {
        path,
        amount,
        script_config_index,
    }) {
        Ok(v) => write_out(out, out_len, &v),
        Err(e) => map_err(e),
    }
}

/// Build `Request{btc: BTCRequest{prevtx_init}}` (UNENCRYPTED).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hw_bitbox_sign_prevtx_init(
    version: u32,
    num_inputs: u32,
    num_outputs: u32,
    locktime: u32,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    use crate::hw::bitbox::{bitbox_sign_ack_bytes, BitBoxTxChunk};
    match bitbox_sign_ack_bytes(&BitBoxTxChunk::PrevtxInit {
        version,
        num_inputs,
        num_outputs,
        locktime,
    }) {
        Ok(v) => write_out(out, out_len, &v),
        Err(e) => map_err(e),
    }
}

/// Build `Request{btc: BTCRequest{prevtx_input}}` (UNENCRYPTED).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hw_bitbox_sign_prevtx_input(
    prev_hash_ptr: *const u8,
    prev_hash_len: usize,
    prev_index: u32,
    script_sig_ptr: *const u8,
    script_sig_len: usize,
    sequence: u32,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    use crate::hw::bitbox::{bitbox_sign_ack_bytes, BitBoxTxChunk};
    if check_in(prev_hash_ptr, prev_hash_len).is_err()
        || check_in(script_sig_ptr, script_sig_len).is_err()
    {
        return -BU_HW_ERR_NULL;
    }
    if prev_hash_len != 32 {
        return -BU_HW_ERR_INVALID;
    }
    let mut prev_hash = [0u8; 32];
    prev_hash.copy_from_slice(in_bytes(prev_hash_ptr, 32));
    match bitbox_sign_ack_bytes(&BitBoxTxChunk::PrevtxInput {
        prev_hash,
        prev_index,
        script_sig: in_bytes(script_sig_ptr, script_sig_len).to_vec(),
        sequence,
    }) {
        Ok(v) => write_out(out, out_len, &v),
        Err(e) => map_err(e),
    }
}

/// Build `Request{btc: BTCRequest{prevtx_output}}` (UNENCRYPTED).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hw_bitbox_sign_prevtx_output(
    amount: u64,
    script_ptr: *const u8,
    script_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    use crate::hw::bitbox::{bitbox_sign_ack_bytes, BitBoxTxChunk};
    if check_in(script_ptr, script_len).is_err() {
        return -BU_HW_ERR_NULL;
    }
    match bitbox_sign_ack_bytes(&BitBoxTxChunk::PrevtxOutput {
        amount,
        script: in_bytes(script_ptr, script_len).to_vec(),
    }) {
        Ok(v) => write_out(out, out_len, &v),
        Err(e) => map_err(e),
    }
}
