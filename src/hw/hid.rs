//! HID report chunking (Ledger + Trezor + BitBox02 USB framing).
//!
//! Ledger HID: `channel(2) || tag(1: 0x05 cmd) || seq(2) || len(2) || data`,
//! 64-byte reports. Trezor framing adds `?##` magic — see `trezor::`.
//! Pure codec; report transport stays in `Transport`.

use crate::error::{Error, Result};

use alloc::vec::Vec;

/// HID report size (USB interrupt).
pub const HID_REPORT_LEN: usize = 64;
/// Ledger HID channel id (default).
pub const LEDGER_CHANNEL: u16 = 0x0101;
/// Ledger HID command tag.
pub const LEDGER_TAG_APDU: u8 = 0x05;

/// Chunk `payload` into 64-byte HID reports (Ledger style).
pub fn hid_frame(payload: &[u8], channel: u16, tag: u8) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut seq: u16 = 0;
    let first_capacity = HID_REPORT_LEN - 7; // ch(2)+tag(1)+seq(2)+len(2)
    let next_capacity = HID_REPORT_LEN - 5; // ch(2)+tag(1)+seq(2)
                                            // first block carries total length
    let mut first = Vec::with_capacity(HID_REPORT_LEN);
    first.extend_from_slice(&channel.to_be_bytes());
    first.push(tag);
    first.extend_from_slice(&seq.to_be_bytes());
    first.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    let take = core::cmp::min(first_capacity, payload.len());
    first.extend_from_slice(&payload[..take]);
    while first.len() < HID_REPORT_LEN {
        first.push(0);
    }
    out.push(first);
    let mut off = take;
    seq += 1;
    while off < payload.len() {
        let mut blk = Vec::with_capacity(HID_REPORT_LEN);
        blk.extend_from_slice(&channel.to_be_bytes());
        blk.push(tag);
        blk.extend_from_slice(&seq.to_be_bytes());
        let take = core::cmp::min(next_capacity, payload.len() - off);
        blk.extend_from_slice(&payload[off..off + take]);
        while blk.len() < HID_REPORT_LEN {
            blk.push(0);
        }
        out.push(blk);
        off += take;
        seq += 1;
    }
    out
}

/// Reassemble HID reports into one payload. Validates channel/tag/sequence.
pub fn hid_unframe(reports: &[Vec<u8>], channel: u16, tag: u8) -> Result<Vec<u8>> {
    if reports.is_empty() {
        return Err(Error::InvalidLength);
    }
    let first = &reports[0];
    if first.len() != HID_REPORT_LEN {
        return Err(Error::InvalidLength);
    }
    if u16::from_be_bytes([first[0], first[1]]) != channel || first[2] != tag {
        return Err(Error::InvalidEncoding);
    }
    if u16::from_be_bytes([first[3], first[4]]) != 0 {
        return Err(Error::InvalidEncoding);
    }
    let total = u16::from_be_bytes([first[5], first[6]]) as usize;
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&first[7..core::cmp::min(7 + total, HID_REPORT_LEN)]);
    for (k, blk) in reports.iter().enumerate().skip(1) {
        if blk.len() != HID_REPORT_LEN {
            return Err(Error::InvalidLength);
        }
        if u16::from_be_bytes([blk[0], blk[1]]) != channel || blk[2] != tag {
            return Err(Error::InvalidEncoding);
        }
        if u16::from_be_bytes([blk[3], blk[4]]) != k as u16 {
            return Err(Error::InvalidEncoding);
        }
        let need = total - out.len();
        let take = core::cmp::min(HID_REPORT_LEN - 5, need);
        out.extend_from_slice(&blk[5..5 + take]);
    }
    if out.len() != total {
        return Err(Error::InvalidLength);
    }
    Ok(out)
}
