//! Device discovery data: which USB devices *might* be hardware wallets.
//!
//! Pure data, zero-dep. Actual enumeration (`hidapi` / `rusb` / WebHID)
//! lives in the app layer — this table only filters candidates by vendor.
//! PIDs vary per model/firmware, so match on VID, then **probe**: open the
//! candidate, send the family's harmless status request with a short
//! timeout, close. Timeout / disconnect / wrong answer = not alive —
//! never assert, never panic, just skip it.
//!
//! PIDs change with firmware; extend from your own `lsusb` output.

/// One USB vendor/product pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct UsbId {
    pub vid: u16,
    pub pid: u16,
}

/// Known vendor ids → wallet family. PID is deliberately ignored.
pub const KNOWN_VIDS: &[(u16, &str)] = &[
    (0x2C97, "ledger"), // Ledger Nano S / S Plus / X / Flex / Stax
    (0x534C, "trezor"), // Trezor Model One
    (0x1209, "trezor"), // Trezor T / Safe 3 / 5 / 7 (also some OneKey)
    (0x2B24, "trezor"), // KeepKey (Trezor-protocol family)
    (0x03EB, "bitbox"), // BitBox02 (Atmel VID)
];

/// Family name for a vendor id, if it looks like a wallet.
pub const fn family_for_vid(vid: u16) -> Option<&'static str> {
    let mut i = 0usize;
    while i < KNOWN_VIDS.len() {
        if KNOWN_VIDS[i].0 == vid {
            return Some(KNOWN_VIDS[i].1);
        }
        i += 1;
    }
    None
}

/// True when `vid` belongs to a known wallet vendor (probe to confirm).
pub const fn is_candidate_vid(vid: u16) -> bool {
    family_for_vid(vid).is_some()
}
