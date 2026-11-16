#![no_main]
use libfuzzer_sys::fuzz_target;
use blockchain_utils::hw::hid::{hid_unframe, LEDGER_CHANNEL, LEDGER_TAG_APDU};

fuzz_target!(|data: &[u8]| {
    // Regroup into 64-byte HID reports (pad the tail like a real driver).
    let mut reports: Vec<Vec<u8>> = data.chunks(64).map(|c| {
        let mut blk = c.to_vec();
        blk.resize(64, 0);
        blk
    }).collect();
    if reports.is_empty() {
        reports.push(vec![0u8; 64]);
    }
    let _ = hid_unframe(&reports, LEDGER_CHANNEL, LEDGER_TAG_APDU);
});
