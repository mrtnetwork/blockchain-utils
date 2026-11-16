#![no_main]
use libfuzzer_sys::fuzz_target;
use blockchain_utils::hw::apdu::{Apdu, ApduResponse};

fuzz_target!(|data: &[u8]| {
    // GIGO: any input must yield Ok or Err — never panic, never hang.
    // (Length-bounded parsers; no allocation without a length cap.)
    let _ = Apdu::parse(data);
    let _ = ApduResponse::parse(data);
});
