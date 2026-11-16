#![no_main]
use libfuzzer_sys::fuzz_target;
use blockchain_utils::hw::ur::{ur_decode_single, UrAssembler};

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    // Single decode (all errors are values, never panics).
    let _ = ur_decode_single(&s);
    // Assembler: whole input as one shard, then as a duplicate feed.
    let mut asm = UrAssembler::new();
    if let Ok(first) = asm.feed(&s) {
        let _ = first;
        let _ = asm.feed(&s);
    }
});
