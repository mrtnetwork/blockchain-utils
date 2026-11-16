#![no_main]
use libfuzzer_sys::fuzz_target;
use blockchain_utils::hw::trezor::{proto_decode, trezor_unframe, varint_decode};

fuzz_target!(|data: &[u8]| {
    // Frame path: regroup raw bytes into 63-byte Trezor chunks.
    let chunks: Vec<Vec<u8>> = data.chunks(63).map(|c| c.to_vec()).collect();
    if let Ok((_t, body)) = trezor_unframe(&chunks) {
        let _ = proto_decode(&body);
    }
    let _ = proto_decode(data);
    let _ = varint_decode(data);
});
