#![no_main]
use libfuzzer_sys::fuzz_target;
use blockchain_utils::hw::noise::NoiseXX;

// Fixed roles: initiator completes m1, then the fuzzer drives message 2.
// AEAD rejects garbage with Err (no panic); a *valid* m2 would complete
// the handshake (coverage explores both).
fuzz_target!(|data: &[u8]| {
    let mut init = NoiseXX::new_initiator([0x11; 32], [0x12; 32]);
    let m1 = match init.write_message_1(b"") {
        Ok(m) => m,
        Err(_) => return,
    };
    let mut resp = NoiseXX::new_responder([0x21; 32], [0x22; 32]);
    if resp.read_message_1(&m1).is_err() {
        return;
    }
    let _m2 = resp.write_message_2(b"");
    // Fuzz the initiator's message-2 ingest (attacker-controlled bytes).
    let _ = init.read_message_2(data);
    // Responder side: attacker-controlled message 1. The device ingests
    // this from any host, so low-order/zero-contribution rejection must
    // hold on garbage too.
    let mut resp2 = NoiseXX::new_responder([0x21; 32], [0x22; 32]);
    let _ = resp2.read_message_1(data);
});
