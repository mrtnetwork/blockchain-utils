//! Global RNG seeding for wasm-bindgen.
#![cfg(all(feature = "wasm", feature = "alloc"))]

use crate::rng::{global_fill, is_global_seeded, seed_global};
use wasm_bindgen::prelude::*;

/// Seed global ChaCha20 once with 32 bytes. Returns true if accepted, false if already seeded.
#[wasm_bindgen(js_name = rngSeed)]
pub fn wasm_rng_seed(seed: &[u8]) -> bool {
    if seed.len() != 32 {
        return false;
    }
    let mut s = [0u8; 32];
    s.copy_from_slice(seed);
    seed_global(&s)
}

/// True once the global RNG has been seeded.
#[wasm_bindgen(js_name = rngIsSeeded)]
pub fn wasm_rng_is_seeded() -> bool {
    is_global_seeded()
}

/// Fill `len` bytes from the global RNG.
#[wasm_bindgen(js_name = rngFill)]
pub fn wasm_rng_fill(len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    global_fill(&mut out);
    out
}
