//! Deterministic field RNGs for proof blinding (no globals, WASM-safe).
//!
//! - `FieldRng`: SplitMix64-based fallback (kept for tooling).
//! - `ChaChaBlindRng`: wraps the crate-level `ChaCha20Rng`, which is
//!   byte-identical to the reference's `ChaCha20Rng` (same seed → same stream).
//!   The reference draws one 64-byte sample per `PallasNativeFp.random()` via
//!   `fromBytes64`, mirrored by `BlindRng::next_pallas`.
//! - `BlindRng`: uniform interface threaded through prover stages so the
//!   draw ORDER matches the reference implementation.

use crate::zk::orchard_halo2::field::PallasFp;

pub trait BlindRng {
    fn next_pallas(&mut self) -> PallasFp;
}

pub struct FieldRng {
    state: u64,
}

impl FieldRng {
    pub fn new(seed: u64) -> Self {
        Self { state: seed | 1 }
    }

    /// Seed from 32 LE bytes (e.g. a transcript challenge).
    pub fn seed_from_le(bytes: &[u8; 32]) -> Self {
        let mut s: u64 = 0x9e3779b97f4a7c15;
        for (i, b) in bytes.iter().enumerate() {
            s = s.wrapping_add(
                (*b as u64)
                    .wrapping_mul(0xbf58476d1ce4e5b9)
                    .wrapping_add(i as u64),
            );
            s = splitmix_step(s);
        }
        Self { state: s | 1 }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = splitmix_step(self.state);
        self.state
    }
}

impl BlindRng for FieldRng {
    fn next_pallas(&mut self) -> PallasFp {
        let mut bytes = [0u8; 64];
        for chunk in bytes.chunks_mut(8) {
            chunk.copy_from_slice(&self.next_u64().to_le_bytes());
        }
        // from_le_bytes64_wrapping is infallible for 64 bytes; unwrap safely.
        match PallasFp::from_le_bytes64_wrapping(&bytes) {
            Ok(v) => v,
            Err(_) => PallasFp::one(),
        }
    }
}

fn splitmix_step(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9e3779b97f4a7c15);
    let mut r = z;
    r = (r ^ (r >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    r = (r ^ (r >> 27)).wrapping_mul(0x94d049bb133111eb);
    r ^ (r >> 31)
}

/// ChaCha-backed blinding RNG (deterministic stream).
pub struct ChaChaBlindRng {
    inner: crate::rng::ChaCha20Rng,
}

impl ChaChaBlindRng {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            inner: crate::rng::ChaCha20Rng::from_seed(seed),
        }
    }

    /// Skip `n` bytes (fast-forward past witness-generation draws).
    pub fn skip_bytes(&mut self, n: usize) {
        let mut chunk = [0u8; 256];
        let mut left = n;
        while left > 0 {
            let take = core::cmp::min(left, 256);
            self.inner.next_bytes(take, &mut chunk[..take]);
            left -= take;
        }
    }
}

impl BlindRng for ChaChaBlindRng {
    fn next_pallas(&mut self) -> PallasFp {
        let mut bytes = [0u8; 64];
        self.inner.next_bytes(64, &mut bytes);
        match PallasFp::from_le_bytes64_wrapping(&bytes) {
            Ok(v) => v,
            Err(_) => PallasFp::one(),
        }
    }
}
