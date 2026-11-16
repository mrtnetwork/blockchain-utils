//! Pure `no_std` random number generation matching the reference implementation.
//!
//! - [`ChaCha20Rng`]: same layout as the reference ChaCha20 PRNG
//!   (32-byte key, 64-bit block counter + 64-bit stream id, 256-byte refill).
//! - One process-wide backend ([`GlobalRng`]): starts as ChaCha20 from zero seed;
//!   can be replaced **once** via [`seed_global`] (or swapped to a custom [`RngCore`]
//!   behind the same slot).
//! - Callers that need entropy pass a 32-byte seed (local ChaCha) or `None` (global).

/// Minimal RNG trait (`no_std`).
pub trait Rng {
    fn fill_bytes(&mut self, dest: &mut [u8]);

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }
}

/// Object-safe RNG for the global slot.
pub trait RngCore: Send {
    fn fill_bytes(&mut self, dest: &mut [u8]);
}

impl<T: Rng + Send> RngCore for T {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        Rng::fill_bytes(self, dest);
    }
}

// ── ChaCha20Rng  ───────────────────────────────────────────

/// Deterministic ChaCha20 PRNG matching the reference implementation.
///
/// Refill: 4×64-byte blocks with counter = `_block_counter .. +3`,
/// nonce layout = `counter_u64_le || stream_id_u64_le` (16 bytes total),
/// `nonceInplaceCounterLength = 8` (first 8 bytes are the per-block counter).
pub struct ChaCha20Rng {
    key: [u8; 32],
    stream_id: u64,
    block_counter: u64,
    buffer: [u8; 256],
    buffer_offset: usize,
}

impl ChaCha20Rng {
    /// Ref: `ChaCha20Rng(seed, {streamId: 0})`.
    pub fn new(seed: &[u8; 32], stream_id: u64) -> Self {
        Self {
            key: *seed,
            stream_id,
            block_counter: 0,
            buffer: [0u8; 256],
            buffer_offset: 256, // force refill
        }
    }

    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self::new(seed, 0)
    }

    #[inline]
    fn rotl32(x: u32, n: u32) -> u32 {
        x.rotate_left(n)
    }

    fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        s[a] = s[a].wrapping_add(s[b]);
        s[d] = Self::rotl32(s[d] ^ s[a], 16);
        s[c] = s[c].wrapping_add(s[d]);
        s[b] = Self::rotl32(s[b] ^ s[c], 12);
        s[a] = s[a].wrapping_add(s[b]);
        s[d] = Self::rotl32(s[d] ^ s[a], 8);
        s[c] = s[c].wrapping_add(s[d]);
        s[b] = Self::rotl32(s[b] ^ s[c], 7);
    }

    /// One 64-byte ChaCha20 block. `counter` is the 64-bit LE value in the first
    /// 8 bytes of the 16-byte nonce/counter region (inplace counter).
    fn block(key: &[u8; 32], counter: u64, stream_id: u64) -> [u8; 64] {
        let mut state = [0u32; 16];
        // "expand 32-byte k"
        state[0] = 0x6170_7865;
        state[1] = 0x3320_646e;
        state[2] = 0x7962_2d32;
        state[3] = 0x6b20_6574;
        for i in 0..8 {
            state[4 + i] =
                u32::from_le_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
        }
        // counter_u64_le → state[12], state[13]
        let c = counter.to_le_bytes();
        state[12] = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
        state[13] = u32::from_le_bytes([c[4], c[5], c[6], c[7]]);
        // stream_id_u64_le → state[14], state[15]
        let s = stream_id.to_le_bytes();
        state[14] = u32::from_le_bytes([s[0], s[1], s[2], s[3]]);
        state[15] = u32::from_le_bytes([s[4], s[5], s[6], s[7]]);

        // Match `ChaCha20._core` diagonal rounds exactly:
        // RFC 7539 uses (2,7,12,13)/(3,4,13,14); reference uses (2,7,8,13)/(3,4,9,14).
        // ML-DSA keygen byte-identity depends on this reference layout.
        let mut working = state;
        for _ in 0..10 {
            Self::quarter_round(&mut working, 0, 4, 8, 12);
            Self::quarter_round(&mut working, 1, 5, 9, 13);
            Self::quarter_round(&mut working, 2, 6, 10, 14);
            Self::quarter_round(&mut working, 3, 7, 11, 15);
            Self::quarter_round(&mut working, 0, 5, 10, 15);
            Self::quarter_round(&mut working, 1, 6, 11, 12);
            Self::quarter_round(&mut working, 2, 7, 8, 13);
            Self::quarter_round(&mut working, 3, 4, 9, 14);
        }
        for i in 0..16 {
            working[i] = working[i].wrapping_add(state[i]);
        }
        let mut out = [0u8; 64];
        for i in 0..16 {
            out[i * 4..i * 4 + 4].copy_from_slice(&working[i].to_le_bytes());
        }
        out
    }

    fn refill(&mut self) {
        // 4 blocks, counters block_counter .. block_counter+3
        for i in 0..4 {
            let b = Self::block(&self.key, self.block_counter + i as u64, self.stream_id);
            self.buffer[i * 64..(i + 1) * 64].copy_from_slice(&b);
        }
        self.block_counter = self.block_counter.wrapping_add(4);
        self.buffer_offset = 0;
    }

    /// `nextBytes(length)` — may over-consume internally to 4-byte align.
    pub fn next_bytes(&mut self, length: usize, out: &mut [u8]) {
        assert_eq!(out.len(), length);
        let mut written = 0;
        let fil = length + ((4 - (length % 4)) % 4);
        while written < fil {
            if self.buffer_offset >= 256 {
                self.refill();
            }
            let remaining = 256 - self.buffer_offset;
            let take = core::cmp::min(remaining, fil - written);
            let to_copy = if written + take <= length {
                take
            } else {
                length.saturating_sub(written)
            };
            if to_copy > 0 {
                out[written..written + to_copy].copy_from_slice(
                    &self.buffer[self.buffer_offset..self.buffer_offset + to_copy],
                );
            }
            self.buffer_offset += take;
            written += take;
        }
    }
}

impl Rng for ChaCha20Rng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut offset = 0;
        while offset < dest.len() {
            if self.buffer_offset >= 256 {
                self.refill();
            }
            let available = 256 - self.buffer_offset;
            let needed = dest.len() - offset;
            let take = core::cmp::min(available, needed);
            dest[offset..offset + take]
                .copy_from_slice(&self.buffer[self.buffer_offset..self.buffer_offset + take]);
            self.buffer_offset += take;
            offset += take;
        }
    }
}

// ── Global backend ──────────────────────────────────────────────────────────

#[cfg(feature = "std")]
mod global {
    use super::*;
    use std::sync::Mutex;

    struct State {
        seeded: bool,
        rng: ChaCha20Rng,
    }

    static GLOBAL: Mutex<State> = Mutex::new(State {
        seeded: false,
        rng: ChaCha20Rng {
            key: [0u8; 32],
            stream_id: 0,
            block_counter: 0,
            buffer: [0u8; 256],
            buffer_offset: 256,
        },
    });

    pub fn seed_global(seed: &[u8; 32]) -> bool {
        let mut g = GLOBAL.lock().unwrap_or_else(|e| e.into_inner());
        if g.seeded {
            return false;
        }
        g.rng = ChaCha20Rng::from_seed(seed);
        g.seeded = true;
        true
    }

    pub fn is_global_seeded() -> bool {
        GLOBAL.lock().map(|g| g.seeded).unwrap_or(false)
    }

    pub fn global_fill(dest: &mut [u8]) {
        let mut g = GLOBAL.lock().unwrap_or_else(|e| e.into_inner());
        Rng::fill_bytes(&mut g.rng, dest);
    }
}

#[cfg(not(feature = "std"))]
mod global {
    use super::*;
    /// Without `std`, no process-wide mutable state (no_std + forbid unsafe).
    /// `seed_global` is a no-op that returns false; fills use a fresh zero-seeded ChaCha.
    pub fn seed_global(_seed: &[u8; 32]) -> bool {
        false
    }
    pub fn is_global_seeded() -> bool {
        false
    }
    pub fn global_fill(dest: &mut [u8]) {
        let mut rng = ChaCha20Rng::from_seed(&[0u8; 32]);
        Rng::fill_bytes(&mut rng, dest);
    }
}

pub use global::{global_fill, is_global_seeded, seed_global};

/// Resolve randomness: if `seed` is `Some(32)`, use a **local** ChaCha20Rng;
/// if `None`, use the **global** backend.
pub fn fill_from_seed_or_global(seed: Option<&[u8; 32]>, dest: &mut [u8]) {
    match seed {
        Some(s) => {
            let mut rng = ChaCha20Rng::from_seed(s);
            Rng::fill_bytes(&mut rng, dest);
        }
        None => global_fill(dest),
    }
}

/// One-shot fill from a seed (local ChaCha, does not touch global).
pub fn fill_bytes_with_seed(seed: &[u8; 32], dest: &mut [u8]) {
    fill_from_seed_or_global(Some(seed), dest);
}

/// Produce 32 random bytes: from optional seed or global.
pub fn random_32(seed: Option<&[u8; 32]>) -> [u8; 32] {
    let mut out = [0u8; 32];
    fill_from_seed_or_global(seed, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_local() {
        let seed = [0x42u8; 32];
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        fill_bytes_with_seed(&seed, &mut a);
        fill_bytes_with_seed(&seed, &mut b);
        assert_eq!(a, b);
    }

    #[test]
    fn different_seeds_differ() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        fill_bytes_with_seed(&[1u8; 32], &mut a);
        fill_bytes_with_seed(&[2u8; 32], &mut b);
        assert_ne!(a, b);
    }

    #[test]
    fn zero_seed_produces_output() {
        let mut buf = [0u8; 64];
        fill_bytes_with_seed(&[0u8; 32], &mut buf);
        // ChaCha of zeros is not all-zero keystream after expand
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn long_fill() {
        let mut buf = [0u8; 300];
        let mut rng = ChaCha20Rng::from_seed(&[9u8; 32]);
        Rng::fill_bytes(&mut rng, &mut buf);
        assert!(buf.iter().any(|&b| b != 0));
    }

    fn h32(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Byte-compat with `ChaCha20Rng` + `QuickCrypto.generateRandom`
    /// (seed 12), including the 4-byte-roundup consumption quirk.
    /// Oracle: reference RNG vectors.
    #[test]
    fn chacha20_stream_compat() {
        let seed = [12u8; 32];
        let mut rng = ChaCha20Rng::from_seed(&seed);
        let mut out64 = [0u8; 64];
        rng.next_bytes(64, &mut out64);
        assert_eq!(
            out64.to_vec(),
            h32("ae55271b86e72e4ab2cbf25967641a6c33cdea11e2d979e22d88c158c455ac1595eef9959d0a8789d984ea1c7786b0bf720af26fc7e528d628cb5d4cb62da256")
        );
        let mut out32 = [0u8; 32];
        rng.next_bytes(32, &mut out32);
        assert_eq!(
            out32.to_vec(),
            h32("fd54ea4fc93be38253e3a2405e8335be58c8a62d848df03445cb0356f6986115")
        );
        let mut out43 = [0u8; 43];
        rng.next_bytes(43, &mut out43);
        assert_eq!(
            out43.to_vec(),
            h32("aa3f43eeea5e1bbd16a677be72ff9bb7ccd9d11bd8f88c4dca667a1d4978f7bf07e0c8b9595d00ffda4019")
        );
        // The 43-length draw consumed 44 stream bytes (quirk); next draw must match.
        let mut out32b = [0u8; 32];
        rng.next_bytes(32, &mut out32b);
        assert_eq!(
            out32b.to_vec(),
            h32("a78b777bd09bd2c188a3a8d46d9be3586cd1b479e49630bdd02644e9e8507262")
        );
    }
}
