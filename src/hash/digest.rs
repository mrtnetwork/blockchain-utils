//! Common digest interface (Streaming + one-shot API).
//!
//! Every concrete hash implements this trait so callers can write generic code
//! and so HMAC / HKDF / PBKDF2 can work uniformly over all hashes.

use super::error::{HashError, HashResult};

/// Streaming + one-shot hash interface.
///
/// Designed for ergonomic use while
/// remaining fully `no_std` and allocation-free.
pub trait Digest: Sized {
    /// Output size in bytes.
    const OUTPUT_SIZE: usize;
    /// Internal block size in bytes (used by HMAC).
    const BLOCK_SIZE: usize;
    /// Human-readable algorithm name.
    const NAME: &'static str;

    /// Create a fresh hasher.
    fn new() -> Self;

    /// Reset to the initial state (equivalent to `new()`).
    fn reset(&mut self);

    /// Absorb more input data.
    fn update(&mut self, data: &[u8]);

    /// Finalize and write the digest into `out`.
    ///
    /// `out` must be at least `OUTPUT_SIZE` bytes.
    /// After this call the hasher should not be reused unless `reset` is called.
    fn finalize_into(self, out: &mut [u8]) -> HashResult<()>;

    /// Finalize and return a fixed-size array.
    ///
    /// Default implementation allocates a stack buffer of `OUTPUT_SIZE`.
    fn finalize_array(self) -> HashResult<[u8; 64]> {
        // 64 is the largest digest we currently support (SHA-512 / BLAKE2b).
        // Concrete types that need a tighter array should override.
        let mut buf = [0u8; 64];
        if Self::OUTPUT_SIZE > 64 {
            return Err(HashError::Unsupported);
        }
        self.finalize_into(&mut buf[..Self::OUTPUT_SIZE])?;
        Ok(buf)
    }

    /// One-shot hash: create, update, finalize into `out`.
    fn hash_into(data: &[u8], out: &mut [u8]) -> HashResult<()> {
        if out.len() < Self::OUTPUT_SIZE {
            return Err(HashError::OutputTooSmall);
        }
        let mut h = Self::new();
        h.update(data);
        h.finalize_into(out)
    }
}

/// Marker for digests that can be used as the underlying PRF for HMAC.
pub trait HmacCapable: Digest {}

/// Serializable intermediate hash state (`HashState` / `SerializableHash`).
pub trait HashState: Clone {
    /// Securely wipe this state (best-effort; no external zeroize crate).
    fn clean(&mut self);
}

/// Hash algorithms that can snapshot / restore intermediate state.
///
/// mirrors the reference implementation
/// `saveState` / `restoreState` / `cleanSavedState`.
pub trait SerializableHash {
    /// Snapshot type.
    type State: HashState;

    /// Capture current intermediate state (before finalize).
    fn save_state(&self) -> Self::State;

    /// Restore a previously saved state.
    fn restore_state(&mut self, saved: &Self::State);

    /// Wipe a saved state object.
    fn clean_saved_state(saved: &mut Self::State) {
        saved.clean();
    }
}
