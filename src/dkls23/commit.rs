//! Hash commitments: `com = H(salt || msg)` with a 64-byte salt.
//!
//! Follows the paper's ideal commitment functionality: the committer
//! broadcasts `com` first, then later reveals `(msg, salt)`. The salt is
//! `2·lambda_c` bits (`lambda_c = 256`), drawn from an explicit
//! [`ChaCha20Rng`] so WASM/no_std callers stay deterministic.

use super::digest::tagged_hash;
use super::error::{DklsError, DklsResult};
use super::oracle::TAG_COMMITMENT;
use crate::ct::ct_eq;
use crate::rng::{ChaCha20Rng, Rng};
use alloc::vec::Vec;

/// Salt length in bytes (`2 * 256 bits`).
pub const SALT_LEN: usize = 64;
/// Commitment length in bytes (SHA-256).
pub const COMMIT_LEN: usize = 32;

/// A commitment opening (message + salt). The salt is wiped on drop.
pub struct Opening {
    msg: Vec<u8>,
    salt: [u8; SALT_LEN],
}

impl Opening {
    /// Reveal the committed message.
    pub fn msg(&self) -> &[u8] {
        &self.msg
    }
    /// Reveal the salt.
    pub fn salt(&self) -> &[u8; SALT_LEN] {
        &self.salt
    }
}

impl Drop for Opening {
    fn drop(&mut self) {
        crate::bytes::zeroize(&mut self.salt);
        for b in self.msg.iter_mut() {
            *b = 0;
        }
    }
}

/// Commit to `msg`: draw a fresh salt and hash `(salt, msg)`.
pub fn commit(rng: &mut ChaCha20Rng, msg: &[u8]) -> ([u8; COMMIT_LEN], Opening) {
    let mut salt = [0u8; SALT_LEN];
    rng.fill_bytes(&mut salt);
    let com = tagged_hash(TAG_COMMITMENT, &[&salt, msg]);
    (com, Opening { msg: msg.to_vec(), salt })
}

/// Verify a `(msg, salt)` opening against `com` (constant-time compare).
pub fn verify(com: &[u8; COMMIT_LEN], msg: &[u8], salt: &[u8]) -> DklsResult<()> {
    if salt.len() != SALT_LEN {
        return Err(DklsError::InvalidLength);
    }
    let expect = tagged_hash(TAG_COMMITMENT, &[salt, msg]);
    if ct_eq(com, &expect) == 1 {
        Ok(())
    } else {
        Err(DklsError::BadCommitment)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed(&[7u8; 32])
    }

    #[test]
    fn roundtrip() {
        let mut r = rng();
        let (com, open) = commit(&mut r, b"hello dkls23");
        verify(&com, open.msg(), open.salt()).unwrap();
    }

    #[test]
    fn tamper_fails() {
        let mut r = rng();
        let (com, open) = commit(&mut r, b"msg");
        assert_eq!(verify(&com, b"other", open.salt()), Err(DklsError::BadCommitment));
        let mut bad = *open.salt();
        bad[0] ^= 1;
        assert_eq!(verify(&com, open.msg(), &bad), Err(DklsError::BadCommitment));
        assert_eq!(verify(&com, open.msg(), &[0u8; 3]), Err(DklsError::InvalidLength));
    }

    #[test]
    fn salts_differ() {
        let mut r = rng();
        let (c1, _) = commit(&mut r, b"same");
        let (c2, _) = commit(&mut r, b"same");
        assert_ne!(c1, c2);
    }
}
