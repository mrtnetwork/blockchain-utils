//! Block cipher trait.

use super::error::CipherResult;

/// Fixed-size block cipher (e.g. AES).
pub trait BlockCipher: Sized {
    /// Block size in bytes (16 for AES).
    const BLOCK_SIZE: usize;

    /// Construct from raw key bytes. Returns error if key length is invalid.
    fn new(key: &[u8]) -> CipherResult<Self>;

    /// Encrypt one block in place. `block.len()` must equal `BLOCK_SIZE`.
    fn encrypt_block(&self, block: &mut [u8]) -> CipherResult<()>;

    /// Decrypt one block in place. `block.len()` must equal `BLOCK_SIZE`.
    fn decrypt_block(&self, block: &mut [u8]) -> CipherResult<()>;
}
