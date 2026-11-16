//! Authenticated Encryption with Associated Data (AEAD).

pub mod aes_gcm;
pub mod chacha20poly1305;
pub mod xsalsa20poly1305;

use crate::cipher::error::CipherResult;

pub use aes_gcm::{aes_gcm_decrypt, aes_gcm_encrypt, AesGcm};
pub use chacha20poly1305::{
    chacha20_poly1305_decrypt, chacha20_poly1305_encrypt, ChaCha20Poly1305,
};
pub use xsalsa20poly1305::{
    salsabox_beforenm, salsabox_decrypt, salsabox_encrypt, salsabox_open, salsabox_seal,
    xsalsa20_poly1305_decrypt, xsalsa20_poly1305_encrypt, SALSABOX_KEY_LEN, XSALSA_KEY_LEN,
    XSALSA_NONCE_LEN, XSALSA_TAG_LEN,
};

/// AEAD interface (buffer-oriented, Result-based).
pub trait Aead {
    /// Key length in bytes (minimum / nominal).
    const KEY_LEN: usize;
    /// Nonce length in bytes.
    const NONCE_LEN: usize;
    /// Tag length in bytes.
    const TAG_LEN: usize;

    /// Encrypt: `out` must be `plaintext.len() + TAG_LEN` (ciphertext || tag).
    fn encrypt(
        key: &[u8],
        nonce: &[u8],
        plaintext: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> CipherResult<()>;

    /// Decrypt: `ciphertext_and_tag` is ciphertext || tag.
    /// On tag failure return `AuthenticationFailed`; do not release plaintext.
    fn decrypt(
        key: &[u8],
        nonce: &[u8],
        ciphertext_and_tag: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> CipherResult<()>;
}
