//! Block ciphers, stream ciphers, modes, and padding.
//!
//! Pure `no_std`, zero-dependency.

pub mod aes;
pub mod block;
pub mod chacha20;
pub mod error;
#[cfg(feature = "alloc")]
pub mod ff1;
pub mod modes;
pub mod padding;
pub mod poly1305;

pub use aes::Aes;
pub use block::BlockCipher;
pub use chacha20::{
    chacha20_block, chacha20_block_nc, chacha20_xor, stream_xor, stream_xor_ietf,
    BLOCK_LEN as CHACHA20_BLOCK_LEN, KEY_LEN as CHACHA20_KEY_LEN, NONCE_LEN as CHACHA20_NONCE_LEN,
    NONCE_LEN_8 as CHACHA20_NONCE_LEN_8,
};
pub use error::{CipherError, CipherResult};
pub use modes::cbc::{
    aes_cbc_decrypt, aes_cbc_decrypt_padded, aes_cbc_encrypt, aes_cbc_encrypt_padded,
};
pub use modes::ctr::aes_ctr;
pub use modes::ecb::{
    aes_ecb_decrypt, aes_ecb_decrypt_padded, aes_ecb_encrypt, aes_ecb_encrypt_padded,
};
pub use padding::{
    pad, padded_len, pkcs7_pad, pkcs7_padded_len, pkcs7_unpad, pkcs7_unpad_into, unpad, unpad_into,
    PaddingAlgorithm,
};
pub use poly1305::{poly1305, Poly1305, KEY_LEN as POLY1305_KEY_LEN, TAG_LEN as POLY1305_TAG_LEN};

#[cfg(feature = "alloc")]
pub use ff1::{
    ff1_decrypt_binary, ff1_decrypt_flexible, ff1_encrypt_binary, ff1_encrypt_flexible, Ff1Error,
    Ff1Result,
};
