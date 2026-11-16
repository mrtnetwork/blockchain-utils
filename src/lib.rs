//! # blockchain-utils
//!
//! Pure `no_std`, **zero-dependency** cryptographic and blockchain utilities
//! with a focus on constant-time operations where secrets are involved.
//!
//! ## Design goals
//!
//! - `#![no_std]` compatible (works on bare metal and `wasm32-unknown-unknown`)
//! - Zero external dependencies
//! - Constant-time primitives for secret data
//! - Clean, stable API suitable for later FFI / WASM interop
//! - Thorough unit tests
//!
//! ## Feature flags
//!
//! - `alloc` (default) — enables APIs that require allocation
//! - `ffi` — C ABI for native (`connector`); core crypto modules unchanged
//! - `wasm` — wasm-bindgen exports for web (`connector::wasm`); enables `std`
//!
//! ## Module overview
//!
//! | Module       | Status          | Description                          |
//! |--------------|-----------------|--------------------------------------|
//! | `error`      | Stable          | Crate-wide error type                |
//! | `ct`         | Stable          | Constant-time helpers                |
//! | `bytes`      | Stable          | Byte utilities                       |
//! | `rng`        | Stable          | Deterministic ChaCha20 RNG           |
//! | `hash`       | Stable          | SHA-2, Keccak, Blake2, HMAC, …       |
//! | `field`      | Stable          | Prime fields                         |
//! | `curve`      | Stable          | secp256k1, Ed25519, BLS, Pasta, …    |
//! | `signature`  | Stable          | ECDSA, Schnorr, EdDSA, BLS, PQ       |
//! | `encoding`   | Stable          | Hex                                |
//! | `musig2`     | Stable          | BIP-327 MuSig2                       |
//! | `frost`      | Stable          | RFC 9591 FROST (secp256k1, Ed25519)  |
//! | `connector`  | Feature `ffi`/`wasm` | C ABI / wasm-bindgen exports      |

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(any(feature = "ffi", feature = "wasm")), forbid(unsafe_code))]
#![warn(rust_2018_idioms)]
#![warn(dead_code)]
#![warn(unused_imports)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod bytes;
pub mod ct;
pub mod error;
pub mod rng;

pub mod aead;
pub mod cipher;
pub mod curve;
pub mod encoding;
pub mod field;
pub mod hash;
pub mod multicore;
pub mod signature;

pub mod keys;
pub mod merlin;
#[cfg(feature = "alloc")]
pub mod musig2;
#[cfg(feature = "alloc")]
pub mod frost;
#[cfg(feature = "alloc")]
pub mod dkls23;
pub mod schnorrkel;
#[cfg(feature = "solana-zk")]
pub mod solana_zk;
pub mod strobe;

#[cfg(any(
    feature = "groth16",
    feature = "orchard-halo2",
    feature = "zcash-incrementalmerkle"
))]
pub mod zk;

#[cfg(feature = "monero")]
pub mod monero;

#[cfg(any(feature = "ffi", feature = "wasm"))]
pub mod connector;

#[cfg(feature = "hw")]
pub mod hw;

// Re-export the most commonly used items at the crate root for convenience.
pub use error::{Error, Result};

pub use encoding::hex;
#[cfg(feature = "alloc")]
pub use encoding::{decode as hex_decode, encode as hex_encode};

pub use aead::{
    aes_gcm_decrypt, aes_gcm_encrypt, chacha20_poly1305_decrypt, chacha20_poly1305_encrypt,
    salsabox_beforenm, salsabox_decrypt, salsabox_encrypt, salsabox_open, salsabox_seal,
    xsalsa20_poly1305_decrypt, xsalsa20_poly1305_encrypt, Aead, AesGcm, ChaCha20Poly1305,
    SALSABOX_KEY_LEN, XSALSA_KEY_LEN, XSALSA_NONCE_LEN, XSALSA_TAG_LEN,
};
pub use bytes::{secure_eq, try_into_array, zeroize};
pub use cipher::{
    aes_cbc_decrypt, aes_cbc_decrypt_padded, aes_cbc_encrypt, aes_cbc_encrypt_padded, aes_ctr,
    aes_ecb_decrypt, aes_ecb_decrypt_padded, aes_ecb_encrypt, aes_ecb_encrypt_padded, chacha20_xor,
    pkcs7_pad, pkcs7_unpad, stream_xor, stream_xor_ietf, Aes, BlockCipher, CipherError,
    CipherResult, PaddingAlgorithm,
};
pub use ct::{ct_assign_bytes, ct_eq, ct_eq_bool, ct_select_u8, ct_verify, ct_zeroize};
pub use curve::{
    BlsG1Point, BlsG2Point, CurveError, CurvePoint, CurveResult, Ed25519Point, FieldElement,
    JubJubPoint, PallasPoint, RistrettoPoint, Scalar, Secp256k1Point, Secp256r1Point, VestaPoint,
};
pub use rng::{
    fill_bytes_with_seed, fill_from_seed_or_global, global_fill, is_global_seeded, random_32,
    seed_global, ChaCha20Rng, Rng, RngCore,
};
