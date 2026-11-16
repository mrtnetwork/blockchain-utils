//! RFC 9591 FROST threshold Schnorr signing (two-round protocol).
//!
//! Domains match the RFC ciphersuite sections:
//! - [`k1`]: FROST(secp256k1, SHA-256) — Section 6.5, vectors E.5.
//! - [`ed`]: FROST(Ed25519, SHA-512) — Section 6.1, vectors E.1.
//!
//! Wire formats are byte-oriented (`[u8; N]` + small structs) so the
//! FFI/WASM connectors can expose them without extra translation:
//! - scalars: 32 bytes (big-endian secp256k1, little-endian Ed25519)
//! - secp256k1 elements: 33-byte SEC1 compressed
//! - Ed25519 elements: 32-byte RFC 8032
//! - participant identifiers: `u32` (`1..=MAX_PARTICIPANTS`)
//! - final signatures: Appendix-A encoding (`65` / `64` bytes)
//!
//! Randomness is caller-supplied (`commit_with_randomness`); key
//! generation helpers implement the trusted-dealer flow of Appendix C
//! (`shard` / `combine` / `vss_*` / `group_info`). Distributed key
//! generation is out of scope (same as the RFC).

#![cfg(feature = "alloc")]

mod error;
mod hash;
pub mod ed;
pub mod k1;

pub use error::{FrostError, FrostResult};
