//! `orchard_halo2` — standalone zero-dependency Orchard Halo2 implementation.
//!
//! Independently implemented from the official Zcash Orchard protocol
//! specification and Halo2 circuit description. Verified byte-identical
//! against official orchard 0.15.5 vectors
//! (see `tests/orchard_official_vectors.rs`).
//!
//! - Zero dependencies. Fully self-contained (no wallet parsing; see `bridge`).
//! - `no_std` compatible (`alloc` only). `std` is opt-in. WASM/FFI safe:
//!   `forbid(unsafe_code)`, no threads, no env, no I/O.
//! - No `assert!`/`panic!` paths in library logic: every fallible op
//!   returns `Result<T, Halo2Error>`.
//! - Field/point wire encoding is **LE** (`to_le_bytes` / `from_le_bytes`).
//!   Debug hex is **BE** for display only.
//! - Orchard constants are compile-time `&[u8; 32]` LE byte tables
//!   (see `orchard::constants`), never hex strings or runtime parsing.

pub mod blake2b;
pub mod bridge;
pub mod bytes;
pub mod chip;
pub mod crypto_context;
pub mod curve;
pub mod error;
pub mod field;
pub mod floor_planner;
pub mod orchard;
pub mod plonk;
pub mod poly;
pub mod poseidon;
pub mod proof;
pub mod rng;
pub mod sinsemilla;
pub mod tables;
pub mod tables_ipa_mont;
pub mod transcript;
pub mod utility;

pub use error::{Halo2Error, Halo2Result};
