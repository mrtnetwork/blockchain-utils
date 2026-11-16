//! wasm-bindgen exports for the web connector (`BuWasm`).
//!
//! Build: `cargo build --target wasm32-unknown-unknown --features wasm --release`
//! Then use `wasm-bindgen` CLI to generate JS, or the package glue in
//! `blockchain_utils_connector/web/bu_wasm_glue.js`.

#![cfg(feature = "wasm")]

#[cfg(all(feature = "wasm", feature = "groth16"))]
mod groth16;
mod handles;
mod hash;
mod kdf;
#[cfg(all(
    feature = "wasm",
    any(feature = "orchard-halo2", feature = "zcash-halo2")
))]
mod orchard;
mod zkcodes;

mod aead;
mod bls;
mod cipher;
mod curve;
mod ff1;
mod frost;
mod dkls23;
mod musig2;
mod signature;
mod sr25519;
mod transcript;
mod x25519;

#[cfg(all(feature = "wasm", feature = "groth16"))]
pub use groth16::*;
pub use hash::*;
pub use kdf::*;
#[cfg(all(feature = "wasm", feature = "orchard-halo2"))]
pub use orchard::*;
pub use zkcodes::*;

pub use aead::*;
#[cfg(feature = "alloc")]
pub use bls::*;
pub use cipher::*;
#[cfg(feature = "alloc")]
pub use curve::*;
pub use ff1::*;
#[cfg(feature = "alloc")]
pub use frost::*;
#[cfg(feature = "alloc")]
pub use dkls23::*;
#[cfg(feature = "alloc")]
pub use musig2::*;
pub use signature::*;
pub use sr25519::*;
pub use transcript::*;
pub use x25519::*;

#[cfg(feature = "alloc")]
pub mod mldsa;
pub mod rng;

#[cfg(all(
    feature = "wasm",
    any(feature = "zcash-sapling", feature = "groth16-prover")
))]
mod sapling;
#[cfg(all(
    feature = "wasm",
    any(feature = "zcash-sapling", feature = "groth16-prover")
))]
pub use sapling::*;

#[cfg(all(
    feature = "wasm",
    any(
        feature = "zcash-incrementalmerkle",
        all(feature = "groth16-prover", feature = "orchard-halo2")
    )
))]
mod merkle;
#[cfg(all(
    feature = "wasm",
    any(
        feature = "zcash-incrementalmerkle",
        all(feature = "groth16-prover", feature = "orchard-halo2")
    )
))]
pub use merkle::*;

#[cfg(all(feature = "wasm", feature = "monero"))]
mod monero;
#[cfg(all(feature = "wasm", feature = "monero"))]
pub use monero::*;
#[cfg(all(feature = "wasm", feature = "solana-zk"))]
mod solana_zk;
#[cfg(all(feature = "wasm", feature = "solana-zk"))]
pub use solana_zk::*;

#[cfg(feature = "wasm")]
pub mod reddsa;

#[cfg(all(feature = "wasm", feature = "hw"))]
mod hw;
#[cfg(all(feature = "wasm", feature = "hw"))]
pub use hw::*;
