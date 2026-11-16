//! ML-DSA (FIPS 204 / Dilithium) — pure Rust, `no_std` + `alloc`.
//!
//! Parameter sets: ML-DSA-44, ML-DSA-65, ML-DSA-87.
//! Field/NTT arithmetic is branch-light; rejection sampling loops are
//! inherently data-dependent (as in the reference design).

#![cfg(feature = "alloc")]

mod encode;
mod field;
mod mldsa;
mod ntt;
mod params;
mod poly;
mod zetas;

pub use mldsa::{MlDsa, MlDsaError};
pub use params::Params;
