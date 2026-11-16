//! Locked KAT / official-vector suite: one integration target grouping every
//! known-answer and RFC/official-vector test module.
//!
//! Run it all: `cargo test --test kats`
//! Run one module: `cargo test --test kats kat_locked`

mod bip327_official;
mod bitcoin_signer;
mod bls_kat;
mod bls_eth2_kat;
mod bn254_vectors;
mod curve_edge;
mod curve_vectors;
mod vectors;
mod hash_vectors;
mod kat_locked;
mod mldsa_kat;
mod monero_scan_kat;
mod musig2_kat;
mod orchard_test2_vectors;
mod orchard_official_vectors;
mod reddsa_official;
mod rfc6979_bip340_vectors;
mod rfc6979_p256_vectors;
mod secp_infinity;
mod sqrt_check;
