//! DKLs23 threshold-signing suite: KATs, ETH compatibility, adversarial cases,
//! and the 2-of-3 keygen/sign timing bench.
//!
//! Run: `cargo test --release --test dkls23 -- --nocapture --test-threads=1`

mod dkls23_adversarial;
mod dkls23_bench;
mod dkls23_eth;
mod dkls23_kat;
