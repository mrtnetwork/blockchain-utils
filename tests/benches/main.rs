//! Side-by-side bench suite: official stacks vs our ports. Every case asserts
//! functional correctness first, then reports timing (timings are only
//! meaningful in release).
//!
//! Run: `cargo test --release --test benches -- --nocapture --test-threads=1`

mod groth16_compare;
