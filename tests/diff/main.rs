//! Differential / smoke suite: OpenSSL cross-checks, algebraic self-consistency,
//! constant-time timing smoke, and the FFI surface smoke test.
//!
//! Run: `cargo test --test diff`

mod ct_timing_smoke;
mod diff_openssl;
mod diff_self;
mod ffi_smoke;
