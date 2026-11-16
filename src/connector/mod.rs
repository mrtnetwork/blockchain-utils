//! External connector surface.
//!
//! - `ffi` feature: C ABI (`cdylib` / native dynamic library)
//! - `wasm` feature: wasm-bindgen exports for the web connector
//!
//! Core crypto modules are unchanged; this is only an interop layer.

#![allow(missing_docs)]

#[cfg(feature = "ffi")]
pub mod ffi;

#[cfg(feature = "wasm")]
pub mod wasm;

/// Backend interface version (increments on breaking connector changes).
///
/// Reported by `bu_build_version` (FFI) and `backendVersion` (WASM) so callers
/// can refuse artifacts older than it understands.
#[cfg(any(feature = "ffi", feature = "wasm"))]
pub const BU_BUILD_VERSION: u32 = 1;

/// Bitmask of Cargo features compiled into this backend artifact.
///
/// Shared by the `ffi` (`bu_build_features`) and `wasm` (`backendFeatures`)
/// exports so callers detect at runtime which capability set the loaded `.so`
/// / `.wasm` was built with. Bits are stable — only append new ones:
///
/// | Bit | Feature |
/// |-----|---------|
/// | 0 | `std` |
/// | 1 | `alloc` |
/// | 2 | `ffi` (native C ABI present) |
/// | 3 | `wasm` (wasm-bindgen exports present) |
/// | 4 | `groth16` |
/// | 5 | `groth16-prover` |
/// | 6 | `poseidon-bn254` |
/// | 7 | `multicore` |
/// | 8 | `solana-zk` |
/// | 9 | `orchard-halo2` |
/// | 10 | `zcash-sapling` |
/// | 11 | `zcash-halo2` |
/// | 12 | `zcash-incrementalmerkle` |
/// | 13 | `hw` |
/// | 14 | `monero` |
#[cfg(any(feature = "ffi", feature = "wasm"))]
pub const fn build_features() -> u32 {
    let mut f = 0u32;
    if cfg!(feature = "std") {
        f |= 1 << 0;
    }
    if cfg!(feature = "alloc") {
        f |= 1 << 1;
    }
    if cfg!(feature = "ffi") {
        f |= 1 << 2;
    }
    if cfg!(feature = "wasm") {
        f |= 1 << 3;
    }
    if cfg!(feature = "groth16") {
        f |= 1 << 4;
    }
    if cfg!(feature = "groth16-prover") {
        f |= 1 << 5;
    }
    if cfg!(feature = "poseidon-bn254") {
        f |= 1 << 6;
    }
    if cfg!(feature = "multicore") {
        f |= 1 << 7;
    }
    if cfg!(feature = "solana-zk") {
        f |= 1 << 8;
    }
    if cfg!(feature = "orchard-halo2") {
        f |= 1 << 9;
    }
    if cfg!(feature = "zcash-sapling") {
        f |= 1 << 10;
    }
    if cfg!(feature = "zcash-halo2") {
        f |= 1 << 11;
    }
    if cfg!(feature = "zcash-incrementalmerkle") {
        f |= 1 << 12;
    }
    if cfg!(feature = "hw") {
        f |= 1 << 13;
    }
    if cfg!(feature = "monero") {
        f |= 1 << 14;
    }
    f
}
