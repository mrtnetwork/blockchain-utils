//! ZK version / logging WASM exports (`BuWasm.zk*`).
//!
//! Mirrors `connector::ffi::zkcodes`: version 1 + accepted no-op logging.

#![cfg(feature = "wasm")]

use wasm_bindgen::prelude::*;

/// ZK API version (1).
#[wasm_bindgen(js_name = zkVersion)]
pub fn zk_version_js() -> u32 {
    1
}

/// Logging toggle (accepted no-op); always returns 0.
#[wasm_bindgen(js_name = zkEnableLogging)]
pub fn zk_enable_logging_js(_enable: u32, _mode: u32) -> i32 {
    0
}

/// Backend interface version (mirrors FFI `bu_build_version`).
#[wasm_bindgen(js_name = backendVersion)]
pub fn backend_version_js() -> u32 {
    crate::connector::BU_BUILD_VERSION
}

/// Cargo feature bitmask of this `.wasm` (mirrors FFI `bu_build_features`).
#[wasm_bindgen(js_name = backendFeatures)]
pub fn backend_features_js() -> u32 {
    crate::connector::build_features()
}
