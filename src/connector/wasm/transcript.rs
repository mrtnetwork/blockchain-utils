//! Merlin transcripts + Strobe contexts for the web connector.
//!
//! Integer-handle surface mirroring `connector::ffi::transcript`
//! (`bu_merlin_*`, `bu_strobe_*`): JS cannot hold Rust structs, so live
//! objects sit in process tables keyed by `u32` ids (see `handles.rs`).
//! Tables are append-only until `Free`; dropping without free leaks until
//! page unload (same discipline as the native `bu_*_free` contract).

#![cfg(all(feature = "wasm", feature = "alloc"))]

use std::cell::RefCell;
use std::collections::HashMap;
use wasm_bindgen::prelude::*;

use super::handles::alloc_id;
use crate::merlin::Transcript;
use crate::strobe::Strobe;

thread_local! {
    static MERLIN: RefCell<HashMap<u32, Transcript>> = RefCell::new(HashMap::new());
    static STROBE: RefCell<HashMap<u32, Strobe>> = RefCell::new(HashMap::new());
}

fn merlin_with<T>(id: u32, f: impl FnOnce(&mut Transcript) -> Result<T, JsValue>) -> Result<T, JsValue> {
    MERLIN.with(|m| {
        let mut m = m.borrow_mut();
        let t = m.get_mut(&id).ok_or_else(|| JsValue::from_str("bad handle"))?;
        f(t)
    })
}

fn strobe_with<T>(id: u32, f: impl FnOnce(&mut Strobe) -> Result<T, JsValue>) -> Result<T, JsValue> {
    STROBE.with(|s| {
        let mut s = s.borrow_mut();
        let t = s.get_mut(&id).ok_or_else(|| JsValue::from_str("bad handle"))?;
        f(t)
    })
}

/// Open a Merlin transcript over `label` → integer handle.
#[wasm_bindgen(js_name = merlinNew)]
pub fn merlin_new(label: &[u8]) -> u32 {
    let id = alloc_id();
    MERLIN.with(|m| {
        m.borrow_mut().insert(id, Transcript::new(label));
    });
    id
}

/// `append_message(label, message)` on `handle`.
#[wasm_bindgen(js_name = merlinAppend)]
pub fn merlin_append(handle: u32, label: &[u8], message: &[u8]) -> Result<(), JsValue> {
    let label = label.to_vec();
    let message = message.to_vec();
    merlin_with(handle, |t| {
        t.append_message(&label, &message);
        Ok(())
    })
}

/// `challenge_bytes(label)` — `len` bytes.
#[wasm_bindgen(js_name = merlinChallenge)]
pub fn merlin_challenge(handle: u32, label: &[u8], len: usize) -> Result<Vec<u8>, JsValue> {
    let label = label.to_vec();
    merlin_with(handle, |t| {
        let mut out = vec![0u8; len];
        t.challenge_bytes(&label, &mut out);
        Ok(out)
    })
}

/// Fork `handle` → fresh handle with identical state.
#[wasm_bindgen(js_name = merlinFork)]
pub fn merlin_fork(handle: u32) -> Result<u32, JsValue> {
    // Clone under a shared borrow first: inserting while the table is
    // mutably borrowed (as `merlin_with` does) would panic the RefCell.
    let forked = MERLIN.with(|m| {
        m.borrow()
            .get(&handle)
            .map(|t| t.fork())
            .ok_or_else(|| JsValue::from_str("bad handle"))
    })?;
    let id = alloc_id();
    MERLIN.with(|m| {
        m.borrow_mut().insert(id, forked);
    });
    Ok(id)
}

/// Close `handle` (idempotent).
#[wasm_bindgen(js_name = merlinFree)]
pub fn merlin_free(handle: u32) {
    MERLIN.with(|m| {
        m.borrow_mut().remove(&handle);
    });
}

/// Open a Strobe-128 context over `protocol` → integer handle.
#[wasm_bindgen(js_name = strobeNew)]
pub fn strobe_new(protocol: &[u8]) -> u32 {
    let id = alloc_id();
    STROBE.with(|s| {
        s.borrow_mut().insert(id, Strobe::new_128(protocol));
    });
    id
}

/// `key(data)` on `handle`.
#[wasm_bindgen(js_name = strobeKey)]
pub fn strobe_key(handle: u32, data: &[u8]) -> Result<(), JsValue> {
    let data = data.to_vec();
    strobe_with(handle, |s| {
        s.key(&data);
        Ok(())
    })
}

/// `ad(data)` on `handle` (`meta` nonzero → meta-AD).
#[wasm_bindgen(js_name = strobeAd)]
pub fn strobe_ad(handle: u32, meta: bool, data: &[u8]) -> Result<(), JsValue> {
    let data = data.to_vec();
    strobe_with(handle, |s| {
        s.ad(meta, &data);
        Ok(())
    })
}

/// `prf(len)` on `handle` → `len` bytes.
#[wasm_bindgen(js_name = strobePrf)]
pub fn strobe_prf(handle: u32, len: usize) -> Result<Vec<u8>, JsValue> {
    strobe_with(handle, |s| Ok(s.prf(len)))
}

/// Close `handle` (idempotent).
#[wasm_bindgen(js_name = strobeFree)]
pub fn strobe_free(handle: u32) {
    STROBE.with(|s| {
        s.borrow_mut().remove(&handle);
    });
}
