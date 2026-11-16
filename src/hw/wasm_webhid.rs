//! WebHID backend for `wasm32`: zero Rust dependencies, raw `extern "C"`.
//!
//! The actual `navigator.hid.*` calls live OUTSIDE the WASM binary in a
//! hand-written JS host module (see `hw/host.js`) — repo policy forbids
//! `js-sys`/`web-sys`. This module only declares the four raw imports it
//! needs (integers + linear-memory pointers) and wraps them in the
//! [`Transport`] trait with the same one-report-per-exchange model as the
//! native backends.
//!
//! Compiles on every target (`core` + `alloc` only). The symbols resolve
//! at instantiation time: the browser host provides them in production;
//! native `#[cfg(test)]` builds provide loopback stubs (see the test
//! module) so framing, error mapping, and timeout plumbing run in CI.
//!
//! Host contract (mirrored in `hw/host.js`):
//! - `hw_hid_open(vid, pid)`: prompt the user (**must run inside a user
//!   gesture**) and return an opaque handle ≥ 0, or -1 on failure/cancel.
//! - `hw_hid_write(handle, ptr, len)`: send one report; bytes read from
//!   WASM linear memory. Returns bytes written, or -1 on error. The host
//!   MUST bounds-check `ptr/len` against `memory.buffer.byteLength`
//!   before touching memory (security boundary
//! - `hw_hid_read(handle, out_ptr, cap, timeout_ms)`: wait for one input
//!   report (host-side wait, NOT a single poll); write ≤ `cap` bytes to
//!   `out_ptr`. Returns bytes written, 0 on timeout, -1 on error.
//! - `hw_hid_close(handle)`: release the device.
//!
//! Browser gap: Safari has no WebHID — the app must offer a fallback
//! (desktop app / QR flow) independent of this module.

use crate::error::{Error, Result};
use crate::hw::transport::Transport;

use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::time::Duration;

// Implemented by the JS host (production) or the test stubs (native tests).
extern "C" {
    fn hw_hid_open(vid: u32, pid: u32) -> i32;
    fn hw_hid_write(handle: i32, ptr: *const u8, len: u32) -> i32;
    fn hw_hid_read(handle: i32, out_ptr: *mut u8, cap: u32, timeout_ms: u32) -> i32;
    fn hw_hid_close(handle: i32);
}

/// HID report payload size (same framing as the native backends).
pub const HID_RAW_REPORT_LEN: usize = 64;
/// Default per-exchange deadline.
#[cfg(feature = "std")]
pub const DEFAULT_TIMEOUT_MS: u32 = 5000;

/// Open WebHID device. On the web this must be called from a user gesture
/// (button click) — `requestDevice()` rejects otherwise.
#[derive(Debug)]
pub struct WebHidTransport {
    handle: i32,
}

impl WebHidTransport {
    /// Open by vendor/product id. `pid == 0` matches any product (the host
    /// applies `{vendorId}`-only filters then).
    pub fn open(vid: u16, pid: u16) -> Result<Self> {
        let handle = unsafe { hw_hid_open(vid as u32, pid as u32) };
        if handle < 0 {
            crate::hw::log::warn("hw::wasm_webhid", "webhid open failed");
            return Err(Error::TransportUnavailable);
        }
        crate::hw::log::info("hw::wasm_webhid", "webhid open");
        Ok(Self { handle })
    }

    /// Convenience: first device with this vendor id.
    pub fn open_first(vid: u16) -> Result<Self> {
        Self::open(vid, 0)
    }

    fn read_report_ms(&self, timeout_ms: u32) -> Result<[u8; HID_RAW_REPORT_LEN]> {
        let mut buf = [0u8; HID_RAW_REPORT_LEN];
        let n = unsafe { hw_hid_read(self.handle, buf.as_mut_ptr(), buf.len() as u32, timeout_ms) };
        if n < 0 {
            return Err(Error::TransportRead);
        }
        if n == 0 {
            return Err(Error::TransportTimeout);
        }
        if n as usize != HID_RAW_REPORT_LEN {
            return Err(Error::TransportRead);
        }
        Ok(buf)
    }

    fn write_report(&mut self, report: &[u8; HID_RAW_REPORT_LEN]) -> Result<()> {
        let n = unsafe { hw_hid_write(self.handle, report.as_ptr(), report.len() as u32) };
        if n < 0 {
            return Err(Error::TransportWrite);
        }
        if n as usize != HID_RAW_REPORT_LEN {
            return Err(Error::TransportWrite);
        }
        Ok(())
    }

    fn exchange_ms(&mut self, msg: &[u8], timeout_ms: u32) -> Result<Vec<u8>> {
        if msg.len() != HID_RAW_REPORT_LEN {
            return Err(Error::InvalidLength);
        }
        let mut report = [0u8; HID_RAW_REPORT_LEN];
        report.copy_from_slice(msg);
        self.write_report(&report).inspect_err(|_| {
            crate::hw::log::warn("hw::wasm_webhid", "webhid write failed");
        })?;
        self.read_report_ms(timeout_ms)
            .map(|r| r.to_vec())
            .inspect_err(|_| {
                crate::hw::log::warn("hw::wasm_webhid", "webhid read failed");
            })
    }
}

impl Drop for WebHidTransport {
    fn drop(&mut self) {
        unsafe { hw_hid_close(self.handle) };
    }
}

impl Transport for WebHidTransport {
    fn exchange(&mut self, msg: &[u8]) -> Result<Vec<u8>> {
        #[cfg(feature = "std")]
        {
            self.exchange_ms(msg, DEFAULT_TIMEOUT_MS)
        }
        #[cfg(not(feature = "std"))]
        {
            // No clock on `no_std` web builds: the host applies its own
            // default (documented as 5 s in `hw/host.js`).
            return self.exchange_ms(msg, 5000);
        }
    }

    #[cfg(feature = "std")]
    fn exchange_timeout(&mut self, msg: &[u8], timeout: Duration) -> Result<Vec<u8>> {
        let ms = timeout.as_millis().min(u32::MAX as u128) as u32;
        self.exchange_ms(msg, ms)
    }
}

// ------------------------------------------------------------------- tests ---
// Native loopback stubs for the host imports: a scripted fake device so
// the Rust side (framing, mapping, drop) is covered without a browser.

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "std")]
    use std::sync::Mutex;

    #[cfg(feature = "std")]
    struct FakeDevice {
        open_fails: bool,
        reply: Option<[u8; HID_RAW_REPORT_LEN]>,
        seen: Vec<Vec<u8>>,
        closes: usize,
    }

    #[cfg(feature = "std")]
    static FAKE: Mutex<FakeDevice> = Mutex::new(FakeDevice {
        open_fails: false,
        reply: None,
        seen: Vec::new(),
        closes: 0,
    });

    #[cfg(feature = "std")]
    fn fake_with(reply: Option<[u8; HID_RAW_REPORT_LEN]>, open_fails: bool) {
        let mut f = FAKE.lock().unwrap();
        f.reply = reply;
        f.open_fails = open_fails;
        f.seen.clear();
        f.closes = 0;
    }

    // Host-import stand-ins. Only compiled for native tests — on real
    // wasm32 builds the JS host provides these symbols instead.
    #[cfg(feature = "std")]
    #[no_mangle]
    pub extern "C" fn hw_hid_open(_vid: u32, _pid: u32) -> i32 {
        if FAKE.lock().unwrap().open_fails {
            -1
        } else {
            7 // opaque fake handle
        }
    }

    #[cfg(feature = "std")]
    #[no_mangle]
    pub extern "C" fn hw_hid_write(handle: i32, ptr: *const u8, len: u32) -> i32 {
        if handle != 7 {
            return -1;
        }
        let bytes = unsafe { core::slice::from_raw_parts(ptr, len as usize) };
        FAKE.lock().unwrap().seen.push(bytes.to_vec());
        len as i32
    }

    #[cfg(feature = "std")]
    #[no_mangle]
    pub extern "C" fn hw_hid_read(
        handle: i32,
        out_ptr: *mut u8,
        cap: u32,
        _timeout_ms: u32,
    ) -> i32 {
        if handle != 7 {
            return -1;
        }
        match FAKE.lock().unwrap().reply {
            // Wedged device: nothing arrives before the deadline.
            None => 0,
            Some(reply) => {
                let n = core::cmp::min(cap as usize, HID_RAW_REPORT_LEN);
                unsafe { core::ptr::copy_nonoverlapping(reply.as_ptr(), out_ptr, n) };
                n as i32
            }
        }
    }

    #[cfg(feature = "std")]
    #[no_mangle]
    pub extern "C" fn hw_hid_close(handle: i32) {
        if handle == 7 {
            FAKE.lock().unwrap().closes += 1;
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn exchange_round_trip_through_stub() {
        fake_with(Some([0x99; HID_RAW_REPORT_LEN]), false);
        let mut t = WebHidTransport::open(0x2C97, 0x5011).unwrap();
        let out = t.exchange(&[0x77; HID_RAW_REPORT_LEN]).unwrap();
        assert_eq!(out, alloc::vec![0x99; HID_RAW_REPORT_LEN]);
        let f = FAKE.lock().unwrap();
        assert_eq!(f.seen.len(), 1);
        assert_eq!(f.seen[0], alloc::vec![0x77; HID_RAW_REPORT_LEN]);
    }

    #[cfg(feature = "std")]
    #[test]
    fn silent_device_surfaces_timeout() {
        fake_with(None, false);
        let mut t = WebHidTransport::open_first(0x2C97).unwrap();
        let err = t
            .exchange_timeout(&[0x77; HID_RAW_REPORT_LEN], Duration::from_millis(50))
            .unwrap_err();
        assert_eq!(err, Error::TransportTimeout);
    }

    #[cfg(feature = "std")]
    #[test]
    fn denied_device_is_unavailable() {
        fake_with(None, true);
        assert_eq!(
            WebHidTransport::open(0x2C97, 0).unwrap_err(),
            Error::TransportUnavailable
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn wrong_size_rejected_before_wire() {
        fake_with(Some([0x99; HID_RAW_REPORT_LEN]), false);
        let mut t = WebHidTransport::open_first(0x1209).unwrap();
        assert_eq!(t.exchange(&[0u8; 63]), Err(Error::InvalidLength));
        assert!(FAKE.lock().unwrap().seen.is_empty());
    }

    #[cfg(feature = "std")]
    #[test]
    fn drop_closes_device() {
        fake_with(Some([0x99; HID_RAW_REPORT_LEN]), false);
        {
            let _t = WebHidTransport::open_first(0x2C97).unwrap();
        }
        assert_eq!(FAKE.lock().unwrap().closes, 1);
    }
}
