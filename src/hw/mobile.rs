//! Mobile boundary (Android+iOS): plain C ABI, zero crates, `no_std` + `alloc`.
//!
//! Same delegation as `hw::wasm_webhid` — Rust owns the protocol, the host
//! owns the radio/USB — but shaped for Kotlin/Swift instead of JS:
//! - Android: Kotlin owns `UsbManager` (USB-OTG host mode) and
//!   `BluetoothGatt` (BLE); expose this module over JNI (or `uniffi`, if
//!   the app already uses it) with the C symbols below as the narrow waist.
//! - iOS: Swift calls the C symbols directly (no wrapper needed); Swift
//!   owns `CoreBluetooth` plus the `NSBluetoothAlwaysUsageDescription`
//!   plist entry.
//!
//! Message units here are APP-PROTOCOL units (an APDU for Ledger, a `?##`
//! frame for Trezor), NOT 64-byte HID reports: BLE ATT MTUs and USB-HID
//! report framing differ, so framing stays on the host side next to the
//! bearer it understands. [`Wallet::execute_get_address`] and
//! [`NoiseTransportAdapter`] work unchanged — the [`Transport`] trait is
//! framing-agnostic by design.
//!
//! Platform reach:
//! BLE-capable Ledgers (Nano X / Stax / Flex) work on both mobile OSes;
//! USB-only devices (Nano S Plus, Trezor, KeepKey, OneKey, BitBox02) work
//! on Android via OTG and are UNREACHABLE on iOS (no public USB-HID host
//! API; steer those users to desktop/Android or the QR-airgap flow).
//!
//! Memory rule: every buffer is caller-owned. The host passes request
//! bytes and a reply buffer; Rust never allocates across the boundary.
//! Error mapping is a stable `i64` code (see [`MobileErrorCode`]).

use crate::error::{Error, Result};
use crate::hw::transport::Transport;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

#[cfg(feature = "std")]
use std::time::Duration;

/// Stable C-ABI error codes (negative `i64`). Never renumber.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i64)]
pub enum MobileErrorCode {
    Ok = 0,
    TransportUnavailable = -1,
    TransportWrite = -2,
    TransportRead = -3,
    TransportTimeout = -4,
    TransportDisconnected = -5,
    TransportCancelled = -6,
    InvalidLength = -7,
    Other = -8,
}

impl From<Error> for MobileErrorCode {
    fn from(e: Error) -> Self {
        match e {
            Error::TransportUnavailable => Self::TransportUnavailable,
            Error::TransportWrite => Self::TransportWrite,
            Error::TransportRead => Self::TransportRead,
            Error::TransportTimeout => Self::TransportTimeout,
            Error::TransportDisconnected => Self::TransportDisconnected,
            Error::TransportCancelled => Self::TransportCancelled,
            Error::InvalidLength => Self::InvalidLength,
            _ => Self::Other,
        }
    }
}

/// Host-provided I/O, set once via [`register_host_ops`]. Mirrors the
/// `hw_hid_*` JS contract, shaped for pass-by-buffer C:
///
/// - `open(vid, pid)`: run permission dialogs here (USB attach / BLE scan
///   prompts are the host's job); return a handle ≥ 0 or a negative code.
/// - `exchange(handle, req, req_len, out, out_cap, timeout_ms)`: move one
///   app-protocol message; write ≤ `out_cap` reply bytes to `out`; return
///   bytes written or a negative code. The host MUST bounds-check against
///   `out_cap` (same security boundary as the WASM host).
/// - `close(handle)`: release the bearer.
/// - `cancel`: optional abort for an in-flight exchange (may be `None` —
///   then `cancel()` is a no-op and timeouts bound the wait).
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct HostOps {
    pub open: extern "C" fn(vid: u16, pid: u16) -> i64,
    pub exchange: extern "C" fn(
        handle: i64,
        req: *const u8,
        req_len: usize,
        out: *mut u8,
        out_cap: usize,
        timeout_ms: u32,
    ) -> i64,
    pub close: extern "C" fn(handle: i64),
    pub cancel: Option<extern "C" fn(handle: i64)>,
}

// SAFETY: plain function pointers are `Sync`.
unsafe impl Send for HostOps {}
unsafe impl Sync for HostOps {}

static OPS: AtomicUsize = AtomicUsize::new(0);

/// Register the host operations (call once at app startup, before any
/// `hw_mobile_*` call). Stores a COPY of the struct. Returns 0 on success.
pub fn register_host_ops(ops: &HostOps) -> i32 {
    let boxed = alloc::boxed::Box::new(*ops);
    let prev = OPS.swap(
        alloc::boxed::Box::into_raw(boxed) as usize,
        Ordering::AcqRel,
    );
    if prev != 0 {
        // Drop the superseded table (avoids leaking one registration).
        unsafe {
            drop(alloc::boxed::Box::from_raw(prev as *mut HostOps));
        }
    }
    0
}

fn host_ops() -> Result<HostOps> {
    let raw = OPS.load(Ordering::Acquire);
    if raw == 0 {
        return Err(Error::TransportUnavailable);
    }
    Ok(unsafe { *(raw as *const HostOps) })
}

/// Default per-exchange deadline (host also enforces `timeout_ms`).
#[cfg(feature = "std")]
pub const DEFAULT_TIMEOUT_MS: u32 = 5000;

/// USB/BLE device behind the mobile host boundary. Carries its own
/// copy of [`HostOps`] (they are plain function pointers), so an explicit
/// `open(ops, …)` never depends on the global slot afterwards.
#[derive(Debug)]
pub struct MobileTransport {
    handle: i64,
    ops: HostOps,
}

impl MobileTransport {
    /// Open by vendor/product id (`pid == 0` matches any product — the
    /// host applies the filter it can express).
    pub fn open(ops: &HostOps, vid: u16, pid: u16) -> Result<Self> {
        let handle = (ops.open)(vid, pid);
        if handle < 0 {
            crate::hw::log::warn("hw::mobile", "mobile open failed");
            return Err(Error::TransportUnavailable);
        }
        crate::hw::log::info("hw::mobile", "mobile open");
        Ok(Self { handle, ops: *ops })
    }

    /// Open through the globally registered [`HostOps`].
    pub fn open_registered(vid: u16, pid: u16) -> Result<Self> {
        let ops = host_ops()?;
        Self::open(&ops, vid, pid)
    }

    fn exchange_ms(&mut self, msg: &[u8], timeout_ms: u32) -> Result<Vec<u8>> {
        // Bound the reply buffer: app-protocol units are small (APDUs);
        // Bound the reply buffer: app-protocol units are small (APDUs);
        // 4 KiB covers any wallet message without trusting the host.
        const MAX_REPLY: usize = 4096;
        let mut out = alloc::vec![0u8; MAX_REPLY];
        let n = (self.ops.exchange)(
            self.handle,
            msg.as_ptr(),
            msg.len(),
            out.as_mut_ptr(),
            out.len(),
            timeout_ms,
        );
        if n < 0 {
            let code = n;
            let err = match code {
                x if x == MobileErrorCode::TransportWrite as i64 => Error::TransportWrite,
                x if x == MobileErrorCode::TransportTimeout as i64 => Error::TransportTimeout,
                x if x == MobileErrorCode::TransportDisconnected as i64 => {
                    Error::TransportDisconnected
                }
                x if x == MobileErrorCode::TransportCancelled as i64 => Error::TransportCancelled,
                x if x == MobileErrorCode::InvalidLength as i64 => Error::InvalidLength,
                _ => Error::TransportRead,
            };
            crate::hw::log::warn("hw::mobile", "mobile exchange failed");
            return Err(err);
        }
        // Defensive: a buggy host must not make us over-read our own buffer.
        let n = core::cmp::min(n as usize, out.len());
        out.truncate(n);
        Ok(out)
    }

    /// Close the bearer (also runs on drop).
    pub fn close(self) {
        drop(self);
    }
}

impl Drop for MobileTransport {
    fn drop(&mut self) {
        (self.ops.close)(self.handle);
    }
}

impl Transport for MobileTransport {
    fn exchange(&mut self, msg: &[u8]) -> Result<Vec<u8>> {
        #[cfg(feature = "std")]
        {
            self.exchange_ms(msg, DEFAULT_TIMEOUT_MS)
        }
        #[cfg(not(feature = "std"))]
        {
            return self.exchange_ms(msg, 5000);
        }
    }

    #[cfg(feature = "std")]
    fn exchange_timeout(&mut self, msg: &[u8], timeout: Duration) -> Result<Vec<u8>> {
        let ms = timeout.as_millis().min(u32::MAX as u128) as u32;
        self.exchange_ms(msg, ms)
    }

    fn cancel(&self) {
        if let Some(cancel) = self.ops.cancel {
            cancel(self.handle);
        }
    }
}

// ------------------------------------------------------------ C ABI entrances ---
// Swift calls these directly; Kotlin reaches them through one tiny JNI
// shim each (no per-method marshalling logic in Rust beyond this file).

/// Register host ops from C: `hw_mobile_register_ops(&ops)`. Returns 0.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn hw_mobile_register_ops(ops: *const HostOps) -> i32 {
    if ops.is_null() {
        return MobileErrorCode::InvalidLength as i32;
    }
    register_host_ops(unsafe { &*ops })
}

/// Open: returns a handle ≥ 0, or a negative [`MobileErrorCode`].
#[no_mangle]
pub extern "C" fn hw_mobile_open(vid: u16, pid: u16) -> i64 {
    match MobileTransport::open_registered(vid, pid) {
        Ok(t) => {
            let handle = t.handle;
            core::mem::forget(t); // host owns it until hw_mobile_close
            handle
        }
        Err(e) => MobileErrorCode::from(e) as i64,
    }
}

/// Exchange: move one message; returns bytes written to `out`, or a
/// negative [`MobileErrorCode`]. `out` must hold ≥ `out_cap` bytes.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn hw_mobile_exchange(
    handle: i64,
    req: *const u8,
    req_len: usize,
    out: *mut u8,
    out_cap: usize,
    timeout_ms: u32,
) -> i64 {
    if req.is_null() || out.is_null() {
        return MobileErrorCode::InvalidLength as i64;
    }
    let ops = match host_ops() {
        Ok(ops) => ops,
        Err(e) => return MobileErrorCode::from(e) as i64,
    };
    let request = unsafe { core::slice::from_raw_parts(req, req_len) };
    let mut t = MobileTransport { handle, ops };
    // Re-wrap without closing: the host still owns the bearer (close is
    // explicit via hw_mobile_close).
    let result = t.exchange_ms(request, timeout_ms);
    core::mem::forget(t);
    match result {
        Ok(reply) => {
            let n = core::cmp::min(reply.len(), out_cap);
            unsafe { core::ptr::copy_nonoverlapping(reply.as_ptr(), out, n) };
            n as i64
        }
        Err(e) => MobileErrorCode::from(e) as i64,
    }
}

/// Close a handle opened by [`hw_mobile_open`].
#[no_mangle]
pub extern "C" fn hw_mobile_close(handle: i64) {
    if let Ok(ops) = host_ops() {
        (ops.close)(handle);
    }
}
