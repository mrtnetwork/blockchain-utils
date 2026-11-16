//! `Transport`: the ONLY hardware boundary.
//!
//! Everything in `hw` builds/parses byte messages. Moving those bytes over
//! USB-HID / BLE / NFC / TCP (Speculos/emu) is the embedder's job:
//! - native (`std` builds): in-crate backends `hw::linux` / `hw::macos` /
//!   `hw::windows` (OS-gated), or the app's own driver — same trait.
//! - web (`wasm32`): `hw::wasm_webhid` — raw `extern "C"` imports served by
//!   a hand-written JS host (repo policy: no `js-sys`/`web-sys`).
//! - mobile: `hw::mobile` C-ABI boundary; Kotlin/Swift owns USB/BLE.
//! - tests: `hw::MockTransport`, `hw::emu::TcpTransport` (Speculos).
//!
//! Airgap QR devices (Passport / Keystone / Coldcard-QR / Jade-QR) do not use
//! this trait at all — see `hw::ur` + `hw::psbt`.
//!
//! Hotplug story: `hw` only ever does
//! point-in-time enumeration (`linux::enumerate_candidates()` and friends).
//! There are no OS hotplug callbacks in this crate — detecting plug/unplug
//! and re-enumerating on a timer is the embedder's job. A device that
//! vanishes mid-exchange surfaces [`Error::TransportDisconnected`].

use crate::error::Result;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::time::Duration;

/// Byte transport. Implementations must be blocking `request -> response`.
/// `apdu` for Ledger/BitBox, raw HID frame for Trezor (see `hid` + `trezor`).
pub trait Transport {
    /// Send one request unit, return one response unit (or an error).
    fn exchange(&mut self, msg: &[u8]) -> Result<Vec<u8>>;

    /// Same, with a per-call deadline. The default impl forwards to
    /// [`Transport::exchange`] (no deadline enforcement); every production
    /// backend MUST override this — a stuck device surfaces
    /// [`Error::TransportTimeout`], never hangs the caller. Only available
    /// on `std` builds (`core` has no clock).
    #[cfg(feature = "std")]
    fn exchange_timeout(&mut self, msg: &[u8], _timeout: Duration) -> Result<Vec<u8>> {
        self.exchange(msg)
    }

    /// Abort this transport. Cooperative, best-effort, `&self` so it can
    /// be called while another task owns the `&mut` exchange borrow via
    /// shared ownership OUTSIDE this trait.
    ///
    /// Per-backend reality:
    /// - OS backends (`linux`/`macos`/`windows`): a parked blocking read
    ///   cannot be interrupted through `std` alone — `cancel` is accepted
    ///   and resources release on drop; the parked reader thread exits
    ///   when the device next answers. Bounded waits come from
    ///   `exchange_timeout`, not from this hook.
    /// - `emu::TcpTransport`: dropping closes the socket (peer sees EOF);
    ///   same parked-read caveat as above.
    /// - `wasm_webhid` / `mobile`: the host owns the actual I/O threads
    ///   and CAN abort — hosts report [`Error::TransportCancelled`].
    /// - `MockTransport`: poisons itself — the next `exchange` returns
    ///   [`Error::TransportCancelled`] (for app cancel-flow tests).
    ///
    /// The default impl is a no-op for backends that cannot abort.
    fn cancel(&self) {}
}

/// Blanket impl for `&mut T`.
impl<T: Transport + ?Sized> Transport for &mut T {
    fn exchange(&mut self, msg: &[u8]) -> Result<Vec<u8>> {
        (**self).exchange(msg)
    }

    #[cfg(feature = "std")]
    fn exchange_timeout(&mut self, msg: &[u8], timeout: Duration) -> Result<Vec<u8>> {
        (**self).exchange_timeout(msg, timeout)
    }

    fn cancel(&self) {
        (**self).cancel()
    }
}
