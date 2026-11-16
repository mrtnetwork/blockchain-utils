//! macOS USB-HID backend over IOKit: pure `std` + raw `extern "C"`, zero crates.
//!
//! Compiled only on `std` macOS builds. Links `IOKit.framework` and
//! `CoreFoundation.framework` — no crate needed, just the `#[link]`
//! attributes below. Sandboxed / App-Store apps additionally need the
//! `com.apple.security.device.usb` entitlement or HID access fails.
//!
//! Same architecture as `hw::linux`: one [`Transport::exchange`] moves one
//! 64-byte report (framing stays in the caller), and a reader thread from
//! `hw::report` turns synchronous `IOHIDDeviceGetReport` calls into
//! deadline-honoring reads.
//!
//! **Status: written, not yet compiled against real IOKit headers.**
//! `cargo check --target x86_64-apple-darwin` validates shapes only — the
//! first real macOS build must confirm the `extern` signatures against
//! `IOKit/hid/IOHIDManager.h` (see `VERIFY` notes inline).

use std::ffi::c_void;
use std::os::raw::{c_char, c_uchar};
use std::time::Duration;

use crate::error::{Error, Result};
use crate::hw::discover::{family_for_vid, is_candidate_vid, UsbId};
use crate::hw::report::{spawn_report_reader, ReportReader};
use crate::hw::transport::Transport;

use alloc::string::String;
use alloc::vec::Vec;

/// HID report payload size. Report ID is passed separately to IOKit.
pub const HID_RAW_REPORT_LEN: usize = 64;
/// Default per-exchange deadline.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

// --------------------------------------------------------------- FFI layer ---

type CFIndex = isize;
type CFStringRef = *const c_void;
type CFNumberRef = *const c_void;
type CFSetRef = *const c_void;
type IOHIDManagerRef = *mut c_void;
type IOHIDDeviceRef = *mut c_void;

type IOReturn = i32;
const K_IO_RETURN_SUCCESS: IOReturn = 0;

/// VERIFY against IOHIDLib.h: `kIOHIDReportTypeInput = 0, Output = 1, Feature = 2`.
const K_IO_HID_REPORT_INPUT: u32 = 0;
const K_IO_HID_REPORT_OUTPUT: u32 = 1;
/// VERIFY against CFNumber.h: `kCFNumberSInt32Type = 3`.
const K_CF_NUMBER_SINT32: i32 = 3;
const K_CF_STRING_UTF8: u32 = 0x0800_0100;

#[link(name = "IOKit", kind = "framework")]
#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    // VERIFY: exported `CFStringRef const` symbols in IOKit.
    static kIOHIDVendorIDKey: CFStringRef;
    static kIOHIDProductIDKey: CFStringRef;
    static kIOHIDLocationIDKey: CFStringRef;
    static kIOHIDProductKey: CFStringRef;

    fn IOHIDManagerCreate(allocator: *const c_void, options: u32) -> IOHIDManagerRef;
    fn IOHIDManagerSetDeviceMatching(manager: IOHIDManagerRef, matching: *const c_void);
    fn IOHIDManagerOpen(manager: IOHIDManagerRef, options: u32) -> IOReturn;
    fn IOHIDManagerClose(manager: IOHIDManagerRef, options: u32) -> IOReturn;
    fn IOHIDManagerCopyDevices(manager: IOHIDManagerRef) -> CFSetRef;

    fn CFSetGetCount(set: CFSetRef) -> CFIndex;
    fn CFSetGetValues(set: CFSetRef, values: *mut *const c_void);
    fn CFRetain(cf: *const c_void) -> *const c_void;
    fn CFRelease(cf: *const c_void);

    fn IOHIDDeviceGetProperty(device: IOHIDDeviceRef, key: CFStringRef) -> *const c_void;
    fn CFNumberGetTypeID() -> usize;
    fn CFGetTypeID(cf: *const c_void) -> usize;
    fn CFNumberGetValue(number: CFNumberRef, the_type: i32, value_ptr: *mut c_void) -> c_uchar;
    fn CFStringGetCString(
        string: CFStringRef,
        buffer: *mut c_char,
        buffer_size: CFIndex,
        encoding: u32,
    ) -> c_uchar;

    fn IOHIDDeviceOpen(device: IOHIDDeviceRef, options: u32) -> IOReturn;
    fn IOHIDDeviceClose(device: IOHIDDeviceRef, options: u32) -> IOReturn;
    fn IOHIDDeviceSetReport(
        device: IOHIDDeviceRef,
        report_type: u32,
        report_id: CFIndex,
        report: *const u8,
        length: CFIndex,
    ) -> IOReturn;
    fn IOHIDDeviceGetReport(
        device: IOHIDDeviceRef,
        report_type: u32,
        report_id: CFIndex,
        report: *mut u8,
        length: *mut CFIndex,
    ) -> IOReturn;
}

fn cf_number(prop: *const c_void) -> Option<i64> {
    if prop.is_null() {
        return None;
    }
    unsafe {
        if CFGetTypeID(prop) != CFNumberGetTypeID() {
            return None;
        }
        let mut v: i64 = 0;
        // SInt32 read into 64 bits: value-promotion is safe for IDs < 2^31.
        let mut v32: i32 = 0;
        if CFNumberGetValue(
            prop,
            K_CF_NUMBER_SINT32,
            &mut v32 as *mut i32 as *mut c_void,
        ) == 0
        {
            return None;
        }
        v = v32 as i64;
        Some(v)
    }
}

fn cf_string(prop: *const c_void) -> Option<String> {
    if prop.is_null() {
        return None;
    }
    unsafe {
        let mut buf = [0 as c_char; 256];
        if CFStringGetCString(
            prop,
            buf.as_mut_ptr(),
            buf.len() as CFIndex,
            K_CF_STRING_UTF8,
        ) == 0
        {
            return None;
        }
        let bytes: Vec<u8> = buf
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8)
            .collect();
        String::from_utf8(bytes).ok()
    }
}

// ------------------------------------------------------------ enumeration ---

/// One HID device found by [`enumerate_candidates`]. `location_id` is the
/// stable open key (IOHID location ID survives re-enumeration while the
/// device stays plugged).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacHidDevice {
    pub location_id: u32,
    pub id: UsbId,
    pub name: String,
}

impl MacHidDevice {
    /// Wallet family (`"ledger"`, `"trezor"`, `"bitbox"`) or `None`.
    pub fn family(&self) -> Option<&'static str> {
        family_for_vid(self.id.vid)
    }

    /// True when the VID belongs to a known wallet vendor (probe to confirm).
    pub fn is_candidate(&self) -> bool {
        is_candidate_vid(self.id.vid)
    }
}

/// Point-in-time enumeration via `IOHIDManager` (NULL matching = all HID,
/// filtered to known VIDs in Rust so PID variations never hide a device).
/// Hotplug polling stays the embedder's job.
pub fn enumerate_candidates() -> Vec<MacHidDevice> {
    let mut out = Vec::new();
    unsafe {
        let mgr = IOHIDManagerCreate(core::ptr::null(), 0);
        if mgr.is_null() {
            return out;
        }
        IOHIDManagerSetDeviceMatching(mgr, core::ptr::null());
        if IOHIDManagerOpen(mgr, 0) != K_IO_RETURN_SUCCESS {
            IOHIDManagerClose(mgr, 0);
            return out;
        }
        let set = IOHIDManagerCopyDevices(mgr);
        if !set.is_null() {
            let n = CFSetGetCount(set);
            if n > 0 {
                let mut vals = alloc::vec![core::ptr::null::<c_void>(); n as usize];
                CFSetGetValues(set, vals.as_mut_ptr());
                for &d in &vals {
                    let dev = d as IOHIDDeviceRef;
                    let vid = cf_number(IOHIDDeviceGetProperty(dev, kIOHIDVendorIDKey));
                    let pid = cf_number(IOHIDDeviceGetProperty(dev, kIOHIDProductIDKey));
                    let loc = cf_number(IOHIDDeviceGetProperty(dev, kIOHIDLocationIDKey));
                    if let (Some(v), Some(p), Some(l)) = (vid, pid, loc) {
                        if is_candidate_vid(v as u16) {
                            let name = cf_string(IOHIDDeviceGetProperty(dev, kIOHIDProductKey))
                                .unwrap_or_else(|| String::from("unknown"));
                            out.push(MacHidDevice {
                                location_id: l as u32,
                                id: UsbId {
                                    vid: v as u16,
                                    pid: p as u16,
                                },
                                name,
                            });
                        }
                    }
                }
            }
            CFRelease(set);
        }
        IOHIDManagerClose(mgr, 0);
    }
    out
}

/// Index of the `index`-th device with this VID/PID (`pid == 0` matches any).
pub fn pick_candidate(devs: &[MacHidDevice], vid: u16, pid: u16, index: usize) -> Option<usize> {
    devs.iter()
        .enumerate()
        .filter(|(_, d)| d.id.vid == vid && (pid == 0 || d.id.pid == pid))
        .map(|(i, _)| i)
        .nth(index)
}

/// Re-enumerate and retain the device with this location ID. The manager is
/// closed afterwards; the retained device ref stays usable while plugged.
/// Unplug mid-session surfaces as I/O errors → `TransportDisconnected`.
fn retain_device_by_location(location_id: u32) -> Result<IOHIDDeviceRef> {
    unsafe {
        let mgr = IOHIDManagerCreate(core::ptr::null(), 0);
        if mgr.is_null() {
            return Err(Error::TransportUnavailable);
        }
        IOHIDManagerSetDeviceMatching(mgr, core::ptr::null());
        if IOHIDManagerOpen(mgr, 0) != K_IO_RETURN_SUCCESS {
            IOHIDManagerClose(mgr, 0);
            return Err(Error::TransportUnavailable);
        }
        let mut found: IOHIDDeviceRef = core::ptr::null_mut();
        let set = IOHIDManagerCopyDevices(mgr);
        if !set.is_null() {
            let n = CFSetGetCount(set);
            if n > 0 {
                let mut vals = alloc::vec![core::ptr::null::<c_void>(); n as usize];
                CFSetGetValues(set, vals.as_mut_ptr());
                for &d in &vals {
                    let dev = d as IOHIDDeviceRef;
                    if cf_number(IOHIDDeviceGetProperty(dev, kIOHIDLocationIDKey))
                        == Some(location_id as i64)
                    {
                        found = CFRetain(dev) as IOHIDDeviceRef;
                        break;
                    }
                }
            }
            CFRelease(set);
        }
        IOHIDManagerClose(mgr, 0);
        if found.is_null() {
            return Err(Error::TransportUnavailable);
        }
        if IOHIDDeviceOpen(found, 0) != K_IO_RETURN_SUCCESS {
            CFRelease(found);
            return Err(Error::TransportUnavailable);
        }
        Ok(found)
    }
}

// ---------------------------------------------------------------- transport ---

/// Synchronous-GetReport read handle for the `hw::report` reader thread.
/// IOKit device refs are safe to use from a non-creator thread for
/// GetReport/SetReport pairs; the transport owns both ends exclusively.
struct MacReadHandle {
    device: IOHIDDeviceRef,
}

// SAFETY: exclusively owned by the reader thread; IOKit serializes
// GetReport against the writer's SetReport internally.
unsafe impl Send for MacReadHandle {}

impl std::io::Read for MacReadHandle {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut tmp = [0u8; HID_RAW_REPORT_LEN];
        let mut len: CFIndex = tmp.len() as CFIndex;
        let rc = unsafe {
            IOHIDDeviceGetReport(
                self.device,
                K_IO_HID_REPORT_INPUT,
                0,
                tmp.as_mut_ptr(),
                &mut len,
            )
        };
        if rc != K_IO_RETURN_SUCCESS || len <= 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
        }
        let n = core::cmp::min(len as usize, buf.len());
        buf[..n].copy_from_slice(&tmp[..n]);
        Ok(n)
    }
}

/// Open USB-HID device on macOS.
pub struct UsbHidTransport {
    device: IOHIDDeviceRef,
    reader: ReportReader,
    reader_thread: std::thread::JoinHandle<()>,
}

// SAFETY: the device ref is exclusively owned; reader thread access goes
// through the same serialization IOKit provides. `UsbHidTransport` itself
// is `!Sync` by default (`*mut` field) — transports are `&mut`-driven.
unsafe impl Send for UsbHidTransport {}

impl UsbHidTransport {
    /// Open by IOHID location ID (see [`enumerate_candidates`]).
    pub fn open_location(location_id: u32) -> Result<Self> {
        let device = retain_device_by_location(location_id).map_err(|e| {
            crate::hw::log::warn("hw::macos", "iohid open failed");
            e
        })?;
        crate::hw::log::info("hw::macos", "iohid open");
        let (reader, reader_thread) =
            spawn_report_reader(MacReadHandle { device }, HID_RAW_REPORT_LEN);
        Ok(Self {
            device,
            reader,
            reader_thread,
        })
    }

    /// Open the `index`-th device with this VID (`pid == 0` matches any).
    pub fn open_nth(vid: u16, pid: u16, index: usize) -> Result<Self> {
        let devs = enumerate_candidates();
        let pos = pick_candidate(&devs, vid, pid, index).ok_or(Error::TransportUnavailable)?;
        Self::open_location(devs[pos].location_id)
    }

    /// Convenience: first device with this VID.
    pub fn open_first(vid: u16) -> Result<Self> {
        Self::open_nth(vid, 0, 0)
    }

    /// Read one 64-byte report with a deadline (no write first).
    pub fn read_report(&self, timeout: Duration) -> Result<[u8; HID_RAW_REPORT_LEN]> {
        let v = self.reader.read_report(timeout)?;
        if v.len() != HID_RAW_REPORT_LEN {
            return Err(Error::TransportRead);
        }
        let mut out = [0u8; HID_RAW_REPORT_LEN];
        out.copy_from_slice(&v);
        Ok(out)
    }

    /// Write one 64-byte report (no read after).
    pub fn write_report(&mut self, report: &[u8; HID_RAW_REPORT_LEN]) -> Result<()> {
        let rc = unsafe {
            IOHIDDeviceSetReport(
                self.device,
                K_IO_HID_REPORT_OUTPUT,
                0,
                report.as_ptr(),
                report.len() as CFIndex,
            )
        };
        if rc == K_IO_RETURN_SUCCESS {
            Ok(())
        } else {
            Err(Error::TransportWrite)
        }
    }
}

impl Drop for UsbHidTransport {
    fn drop(&mut self) {
        self.reader.stop();
        unsafe {
            IOHIDDeviceClose(self.device, 0);
            CFRelease(self.device);
        }
    }
}

impl Transport for UsbHidTransport {
    fn exchange(&mut self, msg: &[u8]) -> Result<Vec<u8>> {
        self.exchange_timeout(msg, DEFAULT_TIMEOUT)
    }

    fn exchange_timeout(&mut self, msg: &[u8], timeout: Duration) -> Result<Vec<u8>> {
        if msg.len() != HID_RAW_REPORT_LEN {
            return Err(Error::InvalidLength);
        }
        let mut report = [0u8; HID_RAW_REPORT_LEN];
        report.copy_from_slice(msg);
        self.write_report(&report)?;
        Ok(self.read_report(timeout)?.to_vec())
    }
}
