//! Windows USB-HID backend over `hid.dll` / `setupapi.dll`: pure `std` + raw
//! `extern "system"`, zero crates.
//!
//! Compiled only on `std` Windows builds. Same architecture as `hw::linux`:
//! one [`Transport::exchange`] moves one 64-byte report, and a reader thread
//! from `hw::report` turns blocking `ReadFile` calls into deadline-honoring
//! reads (deliberately synchronous I/O — no `OVERLAPPED` structs; the thread
//! is the timeout mechanism).
//!
//! Report-ID note: Windows prefixes interrupt reads with the report ID even
//! for unnumbered devices, so the reader consumes 65 bytes and strips a
//! leading `0x00`. All `DeviceKind`s here use 64-byte unnumbered reports.
//!
//! Driver note: current Ledger/Trezor firmware works with
//! the inbox HID driver. This backend speaks HID only.
//!
//! **Status: written, not yet built on Windows.** `cargo check --target
//! x86_64-pc-windows-gnu` validates shapes only — the first real Windows
//! build must confirm behavior on Win10 + Win11 separately.

use std::ffi::c_void;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::time::Duration;

use crate::error::{Error, Result};
use crate::hw::discover::{family_for_vid, is_candidate_vid, UsbId};
use crate::hw::report::{spawn_report_reader, write_report_with_id, ReportReader};
use crate::hw::transport::Transport;

use alloc::string::String;
use alloc::vec::Vec;

/// HID report payload size (device bytes; the wire adds a report-ID byte).
pub const HID_RAW_REPORT_LEN: usize = 64;
/// Bytes consumed per read: 64 payload + 1 report-ID prefix.
const HID_WIRE_LEN: usize = HID_RAW_REPORT_LEN + 1;
/// Default per-exchange deadline.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

// --------------------------------------------------------------- FFI layer ---

type HANDLE = *mut c_void;
type BOOL = i32;
type DWORD = u32;
type HDEVINFO = *mut c_void;

const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;
const GENERIC_READ: DWORD = 0x8000_0000;
const GENERIC_WRITE: DWORD = 0x4000_0000;
const FILE_SHARE_READ: DWORD = 0x0000_0001;
const FILE_SHARE_WRITE: DWORD = 0x0000_0002;
const OPEN_EXISTING: DWORD = 3;
const DIGCF_PRESENT: DWORD = 0x02;
const DIGCF_DEVICEINTERFACE: DWORD = 0x10;

/// VERIFY against `hidclass.h`: `{4D1E55B2-F16F-11CF-88CB-001111000030}`.
const HID_CLASS_GUID: GUID = GUID {
    data1: 0x4D1E_55B2,
    data2: 0xF16F,
    data3: 0x11CF,
    data4: [0x88, 0xCB, 0x00, 0x11, 0x11, 0x00, 0x00, 0x30],
};

#[repr(C)]
struct GUID {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

#[repr(C)]
struct SpDeviceInterfaceData {
    cb_size: DWORD,
    interface_class_guid: GUID,
    flags: DWORD,
    reserved: usize,
}

#[repr(C)]
struct HiddAttributes {
    size: DWORD,
    vendor_id: u16,
    product_id: u16,
    version_number: u16,
}

#[link(name = "kernel32")]
extern "system" {
    fn CreateFileW(
        file_name: *const u16,
        desired_access: DWORD,
        share_mode: DWORD,
        security_attributes: *mut c_void,
        creation_disposition: DWORD,
        flags_and_attributes: DWORD,
        template_file: HANDLE,
    ) -> HANDLE;
    fn ReadFile(
        file: HANDLE,
        buffer: *mut u8,
        bytes_to_read: DWORD,
        bytes_read: *mut DWORD,
        overlapped: *mut c_void,
    ) -> BOOL;
    fn WriteFile(
        file: HANDLE,
        buffer: *const u8,
        bytes_to_write: DWORD,
        bytes_written: *mut DWORD,
        overlapped: *mut c_void,
    ) -> BOOL;
    fn CloseHandle(object: HANDLE) -> BOOL;
}

#[link(name = "setupapi")]
extern "system" {
    fn SetupDiGetClassDevsW(
        class_guid: *const GUID,
        enumerator: *const u16,
        hwnd_parent: *mut c_void,
        flags: DWORD,
    ) -> HDEVINFO;
    fn SetupDiEnumDeviceInterfaces(
        device_info_set: HDEVINFO,
        device_info_data: *mut c_void,
        interface_class_guid: *const GUID,
        member_index: DWORD,
        device_interface_data: *mut SpDeviceInterfaceData,
    ) -> BOOL;
    fn SetupDiGetDeviceInterfaceDetailW(
        device_info_set: HDEVINFO,
        device_interface_data: *mut SpDeviceInterfaceData,
        device_interface_detail_data: *mut u8,
        device_interface_detail_data_size: DWORD,
        required_size: *mut DWORD,
        device_info_data: *mut c_void,
    ) -> BOOL;
    fn SetupDiDestroyDeviceInfoList(device_info_set: HDEVINFO) -> BOOL;
}

#[link(name = "hid")]
extern "system" {
    fn HidD_GetAttributes(hid_device_object: HANDLE, attributes: *mut HiddAttributes) -> BOOL;
    fn HidD_GetProductString(
        hid_device_object: HANDLE,
        buffer: *mut u16,
        buffer_length: DWORD,
    ) -> BOOL;
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(core::iter::once(0)).collect()
}

/// `cbSize` for `SP_DEVICE_INTERFACE_DETAIL_DATA_W`: 8 on 64-bit, 6 on 32-bit.
#[cfg(target_pointer_width = "64")]
const DETAIL_CB_SIZE: DWORD = 8;
#[cfg(target_pointer_width = "32")]
const DETAIL_CB_SIZE: DWORD = 6;

fn detail_cb_size() -> DWORD {
    DETAIL_CB_SIZE
}

/// Open a HID device-interface path for sync read/write.
fn open_path_raw(path: &str) -> Result<OwnedHandle> {
    let w = wide(path);
    let h = unsafe {
        CreateFileW(
            w.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            core::ptr::null_mut(),
            OPEN_EXISTING,
            0,
            core::ptr::null_mut(),
        )
    };
    if h.is_null() || h == INVALID_HANDLE_VALUE {
        return Err(Error::TransportUnavailable);
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(h as *mut core::ffi::c_void) })
}

fn product_string(handle: HANDLE) -> String {
    let mut buf = [0u16; 126];
    let ok = unsafe { HidD_GetProductString(handle, buf.as_mut_ptr(), (buf.len() * 2) as DWORD) };
    if ok == 0 {
        return String::from("unknown");
    }
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

// ------------------------------------------------------------ enumeration ---

/// One HID device found by [`enumerate_candidates`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsHidDevice {
    /// Device-interface path for `CreateFileW`.
    pub path: String,
    pub id: UsbId,
    pub name: String,
}

impl WindowsHidDevice {
    /// Wallet family (`"ledger"`, `"trezor"`, `"bitbox"`) or `None`.
    pub fn family(&self) -> Option<&'static str> {
        family_for_vid(self.id.vid)
    }

    /// True when the VID belongs to a known wallet vendor (probe to confirm).
    pub fn is_candidate(&self) -> bool {
        is_candidate_vid(self.id.vid)
    }
}

/// Point-in-time enumeration via setupapi + `HidD_GetAttributes` per
/// candidate (each is briefly opened to read VID/PID, then closed).
/// Hotplug polling stays the embedder's job.
pub fn enumerate_candidates() -> Vec<WindowsHidDevice> {
    let mut out = Vec::new();
    unsafe {
        let set = SetupDiGetClassDevsW(
            &HID_CLASS_GUID,
            core::ptr::null(),
            core::ptr::null_mut(),
            DIGCF_PRESENT | DIGCF_DEVICEINTERFACE,
        );
        if set.is_null() {
            return out;
        }
        let mut index: DWORD = 0;
        loop {
            let mut iface = SpDeviceInterfaceData {
                cb_size: core::mem::size_of::<SpDeviceInterfaceData>() as DWORD,
                interface_class_guid: HID_CLASS_GUID,
                flags: 0,
                reserved: 0,
            };
            // VERIFY: does the real struct carry the GUID field, or only
            // cbSize? setupapi.h: cbSize + InterfaceClassGuid + Flags +
            // Reserved — as declared. First Windows build confirms.
            if SetupDiEnumDeviceInterfaces(
                set,
                core::ptr::null_mut(),
                &HID_CLASS_GUID,
                index,
                &mut iface,
            ) == 0
            {
                break;
            }
            index += 1;
            let mut need: DWORD = 0;
            SetupDiGetDeviceInterfaceDetailW(
                set,
                &mut iface,
                core::ptr::null_mut(),
                0,
                &mut need,
                core::ptr::null_mut(),
            );
            if need == 0 || need > 4096 {
                continue;
            }
            let mut detail = alloc::vec![0u8; need as usize];
            // Write cbSize into the buffer head (native endian DWORD).
            detail[..4].copy_from_slice(&detail_cb_size().to_ne_bytes());
            if SetupDiGetDeviceInterfaceDetailW(
                set,
                &mut iface,
                detail.as_mut_ptr(),
                need,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            ) == 0
            {
                continue;
            }
            // DevicePath starts at offset cbSize, NUL-terminated UTF-16.
            let off = detail_cb_size() as usize;
            let units = need as usize - off;
            if units % 2 != 0 || off >= need as usize {
                continue;
            }
            let words: Vec<u16> = (0..units / 2)
                .map(|i| u16::from_ne_bytes([detail[off + 2 * i], detail[off + 2 * i + 1]]))
                .collect();
            let end = words.iter().position(|&c| c == 0).unwrap_or(words.len());
            let path = String::from_utf16_lossy(&words[..end]);
            // Briefly open for VID/PID + product string, then close.
            if let Ok(handle) = open_path_raw(&path) {
                let raw: HANDLE = handle.as_raw_handle() as HANDLE;
                let mut attr = HiddAttributes {
                    size: core::mem::size_of::<HiddAttributes>() as DWORD,
                    vendor_id: 0,
                    product_id: 0,
                    version_number: 0,
                };
                if HidD_GetAttributes(raw, &mut attr) != 0 && is_candidate_vid(attr.vendor_id) {
                    out.push(WindowsHidDevice {
                        path,
                        id: UsbId {
                            vid: attr.vendor_id,
                            pid: attr.product_id,
                        },
                        name: product_string(raw),
                    });
                }
            }
        }
        SetupDiDestroyDeviceInfoList(set);
    }
    out
}

/// Index of the `index`-th device with this VID/PID (`pid == 0` matches any).
pub fn pick_candidate(
    devs: &[WindowsHidDevice],
    vid: u16,
    pid: u16,
    index: usize,
) -> Option<usize> {
    devs.iter()
        .enumerate()
        .filter(|(_, d)| d.id.vid == vid && (pid == 0 || d.id.pid == pid))
        .map(|(i, _)| i)
        .nth(index)
}

// ---------------------------------------------------------------- transport ---

/// Synchronous-`ReadFile` handle adapter for the `hw::report` reader thread.
/// `File:try_clone` duplicates the HANDLE; both ends stay synchronous.
struct WinReadHandle {
    file: std::fs::File,
}

// SAFETY: exclusively owned by the reader thread.
unsafe impl Send for WinReadHandle {}

impl std::io::Read for WinReadHandle {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        use std::io::Read as _;
        self.file.read(buf)
    }
}

/// Open USB-HID device on Windows.
pub struct UsbHidTransport {
    writer: std::fs::File,
    reader: ReportReader,
    reader_thread: std::thread::JoinHandle<()>,
}

impl UsbHidTransport {
    fn from_handle(handle: OwnedHandle) -> Result<Self> {
        let file = std::fs::File::from(handle);
        let rf = file.try_clone().map_err(|_| Error::TransportUnavailable)?;
        let (reader, reader_thread) = spawn_report_reader(WinReadHandle { file: rf }, HID_WIRE_LEN);
        Ok(Self {
            writer: file,
            reader,
            reader_thread,
        })
    }

    /// Open a device-interface path (see [`enumerate_candidates`]).
    pub fn open_path(path: &str) -> Result<Self> {
        let handle = open_path_raw(path).map_err(|e| {
            crate::hw::log::warn("hw::windows", "hid open failed");
            e
        })?;
        crate::hw::log::info("hw::windows", "hid open");
        Self::from_handle(handle)
    }

    /// Open the `index`-th device with this VID (`pid == 0` matches any).
    pub fn open_nth(vid: u16, pid: u16, index: usize) -> Result<Self> {
        let devs = enumerate_candidates();
        let pos = pick_candidate(&devs, vid, pid, index).ok_or(Error::TransportUnavailable)?;
        Self::open_path(&devs[pos].path)
    }

    /// Convenience: first device with this VID.
    pub fn open_first(vid: u16) -> Result<Self> {
        Self::open_nth(vid, 0, 0)
    }

    /// Read one 64-byte report with a deadline (strips the report-ID byte).
    pub fn read_report(&self, timeout: Duration) -> Result<[u8; HID_RAW_REPORT_LEN]> {
        let v = self.reader.read_report(timeout)?;
        // Unnumbered devices: 65 bytes with leading 0x00. Tolerate a bare
        // 64-byte read too (some drivers strip it themselves).
        let payload: &[u8] = if v.len() == HID_WIRE_LEN && v[0] == 0x00 {
            &v[1..]
        } else if v.len() == HID_RAW_REPORT_LEN {
            &v
        } else {
            return Err(Error::TransportRead);
        };
        let mut out = [0u8; HID_RAW_REPORT_LEN];
        out.copy_from_slice(payload);
        Ok(out)
    }

    /// Write one 64-byte report (leading `0x00` report ID added).
    pub fn write_report(&mut self, report: &[u8; HID_RAW_REPORT_LEN]) -> Result<()> {
        write_report_with_id(&mut self.writer, report)
    }
}

impl Drop for UsbHidTransport {
    fn drop(&mut self) {
        // Same parked-thread profile as Linux: the reader exits when the
        // device next answers (or the process exits). `CancelIoEx` on the
        // reader thread is a possible future tightening.
        self.reader.stop();
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
