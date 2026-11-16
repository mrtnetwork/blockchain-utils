//! Linux USB-HID backend over `/dev/hidrawN`: pure `std`, zero new crates.
//!
//! Compiled only on `std` Linux builds. Needs read/write access to
//! `/dev/hidrawN` — without the shipped udev rules
//! (`hw/51-hw-wallets.rules`) `open()` fails with EACCES for normal users.
//!
//! Report model: one [`Transport::exchange`] moves exactly one 64-byte HID
//! report. Multi-report framing stays in the caller (`hid::hid_frame` /
//! `hid_unframe`, `trezor_frame` / `trezor_unframe`) — this backend never
//! guesses device framing.
//!
//! Timeout model: a dedicated reader thread owns a cloned handle and does
//! blocking reads; [`Transport::exchange_timeout`] waits on it with
//! `recv_timeout`. No raw syscalls, no `O_NONBLOCK` arch juggling — plain
//! `std` threads and channels.
//!
//! Hotplug: [`enumerate_candidates`] is point-in-time only; re-call it on a
//! timer in the embedder (see `Transport` docs).

use std::fs::{File, OpenOptions};
use std::thread::JoinHandle;
use std::time::Duration;

use crate::error::{Error, Result};
use crate::hw::discover::{family_for_vid, is_candidate_vid, UsbId};
use crate::hw::report::{spawn_report_reader, write_report_with_id, ReportReader};
use crate::hw::transport::Transport;

use alloc::string::String;
use alloc::vec::Vec;

/// HID report payload size (USB interrupt). hidraw adds a 1-byte report-ID
/// prefix on the wire — see [`write_report_to`].
pub const HID_RAW_REPORT_LEN: usize = 64;
/// Default per-exchange deadline.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

// ------------------------------------------------------------ enumeration ---

/// One hidraw device found by [`enumerate_candidates`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxHidDevice {
    /// `/dev/hidrawN` path.
    pub path: String,
    pub id: UsbId,
    /// `HID_NAME` from uevent (human label, informational only).
    pub name: String,
}

impl LinuxHidDevice {
    /// Wallet family (`"ledger"`, `"trezor"`, `"bitbox"`) or `None`.
    pub fn family(&self) -> Option<&'static str> {
        family_for_vid(self.id.vid)
    }

    /// True when the VID belongs to a known wallet vendor (probe to confirm).
    pub fn is_candidate(&self) -> bool {
        is_candidate_vid(self.id.vid)
    }
}

/// Parse one `/sys/.../device/uevent` body. Expects `HID_ID=<bus>:<vid>:<pid>`
/// (hex) and `HID_NAME=<label>` lines. Pure function, fixture-tested.
pub(crate) fn parse_uevent(body: &str) -> Option<(UsbId, String)> {
    let mut vid: Option<u16> = None;
    let mut pid: Option<u16> = None;
    let mut name: Option<&str> = None;
    for line in body.lines() {
        if let Some(rest) = line.strip_prefix("HID_ID=") {
            let mut parts = rest.split(':');
            parts.next()?; // bus type, ignored
            vid = u16::from_str_radix(parts.next()?, 16).ok();
            pid = u16::from_str_radix(parts.next()?, 16).ok();
        } else if let Some(rest) = line.strip_prefix("HID_NAME=") {
            name = Some(rest);
        }
    }
    Some((
        UsbId {
            vid: vid?,
            pid: pid?,
        },
        String::from(name.unwrap_or("unknown")),
    ))
}

/// Point-in-time enumeration of `/dev/hidraw*`. Returns every HID device
/// (not just wallet candidates) — filter with [`LinuxHidDevice::is_candidate`]
/// or [`pick_candidate`], then **probe** survivors (open + harmless status
/// request + short timeout) before trusting them.
pub fn enumerate_candidates() -> Vec<LinuxHidDevice> {
    let mut out = Vec::new();
    let Ok(dir) = std::fs::read_dir("/dev") else {
        return out;
    };
    for entry in dir.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.starts_with("hidraw") {
            continue;
        }
        let uevent = alloc::format!("/sys/class/hidraw/{name}/device/uevent");
        let Ok(body) = std::fs::read_to_string(&uevent) else {
            continue;
        };
        if let Some((id, dev_name)) = parse_uevent(&body) {
            out.push(LinuxHidDevice {
                path: alloc::format!("/dev/{name}"),
                id,
                name: dev_name,
            });
        }
    }
    out
}

/// Pick the `index`-th device with this VID/PID (solves "two Ledgers plugged
/// in"): returns its position in `devs`, or `None`. Pure, tested.
pub fn pick_candidate(devs: &[LinuxHidDevice], vid: u16, pid: u16, index: usize) -> Option<usize> {
    devs.iter()
        .enumerate()
        .filter(|(_, d)| d.id.vid == vid && (pid == 0 || d.id.pid == pid))
        .map(|(i, _)| i)
        .nth(index)
}

// --------------------------------------------------------------- reporting ---
// Blocking reads/writes live in `hw::report` (shared with macOS/Windows);
// this module only adds the hidraw open/enumerate side.

// ---------------------------------------------------------------- transport ---

/// Open USB-HID device at `/dev/hidrawN`.
#[derive(Debug)]
pub struct UsbHidTransport {
    writer: File,
    reader: ReportReader,
    /// Kept alive so the reader thread outlives nothing it borrows (it owns
    /// a cloned `File`, so this is only a join/stop handle — never joined
    /// on drop, see below).
    #[allow(dead_code)]
    reader_thread: JoinHandle<()>,
}

impl UsbHidTransport {
    /// Open `/dev/hidrawN` directly.
    pub fn open_path(path: &str) -> Result<Self> {
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| {
                crate::hw::log::warn("hw::linux", "hidraw open failed");
                use std::io::ErrorKind as K;
                match e.kind() {
                    // Missing node, EACCES without udev rules, busy: all mean
                    // "no usable channel yet" — never a write/read error.
                    K::NotFound | K::PermissionDenied | K::AlreadyExists | K::WouldBlock => {
                        Error::TransportUnavailable
                    }
                    K::TimedOut => Error::TransportTimeout,
                    _ => Error::TransportUnavailable,
                }
            })?;
        crate::hw::log::info("hw::linux", "hidraw open");
        let rf = f.try_clone().map_err(|_| Error::TransportUnavailable)?;
        let (reader, reader_thread) = spawn_report_reader(rf, HID_RAW_REPORT_LEN);
        Ok(Self {
            writer: f,
            reader,
            reader_thread,
        })
    }

    /// Open the `index`-th device with this VID (`pid == 0` matches any
    /// PID — PIDs vary per model/firmware). Probe the result before use.
    pub fn open_nth(vid: u16, pid: u16, index: usize) -> Result<Self> {
        let devs = enumerate_candidates();
        let pos = pick_candidate(&devs, vid, pid, index).ok_or(Error::TransportUnavailable)?;
        Self::open_path(&devs[pos].path)
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
        write_report_with_id(&mut self.writer, report)
    }
}

impl Drop for UsbHidTransport {
    fn drop(&mut self) {
        // Ask the reader to exit. If it is parked in a timed-out blocking
        // read it exits when the device finally answers (at most one parked
        // thread per transport); never block Drop waiting for hardware.
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
        self.write_report(&report).inspect_err(|_| {
            crate::hw::log::warn("hw::linux", "hidraw write failed");
        })?;
        let reply = self.read_report(timeout).inspect_err(|&e| {
            if e == Error::TransportTimeout {
                crate::hw::log::warn("hw::linux", "hidraw read timeout");
            } else {
                crate::hw::log::warn("hw::linux", "hidraw read failed");
            }
        })?;
        Ok(reply.to_vec())
    }
}

// ------------------------------------------------------------------- tests ---

#[cfg(test)]
mod tests {
    use super::*;
    // `Read`/`Write` are used only by the loopback test below.
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};

    const LEDGER_UEVENT: &str =
        "DRIVER=hid-generic\nHID_ID=0003:00002C97:00005011\nHID_NAME=Ledger Nano S Plus\n";
    const TREZOR_UEVENT: &str =
        "DRIVER=hid-generic\nHID_ID=0003:00001209:000053C1\nHID_NAME=Trezor\n";

    #[test]
    fn uevent_parses_vid_pid_name() {
        let (id, name) = parse_uevent(LEDGER_UEVENT).unwrap();
        assert_eq!((id.vid, id.pid), (0x2C97, 0x5011));
        assert_eq!(name, "Ledger Nano S Plus");
        let (id, _) = parse_uevent(TREZOR_UEVENT).unwrap();
        assert_eq!((id.vid, id.pid), (0x1209, 0x53C1));
    }

    #[test]
    fn uevent_rejects_garbage() {
        for bad in [
            "",
            "HID_ID=nope",
            "HID_ID=0003:zzzz:0001\n",
            "HID_NAME=only-name\n",
        ] {
            assert!(parse_uevent(bad).is_none(), "{bad:?}");
        }
    }

    fn two_ledgers() -> Vec<LinuxHidDevice> {
        alloc::vec![
            LinuxHidDevice {
                path: String::from("/dev/hidraw0"),
                id: UsbId {
                    vid: 0x2C97,
                    pid: 0x5011
                },
                name: String::from("Ledger Nano S Plus"),
            },
            LinuxHidDevice {
                path: String::from("/dev/hidraw3"),
                id: UsbId {
                    vid: 0x2C97,
                    pid: 0x5011
                },
                name: String::from("Ledger Nano S Plus"),
            },
        ]
    }

    #[test]
    fn pick_selects_among_identical_vids() {
        let devs = two_ledgers();
        assert_eq!(pick_candidate(&devs, 0x2C97, 0, 0), Some(0));
        assert_eq!(pick_candidate(&devs, 0x2C97, 0, 1), Some(1));
        assert_eq!(pick_candidate(&devs, 0x2C97, 0, 2), None);
        assert_eq!(pick_candidate(&devs, 0x1209, 0, 0), None);
        // pid filter still works when the caller knows the model
        assert_eq!(pick_candidate(&devs, 0x2C97, 0x5011, 1), Some(1));
        assert_eq!(pick_candidate(&devs, 0x2C97, 0x9999, 0), None);
    }

    /// TCP pair standing in for the hidraw `File` (both are blocking
    /// byte streams — the reader/writer code cannot tell).
    fn stream_pair() -> (TcpStream, TcpStream) {
        let ln = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = ln.local_addr().unwrap().port();
        let a = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let (b, _) = ln.accept().unwrap();
        (a, b)
    }

    #[test]
    fn report_round_trip_over_loopback() {
        let (mut w, mut r) = stream_pair();
        // Reader sits on the writer's end (data emerging at `w` was written
        // by the device side `r`); the fake device drains/writes via `r`.
        let (reader, _h) = spawn_report_reader(w.try_clone().unwrap(), HID_RAW_REPORT_LEN);
        let report = [0xAB; HID_RAW_REPORT_LEN];
        write_report_with_id(&mut w, &report).unwrap();
        // Fake device side: consume the 65-byte write (kernel strips the
        // report ID on real hidraw), then answer one 64-byte report.
        let mut wire = [0u8; HID_RAW_REPORT_LEN + 1];
        r.read_exact(&mut wire).unwrap();
        assert_eq!(wire[0], 0x00);
        r.write_all(&report).unwrap();
        r.flush().unwrap();
        let got = reader.read_report(Duration::from_secs(5)).unwrap();
        assert_eq!(got, report.to_vec());
        reader.stop();
    }

    #[test]
    fn silent_device_times_out() {
        let (_w, r) = stream_pair(); // never written to
        let (reader, _h) = spawn_report_reader(r, HID_RAW_REPORT_LEN);
        let err = reader.read_report(Duration::from_millis(100)).unwrap_err();
        assert_eq!(err, Error::TransportTimeout);
        reader.stop();
    }

    #[test]
    fn write_prefixes_report_id() {
        // hidraw wire format: 0x00 || 64 payload bytes.
        let ln = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = ln.local_addr().unwrap().port();
        let mut w = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let (mut srv, _) = ln.accept().unwrap();
        write_report_with_id(&mut w, &[0x05; HID_RAW_REPORT_LEN]).unwrap();
        let mut wire = [0u8; HID_RAW_REPORT_LEN + 1];
        srv.read_exact(&mut wire).unwrap();
        assert_eq!(wire[0], 0x00);
        assert_eq!(&wire[1..], &[0x05; HID_RAW_REPORT_LEN]);
    }

    #[test]
    fn exchange_rejects_wrong_size_before_io() {
        let (t, _srv) = loopback_transport();
        let mut t = t;
        // 63 and 65 bytes must be refused without touching the wire.
        assert_eq!(t.exchange(&[0u8; 63]), Err(Error::InvalidLength));
        assert_eq!(t.exchange(&[0u8; 65]), Err(Error::InvalidLength));
    }

    #[test]
    fn exchange_round_trip_one_report() {
        use crate::hw::transport::Transport as _;
        let (mut t, mut srv) = loopback_transport();
        let report = [0x77u8; HID_RAW_REPORT_LEN];
        // Fake device: read the 65-byte write, answer one 64-byte report.
        let h = std::thread::spawn(move || {
            let mut wire = [0u8; HID_RAW_REPORT_LEN + 1];
            srv.read_exact(&mut wire).unwrap();
            assert_eq!(wire[0], 0x00);
            assert_eq!(&wire[1..], &report);
            srv.write_all(&[0x99u8; HID_RAW_REPORT_LEN]).unwrap();
            srv.flush().unwrap();
        });
        let resp = t.exchange(&report).unwrap();
        assert_eq!(resp, alloc::vec![0x99u8; HID_RAW_REPORT_LEN]);
        h.join().unwrap();
    }

    /// `UsbHidTransport` whose hidraw `File` is one end of a TCP pair.
    #[cfg(test)]
    fn loopback_transport() -> (UsbHidTransport, TcpStream) {
        use std::os::unix::io::{FromRawFd, IntoRawFd};
        let (sock, srv) = stream_pair();
        let file = unsafe { File::from_raw_fd(sock.into_raw_fd()) };
        let rf = file.try_clone().unwrap();
        let (reader, reader_thread) = spawn_report_reader(rf, HID_RAW_REPORT_LEN);
        (
            UsbHidTransport {
                writer: file,
                reader,
                reader_thread,
            },
            srv,
        )
    }
}
