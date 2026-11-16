//! Linux backend smoke tests: enumeration + selection without hardware.
//! Report-machinery tests live in-module (`hw::linux::tests`) over TCP
//! loopback. Real-device validation (`open_*` against a Ledger/Trezor)
//! stays manual.
//!
//! Run: `cargo test --features hw --test hw_linux` (Linux only).

#![cfg(all(feature = "hw", feature = "std", target_os = "linux"))]

use blockchain_utils::error::Error;
use blockchain_utils::hw::{enumerate_candidates, pick_candidate, LinuxHidDevice};

fn fake(vid: u16, pid: u16, path: &str) -> LinuxHidDevice {
    LinuxHidDevice {
        path: path.into(),
        id: blockchain_utils::hw::discover::UsbId { vid, pid },
        name: "fake".into(),
    }
}

#[test]
fn enumerate_runs_without_hardware() {
    // Must never panic/privilege-fail when no devices exist; every entry
    // must carry a hidraw path.
    for d in enumerate_candidates() {
        assert!(d.path.starts_with("/dev/hidraw"), "{}", d.path);
    }
}

#[test]
fn pick_supports_multi_device_selection() {
    let devs = vec![
        fake(0x2C97, 0x5011, "/dev/hidraw0"),
        fake(0x2C97, 0xC001, "/dev/hidraw1"),
        fake(0x1209, 0x53C1, "/dev/hidraw2"),
    ];
    assert_eq!(pick_candidate(&devs, 0x2C97, 0, 0), Some(0));
    assert_eq!(pick_candidate(&devs, 0x2C97, 0, 1), Some(1));
    assert_eq!(pick_candidate(&devs, 0x2C97, 0xC001, 0), Some(1));
    assert_eq!(pick_candidate(&devs, 0x1209, 0, 0), Some(2));
    assert_eq!(pick_candidate(&devs, 0x1209, 0, 1), None);
    assert!(devs[0].is_candidate() && devs[2].is_candidate());
    assert_eq!(devs[0].family(), Some("ledger"));
    assert_eq!(devs[2].family(), Some("trezor"));
}

#[test]
fn open_missing_node_is_unavailable() {
    let err = blockchain_utils::hw::UsbHidTransport::open_path("/dev/hidraw-nonexistent-xyz")
        .unwrap_err();
    assert_eq!(err, Error::TransportUnavailable);
}
