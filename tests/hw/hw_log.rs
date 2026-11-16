//! `hw::log` hook tests: install/replace/remove, event capture from real
//! backend failures, ordering. The sink is process-global, so the tests
//! serialize on `SERIAL` (same pattern as `hw_mobile.rs`).
//!
//! Run: `cargo test --features hw --test hw_log` (needs `std`).

#![cfg(all(feature = "hw", feature = "std"))]

use std::sync::Mutex;

use blockchain_utils::hw::{log_record, set_log_sink, LogLevel, LogRecord};

static EVENTS: Mutex<Vec<(LogLevel, &'static str, &'static str)>> = Mutex::new(Vec::new());
static SERIAL: Mutex<()> = Mutex::new(());

fn sink(r: LogRecord) {
    EVENTS.lock().unwrap().push((r.level, r.target, r.msg));
}

fn take() -> Vec<(LogLevel, &'static str, &'static str)> {
    core::mem::take(&mut *EVENTS.lock().unwrap())
}

#[test]
fn log_sink_lifecycle_and_backend_events() {
    let _serial = SERIAL.lock().unwrap();
    // No sink: no-op, no panic.
    log_record(LogLevel::Info, "test", "dropped silently");
    assert!(take().is_empty());

    // Install: unknown target events still flow (sink filters, not hw).
    assert!(set_log_sink(Some(sink)).is_none());
    log_record(LogLevel::Debug, "test", "hello");
    assert_eq!(take(), vec![(LogLevel::Debug, "test", "hello")]);

    // Level ordering is total (sinks use it to filter).
    assert!(LogLevel::Error > LogLevel::Warn);
    assert!(LogLevel::Warn > LogLevel::Info);
    assert!(LogLevel::Info > LogLevel::Debug);

    // Replacing returns the previous sink (still ours).
    assert!(set_log_sink(Some(sink)).is_some());
    assert!(take().is_empty());

    // Real backend failure emits (TCP connect refused — no emulator).
    let _ = blockchain_utils::hw::TcpTransport::connect(
        "127.0.0.1:1",
        core::time::Duration::from_millis(200),
    );
    let evts = take();
    assert!(
        evts.iter()
            .any(|(l, t, _)| *l == LogLevel::Warn && *t == "hw::emu"),
        "expected hw::emu warn, got {evts:?}"
    );

    // Removal stops capture; double-remove is fine.
    assert!(set_log_sink(None).is_some());
    assert!(set_log_sink(None).is_none());
    log_record(LogLevel::Error, "test", "dropped after removal");
    assert!(take().is_empty());
}

#[cfg(target_os = "linux")]
#[test]
fn linux_open_failure_logged() {
    let _serial = SERIAL.lock().unwrap();
    assert!(set_log_sink(Some(sink)).is_none());
    let _ = blockchain_utils::hw::UsbHidTransport::open_path("/dev/hidraw-nonexistent-xyz");
    let evts = take();
    assert!(
        evts.iter().any(|(l, t, m)| *l == LogLevel::Warn
            && *t == "hw::linux"
            && *m == "hidraw open failed"),
        "got {evts:?}"
    );
    assert!(set_log_sink(None).is_some());
}
