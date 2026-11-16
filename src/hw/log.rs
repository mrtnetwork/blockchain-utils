//! Structured diagnostics hook: zero-dep, `no_std`-safe, `alloc`-free.
//!
//! The `log` crate is a dependency — so `hw` ships its own 40-line sink
//! instead. The app installs one global `fn(LogRecord)`; backends report
//! lifecycle events (opened, closed, timeout, read/write failure,
//! disconnect) with STATIC strings, so the log path never allocates and
//! costs one atomic load when no sink is installed.
//!
//! This separates concerns so that: the
//! codec layer already surfaces user-rejection vs failure via status
//! words (`apdu`/`trezor` parse results); the log hook tells you WHICH
//! backend hit WHAT transport event, without dragging `error` payloads
//! through a formatting layer. Targets are backend paths
//! (`"hw::linux"`, `"hw::emu"`, …); messages are fixed event names.
//!
//! Not a general logger: no levels below `Debug`, no kv-pairs, no
//! per-transport sinks. If you need those, wrap `Transport` in the app.

use core::sync::atomic::{AtomicUsize, Ordering};

/// Severity, ascending (`Debug < Info < Warn < Error` via derived `Ord`);
/// sinks typically filter with `record.level >= min_level`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

/// One diagnostic event. All strings are `'static` — no allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LogRecord {
    pub level: LogLevel,
    pub target: &'static str,
    pub msg: &'static str,
}

static SINK: AtomicUsize = AtomicUsize::new(0);

/// Install (or, with `None`, remove) the global log sink. Returns the
/// previously installed sink, if any. `fn` pointers are `Sync`, so this
/// is safe to call from any thread; last writer wins.
pub fn set_log_sink(sink: Option<fn(LogRecord)>) -> Option<fn(LogRecord)> {
    let prev = SINK.swap(sink.map_or(0, |f| f as usize), Ordering::AcqRel);
    if prev == 0 {
        None
    } else {
        // SAFETY: only ever stored from a real `fn` item above.
        Some(unsafe { core::mem::transmute::<usize, fn(LogRecord)>(prev) })
    }
}

/// Emit a record if a sink is installed. One atomic load on the cold path;
/// backends call this unconditionally (no `if sink_installed` dance at
/// call sites).
#[inline]
pub fn log_record(level: LogLevel, target: &'static str, msg: &'static str) {
    let raw = SINK.load(Ordering::Acquire);
    if raw != 0 {
        // SAFETY: only ever stored from a real `fn` item (see setter).
        let sink = unsafe { core::mem::transmute::<usize, fn(LogRecord)>(raw) };
        sink(LogRecord { level, target, msg });
    }
}

/// Shorthand for [`log_record`] at [`LogLevel::Error`].
#[inline]
pub fn error(target: &'static str, msg: &'static str) {
    log_record(LogLevel::Error, target, msg);
}

/// Shorthand for [`log_record`] at [`LogLevel::Warn`].
#[inline]
pub fn warn(target: &'static str, msg: &'static str) {
    log_record(LogLevel::Warn, target, msg);
}

/// Shorthand for [`log_record`] at [`LogLevel::Info`].
#[inline]
pub fn info(target: &'static str, msg: &'static str) {
    log_record(LogLevel::Info, target, msg);
}

/// Shorthand for [`log_record`] at [`LogLevel::Debug`].
#[inline]
pub fn debug(target: &'static str, msg: &'static str) {
    log_record(LogLevel::Debug, target, msg);
}
