//! Mobile-boundary tests: the C ABI driven by direct calls with
//! in-process stub host ops (no JNI, no Swift, no device — the boundary
//! is plain C and fully testable natively).
//!
//! Run: `cargo test --features hw --test hw_mobile` (needs `std` for the
//! stub's Mutex; the module itself is `no_std`).

#![cfg(all(feature = "hw", feature = "std"))]

use std::sync::Mutex;

use blockchain_utils::error::Error;
use blockchain_utils::hw::{
    mobile::{
        hw_mobile_close, hw_mobile_exchange, hw_mobile_open, hw_mobile_register_ops,
        register_host_ops, HostOps, MobileErrorCode, MobileTransport,
    },
    transport::Transport,
};

struct Stub {
    /// canned reply, or `None` for a wedged bearer (host never answers)
    reply: Option<Vec<u8>>,
    /// fail opens when true
    open_fails: bool,
    seen: Vec<Vec<u8>>,
    closes: usize,
    cancels: usize,
    timeouts_seen_ms: Vec<u32>,
}

static STUB: Mutex<Stub> = Mutex::new(Stub {
    reply: None,
    open_fails: false,
    seen: Vec::new(),
    closes: 0,
    cancels: 0,
    timeouts_seen_ms: Vec::new(),
});

extern "C" fn stub_open(vid: u16, _pid: u16) -> i64 {
    let s = STUB.lock().unwrap();
    if s.open_fails || vid == 0 {
        return MobileErrorCode::TransportUnavailable as i64;
    }
    41 // opaque fake handle
}

extern "C" fn stub_exchange(
    handle: i64,
    req: *const u8,
    req_len: usize,
    out: *mut u8,
    out_cap: usize,
    timeout_ms: u32,
) -> i64 {
    if handle != 41 {
        return MobileErrorCode::TransportDisconnected as i64;
    }
    let mut s = STUB.lock().unwrap();
    s.timeouts_seen_ms.push(timeout_ms);
    let bytes = unsafe { core::slice::from_raw_parts(req, req_len) };
    s.seen.push(bytes.to_vec());
    match &s.reply {
        None => MobileErrorCode::TransportTimeout as i64, // wedged bearer
        Some(reply) => {
            let n = core::cmp::min(reply.len(), out_cap);
            unsafe { core::ptr::copy_nonoverlapping(reply.as_ptr(), out, n) };
            n as i64
        }
    }
}

extern "C" fn stub_close(handle: i64) {
    if handle == 41 {
        STUB.lock().unwrap().closes += 1;
    }
}

extern "C" fn stub_cancel(handle: i64) {
    if handle == 41 {
        STUB.lock().unwrap().cancels += 1;
    }
}

fn ops() -> HostOps {
    HostOps {
        open: stub_open,
        exchange: stub_exchange,
        close: stub_close,
        cancel: Some(stub_cancel),
    }
}

fn reset(reply: Option<Vec<u8>>, open_fails: bool) {
    let mut s = STUB.lock().unwrap();
    s.reply = reply;
    s.open_fails = open_fails;
    s.seen.clear();
    s.closes = 0;
    s.cancels = 0;
    s.timeouts_seen_ms.clear();
}

// The stub + the global ops slot are process-global (`hw_log.rs` avoids
// this with a single test fn); serialize the stateful tests so one test's
// `reset()` can never interleave with another's exchange sequence.
static SERIAL: Mutex<()> = Mutex::new(());

#[test]
fn rust_side_round_trip() {
    let _serial = SERIAL.lock().unwrap();
    reset(Some(b"apdu-reply".to_vec()), false);
    let o = ops();
    let mut t = MobileTransport::open(&o, 0x2C97, 0).unwrap();
    let out = t.exchange(b"apdu-request").unwrap();
    assert_eq!(out, b"apdu-reply");
    let s = STUB.lock().unwrap();
    assert_eq!(s.seen, vec![b"apdu-request".to_vec()]);
}

#[test]
fn rust_side_timeout_and_cancel() {
    let _serial = SERIAL.lock().unwrap();
    reset(None, false); // wedged bearer
    let o = ops();
    let mut t = MobileTransport::open(&o, 0x2C97, 0).unwrap();
    let err = t
        .exchange_timeout(b"ping", core::time::Duration::from_millis(120))
        .unwrap_err();
    assert_eq!(err, Error::TransportTimeout);
    // The timeout reached the host (it enforces the deadline, like WASM).
    assert_eq!(STUB.lock().unwrap().timeouts_seen_ms, vec![120]);
    // Cancel reaches the host abort hook.
    t.cancel();
    assert_eq!(STUB.lock().unwrap().cancels, 1);
}

#[test]
fn rust_side_open_denied_and_drop_closes() {
    let _serial = SERIAL.lock().unwrap();
    reset(None, true);
    let o = ops();
    assert_eq!(
        MobileTransport::open(&o, 0x2C97, 0).unwrap_err(),
        Error::TransportUnavailable
    );
    reset(Some(b"x".to_vec()), false);
    {
        let _t = MobileTransport::open(&o, 0x2C97, 0).unwrap();
    }
    assert_eq!(STUB.lock().unwrap().closes, 1);
}

#[test]
fn c_abi_round_trip() {
    // Full C path: register → open → exchange → close, direct calls.
    let _serial = SERIAL.lock().unwrap();
    reset(Some(b"c-reply".to_vec()), false);
    let o = ops();
    assert_eq!(register_host_ops(&o), 0);
    assert_eq!(unsafe { hw_mobile_register_ops(&o as *const HostOps) }, 0);
    let h = hw_mobile_open(0x2C97, 0);
    assert!(h >= 0, "open failed: {h}");
    let mut out = [0u8; 64];
    let n = unsafe {
        hw_mobile_exchange(
            h,
            b"c-request".as_ptr(),
            b"c-request".len(),
            out.as_mut_ptr(),
            out.len(),
            1000,
        )
    };
    assert!(n >= 0, "exchange failed: {n}");
    assert_eq!(&out[..n as usize], b"c-reply");
    hw_mobile_close(h);
    assert_eq!(STUB.lock().unwrap().closes, 1);
}

#[test]
fn c_abi_error_codes_are_stable() {
    let _serial = SERIAL.lock().unwrap();
    reset(None, true); // opens fail
    let o = ops();
    assert_eq!(register_host_ops(&o), 0);
    assert_eq!(
        hw_mobile_open(0x2C97, 0),
        MobileErrorCode::TransportUnavailable as i64
    );
    // Null buffers are InvalidLength, never UB.
    let mut out = [0u8; 8];
    assert_eq!(
        unsafe { hw_mobile_exchange(1, core::ptr::null(), 0, out.as_mut_ptr(), out.len(), 10) },
        MobileErrorCode::InvalidLength as i64
    );
    assert_eq!(
        unsafe { hw_mobile_exchange(1, b"x".as_ptr(), 1, core::ptr::null_mut(), 8, 10) },
        MobileErrorCode::InvalidLength as i64
    );
    // Unknown handle → host reports disconnect.
    reset(Some(b"x".to_vec()), false);
    let mut out = [0u8; 8];
    assert_eq!(
        unsafe { hw_mobile_exchange(999, b"x".as_ptr(), 1, out.as_mut_ptr(), out.len(), 10) },
        MobileErrorCode::TransportDisconnected as i64
    );
}

#[test]
fn error_code_mapping_covers_variants() {
    use MobileErrorCode as C;
    assert_eq!(C::from(Error::TransportTimeout) as i64, -4);
    assert_eq!(C::from(Error::TransportCancelled) as i64, -6);
    assert_eq!(C::from(Error::InvalidLength) as i64, -7);
    assert_eq!(C::from(Error::VerificationFailed) as i64, C::Other as i64);
}
