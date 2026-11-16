//! Emulator-protocol tests WITHOUT the emulator: a loopback TCP server that
//! speaks the same ledgercomm framing as Speculos (`u32 BE len || bytes`
//! both ways), so `TcpTransport` + the wallet codec get exercised in CI.
//! The real Speculos run stays in `hw_speculos.rs` (ignored, needs docker).
//!
//! Run: `cargo test --features hw --test hw_loopback` (needs `std`).

#![cfg(all(feature = "hw", feature = "std"))]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::Duration;

use blockchain_utils::error::Error;
use blockchain_utils::hw::{
    coin::CoinProfile, path::parse_path, transport::Transport, wallet::DeviceKind,
    wallet::HardwareWallet, wallet::Wallet, TcpTransport,
};

/// Spawn a ledgercomm echo server: replies `msg` back verbatim. Returns port.
fn echo_server() -> u16 {
    let ln = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = ln.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let (mut s, _) = ln.accept().unwrap();
        let mut hdr = [0u8; 4];
        s.read_exact(&mut hdr).unwrap();
        let n = u32::from_be_bytes(hdr) as usize;
        let mut msg = vec![0u8; n];
        s.read_exact(&mut msg).unwrap();
        s.write_all(&hdr).unwrap();
        s.write_all(&msg).unwrap();
        s.flush().unwrap();
    });
    port
}

/// Spawn a black-hole server: accepts, then never answers (wedged device).
fn blackhole_server() -> u16 {
    let ln = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = ln.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let (mut s, _) = ln.accept().unwrap();
        let mut buf = [0u8; 4096];
        let _ = s.read(&mut buf); // consume, then hold the socket open
        std::thread::sleep(Duration::from_secs(30));
    });
    port
}

#[test]
fn loopback_round_trip() {
    let port = echo_server();
    let mut t = TcpTransport::connect(format!("127.0.0.1:{port}"), Duration::from_secs(5)).unwrap();
    let echo = t.exchange(b"hello-ledger").unwrap();
    assert_eq!(echo, b"hello-ledger");
}

#[test]
fn loopback_wallet_apdu() {
    // Full wallet call over the ledgercomm framing: echo returns our APDU,
    // which is NOT a valid Ledger response — assert the codec rejects it
    // (proves bytes actually crossed the socket both ways).
    let port = echo_server();
    let mut t = TcpTransport::connect(format!("127.0.0.1:{port}"), Duration::from_secs(5)).unwrap();
    let w = Wallet::new(DeviceKind::LedgerNanoSPlus);
    let path = parse_path("m/44'/0'/0'/0/0").unwrap();
    let req = w.get_address_request(&CoinProfile::BITCOIN, &path).unwrap();
    let resp = t.exchange(&req).unwrap();
    assert_eq!(resp, req); // echo: request came back
    assert!(w.parse_address_response(&resp).is_err()); // not a valid reply
}

#[test]
fn wedged_device_surfaces_timeout() {
    let port = blackhole_server();
    let mut t = TcpTransport::connect(format!("127.0.0.1:{port}"), Duration::from_secs(5)).unwrap();
    let err = t
        .exchange_timeout(b"ping", Duration::from_millis(200))
        .unwrap_err();
    assert_eq!(err, Error::TransportTimeout);
}

#[test]
fn refused_connection_is_unavailable() {
    // Port 1 is (practically) never listening: connect must map to
    // TransportUnavailable, not a generic failure string.
    let err = TcpTransport::connect("127.0.0.1:1", Duration::from_millis(200)).unwrap_err();
    assert_eq!(err, Error::TransportUnavailable);
}
