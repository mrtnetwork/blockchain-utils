//! Transport tests: scripted failure simulation + timeout plumbing.
//! No device, no network — pure mock devices.
//! Run: `cargo test --features hw --test hw_transport`
//! (`--no-default-features --features hw` runs the no_std-safe subset.)

#![cfg(feature = "hw")]

use blockchain_utils::error::Error;
use blockchain_utils::hw::{
    coin::CoinProfile,
    mock::MockTransport,
    path::parse_path,
    transport::Transport,
    wallet::{DeviceKind, Wallet},
};

fn ledger_pubkey_resp(tag: u8) -> Vec<u8> {
    let mut resp = vec![33u8];
    resp.extend_from_slice(&[tag; 33]);
    resp.extend_from_slice(&[0x90, 0x00]);
    resp
}

#[test]
fn mock_scripts_failures() {
    let mut dev = MockTransport::scripted_results(vec![
        Ok(vec![0x90, 0x00]),
        Err(Error::TransportTimeout),
        Err(Error::TransportDisconnected),
        Err(Error::TransportCancelled),
    ]);
    assert_eq!(dev.exchange(&[0xE0]).unwrap(), vec![0x90, 0x00]);
    assert_eq!(dev.exchange(&[0xE0]), Err(Error::TransportTimeout));
    assert_eq!(dev.exchange(&[0xE0]), Err(Error::TransportDisconnected));
    assert_eq!(dev.exchange(&[0xE0]), Err(Error::TransportCancelled));
    assert_eq!(dev.remaining(), 0);
    assert_eq!(dev.seen().len(), 4);
}

#[test]
fn transport_errors_have_stable_strings() {
    let cases = [
        (Error::TransportUnavailable, "transport unavailable"),
        (Error::TransportWrite, "transport write failed"),
        (Error::TransportRead, "transport read failed"),
        (Error::TransportTimeout, "transport timeout"),
        (Error::TransportDisconnected, "transport disconnected"),
        (Error::TransportCancelled, "transport cancelled"),
    ];
    for (e, s) in cases {
        assert_eq!(e.as_str(), s);
        assert_eq!(format!("{e}"), s);
    }
}

#[test]
fn wallet_propagates_scripted_timeout() {
    // A wedged mock device surfaces TransportTimeout through the full
    // wallet call — no hang, no reinterpretation as another error.
    let w = Wallet::new(DeviceKind::LedgerNanoSPlus);
    let path = parse_path("m/44'/0'/0'/0/0").unwrap();
    let mut dev = MockTransport::scripted_results(vec![Err(Error::TransportTimeout)]);
    assert_eq!(
        w.execute_get_address(&mut dev, &CoinProfile::BITCOIN, &path),
        Err(Error::TransportTimeout)
    );
    assert_eq!(dev.seen().len(), 1); // request still went out
}

#[test]
fn wallet_recovers_after_scripted_drop() {
    // Drop mid-session, then a healthy reconnect: script both phases.
    let w = Wallet::new(DeviceKind::LedgerNanoSPlus);
    let path = parse_path("m/44'/0'/0'/0/0").unwrap();
    let mut dev = MockTransport::scripted_results(vec![
        Err(Error::TransportDisconnected),
        Ok(ledger_pubkey_resp(0x03)),
    ]);
    assert_eq!(
        w.execute_get_address(&mut dev, &CoinProfile::BITCOIN, &path),
        Err(Error::TransportDisconnected)
    );
    let pk = w
        .execute_get_address(&mut dev, &CoinProfile::BITCOIN, &path)
        .unwrap();
    assert_eq!(pk, vec![0x03; 33]);
}

#[cfg(feature = "std")]
#[test]
fn exchange_timeout_default_forwards() {
    use std::time::Duration;
    let mut dev = MockTransport::fixed(vec![0x90, 0x00]);
    let out = dev
        .exchange_timeout(&[0xE0], Duration::from_millis(10))
        .unwrap();
    assert_eq!(out, vec![0x90, 0x00]);
    let mut dev = MockTransport::scripted_results(vec![Err(Error::TransportTimeout)]);
    assert_eq!(
        dev.exchange_timeout(&[0xE0], Duration::from_millis(10)),
        Err(Error::TransportTimeout)
    );
}

#[test]
fn cancel_poisons_mock() {
    // Cooperative cancellation contract: after cancel(), exchanges fail
    // with TransportCancelled — even through a shared (&) reference, the
    // shape a supervising task holds while another task exchanges.
    let mut dev = MockTransport::fixed(vec![0x90, 0x00]);
    assert!(dev.exchange(&[0xE0]).is_ok());
    dev.cancel();
    assert_eq!(dev.exchange(&[0xE0]), Err(Error::TransportCancelled));

    let mut dev2 = MockTransport::fixed(vec![0x90, 0x00]);
    let shared: &MockTransport = &dev2;
    shared.cancel();
    assert_eq!(dev2.exchange(&[0xE0]), Err(Error::TransportCancelled));
}
