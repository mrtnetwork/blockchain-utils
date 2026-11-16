//! LIVE emulator test — ignored by default, needs Speculos + Bitcoin app.
//!
//! 1. Run Speculos (Ledger Nano S Plus / X emulator), e.g.:
//!    docker run --rm -p 9999:9999 -p 5000:5000 \
//!    -v "$PWD/btc.elf:/speculos/app.elf" \
//!    ghcr.io/ledgerhq/speculos \
//!    --model nanosplus --sdk 2.4 --apdu-port 9999 --automation-port 5000 \
//!    /speculos/app.elf
//!    (check `speculos --help` in your version for exact flags/ports;
//!    get `btc.elf` from the ledger-app-bitcoin releases.)
//! 2. SPECULOS_ADDR=127.0.0.1:9999 cargo test --features hw \
//!    --test hw_speculos -- --ignored --nocapture
//!
//! What it proves: real `GET WALLET PUBLIC KEY` round-trip — our APDU bytes
//! are accepted by real firmware code and the reply parses to a secp256k1
//! pubkey. Uses testnet path `m/44'/1'/0'/0/0` (no mainnet keys).
//!
//! NOTE: needs `std` (TCP). Never runs in CI without the emulator.
//!
//! SIGN COVERAGE (deliberately mock-only for now): `Wallet::sign_request`
//! builds a single-round template (Ledger `INS_SIGN`, Trezor `SignMessage`)
//! that `hw_sign.rs` pins against scripted transports. Real BTC-app signing
//! on Speculos needs the full multi-APDU trusted-input prelude (hash the tx
//! inputs first, then sign) — a single `INS 0x48` is correctly rejected by
//! real firmware, so there is no honest live sign assertion to write until
//! that prelude lands. Trezor `SignMessage`, by contrast, IS single-round
//! and is the first candidate for a live emulator case (needs the Trezor
//! core emulator, heavier than Speculos — not wired yet).

#![cfg(all(feature = "hw", feature = "std"))]

use std::time::Duration;

use blockchain_utils::hw::{
    coin::CoinProfile, path::parse_path, transport::Transport, wallet::DeviceKind,
    wallet::HardwareWallet, wallet::Wallet, TcpTransport,
};

fn addr() -> String {
    std::env::var("SPECULOS_ADDR").unwrap_or_else(|_| "127.0.0.1:9999".into())
}

#[test]
#[ignore = "needs live Speculos emulator (see file docs)"]
fn speculos_btc_get_pubkey_testnet() {
    let mut t = TcpTransport::connect(addr(), Duration::from_secs(10)).expect("connect Speculos");
    let w = Wallet::new(DeviceKind::LedgerNanoSPlus);
    // Testnet coin profile built inline (mainnet-only table in core).
    let coin = CoinProfile::new(
        "btc-test",
        1,
        blockchain_utils::keys::CryptoKeyType::Secp256k1,
        blockchain_utils::hw::coin::HwCurve::Secp256k1,
        44,
        "0'/0/0",
    );
    let path = parse_path("m/44'/1'/0'/0/0").unwrap();
    let req = w.get_address_request(&coin, &path).expect("build APDU");
    let resp = t
        .exchange(&req)
        .expect("emulator answered (is Speculos up?)");
    let pk = w
        .parse_address_response(&resp)
        .expect("parse 0x9000 + pubkey");
    assert!(
        pk.len() == 33 || pk.len() == 65,
        "expected compressed/uncompressed pubkey, got {} bytes",
        pk.len()
    );
    assert!(
        pk[0] == 0x02 || pk[0] == 0x03 || pk[0] == 0x04,
        "bad pubkey prefix {:02x}",
        pk[0]
    );
    println!("speculos pubkey m/44'/1'/0'/0/0 = {}", hex_of(&pk));
}

fn hex_of(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(2 * b.len());
    for x in b {
        s.push(H[(x >> 4) as usize] as char);
        s.push(H[(x & 15) as usize] as char);
    }
    s
}
