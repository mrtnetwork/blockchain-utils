//! Hardware-wallet support: pure `no_std` + `alloc`, zero dependencies.
//!
//! Feature: `--features hw` (implies `alloc`). Not in `default` so the core
//! stays minimal.
//!
//! ## Design
//!
//! ```text
//! codec (testable, no device)        | transport (moves bytes, OS-gated)
//! ----------------------------------+----------------------------------
//! hw::path   BIP32/SLIP10 path      | hw::Transport trait
//! hw::coin   SLIP44 + curve profile |  hw::linux   hidraw (std, linux)
//! hw::apdu   Ledger CLA/INS framing |  hw::macos   IOHID (std, macos)
//! hw::hid    64B HID chunking       |  hw::windows hid.dll (std, windows)
//! hw::trezor protobuf + `?##` frame |  hw::wasm_webhid (wasm32, raw host)
//! hw::ur     UR2.0 / Bytewords / QR |  hw::noise   BitBox02 Noise_XX
//! hw::psbt   PSBT TLV parser        |  hw::mobile  C-ABI (Kotlin/Swift)
//! hw::wallet ONE `HardwareWallet`   |  hw::emu     Speculos TCP (std)
//! hw::mock   scripted test device   |  airgap: no transport (QR/SD)
//! ```
//!
//! Feature layout: codecs are `no_std` + `alloc`
//! (`--features hw` alone). Every OS transport needs file I/O, sockets, or
//! threads, so all of `linux` / `macos` / `windows` / `emu` require `std`
//! and are additionally gated on their `target_os` — a backend can never
//! compile on the wrong OS. `wasm_webhid` is `target_arch = "wasm32"` only
//! and stays `no_std`: it holds zero Rust dependencies, only raw
//! `extern "C"` imports served by the application's hand-written JS host
//! (see `hw/host.js` example; repo policy forbids `js-sys`/`web-sys`).
//! `noise` and `mobile` are pure `no_std` + `alloc`.
//!
//! ## One interaction interface
//!
//! ```ignore
//! use blockchain_utils::hw::{
//!     CoinProfile, DeviceKind, HardwareWallet, MockTransport, Wallet,
//! };
//!
//! let wallet = Wallet::new(DeviceKind::LedgerNanoSPlus);
//! assert!(wallet.supports_coin(&CoinProfile::TEZOS_TZ1));
//! let req = wallet.get_address_request(&CoinProfile::BITCOIN, &[0x8000_002C, 0x8000_0000, 0x8000_0000, 0, 0])?;
//! let mut dev = MockTransport::scripted(alloc::vec![Ok(alloc::vec![0x04])]);
//! let pubkey = wallet.execute_get_address(&mut dev, &CoinProfile::BITCOIN, &path)?;
//! ```
//!
//! Airgap devices (`Passport`, `Keystone`, `ColdcardQr`, `JadeQr`) never touch
//! `Transport`: use `wallet.qr_request(...)` -> show QR -> `wallet.qr_response(...)`.

pub mod apdu;
pub mod bitbox;
pub mod coin;
pub mod discover;
#[cfg(feature = "std")]
pub mod emu;
pub mod hid;
#[cfg(all(feature = "std", target_os = "linux"))]
pub mod linux;
pub mod log;
#[cfg(all(feature = "std", target_os = "macos"))]
pub mod macos;
pub mod mobile;
pub mod mock;
pub mod noise;
pub mod path;
pub mod psbt;
#[cfg(feature = "std")]
pub(crate) mod report;
pub mod transport;
pub mod trezor;
pub mod ur;
pub mod wallet;
pub mod wasm_webhid;
#[cfg(all(feature = "std", target_os = "windows"))]
pub mod windows;

pub use apdu::{Apdu, ApduResponse, SW_OK};
pub use coin::{CoinProfile, HwCurve, WELL_KNOWN_COINS};
pub use discover::{family_for_vid, is_candidate_vid, UsbId, KNOWN_VIDS};
#[cfg(feature = "std")]
pub use emu::{TcpTransport, MAX_APDU_LEN};
pub use hid::{hid_frame, hid_unframe};
#[cfg(all(feature = "std", target_os = "linux"))]
pub use linux::{enumerate_candidates, pick_candidate, LinuxHidDevice, UsbHidTransport};
pub use log::{log_record, set_log_sink, LogLevel, LogRecord};
#[cfg(all(feature = "std", target_os = "macos"))]
pub use macos::{enumerate_candidates, pick_candidate, MacHidDevice, UsbHidTransport};
pub use mobile::{
    hw_mobile_close, hw_mobile_exchange, hw_mobile_open, hw_mobile_register_ops, register_host_ops,
    HostOps, MobileErrorCode, MobileTransport,
};
pub use mock::MockTransport;
pub use noise::{
    NoiseTransport, NoiseTransportAdapter, NoiseXX, ENC_STATIC_LEN, MSG1_LEN, MSG2_LEN, MSG3_LEN,
};
pub use path::{is_hardened, parse_path, path_to_string};
pub use transport::Transport;
pub use trezor::{proto_decode, proto_encode, trezor_frame, trezor_unframe};
pub use ur::{ur_decode_single, ur_encode_single, UrMessage};
pub use wallet::{DeviceKind, HardwareWallet, Wallet};
pub use wasm_webhid::WebHidTransport;
#[cfg(all(feature = "std", target_os = "windows"))]
pub use windows::{enumerate_candidates, pick_candidate, UsbHidTransport, WindowsHidDevice};
