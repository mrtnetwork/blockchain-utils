//! Hardware-wallet codec/interface suite: APDU / Trezor proto / UR / PSBT
//! codecs, transports, sign flows, and Noise-channel vectors.
//!
//! Run: `cargo test --test hw`

mod hw_bitbox;
mod hw_codec_fuzz;
mod hw_kat;
mod hw_linux;
mod hw_log;
mod hw_loopback;
mod hw_mobile;
mod hw_noise;
mod hw_noise_snow;
mod hw_noise_vector;
mod hw_robust;
mod hw_sign;
mod hw_signtx;
mod hw_speculos;
mod hw_transport;
mod hw_ur_airgap;
