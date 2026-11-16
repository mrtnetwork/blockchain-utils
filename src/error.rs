//! Error types for the `blockchain-utils` crate.
//!
//! This module is fully `no_std` and does not depend on any external crates.

use core::fmt;

/// Primary error type used throughout the crate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Invalid input length.
    InvalidLength,
    /// Invalid encoding / decoding.
    InvalidEncoding,
    /// Checksum verification failed.
    InvalidChecksum,
    /// Invalid character in encoding.
    InvalidCharacter,
    /// Cryptographic verification failed.
    VerificationFailed,
    /// Invalid private key.
    InvalidPrivateKey,
    /// Invalid public key.
    InvalidPublicKey,
    /// Invalid signature.
    InvalidSignature,
    /// Invalid point on the curve.
    InvalidPoint,
    /// Invalid scalar.
    InvalidScalar,
    /// Invalid mnemonic / seed.
    InvalidMnemonic,
    /// Derivation path error.
    InvalidPath,
    /// Unsupported operation or feature.
    Unsupported,
    /// Algorithm or key type not yet implemented.
    Unimplemented,
    /// Generic failure with a static message.
    Failure(&'static str),
    /// Hardware transport: no usable device / backend.
    /// Connection refused, no matching HID device, WebHID denied
    /// before any bytes moved.
    TransportUnavailable,
    /// Hardware transport: request bytes could not be written.
    TransportWrite,
    /// Hardware transport: response could not be read (I/O error, short
    /// read, malformed framing) — distinct from a clean timeout.
    TransportRead,
    /// Hardware transport: per-call deadline elapsed (`exchange_timeout`).
    /// A wedged device must surface here, never hang the caller.
    TransportTimeout,
    /// Hardware transport: established channel dropped mid-exchange
    /// (unplug, BLE drop, emulator killed).
    TransportDisconnected,
    /// Hardware transport: exchange aborted by the caller (dialog closed,
    /// app backgrounded).
    TransportCancelled,
}

impl Error {
    /// Returns a static description of the error.
    pub const fn as_str(self) -> &'static str {
        match self {
            Error::InvalidLength => "invalid length",
            Error::InvalidEncoding => "invalid encoding",
            Error::InvalidChecksum => "invalid checksum",
            Error::InvalidCharacter => "invalid character",
            Error::VerificationFailed => "verification failed",
            Error::InvalidPrivateKey => "invalid private key",
            Error::InvalidPublicKey => "invalid public key",
            Error::InvalidSignature => "invalid signature",
            Error::InvalidPoint => "invalid point",
            Error::InvalidScalar => "invalid scalar",
            Error::InvalidMnemonic => "invalid mnemonic",
            Error::InvalidPath => "invalid derivation path",
            Error::Unsupported => "unsupported operation",
            Error::Unimplemented => "unimplemented",
            Error::Failure(msg) => msg,
            Error::TransportUnavailable => "transport unavailable",
            Error::TransportWrite => "transport write failed",
            Error::TransportRead => "transport read failed",
            Error::TransportTimeout => "transport timeout",
            Error::TransportDisconnected => "transport disconnected",
            Error::TransportCancelled => "transport cancelled",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Convenience result type used across the crate.
pub type Result<T> = core::result::Result<T, Error>;
