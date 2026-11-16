//! Error types for block ciphers, modes, and AEAD.

use core::fmt;

/// Errors from cipher / AEAD operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CipherError {
    /// Key length is not valid for the algorithm.
    InvalidKeyLength,
    /// Nonce / IV length is not valid.
    InvalidNonceLength,
    /// Buffer length, block alignment, or output size is invalid.
    InvalidLength,
    /// PKCS7 or other padding is invalid.
    InvalidPadding,
    /// AEAD authentication tag verification failed.
    /// Plaintext must not be released when this is returned.
    AuthenticationFailed,
    /// Operation or parameter combination is not supported.
    Unsupported,
    /// Generic failure with a static message.
    Failure(&'static str),
}

impl CipherError {
    /// Static description.
    pub const fn as_str(self) -> &'static str {
        match self {
            CipherError::InvalidKeyLength => "invalid key length",
            CipherError::InvalidNonceLength => "invalid nonce length",
            CipherError::InvalidLength => "invalid length",
            CipherError::InvalidPadding => "invalid padding",
            CipherError::AuthenticationFailed => "authentication failed",
            CipherError::Unsupported => "unsupported operation",
            CipherError::Failure(msg) => msg,
        }
    }
}

impl fmt::Display for CipherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<CipherError> for crate::error::Error {
    fn from(e: CipherError) -> Self {
        match e {
            CipherError::InvalidKeyLength => crate::error::Error::InvalidLength,
            CipherError::InvalidNonceLength => crate::error::Error::InvalidLength,
            CipherError::InvalidLength => crate::error::Error::InvalidLength,
            CipherError::InvalidPadding => crate::error::Error::InvalidEncoding,
            CipherError::AuthenticationFailed => crate::error::Error::VerificationFailed,
            CipherError::Unsupported => crate::error::Error::Unsupported,
            CipherError::Failure(msg) => crate::error::Error::Failure(msg),
        }
    }
}

/// Result alias for cipher-module operations.
pub type CipherResult<T> = core::result::Result<T, CipherError>;
