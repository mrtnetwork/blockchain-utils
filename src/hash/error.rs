//! Error types specific to the hash module.

use core::fmt;

/// Errors produced by hash, HMAC, HKDF and PBKDF2 operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HashError {
    /// Input length is invalid for the requested operation.
    InvalidLength,
    /// Output buffer is too small for the digest / derived key.
    OutputTooSmall,
    /// Key length is invalid (e.g. empty where forbidden, or too long).
    InvalidKeyLength,
    /// Iteration count is zero or otherwise illegal.
    InvalidIterations,
    /// Requested output length exceeds the algorithm limit.
    OutputTooLarge,
    /// Unsupported parameter combination.
    Unsupported,
    /// Internal / unexpected failure.
    Failure(&'static str),
}

impl HashError {
    /// Static description.
    pub const fn as_str(self) -> &'static str {
        match self {
            HashError::InvalidLength => "invalid length",
            HashError::OutputTooSmall => "output buffer too small",
            HashError::InvalidKeyLength => "invalid key length",
            HashError::InvalidIterations => "invalid iteration count",
            HashError::OutputTooLarge => "requested output too large",
            HashError::Unsupported => "unsupported operation",
            HashError::Failure(msg) => msg,
        }
    }
}

impl fmt::Display for HashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<HashError> for crate::error::Error {
    fn from(e: HashError) -> Self {
        match e {
            HashError::InvalidLength => crate::error::Error::InvalidLength,
            HashError::OutputTooSmall => crate::error::Error::InvalidLength,
            HashError::InvalidKeyLength => crate::error::Error::InvalidLength,
            HashError::InvalidIterations => crate::error::Error::InvalidLength,
            HashError::OutputTooLarge => crate::error::Error::InvalidLength,
            HashError::Unsupported => crate::error::Error::Unsupported,
            HashError::Failure(msg) => crate::error::Error::Failure(msg),
        }
    }
}

/// Result alias for hash-module operations.
pub type HashResult<T> = core::result::Result<T, HashError>;
