//! Signature scheme errors.

use core::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureError {
    InvalidLength,
    InvalidEncoding,
    InvalidSignature,
    InvalidPublicKey,
    InvalidPrivateKey,
    VerificationFailed,
    Unsupported,
    Failure(&'static str),
}

impl SignatureError {
    pub const fn as_str(self) -> &'static str {
        match self {
            SignatureError::InvalidLength => "invalid length",
            SignatureError::InvalidEncoding => "invalid encoding",
            SignatureError::InvalidSignature => "invalid signature",
            SignatureError::InvalidPublicKey => "invalid public key",
            SignatureError::InvalidPrivateKey => "invalid private key",
            SignatureError::VerificationFailed => "verification failed",
            SignatureError::Unsupported => "unsupported",
            SignatureError::Failure(m) => m,
        }
    }
}

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<SignatureError> for crate::error::Error {
    fn from(e: SignatureError) -> Self {
        match e {
            SignatureError::InvalidLength => crate::error::Error::InvalidLength,
            SignatureError::InvalidEncoding => crate::error::Error::InvalidEncoding,
            SignatureError::InvalidSignature => crate::error::Error::Failure("invalid signature"),
            SignatureError::InvalidPublicKey => crate::error::Error::InvalidPoint,
            SignatureError::InvalidPrivateKey => crate::error::Error::InvalidScalar,
            SignatureError::VerificationFailed => crate::error::Error::VerificationFailed,
            SignatureError::Unsupported => crate::error::Error::Unsupported,
            SignatureError::Failure(m) => crate::error::Error::Failure(m),
        }
    }
}

pub type SignatureResult<T> = core::result::Result<T, SignatureError>;
