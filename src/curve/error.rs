//! Errors for elliptic-curve operations.

use core::fmt;

/// Curve / field / point errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CurveError {
    /// Invalid byte length for field, scalar, or point encoding.
    InvalidLength,
    /// Bytes do not encode a valid field element or scalar.
    InvalidEncoding,
    /// Point is not on the curve or is the identity when disallowed.
    InvalidPoint,
    /// Scalar is out of range or zero when disallowed.
    InvalidScalar,
    /// Inversion of zero (or non-invertible element).
    NotInvertible,
    /// Unsupported feature or parameter.
    Unsupported,
    /// Generic failure.
    Failure(&'static str),
}

impl CurveError {
    /// Static description.
    pub const fn as_str(self) -> &'static str {
        match self {
            CurveError::InvalidLength => "invalid length",
            CurveError::InvalidEncoding => "invalid encoding",
            CurveError::InvalidPoint => "invalid point",
            CurveError::InvalidScalar => "invalid scalar",
            CurveError::NotInvertible => "not invertible",
            CurveError::Unsupported => "unsupported",
            CurveError::Failure(m) => m,
        }
    }
}

impl fmt::Display for CurveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<CurveError> for crate::error::Error {
    fn from(e: CurveError) -> Self {
        match e {
            CurveError::InvalidLength => crate::error::Error::InvalidLength,
            CurveError::InvalidEncoding => crate::error::Error::InvalidEncoding,
            CurveError::InvalidPoint => crate::error::Error::InvalidPoint,
            CurveError::InvalidScalar => crate::error::Error::InvalidScalar,
            CurveError::NotInvertible => crate::error::Error::Failure("not invertible"),
            CurveError::Unsupported => crate::error::Error::Unsupported,
            CurveError::Failure(m) => crate::error::Error::Failure(m),
        }
    }
}

/// Result alias for curve operations.
pub type CurveResult<T> = core::result::Result<T, CurveError>;
