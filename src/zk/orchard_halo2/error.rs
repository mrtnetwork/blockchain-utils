//! Result-style errors only. No `assert!`, no panics in library paths.
//! WASM/FFI safe: plain `alloc::string::String`, no backtrace, no I/O.

#[cfg(feature = "alloc")]
use alloc::string::String;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Halo2Error {
    pub operation: &'static str,
    pub reason: &'static str,
    pub details: Option<ErrorDetails>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorDetails {
    #[cfg(feature = "alloc")]
    pub message: String,
    #[cfg(not(feature = "alloc"))]
    pub code: u32,
}

impl Halo2Error {
    pub const fn operation_failed(operation: &'static str, reason: &'static str) -> Self {
        Self {
            operation,
            reason,
            details: None,
        }
    }

    #[cfg(feature = "alloc")]
    pub fn with_message(operation: &'static str, reason: &'static str, message: String) -> Self {
        Self {
            operation,
            reason,
            details: Some(ErrorDetails { message }),
        }
    }

    pub fn operation(&self) -> &'static str {
        self.operation
    }

    pub fn reason(&self) -> &'static str {
        self.reason
    }

    #[cfg(feature = "alloc")]
    pub fn to_debug_string(&self) -> String {
        match &self.details {
            Some(d) => alloc::format!(
                "Halo2Error({}: {}: {})",
                self.operation,
                self.reason,
                d.message
            ),
            None => alloc::format!("Halo2Error({}: {})", self.operation, self.reason),
        }
    }

    #[cfg(not(feature = "alloc"))]
    pub fn to_debug_string<const N: usize>(&self, buf: &mut [u8; N]) -> usize {
        let mut n = 0usize;
        let parts: [&[u8]; 5] = [
            b"Halo2Error(",
            self.operation.as_bytes(),
            b": ",
            self.reason.as_bytes(),
            b")",
        ];
        for p in parts {
            for &b in p {
                if n >= N {
                    return n;
                }
                buf[n] = b;
                n += 1;
            }
        }
        n
    }
}

impl core::fmt::Display for Halo2Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.operation)?;
        f.write_str(" operation failed: ")?;
        f.write_str(self.reason)
    }
}

pub type Halo2Result<T> = Result<T, Halo2Error>;

/// Generic, description-free error for FFI/WASM boundaries (`repr(i32)` so
/// the discriminant crosses the ABI directly).
///
/// Internal code keeps `Halo2Error` (operation/reason strings for debugging);
/// bridge layers convert here and transport only the code. Stage-specific
/// outcomes (`ProveFailed` vs `VerifyFailed`) are assigned by the caller
/// stage, not inferred from strings.
#[repr(i32)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OrchardError {
    Ok = 0,
    /// Null pointer argument (FFI).
    Null = 1,
    /// Wrong blob/field/row shape (lengths, counts, overflows, truncations).
    InvalidLength = 2,
    /// Undecodable value (field/point/scalar encoding, on-curve failure,
    /// unknown version/domain, flag-rule violation).
    InvalidEncoding = 3,
    /// Proving failed (synthesis/commitment/transcript error).
    ProveFailed = 4,
    /// Proof rejected by the verifier (boolean `false`, not a fault).
    VerifyFailed = 5,
    /// Anything else (internal constraint/assembly fault).
    Internal = 6,
}

impl OrchardError {
    /// ABI code (matches the discriminant).
    pub fn code(self) -> i32 {
        self as i32
    }

    /// `true` for [`OrchardError::Ok`].
    pub fn is_ok(self) -> bool {
        matches!(self, OrchardError::Ok)
    }
}

impl From<Halo2Error> for OrchardError {
    fn from(e: Halo2Error) -> Self {
        classify_reason(e.reason)
    }
}

impl From<crate::curve::CurveError> for OrchardError {
    fn from(e: crate::curve::CurveError) -> Self {
        use crate::curve::CurveError::*;
        match e {
            InvalidLength => OrchardError::InvalidLength,
            InvalidEncoding | InvalidPoint | InvalidScalar => OrchardError::InvalidEncoding,
            NotInvertible | Unsupported => OrchardError::Internal,
            Failure(reason) => classify_reason(reason),
        }
    }
}

/// Reason-family classifier (single place; no string transport).
fn classify_reason(reason: &'static str) -> OrchardError {
    // Shape/length failures (caller-side sizes, counts, truncations).
    if reason.contains("length")
        || reason.contains("too long")
        || reason.contains("too many")
        || reason.contains("count")
        || reason.contains("short")
        || reason.contains("empty")
        || reason.contains("missing")
        || reason.contains("overflow")
        || reason.contains("out of range")
        || reason.contains("offset")
        || reason.contains("chunk")
        || reason.contains("piece")
        || reason.contains("bits")
        || reason.contains("rows")
        || reason.contains("values")
        || reason.contains("index")
        || reason.contains("range")
        || reason.contains("mismatch")
    {
        return OrchardError::InvalidLength;
    }
    // Encoding/value failures (also version/domain/flag rules).
    if reason.contains("invalid")
        || reason.contains("encoding")
        || reason.contains("parse")
        || reason.contains("curve")
        || reason.contains("point")
        || reason.contains("square root")
        || reason.contains("division by zero")
        || reason.contains("version")
        || reason.contains("domain")
        || reason.contains("flag")
        || reason.contains("scalar")
        || reason.contains("canonical")
        || reason.contains("identity")
        || reason.contains("unknown")
    {
        return OrchardError::InvalidEncoding;
    }
    OrchardError::Internal
}

/// Map shared-curve errors into Halo2 errors (keeps `?` working on
/// `CurveResult` inside orchard code).
impl From<crate::curve::CurveError> for Halo2Error {
    fn from(e: crate::curve::CurveError) -> Self {
        #[cfg(feature = "alloc")]
        {
            Halo2Error::with_message("curve", "curve operation failed", alloc::format!("{:?}", e))
        }
        #[cfg(not(feature = "alloc"))]
        {
            let _ = e;
            Halo2Error::operation_failed("curve", "curve operation failed")
        }
    }
}

/// Validate a length without `assert!`. Returns `Err` on mismatch.
pub fn expect_len(actual: usize, expected: usize, op: &'static str) -> Halo2Result<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(Halo2Error::operation_failed(op, "invalid length"))
    }
}

/// Validate a boolean condition without `assert!`.
pub fn ensure(cond: bool, op: &'static str, reason: &'static str) -> Halo2Result<()> {
    if cond {
        Ok(())
    } else {
        Err(Halo2Error::operation_failed(op, reason))
    }
}
