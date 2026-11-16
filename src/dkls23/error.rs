//! DKLs23 error type.

/// Errors raised by the DKLs23 routines.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DklsError {
    /// A fixed-size input has the wrong length.
    InvalidLength,
    /// A scalar encoding is malformed (`>= order` or wrong length).
    InvalidScalar,
    /// A point encoding is malformed, off-curve, or the identity where
    /// a non-identity point is required.
    InvalidPoint,
    /// Unknown curve selector or participant index.
    InvalidParticipant,
    /// Commitment / decommitment mismatch.
    BadCommitment,
    /// A Schnorr / OT consistency proof failed to verify.
    BadProof,
    /// A Feldman share check failed.
    BadShare,
    /// Fewer parties / shares than required, or an empty committee.
    TooFew,
    /// Malformed wire encoding.
    BadEncoding,
    /// Secret is zero where forbidden, or public key is identity.
    ZeroSecret,
    /// Hash backend failure (infallible in practice).
    Internal,
}

/// Result type for DKLs23 operations.
pub type DklsResult<T> = Result<T, DklsError>;
