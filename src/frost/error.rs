//! FROST errors (RFC 9591).

/// Errors raised by the FROST signing and key-generation routines.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrostError {
    /// A length-prefixed / fixed-size input has the wrong length.
    InvalidLength,
    /// A scalar encoding is malformed (bad length or value ≥ order).
    InvalidScalar,
    /// A point encoding is malformed, off-curve, identity, or (Ed25519)
    /// outside the prime-order subgroup.
    InvalidKey,
    /// A nonce is zero or otherwise unusable.
    InvalidNonce,
    /// A commitment entry is malformed (unknown encoding, identity).
    InvalidCommitment,
    /// Duplicate, zero, or unknown participant identifier.
    InvalidParticipant,
    /// The computed group commitment is the identity element.
    IdentityCommitment,
    /// Fewer shares than required / empty share set.
    TooFewShares,
    /// Hash backend failure (infallible in practice).
    Internal,
}

/// Result type for FROST operations.
pub type FrostResult<T> = Result<T, FrostError>;
