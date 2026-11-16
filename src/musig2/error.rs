//! MuSig2 errors.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Musig2Error {
    InvalidLength,
    InvalidKey,
    InvalidNonce,
    InvalidScalar,
    InvalidSession,
    VerificationFailed,
    TooFewKeys,
    Internal,
}

pub type Musig2Result<T> = Result<T, Musig2Error>;
