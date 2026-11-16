//! Signing / verifying key traits.

use crate::error::Result;
use crate::keys::types::CryptoKeyType;

/// Opaque signature bytes produced by a signing key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignatureBytes {
    /// Serialized signature.
    #[cfg(feature = "alloc")]
    pub bytes: alloc::vec::Vec<u8>,
}

#[cfg(feature = "alloc")]
impl SignatureBytes {
    /// Wrap owned bytes.
    pub fn new(bytes: alloc::vec::Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Borrow the signature bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

/// Public / verifying key.
pub trait VerifyingKey {
    /// Algorithm tag.
    fn key_type(&self) -> CryptoKeyType;

    /// Verify `signature` over `message`.
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool>;

    /// Compressed / canonical public-key encoding length.
    fn public_key_len(&self) -> usize;

    /// Write public key bytes into `out` (must be ≥ `public_key_len()`).
    fn to_public_bytes(&self, out: &mut [u8]) -> Result<()>;
}

/// Private / signing key.
pub trait SigningKey {
    /// Matching verifying-key type.
    type Verifying: VerifyingKey;

    /// Algorithm tag.
    fn key_type(&self) -> CryptoKeyType;

    /// Sign `message`, returning serialized signature bytes.
    #[cfg(feature = "alloc")]
    fn sign(&self, message: &[u8]) -> Result<SignatureBytes>;

    /// Corresponding public / verifying key.
    fn verifying_key(&self) -> Self::Verifying;
}
