//! secp256k1 signing / verifying keys.

use crate::error::{Error, Result};
use crate::hash::sha256;
use crate::keys::traits::{SignatureBytes, SigningKey, VerifyingKey};
use crate::keys::types::CryptoKeyType;
use crate::signature::ecdsa;

/// secp256k1 private key.
pub struct Secp256k1SigningKey {
    inner: ecdsa::SecretKey,
}

/// secp256k1 public key.
pub struct Secp256k1VerifyingKey {
    inner: ecdsa::PublicKey,
}

impl Secp256k1SigningKey {
    /// Parse 32-byte secret.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let inner = ecdsa::SecretKey::from_bytes(bytes).map_err(|_| Error::InvalidPrivateKey)?;
        Ok(Self { inner })
    }
}

impl Secp256k1VerifyingKey {
    /// Parse compressed or uncompressed public key bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let inner = ecdsa::PublicKey::from_bytes(bytes).map_err(|_| Error::InvalidPublicKey)?;
        Ok(Self { inner })
    }
}

impl VerifyingKey for Secp256k1VerifyingKey {
    fn key_type(&self) -> CryptoKeyType {
        CryptoKeyType::Secp256k1
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        let hash = sha256(message).map_err(|_| Error::Failure("sha256"))?;
        let sig = ecdsa::Signature::from_compact(signature).map_err(|_| Error::InvalidSignature)?;
        match ecdsa::verify(&self.inner, &hash, &sig) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn public_key_len(&self) -> usize {
        33
    }

    fn to_public_bytes(&self, out: &mut [u8]) -> Result<()> {
        if out.len() < 33 {
            return Err(Error::InvalidLength);
        }
        let mut buf = [0u8; 33];
        self.inner
            .to_bytes_compressed(&mut buf)
            .map_err(|_| Error::InvalidPublicKey)?;
        out[..33].copy_from_slice(&buf);
        Ok(())
    }
}

impl SigningKey for Secp256k1SigningKey {
    type Verifying = Secp256k1VerifyingKey;

    fn key_type(&self) -> CryptoKeyType {
        CryptoKeyType::Secp256k1
    }

    #[cfg(feature = "alloc")]
    fn sign(&self, message: &[u8]) -> Result<SignatureBytes> {
        let hash = sha256(message).map_err(|_| Error::Failure("sha256"))?;
        let sig = ecdsa::sign(&self.inner, &hash).map_err(|_| Error::Failure("sign"))?;
        let mut out = [0u8; 64];
        sig.to_compact(&mut out);
        Ok(SignatureBytes::new(out.to_vec()))
    }

    fn verifying_key(&self) -> Self::Verifying {
        let pk = self.inner.public_key().expect("derive pk");
        Secp256k1VerifyingKey { inner: pk }
    }
}
