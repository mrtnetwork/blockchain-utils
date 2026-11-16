//! Ed25519 signing / verifying keys.

use crate::error::{Error, Result};
use crate::keys::traits::{SignatureBytes, SigningKey, VerifyingKey};
use crate::keys::types::CryptoKeyType;
use crate::signature::ed25519 as ed;

/// Ed25519 private key (32-byte seed).
pub struct Ed25519SigningKey {
    inner: ed::SecretKey,
}

/// Ed25519 public key.
pub struct Ed25519VerifyingKey {
    inner: ed::PublicKey,
}

impl Ed25519SigningKey {
    /// Parse 32-byte seed.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let inner = ed::SecretKey::from_bytes(bytes).map_err(|_| Error::InvalidPrivateKey)?;
        Ok(Self { inner })
    }
}

impl Ed25519VerifyingKey {
    /// Parse 32-byte public key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let inner = ed::PublicKey::from_bytes(bytes).map_err(|_| Error::InvalidPublicKey)?;
        Ok(Self { inner })
    }
}

impl VerifyingKey for Ed25519VerifyingKey {
    fn key_type(&self) -> CryptoKeyType {
        CryptoKeyType::Ed25519
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        let sig = ed::Signature::from_bytes(signature).map_err(|_| Error::InvalidSignature)?;
        match ed::verify(&self.inner, message, &sig) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn public_key_len(&self) -> usize {
        32
    }

    fn to_public_bytes(&self, out: &mut [u8]) -> Result<()> {
        if out.len() < 32 {
            return Err(Error::InvalidLength);
        }
        out[..32].copy_from_slice(&self.inner.0);
        Ok(())
    }
}

impl SigningKey for Ed25519SigningKey {
    type Verifying = Ed25519VerifyingKey;

    fn key_type(&self) -> CryptoKeyType {
        CryptoKeyType::Ed25519
    }

    #[cfg(feature = "alloc")]
    fn sign(&self, message: &[u8]) -> Result<SignatureBytes> {
        let sig = ed::sign(&self.inner, message).map_err(|_| Error::Failure("sign"))?;
        Ok(SignatureBytes::new(sig.0.to_vec()))
    }

    fn verifying_key(&self) -> Self::Verifying {
        let pk = self.inner.public_key().expect("derive pk");
        Ed25519VerifyingKey { inner: pk }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::traits::{SigningKey, VerifyingKey};

    #[test]
    fn sign_verify_roundtrip() {
        let sk = Ed25519SigningKey::from_bytes(&[7u8; 32]).unwrap();
        let vk = sk.verifying_key();
        let sig = sk.sign(b"hello keys").unwrap();
        assert!(vk.verify(b"hello keys", sig.as_slice()).unwrap());
        assert!(!vk.verify(b"other", sig.as_slice()).unwrap());
        assert_eq!(sk.key_type(), CryptoKeyType::Ed25519);
        assert!(CryptoKeyType::Ed25519.is_implemented());
    }
}
