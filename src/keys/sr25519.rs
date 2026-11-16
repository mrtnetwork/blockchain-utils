//! sr25519 / Schnorrkel signing / verifying keys.

use crate::error::{Error, Result};
use crate::keys::traits::{SignatureBytes, SigningKey, VerifyingKey};
use crate::keys::types::CryptoKeyType;
use crate::schnorrkel::{MiniSecretKey, PublicKey, SecretKey, Signature};

/// sr25519 signing key (expanded from 32-byte mini-secret).
pub struct Sr25519SigningKey {
    inner: SecretKey,
}

/// sr25519 verifying key.
pub struct Sr25519VerifyingKey {
    inner: PublicKey,
}

impl Sr25519SigningKey {
    /// From 32-byte mini-secret (Ed25519 expansion).
    pub fn from_mini_secret(bytes: &[u8; 32]) -> Self {
        let mini = MiniSecretKey::from_bytes(bytes);
        Self {
            inner: mini.expand(),
        }
    }

    /// Sign with an explicit 64-byte external nonce (tests / deterministic).
    pub fn sign_with_nonce(&self, message: &[u8], nonce: &[u8; 64]) -> Signature {
        self.inner.sign_simple(message, nonce)
    }
}

impl Sr25519VerifyingKey {
    /// From 32-byte compressed Ristretto public key.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let inner = PublicKey::from_bytes(bytes).map_err(|_| Error::InvalidPublicKey)?;
        Ok(Self { inner })
    }
}

impl VerifyingKey for Sr25519VerifyingKey {
    fn key_type(&self) -> CryptoKeyType {
        CryptoKeyType::Sr25519
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        if signature.len() != 64 {
            return Err(Error::InvalidSignature);
        }
        let mut b = [0u8; 64];
        b.copy_from_slice(signature);
        let sig = Signature::from_bytes(&b).ok_or(Error::InvalidSignature)?;
        Ok(self.inner.verify_simple(message, &sig))
    }

    fn public_key_len(&self) -> usize {
        32
    }

    fn to_public_bytes(&self, out: &mut [u8]) -> Result<()> {
        if out.len() < 32 {
            return Err(Error::InvalidLength);
        }
        out[..32].copy_from_slice(&self.inner.to_bytes());
        Ok(())
    }
}

impl SigningKey for Sr25519SigningKey {
    type Verifying = Sr25519VerifyingKey;

    fn key_type(&self) -> CryptoKeyType {
        CryptoKeyType::Sr25519
    }

    #[cfg(feature = "alloc")]
    fn sign(&self, message: &[u8]) -> Result<SignatureBytes> {
        // Deterministic-ish nonce from message binding (not RNG — caller should prefer
        // `sign_with_nonce` when external entropy is available).
        let mut nonce = [0u8; 64];
        let h1 = crate::hash::sha512(message).map_err(|_| Error::Failure("sha512"))?;
        nonce.copy_from_slice(&h1);
        let sig = self.inner.sign_simple(message, &nonce);
        Ok(SignatureBytes::new(sig.to_bytes().to_vec()))
    }

    fn verifying_key(&self) -> Self::Verifying {
        Sr25519VerifyingKey {
            inner: self.inner.public_key(),
        }
    }
}
