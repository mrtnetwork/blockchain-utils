//! Stubs for key types that need specialised crypto not yet in this crate.
//!
//! Every method returns [`Error::Unimplemented`].

use crate::error::{Error, Result};
use crate::keys::traits::{SignatureBytes, SigningKey, VerifyingKey};
use crate::keys::types::CryptoKeyType;

macro_rules! unimplemented_pair {
    (
        $sign_name:ident, $verify_name:ident, $key_type:expr, $pk_len:expr
    ) => {
        /// Signing key stub — always [`Error::Unimplemented`].
        #[derive(Clone, Debug, Default)]
        pub struct $sign_name;

        /// Verifying key stub — always [`Error::Unimplemented`].
        #[derive(Clone, Debug, Default)]
        pub struct $verify_name;

        impl $sign_name {
            /// Construct stub (no key material accepted yet).
            pub fn new() -> Self {
                Self
            }

            /// Parsing is not available for this algorithm yet.
            pub fn from_bytes(_bytes: &[u8]) -> Result<Self> {
                Err(Error::Unimplemented)
            }
        }

        impl $verify_name {
            /// Construct stub.
            pub fn new() -> Self {
                Self
            }

            /// Parsing is not available for this algorithm yet.
            pub fn from_bytes(_bytes: &[u8]) -> Result<Self> {
                Err(Error::Unimplemented)
            }
        }

        impl VerifyingKey for $verify_name {
            fn key_type(&self) -> CryptoKeyType {
                $key_type
            }

            fn verify(&self, _message: &[u8], _signature: &[u8]) -> Result<bool> {
                Err(Error::Unimplemented)
            }

            fn public_key_len(&self) -> usize {
                $pk_len
            }

            fn to_public_bytes(&self, _out: &mut [u8]) -> Result<()> {
                Err(Error::Unimplemented)
            }
        }

        impl SigningKey for $sign_name {
            type Verifying = $verify_name;

            fn key_type(&self) -> CryptoKeyType {
                $key_type
            }

            #[cfg(feature = "alloc")]
            fn sign(&self, _message: &[u8]) -> Result<SignatureBytes> {
                Err(Error::Unimplemented)
            }

            fn verifying_key(&self) -> Self::Verifying {
                $verify_name
            }
        }
    };
}

// NIST PQC
unimplemented_pair!(
    MlDsaSigningKey,
    MlDsaVerifyingKey,
    CryptoKeyType::MlDsa,
    1952
);

// BLS modes (full aggregate / min-pk / min-sig need specialised pairing API)
unimplemented_pair!(BlsSigningKey, BlsVerifyingKey, CryptoKeyType::Bls12G1, 48);

// Zcash RedDSA
unimplemented_pair!(
    RedDsaSigningKey,
    RedDsaVerifyingKey,
    CryptoKeyType::RedPallasSpend,
    32
);

/// Dispatch helper: return whether a key type is implemented.
/// Test-only helper (unit tests below).
#[cfg(test)]
pub fn ensure_implemented(key_type: CryptoKeyType) -> Result<()> {
    if key_type.is_implemented() {
        Ok(())
    } else {
        Err(Error::Unimplemented)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mldsa_is_unimplemented() {
        assert!(matches!(
            MlDsaSigningKey::from_bytes(&[]),
            Err(Error::Unimplemented)
        ));
        assert!(!CryptoKeyType::MlDsa.is_implemented());
    }

    #[test]
    fn ensure_implemented_works() {
        assert!(ensure_implemented(CryptoKeyType::Secp256k1).is_ok());
        assert!(matches!(
            ensure_implemented(CryptoKeyType::MlDsa),
            Err(Error::Unimplemented)
        ));
    }
}
