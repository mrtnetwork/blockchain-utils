//! Cryptographic key interfaces (signing / verifying).
//!
//! Mirrors the `crypto/keys` surface at a high level:
//! - [`CryptoKeyType`] enumerates all known algorithms
//! - Traits for signing and verifying keys
//! - Concrete keys for schemes we already support (secp256k1, secp256r1,
//!   Ed25519, sr25519 / Schnorrkel)
//! - Stubs for schemes that need specialised crypto not yet in this crate
//!   (ML-DSA, RedDSA, full BLS aggregate modes) — all return
//!   [`Error::Unimplemented`]
//!
//! Pure `no_std`. No external dependencies.

mod ecdsa_k1;
mod ecdsa_r1;
mod ed25519;
mod sr25519;
mod traits;
mod types;
mod unimplemented;

pub use ecdsa_k1::{Secp256k1SigningKey, Secp256k1VerifyingKey};
pub use ecdsa_r1::{Secp256r1SigningKey, Secp256r1VerifyingKey};
pub use ed25519::{Ed25519SigningKey, Ed25519VerifyingKey};
pub use sr25519::{Sr25519SigningKey, Sr25519VerifyingKey};
pub use traits::{SignatureBytes, SigningKey, VerifyingKey};
pub use types::{CryptoKeyType, EcdsaSignatureEncoding};
pub use unimplemented::{
    BlsSigningKey, BlsVerifyingKey, MlDsaSigningKey, MlDsaVerifyingKey, RedDsaSigningKey,
    RedDsaVerifyingKey,
};
