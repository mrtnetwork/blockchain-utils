//! Signature schemes: Ed25519 (EdDSA), ECDSA (secp256k1), BIP-340 Schnorr.

pub mod bls12_381;
pub mod ecdsa;
pub mod ecdsa_p256;
pub mod ed25519;
pub mod error;
#[cfg(feature = "alloc")]
pub mod ml_dsa;
#[cfg(feature = "alloc")]
pub mod reddsa;
pub mod rfc6979;
pub mod schnorr;
pub mod schnorr_bch;

pub use ecdsa::{
    recover as ecdsa_recover, recover_and_verify as ecdsa_recover_and_verify,
    recovery_id_for as ecdsa_recovery_id_for, sign as ecdsa_sign, sign_ex as ecdsa_sign_ex,
    sign_with_nonce as ecdsa_sign_with_nonce, verify as ecdsa_verify, PublicKey as EcdsaPublicKey,
    SecretKey as EcdsaSecretKey, Signature as EcdsaSignature,
};
pub use ecdsa_p256::{
    sign as ecdsa_p256_sign, sign_ex as ecdsa_p256_sign_ex,
    sign_with_nonce as ecdsa_p256_sign_with_nonce, verify as ecdsa_p256_verify,
    PublicKey as EcdsaP256PublicKey, SecretKey as EcdsaP256SecretKey,
    Signature as EcdsaP256Signature,
};
pub use ed25519::{
    expand_secret, public_key_variant, sign as ed25519_sign, sign_variant,
    verify as ed25519_verify, verify_variant, ExpandedSecretKey, PublicKey as Ed25519PublicKey,
    SecretKey as Ed25519SecretKey, Signature as Ed25519Signature, Variant as Ed25519Variant,
};
pub use error::{SignatureError, SignatureResult};
pub use schnorr::{
    sign as schnorr_sign, sign_with_aux as schnorr_sign_with_aux,
    sign_with_aux_and_tweak as schnorr_sign_with_aux_and_tweak,
    tweak_public as schnorr_tweak_public, tweak_secret as schnorr_tweak_secret,
    verify as schnorr_verify, PublicKey as SchnorrPublicKey, SecretKey as SchnorrSecretKey,
    Signature as SchnorrSignature,
};
pub use schnorr_bch::{sign as schnorr_bch_sign, verify as schnorr_bch_verify, BCH_SCHNORR_EXTRA};

pub use bls12_381::{
    aggregate_public_keys_g1, aggregate_public_keys_g2, aggregate_signatures_g1,
    aggregate_signatures_g2, aggregate_verify_min_pk, aggregate_verify_min_sig,
    batch_verify_min_pk, batch_verify_min_sig, fast_aggregate_verify_min_pk,
    fast_aggregate_verify_min_sig, sign_min_pk, sign_min_sig, verify_min_pk, verify_min_sig,
    PublicKeyG1 as BlsPublicKeyG1, PublicKeyG2 as BlsPublicKeyG2, SecretKey as BlsSecretKey,
    SignatureG1 as BlsSignatureG1, SignatureG2 as BlsSignatureG2, DST_MIN_PK_NUL, DST_MIN_PK_POP,
    DST_MIN_SIG_NUL, DST_MIN_SIG_POP,
};
