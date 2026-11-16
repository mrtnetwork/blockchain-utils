//! Solana ZK Sigma-protocol shared transcript (zero-dep port).
//!
//! /// Byte-compatible port of `zk-sdk/src/transcript.rs`
//! (`TranscriptProtocol`): Merlin/STROBE framing over our
//! [`crate::merlin::Transcript`], domain `solana-zk-elgamal-proof-program-v1`.
//! Challenge scalars are 64-byte Merlin outputs reduced wide, exactly like
//! upstream `challenge_scalar`.

use crate::curve::traits::CurvePoint;
use crate::curve::RistrettoPoint;
use crate::merlin::Transcript;

pub mod ciphertext_equality;
pub mod equality;
pub mod grouped_validity;
pub mod percentage_with_cap;
pub mod pubkey_validity;
pub mod zero_ciphertext;

pub use equality::{
    prove_ciphertext_commitment_equality, verify_ciphertext_commitment_equality,
    EQUALITY_PROOF_LEN,
};
pub use grouped_validity::{
    prove_grouped_validity_2, verify_grouped_validity_2,
    GROUPED_VALIDITY_2_PROOF_LEN,
};
pub use grouped_validity::{
    prove_grouped_validity_3, verify_grouped_validity_3,
    GROUPED_VALIDITY_3_PROOF_LEN,
};
pub use grouped_validity::{
    prove_batched_grouped_validity_2, prove_batched_grouped_validity_3,
    verify_batched_grouped_validity_2, verify_batched_grouped_validity_3,
    BATCHED_GROUPED_VALIDITY_2_PROOF_LEN, BATCHED_GROUPED_VALIDITY_3_PROOF_LEN,
};
pub use percentage_with_cap::{
    prove_percentage_with_cap, verify_percentage_with_cap,
    PERCENTAGE_WITH_CAP_PROOF_LEN,
};
pub use ciphertext_equality::{
    prove_ciphertext_ciphertext_equality, verify_ciphertext_ciphertext_equality,
    CIPHERTEXT_EQUALITY_PROOF_LEN,
};

pub use pubkey_validity::{
    prove_pubkey_validity, verify_pubkey_validity, PUBKEY_VALIDITY_PROOF_LEN,
};
pub use zero_ciphertext::{
    prove_zero_ciphertext, verify_zero_ciphertext, ZERO_CIPHERTEXT_PROOF_LEN,
};

/// Global transcript domain (must match upstream
/// `TRANSCRIPT_DOMAIN`; changing it breaks on-chain verification).
pub const TRANSCRIPT_DOMAIN: &[u8] = b"solana-zk-elgamal-proof-program-v1";

/// zk-elgamal transcript with `TranscriptProtocol` helpers.
#[derive(Clone)]
pub struct ZkTranscript {
    /// Underlying Merlin transcript.
    inner: Transcript,
}

impl ZkTranscript {
    /// `Transcript::new(TRANSCRIPT_DOMAIN)` +
    /// `append_message("dom-sep", label)`.
    pub fn new(label: &[u8]) -> Self {
        let mut inner = Transcript::new(TRANSCRIPT_DOMAIN);
        inner.append_message(b"dom-sep", label);
        Self { inner }
    }

    /// Append labeled message bytes.
    pub fn append_message(&mut self, label: &[u8], message: &[u8]) {
        self.inner.append_message(label, message);
    }

    /// Append a u64 as LE bytes (dalek `append_u64`).
    pub fn append_u64(&mut self, label: &[u8], v: u64) {
        self.append_message(label, &v.to_le_bytes());
    }

    /// Append a 32-byte compressed point.
    pub fn append_point(&mut self, label: &[u8], point_enc: &[u8; 32]) {
        self.append_message(label, point_enc);
    }

    /// Append a 32-byte scalar.
    pub fn append_scalar(&mut self, label: &[u8], scalar_enc: &[u8; 32]) {
        self.append_message(label, scalar_enc);
    }

    /// Reject identity encodings, else append (mirrors
    /// `validate_and_append_point`; identity Ristretto encodes to zeros).
    pub fn validate_and_append_point(
        &mut self,
        label: &[u8],
        point_enc: &[u8; 32],
    ) -> SolanaSigResult<()> {
        let p = RistrettoPoint::from_bytes(point_enc)
            .map_err(|_| SigmaError::Deserialization)?;
        if p.ct_is_identity() == 1 {
            return Err(SigmaError::IdentityPoint);
        }
        self.append_point(label, point_enc);
        Ok(())
    }

    /// Labeled 64-byte challenge reduced wide to a scalar.
    pub fn challenge_scalar(
        &mut self,
        label: &[u8],
    ) -> crate::curve::ed25519::Scalar {
        let mut wide = [0u8; 64];
        self.inner.challenge_bytes(label, &mut wide);
        crate::curve::ed25519::Scalar::from_bytes_wide(&wide)
    }

    /// Domain separator for pubkey-validity proofs.
    pub fn pubkey_proof_domain_separator(&mut self) {
        self.append_message(b"dom-sep", b"pubkey-proof");
    }

    /// Domain separator for zero-ciphertext proofs.
    pub fn zero_ciphertext_proof_domain_separator(&mut self) {
        self.append_message(b"dom-sep", b"zero-ciphertext-proof");
    }

    /// Domain separator for an `n`-bit range proof.
    pub fn range_proof_domain_separator(&mut self, n: u64) {
        self.append_message(b"dom-sep", b"range-proof");
        self.append_u64(b"n", n);
    }

    /// Domain separator for a length-`n` inner-product proof.
    pub fn inner_product_domain_separator(&mut self, n: u64) {
        self.append_message(b"dom-sep", b"inner-product");
        self.append_u64(b"n", n);
    }

    /// Domain separator for percentage-with-cap.
    pub fn percentage_with_cap_domain_separator(&mut self) {
        self.append_message(b"dom-sep", b"percentage-with-cap-proof");
    }

    /// Domain separator for grouped ciphertext validity.
    pub fn grouped_validity_domain_separator(&mut self, handles: u64) {
        self.append_message(b"dom-sep", b"validity-proof");
        self.append_u64(b"handles", handles);
    }

    /// Domain separator for batched grouped validity.
    pub fn batched_grouped_validity_domain_separator(&mut self, handles: u64) {
        self.append_message(b"dom-sep", b"batched-validity-proof");
        self.append_u64(b"handles", handles);
    }

    /// Domain separator for ciphertext-ciphertext equality.
    pub fn ciphertext_ciphertext_equality_proof_domain_separator(&mut self) {
        self.append_message(b"dom-sep", b"ciphertext-ciphertext-equality-proof");
    }

    /// Domain separator for ciphertext-commitment equality.
    pub fn ciphertext_commitment_equality_proof_domain_separator(&mut self) {
        self.append_message(b"dom-sep", b"ciphertext-commitment-equality-proof");
    }
}

/// Sigma-protocol errors (mirrors upstream verification errors).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SigmaError {
    /// Malformed proof bytes / point / scalar encoding.
    Deserialization,
    /// Verification equation failed.
    AlgebraicRelation,
    /// Identity point where a generator-multiple is required.
    IdentityPoint,
}

/// On-chain instruction transcript labels (must match the
/// `zk-elgamal-proof` program exactly; proofs made under any other context
/// will NOT verify on-chain).
pub const CTX_PUBKEY_VALIDITY: &[u8] = b"pubkey-validity-instruction";
pub const CTX_ZERO_CIPHERTEXT: &[u8] = b"zero-ciphertext-instruction";
pub const CTX_CIPHERTEXT_COMMITMENT_EQUALITY: &[u8] =
    b"ciphertext-commitment-equality-instruction";
pub const CTX_CIPHERTEXT_CIPHERTEXT_EQUALITY: &[u8] =
    b"ciphertext-ciphertext-equality-instruction";
pub const CTX_GROUPED_VALIDITY_2: &[u8] =
    b"grouped-ciphertext-validity-2-handles-instruction";
pub const CTX_GROUPED_VALIDITY_3: &[u8] =
    b"grouped-ciphertext-validity-3-handles-instruction";
pub const CTX_BATCHED_GROUPED_VALIDITY_2: &[u8] =
    b"batched-grouped-ciphertext-validity-2-handles-instruction";
pub const CTX_BATCHED_GROUPED_VALIDITY_3: &[u8] =
    b"batched-grouped-ciphertext-validity-3-handles-instruction";
pub const CTX_PERCENTAGE_WITH_CAP: &[u8] = b"percentage-with-cap-instruction";
pub const CTX_BATCHED_RANGE_PROOF: &[u8] = b"batched-range-proof-instruction";

/// Result alias for Sigma protocols.
pub type SolanaSigResult<T> = core::result::Result<T, SigmaError>;

/// Identity check via canonical encoding — the same rule as
/// the crate's Monero verifier (`pt_encode(&mp) == IDENTITY_BYTES`).
/// Used instead of `ct_is_identity`, which misses some computed
/// identity-representatives (observed: encodes-to-zero yet `ct` says
/// non-identity on 6-term combined checks).
pub fn is_identity_enc(p: &RistrettoPoint) -> bool {
    let mut enc = [0u8; 32];
    if p.to_bytes_compressed(&mut enc).is_err() {
        return false;
    }
    enc == [0u8; 32]
}

/// Strict canonical scalar from a 32-byte slice (mirrors
/// `canonical_scalar_from_optional_slice`).
pub fn canonical_scalar(
    bytes: &[u8],
) -> SolanaSigResult<crate::curve::ed25519::Scalar> {
    if bytes.len() != 32 {
        return Err(SigmaError::Deserialization);
    }
    let mut fixed = [0u8; 32];
    fixed.copy_from_slice(bytes);
    crate::curve::ed25519::Scalar::from_bytes_le(&fixed)
        .map_err(|_| SigmaError::Deserialization)
}

/// Decode a 32-byte compressed Ristretto point (mirrors
/// `ristretto_point_from_optional_slice`).
pub fn decode_point(bytes: &[u8]) -> SolanaSigResult<RistrettoPoint> {
    if bytes.len() != 32 {
        return Err(SigmaError::Deserialization);
    }
    RistrettoPoint::from_bytes(bytes).map_err(|_| SigmaError::Deserialization)
}
