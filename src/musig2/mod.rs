//! BIP-327 MuSig2 multi-signature over secp256k1.
//!
//! Domains match the `MuSig2Constants` / BIP-327 tagged hashes:
//! - `KeyAgg list`, `KeyAgg coefficient`
//! - `MuSig/nonce`, `MuSig/noncecoef`, `MuSig/aux`
//! - `BIP0340/challenge`
//!
//! Point encodings: 33-byte SEC1 compressed. Nonces: 66-byte (R1||R2).
//! Partial sigs: 32-byte scalar. Final aggregate sig: BIP-340 64-byte.

#![cfg(feature = "alloc")]

mod error;
mod hash;
mod key_agg;
mod nonce;
mod session;
mod sign;

pub use error::{Musig2Error, Musig2Result};
pub use key_agg::{key_agg, key_agg_and_tweak, KeyAggContext, Tweak};
pub use nonce::{nonce_agg, nonce_generate, NoncePair};
pub use session::{session_values, Session, SessionValues};
pub use sign::{
    deterministic_sign, partial_sig_agg, partial_sig_verify, partial_sign, verify_aggregate,
    DeterministicSignature,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::secp256k1::{Scalar, Secp256k1Point};
    use crate::curve::traits::CurvePoint;

    fn sk_to_pk(sk: &[u8; 32]) -> [u8; 33] {
        let d = Scalar::from_bytes(sk).unwrap();
        let p = Secp256k1Point::generator().mul(&d);
        let mut out = [0u8; 33];
        p.to_bytes_compressed(&mut out).unwrap();
        out
    }

    #[test]
    fn key_agg_two_keys_roundtrip_shape() {
        let _sk1 = [1u8; 32];
        let _sk2 = [2u8; 32];
        // force valid scalars by hashing
        let h1 = crate::hash::sha256::sha256(b"musig-sk-1").unwrap();
        let h2 = crate::hash::sha256::sha256(b"musig-sk-2").unwrap();
        let pk1 = sk_to_pk(&h1);
        let pk2 = sk_to_pk(&h2);
        let ctx = key_agg(&[pk1.as_slice(), pk2.as_slice()]).expect("key_agg");
        let mut enc = [0u8; 33];
        ctx.q.to_bytes_compressed(&mut enc).unwrap();
        assert_eq!(enc[0], 0x02 | (enc[0] & 1)); // compressed
        assert_ne!(enc[1..], [0u8; 32]);
    }

    #[test]
    fn nonce_generate_lengths() {
        let sk = crate::hash::sha256::sha256(b"musig-nonce-sk").unwrap();
        let pk = sk_to_pk(&sk);
        let pair = nonce_generate(
            Some(&sk),
            Some(&pk),
            None,
            None,
            Some(b"msg"),
            &[9u8; 32],
        )
        .expect("nonce");
        assert_eq!(pair.secnonce.len(), 32 + 32 + 33);
        assert_eq!(pair.pubnonce.len(), 66);
    }
}
