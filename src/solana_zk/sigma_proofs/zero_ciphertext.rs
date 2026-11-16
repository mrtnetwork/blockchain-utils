//! Zero-ciphertext Sigma proof (zero-dep port).
//!
//! /// Byte-compatible port of
//! `zk-sdk/src/sigma_proofs/zero_ciphertext.rs`: proves a ciphertext
//! encrypts 0 under the given pubkey. Transcript labels (`pubkey`,
//! `ciphertext`, `zero-ciphertext-proof` dom-sep, `Y_P`, `Y_D`, `c`, `z`,
//! `w` batching challenge) and proof layout (`Y_P || Y_D || z`, 96 bytes)
//! match upstream exactly. Randomness from a caller-supplied 32-byte seed.

use crate::solana_zk::sigma_proofs::{
    canonical_scalar, decode_point, SigmaError, SolanaSigResult, ZkTranscript, is_identity_enc,
};
use crate::solana_zk::{h_point, SolanaZkError, SolanaZkResult};
use crate::curve::traits::CurvePoint;
use crate::curve::RistrettoPoint;
use crate::rng::ChaCha20Rng;

/// Byte length of a zero-ciphertext proof.
pub const ZERO_CIPHERTEXT_PROOF_LEN: usize = 96;

/// Draw a nonzero masking scalar from a seeded ChaCha20 stream.
fn masking_scalar(rng: &mut ChaCha20Rng) -> crate::curve::ed25519::Scalar {
    loop {
        let mut b = [0u8; 32];
        rng.next_bytes(32, &mut b);
        let s = crate::curve::ed25519::Scalar::from_bytes_mod_order(&b);
        if !s.is_zero() {
            return s;
        }
    }
}

/// Prove `ciphertext` encrypts 0 under `pubkey` (caller must
/// pass the pubkey matching `secret`).
pub fn prove_zero_ciphertext(
    secret: &[u8; 32],
    pubkey: &[u8; 32],
    ciphertext: &[u8; 64],
    seed: &[u8; 32],
    context: &[u8],
) -> SolanaZkResult<[u8; 96]> {
    let s = crate::curve::ed25519::Scalar::from_bytes_le(secret)
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    if s.is_zero() {
        return Err(SolanaZkError::InvalidPoint);
    }
    let p = RistrettoPoint::from_bytes(pubkey).map_err(|_| SolanaZkError::InvalidPoint)?;
    let c_pt = RistrettoPoint::from_bytes(&ciphertext[..32])
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    let d_pt = RistrettoPoint::from_bytes(&ciphertext[32..])
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    let _ = c_pt;

    let mut transcript = ZkTranscript::new(context);
    transcript.append_message(b"pubkey", pubkey);
    transcript.append_message(b"ciphertext", ciphertext);
    transcript.zero_ciphertext_proof_domain_separator();

    let mut rng = ChaCha20Rng::from_seed(seed);
    let y = masking_scalar(&mut rng);
    let mut yp_enc = [0u8; 32];
    let mut yd_enc = [0u8; 32];
    p.mul(&y)
        .to_bytes_compressed(&mut yp_enc)
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    d_pt
        .mul(&y)
        .to_bytes_compressed(&mut yd_enc)
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    transcript.append_point(b"Y_P", &yp_enc);
    transcript.append_point(b"Y_D", &yd_enc);
    let c = transcript.challenge_scalar(b"c");
    let z = c.mul(&s).add(&y);
    let mut z_enc = [0u8; 32];
    z.to_bytes_le(&mut z_enc);
    transcript.append_scalar(b"z", &z_enc);
    let _w = transcript.challenge_scalar(b"w");

    let mut out = [0u8; 96];
    out[..32].copy_from_slice(&yp_enc);
    out[32..64].copy_from_slice(&yd_enc);
    out[64..].copy_from_slice(&z_enc);
    Ok(out)
}

/// Verify a zero-ciphertext proof. Rejects identity pubkey /
/// commitment / handle even if the equation would hold.
pub fn verify_zero_ciphertext(
    pubkey: &[u8; 32],
    ciphertext: &[u8; 64],
    proof: &[u8; 96],
    context: &[u8],
) -> SolanaSigResult<()> {
    let p = decode_point(pubkey)?;
    let c_pt = decode_point(&ciphertext[..32])?;
    let d_pt = decode_point(&ciphertext[32..])?;
    if p.ct_is_identity() == 1
        || c_pt.ct_is_identity() == 1
        || d_pt.ct_is_identity() == 1
    {
        return Err(SigmaError::IdentityPoint);
    }

    let mut transcript = ZkTranscript::new(context);
    transcript.append_message(b"pubkey", pubkey);
    transcript.append_message(b"ciphertext", ciphertext);
    transcript.zero_ciphertext_proof_domain_separator();

    let yp_enc: [u8; 32] = proof[..32]
        .try_into()
        .map_err(|_| SigmaError::Deserialization)?;
    let yd_enc: [u8; 32] = proof[32..64]
        .try_into()
        .map_err(|_| SigmaError::Deserialization)?;
    transcript.validate_and_append_point(b"Y_P", &yp_enc)?;
    transcript.append_point(b"Y_D", &yd_enc);
    let c = transcript.challenge_scalar(b"c");
    let z = canonical_scalar(&proof[64..])?;
    let mut z_enc = [0u8; 32];
    z.to_bytes_le(&mut z_enc);
    transcript.append_scalar(b"z", &z_enc);
    let w = transcript.challenge_scalar(b"w");

    let y_p = decode_point(&yp_enc)?;
    let y_d = decode_point(&yd_enc)?;
    let h = h_point().map_err(|_| SigmaError::Deserialization)?;
    // z*P - c*H - Y_P + (w*z)*D - (w*c)*C - w*Y_D == 0
    let check = p
        .mul(&z)
        .add(&h.mul(&c.neg()))
        .add(&y_p.neg())
        .add(&d_pt.mul(&w.mul(&z)))
        .add(&c_pt.mul(&w.neg().mul(&c)))
        .add(&y_d.mul(&w.neg()));
    if is_identity_enc(&check) {
        Ok(())
    } else {
        Err(SigmaError::AlgebraicRelation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Upstream golden vector (`zero_ciphertext` test):
    /// official proof verifies under `b"test"`.
    #[test]
    fn golden_vector_verifies() {
        let pubkey: [u8; 32] = [
            136, 167, 174, 141, 22, 182, 144, 191, 54, 3, 61, 159, 151, 179, 23,
            29, 133, 76, 115, 69, 201, 22, 129, 153, 114, 64, 251, 46, 243, 237,
            73, 79,
        ];
        let ciphertext: [u8; 64] = [
            114, 187, 195, 169, 179, 3, 224, 229, 94, 226, 105, 46, 206, 165, 9,
            174, 28, 155, 151, 20, 192, 187, 123, 218, 82, 163, 47, 125, 139,
            128, 31, 38, 192, 14, 74, 87, 150, 47, 102, 215, 53, 199, 174, 247,
            105, 59, 83, 223, 13, 14, 148, 253, 17, 241, 46, 10, 247, 93, 75,
            195, 131, 107, 11, 4,
        ];
        let proof: [u8; 96] = [
            124, 200, 155, 94, 220, 33, 164, 19, 43, 228, 85, 160, 244, 42, 193,
            170, 80, 171, 46, 175, 220, 11, 100, 102, 139, 3, 41, 78, 131, 7,
            197, 44, 130, 35, 144, 19, 248, 219, 56, 162, 182, 243, 113, 186,
            147, 136, 226, 115, 23, 235, 66, 129, 162, 99, 249, 112, 139, 92,
            121, 63, 97, 2, 220, 67, 129, 190, 131, 118, 233, 166, 253, 209, 12,
            226, 230, 26, 117, 110, 201, 234, 76, 177, 32, 149, 35, 128, 134,
            202, 68, 193, 169, 118, 254, 69, 228, 9,
        ];
        verify_zero_ciphertext(&pubkey, &ciphertext, &proof, b"test").unwrap();
    }

    /// Prove/verify roundtrip on an encryption of 0; a proof
    /// over an encryption of 1 must NOT verify.
    #[test]
    fn roundtrip() {
        let secret = [13u8; 32];
        let pubkey =
            crate::solana_zk::elgamal_pubkey_from_secret(&secret).unwrap();
        let ct0 =
            crate::solana_zk::elgamal_encrypt_with(&pubkey, 0, &[3u8; 32])
                .unwrap();
        let proof =
            prove_zero_ciphertext(&secret, &pubkey, &ct0, &[5u8; 32], b"test")
                .unwrap();
        verify_zero_ciphertext(&pubkey, &ct0, &proof, b"test").unwrap();

        let ct1 =
            crate::solana_zk::elgamal_encrypt_with(&pubkey, 1, &[3u8; 32])
                .unwrap();
        assert!(
            verify_zero_ciphertext(&pubkey, &ct1, &proof, b"test").is_err()
        );
        // All-zero ciphertext rejected.
        assert_eq!(
            verify_zero_ciphertext(&pubkey, &[0u8; 64], &proof, b"test")
                .unwrap_err(),
            SigmaError::IdentityPoint
        );
    }
}
