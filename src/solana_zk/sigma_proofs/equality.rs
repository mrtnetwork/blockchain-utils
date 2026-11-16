//! Ciphertext-commitment equality Sigma proof (zero-dep port).
//!
//! /// Byte-compatible port of
//! `zk-sdk/src/sigma_proofs/ciphertext_commitment_equality.rs`: certifies an
//! ElGamal ciphertext and a Pedersen commitment encode the same amount.
//! Transcript labels and 192-byte layout
//! (`Y_0 || Y_1 || Y_2 || z_s || z_x || z_r`) match upstream exactly.
//! Randomness from a caller-supplied 32-byte seed.

use crate::solana_zk::sigma_proofs::{
    canonical_scalar, decode_point, SigmaError, SolanaSigResult, ZkTranscript, is_identity_enc,
};
use crate::solana_zk::{amount_scalar, h_point, SolanaZkError, SolanaZkResult};
use crate::curve::traits::CurvePoint;
use crate::curve::RistrettoPoint;
use crate::rng::ChaCha20Rng;

/// Byte length of an equality proof.
pub const EQUALITY_PROOF_LEN: usize = 192;

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

/// Prove `ciphertext` and `commitment` encode `amount`
/// (`opening` is the commitment opening, `secret` the ElGamal secret).
#[allow(clippy::too_many_arguments)]
pub fn prove_ciphertext_commitment_equality(
    secret: &[u8; 32],
    pubkey: &[u8; 32],
    ciphertext: &[u8; 64],
    commitment: &[u8; 32],
    opening: &[u8; 32],
    amount: u64,
    seed: &[u8; 32],
    context: &[u8],
) -> SolanaZkResult<[u8; 192]> {
    let s = crate::curve::ed25519::Scalar::from_bytes_le(secret)
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    if s.is_zero() {
        return Err(SolanaZkError::InvalidPoint);
    }
    let p = RistrettoPoint::from_bytes(pubkey).map_err(|_| SolanaZkError::InvalidPoint)?;
    let d = RistrettoPoint::from_bytes(&ciphertext[32..])
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    let r = crate::curve::ed25519::Scalar::from_bytes_le(opening)
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    let x = amount_scalar(amount);
    let g = RistrettoPoint::generator();
    let h = h_point()?;
    let _ = commitment;

    let mut transcript = ZkTranscript::new(context);
    transcript.append_message(b"pubkey", pubkey);
    transcript.append_message(b"ciphertext", ciphertext);
    transcript.append_message(b"commitment", commitment);
    transcript.ciphertext_commitment_equality_proof_domain_separator();

    let mut rng = ChaCha20Rng::from_seed(seed);
    let y_s = masking_scalar(&mut rng);
    let y_x = masking_scalar(&mut rng);
    let y_r = masking_scalar(&mut rng);
    let y0 = p.mul(&y_s);
    let y1 = g.mul(&y_x).add(&d.mul(&y_s));
    let y2 = g.mul(&y_x).add(&h.mul(&y_r));
    let mut y0_enc = [0u8; 32];
    let mut y1_enc = [0u8; 32];
    let mut y2_enc = [0u8; 32];
    y0.to_bytes_compressed(&mut y0_enc)
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    y1.to_bytes_compressed(&mut y1_enc)
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    y2.to_bytes_compressed(&mut y2_enc)
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    transcript.append_point(b"Y_0", &y0_enc);
    transcript.append_point(b"Y_1", &y1_enc);
    transcript.append_point(b"Y_2", &y2_enc);
    let c = transcript.challenge_scalar(b"c");
    let z_s = c.mul(&s).add(&y_s);
    let z_x = c.mul(&x).add(&y_x);
    let z_r = c.mul(&r).add(&y_r);
    let mut zs_enc = [0u8; 32];
    let mut zx_enc = [0u8; 32];
    let mut zr_enc = [0u8; 32];
    z_s.to_bytes_le(&mut zs_enc);
    z_x.to_bytes_le(&mut zx_enc);
    z_r.to_bytes_le(&mut zr_enc);
    transcript.append_scalar(b"z_s", &zs_enc);
    transcript.append_scalar(b"z_x", &zx_enc);
    transcript.append_scalar(b"z_r", &zr_enc);
    let _w = transcript.challenge_scalar(b"w");

    let mut out = [0u8; 192];
    out[..32].copy_from_slice(&y0_enc);
    out[32..64].copy_from_slice(&y1_enc);
    out[64..96].copy_from_slice(&y2_enc);
    out[96..128].copy_from_slice(&zs_enc);
    out[128..160].copy_from_slice(&zx_enc);
    out[160..].copy_from_slice(&zr_enc);
    Ok(out)
}

/// Verify an equality proof against pubkey / ciphertext /
/// commitment. Rejects identity inputs.
pub fn verify_ciphertext_commitment_equality(
    pubkey: &[u8; 32],
    ciphertext: &[u8; 64],
    commitment: &[u8; 32],
    proof: &[u8; 192],
    context: &[u8],
) -> SolanaSigResult<()> {
    let p = decode_point(pubkey)?;
    let c_ct = decode_point(&ciphertext[..32])?;
    let d = decode_point(&ciphertext[32..])?;
    let c_cm = decode_point(commitment)?;
    if p.ct_is_identity() == 1
        || c_ct.ct_is_identity() == 1
        || d.ct_is_identity() == 1
        || c_cm.ct_is_identity() == 1
    {
        return Err(SigmaError::IdentityPoint);
    }

    let mut transcript = ZkTranscript::new(context);
    transcript.append_message(b"pubkey", pubkey);
    transcript.append_message(b"ciphertext", ciphertext);
    transcript.append_message(b"commitment", commitment);
    transcript.ciphertext_commitment_equality_proof_domain_separator();

    let y0_enc: [u8; 32] = proof[..32]
        .try_into()
        .map_err(|_| SigmaError::Deserialization)?;
    let y1_enc: [u8; 32] = proof[32..64]
        .try_into()
        .map_err(|_| SigmaError::Deserialization)?;
    let y2_enc: [u8; 32] = proof[64..96]
        .try_into()
        .map_err(|_| SigmaError::Deserialization)?;
    transcript.validate_and_append_point(b"Y_0", &y0_enc)?;
    transcript.validate_and_append_point(b"Y_1", &y1_enc)?;
    transcript.validate_and_append_point(b"Y_2", &y2_enc)?;
    let c = transcript.challenge_scalar(b"c");
    let z_s = canonical_scalar(&proof[96..128])?;
    let z_x = canonical_scalar(&proof[128..160])?;
    let z_r = canonical_scalar(&proof[160..])?;
    let mut zs_enc = [0u8; 32];
    let mut zx_enc = [0u8; 32];
    let mut zr_enc = [0u8; 32];
    z_s.to_bytes_le(&mut zs_enc);
    z_x.to_bytes_le(&mut zx_enc);
    z_r.to_bytes_le(&mut zr_enc);
    transcript.append_scalar(b"z_s", &zs_enc);
    transcript.append_scalar(b"z_x", &zx_enc);
    transcript.append_scalar(b"z_r", &zr_enc);
    let w = transcript.challenge_scalar(b"w");
    let ww = w.mul(&w);

    let y0 = decode_point(&y0_enc)?;
    let y1 = decode_point(&y1_enc)?;
    let y2 = decode_point(&y2_enc)?;
    let g = RistrettoPoint::generator();
    let h = h_point().map_err(|_| SigmaError::Deserialization)?;
    // [z_s, -c, -1, w*z_x, w*z_s, -w*c, -w, ww*z_x, ww*z_r, -ww*c, -ww]
    // over [P, H, Y_0, G, D, C_ct, Y_1, G, H, C_cm, Y_2]
    let check = p
        .mul(&z_s)
        .add(&h.mul(&c.neg()))
        .add(&y0.neg())
        .add(&g.mul(&w.mul(&z_x)))
        .add(&d.mul(&w.mul(&z_s)))
        .add(&c_ct.mul(&w.neg().mul(&c)))
        .add(&y1.mul(&w.neg()))
        .add(&g.mul(&ww.mul(&z_x)))
        .add(&h.mul(&ww.mul(&z_r)))
        .add(&c_cm.mul(&ww.neg().mul(&c)))
        .add(&y2.mul(&ww.neg()));
    if is_identity_enc(&check) {
        Ok(())
    } else {
        Err(SigmaError::AlgebraicRelation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Upstream golden vector (`Test` context).
    #[test]
    fn golden_vector_verifies() {
        let pubkey: [u8; 32] = [
            184, 237, 227, 228, 91, 138, 224, 225, 137, 15, 198, 162, 159, 238,
            12, 92, 181, 60, 226, 44, 104, 153, 137, 193, 35, 155, 52, 165, 13,
            215, 208, 43,
        ];
        let ciphertext: [u8; 64] = [
            62, 195, 56, 168, 14, 8, 152, 82, 134, 186, 46, 123, 37, 146, 179,
            32, 89, 117, 68, 237, 244, 24, 111, 172, 104, 35, 38, 35, 216, 0, 0,
            67, 110, 243, 105, 175, 185, 222, 174, 133, 158, 152, 44, 154, 11,
            114, 174, 97, 45, 34, 207, 99, 143, 17, 242, 159, 255, 31, 110, 32,
            54, 60, 104, 6,
        ];
        let commitment: [u8; 32] = [
            68, 219, 45, 246, 116, 198, 47, 179, 228, 150, 225, 49, 186, 25,
            131, 214, 66, 77, 51, 206, 153, 100, 126, 142, 19, 196, 120, 63, 90,
            79, 20, 116,
        ];
        let proof: [u8; 192] = [
            16, 188, 154, 206, 158, 10, 184, 239, 239, 46, 127, 117, 26, 40,
            132, 6, 12, 24, 148, 203, 226, 177, 88, 172, 85, 23, 252, 13, 100,
            99, 19, 82, 168, 20, 101, 118, 155, 20, 87, 223, 189, 13, 254, 186,
            7, 21, 112, 43, 85, 113, 147, 204, 189, 94, 208, 47, 20, 0, 241,
            199, 85, 130, 57, 51, 234, 196, 238, 101, 225, 164, 98, 117, 174,
            147, 46, 25, 219, 130, 106, 243, 155, 237, 98, 47, 205, 129, 52,
            196, 238, 160, 66, 99, 204, 122, 140, 52, 243, 30, 78, 253, 238, 18,
            151, 33, 159, 3, 107, 53, 75, 246, 124, 39, 235, 125, 203, 26, 155,
            126, 164, 238, 130, 127, 83, 54, 49, 65, 20, 7, 12, 221, 99, 142,
            20, 105, 52, 117, 7, 98, 237, 93, 216, 26, 147, 80, 51, 61, 207,
            246, 133, 132, 237, 221, 82, 177, 90, 33, 80, 54, 4, 2, 252, 154,
            169, 118, 22, 115, 79, 152, 72, 145, 29, 11, 176, 90, 69, 212, 234,
            94, 158, 31, 183, 204, 155, 2, 51, 65, 233, 41, 130, 122, 43, 14,
        ];
        verify_ciphertext_commitment_equality(
            &pubkey,
            &ciphertext,
            &commitment,
            &proof,
            b"Test",
        )
        .unwrap();
    }

    /// Roundtrip on matching amount/opening; mismatch fails.
    #[test]
    fn roundtrip_and_mismatch() {
        let secret = [2u8; 32];
        let pubkey =
            crate::solana_zk::elgamal_pubkey_from_secret(&secret).unwrap();
        let opening = [4u8; 32];
        let amount = 55u64;
        let ct =
            crate::solana_zk::elgamal_encrypt_with(&pubkey, amount, &opening)
                .unwrap();
        // Commitment with the same opening: C = m*G + r*H.
        let g = RistrettoPoint::generator();
        let h = crate::solana_zk::h_point().unwrap();
        let r = crate::curve::ed25519::Scalar::from_bytes_le(&opening).unwrap();
        let mut commitment = [0u8; 32];
        g.mul(&crate::solana_zk::amount_scalar(amount))
            .add(&h.mul(&r))
            .to_bytes_compressed(&mut commitment)
            .unwrap();
        let proof = prove_ciphertext_commitment_equality(
            &secret,
            &pubkey,
            &ct,
            &commitment,
            &opening,
            amount,
            &[23u8; 32],
            b"Test",
        )
        .unwrap();
        verify_ciphertext_commitment_equality(
            &pubkey,
            &ct,
            &commitment,
            &proof,
            b"Test",
        )
        .unwrap();
        // Same proof against a different commitment must fail.
        let mut bad = commitment;
        bad[0] ^= 1;
        assert!(
            verify_ciphertext_commitment_equality(
                &pubkey, &ct, &bad, &proof, b"Test"
            )
            .is_err()
        );
    }
}
