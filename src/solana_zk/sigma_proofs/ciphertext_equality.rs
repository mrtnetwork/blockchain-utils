//! Ciphertext-ciphertext equality Sigma proof (zero-dep port).
//!
//! /// Byte-compatible port of
//! `zk-sdk/src/sigma_proofs/ciphertext_ciphertext_equality.rs`: certifies two
//! ElGamal ciphertexts under different pubkeys encrypt the same amount.
//! Transcript labels (`first-pubkey`, `second-pubkey`, `first-ciphertext`,
//! `second-ciphertext`, `ciphertext-ciphertext-equality-proof` dom-sep) and
//! 224-byte layout (`Y_0 || Y_1 || Y_2 || Y_3 || z_s || z_x || z_r`) match
//! upstream exactly. Randomness from a caller-supplied 32-byte seed.

use crate::solana_zk::sigma_proofs::{
    canonical_scalar, decode_point, is_identity_enc, SigmaError, SolanaSigResult,
    ZkTranscript,
};
use crate::solana_zk::{amount_scalar, h_point, SolanaZkError, SolanaZkResult};
use crate::curve::traits::CurvePoint;
use crate::curve::RistrettoPoint;
use crate::rng::ChaCha20Rng;

/// Byte length of a ciphertext-ciphertext equality proof.
pub const CIPHERTEXT_EQUALITY_PROOF_LEN: usize = 224;

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

/// Prove `first_ciphertext` (known secret) and
/// `second_ciphertext` (known opening) encrypt `amount`.
#[allow(clippy::too_many_arguments)]
pub fn prove_ciphertext_ciphertext_equality(
    first_secret: &[u8; 32],
    first_pubkey: &[u8; 32],
    second_pubkey: &[u8; 32],
    first_ciphertext: &[u8; 64],
    second_ciphertext: &[u8; 64],
    second_opening: &[u8; 32],
    amount: u64,
    seed: &[u8; 32],
    context: &[u8],
) -> SolanaZkResult<[u8; 224]> {
    let s = crate::curve::ed25519::Scalar::from_bytes_le(first_secret)
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    if s.is_zero() {
        return Err(SolanaZkError::InvalidPoint);
    }
    let p1 = RistrettoPoint::from_bytes(first_pubkey)
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    let p2 = RistrettoPoint::from_bytes(second_pubkey)
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    let d1 = RistrettoPoint::from_bytes(&first_ciphertext[32..])
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    let r = crate::curve::ed25519::Scalar::from_bytes_le(second_opening)
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    let x = amount_scalar(amount);
    let g = RistrettoPoint::generator();
    let h = h_point()?;

    let mut transcript = ZkTranscript::new(context);
    transcript.append_message(b"first-pubkey", first_pubkey);
    transcript.append_message(b"second-pubkey", second_pubkey);
    transcript.append_message(b"first-ciphertext", first_ciphertext);
    transcript.append_message(b"second-ciphertext", second_ciphertext);
    transcript.ciphertext_ciphertext_equality_proof_domain_separator();

    let mut rng = ChaCha20Rng::from_seed(seed);
    let y_s = masking_scalar(&mut rng);
    let y_x = masking_scalar(&mut rng);
    let y_r = masking_scalar(&mut rng);
    let y0 = p1.mul(&y_s);
    let y1 = g.mul(&y_x).add(&d1.mul(&y_s));
    let y2 = g.mul(&y_x).add(&h.mul(&y_r));
    let y3 = p2.mul(&y_r);
    let mut y0_enc = [0u8; 32];
    let mut y1_enc = [0u8; 32];
    let mut y2_enc = [0u8; 32];
    let mut y3_enc = [0u8; 32];
    y0.to_bytes_compressed(&mut y0_enc)
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    y1.to_bytes_compressed(&mut y1_enc)
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    y2.to_bytes_compressed(&mut y2_enc)
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    y3.to_bytes_compressed(&mut y3_enc)
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    transcript.append_point(b"Y_0", &y0_enc);
    transcript.append_point(b"Y_1", &y1_enc);
    transcript.append_point(b"Y_2", &y2_enc);
    transcript.append_point(b"Y_3", &y3_enc);
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

    let mut out = [0u8; 224];
    out[..32].copy_from_slice(&y0_enc);
    out[32..64].copy_from_slice(&y1_enc);
    out[64..96].copy_from_slice(&y2_enc);
    out[96..128].copy_from_slice(&y3_enc);
    out[128..160].copy_from_slice(&zs_enc);
    out[160..192].copy_from_slice(&zx_enc);
    out[192..].copy_from_slice(&zr_enc);
    Ok(out)
}

/// Verify a ciphertext-ciphertext equality proof. Rejects
/// identity first pubkey / second pubkey / first commitment / first handle;
/// the second ciphertext may be identity (common Token-2022 state).
#[allow(clippy::too_many_arguments)]
pub fn verify_ciphertext_ciphertext_equality(
    first_pubkey: &[u8; 32],
    second_pubkey: &[u8; 32],
    first_ciphertext: &[u8; 64],
    second_ciphertext: &[u8; 64],
    proof: &[u8; 224],
    context: &[u8],
) -> SolanaSigResult<()> {
    let p1 = decode_point(first_pubkey)?;
    let p2 = decode_point(second_pubkey)?;
    let c1 = decode_point(&first_ciphertext[..32])?;
    let d1 = decode_point(&first_ciphertext[32..])?;
    let c2 = decode_point(&second_ciphertext[..32])?;
    let d2 = decode_point(&second_ciphertext[32..])?;
    if p1.ct_is_identity() == 1
        || p2.ct_is_identity() == 1
        || c1.ct_is_identity() == 1
        || d1.ct_is_identity() == 1
    {
        return Err(SigmaError::IdentityPoint);
    }

    let mut transcript = ZkTranscript::new(context);
    transcript.append_message(b"first-pubkey", first_pubkey);
    transcript.append_message(b"second-pubkey", second_pubkey);
    transcript.append_message(b"first-ciphertext", first_ciphertext);
    transcript.append_message(b"second-ciphertext", second_ciphertext);
    transcript.ciphertext_ciphertext_equality_proof_domain_separator();

    macro_rules! yenc {
        ($lo:expr) => {{
            let y: [u8; 32] = proof[$lo..$lo + 32]
                .try_into()
                .map_err(|_| SigmaError::Deserialization)?;
            transcript.validate_and_append_point(
                match $lo {
                    0 => b"Y_0",
                    32 => b"Y_1",
                    64 => b"Y_2",
                    _ => b"Y_3",
                },
                &y,
            )?;
            y
        }};
    }
    let y0_enc = yenc!(0);
    let y1_enc = yenc!(32);
    let y2_enc = yenc!(64);
    let y3_enc = yenc!(96);
    let c = transcript.challenge_scalar(b"c");
    let z_s = canonical_scalar(&proof[128..160])?;
    let z_x = canonical_scalar(&proof[160..192])?;
    let z_r = canonical_scalar(&proof[192..])?;
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
    let www = w.mul(&ww);

    let y0 = decode_point(&y0_enc)?;
    let y1 = decode_point(&y1_enc)?;
    let y2 = decode_point(&y2_enc)?;
    let y3 = decode_point(&y3_enc)?;
    let g = RistrettoPoint::generator();
    let h = h_point().map_err(|_| SigmaError::Deserialization)?;
    // [z_s, -c, -1, w*z_x, w*z_s, -w*c, -w, ww*z_x, ww*z_r, -ww*c, -ww,
    //  www*z_r, -www*c, -www]
    // over [P1, H, Y_0, G, D1, C1, Y_1, G, H, C2, Y_2, P2, D2, Y_3]
    let check = p1
        .mul(&z_s)
        .add(&h.mul(&c.neg()))
        .add(&y0.neg())
        .add(&g.mul(&w.mul(&z_x)))
        .add(&d1.mul(&w.mul(&z_s)))
        .add(&c1.mul(&w.neg().mul(&c)))
        .add(&y1.mul(&w.neg()))
        .add(&g.mul(&ww.mul(&z_x)))
        .add(&h.mul(&ww.mul(&z_r)))
        .add(&c2.mul(&ww.neg().mul(&c)))
        .add(&y2.mul(&ww.neg()))
        .add(&p2.mul(&www.mul(&z_r)))
        .add(&d2.mul(&www.neg().mul(&c)))
        .add(&y3.mul(&www.neg()));
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
        let first_pubkey: [u8; 32] = [
            24, 130, 167, 34, 34, 136, 232, 14, 129, 111, 60, 83, 160, 52, 106,
            206, 139, 82, 240, 44, 179, 41, 150, 208, 206, 246, 12, 146, 77, 86,
            66, 59,
        ];
        let second_pubkey: [u8; 32] = [
            34, 152, 118, 174, 23, 110, 121, 159, 179, 187, 205, 42, 170, 137,
            121, 208, 122, 66, 13, 38, 84, 139, 192, 236, 158, 62, 71, 128, 109,
            82, 47, 26,
        ];
        let first_ciphertext: [u8; 64] = [
            36, 222, 119, 203, 135, 141, 52, 57, 75, 85, 63, 127, 43, 84, 90,
            18, 103, 110, 53, 145, 158, 179, 255, 45, 37, 131, 125, 35, 18, 58,
            231, 95, 92, 202, 246, 158, 229, 179, 153, 16, 65, 150, 120, 121,
            177, 105, 52, 112, 87, 255, 56, 255, 44, 57, 224, 7, 94, 205, 133,
            136, 151, 82, 131, 122,
        ];
        let second_ciphertext: [u8; 64] = [
            86, 94, 117, 96, 236, 18, 128, 185, 237, 175, 147, 10, 49, 95, 105,
            77, 228, 88, 205, 249, 218, 10, 41, 213, 115, 243, 251, 49, 44, 224,
            128, 100, 78, 238, 73, 38, 182, 109, 230, 155, 1, 190, 105, 26, 219,
            218, 52, 171, 10, 181, 191, 231, 189, 18, 255, 151, 174, 136, 69, 85,
            236, 184, 52, 117,
        ];
        let proof: [u8; 224] = [
            138, 63, 223, 132, 41, 89, 122, 136, 46, 3, 68, 111, 192, 250, 155,
            205, 77, 3, 127, 121, 106, 91, 6, 96, 65, 211, 139, 10, 36, 102,
            171, 98, 128, 239, 219, 120, 252, 67, 154, 29, 229, 165, 92, 219,
            160, 9, 16, 194, 253, 35, 29, 109, 82, 237, 214, 77, 246, 42, 141,
            207, 220, 24, 205, 3, 188, 215, 160, 141, 125, 131, 135, 177, 235,
            95, 212, 24, 190, 62, 73, 194, 253, 198, 151, 44, 37, 21, 97, 122,
            161, 68, 55, 24, 91, 102, 54, 123, 8, 180, 86, 94, 70, 0, 151, 229,
            47, 85, 203, 199, 141, 43, 142, 217, 181, 71, 62, 155, 135, 6, 128,
            78, 54, 85, 45, 230, 179, 249, 43, 103, 49, 174, 13, 108, 128, 126,
            240, 94, 250, 213, 217, 195, 4, 181, 147, 170, 3, 211, 16, 209, 102,
            30, 152, 70, 246, 55, 215, 59, 236, 28, 156, 2, 178, 96, 25, 207,
            240, 149, 27, 185, 241, 92, 160, 30, 102, 196, 187, 6, 230, 90, 202,
            223, 115, 92, 93, 166, 54, 249, 44, 84, 129, 185, 170, 4, 120, 43,
            242, 193, 114, 102, 71, 184, 139, 244, 152, 31, 144, 136, 111, 191,
            255, 227, 188, 48, 158, 43, 160, 100, 170, 199, 210, 182, 135, 5,
            173, 4,
        ];
        verify_ciphertext_ciphertext_equality(
            &first_pubkey,
            &second_pubkey,
            &first_ciphertext,
            &second_ciphertext,
            &proof,
            b"Test",
        )
        .unwrap();
    }

    /// Roundtrip on matching amounts; mismatch fails.
    #[test]
    fn roundtrip_and_mismatch() {
        let first_secret = [2u8; 32];
        let second_secret = [4u8; 32];
        let first_pubkey =
            crate::solana_zk::elgamal_pubkey_from_secret(&first_secret).unwrap();
        let second_pubkey =
            crate::solana_zk::elgamal_pubkey_from_secret(&second_secret).unwrap();
        let opening = [6u8; 32];
        let amount = 55u64;
        let first_ct = crate::solana_zk::elgamal_encrypt_with(
            &first_pubkey,
            amount,
            &opening,
        )
        .unwrap();
        let second_ct = crate::solana_zk::elgamal_encrypt_with(
            &second_pubkey,
            amount,
            &opening,
        )
        .unwrap();
        let proof = prove_ciphertext_ciphertext_equality(
            &first_secret,
            &first_pubkey,
            &second_pubkey,
            &first_ct,
            &second_ct,
            &opening,
            amount,
            &[7u8; 32],
            b"Test",
        )
        .unwrap();
        verify_ciphertext_ciphertext_equality(
            &first_pubkey,
            &second_pubkey,
            &first_ct,
            &second_ct,
            &proof,
            b"Test",
        )
        .unwrap();
        // Different amount in the second ciphertext must fail.
        let bad_ct = crate::solana_zk::elgamal_encrypt_with(
            &second_pubkey,
            77,
            &opening,
        )
        .unwrap();
        assert!(
            verify_ciphertext_ciphertext_equality(
                &first_pubkey,
                &second_pubkey,
                &first_ct,
                &bad_ct,
                &proof,
                b"Test",
            )
            .is_err()
        );
    }
}
