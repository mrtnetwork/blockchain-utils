//! Grouped ciphertext validity Sigma proof, 2 handles (zero-dep port).
//!
//! /// Byte-compatible port of
//! `zk-sdk/src/sigma_proofs/grouped_ciphertext_validity/handles_2.rs`:
//! certifies a Pedersen commitment decrypts under two ElGamal pubkeys.
//! Transcript labels (`first-pubkey`, `second-pubkey`, `grouped-ciphertext`,
//! `validity-proof` dom-sep + `handles` = 2) and 160-byte layout
//! (`Y_0 || Y_1 || Y_2 || z_r || z_x`) match upstream exactly. Randomness
//! from a caller-supplied 32-byte seed.

use crate::solana_zk::sigma_proofs::{
    canonical_scalar, decode_point, is_identity_enc, SigmaError, SolanaSigResult,
    ZkTranscript,
};
use crate::solana_zk::{amount_scalar, h_point, SolanaZkError, SolanaZkResult};
use crate::curve::traits::CurvePoint;
use crate::curve::RistrettoPoint;
use crate::rng::ChaCha20Rng;

/// Byte length of a 2-handle validity proof.
pub const GROUPED_VALIDITY_2_PROOF_LEN: usize = 160;

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

/// Prove `commitment` ( Pedersen `m`, opening `r`) decrypts
/// under `first_pubkey` and `second_pubkey`. `grouped_ciphertext` is
/// `commitment || handle1 || handle2` (96 bytes) and only enters the
/// transcript; the math uses the pubkeys directly.
#[allow(clippy::too_many_arguments)]
pub fn prove_grouped_validity_2(
    first_pubkey: &[u8; 32],
    second_pubkey: &[u8; 32],
    grouped_ciphertext: &[u8; 96],
    amount: u64,
    opening: &[u8; 32],
    seed: &[u8; 32],
    context: &[u8],
) -> SolanaZkResult<[u8; 160]> {
    let p1 = RistrettoPoint::from_bytes(first_pubkey)
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    let p2 = RistrettoPoint::from_bytes(second_pubkey)
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    let r = crate::curve::ed25519::Scalar::from_bytes_le(opening)
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    let x = amount_scalar(amount);
    let _g = RistrettoPoint::generator();
    let _h = h_point()?;

    let mut transcript = ZkTranscript::new(context);
    transcript.append_message(b"first-pubkey", first_pubkey);
    transcript.append_message(b"second-pubkey", second_pubkey);
    transcript.append_message(b"grouped-ciphertext", grouped_ciphertext);

    let mut rng = ChaCha20Rng::from_seed(seed);
    prove_grouped_2_direct(&mut transcript, &p1, &p2, &x, &r, &mut rng)
}

/// Core 2-handle validity prover on an open transcript
/// (mirrors `GroupedCiphertext2HandlesValidityProof::new_direct`): appends
/// the `validity-proof` dom-sep itself; caller hashes context first.
fn prove_grouped_2_direct(
    transcript: &mut ZkTranscript,
    p1: &RistrettoPoint,
    p2: &RistrettoPoint,
    x: &crate::curve::ed25519::Scalar,
    r: &crate::curve::ed25519::Scalar,
    rng: &mut ChaCha20Rng,
) -> SolanaZkResult<[u8; 160]> {
    let g = RistrettoPoint::generator();
    let h = h_point()?;
    transcript.grouped_validity_domain_separator(2);
    let y_r = masking_scalar(&mut *rng);
    let y_x = masking_scalar(&mut *rng);
    let y0 = h.mul(&y_r).add(&g.mul(&y_x));
    let y1 = p1.mul(&y_r);
    let y2 = p2.mul(&y_r);
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
    let z_r = c.mul(r).add(&y_r);
    let z_x = c.mul(x).add(&y_x);
    let mut zr_enc = [0u8; 32];
    let mut zx_enc = [0u8; 32];
    z_r.to_bytes_le(&mut zr_enc);
    z_x.to_bytes_le(&mut zx_enc);
    transcript.append_scalar(b"z_r", &zr_enc);
    transcript.append_scalar(b"z_x", &zx_enc);
    let _w = transcript.challenge_scalar(b"w");

    let mut out = [0u8; 160];
    out[..32].copy_from_slice(&y0_enc);
    out[32..64].copy_from_slice(&y1_enc);
    out[64..96].copy_from_slice(&y2_enc);
    out[96..128].copy_from_slice(&zr_enc);
    out[128..].copy_from_slice(&zx_enc);
    Ok(out)
}

/// Verify a 2-handle validity proof. Rejects identity first
/// pubkey or commitment; the second pubkey may be identity (auditor key).
#[allow(clippy::too_many_arguments)]
pub fn verify_grouped_validity_2(
    first_pubkey: &[u8; 32],
    second_pubkey: &[u8; 32],
    grouped_ciphertext: &[u8; 96],
    proof: &[u8; 160],
    context: &[u8],
) -> SolanaSigResult<()> {
    let p1 = decode_point(first_pubkey)?;
    let c = decode_point(&grouped_ciphertext[..32])?;
    if p1.ct_is_identity() == 1 || c.ct_is_identity() == 1 {
        return Err(SigmaError::IdentityPoint);
    }
    let p2 = decode_point(second_pubkey)?;
    let d1 = decode_point(&grouped_ciphertext[32..64])?;
    let d2 = decode_point(&grouped_ciphertext[64..])?;

    let mut transcript = ZkTranscript::new(context);
    transcript.append_message(b"first-pubkey", first_pubkey);
    transcript.append_message(b"second-pubkey", second_pubkey);
    transcript.append_message(b"grouped-ciphertext", grouped_ciphertext);

    verify_grouped_2_direct(&mut transcript, &p1, &p2, &c, &d1, &d2, proof)
}

/// Core 2-handle validity verifier on an open transcript
/// (mirrors `GroupedCiphertext2HandlesValidityProof::verify_direct`).
fn verify_grouped_2_direct(
    transcript: &mut ZkTranscript,
    p1: &RistrettoPoint,
    p2: &RistrettoPoint,
    commitment: &RistrettoPoint,
    handle1: &RistrettoPoint,
    handle2: &RistrettoPoint,
    proof: &[u8; 160],
) -> SolanaSigResult<()> {
    transcript.grouped_validity_domain_separator(2);

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
    // Y_2 may be identity when the second pubkey is the identity auditor key.
    transcript.append_point(b"Y_2", &y2_enc);
    let ch = transcript.challenge_scalar(b"c");
    let z_r = canonical_scalar(&proof[96..128])?;
    let z_x = canonical_scalar(&proof[128..])?;
    let mut zr_enc = [0u8; 32];
    let mut zx_enc = [0u8; 32];
    z_r.to_bytes_le(&mut zr_enc);
    z_x.to_bytes_le(&mut zx_enc);
    transcript.append_scalar(b"z_r", &zr_enc);
    transcript.append_scalar(b"z_x", &zx_enc);
    let w = transcript.challenge_scalar(b"w");
    let ww = w.mul(&w);

    let y0 = decode_point(&y0_enc)?;
    let y1 = decode_point(&y1_enc)?;
    let y2 = decode_point(&y2_enc)?;
    let g = RistrettoPoint::generator();
    let h = h_point().map_err(|_| SigmaError::Deserialization)?;
    // [z_r, z_x, -c, -1, w*z_r, -w*c, -w, ww*z_r, -ww*c, -ww]
    // over [H, G, C, Y_0, P1, D1, Y_1, P2, D2, Y_2]
    let check = h
        .mul(&z_r)
        .add(&g.mul(&z_x))
        .add(&commitment.mul(&ch.neg()))
        .add(&y0.neg())
        .add(&p1.mul(&w.mul(&z_r)))
        .add(&handle1.mul(&w.neg().mul(&ch)))
        .add(&y1.mul(&w.neg()))
        .add(&p2.mul(&ww.mul(&z_r)))
        .add(&handle2.mul(&ww.neg().mul(&ch)))
        .add(&y2.mul(&ww.neg()));
    if is_identity_enc(&check) {
        Ok(())
    } else {
        Err(SigmaError::AlgebraicRelation)
    }
}


/// Byte length of a batched 2-handle validity proof (same as
/// unbatched: one compressed `GroupedCiphertext2HandlesValidityProof`).
pub const BATCHED_GROUPED_VALIDITY_2_PROOF_LEN: usize = 160;

/// Byte length of a batched 3-handle validity proof.
pub const BATCHED_GROUPED_VALIDITY_3_PROOF_LEN: usize = 192;

/// Prove validity of two (commitment, handles) pairs at once
/// (mirrors `BatchedGroupedCiphertext2HandlesValidityProof::new`): hash lo/hi
/// context, `batched-validity-proof` dom-sep, batch amounts/openings with the
/// transcript challenge `t`, then the standard direct core.
#[allow(clippy::too_many_arguments)]
pub fn prove_batched_grouped_validity_2(
    first_pubkey: &[u8; 32],
    second_pubkey: &[u8; 32],
    grouped_lo: &[u8; 96],
    grouped_hi: &[u8; 96],
    amount_lo: u64,
    amount_hi: u64,
    opening_lo: &[u8; 32],
    opening_hi: &[u8; 32],
    seed: &[u8; 32],
    context: &[u8],
) -> SolanaZkResult<[u8; 160]> {
    let p1 = RistrettoPoint::from_bytes(first_pubkey)
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    let p2 = RistrettoPoint::from_bytes(second_pubkey)
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    let r_lo = crate::curve::ed25519::Scalar::from_bytes_le(opening_lo)
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    let r_hi = crate::curve::ed25519::Scalar::from_bytes_le(opening_hi)
        .map_err(|_| SolanaZkError::InvalidPoint)?;

    let mut transcript = ZkTranscript::new(context);
    transcript.append_message(b"first-pubkey", first_pubkey);
    transcript.append_message(b"second-pubkey", second_pubkey);
    transcript.append_message(b"grouped-ciphertext-lo", grouped_lo);
    transcript.append_message(b"grouped-ciphertext-hi", grouped_hi);
    transcript.batched_grouped_validity_domain_separator(2);
    let t = transcript.challenge_scalar(b"t");

    let x = amount_scalar(amount_lo).add(&amount_scalar(amount_hi).mul(&t));
    let r = r_lo.add(&r_hi.mul(&t));
    let mut rng = ChaCha20Rng::from_seed(seed);
    prove_grouped_2_direct(&mut transcript, &p1, &p2, &x, &r, &mut rng)
}

/// Verify a batched 2-handle validity proof: batch the lo/hi
/// commitments and handles with `t`, then the standard direct core. Rejects
/// identity first pubkey or either commitment.
#[allow(clippy::too_many_arguments)]
pub fn verify_batched_grouped_validity_2(
    first_pubkey: &[u8; 32],
    second_pubkey: &[u8; 32],
    grouped_lo: &[u8; 96],
    grouped_hi: &[u8; 96],
    proof: &[u8; 160],
    context: &[u8],
) -> SolanaSigResult<()> {
    let p1 = decode_point(first_pubkey)?;
    let p2 = decode_point(second_pubkey)?;
    let c_lo = decode_point(&grouped_lo[..32])?;
    let c_hi = decode_point(&grouped_hi[..32])?;
    if p1.ct_is_identity() == 1
        || c_lo.ct_is_identity() == 1
        || c_hi.ct_is_identity() == 1
    {
        return Err(SigmaError::IdentityPoint);
    }
    let d1_lo = decode_point(&grouped_lo[32..64])?;
    let d2_lo = decode_point(&grouped_lo[64..])?;
    let d1_hi = decode_point(&grouped_hi[32..64])?;
    let d2_hi = decode_point(&grouped_hi[64..])?;

    let mut transcript = ZkTranscript::new(context);
    transcript.append_message(b"first-pubkey", first_pubkey);
    transcript.append_message(b"second-pubkey", second_pubkey);
    transcript.append_message(b"grouped-ciphertext-lo", grouped_lo);
    transcript.append_message(b"grouped-ciphertext-hi", grouped_hi);
    transcript.batched_grouped_validity_domain_separator(2);
    let t = transcript.challenge_scalar(b"t");

    let c = c_lo.add(&c_hi.mul(&t));
    let d1 = d1_lo.add(&d1_hi.mul(&t));
    let d2 = d2_lo.add(&d2_hi.mul(&t));
    verify_grouped_2_direct(&mut transcript, &p1, &p2, &c, &d1, &d2, proof)
}

/// Prove validity of two 3-handle pairs at once (mirrors the
/// 3-handle batched constructor). Proof layout is the standard 192 bytes.
#[allow(clippy::too_many_arguments)]
pub fn prove_batched_grouped_validity_3(
    first_pubkey: &[u8; 32],
    second_pubkey: &[u8; 32],
    third_pubkey: &[u8; 32],
    grouped_lo: &[u8; 128],
    grouped_hi: &[u8; 128],
    amount_lo: u64,
    amount_hi: u64,
    opening_lo: &[u8; 32],
    opening_hi: &[u8; 32],
    seed: &[u8; 32],
    context: &[u8],
) -> SolanaZkResult<[u8; 192]> {
    let p1 = RistrettoPoint::from_bytes(first_pubkey)
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    let p2 = RistrettoPoint::from_bytes(second_pubkey)
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    let p3 = RistrettoPoint::from_bytes(third_pubkey)
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    let r_lo = crate::curve::ed25519::Scalar::from_bytes_le(opening_lo)
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    let r_hi = crate::curve::ed25519::Scalar::from_bytes_le(opening_hi)
        .map_err(|_| SolanaZkError::InvalidPoint)?;

    let mut transcript = ZkTranscript::new(context);
    transcript.append_message(b"first-pubkey", first_pubkey);
    transcript.append_message(b"second-pubkey", second_pubkey);
    transcript.append_message(b"third-pubkey", third_pubkey);
    transcript.append_message(b"grouped-ciphertext-lo", grouped_lo);
    transcript.append_message(b"grouped-ciphertext-hi", grouped_hi);
    transcript.batched_grouped_validity_domain_separator(3);
    let t = transcript.challenge_scalar(b"t");

    let x = amount_scalar(amount_lo).add(&amount_scalar(amount_hi).mul(&t));
    let r = r_lo.add(&r_hi.mul(&t));
    let mut rng = ChaCha20Rng::from_seed(seed);
    prove_grouped_3_direct(&mut transcript, &p1, &p2, &p3, &x, &r, &mut rng)
}

/// Verify a batched 3-handle validity proof. Rejects identity
/// first/second pubkey or either commitment.
#[allow(clippy::too_many_arguments)]
pub fn verify_batched_grouped_validity_3(
    first_pubkey: &[u8; 32],
    second_pubkey: &[u8; 32],
    third_pubkey: &[u8; 32],
    grouped_lo: &[u8; 128],
    grouped_hi: &[u8; 128],
    proof: &[u8; 192],
    context: &[u8],
) -> SolanaSigResult<()> {
    let p1 = decode_point(first_pubkey)?;
    let p2 = decode_point(second_pubkey)?;
    let p3 = decode_point(third_pubkey)?;
    let c_lo = decode_point(&grouped_lo[..32])?;
    let c_hi = decode_point(&grouped_hi[..32])?;
    if p1.ct_is_identity() == 1
        || p2.ct_is_identity() == 1
        || c_lo.ct_is_identity() == 1
        || c_hi.ct_is_identity() == 1
    {
        return Err(SigmaError::IdentityPoint);
    }
    let d1_lo = decode_point(&grouped_lo[32..64])?;
    let d2_lo = decode_point(&grouped_lo[64..96])?;
    let d3_lo = decode_point(&grouped_lo[96..])?;
    let d1_hi = decode_point(&grouped_hi[32..64])?;
    let d2_hi = decode_point(&grouped_hi[64..96])?;
    let d3_hi = decode_point(&grouped_hi[96..])?;

    let mut transcript = ZkTranscript::new(context);
    transcript.append_message(b"first-pubkey", first_pubkey);
    transcript.append_message(b"second-pubkey", second_pubkey);
    transcript.append_message(b"third-pubkey", third_pubkey);
    transcript.append_message(b"grouped-ciphertext-lo", grouped_lo);
    transcript.append_message(b"grouped-ciphertext-hi", grouped_hi);
    transcript.batched_grouped_validity_domain_separator(3);
    let t = transcript.challenge_scalar(b"t");

    let c = c_lo.add(&c_hi.mul(&t));
    let d1 = d1_lo.add(&d1_hi.mul(&t));
    let d2 = d2_lo.add(&d2_hi.mul(&t));
    let d3 = d3_lo.add(&d3_hi.mul(&t));
    verify_grouped_3_direct(
        &mut transcript,
        &p1,
        &p2,
        &p3,
        &c,
        &d1,
        &d2,
        &d3,
        proof,
    )
}


#[cfg(test)]
mod tests_batched {
    use super::*;

    /// Upstream golden vector, batched 2-handle (`Test`).
    #[test]
    fn golden_batched_2_verifies() {
        let first_pubkey: [u8; 32] = [
        114, 249, 47, 30, 121, 107, 234, 31, 21, 245, 93, 80,
        218, 97, 163, 231, 229, 199, 233, 32, 111, 37, 20, 119,
        116, 199, 67, 98, 216, 39, 167, 9,
        ];
        let second_pubkey: [u8; 32] = [
        122, 247, 35, 47, 15, 62, 191, 105, 156, 89, 24, 172,
        8, 34, 151, 110, 53, 149, 53, 27, 2, 208, 155, 159,
        58, 132, 149, 229, 196, 125, 139, 24,
        ];
        let grouped_lo: [u8; 96] = [
        50, 201, 229, 83, 123, 61, 98, 53, 133, 104, 45, 200,
        140, 130, 146, 231, 108, 165, 227, 85, 245, 196, 127, 166,
        173, 237, 1, 108, 12, 4, 218, 61, 196, 219, 204, 35,
        89, 3, 217, 159, 128, 120, 156, 207, 158, 87, 76, 224,
        138, 17, 234, 238, 229, 18, 99, 158, 218, 226, 94, 54,
        28, 148, 84, 44, 128, 101, 9, 31, 252, 27, 101, 159,
        186, 174, 183, 89, 86, 193, 174, 140, 102, 69, 182, 201,
        205, 145, 70, 129, 218, 70, 84, 186, 5, 3, 192, 48,
        ];
        let grouped_hi: [u8; 96] = [
        218, 74, 115, 76, 166, 142, 162, 35, 76, 255, 54, 98,
        154, 223, 96, 230, 229, 250, 208, 97, 66, 122, 205, 249,
        230, 83, 56, 75, 100, 47, 91, 30, 58, 96, 202, 110,
        25, 106, 20, 230, 1, 185, 27, 216, 104, 10, 230, 57,
        79, 211, 240, 25, 56, 136, 65, 171, 33, 127, 169, 148,
        22, 235, 165, 61, 106, 244, 17, 130, 154, 181, 30, 208,
        241, 215, 242, 120, 90, 73, 151, 106, 93, 103, 98, 38,
        194, 103, 249, 44, 58, 131, 81, 116, 173, 245, 152, 55,
        ];
        let proof: [u8; 160] = [
        26, 165, 113, 75, 123, 8, 73, 223, 97, 195, 122, 244,
        140, 60, 119, 171, 3, 69, 2, 178, 233, 137, 115, 28,
        201, 43, 237, 66, 171, 185, 61, 33, 168, 100, 52, 237,
        70, 5, 204, 14, 36, 132, 61, 36, 104, 76, 68, 123,
        254, 152, 200, 255, 61, 134, 243, 35, 86, 96, 19, 18,
        232, 77, 188, 83, 202, 231, 84, 32, 18, 234, 77, 74,
        241, 169, 219, 173, 49, 120, 159, 180, 209, 152, 6, 156,
        224, 39, 105, 40, 40, 124, 1, 147, 243, 190, 46, 52,
        146, 149, 172, 146, 93, 180, 22, 136, 42, 241, 99, 213,
        127, 90, 246, 139, 169, 222, 177, 1, 147, 172, 203, 10,
        92, 126, 99, 237, 40, 66, 241, 6, 91, 62, 212, 231,
        243, 191, 30, 77, 208, 123, 43, 208, 205, 88, 92, 70,
        178, 28, 75, 240, 172, 204, 135, 71, 75, 50, 88, 251,
        32, 2, 103, 2,
        ];
        verify_batched_grouped_validity_2(
            &first_pubkey,
            &second_pubkey,
            &grouped_lo,
            &grouped_hi,
            &proof,
            b"Test",
        )
        .unwrap();
    }

    /// Batched 2-handle roundtrip; tampered hi fails.
    #[test]
    fn roundtrip_batched_2() {
        let pks = [[2u8; 32], [4u8; 32]];
        let pubs = [
            crate::solana_zk::elgamal_pubkey_from_secret(&pks[0]).unwrap(),
            crate::solana_zk::elgamal_pubkey_from_secret(&pks[1]).unwrap(),
        ];
        let (o_lo, o_hi) = ([6u8; 32], [8u8; 32]);
        let (a_lo, a_hi) = (55u64, 77u64);
        let g = RistrettoPoint::generator();
        let h = crate::solana_zk::h_point().unwrap();
        let comm = |a: u64, o: &[u8; 32]| {
            let r = crate::curve::ed25519::Scalar::from_bytes_le(o).unwrap();
            let mut c = [0u8; 32];
            g.mul(&crate::solana_zk::amount_scalar(a))
                .add(&h.mul(&r))
                .to_bytes_compressed(&mut c)
                .unwrap();
            c
        };
        let mk_grouped = |a: u64, o: &[u8; 32]| {
            let c = comm(a, o);
            let d1 =
                crate::solana_zk::elgamal_encrypt_with(&pubs[0], a, o).unwrap();
            let d2 =
                crate::solana_zk::elgamal_encrypt_with(&pubs[1], a, o).unwrap();
            let mut gr = [0u8; 96];
            gr[..32].copy_from_slice(&c);
            gr[32..64].copy_from_slice(&d1[32..]);
            gr[64..].copy_from_slice(&d2[32..]);
            gr
        };
        let lo = mk_grouped(a_lo, &o_lo);
        let hi = mk_grouped(a_hi, &o_hi);
        let proof = prove_batched_grouped_validity_2(
            &pubs[0], &pubs[1], &lo, &hi, a_lo, a_hi, &o_lo, &o_hi,
            &[9u8; 32], b"Test",
        )
        .unwrap();
        verify_batched_grouped_validity_2(
            &pubs[0], &pubs[1], &lo, &hi, &proof, b"Test",
        )
        .unwrap();
        let mut bad = hi;
        bad[0] ^= 1;
        assert!(verify_batched_grouped_validity_2(
            &pubs[0], &pubs[1], &lo, &bad, &proof, b"Test",
        )
        .is_err());
    }

    /// Upstream golden vector, batched 3-handle (`Test`).
    #[test]
    fn golden_batched_3_verifies() {
        let first_pubkey: [u8; 32] = [
        154, 255, 248, 161, 38, 242, 220, 247, 211, 16, 111, 96,
        27, 132, 131, 14, 89, 13, 221, 189, 24, 78, 155, 178,
        141, 213, 253, 251, 141, 5, 41, 6,
        ];
        let second_pubkey: [u8; 32] = [
        132, 247, 161, 53, 109, 240, 35, 150, 29, 43, 150, 248,
        201, 226, 12, 250, 223, 115, 75, 154, 1, 180, 98, 11,
        46, 41, 109, 21, 75, 162, 213, 64,
        ];
        let third_pubkey: [u8; 32] = [
        134, 80, 2, 10, 201, 149, 37, 82, 25, 197, 173, 185,
        170, 146, 155, 140, 19, 181, 215, 8, 63, 77, 219, 92,
        207, 222, 120, 58, 209, 206, 89, 92,
        ];
        let grouped_lo: [u8; 128] = [
        146, 194, 160, 232, 165, 204, 4, 15, 98, 21, 40, 127,
        60, 202, 149, 246, 77, 55, 0, 108, 249, 122, 40, 44,
        155, 111, 147, 79, 164, 89, 166, 88, 54, 28, 33, 49,
        177, 18, 73, 64, 42, 71, 108, 43, 190, 105, 190, 218,
        143, 152, 76, 17, 104, 77, 46, 137, 10, 7, 100, 182,
        184, 75, 39, 16, 94, 240, 232, 122, 226, 55, 223, 127,
        250, 242, 155, 144, 104, 59, 235, 93, 221, 219, 228, 243,
        95, 200, 49, 141, 224, 186, 110, 134, 86, 180, 97, 66,
        168, 125, 52, 37, 116, 175, 109, 146, 35, 110, 243, 143,
        125, 248, 70, 203, 246, 59, 187, 252, 225, 214, 191, 154,
        120, 57, 174, 65, 23, 123, 190, 99,
        ];
        let grouped_hi: [u8; 128] = [
        12, 195, 65, 58, 176, 192, 106, 103, 231, 182, 134, 205,
        164, 173, 68, 92, 159, 221, 72, 14, 56, 66, 104, 92,
        228, 71, 149, 113, 148, 243, 254, 4, 14, 159, 19, 184,
        25, 132, 82, 165, 232, 174, 236, 140, 46, 140, 3, 207,
        106, 89, 238, 105, 105, 16, 98, 92, 223, 75, 198, 251,
        244, 231, 205, 37, 24, 26, 156, 150, 88, 85, 8, 56,
        105, 77, 148, 151, 227, 163, 42, 177, 19, 41, 216, 66,
        163, 178, 183, 168, 88, 76, 160, 152, 153, 24, 145, 74,
        156, 114, 197, 8, 108, 131, 176, 35, 242, 189, 205, 133,
        66, 138, 113, 141, 182, 131, 142, 181, 108, 152, 52, 204,
        16, 147, 210, 182, 150, 89, 0, 127,
        ];
        let proof: [u8; 192] = [
        180, 14, 30, 57, 99, 133, 20, 161, 121, 210, 30, 111,
        16, 101, 29, 135, 188, 231, 100, 53, 118, 41, 143, 207,
        36, 223, 26, 22, 202, 173, 201, 91, 142, 188, 122, 9,
        65, 60, 177, 48, 15, 31, 212, 244, 216, 107, 127, 107,
        78, 72, 149, 17, 140, 247, 175, 103, 149, 224, 75, 60,
        130, 240, 204, 92, 38, 93, 66, 132, 156, 254, 97, 196,
        229, 11, 15, 45, 61, 54, 2, 186, 83, 74, 193, 104,
        103, 92, 248, 19, 208, 217, 59, 18, 46, 162, 164, 57,
        16, 23, 56, 103, 47, 219, 174, 77, 141, 89, 186, 73,
        185, 174, 5, 180, 244, 1, 237, 242, 199, 88, 132, 191,
        98, 2, 187, 191, 175, 220, 42, 82, 161, 207, 174, 34,
        200, 167, 153, 198, 99, 69, 42, 45, 118, 107, 7, 121,
        179, 219, 209, 24, 49, 153, 190, 253, 34, 158, 129, 126,
        66, 138, 160, 4, 30, 79, 69, 48, 145, 247, 125, 255,
        175, 143, 128, 150, 76, 119, 227, 74, 5, 77, 9, 217,
        27, 177, 192, 4, 110, 40, 173, 173, 226, 208, 172, 10,
        ];
        verify_batched_grouped_validity_3(
            &first_pubkey,
            &second_pubkey,
            &third_pubkey,
            &grouped_lo,
            &grouped_hi,
            &proof,
            b"Test",
        )
        .unwrap();
    }

    /// Batched 3-handle roundtrip; tampered hi fails.
    #[test]
    fn roundtrip_batched_3() {
        let pks = [[2u8; 32], [4u8; 32], [6u8; 32]];
        let pubs = [
            crate::solana_zk::elgamal_pubkey_from_secret(&pks[0]).unwrap(),
            crate::solana_zk::elgamal_pubkey_from_secret(&pks[1]).unwrap(),
            crate::solana_zk::elgamal_pubkey_from_secret(&pks[2]).unwrap(),
        ];
        let (o_lo, o_hi) = ([6u8; 32], [8u8; 32]);
        let (a_lo, a_hi) = (55u64, 77u64);
        let g = RistrettoPoint::generator();
        let h = crate::solana_zk::h_point().unwrap();
        let comm = |a: u64, o: &[u8; 32]| {
            let r = crate::curve::ed25519::Scalar::from_bytes_le(o).unwrap();
            let mut c = [0u8; 32];
            g.mul(&crate::solana_zk::amount_scalar(a))
                .add(&h.mul(&r))
                .to_bytes_compressed(&mut c)
                .unwrap();
            c
        };
        let mk_grouped = |a: u64, o: &[u8; 32]| {
            let c = comm(a, o);
            let ds = [
                crate::solana_zk::elgamal_encrypt_with(&pubs[0], a, o).unwrap(),
                crate::solana_zk::elgamal_encrypt_with(&pubs[1], a, o).unwrap(),
                crate::solana_zk::elgamal_encrypt_with(&pubs[2], a, o).unwrap(),
            ];
            let mut gr = [0u8; 128];
            gr[..32].copy_from_slice(&c);
            gr[32..64].copy_from_slice(&ds[0][32..]);
            gr[64..96].copy_from_slice(&ds[1][32..]);
            gr[96..].copy_from_slice(&ds[2][32..]);
            gr
        };
        let lo = mk_grouped(a_lo, &o_lo);
        let hi = mk_grouped(a_hi, &o_hi);
        let proof = prove_batched_grouped_validity_3(
            &pubs[0], &pubs[1], &pubs[2], &lo, &hi, a_lo, a_hi, &o_lo, &o_hi,
            &[9u8; 32], b"Test",
        )
        .unwrap();
        verify_batched_grouped_validity_3(
            &pubs[0], &pubs[1], &pubs[2], &lo, &hi, &proof, b"Test",
        )
        .unwrap();
        let mut bad = hi;
        bad[0] ^= 1;
        assert!(verify_batched_grouped_validity_3(
            &pubs[0], &pubs[1], &pubs[2], &lo, &bad, &proof, b"Test",
        )
        .is_err());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Upstream golden vector (`Test` context).
    #[test]
    fn golden_vector_verifies() {
        let first_pubkey: [u8; 32] = [
            130, 211, 113, 18, 142, 5, 61, 152, 31, 148, 80, 77, 36, 254, 91,
            31, 152, 252, 148, 210, 10, 203, 107, 82, 116, 199, 54, 54, 1, 253,
            252, 97,
        ];
        let second_pubkey: [u8; 32] = [
            218, 125, 80, 55, 109, 79, 245, 39, 45, 217, 82, 200, 61, 147, 231,
            50, 178, 154, 104, 233, 55, 216, 120, 9, 179, 0, 82, 174, 116, 191,
            255, 103,
        ];
        let grouped_ciphertext: [u8; 96] = [
            100, 28, 53, 8, 101, 18, 79, 15, 135, 80, 195, 179, 230, 70, 95,
            185, 218, 239, 164, 13, 58, 69, 21, 217, 222, 189, 69, 109, 185,
            125, 91, 99, 96, 163, 8, 204, 251, 74, 87, 24, 53, 247, 163, 237,
            121, 98, 51, 14, 117, 130, 204, 164, 4, 242, 69, 83, 128, 159, 251,
            111, 86, 44, 167, 116, 70, 114, 224, 22, 14, 232, 255, 96, 43, 123,
            39, 8, 53, 65, 169, 82, 214, 123, 115, 97, 165, 138, 153, 56, 56,
            178, 208, 172, 156, 68, 186, 53,
        ];
        let proof: [u8; 160] = [
            208, 171, 157, 170, 9, 104, 71, 66, 30, 146, 65, 102, 132, 52, 243,
            235, 121, 48, 182, 167, 156, 77, 81, 12, 102, 217, 155, 214, 170,
            238, 1, 27, 170, 170, 72, 185, 2, 56, 25, 163, 33, 242, 234, 162,
            70, 220, 11, 160, 59, 133, 43, 240, 3, 250, 255, 132, 91, 31, 225,
            9, 19, 16, 51, 52, 162, 98, 157, 192, 216, 101, 76, 94, 213, 81, 89,
            70, 9, 131, 226, 148, 103, 125, 140, 246, 52, 74, 153, 221, 136,
            179, 96, 45, 205, 67, 78, 117, 138, 47, 117, 59, 81, 113, 67, 54,
            31, 92, 232, 236, 157, 9, 120, 170, 251, 100, 102, 163, 58, 115,
            168, 25, 51, 21, 173, 86, 105, 76, 36, 11, 174, 221, 187, 142, 55,
            37, 14, 179, 32, 199, 19, 29, 32, 92, 21, 147, 55, 152, 111, 252,
            43, 210, 102, 40, 251, 163, 7, 207, 157, 157, 250, 8,
        ];
        verify_grouped_validity_2(
            &first_pubkey,
            &second_pubkey,
            &grouped_ciphertext,
            &proof,
            b"Test",
        )
        .unwrap();
    }

    /// Roundtrip on matching opening; wrong amount fails.
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
        let g = RistrettoPoint::generator();
        let h = crate::solana_zk::h_point().unwrap();
        let r = crate::curve::ed25519::Scalar::from_bytes_le(&opening).unwrap();
        let mut commitment = [0u8; 32];
        g.mul(&crate::solana_zk::amount_scalar(amount))
            .add(&h.mul(&r))
            .to_bytes_compressed(&mut commitment)
            .unwrap();
        let (d1, d2) = (
            crate::solana_zk::elgamal_encrypt_with(&first_pubkey, amount, &opening)
                .unwrap(),
            crate::solana_zk::elgamal_encrypt_with(&second_pubkey, amount, &opening)
                .unwrap(),
        );
        let mut grouped = [0u8; 96];
        grouped[..32].copy_from_slice(&commitment);
        grouped[32..64].copy_from_slice(&d1[32..]);
        grouped[64..].copy_from_slice(&d2[32..]);
        let proof = prove_grouped_validity_2(
            &first_pubkey,
            &second_pubkey,
            &grouped,
            amount,
            &opening,
            &[8u8; 32],
            b"Test",
        )
        .unwrap();
        verify_grouped_validity_2(
            &first_pubkey,
            &second_pubkey,
            &grouped,
            &proof,
            b"Test",
        )
        .unwrap();
        // Wrong commitment must fail.
        let mut bad = grouped;
        bad[0] ^= 1;
        assert!(
            verify_grouped_validity_2(
                &first_pubkey,
                &second_pubkey,
                &bad,
                &proof,
                b"Test"
            )
            .is_err()
        );
    }
}

/// Byte length of a 3-handle validity proof.
pub const GROUPED_VALIDITY_3_PROOF_LEN: usize = 192;

/// Prove `commitment` (Pedersen `m`, opening `r`) decrypts
/// under three pubkeys. `grouped_ciphertext` is `commitment || h1 || h2 || h3`
/// (128 bytes), transcript-only.
#[allow(clippy::too_many_arguments)]
pub fn prove_grouped_validity_3(
    first_pubkey: &[u8; 32],
    second_pubkey: &[u8; 32],
    third_pubkey: &[u8; 32],
    grouped_ciphertext: &[u8; 128],
    amount: u64,
    opening: &[u8; 32],
    seed: &[u8; 32],
    context: &[u8],
) -> SolanaZkResult<[u8; 192]> {
    let p1 = RistrettoPoint::from_bytes(first_pubkey)
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    let p2 = RistrettoPoint::from_bytes(second_pubkey)
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    let p3 = RistrettoPoint::from_bytes(third_pubkey)
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    let r = crate::curve::ed25519::Scalar::from_bytes_le(opening)
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    let x = amount_scalar(amount);
    let _g = RistrettoPoint::generator();
    let _h = h_point()?;

    let mut transcript = ZkTranscript::new(context);
    transcript.append_message(b"first-pubkey", first_pubkey);
    transcript.append_message(b"second-pubkey", second_pubkey);
    transcript.append_message(b"third-pubkey", third_pubkey);
    transcript.append_message(b"grouped-ciphertext", grouped_ciphertext);

    let mut rng = ChaCha20Rng::from_seed(seed);
    prove_grouped_3_direct(&mut transcript, &p1, &p2, &p3, &x, &r, &mut rng)
}

/// Core 3-handle validity prover on an open transcript
/// (mirrors `GroupedCiphertext3HandlesValidityProof::new_direct`).
fn prove_grouped_3_direct(
    transcript: &mut ZkTranscript,
    p1: &RistrettoPoint,
    p2: &RistrettoPoint,
    p3: &RistrettoPoint,
    x: &crate::curve::ed25519::Scalar,
    r: &crate::curve::ed25519::Scalar,
    rng: &mut ChaCha20Rng,
) -> SolanaZkResult<[u8; 192]> {
    let g = RistrettoPoint::generator();
    let h = h_point()?;
    transcript.grouped_validity_domain_separator(3);
    let y_r = masking_scalar(&mut *rng);
    let y_x = masking_scalar(&mut *rng);
    let y0 = h.mul(&y_r).add(&g.mul(&y_x));
    let y1 = p1.mul(&y_r);
    let y2 = p2.mul(&y_r);
    let y3 = p3.mul(&y_r);
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
    let z_r = c.mul(r).add(&y_r);
    let z_x = c.mul(x).add(&y_x);
    let mut zr_enc = [0u8; 32];
    let mut zx_enc = [0u8; 32];
    z_r.to_bytes_le(&mut zr_enc);
    z_x.to_bytes_le(&mut zx_enc);
    transcript.append_scalar(b"z_r", &zr_enc);
    transcript.append_scalar(b"z_x", &zx_enc);
    let _w = transcript.challenge_scalar(b"w");

    let mut out = [0u8; 192];
    out[..32].copy_from_slice(&y0_enc);
    out[32..64].copy_from_slice(&y1_enc);
    out[64..96].copy_from_slice(&y2_enc);
    out[96..128].copy_from_slice(&y3_enc);
    out[128..160].copy_from_slice(&zr_enc);
    out[160..].copy_from_slice(&zx_enc);
    Ok(out)
}

/// Verify a 3-handle validity proof. Rejects identity first /
/// second pubkey or commitment; the third pubkey may be identity (auditor).
#[allow(clippy::too_many_arguments)]
pub fn verify_grouped_validity_3(
    first_pubkey: &[u8; 32],
    second_pubkey: &[u8; 32],
    third_pubkey: &[u8; 32],
    grouped_ciphertext: &[u8; 128],
    proof: &[u8; 192],
    context: &[u8],
) -> SolanaSigResult<()> {
    let p1 = decode_point(first_pubkey)?;
    let p2 = decode_point(second_pubkey)?;
    let c = decode_point(&grouped_ciphertext[..32])?;
    if p1.ct_is_identity() == 1
        || p2.ct_is_identity() == 1
        || c.ct_is_identity() == 1
    {
        return Err(SigmaError::IdentityPoint);
    }
    let p3 = decode_point(third_pubkey)?;
    let d1 = decode_point(&grouped_ciphertext[32..64])?;
    let d2 = decode_point(&grouped_ciphertext[64..96])?;
    let d3 = decode_point(&grouped_ciphertext[96..])?;

    let mut transcript = ZkTranscript::new(context);
    transcript.append_message(b"first-pubkey", first_pubkey);
    transcript.append_message(b"second-pubkey", second_pubkey);
    transcript.append_message(b"third-pubkey", third_pubkey);
    transcript.append_message(b"grouped-ciphertext", grouped_ciphertext);

    verify_grouped_3_direct(&mut transcript, &p1, &p2, &p3, &c, &d1, &d2, &d3, proof)
}

/// Core 3-handle validity verifier on an open transcript
/// (mirrors `GroupedCiphertext3HandlesValidityProof::verify_direct`).
// Nine-point parameter list mirrors the upstream verifier signature; splitting
// it would diverge from the ported API, so the arity lint is allowed.
#[allow(clippy::too_many_arguments)]
fn verify_grouped_3_direct(
    transcript: &mut ZkTranscript,
    p1: &RistrettoPoint,
    p2: &RistrettoPoint,
    p3: &RistrettoPoint,
    commitment: &RistrettoPoint,
    handle1: &RistrettoPoint,
    handle2: &RistrettoPoint,
    handle3: &RistrettoPoint,
    proof: &[u8; 192],
) -> SolanaSigResult<()> {
    transcript.grouped_validity_domain_separator(3);

    macro_rules! yenc3 {
        ($lo:expr, $label:expr) => {{
            let y: [u8; 32] = proof[$lo..$lo + 32]
                .try_into()
                .map_err(|_| SigmaError::Deserialization)?;
            transcript.validate_and_append_point($label, &y)?;
            y
        }};
    }
    let y0_enc = yenc3!(0, b"Y_0");
    let y1_enc = yenc3!(32, b"Y_1");
    let y2_enc = yenc3!(64, b"Y_2");
    // Y_3 may be identity when the third pubkey is the identity auditor key.
    let y3_enc: [u8; 32] = proof[96..128]
        .try_into()
        .map_err(|_| SigmaError::Deserialization)?;
    transcript.append_point(b"Y_3", &y3_enc);
    let ch = transcript.challenge_scalar(b"c");
    let z_r = canonical_scalar(&proof[128..160])?;
    let z_x = canonical_scalar(&proof[160..])?;
    let mut zr_enc = [0u8; 32];
    let mut zx_enc = [0u8; 32];
    z_r.to_bytes_le(&mut zr_enc);
    z_x.to_bytes_le(&mut zx_enc);
    transcript.append_scalar(b"z_r", &zr_enc);
    transcript.append_scalar(b"z_x", &zx_enc);
    let w = transcript.challenge_scalar(b"w");
    let ww = w.mul(&w);
    let www = w.mul(&ww);

    let y0 = decode_point(&y0_enc)?;
    let y1 = decode_point(&y1_enc)?;
    let y2 = decode_point(&y2_enc)?;
    let y3 = decode_point(&y3_enc)?;
    let g = RistrettoPoint::generator();
    let h = h_point().map_err(|_| SigmaError::Deserialization)?;
    // [z_r, z_x, -c, -1, w*z_r, -w*c, -w, ww*z_r, -ww*c, -ww,
    //  www*z_r, -www*c, -www]
    // over [H, G, C, Y_0, P1, D1, Y_1, P2, D2, Y_2, P3, D3, Y_3]
    let check = h
        .mul(&z_r)
        .add(&g.mul(&z_x))
        .add(&commitment.mul(&ch.neg()))
        .add(&y0.neg())
        .add(&p1.mul(&w.mul(&z_r)))
        .add(&handle1.mul(&w.neg().mul(&ch)))
        .add(&y1.mul(&w.neg()))
        .add(&p2.mul(&ww.mul(&z_r)))
        .add(&handle2.mul(&ww.neg().mul(&ch)))
        .add(&y2.mul(&ww.neg()))
        .add(&p3.mul(&www.mul(&z_r)))
        .add(&handle3.mul(&www.neg().mul(&ch)))
        .add(&y3.mul(&www.neg()));
    if is_identity_enc(&check) {
        Ok(())
    } else {
        Err(SigmaError::AlgebraicRelation)
    }
}

#[cfg(test)]
mod tests3 {
    use super::*;

    /// Upstream golden vector (`Test` context).
    #[test]
    fn golden_vector_verifies_3() {
        let first_pubkey: [u8; 32] = [
            16, 6, 199, 122, 88, 219, 243, 214, 132, 189, 188, 90, 171, 104,
            183, 79, 199, 187, 144, 72, 117, 137, 150, 185, 228, 110, 187, 75,
            134, 143, 55, 101,
        ];
        let second_pubkey: [u8; 32] = [
            148, 125, 189, 212, 93, 69, 192, 52, 4, 22, 173, 228, 200, 33, 16,
            236, 3, 64, 8, 10, 18, 250, 219, 97, 176, 34, 193, 68, 195, 10,
            188, 42,
        ];
        let third_pubkey: [u8; 32] = [
            18, 230, 149, 104, 253, 218, 233, 139, 211, 162, 71, 60, 118, 174,
            164, 41, 57, 231, 245, 204, 252, 3, 221, 167, 48, 132, 166, 15, 53,
            132, 148, 106,
        ];
        let grouped_ciphertext: [u8; 128] = [
            6, 155, 204, 218, 20, 80, 131, 220, 74, 168, 64, 186, 241, 152,
            220, 238, 59, 85, 43, 39, 217, 230, 24, 133, 248, 24, 5, 211, 227,
            231, 207, 80, 136, 251, 249, 87, 242, 46, 241, 128, 23, 163, 175,
            211, 190, 134, 186, 202, 88, 10, 38, 52, 46, 153, 191, 147, 60, 7,
            227, 20, 162, 76, 64, 10, 82, 235, 179, 236, 225, 114, 110, 83,
            118, 146, 219, 190, 213, 44, 51, 243, 211, 41, 83, 74, 135, 125,
            15, 68, 100, 138, 175, 93, 158, 235, 145, 9, 228, 72, 50, 52, 237,
            133, 142, 50, 203, 226, 141, 163, 72, 151, 169, 110, 179, 168, 134,
            69, 21, 90, 136, 234, 76, 100, 56, 157, 144, 33, 181, 82,
        ];
        let proof: [u8; 192] = [
        200, 2, 97, 182, 162, 79, 133, 119, 84, 55, 110, 37, 97, 224, 251,
        39, 233, 251, 255, 161, 126, 105, 95, 135, 210, 176, 82, 177, 225, 239,
        15, 87, 68, 175, 97, 86, 203, 214, 229, 219, 68, 31, 228, 77, 194,
        28, 15, 8, 150, 243, 179, 65, 10, 76, 38, 38, 124, 7, 219, 49,
        134, 161, 157, 14, 12, 21, 53, 184, 79, 132, 198, 138, 146, 196, 106,
        51, 34, 171, 30, 173, 149, 166, 45, 212, 207, 194, 193, 235, 251, 130,
        64, 215, 24, 200, 176, 76, 148, 40, 224, 86, 155, 28, 190, 231, 106,
        164, 187, 136, 166, 77, 207, 69, 88, 66, 230, 40, 13, 5, 95, 70,
        72, 190, 162, 92, 160, 46, 134, 69, 156, 218, 230, 194, 118, 86, 74,
        92, 147, 53, 196, 80, 39, 77, 185, 249, 69, 42, 17, 153, 42, 39,
        17, 32, 107, 224, 208, 112, 140, 124, 154, 8, 115, 48, 95, 181, 188,
        250, 56, 241, 5, 205, 225, 13, 34, 78, 168, 163, 100, 102, 12, 166,
        210, 9, 150, 191, 174, 28, 115, 125, 176, 41, 81, 0,
    ];
        verify_grouped_validity_3(
            &first_pubkey,
            &second_pubkey,
            &third_pubkey,
            &grouped_ciphertext,
            &proof,
            b"Test",
        )
        .unwrap();
    }

    /// Roundtrip on matching opening; wrong amount fails.
    #[test]
    fn roundtrip_and_mismatch_3() {
        let pks: [[u8; 32]; 3] = [[2u8; 32], [4u8; 32], [6u8; 32]];
        let pubs = [
            crate::solana_zk::elgamal_pubkey_from_secret(&pks[0]).unwrap(),
            crate::solana_zk::elgamal_pubkey_from_secret(&pks[1]).unwrap(),
            crate::solana_zk::elgamal_pubkey_from_secret(&pks[2]).unwrap(),
        ];
        let opening = [8u8; 32];
        let amount = 55u64;
        let g = RistrettoPoint::generator();
        let h = crate::solana_zk::h_point().unwrap();
        let r = crate::curve::ed25519::Scalar::from_bytes_le(&opening).unwrap();
        let mut commitment = [0u8; 32];
        g.mul(&crate::solana_zk::amount_scalar(amount))
            .add(&h.mul(&r))
            .to_bytes_compressed(&mut commitment)
            .unwrap();
        let cts = [
            crate::solana_zk::elgamal_encrypt_with(&pubs[0], amount, &opening)
                .unwrap(),
            crate::solana_zk::elgamal_encrypt_with(&pubs[1], amount, &opening)
                .unwrap(),
            crate::solana_zk::elgamal_encrypt_with(&pubs[2], amount, &opening)
                .unwrap(),
        ];
        let mut grouped = [0u8; 128];
        grouped[..32].copy_from_slice(&commitment);
        grouped[32..64].copy_from_slice(&cts[0][32..]);
        grouped[64..96].copy_from_slice(&cts[1][32..]);
        grouped[96..].copy_from_slice(&cts[2][32..]);
        let proof = prove_grouped_validity_3(
            &pubs[0],
            &pubs[1],
            &pubs[2],
            &grouped,
            amount,
            &opening,
            &[9u8; 32],
            b"Test",
        )
        .unwrap();
        verify_grouped_validity_3(
            &pubs[0],
            &pubs[1],
            &pubs[2],
            &grouped,
            &proof,
            b"Test",
        )
        .unwrap();
        // Wrong commitment must fail (handles alone do not bind the amount).
        let mut bad_grouped = grouped;
        bad_grouped[0] ^= 1;
        assert!(
            verify_grouped_validity_3(
                &pubs[0],
                &pubs[1],
                &pubs[2],
                &bad_grouped,
                &proof,
                b"Test"
            )
            .is_err()
        );
    }
}
