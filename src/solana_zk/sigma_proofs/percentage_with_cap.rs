//! Percentage-with-cap Sigma proof (zero-dep port).
//!
//! /// Byte-compatible port of
//! `zk-sdk/src/sigma_proofs/percentage_with_cap.rs`: OR-composition proving a
//! fee commitment is either capped at `max_value` or equals the computed
//! percentage (delta == claimed). Transcript labels and 256-byte layout
//! (`Y_max || z_max || c_max || Y_delta || Y_claimed || z_x || z_delta ||
//! z_claimed`) match upstream exactly. Randomness from a caller-supplied
//! 32-byte seed driving ChaCha20 (both OR branches always execute, then the
//! true branch is selected — same work profile as upstream).

use crate::solana_zk::sigma_proofs::{
    canonical_scalar, decode_point, is_identity_enc, SigmaError, SolanaSigResult,
    ZkTranscript,
};
use crate::solana_zk::{amount_scalar, h_point, SolanaZkError, SolanaZkResult};
use crate::curve::traits::CurvePoint;
use crate::curve::RistrettoPoint;
use crate::rng::ChaCha20Rng;

/// Byte length of a percentage-with-cap proof.
pub const PERCENTAGE_WITH_CAP_PROOF_LEN: usize = 256;

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

/// Prove the fee relation for (`percentage`, `delta`,
/// `claimed`) commitments with cap `max_value`. All amounts/openings are
/// caller-provided (the fee equation itself is built caller-side).
#[allow(clippy::too_many_arguments)]
pub fn prove_percentage_with_cap(
    percentage_commitment: &[u8; 32],
    percentage_opening: &[u8; 32],
    percentage_amount: u64,
    delta_commitment: &[u8; 32],
    delta_opening: &[u8; 32],
    delta_amount: u64,
    claimed_commitment: &[u8; 32],
    claimed_opening: &[u8; 32],
    max_value: u64,
    seed: &[u8; 32],
    context: &[u8],
) -> SolanaZkResult<[u8; 256]> {
    let _r_pct = crate::curve::ed25519::Scalar::from_bytes_le(percentage_opening)
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    let _r_delta = crate::curve::ed25519::Scalar::from_bytes_le(delta_opening)
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    let _r_claimed = crate::curve::ed25519::Scalar::from_bytes_le(claimed_opening)
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    // Commitments are decoded (and validated) in the transcript prefix
    // implicitly via context bytes; explicit decode checks happen in verify.
    let _ = (percentage_commitment, delta_commitment, claimed_commitment);

    let mut base = ZkTranscript::new(context);
    base.append_message(b"percentage-commitment", percentage_commitment);
    base.append_message(b"delta-commitment", delta_commitment);
    base.append_message(b"claimed-commitment", claimed_commitment);
    base.append_u64(b"max-value", max_value);
    base.percentage_with_cap_domain_separator();

    let mut rng = ChaCha20Rng::from_seed(seed);
    // Branch 1: percentage above max (real max proof, simulated equality).
    let above = prove_above_max(
        &mut rng,
        &base,
        percentage_opening,
        delta_commitment,
        claimed_commitment,
    )?;
    // Branch 2: percentage below max (simulated max, real equality).
    let below = prove_below_max(
        &mut rng,
        &base,
        percentage_commitment,
        delta_opening,
        delta_amount,
        claimed_opening,
        max_value,
    )?;

    // Select the true branch (amounts are prover-known; both branches
    // always execute so the work profile reveals nothing).
    let use_below = max_value > percentage_amount;
    let (ym, zm, cm, yd, yc, zx, zd, zc) = if use_below {
        (below.0, below.1, below.2, below.3, below.4, below.5, below.6, below.7)
    } else {
        (above.0, above.1, above.2, above.3, above.4, above.5, above.6, above.7)
    };

    // Advance the base transcript exactly as upstream `new` does.
    base.append_point(b"Y_max_proof", &ym);
    base.append_point(b"Y_delta", &yd);
    base.append_point(b"Y_claimed", &yc);
    let _c = base.challenge_scalar(b"c");
    base.append_scalar(b"z_max", &zm);
    base.append_scalar(b"c_max_proof", &cm);
    base.append_scalar(b"z_x", &zx);
    base.append_scalar(b"z_delta_real", &zd);
    base.append_scalar(b"z_claimed", &zc);
    let _w = base.challenge_scalar(b"w");

    let mut out = [0u8; 256];
    out[..32].copy_from_slice(&ym);
    out[32..64].copy_from_slice(&zm);
    out[64..96].copy_from_slice(&cm);
    out[96..128].copy_from_slice(&yd);
    out[128..160].copy_from_slice(&yc);
    out[160..192].copy_from_slice(&zx);
    out[192..224].copy_from_slice(&zd);
    out[224..].copy_from_slice(&zc);
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
/// Above-max branch. Returns
/// (Y_max, z_max, c_max, Y_delta, Y_claimed, z_x, z_delta, z_claimed).
fn prove_above_max(
    rng: &mut ChaCha20Rng,
    base: &ZkTranscript,
    percentage_opening: &[u8; 32],
    delta_commitment: &[u8; 32],
    claimed_commitment: &[u8; 32],
) -> SolanaZkResult<([u8; 32], [u8; 32], [u8; 32], [u8; 32], [u8; 32], [u8; 32], [u8; 32], [u8; 32])>
{
    let g = RistrettoPoint::generator();
    let h = h_point()?;
    let r_pct = crate::curve::ed25519::Scalar::from_bytes_le(percentage_opening)
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    let c_delta = RistrettoPoint::from_bytes(delta_commitment)
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    let c_claimed = RistrettoPoint::from_bytes(claimed_commitment)
        .map_err(|_| SolanaZkError::InvalidPoint)?;

    // Simulate the equality part.
    let z_x = masking_scalar(rng);
    let z_delta = masking_scalar(rng);
    let z_claimed = masking_scalar(rng);
    let c_eq = masking_scalar(rng);
    let y_delta = g
        .mul(&z_x)
        .add(&h.mul(&z_delta))
        .add(&c_delta.mul(&c_eq.neg()));
    let y_claimed = g
        .mul(&z_x)
        .add(&h.mul(&z_claimed))
        .add(&c_claimed.mul(&c_eq.neg()));
    let mut yd_enc = [0u8; 32];
    let mut yc_enc = [0u8; 32];
    y_delta
        .to_bytes_compressed(&mut yd_enc)
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    y_claimed
        .to_bytes_compressed(&mut yc_enc)
        .map_err(|_| SolanaZkError::InvalidPoint)?;

    // Real max proof.
    let y_max = masking_scalar(rng);
    let mut ym_enc = [0u8; 32];
    h.mul(&y_max)
        .to_bytes_compressed(&mut ym_enc)
        .map_err(|_| SolanaZkError::InvalidPoint)?;

    let mut t = base.clone();
    t.append_point(b"Y_max_proof", &ym_enc);
    t.append_point(b"Y_delta", &yd_enc);
    t.append_point(b"Y_claimed", &yc_enc);
    let c = t.challenge_scalar(b"c");
    let c_max = c.add(&c_eq.neg());
    let z_max = c_max.mul(&r_pct).add(&y_max);
    let mut zm_enc = [0u8; 32];
    let mut cm_enc = [0u8; 32];
    let mut zx_enc = [0u8; 32];
    let mut zd_enc = [0u8; 32];
    let mut zc_enc = [0u8; 32];
    z_max.to_bytes_le(&mut zm_enc);
    c_max.to_bytes_le(&mut cm_enc);
    z_x.to_bytes_le(&mut zx_enc);
    z_delta.to_bytes_le(&mut zd_enc);
    z_claimed.to_bytes_le(&mut zc_enc);
    t.append_scalar(b"z_max", &zm_enc);
    t.append_scalar(b"c_max_proof", &cm_enc);
    t.append_scalar(b"z_x", &zx_enc);
    t.append_scalar(b"z_delta_real", &zd_enc);
    t.append_scalar(b"z_claimed", &zc_enc);
    let _w = t.challenge_scalar(b"w");
    Ok((ym_enc, zm_enc, cm_enc, yd_enc, yc_enc, zx_enc, zd_enc, zc_enc))
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
/// Below-max branch. Returns the same 8-tuple.
fn prove_below_max(
    rng: &mut ChaCha20Rng,
    base: &ZkTranscript,
    percentage_commitment: &[u8; 32],
    delta_opening: &[u8; 32],
    delta_amount: u64,
    claimed_opening: &[u8; 32],
    max_value: u64,
) -> SolanaZkResult<([u8; 32], [u8; 32], [u8; 32], [u8; 32], [u8; 32], [u8; 32], [u8; 32], [u8; 32])>
{
    let g = RistrettoPoint::generator();
    let h = h_point()?;
    let m = amount_scalar(max_value);
    let c_pct = RistrettoPoint::from_bytes(percentage_commitment)
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    let r_delta = crate::curve::ed25519::Scalar::from_bytes_le(delta_opening)
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    let r_claimed = crate::curve::ed25519::Scalar::from_bytes_le(claimed_opening)
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    let x = amount_scalar(delta_amount);

    // Simulate the max part.
    let z_max = masking_scalar(rng);
    let c_max = masking_scalar(rng);
    let y_max = h
        .mul(&z_max)
        .add(&c_pct.mul(&c_max.neg()))
        .add(&g.mul(&c_max.mul(&m)));
    let mut ym_enc = [0u8; 32];
    y_max
        .to_bytes_compressed(&mut ym_enc)
        .map_err(|_| SolanaZkError::InvalidPoint)?;

    // Real equality part.
    let y_x = masking_scalar(rng);
    let y_delta = masking_scalar(rng);
    let y_claimed = masking_scalar(rng);
    let y_delta_pt = g.mul(&y_x).add(&h.mul(&y_delta));
    let y_claimed_pt = g.mul(&y_x).add(&h.mul(&y_claimed));
    let mut yd_enc = [0u8; 32];
    let mut yc_enc = [0u8; 32];
    y_delta_pt
        .to_bytes_compressed(&mut yd_enc)
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    y_claimed_pt
        .to_bytes_compressed(&mut yc_enc)
        .map_err(|_| SolanaZkError::InvalidPoint)?;

    let mut t = base.clone();
    t.append_point(b"Y_max_proof", &ym_enc);
    t.append_point(b"Y_delta", &yd_enc);
    t.append_point(b"Y_claimed", &yc_enc);
    let c = t.challenge_scalar(b"c");
    let c_eq = c.add(&c_max.neg());
    let z_x = c_eq.mul(&x).add(&y_x);
    let z_delta = c_eq.mul(&r_delta).add(&y_delta);
    let z_claimed = c_eq.mul(&r_claimed).add(&y_claimed);
    let mut zm_enc = [0u8; 32];
    let mut cm_enc = [0u8; 32];
    let mut zx_enc = [0u8; 32];
    let mut zd_enc = [0u8; 32];
    let mut zc_enc = [0u8; 32];
    z_max.to_bytes_le(&mut zm_enc);
    c_max.to_bytes_le(&mut cm_enc);
    z_x.to_bytes_le(&mut zx_enc);
    z_delta.to_bytes_le(&mut zd_enc);
    z_claimed.to_bytes_le(&mut zc_enc);
    t.append_scalar(b"z_max", &zm_enc);
    t.append_scalar(b"c_max_proof", &cm_enc);
    t.append_scalar(b"z_x", &zx_enc);
    t.append_scalar(b"z_delta_real", &zd_enc);
    t.append_scalar(b"z_claimed", &zc_enc);
    let _w = t.challenge_scalar(b"w");
    Ok((ym_enc, zm_enc, cm_enc, yd_enc, yc_enc, zx_enc, zd_enc, zc_enc))
}

/// Verify a percentage-with-cap proof.
#[allow(clippy::too_many_arguments)]
pub fn verify_percentage_with_cap(
    percentage_commitment: &[u8; 32],
    delta_commitment: &[u8; 32],
    claimed_commitment: &[u8; 32],
    max_value: u64,
    proof: &[u8; 256],
    context: &[u8],
) -> SolanaSigResult<()> {
    let c_max_pt = decode_point(percentage_commitment)?;
    let c_delta = decode_point(delta_commitment)?;
    let c_claimed = decode_point(claimed_commitment)?;
    if c_max_pt.ct_is_identity() == 1
        || c_delta.ct_is_identity() == 1
        || c_claimed.ct_is_identity() == 1
    {
        return Err(SigmaError::IdentityPoint);
    }

    let mut transcript = ZkTranscript::new(context);
    transcript.append_message(b"percentage-commitment", percentage_commitment);
    transcript.append_message(b"delta-commitment", delta_commitment);
    transcript.append_message(b"claimed-commitment", claimed_commitment);
    transcript.append_u64(b"max-value", max_value);
    transcript.percentage_with_cap_domain_separator();

    let ym_enc: [u8; 32] = proof[..32]
        .try_into()
        .map_err(|_| SigmaError::Deserialization)?;
    let zm = canonical_scalar(&proof[32..64])?;
    let cm = canonical_scalar(&proof[64..96])?;
    let yd_enc: [u8; 32] = proof[96..128]
        .try_into()
        .map_err(|_| SigmaError::Deserialization)?;
    let yc_enc: [u8; 32] = proof[128..160]
        .try_into()
        .map_err(|_| SigmaError::Deserialization)?;
    let zx = canonical_scalar(&proof[160..192])?;
    let zd = canonical_scalar(&proof[192..224])?;
    let zc = canonical_scalar(&proof[224..])?;
    transcript.validate_and_append_point(b"Y_max_proof", &ym_enc)?;
    transcript.validate_and_append_point(b"Y_delta", &yd_enc)?;
    transcript.validate_and_append_point(b"Y_claimed", &yc_enc)?;
    let c = transcript.challenge_scalar(b"c");
    let c_eq = c.add(&cm.neg());
    let mut zme = [0u8; 32];
    let mut cme = [0u8; 32];
    let mut zxe = [0u8; 32];
    let mut zde = [0u8; 32];
    let mut zce = [0u8; 32];
    zm.to_bytes_le(&mut zme);
    cm.to_bytes_le(&mut cme);
    zx.to_bytes_le(&mut zxe);
    zd.to_bytes_le(&mut zde);
    zc.to_bytes_le(&mut zce);
    transcript.append_scalar(b"z_max", &zme);
    transcript.append_scalar(b"c_max_proof", &cme);
    transcript.append_scalar(b"z_x", &zxe);
    transcript.append_scalar(b"z_delta_real", &zde);
    transcript.append_scalar(b"z_claimed", &zce);
    let w = transcript.challenge_scalar(b"w");
    let ww = w.mul(&w);

    let y_max = decode_point(&ym_enc)?;
    let y_delta = decode_point(&yd_enc)?;
    let y_claimed = decode_point(&yc_enc)?;
    let g = RistrettoPoint::generator();
    let h = h_point().map_err(|_| SigmaError::Deserialization)?;
    let m = amount_scalar(max_value);
    // [c_max, -c_max*m, -z_max, 1, w*z_x, w*z_delta, -w*c_eq, -w,
    //  ww*z_x, ww*z_claimed, -ww*c_eq, -ww]
    // over [C_max, G, H, Y_max, G, H, C_delta, Y_delta, G, H, C_claimed, Y_claimed]
    let check = c_max_pt
        .mul(&cm)
        .add(&g.mul(&cm.neg().mul(&m)))
        .add(&h.mul(&zm.neg()))
        .add(&y_max)
        .add(&g.mul(&w.mul(&zx)))
        .add(&h.mul(&w.mul(&zd)))
        .add(&c_delta.mul(&w.neg().mul(&c_eq)))
        .add(&y_delta.mul(&w.neg()))
        .add(&g.mul(&ww.mul(&zx)))
        .add(&h.mul(&ww.mul(&zc)))
        .add(&c_claimed.mul(&ww.neg().mul(&c_eq)))
        .add(&y_claimed.mul(&ww.neg()));
    if is_identity_enc(&check) {
        Ok(())
    } else {
        Err(SigmaError::AlgebraicRelation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Upstream golden vector (`b"test"`, max 3).
    #[test]
    fn golden_vector_verifies() {
        let percentage_commitment: [u8; 32] = [
            56, 16, 225, 20, 251, 196, 124, 205, 96, 218, 84, 121, 116, 93, 30,
            31, 106, 69, 24, 144, 190, 49, 37, 190, 7, 189, 86, 173, 76, 252,
            110, 73,
        ];
        let delta_commitment: [u8; 32] = [
            12, 103, 49, 131, 8, 119, 243, 81, 255, 90, 32, 229, 166, 220, 164,
            222, 141, 144, 249, 236, 131, 32, 73, 136, 85, 142, 137, 177, 213,
            8, 220, 96,
        ];
        let claimed_commitment: [u8; 32] = [
            60, 37, 40, 85, 7, 199, 19, 70, 85, 253, 154, 213, 228, 64, 178,
            169, 60, 220, 102, 148, 154, 220, 123, 61, 174, 72, 40, 9, 51, 236,
            163, 18,
        ];
        let proof: [u8; 256] = [
            52, 247, 35, 145, 163, 179, 164, 243, 115, 238, 227, 89, 92, 202,
            242, 228, 203, 34, 87, 42, 155, 74, 116, 225, 94, 42, 30, 249, 73,
            112, 235, 78, 151, 13, 153, 118, 118, 146, 156, 67, 236, 24, 133,
            10, 130, 249, 113, 248, 105, 112, 160, 108, 208, 118, 152, 41, 88,
            53, 151, 17, 210, 155, 123, 8, 88, 122, 225, 194, 93, 52, 105, 13,
            187, 53, 64, 141, 0, 95, 122, 173, 6, 249, 67, 59, 114, 33, 119,
            213, 71, 19, 251, 88, 47, 141, 203, 8, 92, 13, 145, 95, 215, 105,
            137, 118, 86, 54, 160, 129, 97, 181, 120, 159, 0, 21, 247, 132, 69,
            139, 234, 232, 224, 115, 67, 4, 185, 230, 67, 127, 130, 219, 27,
            90, 151, 84, 40, 111, 107, 106, 186, 187, 212, 77, 137, 212, 117,
            164, 3, 18, 144, 221, 86, 17, 161, 188, 232, 124, 99, 248, 239, 78,
            190, 33, 217, 164, 30, 13, 32, 66, 139, 77, 234, 55, 210, 248, 203,
            200, 192, 81, 116, 120, 81, 202, 176, 61, 96, 73, 163, 184, 105,
            218, 11, 5, 250, 169, 160, 222, 38, 176, 27, 247, 125, 181, 166,
            142, 178, 196, 103, 203, 163, 149, 91, 8, 110, 5, 77, 79, 238, 147,
            10, 101, 232, 117, 196, 10, 63, 28, 38, 192, 97, 143, 130, 19, 63,
            82, 200, 201, 212, 60, 251, 153, 171, 237, 252, 158, 145, 226, 203,
            168, 156, 169, 10, 8, 183, 7, 209, 14,
        ];
        verify_percentage_with_cap(
            &percentage_commitment,
            &delta_commitment,
            &claimed_commitment,
            3,
            &proof,
            b"test",
        )
        .unwrap();
    }

    /// Below-max roundtrip (mirrors upstream
    /// `test_proof_below_max_proof`); tampered max fails.
    #[test]
    fn roundtrip_below_max() {
        use crate::curve::traits::CurvePoint;
        let g = RistrettoPoint::generator();
        let h = crate::solana_zk::h_point().unwrap();
        let r_transfer = crate::curve::ed25519::Scalar::from_bytes_le(&[7u8; 32]).unwrap();
        let r_pct = crate::curve::ed25519::Scalar::from_bytes_le(&[11u8; 32]).unwrap();
        let r_claimed = crate::curve::ed25519::Scalar::from_bytes_le(&[13u8; 32]).unwrap();
        let enc = |m: u64, r: &crate::curve::ed25519::Scalar| {
            let mut o = [0u8; 32];
            g.mul(&crate::solana_zk::amount_scalar(m))
                .add(&h.mul(r))
                .to_bytes_compressed(&mut o)
                .unwrap();
            o
        };
        // transfer 1 @ 4%: percentage 1, delta 9600, max 3.
        let rate = crate::solana_zk::amount_scalar(400);
        let tenk = crate::solana_zk::amount_scalar(10000);
        let _c_transfer = enc(1, &r_transfer);
        let c_pct = enc(1, &r_pct);
        let c_delta_pt = g
            .mul(&tenk)
            .mul(&crate::solana_zk::amount_scalar(1))
            .add(&h.mul(&tenk.mul(&r_pct)))
            .add(&g.mul(&rate).mul(&crate::solana_zk::amount_scalar(1)).neg())
            .add(&h.mul(&rate.mul(&r_transfer)).neg());
        let mut c_delta = [0u8; 32];
        c_delta_pt.to_bytes_compressed(&mut c_delta).unwrap();
        let r_delta = tenk
            .mul(&r_pct)
            .add(&rate.mul(&r_transfer).neg());
        let c_claimed = enc(9600, &r_claimed);
        let to32 = |s: &crate::curve::ed25519::Scalar| {
            let mut o = [0u8; 32];
            s.to_bytes_le(&mut o);
            o
        };
        let proof = prove_percentage_with_cap(
            &c_pct,
            &to32(&r_pct),
            1,
            &c_delta,
            &to32(&r_delta),
            9600,
            &c_claimed,
            &to32(&r_claimed),
            3,
            &[9u8; 32],
            b"test",
        )
        .unwrap();
        verify_percentage_with_cap(&c_pct, &c_delta, &c_claimed, 3, &proof, b"test")
            .unwrap();
        // Wrong max value must fail.
        assert!(
            verify_percentage_with_cap(&c_pct, &c_delta, &c_claimed, 4, &proof, b"test")
                .is_err()
        );
    }
}
