//! Schnorr DLog proofs: prove knowledge of `x` with `X = G·x`.
//!
//! Non-interactive via Fiat–Shamir over [`tagged_hash`]: commit
//! `A = G·a`, challenge `e = H(ctx || X || A)`, response `z = a + e·x`.
//! Verification checks `G·z == A + e·X`. Nonce and secret paths reuse
//! the CT curve backends; the challenge binds the session context so
//! proofs do not replay across sessions.

use super::curve_id::{CurveId, DklsPoint, DklsScalar};
use super::digest::tagged_hash;
use super::error::{DklsError, DklsResult};
use super::oracle::TAG_DLOG_PROOF;
use crate::rng::{ChaCha20Rng, Rng};

/// A Schnorr proof (commitment point + response scalar).
#[derive(Clone, Debug)]
pub struct DlogProof {
    /// Commitment `A` (compressed, 33 bytes).
    pub commitment: [u8; 33],
    /// Response `z` (canonical, 32 bytes BE).
    pub response: [u8; 32],
}

/// Draw a fresh nonce scalar (`!= 0`) from `rng`.
pub fn fresh_nonce(curve: CurveId, rng: &mut ChaCha20Rng) -> DklsScalar {
    loop {
        let mut raw = [0u8; 32];
        rng.fill_bytes(&mut raw);
        if let Some(s) = DklsScalar::from_bytes_be(curve, &raw) {
            if !s.is_zero() {
                return s;
            }
        }
        // Retry with the next stream block (still deterministic).
    }
}

/// Prove knowledge of `x` for public key `x_pub`. `ctx` binds the
/// session (session id, party index, public key bytes, …).
pub fn prove(
    rng: &mut ChaCha20Rng,
    curve: CurveId,
    x: &DklsScalar,
    x_pub: &DklsPoint,
    ctx: &[u8],
) -> DklsResult<DlogProof> {
    if x.curve() != curve || x_pub.curve() != curve {
        return Err(DklsError::InvalidParticipant);
    }
    let x_enc = x_pub.to_array_compressed().ok_or(DklsError::InvalidPoint)?;
    let a = fresh_nonce(curve, rng);
    let a_pt = DklsPoint::generator(curve).mul(&a);
    let a_enc = a_pt.to_array_compressed().ok_or(DklsError::InvalidPoint)?;
    let e_bytes = tagged_hash(TAG_DLOG_PROOF, &[ctx, &x_enc, &a_enc]);
    let e = DklsScalar::from_bytes_mod_order(curve, &e_bytes);
    let z = a.add(&e.mul(x));
    let mut response = [0u8; 32];
    z.to_bytes_be(&mut response);
    Ok(DlogProof { commitment: a_enc, response })
}

/// Verify a [`DlogProof`] against `x_pub` under the same `ctx`.
pub fn verify(curve: CurveId, x_pub: &DklsPoint, proof: &DlogProof, ctx: &[u8]) -> DklsResult<()> {
    if x_pub.curve() != curve {
        return Err(DklsError::InvalidParticipant);
    }
    if x_pub.ct_is_identity() == 1 {
        return Err(DklsError::ZeroSecret);
    }
    let x_enc = x_pub.to_array_compressed().ok_or(DklsError::InvalidPoint)?;
    let a_pt = DklsPoint::from_bytes(curve, &proof.commitment).ok_or(DklsError::InvalidPoint)?;
    let z = DklsScalar::from_bytes_be(curve, &proof.response).ok_or(DklsError::InvalidScalar)?;
    let e_bytes = tagged_hash(TAG_DLOG_PROOF, &[ctx, &x_enc, &proof.commitment]);
    let e = DklsScalar::from_bytes_mod_order(curve, &e_bytes);
    let lhs = DklsPoint::generator(curve).mul(&z);
    let rhs = a_pt.add(&x_pub.mul(&e));
    let (mut l, mut r) = ([0u8; 33], [0u8; 33]);
    if !lhs.to_bytes_compressed(&mut l) || !rhs.to_bytes_compressed(&mut r) {
        return Err(DklsError::InvalidPoint);
    }
    if crate::ct::ct_eq(&l, &r) == 1 {
        Ok(())
    } else {
        Err(DklsError::BadProof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed(&[11u8; 32])
    }

    fn roundtrip(curve: CurveId) {
        let mut r = rng();
        let mut xb = [0u8; 32];
        xb[31] = 5;
        let x = DklsScalar::from_bytes_be(curve, &xb).unwrap();
        let x_pub = DklsPoint::generator(curve).mul(&x);
        let proof = prove(&mut r, curve, &x, &x_pub, b"ctx-1").unwrap();
        verify(curve, &x_pub, &proof, b"ctx-1").unwrap();
        assert_eq!(verify(curve, &x_pub, &proof, b"other-ctx"), Err(DklsError::BadProof));
    }

    #[test]
    fn k1_roundtrip() {
        roundtrip(CurveId::K1);
    }

    #[test]
    fn r1_roundtrip() {
        roundtrip(CurveId::R1);
    }
}
