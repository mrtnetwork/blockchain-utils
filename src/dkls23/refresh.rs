//! Key refresh: rotate shares without changing the public key.
//!
//! Shamir-compatible refresh: each dealer samples a random polynomial
//! with a **zero constant term** (`g(0) = 0`, degree `t-1`) and unicasts
//! `δ_{j→l} = g_j(id_l)`. The new share is `x_l' = x_l + Σ_j δ_{j→l}`;
//! since every `g_j(0) = 0`, the shared secret (and group key) is
//! unchanged while the new shares lie on a fresh degree-`(t-1)`
//! polynomial. Feldman commitments on each delta polynomial make a
//! cheating dealer identifiable (wrong cell or nonzero constant term).

use super::codec::KeyShare;
use super::curve_id::{CurveId, DklsPoint, DklsScalar};
use super::error::{DklsError, DklsResult};
use super::shares::{eval_poly, eval_poly_points, party_id};
use crate::rng::{ChaCha20Rng, Rng};
use alloc::vec::Vec;

/// Refresh broadcast: one zero-sharing polynomial per dealer.
#[derive(Clone, Debug)]
pub struct RefreshMsg {
    /// Party index.
    pub party: usize,
    /// Delta for each member (`δ_{me→l}`, 32 bytes BE).
    pub deltas: Vec<[u8; 32]>,
    /// `G·δ` per member (for cell verification).
    pub delta_pts: Vec<[u8; 33]>,
    /// Feldman coefficient commitments (`t` points, `F[0]` = identity).
    pub feldman: Vec<[u8; 33]>,
}

impl Drop for RefreshMsg {
    fn drop(&mut self) {
        for d in self.deltas.iter_mut() {
            crate::bytes::zeroize(d);
        }
    }
}

/// Sample a zero-sharing delta row: random degree-`(t-1)` polynomial
/// with `g(0) = 0`, evaluated at every party id.
pub fn sample_deltas(
    rng: &mut ChaCha20Rng,
    curve: CurveId,
    t: usize,
    n: usize,
) -> DklsResult<(Vec<DklsScalar>, Vec<DklsPoint>, Vec<DklsPoint>)> {
    if n == 0 || t == 0 || t > n {
        return Err(DklsError::TooFew);
    }
    // coeffs[0] = 0 (secret unchanged); rest random nonzero.
    let mut coeffs = Vec::with_capacity(t);
    coeffs.push(DklsScalar::zero(curve));
    for _ in 1..t {
        loop {
            let mut raw = [0u8; 32];
            rng.fill_bytes(&mut raw);
            if let Some(s) = DklsScalar::from_bytes_be(curve, &raw) {
                if !s.is_zero() {
                    coeffs.push(s);
                    break;
                }
            }
        }
    }
    let feldman: Vec<DklsPoint> =
        coeffs.iter().map(|c| DklsPoint::generator(curve).mul(c)).collect();
    let mut deltas = Vec::with_capacity(n);
    let mut pts = Vec::with_capacity(n);
    for l in 0..n {
        let d = eval_poly(&coeffs, &party_id(l, curve));
        pts.push(DklsPoint::generator(curve).mul(&d));
        deltas.push(d);
    }
    Ok((deltas, pts, feldman))
}

/// Apply verified refresh messages to old shares (new shares out).
pub fn refresh_apply(
    olds: &[KeyShare],
    msgs: &[RefreshMsg],
    curve: CurveId,
) -> DklsResult<Vec<KeyShare>> {
    if olds.is_empty() || olds.len() != msgs.len() {
        return Err(DklsError::TooFew);
    }
    let n = olds.len();
    let t = olds[0].t.unwrap_or(n);
    for m in msgs {
        if m.deltas.len() != n || m.delta_pts.len() != n || m.feldman.len() != t {
            return Err(DklsError::BadEncoding);
        }
        // Zero constant term: F[0] must be the identity (secret kept).
        let f0 = DklsPoint::from_bytes(curve, &m.feldman[0]).ok_or(DklsError::InvalidPoint)?;
        if f0.ct_is_identity() == 0 {
            return Err(DklsError::BadShare);
        }
        let fpts: Vec<DklsPoint> = m
            .feldman
            .iter()
            .map(|enc| DklsPoint::from_bytes(curve, enc).ok_or(DklsError::InvalidPoint))
            .collect::<DklsResult<Vec<_>>>()?;
        // Every cell must match the committed polynomial (identifies a
        // cheating dealer by row).
        for l in 0..n {
            let d =
                DklsScalar::from_bytes_be(curve, &m.deltas[l]).ok_or(DklsError::InvalidScalar)?;
            let expect = eval_poly_points(&fpts, &party_id(l, curve));
            let got_cell =
                DklsPoint::from_bytes(curve, &m.delta_pts[l]).ok_or(DklsError::InvalidPoint)?;
            let got_g = DklsPoint::generator(curve).mul(&d);
            let (mut a, mut b, mut c) = ([0u8; 33], [0u8; 33], [0u8; 33]);
            if !expect.to_bytes_compressed(&mut a)
                || !got_cell.to_bytes_compressed(&mut b)
                || !got_g.to_bytes_compressed(&mut c)
            {
                return Err(DklsError::InvalidPoint);
            }
            if crate::ct::ct_eq(&a, &b) != 1 || crate::ct::ct_eq(&a, &c) != 1 {
                return Err(DklsError::BadShare);
            }
        }
    }
    // Column sums: add[l] = Σ_j δ_{j→l}; new share + shifted publics.
    let mut out = Vec::with_capacity(n);
    for (i, old) in olds.iter().enumerate() {
        let mut x = DklsScalar::from_bytes_be(curve, &old.x).ok_or(DklsError::InvalidScalar)?;
        let mut shares = old.shares.clone();
        for (l, share_slot) in shares.iter_mut().enumerate().take(n) {
            let mut add = DklsScalar::zero(curve);
            for m in msgs {
                let d = DklsScalar::from_bytes_be(curve, &m.deltas[l])
                    .ok_or(DklsError::InvalidScalar)?;
                add = add.add(&d);
            }
            let cur = DklsPoint::from_bytes(curve, share_slot).ok_or(DklsError::InvalidPoint)?;
            let upd = cur.add(&DklsPoint::generator(curve).mul(&add));
            *share_slot = upd.to_array_compressed().ok_or(DklsError::InvalidPoint)?;
            if l == i {
                x = x.add(&add);
            }
        }
        if x.is_zero() {
            return Err(DklsError::ZeroSecret);
        }
        out.push(KeyShare {
            party: old.party,
            n: old.n,
            t: old.t,
            curve,
            x: x.to_array_be(),
            pk: old.pk,
            shares,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_poly_keeps_secret() {
        // Deltas lie on a zero-constant polynomial: Lagrange at zero
        // over any t-subset reconstructs 0.
        let curve = CurveId::K1;
        let mut rng = ChaCha20Rng::from_seed(&[5u8; 32]);
        let (deltas, _, _) = sample_deltas(&mut rng, curve, 2, 3).unwrap();
        let ids: Vec<DklsScalar> =
            (0..3).map(|i| party_id(i, curve)).collect();
        for subset in [[0usize, 1usize], [0, 2], [1, 2]] {
            let sub: Vec<DklsScalar> = subset.iter().map(|&i| ids[i].clone()).collect();
            let mut secret = DklsScalar::zero(curve);
            for &i in &subset {
                let lambda =
                    super::super::shares::lagrange_at_zero(&sub, &ids[i]).unwrap();
                secret = secret.add(&lambda.mul(&deltas[i]));
            }
            assert!(secret.is_zero());
        }
    }

    #[test]
    fn bad_params_rejected() {
        let mut rng = ChaCha20Rng::from_seed(&[5u8; 32]);
        assert!(sample_deltas(&mut rng, CurveId::K1, 0, 3).is_err());
        assert!(sample_deltas(&mut rng, CurveId::K1, 4, 3).is_err());
        assert!(sample_deltas(&mut rng, CurveId::K1, 2, 0).is_err());
    }
}
