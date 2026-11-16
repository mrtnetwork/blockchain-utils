//! Additive and Shamir secret sharing over the curve order.
//!
//! DKG builds on Feldman VSS: dealer `j` samples `f_j` of degree `t-1`
//! and unicasts `σ_{j→i} = f_j(i+1)`; party `i` sums a column into its
//! share. The 2-of-2 / n-of-n path is the same code with `t = n`.
//! Zero shares ([`zero_share`]) mask presignature nonces per session.

use super::curve_id::{CurveId, DklsPoint, DklsScalar};
use super::digest::tagged_expand;
use super::error::{DklsError, DklsResult};
use super::oracle::TAG_ZERO_SHARE_FRAGMENT;
use alloc::vec::Vec;

/// Evaluate a scalar polynomial at `x` (Horner, CT ops).
pub fn eval_poly(coeffs: &[DklsScalar], x: &DklsScalar) -> DklsScalar {
    let mut v = DklsScalar::zero(x.curve());
    for c in coeffs.iter().rev() {
        v = v.mul(x).add(c);
    }
    v
}

/// Evaluate a point polynomial `Σ F[k]·x^k` (public inputs, vartime OK).
pub fn eval_poly_points(coeffs: &[DklsPoint], x: &DklsScalar) -> DklsPoint {
    let mut acc = DklsPoint::identity(x.curve());
    let mut power = DklsScalar::one(x.curve());
    for c in coeffs {
        acc = acc.add(&c.mul(&power));
        power = power.mul(x);
    }
    acc
}

/// Field element for party `index` (`id = index+1` as a scalar).
pub fn party_id(index: usize, curve: CurveId) -> DklsScalar {
    let mut b = [0u8; 32];
    b[24..32].copy_from_slice(&(index as u64 + 1).to_be_bytes());
    DklsScalar::from_bytes_mod_order(curve, &b)
}

/// Lagrange coefficient at zero over `ids` evaluated for `xi`:
/// `λ = Π xj/(xj−xi)`.
pub fn lagrange_at_zero(ids: &[DklsScalar], xi: &DklsScalar) -> DklsResult<DklsScalar> {
    let curve = xi.curve();
    let mut num = DklsScalar::one(curve);
    let mut den = DklsScalar::one(curve);
    let mut found = false;
    for xj in ids {
        if xj.ct_eq(xi) == 1 {
            found = true;
            continue;
        }
        num = num.mul(xj);
        den = den.mul(&xj.add(&xi.neg()));
    }
    if !found {
        return Err(DklsError::BadEncoding);
    }
    Ok(num.mul(&den.invert().ok_or(DklsError::ZeroSecret)?))
}

/// Verify a Feldman share: `G·σ == Σ F[k]·id^k`.
pub fn verify_feldman_share(
    f_points: &[DklsPoint],
    party: usize,
    sigma: &DklsScalar,
) -> DklsResult<()> {
    let curve = sigma.curve();
    let lhs = DklsPoint::generator(curve).mul(sigma);
    let rhs = eval_poly_points(f_points, &party_id(party, curve));
    let (mut l, mut r) = ([0u8; 33], [0u8; 33]);
    if !lhs.to_bytes_compressed(&mut l) || !rhs.to_bytes_compressed(&mut r) {
        return Err(DklsError::InvalidPoint);
    }
    if crate::ct::ct_eq(&l, &r) == 1 {
        Ok(())
    } else {
        Err(DklsError::BadShare)
    }
}

/// Deterministic zero-share fragment for `(seed, session, direction)`.
/// Fragments sum to zero across the ordered pair by construction
/// (`frag(a→b) = +f`, `frag(b→a) = −f`); callers add the fragment into
/// their nonce share. `direction` must be an ordered pair encoding
/// (e.g. `lo || hi` party indices) — see [`super::mul`].
pub fn zero_share_fragment(
    curve: CurveId,
    seed: &[u8; 32],
    session: &[u8],
    direction: &[u8],
    sign: bool,
) -> DklsScalar {
    let mut ctx = Vec::with_capacity(session.len() + direction.len());
    ctx.extend_from_slice(session);
    ctx.extend_from_slice(direction);
    let mut raw = [0u8; 32];
    tagged_expand(TAG_ZERO_SHARE_FRAGMENT, seed, &ctx, &mut raw);
    let f = DklsScalar::from_bytes_mod_order(curve, &raw);
    crate::bytes::zeroize(&mut raw);
    if sign {
        f
    } else {
        f.neg()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::{ChaCha20Rng, Rng};

    #[test]
    fn zero_fragments_cancel() {
        let seed = [3u8; 32];
        let a = zero_share_fragment(CurveId::K1, &seed, b"sess", b"dir", true);
        let b = zero_share_fragment(CurveId::K1, &seed, b"sess", b"dir", false);
        assert!(a.add(&b).is_zero());
    }

    #[test]
    fn feldman_self_consistent() {
        let curve = CurveId::R1;
        let mut rng = ChaCha20Rng::from_seed(&[9u8; 32]);
        let mut coeffs = Vec::new();
        for _ in 0..2 {
            let mut raw = [0u8; 32];
            rng.fill_bytes(&mut raw);
            let mut s = DklsScalar::from_bytes_mod_order(curve, &raw);
            if s.is_zero() {
                s = DklsScalar::one(curve);
            }
            coeffs.push(s);
        }
        let pts: Vec<DklsPoint> =
            coeffs.iter().map(|c| DklsPoint::generator(curve).mul(c)).collect();
        for i in 0..3 {
            let sigma = eval_poly(&coeffs, &party_id(i, curve));
            verify_feldman_share(&pts, i, &sigma).unwrap();
        }
    }
}
