//! Distributed key generation: commit → release → complain.
//!
//! No proofs of knowledge (paper §3): each party commits to its Feldman
//! coefficients first, then reveals; anyone who opens to a different
//! value than committed is identified as the aborter. Threshold `t`-of-`n`
//! uses Feldman VSS (degree `t-1`); additive n-of-n is `t = n` with the
//! same code path.

use super::codec::KeyShare;
use super::commit::{commit, verify, COMMIT_LEN};
use super::curve_id::{CurveId, DklsPoint, DklsScalar};
use super::error::{DklsError, DklsResult};
use super::schnorr;
use super::shares::{eval_poly, eval_poly_points, party_id, verify_feldman_share};
use crate::rng::{ChaCha20Rng, Rng};
use alloc::vec::Vec;

/// DKG round-1 broadcast (commitment only).
#[derive(Clone, Debug)]
pub struct DkgR1 {
    /// Party index.
    pub party: usize,
    /// Commitment to the round-2 payload.
    pub commitment: [u8; COMMIT_LEN],
}

/// DKG round-2 broadcast (opening + verifiable material).
#[derive(Clone, Debug)]
pub struct DkgR2 {
    /// Party index.
    pub party: usize,
    /// Feldman coefficient points (compressed, degree `t-1`).
    pub feldman: Vec<[u8; 33]>,
    /// Schnorr commitment for the share proof.
    pub sch_commit: [u8; 33],
    /// Opening salt for [`DkgR1::commitment`].
    pub salt: Vec<u8>,
    /// Execution-id randomness contribution.
    pub rid: Vec<u8>,
}

/// Live dealer state (kept secret until refresh erases it).
pub struct Dealer {
    /// Party index.
    pub party: usize,
    /// Curve.
    pub curve: CurveId,
    /// Threshold.
    pub t: usize,
    /// Polynomial coefficients (secret).
    pub coeffs: Vec<DklsScalar>,
    /// Schnorr nonce (secret).
    pub sch_nonce: DklsScalar,
    /// Round-2 payload the commitment binds (recomputed at reveal).
    pub payload: Vec<u8>,
    /// `rid` contribution.
    pub rid: Vec<u8>,
    /// Session id the round-1 commitment binds.
    pub sid: Vec<u8>,
    /// Opening salt for the round-1 commitment (revealed in round 2).
    pub salt: [u8; super::commit::SALT_LEN],
}

impl Drop for Dealer {
    fn drop(&mut self) {
        for c in self.coeffs.iter_mut() {
            c.zeroize();
        }
        self.sch_nonce.zeroize();
        crate::bytes::zeroize(&mut self.salt);
        for b in self.payload.iter_mut() {
            *b = 0;
        }
        for b in self.rid.iter_mut() {
            *b = 0;
        }
        for b in self.sid.iter_mut() {
            *b = 0;
        }
    }
}

/// Session binding context for the Schnorr proof over the share.
fn schnorr_ctx(sid: &[u8], rid: &[u8], party: usize, y_share: &[u8; 33]) -> Vec<u8> {
    let mut o = Vec::with_capacity(sid.len() + rid.len() + 64);
    o.extend_from_slice(sid);
    o.extend_from_slice(rid);
    o.extend_from_slice(&(party as u64).to_be_bytes());
    o.extend_from_slice(y_share);
    o
}

/// Canonical payload encoding the commitment binds:
/// `sid_len(u64 BE) || sid || feldman || sch_commit || rid`.
///
/// Prefixing the session id binds the commitment to one ceremony: a
/// commitment cannot be replayed under a different `sid`.
fn payload_bytes(
    sid: &[u8],
    feldman: &[[u8; 33]],
    sch_commit: &[u8; 33],
    rid: &[u8],
) -> Vec<u8> {
    let mut o = Vec::with_capacity(8 + sid.len() + feldman.len() * 33 + 33 + rid.len());
    o.extend_from_slice(&(sid.len() as u64).to_be_bytes());
    o.extend_from_slice(sid);
    for f in feldman {
        o.extend_from_slice(f);
    }
    o.extend_from_slice(sch_commit);
    o.extend_from_slice(rid);
    o
}

/// Split a round-2 payload into `(sid, feldman, sch_commit, rid)`,
/// requiring exactly `t` Feldman points and a 32-byte `rid`.
pub fn parse_dkg_payload(
    payload: &[u8],
    t: usize,
) -> DklsResult<(Vec<u8>, Vec<[u8; 33]>, [u8; 33], Vec<u8>)> {
    if payload.len() < 8 {
        return Err(DklsError::BadEncoding);
    }
    let sid_len =
        u64::from_be_bytes(payload[0..8].try_into().map_err(|_| DklsError::BadEncoding)?)
            as usize;
    let body = payload.get(8 + sid_len..).ok_or(DklsError::BadEncoding)?;
    if body.len() != t * 33 + 33 + 32 {
        return Err(DklsError::BadEncoding);
    }
    let mut feldman = Vec::with_capacity(t);
    for k in 0..t {
        let mut enc = [0u8; 33];
        enc.copy_from_slice(&body[k * 33..(k + 1) * 33]);
        feldman.push(enc);
    }
    let mut sch = [0u8; 33];
    sch.copy_from_slice(&body[t * 33..t * 33 + 33]);
    let rid = body[t * 33 + 33..].to_vec();
    Ok((payload[8..8 + sid_len].to_vec(), feldman, sch, rid))
}

/// Dealer round 1: sample `f` of degree `t-1`, commit to the reveal.
///
/// The commitment binds `(sid, feldman, sch_commit, rid)`; the opening
/// salt is kept in the returned [`Dealer`] and must be revealed via
/// [`dealer_round2`] — re-committing with a fresh salt breaks
/// [`dkg_finish`] verification by construction.
pub fn dealer_round1(
    rng: &mut ChaCha20Rng,
    party: usize,
    curve: CurveId,
    t: usize,
    sid: &[u8],
) -> DklsResult<(Dealer, DkgR1)> {
    if t == 0 {
        return Err(DklsError::TooFew);
    }
    if sid.is_empty() {
        return Err(DklsError::InvalidLength);
    }
    let mut coeffs = Vec::with_capacity(t);
    for _ in 0..t {
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
    let feldman: Vec<[u8; 33]> = coeffs
        .iter()
        .map(|c| DklsPoint::generator(curve).mul(c).to_array_compressed())
        .collect::<Option<Vec<_>>>()
        .ok_or(DklsError::InvalidPoint)?;
    let sch_nonce = schnorr::fresh_nonce(curve, rng);
    let sch_commit = DklsPoint::generator(curve)
        .mul(&sch_nonce)
        .to_array_compressed()
        .ok_or(DklsError::InvalidPoint)?;
    let mut rid = alloc::vec![0u8; 32];
    rng.fill_bytes(&mut rid);
    let payload = payload_bytes(sid, &feldman, &sch_commit, &rid);
    let (commitment, opening) = commit(rng, &payload);
    let mut salt = [0u8; super::commit::SALT_LEN];
    salt.copy_from_slice(opening.salt());
    Ok((
        Dealer { party, curve, t, coeffs, sch_nonce, payload, rid, sid: sid.to_vec(), salt },
        DkgR1 { party, commitment },
    ))
}

/// Dealer round 2: reveal the payload with the round-1 opening salt.
///
/// Uses the salt stored in [`dealer_round1`]'s [`Dealer`]: the same salt
/// the round-1 commitment was created with, so [`dkg_finish`]
/// verification passes honestly.
pub fn dealer_round2(
    rng: &mut ChaCha20Rng,
    dealer: &Dealer,
) -> DklsResult<(DkgR2, Vec<u8>)> {
    let _ = rng;
    Ok((
        DkgR2 {
            party: dealer.party,
            feldman: dealer
                .coeffs
                .iter()
                .map(|c| {
                    DklsPoint::generator(dealer.curve).mul(c).to_array_compressed().unwrap()
                })
                .collect(),
            sch_commit: DklsPoint::generator(dealer.curve)
                .mul(&dealer.sch_nonce)
                .to_array_compressed()
                .ok_or(DklsError::InvalidPoint)?,
            salt: dealer.salt.to_vec(),
            rid: dealer.rid.clone(),
        },
        dealer.payload.clone(),
    ))
}

/// Dealer round 1 with the opening returned (for callers that relay).
pub fn dealer_round1_opening(
    rng: &mut ChaCha20Rng,
    party: usize,
    curve: CurveId,
    t: usize,
    sid: &[u8],
) -> DklsResult<(Dealer, DkgR1, Vec<u8>)> {
    let (dealer, r1) = dealer_round1(rng, party, curve, t, sid)?;
    let salt = dealer.salt.to_vec();
    Ok((dealer, r1, salt))
}

/// Unicast share `σ_{from → to} = f_from(id_to)`.
pub fn sigma_for(dealer: &Dealer, to: usize) -> DklsScalar {
    eval_poly(&dealer.coeffs, &party_id(to, dealer.curve))
}

/// Finish: verify openings + Feldman + Schnorr, assemble [`KeyShare`]s.
///
/// `openings[j]` = `(payload_j, salt_j)` for dealer `j`;
/// `sigmas[j][i]` = unicast from `j` to `i`;
/// `proofs[j]` = Schnorr response for dealer `j`'s column share.
// `dkg_finish` mirrors the DKLS23 paper's parameter list; bundling them
// into a struct would change the public API, so the arity lint is allowed.
#[allow(clippy::too_many_arguments)]
pub fn dkg_finish(
    curve: CurveId,
    sid: &[u8],
    n: usize,
    t: usize,
    r1s: &[DkgR1],
    openings: &[(Vec<u8>, Vec<u8>)],
    sigmas: &[Vec<DklsScalar>],
    proofs: &[super::schnorr::DlogProof],
) -> DklsResult<Vec<KeyShare>> {
    if n == 0 || r1s.len() != n || openings.len() != n || sigmas.len() != n || proofs.len() != n {
        return Err(DklsError::TooFew);
    }
    if sid.is_empty() {
        return Err(DklsError::InvalidLength);
    }
    // 1. Commitment check (identifies the complainee).
    for j in 0..n {
        verify(&r1s[j].commitment, &openings[j].0, &openings[j].1)?;
    }
    // 2. Decode Feldman coefficients per dealer. Each payload must open
    // with this ceremony's `sid`; anything else is a cross-session
    // replay and aborts before any share math runs.
    let mut f_pts: Vec<Vec<DklsPoint>> = Vec::with_capacity(n);
    let mut rids: Vec<Vec<u8>> = Vec::with_capacity(n);
    let mut sch_commits: Vec<[u8; 33]> = Vec::with_capacity(n);
    for (payload, _) in openings {
        let (psid, feldman, sch, rid) = parse_dkg_payload(payload, t)?;
        if psid != sid {
            return Err(DklsError::BadCommitment);
        }
        let mut pts = Vec::with_capacity(t);
        for enc in &feldman {
            pts.push(DklsPoint::from_bytes(curve, enc).ok_or(DklsError::InvalidPoint)?);
        }
        rids.push(rid);
        sch_commits.push(sch);
        f_pts.push(pts);
    }
    // 3. Feldman verify every unicast.
    for j in 0..n {
        for (i, sigma) in sigmas[j].iter().enumerate().take(n) {
            verify_feldman_share(&f_pts[j], i, sigma)?;
        }
    }
    // 4. Collective rid.
    let mut rid = alloc::vec![0u8; 32];
    for r in &rids {
        if r.len() != 32 {
            return Err(DklsError::BadEncoding);
        }
        for k in 0..32 {
            rid[k] ^= r[k];
        }
    }
    // 5. Column shares + Schnorr verify.
    let mut y_cols: Vec<[u8; 33]> = Vec::with_capacity(n);
    for i in 0..n {
        let mut acc = DklsPoint::identity(curve);
        for pts in &f_pts {
            acc = acc.add(&eval_poly_points(pts, &party_id(i, curve)));
        }
        if acc.ct_is_identity() == 1 {
            return Err(DklsError::ZeroSecret);
        }
        y_cols.push(acc.to_array_compressed().ok_or(DklsError::InvalidPoint)?);
    }
    let mut pk = DklsPoint::identity(curve);
    for pts in &f_pts {
        pk = pk.add(&pts[0]);
    }
    if pk.ct_is_identity() == 1 {
        return Err(DklsError::ZeroSecret);
    }
    let pk_enc = pk.to_array_compressed().ok_or(DklsError::InvalidPoint)?;
    for j in 0..n {
        // Column secret σ_j = Σ_k σ_{k→j}.
        let mut sigma = DklsScalar::zero(curve);
        for row in sigmas {
            sigma = sigma.add(&row[j]);
        }
        if sigma.is_zero() {
            return Err(DklsError::ZeroSecret);
        }
        let y_pt = DklsPoint::from_bytes(curve, &y_cols[j]).ok_or(DklsError::InvalidPoint)?;
        // The proof's commitment must equal the Schnorr commitment the
        // dealer bound in its round-2 payload: otherwise the proof
        // attests to a different nonce than the one committed to.
        if proofs[j].commitment != sch_commits[j] {
            return Err(DklsError::BadProof);
        }
        let a_pt = DklsPoint::from_bytes(curve, &proofs[j].commitment)
            .ok_or(DklsError::InvalidPoint)?;
        if a_pt.ct_is_identity() == 1 {
            return Err(DklsError::ZeroSecret);
        }
        let ctx = schnorr_ctx(sid, &rid, j, &y_cols[j]);
        schnorr::verify(curve, &y_pt, &proofs[j], &ctx)?;
    }
    Ok((0..n)
        .map(|i| {
            let mut sigma = DklsScalar::zero(curve);
            for row in sigmas {
                sigma = sigma.add(&row[i]);
            }
            KeyShare {
                party: i,
                n,
                t: Some(t),
                curve,
                x: sigma.to_array_be(),
                pk: pk_enc,
                shares: y_cols.clone(),
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::ChaCha20Rng;

    #[test]
    fn commitment_binds_payload() {
        let mut rng = ChaCha20Rng::from_seed(&[1u8; 32]);
        let payload = b"dealer-payload";
        let (com, open) = commit(&mut rng, payload);
        verify(&com, open.msg(), open.salt()).unwrap();
    }

    #[test]
    fn round1_rejects_empty_sid() {
        let mut rng = ChaCha20Rng::from_seed(&[2u8; 32]);
        let curve = CurveId::K1;
        let share = KeyShare {
            party: 0,
            n: 2,
            t: Some(2),
            curve,
            x: [1u8; 32],
            pk: [0x02u8; 33],
            shares: alloc::vec![[0x02u8; 33], [0x02u8; 33]],
        };
        assert_eq!(
            dealer_round1(&mut rng, 0, curve, 2, b"").err(),
            Some(DklsError::InvalidLength)
        );
        let _ = share;
    }

    #[test]
    fn round1_opening_verifies_and_binds_sid() {
        let mut rng = ChaCha20Rng::from_seed(&[3u8; 32]);
        let curve = CurveId::K1;
        let (dealer, r1, salt) = dealer_round1_opening(&mut rng, 0, curve, 2, b"sid-a").unwrap();
        // The stored opening verifies against round-1's commitment.
        verify(&r1.commitment, &dealer.payload, &salt).unwrap();
        // Round 2 reveals the same opening (no fresh salt).
        let (r2, payload) = dealer_round2(&mut rng, &dealer).unwrap();
        assert_eq!(payload, dealer.payload);
        assert_eq!(r2.salt, salt);
        verify(&r1.commitment, &payload, &r2.salt).unwrap();
        // The payload binds sid-a: cross-session replay is detectable.
        let (psid, feldman, sch, rid) = parse_dkg_payload(&payload, 2).unwrap();
        assert_eq!(psid, b"sid-a");
        assert_eq!(feldman.len(), 2);
        assert_eq!(rid.len(), 32);
        let expect_sch = DklsPoint::generator(curve)
            .mul(&dealer.sch_nonce)
            .to_array_compressed()
            .unwrap();
        assert_eq!(sch, expect_sch);
    }
}
