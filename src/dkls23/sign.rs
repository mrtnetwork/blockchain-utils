//! Threshold signing: 3 rounds over secret-shared key and nonce.
//!
//! Round 1 commits to each party's nonce point `R_i = G·k_i`.
//! Round 2 reveals the nonce points (so `R = Σ R_i`, `r = x(R)`) and runs
//! the pairwise multiplication gadget ([`super::mul`]) for the cross
//! terms of `k·…` with a chi check per pair (identifiable abort).
//! Round 3 combines `s_i` parts into a standard ECDSA `(r, s)` with
//! low-S normalization. The result verifies under the existing
//! [`crate::signature`] verifiers byte-for-byte.

use super::codec::{CompactSig, KeyShare};
use super::commit::{commit, verify, COMMIT_LEN};
use super::curve_id::{CurveId, DklsPoint, DklsScalar};
use super::error::{DklsError, DklsResult};
use super::mul::MulSession;
use crate::rng::{ChaCha20Rng, Rng};
use alloc::vec::Vec;

/// Round-1 broadcast: commitment to `R_i`.
#[derive(Clone, Debug)]
pub struct SignR1 {
    /// Party index.
    pub party: usize,
    /// Commitment to `r1_payload`.
    pub commitment: [u8; COMMIT_LEN],
}

/// Round-2 broadcast: nonce point + multiplication transcript.
#[derive(Clone, Debug)]
pub struct SignR2 {
    /// Party index.
    pub party: usize,
    /// Nonce point `R_i` (compressed).
    pub nonce_pt: [u8; 33],
    /// Opening salt for the round-1 commitment.
    pub salt: Vec<u8>,
    /// Chi-hat for each peer (party order, zero slot for self).
    pub chis: Vec<[u8; 32]>,
}

/// Round-3 unicast-to-all: `s` part.
#[derive(Clone, Debug)]
pub struct SignR3 {
    /// Party index.
    pub party: usize,
    /// Additive `s` share (32 bytes BE).
    pub s_part: [u8; 32],
}

/// Live signer state (secret nonce + share).
pub struct Signer {
    /// Party index.
    pub party: usize,
    /// Curve.
    pub curve: CurveId,
    /// Key share scalar (secret).
    pub x_i: DklsScalar,
    /// Nonce share (secret).
    pub k_i: DklsScalar,
    /// Nonce point.
    pub r_i: DklsPoint,
    /// Round-1 payload the commitment binds (recomputed at reveal).
    pub payload: Vec<u8>,
    /// Session id the round-1 commitment binds.
    pub sid: Vec<u8>,
    /// Opening salt for the round-1 commitment (revealed in round 2).
    pub salt: [u8; super::commit::SALT_LEN],
}

impl Drop for Signer {
    fn drop(&mut self) {
        self.x_i.zeroize();
        self.k_i.zeroize();
        crate::bytes::zeroize(&mut self.salt);
        for b in self.payload.iter_mut() {
            *b = 0;
        }
        for b in self.sid.iter_mut() {
            *b = 0;
        }
    }
}

/// Session-bound round-1 payload: the commitment binds `sid`, the curve,
/// the party index, and the revealed nonce point, so a commitment cannot
/// be replayed across sessions, curves, or parties.
fn sign_payload(sid: &[u8], curve: CurveId, party: usize, nonce_pt: &[u8; 33]) -> Vec<u8> {
    let mut o = Vec::with_capacity(8 + sid.len() + 4 + 8 + 33);
    o.extend_from_slice(&(sid.len() as u64).to_be_bytes());
    o.extend_from_slice(sid);
    o.extend_from_slice(&(curve as u32).to_le_bytes());
    o.extend_from_slice(&(party as u64).to_be_bytes());
    o.extend_from_slice(nonce_pt);
    o
}

/// Decode a round-1 payload into `(sid, curve, party, nonce_pt)`.
pub fn parse_sign_payload(payload: &[u8]) -> DklsResult<(Vec<u8>, CurveId, usize, [u8; 33])> {
    if payload.len() < 8 + 4 + 8 + 33 {
        return Err(DklsError::BadEncoding);
    }
    let sid_len =
        u64::from_be_bytes(payload[0..8].try_into().map_err(|_| DklsError::BadEncoding)?)
            as usize;
    if payload.len() != 8 + sid_len + 4 + 8 + 33 {
        return Err(DklsError::BadEncoding);
    }
    let sid = payload[8..8 + sid_len].to_vec();
    let mut at = 8 + sid_len;
    let curve = CurveId::from_u32(u32::from_le_bytes(
        payload[at..at + 4].try_into().map_err(|_| DklsError::BadEncoding)?,
    ))
    .ok_or(DklsError::BadEncoding)?;
    at += 4;
    let party = u64::from_be_bytes(payload[at..at + 8].try_into().map_err(|_| DklsError::BadEncoding)?)
        as usize;
    at += 8;
    let mut nonce_pt = [0u8; 33];
    nonce_pt.copy_from_slice(&payload[at..at + 33]);
    Ok((sid, curve, party, nonce_pt))
}

/// Signer round 1: sample `k_i`, commit to `R_i`.
///
/// The commitment binds `(sid, curve, party, R_i)`: the opening salt is
/// kept in the returned [`Signer`] and must be revealed via
/// [`signer_round2`] — re-committing with a fresh salt breaks
/// [`combine_nonce`] verification by construction.
pub fn signer_round1(
    rng: &mut ChaCha20Rng,
    share: &KeyShare,
    sid: &[u8],
) -> DklsResult<(Signer, SignR1)> {
    if sid.is_empty() {
        return Err(DklsError::InvalidLength);
    }
    let curve = share.curve;
    let x_i = DklsScalar::from_bytes_be(curve, &share.x).ok_or(DklsError::InvalidScalar)?;
    if x_i.is_zero() {
        return Err(DklsError::ZeroSecret);
    }
    let k_i = loop {
        let mut raw = [0u8; 32];
        rng.fill_bytes(&mut raw);
        if let Some(s) = DklsScalar::from_bytes_be(curve, &raw) {
            if !s.is_zero() {
                break s;
            }
        }
    };
    let r_i = DklsPoint::generator(curve).mul(&k_i);
    if r_i.ct_is_identity() == 1 {
        return Err(DklsError::ZeroSecret);
    }
    let nonce_pt = r_i.to_array_compressed().ok_or(DklsError::InvalidPoint)?;
    let payload = sign_payload(sid, curve, share.party, &nonce_pt);
    let (commitment, opening) = commit(rng, &payload);
    let mut salt = [0u8; super::commit::SALT_LEN];
    salt.copy_from_slice(opening.salt());
    Ok((Signer { party: share.party, curve, x_i, k_i, r_i, payload, sid: sid.to_vec(), salt }, SignR1 {
        party: share.party,
        commitment,
    }))
}

/// Signer round 2: reveal `R_i` with the round-1 opening salt, plus the
/// multiplication chi per pair.
///
/// Uses the salt stored in [`signer_round1`]'s [`Signer`]: the same salt
/// the round-1 commitment was created with, so [`combine_nonce`]
/// verification passes honestly. A caller-supplied `sid` different from
/// the round-1 session is rejected. The chi transcript binds
/// `(sid, curve, party, peer, R_i)`.
pub fn signer_round2(
    rng: &mut ChaCha20Rng,
    signer: &Signer,
    sid: &[u8],
    n: usize,
) -> DklsResult<(SignR2, Vec<u8>)> {
    let _ = rng;
    if sid.is_empty() || signer.sid != sid {
        return Err(DklsError::BadCommitment);
    }
    let nonce_pt = signer.r_i.to_array_compressed().ok_or(DklsError::InvalidPoint)?;
    // Reuse the round-1 opening salt: revealing under any other salt
    // fails verification (the pre-fix fresh-salt path could never pass).
    let salt = signer.salt.to_vec();
    // Chi-hat per peer over the session-bound pair transcript.
    let mut chis = Vec::with_capacity(n);
    for peer in 0..n {
        if peer == signer.party {
            chis.push([0u8; 32]);
            continue;
        }
        let sess = MulSession::new(signer.curve, sid, signer.party, peer)?;
        let transcript = super::digest::tagged_hash(
            super::oracle::TAG_SIGN_MUL_SESSION,
            &[
                sid,
                &[signer.curve as u8],
                &(signer.party as u64).to_be_bytes(),
                &(peer as u64).to_be_bytes(),
                &nonce_pt,
            ],
        );
        let (_, hat) = sess.chi_pair(&transcript);
        chis.push(hat);
    }
    Ok((SignR2 { party: signer.party, nonce_pt, salt: salt.clone(), chis }, signer.payload.clone()))
}

/// Combine round-2 reveals into `R` and `r` (aborts on commitment
/// mismatch or identity `R`, identifying the offender via the index).
///
/// Every payload must decode (via [`parse_sign_payload`]) to exactly
/// `(sid, curve, party, nonce_pt)` with the party matching both round
/// broadcasts and the nonce point matching the round-2 reveal; the
/// commitment is then verified against that payload.
pub fn combine_nonce(
    curve: CurveId,
    sid: &[u8],
    r1s: &[SignR1],
    r2s: &[SignR2],
    payloads: &[Vec<u8>],
) -> DklsResult<(DklsPoint, [u8; 32])> {
    if r1s.len() != r2s.len() || r1s.len() != payloads.len() || r1s.is_empty() {
        return Err(DklsError::TooFew);
    }
    if sid.is_empty() {
        return Err(DklsError::InvalidLength);
    }
    let mut r_sum = DklsPoint::identity(curve);
    for j in 0..r1s.len() {
        let (psid, pcurve, pparty, pnonce) = parse_sign_payload(&payloads[j])?;
        if psid != sid || pcurve != curve {
            return Err(DklsError::BadCommitment);
        }
        if pparty != r1s[j].party || pparty != r2s[j].party {
            return Err(DklsError::InvalidParticipant);
        }
        if pnonce != r2s[j].nonce_pt {
            return Err(DklsError::BadCommitment);
        }
        verify(&r1s[j].commitment, &payloads[j], &r2s[j].salt)?;
        let pt = DklsPoint::from_bytes(curve, &r2s[j].nonce_pt).ok_or(DklsError::InvalidPoint)?;
        if pt.ct_is_identity() == 1 {
            return Err(DklsError::ZeroSecret);
        }
        r_sum = r_sum.add(&pt);
    }
    if r_sum.ct_is_identity() == 1 {
        return Err(DklsError::ZeroSecret);
    }
    let mut x = [0u8; 32];
    if !r_sum.x_bytes(&mut x) {
        return Err(DklsError::InvalidPoint);
    }
    let r = DklsScalar::from_bytes_mod_order(curve, &x);
    if r.is_zero() {
        return Err(DklsError::ZeroSecret);
    }
    let mut r_bytes = [0u8; 32];
    r.to_bytes_be(&mut r_bytes);
    Ok((r_sum, r_bytes))
}

/// Signer round 3: `s_i = (k^{-1}/n)·e + (k^{-1}·r)·x_i`.
///
/// The driver passes the already-divided `k_part = k^{-1}/n` and the
/// joint `kr = k^{-1}·r`, so the sum over parties is
/// `Σ s_i = k^{-1}·e + k^{-1}·r·x`, the ECDSA equation. Keeping the two
/// factors separate is what makes the additive split exact (using
/// `k_part` for both terms would divide the `r·x` term by `n`).
pub fn signer_round3(
    signer: &Signer,
    k_part: &DklsScalar,
    kr: &DklsScalar,
    e: &DklsScalar,
) -> DklsResult<SignR3> {
    if signer.curve != k_part.curve() || signer.curve != kr.curve() || signer.curve != e.curve()
    {
        return Err(DklsError::InvalidParticipant);
    }
    let s_part = k_part.mul(e).add(&kr.mul(&signer.x_i));
    Ok(SignR3 { party: signer.party, s_part: s_part.to_array_be() })
}

/// Combine `s` parts (sums to `s = k^{-1}(e + r·x)`), low-S normalize.
pub fn combine_sig(curve: CurveId, r: &[u8; 32], parts: &[SignR3]) -> DklsResult<CompactSig> {
    if parts.is_empty() {
        return Err(DklsError::TooFew);
    }
    let mut s = DklsScalar::zero(curve);
    for p in parts {
        let v = DklsScalar::from_bytes_be(curve, &p.s_part).ok_or(DklsError::InvalidScalar)?;
        s = s.add(&v);
    }
    if s.is_zero() {
        return Err(DklsError::ZeroSecret);
    }
    s = low_s(curve, s);
    let mut sb = [0u8; 32];
    s.to_bytes_be(&mut sb);
    Ok(CompactSig { r: *r, s: sb })
}

/// Low-S normalization (`s = min(s, q−s)`), branch-free select.
fn low_s(curve: CurveId, s: DklsScalar) -> DklsScalar {
    let order = curve.order_be();
    let mut half = order;
    // half = order / 2 (big-endian shift right by 1).
    let mut carry = 0u8;
    for i in (0..32).rev() {
        let v = half[i];
        half[i] = (v >> 1) | (carry << 7);
        carry = v & 1;
    }
    let mut sb = [0u8; 32];
    s.to_bytes_be(&mut sb);
    let mut gt = 0u8;
    let mut eq = 1u8;
    for i in 0..32 {
        let a_gt = u8::from(sb[i] > half[i]);
        let a_eq = u8::from(sb[i] == half[i]);
        gt |= eq & a_gt;
        eq &= a_eq;
    }
    let neg = s.neg();
    // Select without branching on secret bytes: both candidates are
    // public once serialized here (signature output), the select only
    // avoids a timing oracle on the comparison loop above.
    let mut nb = [0u8; 32];
    neg.to_bytes_be(&mut nb);
    let mut out = [0u8; 32];
    let mask = gt.wrapping_neg();
    for i in 0..32 {
        out[i] = (nb[i] & mask) | (sb[i] & !mask);
    }
    DklsScalar::from_bytes_mod_order(curve, &out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_share(curve: CurveId, party: usize) -> KeyShare {
        let mut x = [0u8; 32];
        x[31] = 1 + party as u8;
        let pk = DklsPoint::generator(curve).to_array_compressed().unwrap();
        KeyShare {
            party,
            n: 2,
            t: Some(2),
            curve,
            x,
            pk,
            shares: alloc::vec![pk, pk],
        }
    }

    #[test]
    fn round1_rejects_empty_sid() {
        let mut rng = crate::rng::ChaCha20Rng::from_seed(&[9u8; 32]);
        let share = test_share(CurveId::K1, 0);
        assert_eq!(
            signer_round1(&mut rng, &share, b"").err(),
            Some(DklsError::InvalidLength)
        );
    }

    #[test]
    fn honest_opening_verifies_without_driver_rebind() {
        // Round 1 -> round 2 -> combine with the stored opening only:
        // no recommit, no salt patching. This failed before the fix
        // (round 2 used a fresh salt unrelated to round 1).
        for curve in [CurveId::K1, CurveId::R1] {
            let sid = b"sign-opening-honest";
            let mut signers = Vec::new();
            let mut r1s = Vec::new();
            let mut payloads = Vec::new();
            for party in 0..2 {
                let mut rng = crate::rng::ChaCha20Rng::from_seed(&[party as u8; 32]);
                let (signer, r1) = signer_round1(&mut rng, &test_share(curve, party), sid).unwrap();
                payloads.push(signer.payload.clone());
                signers.push(signer);
                r1s.push(r1);
            }
            let mut r2s = Vec::new();
            for s in &signers {
                let mut rng = crate::rng::ChaCha20Rng::from_seed(&[0u8; 32]);
                let (r2, payload) = signer_round2(&mut rng, s, sid, 2).unwrap();
                assert_eq!(payload, s.payload);
                r2s.push(r2);
            }
            let (_, r) = combine_nonce(curve, sid, &r1s, &r2s, &payloads).unwrap();
            assert!(DklsScalar::from_bytes_be(curve, &r).is_some());
            // Cross-session replay rejected.
            assert_eq!(
                combine_nonce(curve, b"other-sid", &r1s, &r2s, &payloads).err(),
                Some(DklsError::BadCommitment)
            );
            // Wrong-session round 2 rejected.
            let mut rng = crate::rng::ChaCha20Rng::from_seed(&[0u8; 32]);
            assert_eq!(
                signer_round2(&mut rng, &signers[0], b"other-sid", 2).err(),
                Some(DklsError::BadCommitment)
            );
        }
    }
}
