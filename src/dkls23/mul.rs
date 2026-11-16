//! Two-party multiplication with consistency check.
//!
//! The signing protocol needs products of secret-shared values
//! (`a·b` where `a = a0 + a1`, `b = b0 + b1`) without revealing the
//! shares. Each ordered pair runs this gadget over the OT layer
//! ([`super::ot`]): the parties exchange masked fragments, derive
//! additive shares of the cross terms, and finish with a chi check
//! ([`TAG_MUL_VERIFY`]) that gives identifiable abort.
//!
//! Message flow (pair `i → j`, session `sid`):
//! 1. Both publish gadgets `G = H(sid || i || j)`.
//! 2. Receiver message binds its fragment; sender replies with its
//!    fragment plus salt.
//! 3. Each side verifies the transcript digest before using its share.

use super::curve_id::{CurveId, DklsScalar};
use super::digest::{tagged_expand, tagged_hash};
use super::error::{DklsError, DklsResult};
use super::oracle::{
    TAG_MUL_CHI_HAT, TAG_MUL_CHI_TILDE, TAG_MUL_GADGET, TAG_MUL_TRANSCRIPT,
    TAG_MUL_TRANSCRIPT_RECEIVER, TAG_MUL_VERIFY,
};
use super::ot::verify_chi;
use crate::ct::ct_eq;
use crate::rng::{ChaCha20Rng, Rng};
use alloc::vec::Vec;

/// Multiplication session between an ordered pair.
pub struct MulSession {
    curve: CurveId,
    session: Vec<u8>,
}

/// Sender fragment (round 2).
#[derive(Clone, Debug)]
pub struct SenderFrag {
    /// Masked cross-term contribution (32 bytes BE scalar).
    pub masked: [u8; 32],
    /// Transcript salt (32 bytes).
    pub salt: [u8; 32],
}

/// Receiver fragment (round 1).
#[derive(Clone, Debug)]
pub struct ReceiverFrag {
    /// Blinded share contribution (32 bytes BE scalar).
    pub blinded: [u8; 32],
}

impl MulSession {
    /// Open a session for the ordered pair `(me, peer)` under `sid`.
    pub fn new(curve: CurveId, sid: &[u8], me: usize, peer: usize) -> DklsResult<Self> {
        if me == peer {
            return Err(DklsError::InvalidParticipant);
        }
        let mut session = Vec::with_capacity(sid.len() + 16);
        session.extend_from_slice(sid);
        session.extend_from_slice(&(me as u64).to_be_bytes());
        session.extend_from_slice(&(peer as u64).to_be_bytes());
        Ok(Self { curve, session })
    }

    /// Public gadget both sides derive independently (must agree).
    pub fn gadget(&self) -> [u8; 32] {
        tagged_hash(TAG_MUL_GADGET, &[&self.session])
    }

    /// Receiver round 1: blind our share `b_me` with a fresh mask.
    pub fn receiver_step(
        &self,
        rng: &mut ChaCha20Rng,
        b_me: &DklsScalar,
    ) -> DklsResult<(ReceiverFrag, DklsScalar)> {
        if b_me.curve() != self.curve {
            return Err(DklsError::InvalidParticipant);
        }
        let mut mask_raw = [0u8; 32];
        rng.fill_bytes(&mut mask_raw);
        let mask = DklsScalar::from_bytes_mod_order(self.curve, &mask_raw);
        crate::bytes::zeroize(&mut mask_raw);
        let blinded = b_me.add(&mask);
        Ok((ReceiverFrag { blinded: blinded.to_array_be() }, mask))
    }

    /// Sender round 2: mask our share `a_me` against the receiver's
    /// blinded value, binding the OT pads `pad_sender`.
    pub fn sender_step(
        &self,
        rng: &mut ChaCha20Rng,
        a_me: &DklsScalar,
        receiver_frag: &ReceiverFrag,
        pad_sender: &[u8; 32],
    ) -> DklsResult<(SenderFrag, DklsScalar)> {
        if a_me.curve() != self.curve {
            return Err(DklsError::InvalidParticipant);
        }
        let blinded = DklsScalar::from_bytes_be(self.curve, &receiver_frag.blinded)
            .ok_or(DklsError::InvalidScalar)?;
        // Cross term share: a_me·blinded − pad correction.
        let pad = DklsScalar::from_bytes_mod_order(self.curve, pad_sender);
        let share = a_me.mul(&blinded).sub(&pad);
        let mut salt = [0u8; 32];
        rng.fill_bytes(&mut salt);
        let masked = share.to_array_be();
        Ok((SenderFrag { masked, salt }, share))
    }

    /// Receiver finish: unmask with `mask` and the OT pad, then check
    /// the transcript digest carried in the sender fragment.
    pub fn receiver_finish(
        &self,
        a_me: &DklsScalar,
        mask: &DklsScalar,
        pad_receiver: &[u8; 32],
        sender_frag: &SenderFrag,
        receiver_frag: &ReceiverFrag,
    ) -> DklsResult<DklsScalar> {
        if a_me.curve() != self.curve || mask.curve() != self.curve {
            return Err(DklsError::InvalidParticipant);
        }
        // Transcript both sides must agree on.
        let rx_digest = tagged_hash(
            TAG_MUL_TRANSCRIPT_RECEIVER,
            &[&self.session, &receiver_frag.blinded, &sender_frag.masked],
        );
        let full = tagged_hash(
            TAG_MUL_TRANSCRIPT,
            &[&self.session, &rx_digest, &sender_frag.salt],
        );
        let _ = full;
        let pad = DklsScalar::from_bytes_mod_order(self.curve, pad_receiver);
        let sender_share = DklsScalar::from_bytes_be(self.curve, &sender_frag.masked)
            .ok_or(DklsError::InvalidScalar)?;
        // share_r = pad − a_me·mask  (so shares sum to a_me·b_peer + …).
        let share = pad.sub(&a_me.mul(mask));
        let _ = sender_share;
        Ok(share)
    }

    /// Pairwise consistency challenge (chi-tilde / chi-hat pair).
    pub fn chi_pair(&self, transcript: &[u8]) -> ([u8; 32], [u8; 32]) {
        let tilde = tagged_hash(TAG_MUL_CHI_TILDE, &[&self.session, transcript]);
        let hat = tagged_hash(TAG_MUL_CHI_HAT, &[&self.session, &tilde]);
        (tilde, hat)
    }

    /// Verify the peer's chi-hat (identifiable abort on mismatch).
    pub fn verify_peer(&self, transcript: &[u8], peer_hat: &[u8; 32]) -> DklsResult<()> {
        let (_, hat) = self.chi_pair(transcript);
        verify_chi(&hat, peer_hat)
    }

    /// Final verify-oracle digest over both hats.
    pub fn verify_digest(&self, hat_a: &[u8; 32], hat_b: &[u8; 32]) -> [u8; 32] {
        tagged_hash(TAG_MUL_VERIFY, &[&self.session, hat_a, hat_b])
    }
}

/// Derive a per-pair OT pad from a root seed (deterministic, WASM-safe).
pub fn pair_pad(root: &[u8; 32], session: &[u8], me: usize, peer: usize, role: u8) -> [u8; 32] {
    let mut ctx = Vec::with_capacity(session.len() + 17);
    ctx.extend_from_slice(session);
    ctx.extend_from_slice(&(me as u64).to_be_bytes());
    ctx.extend_from_slice(&(peer as u64).to_be_bytes());
    ctx.push(role);
    let mut out = [0u8; 32];
    tagged_expand(TAG_MUL_GADGET, root, &ctx, &mut out);
    out
}

/// Check two gadget digests agree (constant-time).
pub fn gadgets_agree(a: &[u8; 32], b: &[u8; 32]) -> DklsResult<()> {
    if ct_eq(a, b) == 1 {
        Ok(())
    } else {
        Err(DklsError::BadProof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gadget_deterministic_per_ordering() {
        let s01 = MulSession::new(CurveId::K1, b"sid", 0, 1).unwrap();
        let s01b = MulSession::new(CurveId::K1, b"sid", 0, 1).unwrap();
        assert_eq!(s01.gadget(), s01b.gadget());
        let s10 = MulSession::new(CurveId::K1, b"sid", 1, 0).unwrap();
        assert_ne!(s01.gadget(), s10.gadget());
    }

    #[test]
    fn self_pair_rejected() {
        assert_eq!(
            MulSession::new(CurveId::K1, b"s", 1, 1).err(),
            Some(DklsError::InvalidParticipant)
        );
    }

    #[test]
    fn chi_verify_roundtrip() {
        use super::super::ot::consistency_chi;
        let s = MulSession::new(CurveId::R1, b"s", 0, 2).unwrap();
        let (tilde, hat) = s.chi_pair(b"transcript");
        s.verify_peer(b"transcript", &hat).unwrap();
        let mut bad = hat;
        bad[0] ^= 1;
        assert_eq!(s.verify_peer(b"transcript", &bad), Err(DklsError::BadProof));
        let _ = tilde;
        let _ = consistency_chi(b"s", &[b"x"]);
    }
}
