//! High-level threshold key API for MuSig2 keys.
//!
//! - [`DklsKeyGroup`] ~ `Musig2PrivateKey`: holds every party's
//!   secret share plus the aggregate key; `generate()` runs DKG,
//!   `sign()` thresholds-signs with any `t`-subset, `verifying_key()`
//!   returns the aggregate key.
//! - [`DklsAggregatePublicKey`] ~ `MuSig2AggregatePublicKey`:
//!   group key + member keys; `agg_public_keys()`, `x_only()`,
//!   `verify()` / `verify_aggregate()`.
//! - [`ThresholdSignature`]: standard 64-byte compact ECDSA `(r || s)`.
//!
//! Single-share holders use [`DklsPrivateKey`]. Only the aggregate key
//! implements [`VerifyingKey`]: one share alone can never sign (that is
//! the threshold property), so there is deliberately no single-key
//! [`SigningKey`] impl — signing always goes through the group over a
//! qualifying subset.

use super::codec::{keyshare_bytes, parse_keyshare, KeyShare};
use super::curve_id::{CurveId, DklsPoint};
use super::error::{DklsError, DklsResult};
use super::session::{dkg_oneshot, sign_oneshot};
use crate::error::{Error, Result};
use crate::keys::{CryptoKeyType, VerifyingKey};
use alloc::vec::Vec;

/// Standard threshold ECDSA signature: compact `r || s` (64 bytes).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThresholdSignature {
    /// `r` (32 bytes BE).
    pub r: [u8; 32],
    /// `s` (32 bytes BE, low-S normalized).
    pub s: [u8; 32],
}

impl ThresholdSignature {
    /// Serialize to 64 bytes.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut o = [0u8; 64];
        o[..32].copy_from_slice(&self.r);
        o[32..].copy_from_slice(&self.s);
        o
    }

    /// Parse from 64 bytes.
    pub fn from_bytes(raw: &[u8]) -> DklsResult<Self> {
        let cs = super::codec::CompactSig::from_bytes(raw)?;
        Ok(Self { r: cs.r, s: cs.s })
    }
}

/// Aggregate (group) public key: the key a verifier checks the final
/// signature against, plus the member keys the quorum was built from.
#[derive(Clone, Debug)]
pub struct DklsAggregatePublicKey {
    curve: CurveId,
    group_pk: [u8; 33],
    members: Vec<[u8; 33]>,
}

impl DklsAggregatePublicKey {
    /// Aggregate member public keys by point addition
    /// (`agg = Σ members`). Members must be non-identity points on
    /// `curve`; needs at least 2 (mirrors the MuSig2 minimum).
    pub fn agg_public_keys(curve: CurveId, members: &[[u8; 33]]) -> DklsResult<Self> {
        if members.len() < 2 {
            return Err(DklsError::TooFew);
        }
        let mut agg = DklsPoint::identity(curve);
        for m in members {
            let pt = DklsPoint::from_bytes(curve, m).ok_or(DklsError::InvalidPoint)?;
            if pt.ct_is_identity() == 1 {
                return Err(DklsError::ZeroSecret);
            }
            agg = agg.add(&pt);
        }
        if agg.ct_is_identity() == 1 {
            return Err(DklsError::ZeroSecret);
        }
        Ok(Self {
            curve,
            group_pk: agg.to_array_compressed().ok_or(DklsError::InvalidPoint)?,
            members: members.to_vec(),
        })
    }

    /// Build from a DKG-issued group key and member keys.
    pub fn from_group_key(
        curve: CurveId,
        group_pk: [u8; 33],
        members: Vec<[u8; 33]>,
    ) -> DklsResult<Self> {
        if members.len() < 2 {
            return Err(DklsError::TooFew);
        }
        let pt = DklsPoint::from_bytes(curve, &group_pk).ok_or(DklsError::InvalidPoint)?;
        if pt.ct_is_identity() == 1 {
            return Err(DklsError::ZeroSecret);
        }
        for m in &members {
            let p = DklsPoint::from_bytes(curve, m).ok_or(DklsError::InvalidPoint)?;
            if p.ct_is_identity() == 1 {
                return Err(DklsError::ZeroSecret);
            }
        }
        Ok(Self { curve, group_pk, members })
    }

    /// Curve of this key.
    pub fn curve(&self) -> CurveId {
        self.curve
    }

    /// Group public key (33-byte compressed).
    pub fn group_key(&self) -> &[u8; 33] {
        &self.group_pk
    }

    /// Member public keys (DKG order).
    pub fn members(&self) -> &[[u8; 33]] {
        &self.members
    }

    /// 32-byte x-only form (BIP-340 style verifier input).
    pub fn x_only(&self) -> DklsResult<[u8; 32]> {
        group_x_only(self.curve, &self.group_pk)
    }

    /// Verify a threshold signature over a 32-byte message hash.
    pub fn verify_hash(&self, msg_hash: &[u8; 32], sig: &ThresholdSignature) -> DklsResult<()> {
        let raw = sig.to_bytes();
        match self.curve {
            CurveId::K1 => {
                let pk = crate::signature::ecdsa::PublicKey::from_bytes(&self.group_pk)
                    .map_err(|_| DklsError::InvalidPoint)?;
                let s = crate::signature::ecdsa::Signature::from_compact(&raw)
                    .map_err(|_| DklsError::InvalidScalar)?;
                crate::signature::ecdsa::verify(&pk, msg_hash, &s)
                    .map_err(|_| DklsError::BadProof)?;
                Ok(())
            }
            CurveId::R1 => {
                let pk = crate::signature::ecdsa_p256::PublicKey::from_bytes(&self.group_pk)
                    .map_err(|_| DklsError::InvalidPoint)?;
                let s = crate::signature::ecdsa_p256::Signature::from_compact(&raw)
                    .map_err(|_| DklsError::InvalidScalar)?;
                crate::signature::ecdsa_p256::verify(&pk, msg_hash, &s)
                    .map_err(|_| DklsError::BadProof)?;
                Ok(())
            }
        }
    }

    /// Verify the final aggregated signature over a message
    /// (SHA-256 hashed first, like the `keys` trait verifiers).
    /// Same check as [`verify_hash`](Self::verify_hash) modulo hashing.
    pub fn verify_aggregate(&self, message: &[u8], sig: &ThresholdSignature) -> DklsResult<()> {
        let h = crate::hash::sha256::sha256(message).map_err(|_| DklsError::Internal)?;
        self.verify_hash(&h, sig)
    }

    /// Serialize: `[curve:u32 LE][agg:33][n:u32 LE][members: n*33]`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut o = Vec::with_capacity(4 + 33 + 4 + self.members.len() * 33);
        o.extend_from_slice(&(self.curve as u32).to_le_bytes());
        o.extend_from_slice(&self.group_pk);
        o.extend_from_slice(&(self.members.len() as u32).to_le_bytes());
        for m in &self.members {
            o.extend_from_slice(m);
        }
        o
    }

    /// Parse [`to_bytes`](Self::to_bytes).
    pub fn from_bytes(raw: &[u8]) -> DklsResult<Self> {
        if raw.len() < 4 + 33 + 4 {
            return Err(DklsError::BadEncoding);
        }
        let curve = CurveId::from_u32(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
            .ok_or(DklsError::BadEncoding)?;
        let mut pk = [0u8; 33];
        pk.copy_from_slice(&raw[4..37]);
        let n = u32::from_le_bytes([raw[37], raw[38], raw[39], raw[40]]) as usize;
        if raw.len() != 4 + 33 + 4 + n * 33 {
            return Err(DklsError::BadEncoding);
        }
        let mut members = Vec::with_capacity(n);
        for i in 0..n {
            let mut m = [0u8; 33];
            m.copy_from_slice(&raw[41 + i * 33..41 + (i + 1) * 33]);
            members.push(m);
        }
        Self::from_group_key(curve, pk, members)
    }
}

impl VerifyingKey for DklsAggregatePublicKey {
    fn key_type(&self) -> CryptoKeyType {
        match self.curve {
            CurveId::K1 => CryptoKeyType::Dkls23K1,
            CurveId::R1 => CryptoKeyType::Dkls23R1,
        }
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        let sig = ThresholdSignature::from_bytes(signature).map_err(|_| Error::InvalidSignature)?;
        match self.verify_aggregate(message, &sig) {
            Ok(()) => Ok(true),
            Err(DklsError::BadProof) => Ok(false),
            Err(_) => Err(Error::InvalidSignature),
        }
    }

    fn public_key_len(&self) -> usize {
        4 + 33 + 4 + self.members.len() * 33
    }

    fn to_public_bytes(&self, out: &mut [u8]) -> Result<()> {
        let b = self.to_bytes();
        if out.len() < b.len() {
            return Err(Error::InvalidLength);
        }
        out[..b.len()].copy_from_slice(&b);
        Ok(())
    }
}

/// X-only form of a group key without needing the member list.
pub fn group_x_only(curve: CurveId, group_pk: &[u8; 33]) -> DklsResult<[u8; 32]> {
    let pt = DklsPoint::from_bytes(curve, group_pk).ok_or(DklsError::InvalidPoint)?;
    if pt.ct_is_identity() == 1 {
        return Err(DklsError::ZeroSecret);
    }
    let mut x = [0u8; 32];
    if !pt.x_bytes(&mut x) {
        return Err(DklsError::InvalidPoint);
    }
    Ok(x)
}
/// One party's secret share plus the group view. The share is wiped on
/// drop; clone only to move it into a new owner.
#[derive(Clone, Debug)]
pub struct DklsPrivateKey {
    share: KeyShare,
}

impl DklsPrivateKey {
    /// Wrap a DKG-issued share.
    pub fn partial(share: KeyShare) -> Self {
        Self { share }
    }

    /// Borrow the share (e.g. to assemble a signing subset).
    pub fn share(&self) -> &KeyShare {
        &self.share
    }

    /// Party index.
    pub fn party(&self) -> usize {
        self.share.party
    }

    /// Aggregate key for this share's group.
    pub fn aggregate_key(&self) -> DklsResult<DklsAggregatePublicKey> {
        DklsAggregatePublicKey::from_group_key(
            self.share.curve,
            self.share.pk,
            self.share.shares.clone(),
        )
    }

    /// Wipe the secret share in place.
    pub fn zeroize(&mut self) {
        crate::bytes::zeroize(&mut self.share.x);
    }

    /// Serialize: framed [`keyshare_bytes`](super::codec::keyshare_bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        super::codec::frame(&[keyshare_bytes(&self.share)])
    }

    /// Parse [`to_bytes`](Self::to_bytes).
    pub fn from_bytes(raw: &[u8]) -> DklsResult<Self> {
        let frames = super::codec::unframe(raw).ok_or(DklsError::BadEncoding)?;
        if frames.len() != 1 {
            return Err(DklsError::BadEncoding);
        }
        Ok(Self { share: parse_keyshare(&frames[0])? })
    }
}

impl Drop for DklsPrivateKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// The coordinator view: every party's secret (test / dealer / single
/// process holding the quorum), mirroring `Musig2PrivateKey` which
/// holds `secretKeys` alongside the aggregate key.
#[derive(Clone, Debug)]
pub struct DklsKeyGroup {
    keys: Vec<DklsPrivateKey>,
    aggregate: DklsAggregatePublicKey,
}

impl DklsKeyGroup {
    /// Run DKG and collect all `n` party keys (threshold `t`).
    /// `seeds[i]` belongs to party `i`; deterministic under `(seeds, sid)`.
    pub fn generate(
        curve: CurveId,
        sid: &[u8],
        n: usize,
        t: usize,
        seeds: &[[u8; 32]],
    ) -> DklsResult<Self> {
        let shares = dkg_oneshot(curve, sid, n, t, seeds)?;
        Self::from_shares(shares)
    }

    /// Assemble from existing shares (all must share one group key).
    pub fn from_shares(shares: Vec<KeyShare>) -> DklsResult<Self> {
        if shares.is_empty() {
            return Err(DklsError::TooFew);
        }
        let curve = shares[0].curve;
        let pk = shares[0].pk;
        for s in &shares {
            if s.curve != curve || s.pk != pk {
                return Err(DklsError::InvalidParticipant);
            }
        }
        let aggregate =
            DklsAggregatePublicKey::from_group_key(curve, pk, shares[0].shares.clone())?;
        Ok(Self {
            keys: shares.into_iter().map(DklsPrivateKey::partial).collect(),
            aggregate,
        })
    }

    /// Party keys (index = position in the group, not party id).
    pub fn keys(&self) -> &[DklsPrivateKey] {
        &self.keys
    }

    /// Aggregate (verifying) key.
    pub fn verifying_key(&self) -> DklsAggregatePublicKey {
        self.aggregate.clone()
    }

    /// Threshold `t` of this group (`None` = additive n-of-n).
    pub fn threshold(&self) -> Option<usize> {
        self.keys.first().and_then(|k| k.share.t)
    }

    /// Sign `message` (SHA-256 hashed first) with parties `subset`
    /// (party indexes into [`keys`](Self::keys), length `>= t`).
    /// mirrors the reference implementation
    /// aggregate, returning the final signature.
    pub fn sign(
        &self,
        sid: &[u8],
        message: &[u8],
        subset: &[usize],
        seeds: &[[u8; 32]],
    ) -> DklsResult<ThresholdSignature> {
        let t = self.threshold().unwrap_or(self.keys.len());
        if subset.len() < t || seeds.len() != subset.len() {
            return Err(DklsError::TooFew);
        }
        let mut shares = Vec::with_capacity(subset.len());
        for &i in subset {
            shares.push(self.keys.get(i).ok_or(DklsError::InvalidParticipant)?.share.clone());
        }
        let h = crate::hash::sha256::sha256(message).map_err(|_| DklsError::Internal)?;
        let cs = sign_oneshot(&shares, sid, &h, seeds)?;
        Ok(ThresholdSignature { r: cs.r, s: cs.s })
    }

    /// Serialize: framed share records (same as the FFI blob).
    pub fn to_bytes(&self) -> Vec<u8> {
        let frames: Vec<Vec<u8>> = self.keys.iter().map(|k| keyshare_bytes(&k.share)).collect();
        super::codec::frame(&frames)
    }

    /// Parse [`to_bytes`](Self::to_bytes).
    pub fn from_bytes(raw: &[u8]) -> DklsResult<Self> {
        let frames = super::codec::unframe(raw).ok_or(DklsError::BadEncoding)?;
        let mut shares = Vec::with_capacity(frames.len());
        for f in &frames {
            shares.push(parse_keyshare(f)?);
        }
        Self::from_shares(shares)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SignatureBytes;

    fn seeds<const N: usize>(base: u8) -> [[u8; 32]; N] {
        let mut out = [[0u8; 32]; N];
        for (i, s) in out.iter_mut().enumerate() {
            for b in s.iter_mut() {
                *b = base.wrapping_add(i as u8);
            }
        }
        out
    }

    fn group_flow(curve: CurveId) {
        let sid = b"keys-api-kat";
        let group = DklsKeyGroup::generate(curve, sid, 2, 2, &seeds::<2>(0xE0)).unwrap();
        assert_eq!(group.threshold(), Some(2));
        // Aggregate key shape: 33-byte group key + 2 members.
        let agg = group.verifying_key();
        assert_eq!(agg.members().len(), 2);
        let mut full = alloc::vec![0u8; agg.public_key_len()];
        agg.to_public_bytes(&mut full).unwrap();
        assert_eq!(&full[4..37], agg.group_key());
        // Short buffer rejected loudly.
        let mut short = [0u8; 8];
        assert!(agg.to_public_bytes(&mut short).is_err());
        // x-only is the x-coordinate of the group key.
        let x = agg.x_only().unwrap();
        assert_eq!(&x, &agg.group_key()[1..33]);
        // Sign via the group (both parties) and verify both ways.
        let sig = group.sign(sid, b"keys api message", &[0, 1], &seeds::<2>(0xE1)).unwrap();
        let raw = sig.to_bytes();
        assert_eq!(ThresholdSignature::from_bytes(&raw).unwrap(), sig);
        assert!(agg.verify(b"keys api message", &raw).unwrap());
        assert!(agg.verify_aggregate(b"keys api message", &sig).is_ok());
        // Wrong message fails (false, not error).
        assert!(!agg.verify(b"other", &raw).unwrap());
        // Serialization roundtrips.
        let blob = group.to_bytes();
        let back = DklsKeyGroup::from_bytes(&blob).unwrap();
        assert_eq!(back.verifying_key().group_key(), agg.group_key());
        let pk_blob = agg.to_bytes();
        let pk_back = DklsAggregatePublicKey::from_bytes(&pk_blob).unwrap();
        assert_eq!(pk_back.group_key(), agg.group_key());
        // Single private key: share access + aggregate derivation.
        let one = &group.keys()[0];
        assert_eq!(one.aggregate_key().unwrap().group_key(), agg.group_key());
        let sk_blob = one.to_bytes();
        assert_eq!(DklsPrivateKey::from_bytes(&sk_blob).unwrap().party(), one.party());
    }

    #[test]
    fn keys_api_k1() {
        group_flow(CurveId::K1);
    }

    #[test]
    fn keys_api_r1() {
        group_flow(CurveId::R1);
    }

    #[test]
    fn agg_rejects_singleton_and_identity() {
        let g = DklsPoint::generator(CurveId::K1).to_array_compressed().unwrap();
        assert_eq!(
            DklsAggregatePublicKey::agg_public_keys(CurveId::K1, &[g]).err(),
            Some(DklsError::TooFew)
        );
        assert_eq!(
            DklsAggregatePublicKey::agg_public_keys(CurveId::K1, &[g, [0u8; 33]]).err(),
            Some(DklsError::ZeroSecret)
        );
        // Summed members verify under the summed key.
        let agg = DklsAggregatePublicKey::agg_public_keys(CurveId::K1, &[g, g]).unwrap();
        let expect = DklsPoint::generator(CurveId::K1)
            .add(&DklsPoint::generator(CurveId::K1))
            .to_array_compressed()
            .unwrap();
        assert_eq!(agg.group_key(), &expect);
    }

    #[test]
    fn key_type_tags_match_curve() {
        let sid = b"keys-tag";
        let gk = DklsKeyGroup::generate(CurveId::K1, sid, 2, 2, &seeds::<2>(0xF0)).unwrap();
        assert_eq!(gk.verifying_key().key_type(), CryptoKeyType::Dkls23K1);
        let gr = DklsKeyGroup::generate(CurveId::R1, sid, 2, 2, &seeds::<2>(0xF0)).unwrap();
        assert_eq!(gr.verifying_key().key_type(), CryptoKeyType::Dkls23R1);
        let _ = SignatureBytes::new(alloc::vec::Vec::new());
    }
}
