//! Wire codec: LE-framed blobs for DKG / signing / refresh.
//!
//! All integers little-endian on the wire; scalars 32-byte big-endian,
//! points 33-byte compressed, hashes 32 bytes. Variable-length vectors
//! are framed as `[len:u32 LE] ++ bytes`; whole messages are framed the
//! same way so FFI/WASM layers can split streams without parsing.
//!
//! Blob inventory (all `Vec<u8>`, curve-agnostic):
//! - `DkgR1 = com(32) ++ pk(33) ++ proof(commit33 ++ resp32)`
//! - `DkgR2 = opening(msg ++ salt64) ++ Feldman F(t*33) ++ schnorr proof`
//! - `Share = i(4) ++ n(4) ++ t(4, 0 = none) ++ x(32) ++ pk(33) ++
//!   shares(n*33)`
//! - `SignR1 = com(32) ++ R-point(33)`
//! - `SignR2 = masked-share(32) ++ salt(32) ++ chi(32)`
//! - `SignR3 = s-part(32)`
//! - `RefreshR1 = com(32) ++ delta-pk(33)`

use super::curve_id::CurveId;
use super::error::{DklsError, DklsResult};
use super::schnorr::DlogProof;
use alloc::vec::Vec;

/// Frame items as `[len:u32 LE] ++ bytes` concatenations.
pub fn frame(items: &[Vec<u8>]) -> Vec<u8> {
    let mut o = Vec::new();
    for it in items {
        o.extend_from_slice(&(it.len() as u32).to_le_bytes());
        o.extend_from_slice(it);
    }
    o
}

/// Inverse of [`frame`]; `None` on truncation or trailing bytes.
pub fn unframe(blob: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut o = Vec::new();
    let mut at = 0usize;
    while at < blob.len() {
        if at + 4 > blob.len() {
            return None;
        }
        let len =
            u32::from_le_bytes([blob[at], blob[at + 1], blob[at + 2], blob[at + 3]]) as usize;
        at += 4;
        if at + len > blob.len() {
            return None;
        }
        o.push(blob[at..at + len].to_vec());
        at += len;
    }
    Some(o)
}

fn take(raw: &[u8], n: usize) -> DklsResult<(&[u8], &[u8])> {
    if raw.len() < n {
        return Err(DklsError::BadEncoding);
    }
    Ok((&raw[..n], &raw[n..]))
}

fn rd_u32(raw: &[u8]) -> DklsResult<(u32, &[u8])> {
    let (b, r) = take(raw, 4)?;
    Ok((u32::from_le_bytes([b[0], b[1], b[2], b[3]]), r))
}

/// A persisted threshold key share.
#[derive(Clone, Debug)]
pub struct KeyShare {
    /// Party index.
    pub party: usize,
    /// Committee size.
    pub n: usize,
    /// Threshold (`None` = additive n-of-n).
    pub t: Option<usize>,
    /// Curve selector.
    pub curve: CurveId,
    /// Secret share (32 bytes BE).
    pub x: [u8; 32],
    /// Group public key (33 bytes compressed).
    pub pk: [u8; 33],
    /// Member public shares (party order, 33 bytes each).
    pub shares: Vec<[u8; 33]>,
}

impl Drop for KeyShare {
    fn drop(&mut self) {
        crate::bytes::zeroize(&mut self.x);
    }
}

/// Encode a [`KeyShare`] (unframed; callers frame).
pub fn keyshare_bytes(sh: &KeyShare) -> Vec<u8> {
    let mut o = Vec::new();
    o.extend_from_slice(&(sh.party as u32).to_le_bytes());
    o.extend_from_slice(&(sh.n as u32).to_le_bytes());
    o.extend_from_slice(&(sh.t.unwrap_or(0) as u32).to_le_bytes());
    o.extend_from_slice(&(sh.curve as u32).to_le_bytes());
    o.extend_from_slice(&sh.x);
    o.extend_from_slice(&sh.pk);
    for s in &sh.shares {
        o.extend_from_slice(s);
    }
    o
}

/// Decode a [`KeyShare`].
pub fn parse_keyshare(raw: &[u8]) -> DklsResult<KeyShare> {
    let (party, r) = rd_u32(raw)?;
    let (n, r) = rd_u32(r)?;
    let (t, r) = rd_u32(r)?;
    let (curve_raw, r) = rd_u32(r)?;
    let curve = CurveId::from_u32(curve_raw).ok_or(DklsError::BadEncoding)?;
    let (x, r) = take(r, 32)?;
    let (pk, r) = take(r, 33)?;
    if r.len() != n as usize * 33 {
        return Err(DklsError::BadEncoding);
    }
    let mut shares = Vec::with_capacity(n as usize);
    for k in 0..n as usize {
        let mut s = [0u8; 33];
        s.copy_from_slice(&r[k * 33..(k + 1) * 33]);
        shares.push(s);
    }
    let mut xb = [0u8; 32];
    let mut pkb = [0u8; 33];
    xb.copy_from_slice(x);
    pkb.copy_from_slice(pk);
    Ok(KeyShare {
        party: party as usize,
        n: n as usize,
        t: if t == 0 { None } else { Some(t as usize) },
        curve,
        x: xb,
        pk: pkb,
        shares,
    })
}

/// Encode a [`DlogProof`] (65 bytes: `commit33 ++ resp32`).
pub fn proof_bytes(p: &DlogProof) -> Vec<u8> {
    let mut o = Vec::with_capacity(65);
    o.extend_from_slice(&p.commitment);
    o.extend_from_slice(&p.response);
    o
}

/// Decode a [`DlogProof`] (65 bytes).
pub fn parse_proof(raw: &[u8]) -> DklsResult<DlogProof> {
    let (c, r) = take(raw, 33)?;
    let (z, r) = take(r, 32)?;
    if !r.is_empty() {
        return Err(DklsError::BadEncoding);
    }
    let mut commitment = [0u8; 33];
    let mut response = [0u8; 32];
    commitment.copy_from_slice(c);
    response.copy_from_slice(z);
    Ok(DlogProof { commitment, response })
}

/// Compact ECDSA signature bytes (`r32 || s32`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompactSig {
    /// `r` (32 bytes BE).
    pub r: [u8; 32],
    /// `s` (32 bytes BE, low-S normalized).
    pub s: [u8; 32],
}

impl CompactSig {
    /// Serialize to 64 bytes.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut o = [0u8; 64];
        o[..32].copy_from_slice(&self.r);
        o[32..].copy_from_slice(&self.s);
        o
    }

    /// Parse from 64 bytes.
    pub fn from_bytes(raw: &[u8]) -> DklsResult<Self> {
        if raw.len() != 64 {
            return Err(DklsError::InvalidLength);
        }
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&raw[..32]);
        s.copy_from_slice(&raw[32..]);
        Ok(Self { r, s })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip() {
        let items = alloc::vec![alloc::vec![1u8, 2], alloc::vec![], alloc::vec![3u8; 100]];
        let f = frame(&items);
        assert_eq!(unframe(&f).unwrap(), items);
        assert!(unframe(&f[..f.len() - 1]).is_none());
    }

    #[test]
    fn keyshare_roundtrip_both_curves() {
        for curve in [CurveId::K1, CurveId::R1] {
            let sh = KeyShare {
                party: 1,
                n: 2,
                t: None,
                curve,
                x: [9u8; 32],
                pk: [0x02u8; 33],
                shares: alloc::vec![[0x02u8; 33], [0x03u8; 33]],
            };
            let raw = keyshare_bytes(&sh);
            let back = parse_keyshare(&raw).unwrap();
            assert_eq!(back.party, 1);
            assert_eq!(back.curve, curve);
            assert_eq!(back.shares.len(), 2);
        }
    }

    #[test]
    fn compact_sig_roundtrip() {
        let s = CompactSig { r: [1u8; 32], s: [2u8; 32] };
        assert_eq!(CompactSig::from_bytes(&s.to_bytes()).unwrap(), s);
        assert_eq!(CompactSig::from_bytes(&[0u8; 63]), Err(DklsError::InvalidLength));
    }
}
