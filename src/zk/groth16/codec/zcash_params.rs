//! Zcash / Bellman `Parameters` + `VerifyingKey` binary format (Sapling spend/output).
//!
//! Matches `bellman::groth16::{VerifyingKey,Parameters}::{read,write}`:
//! - Points are **uncompressed** (G1=96, G2=192).
//! - Vector lengths are **u32 big-endian**.
//! - Order: VK, then `h`, `l`, `a`, `b_g1`, `b_g2` query tables.
//!
//! Sapling spend file (`sapling-spend.params`) is ~48 MB; this module only
//! parses bytes — callers load the file externally.

use crate::curve::bls::{G1Point, G2Point};
use crate::curve::traits::CurvePoint;
use crate::zk::groth16::verify::{Groth16Error, Groth16Result, VerifyingKey};
// `Vec` is prelude under `std`; import from `alloc` only for `no_std`.
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

const G1_U: usize = 96;
const G2_U: usize = 192;

/// Full Bellman verifying key (includes β/δ in G1 used by the prover).
#[derive(Clone, Debug)]
pub struct BellmanVerifyingKey {
    pub alpha_g1: G1Point,
    pub beta_g1: G1Point,
    pub beta_g2: G2Point,
    pub gamma_g2: G2Point,
    pub delta_g1: G1Point,
    pub delta_g2: G2Point,
    pub ic: Vec<G1Point>,
}

impl BellmanVerifyingKey {
    /// Subset used by the pairing verifier.
    pub fn to_verifying_key(&self) -> VerifyingKey {
        VerifyingKey::new(
            self.alpha_g1,
            self.beta_g2,
            self.gamma_g2,
            self.delta_g2,
            self.ic.clone(),
        )
    }

    /// Encode in Bellman VK wire format (uncompressed + BE length).
    pub fn encode(&self) -> Groth16Result<Vec<u8>> {
        let mut out = Vec::with_capacity(G1_U * 3 + G2_U * 3 + 4 + self.ic.len() * G1_U);
        write_g1(&mut out, &self.alpha_g1)?;
        write_g1(&mut out, &self.beta_g1)?;
        write_g2(&mut out, &self.beta_g2)?;
        write_g2(&mut out, &self.gamma_g2)?;
        write_g1(&mut out, &self.delta_g1)?;
        write_g2(&mut out, &self.delta_g2)?;
        write_u32_be(&mut out, self.ic.len() as u32);
        for p in &self.ic {
            write_g1(&mut out, p)?;
        }
        Ok(out)
    }

    /// Decode Bellman VK; `checked` rejects the point at infinity (Bellman default).
    pub fn decode(bytes: &[u8], checked: bool) -> Groth16Result<(Self, usize)> {
        let mut off = 0usize;
        let alpha_g1 = read_g1(bytes, &mut off, checked)?;
        let beta_g1 = read_g1(bytes, &mut off, checked)?;
        let beta_g2 = read_g2(bytes, &mut off, checked)?;
        let gamma_g2 = read_g2(bytes, &mut off, checked)?;
        let delta_g1 = read_g1(bytes, &mut off, checked)?;
        let delta_g2 = read_g2(bytes, &mut off, checked)?;
        let n_ic = read_u32_be(bytes, &mut off)? as usize;
        if n_ic == 0 {
            return Err(Groth16Error::InvalidLength);
        }
        let mut ic = Vec::with_capacity(n_ic);
        for _ in 0..n_ic {
            ic.push(read_g1(bytes, &mut off, checked)?);
        }
        Ok((
            Self {
                alpha_g1,
                beta_g1,
                beta_g2,
                gamma_g2,
                delta_g1,
                delta_g2,
                ic,
            },
            off,
        ))
    }
}

/// Full Bellman `Parameters` (Sapling spend/output proving key).
#[derive(Clone, Debug)]
pub struct ZcashParameters {
    pub vk: BellmanVerifyingKey,
    pub h: Vec<G1Point>,
    pub l: Vec<G1Point>,
    pub a: Vec<G1Point>,
    pub b_g1: Vec<G1Point>,
    pub b_g2: Vec<G2Point>,
}

impl ZcashParameters {
    /// Verifier-only view.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.vk.to_verifying_key()
    }

    /// Domain size inferred from `h` (`|h| = domain − 1` in standard QAP).
    pub fn domain_size(&self) -> usize {
        self.h.len().saturating_add(1)
    }

    /// Encode full parameters (large for Sapling spend).
    pub fn encode(&self) -> Groth16Result<Vec<u8>> {
        let mut out = self.vk.encode()?;
        write_g1_vec(&mut out, &self.h)?;
        write_g1_vec(&mut out, &self.l)?;
        write_g1_vec(&mut out, &self.a)?;
        write_g1_vec(&mut out, &self.b_g1)?;
        write_g2_vec(&mut out, &self.b_g2)?;
        Ok(out)
    }

    /// Decode Sapling-style params blob. Consumes the entire buffer.
    pub fn decode(bytes: &[u8], checked: bool) -> Groth16Result<Self> {
        let (vk, mut off) = BellmanVerifyingKey::decode(bytes, checked)?;
        let h = read_g1_vec(bytes, &mut off, checked)?;
        let l = read_g1_vec(bytes, &mut off, checked)?;
        let a = read_g1_vec(bytes, &mut off, checked)?;
        let b_g1 = read_g1_vec(bytes, &mut off, checked)?;
        let b_g2 = read_g2_vec(bytes, &mut off, checked)?;
        // Official `sapling-*.params` may carry a trailing commitment/hash region
        // after the Bellman Parameters blob (e.g. ~52 KiB on output). Accept any
        // suffix so long as the core tables parsed cleanly.
        let _trailing = bytes.len().saturating_sub(off);
        Ok(Self {
            vk,
            h,
            l,
            a,
            b_g1,
            b_g2,
        })
    }

    /// Convert into the BLS12 proving-key shape used by `prove_bls`.
    #[cfg(feature = "groth16-prover")]
    pub fn into_proving_key(self) -> crate::zk::groth16::ProvingKeyBls {
        use crate::zk::groth16::ProvingKeyBls;
        ProvingKeyBls::from_queries(
            self.vk.to_verifying_key(),
            self.domain_size(),
            self.vk.delta_g1,
            self.vk.beta_g1,
            self.a,
            self.b_g1,
            self.b_g2,
            self.h,
            self.l,
        )
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn write_u32_be(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn read_u32_be(bytes: &[u8], off: &mut usize) -> Groth16Result<u32> {
    if *off + 4 > bytes.len() {
        return Err(Groth16Error::InvalidLength);
    }
    let mut b = [0u8; 4];
    b.copy_from_slice(&bytes[*off..*off + 4]);
    *off += 4;
    Ok(u32::from_be_bytes(b))
}

fn write_g1(out: &mut Vec<u8>, p: &G1Point) -> Groth16Result<()> {
    let mut buf = [0u8; G1_U];
    p.to_bytes_uncompressed(&mut buf)
        .map_err(|_| Groth16Error::InvalidPoint)?;
    out.extend_from_slice(&buf);
    Ok(())
}

fn write_g2(out: &mut Vec<u8>, p: &G2Point) -> Groth16Result<()> {
    let mut buf = [0u8; G2_U];
    p.to_bytes_uncompressed(&mut buf)
        .map_err(|_| Groth16Error::InvalidPoint)?;
    out.extend_from_slice(&buf);
    Ok(())
}

fn read_g1(bytes: &[u8], off: &mut usize, checked: bool) -> Groth16Result<G1Point> {
    if *off + G1_U > bytes.len() {
        return Err(Groth16Error::InvalidLength);
    }
    let raw = &bytes[*off..*off + G1_U];
    *off += G1_U;
    let p = G1Point::from_bytes(raw).map_err(|_| Groth16Error::InvalidPoint)?;
    if checked && p.ct_is_identity() == 1 {
        return Err(Groth16Error::InvalidPoint);
    }
    Ok(p)
}

fn read_g2(bytes: &[u8], off: &mut usize, checked: bool) -> Groth16Result<G2Point> {
    if *off + G2_U > bytes.len() {
        return Err(Groth16Error::InvalidLength);
    }
    let raw = &bytes[*off..*off + G2_U];
    *off += G2_U;
    if raw.iter().all(|&b| b == 0) {
        return Ok(G2Point::identity());
    }
    // Bellman / zkcrypto / reference / our from_bytes uncompressed G2 order is
    // x.c1‖x.c0‖y.c1‖y.c0 (most-significant Fp limb first, same as
    // compressed). Pass through without any c0/c1 swap: swapping here
    // silently loads wrong (generally off-curve) points because the
    // 192-byte uncompressed decoder does not check the curve equation.
    // That exact swap broke ceremony prove→verify (MSMs ran, pairing failed).
    let p = G2Point::from_bytes(raw).map_err(|_| Groth16Error::InvalidPoint)?;
    if checked && p.ct_is_identity() == 1 {
        return Err(Groth16Error::InvalidPoint);
    }
    Ok(p)
}

fn write_g1_vec(out: &mut Vec<u8>, v: &[G1Point]) -> Groth16Result<()> {
    write_u32_be(out, v.len() as u32);
    for p in v {
        write_g1(out, p)?;
    }
    Ok(())
}

fn write_g2_vec(out: &mut Vec<u8>, v: &[G2Point]) -> Groth16Result<()> {
    write_u32_be(out, v.len() as u32);
    for p in v {
        write_g2(out, p)?;
    }
    Ok(())
}

fn read_g1_vec(bytes: &[u8], off: &mut usize, checked: bool) -> Groth16Result<Vec<G1Point>> {
    let n = read_u32_be(bytes, off)? as usize;
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        v.push(read_g1(bytes, off, checked)?);
    }
    Ok(v)
}

fn read_g2_vec(bytes: &[u8], off: &mut usize, checked: bool) -> Groth16Result<Vec<G2Point>> {
    let n = read_u32_be(bytes, off)? as usize;
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        v.push(read_g2(bytes, off, checked)?);
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::bls::{G1Point, G2Point};
    use crate::curve::traits::CurvePoint;

    fn sample_params() -> ZcashParameters {
        let g1 = G1Point::generator();
        let g2 = G2Point::generator();
        let g1_2 = g1.double();
        ZcashParameters {
            vk: BellmanVerifyingKey {
                alpha_g1: g1,
                beta_g1: g1_2,
                beta_g2: g2,
                gamma_g2: g2.double(),
                delta_g1: g1.double().double(),
                delta_g2: g2,
                ic: vec![g1, g1_2],
            },
            h: vec![g1],
            l: vec![g1_2],
            a: vec![g1, g1_2],
            b_g1: vec![g1],
            b_g2: vec![g2],
        }
    }

    #[test]
    fn bellman_vk_roundtrip() {
        let vk = sample_params().vk;
        let bytes = vk.encode().unwrap();
        let (decoded, consumed) = BellmanVerifyingKey::decode(&bytes, true).unwrap();
        assert_eq!(consumed, bytes.len());
        let mut a = [0u8; 96];
        let mut b = [0u8; 96];
        vk.alpha_g1.to_bytes_uncompressed(&mut a).unwrap();
        decoded.alpha_g1.to_bytes_uncompressed(&mut b).unwrap();
        assert_eq!(a, b);
        assert_eq!(decoded.ic.len(), 2);
    }

    #[test]
    fn zcash_parameters_roundtrip() {
        let pk = sample_params();
        let bytes = pk.encode().unwrap();
        let decoded = ZcashParameters::decode(&bytes, true).unwrap();
        assert_eq!(decoded.h.len(), 1);
        assert_eq!(decoded.a.len(), 2);
        assert_eq!(decoded.b_g2.len(), 1);
        assert_eq!(decoded.domain_size(), 2);
        let v = decoded.verifying_key();
        assert_eq!(v.ic.len(), 2);
    }

    #[test]
    fn reject_identity_when_checked() {
        let mut pk = sample_params();
        pk.vk.alpha_g1 = G1Point::identity();
        let bytes = pk.vk.encode().unwrap();
        assert!(BellmanVerifyingKey::decode(&bytes, true).is_err());
        assert!(BellmanVerifyingKey::decode(&bytes, false).is_ok());
    }
}
