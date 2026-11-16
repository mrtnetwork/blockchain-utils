//! Sui Groth16 codecs (BN254).
//!
//! Sui `0x2::groth16` uses BN254 with **uncompressed** points:
//! - Proof: A_g1(64) ‖ B_g2(128) ‖ C_g1(64) = **256**
//! - Public inputs: each Fr as **32-byte big-endian**
//! - VK: α_g1(64) ‖ β_g2(128) ‖ γ_g2(128) ‖ δ_g2(128) ‖ n_ic(u32 BE) ‖ IC…(64 each)

use crate::curve::bn254::{G1Point, G2Point, Scalar};
use crate::curve::traits::CurvePoint;
use crate::zk::groth16::bn254::{ProofBn254, VerifyingKeyBn254};
use crate::zk::groth16::verify::{Groth16Error, Groth16Result};
use alloc::vec::Vec;

pub struct SuiProofBytes;

impl SuiProofBytes {
    pub const LEN: usize = 64 + 128 + 64; // 256

    pub fn encode(proof: &ProofBn254) -> Groth16Result<[u8; Self::LEN]> {
        let mut out = [0u8; Self::LEN];
        proof
            .a
            .to_bytes_uncompressed(&mut out[0..64])
            .map_err(|_| Groth16Error::InvalidPoint)?;
        proof
            .b
            .to_bytes_uncompressed(&mut out[64..192])
            .map_err(|_| Groth16Error::InvalidPoint)?;
        proof
            .c
            .to_bytes_uncompressed(&mut out[192..256])
            .map_err(|_| Groth16Error::InvalidPoint)?;
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Groth16Result<ProofBn254> {
        if bytes.len() != Self::LEN {
            return Err(Groth16Error::InvalidLength);
        }
        let a = G1Point::from_bytes(&bytes[0..64]).map_err(|_| Groth16Error::InvalidPoint)?;
        let b = G2Point::from_bytes(&bytes[64..192]).map_err(|_| Groth16Error::InvalidPoint)?;
        let c = G1Point::from_bytes(&bytes[192..256]).map_err(|_| Groth16Error::InvalidPoint)?;
        Ok(ProofBn254 { a, b, c })
    }
}

pub fn pack_public_inputs_sui(inputs: &[Scalar]) -> Vec<u8> {
    let mut out = Vec::with_capacity(inputs.len() * 32);
    for s in inputs {
        let mut be = [0u8; 32];
        s.to_bytes_be(&mut be);
        out.extend_from_slice(&be);
    }
    out
}

pub fn unpack_public_inputs_sui(bytes: &[u8]) -> Groth16Result<Vec<Scalar>> {
    if !bytes.len().is_multiple_of(32) {
        return Err(Groth16Error::InvalidLength);
    }
    let mut out = Vec::with_capacity(bytes.len() / 32);
    for chunk in bytes.chunks(32) {
        let mut be = [0u8; 32];
        be.copy_from_slice(chunk);
        out.push(Scalar::from_bytes_be(&be).map_err(|_| Groth16Error::InvalidScalar)?);
    }
    Ok(out)
}

pub struct SuiVkBytes;

impl SuiVkBytes {
    pub fn encode(vk: &VerifyingKeyBn254) -> Groth16Result<Vec<u8>> {
        let n = vk.ic.len();
        let mut out = Vec::with_capacity(64 + 128 * 3 + 4 + n * 64);
        let mut b64 = [0u8; 64];
        let mut b128 = [0u8; 128];
        vk.alpha_g1
            .to_bytes_uncompressed(&mut b64)
            .map_err(|_| Groth16Error::InvalidPoint)?;
        out.extend_from_slice(&b64);
        for g2 in [&vk.beta_g2, &vk.gamma_g2, &vk.delta_g2] {
            g2.to_bytes_uncompressed(&mut b128)
                .map_err(|_| Groth16Error::InvalidPoint)?;
            out.extend_from_slice(&b128);
        }
        out.extend_from_slice(&(n as u32).to_be_bytes());
        for p in &vk.ic {
            p.to_bytes_uncompressed(&mut b64)
                .map_err(|_| Groth16Error::InvalidPoint)?;
            out.extend_from_slice(&b64);
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Groth16Result<VerifyingKeyBn254> {
        if bytes.len() < 64 + 128 * 3 + 4 {
            return Err(Groth16Error::InvalidLength);
        }
        let mut off = 0usize;
        let alpha_g1 =
            G1Point::from_bytes(&bytes[off..off + 64]).map_err(|_| Groth16Error::InvalidPoint)?;
        off += 64;
        let beta_g2 =
            G2Point::from_bytes(&bytes[off..off + 128]).map_err(|_| Groth16Error::InvalidPoint)?;
        off += 128;
        let gamma_g2 =
            G2Point::from_bytes(&bytes[off..off + 128]).map_err(|_| Groth16Error::InvalidPoint)?;
        off += 128;
        let delta_g2 =
            G2Point::from_bytes(&bytes[off..off + 128]).map_err(|_| Groth16Error::InvalidPoint)?;
        off += 128;
        let n = u32::from_be_bytes(bytes[off..off + 4].try_into().unwrap()) as usize;
        off += 4;
        if bytes.len() != off + n * 64 {
            return Err(Groth16Error::InvalidLength);
        }
        let mut ic = Vec::with_capacity(n);
        for _ in 0..n {
            ic.push(
                G1Point::from_bytes(&bytes[off..off + 64])
                    .map_err(|_| Groth16Error::InvalidPoint)?,
            );
            off += 64;
        }
        Ok(VerifyingKeyBn254 {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            ic,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::traits::CurvePoint;

    #[test]
    fn proof_roundtrip_uncompressed() {
        let proof = ProofBn254 {
            a: G1Point::generator(),
            b: G2Point::generator(),
            c: G1Point::generator(),
        };
        let bytes = SuiProofBytes::encode(&proof).unwrap();
        assert_eq!(bytes.len(), 256);
        let decoded = SuiProofBytes::decode(&bytes).unwrap();
        // generators encode non-zero
        assert_eq!(decoded.a.ct_is_identity(), 0);
        assert_eq!(decoded.b.ct_is_identity(), 0);
        assert_eq!(decoded.c.ct_is_identity(), 0);
    }

    #[test]
    fn public_inputs_be_roundtrip() {
        let s = Scalar::from_u64(42);
        let packed = pack_public_inputs_sui(&[s]);
        assert_eq!(packed.len(), 32);
        assert_eq!(packed[31], 42);
        let u = unpack_public_inputs_sui(&packed).unwrap();
        assert_eq!(u[0].ct_eq(&s), 1);
    }

    #[test]
    fn vk_roundtrip() {
        let vk = VerifyingKeyBn254 {
            alpha_g1: G1Point::generator(),
            beta_g2: G2Point::generator(),
            gamma_g2: G2Point::generator(),
            delta_g2: G2Point::generator(),
            ic: alloc::vec![G1Point::identity(), G1Point::generator()],
        };
        let bytes = SuiVkBytes::encode(&vk).unwrap();
        let decoded = SuiVkBytes::decode(&bytes).unwrap();
        assert_eq!(decoded.num_inputs(), 1);
        assert_eq!(decoded.alpha_g1.ct_is_identity(), 0);
    }
}
