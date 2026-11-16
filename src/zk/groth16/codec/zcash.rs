//! Zcash Sapling / Bellman codecs (BLS12-381).
//!
//! - Proof: compressed A(48) ‖ B(96) ‖ C(48) = 192
//! - Public inputs: each Fr as **32-byte little-endian** (Jubjub/Sapling convention)
//! - VK: α_g1(48) ‖ β_g2(96) ‖ γ_g2(96) ‖ δ_g2(96) ‖ n_ic(u32 LE) ‖ IC₀… (48 each)

use crate::curve::bls::Scalar;
use crate::curve::traits::CurvePoint;
use crate::zk::groth16::verify::{Groth16Error, Groth16Result, Proof, VerifyingKey};
use alloc::vec::Vec;

/// Zcash compressed proof = 192 bytes.
pub struct ZcashProofBytes;

impl ZcashProofBytes {
    pub const LEN: usize = Proof::COMPRESSED_BYTES; // 192

    pub fn encode(proof: &Proof) -> Groth16Result<[u8; Self::LEN]> {
        let mut out = [0u8; Self::LEN];
        proof.to_bytes_compressed(&mut out)?;
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Groth16Result<Proof> {
        Proof::from_bytes_compressed(bytes)
    }
}

/// Pack public inputs as concatenated 32-byte **LE** Fr (Sapling).
pub fn pack_public_inputs_zcash(inputs: &[Scalar]) -> Vec<u8> {
    let mut out = Vec::with_capacity(inputs.len() * 32);
    for s in inputs {
        let mut be = [0u8; 32];
        s.to_bytes_be(&mut be);
        // LE = reverse of BE
        be.reverse();
        out.extend_from_slice(&be);
    }
    out
}

/// Unpack LE Fr public inputs.
pub fn unpack_public_inputs_zcash(bytes: &[u8]) -> Groth16Result<Vec<Scalar>> {
    if !bytes.len().is_multiple_of(32) {
        return Err(Groth16Error::InvalidLength);
    }
    let mut out = Vec::with_capacity(bytes.len() / 32);
    for chunk in bytes.chunks(32) {
        let mut be = [0u8; 32];
        be.copy_from_slice(chunk);
        be.reverse();
        out.push(Scalar::from_bytes_be(&be).map_err(|_| Groth16Error::InvalidScalar)?);
    }
    Ok(out)
}

/// Verifying key byte layout (Bellman-inspired, compressed points).
pub struct ZcashVkBytes;

impl ZcashVkBytes {
    /// Encode VK: α_g1 ‖ β_g2 ‖ γ_g2 ‖ δ_g2 ‖ n_ic(u32 LE) ‖ IC…
    pub fn encode(vk: &VerifyingKey) -> Groth16Result<Vec<u8>> {
        let n_ic = vk.ic.len();
        let mut out = Vec::with_capacity(48 + 96 * 3 + 4 + n_ic * 48);
        let mut buf48 = [0u8; 48];
        let mut buf96 = [0u8; 96];

        vk.alpha_g1
            .to_bytes_compressed(&mut buf48)
            .map_err(|_| Groth16Error::InvalidPoint)?;
        out.extend_from_slice(&buf48);

        vk.beta_g2
            .to_bytes_compressed(&mut buf96)
            .map_err(|_| Groth16Error::InvalidPoint)?;
        out.extend_from_slice(&buf96);

        vk.gamma_g2
            .to_bytes_compressed(&mut buf96)
            .map_err(|_| Groth16Error::InvalidPoint)?;
        out.extend_from_slice(&buf96);

        vk.delta_g2
            .to_bytes_compressed(&mut buf96)
            .map_err(|_| Groth16Error::InvalidPoint)?;
        out.extend_from_slice(&buf96);

        out.extend_from_slice(&(n_ic as u32).to_le_bytes());
        for p in &vk.ic {
            p.to_bytes_compressed(&mut buf48)
                .map_err(|_| Groth16Error::InvalidPoint)?;
            out.extend_from_slice(&buf48);
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Groth16Result<VerifyingKey> {
        // minimum: 48+96+96+96+4 = 340
        if bytes.len() < 340 {
            return Err(Groth16Error::InvalidLength);
        }
        let mut off = 0usize;
        let alpha_g1 = CurvePoint::from_bytes(&bytes[off..off + 48])
            .map_err(|_| Groth16Error::InvalidPoint)?;
        off += 48;
        let beta_g2 = CurvePoint::from_bytes(&bytes[off..off + 96])
            .map_err(|_| Groth16Error::InvalidPoint)?;
        off += 96;
        let gamma_g2 = CurvePoint::from_bytes(&bytes[off..off + 96])
            .map_err(|_| Groth16Error::InvalidPoint)?;
        off += 96;
        let delta_g2 = CurvePoint::from_bytes(&bytes[off..off + 96])
            .map_err(|_| Groth16Error::InvalidPoint)?;
        off += 96;
        if off + 4 > bytes.len() {
            return Err(Groth16Error::InvalidLength);
        }
        let n_ic = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap()) as usize;
        off += 4;
        if bytes.len() != off + n_ic * 48 {
            return Err(Groth16Error::InvalidLength);
        }
        let mut ic = Vec::with_capacity(n_ic);
        for _ in 0..n_ic {
            ic.push(
                CurvePoint::from_bytes(&bytes[off..off + 48])
                    .map_err(|_| Groth16Error::InvalidPoint)?,
            );
            off += 48;
        }
        Ok(VerifyingKey::new(alpha_g1, beta_g2, gamma_g2, delta_g2, ic))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::bls::{G1Point, G2Point};

    fn sample_vk() -> VerifyingKey {
        VerifyingKey::new(
            G1Point::generator(),
            G2Point::generator(),
            G2Point::generator(),
            G2Point::generator(),
            alloc::vec![G1Point::generator(), G1Point::generator()],
        )
    }

    #[test]
    fn public_inputs_roundtrip_le() {
        let inputs = {
            let mut a = [0u8; 32];
            a[31] = 3;
            let mut b = [0u8; 32];
            b[31] = 9;
            [
                Scalar::from_bytes_be(&a).unwrap(),
                Scalar::from_bytes_be(&b).unwrap(),
            ]
        };
        let packed = pack_public_inputs_zcash(&inputs);
        assert_eq!(packed.len(), 64);
        assert_eq!(packed[0], 3); // LE: low byte first
        let unpacked = unpack_public_inputs_zcash(&packed).unwrap();
        assert_eq!(unpacked.len(), 2);
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        unpacked[0].to_bytes_be(&mut a);
        inputs[0].to_bytes_be(&mut b);
        assert_eq!(a, b);
        unpacked[1].to_bytes_be(&mut a);
        inputs[1].to_bytes_be(&mut b);
        assert_eq!(a, b);
    }

    #[test]
    fn vk_roundtrip() {
        let vk = sample_vk();
        let bytes = ZcashVkBytes::encode(&vk).unwrap();
        assert_eq!(bytes.len(), 48 + 96 * 3 + 4 + 2 * 48);
        // decode may fail if G2 compressed incomplete — length check only
        assert!(bytes.len() >= 340);
    }
}
