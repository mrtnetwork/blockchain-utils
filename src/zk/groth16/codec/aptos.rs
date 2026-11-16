//! Aptos Groth16 codecs (BN254).
//!
//! Layout matches Sui (uncompressed BN254). Separate types for API clarity.

use crate::curve::bn254::Scalar;
use crate::zk::groth16::bn254::{ProofBn254, VerifyingKeyBn254};
use crate::zk::groth16::codec::sui::{
    pack_public_inputs_sui, unpack_public_inputs_sui, SuiProofBytes, SuiVkBytes,
};
use crate::zk::groth16::verify::Groth16Result;
use alloc::vec::Vec;

pub struct AptosProofBytes;

impl AptosProofBytes {
    pub const LEN: usize = SuiProofBytes::LEN; // 256

    pub fn encode(proof: &ProofBn254) -> Groth16Result<[u8; Self::LEN]> {
        SuiProofBytes::encode(proof)
    }

    pub fn decode(bytes: &[u8]) -> Groth16Result<ProofBn254> {
        SuiProofBytes::decode(bytes)
    }
}

pub fn pack_public_inputs_aptos(inputs: &[Scalar]) -> Vec<u8> {
    pack_public_inputs_sui(inputs)
}

pub fn unpack_public_inputs_aptos(bytes: &[u8]) -> Groth16Result<Vec<Scalar>> {
    unpack_public_inputs_sui(bytes)
}

pub struct AptosVkBytes;

impl AptosVkBytes {
    pub fn encode(vk: &VerifyingKeyBn254) -> Groth16Result<Vec<u8>> {
        SuiVkBytes::encode(vk)
    }

    pub fn decode(bytes: &[u8]) -> Groth16Result<VerifyingKeyBn254> {
        SuiVkBytes::decode(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::bn254::{G1Point, G2Point};

    #[test]
    fn aptos_proof_len() {
        let proof = ProofBn254 {
            a: G1Point::generator(),
            b: G2Point::generator(),
            c: G1Point::generator(),
        };
        let b = AptosProofBytes::encode(&proof).unwrap();
        assert_eq!(b.len(), 256);
        assert!(AptosProofBytes::decode(&b).is_ok());
    }
}
