//! Tezos Groth16-compatible codecs.
//!
//! - **BLS12 path:** same compressed 192-byte proof as Zcash/Bellman
//! - **BN254 path:** same uncompressed 256-byte layout as Sui (for Ethereum-aligned tools)
//! - Public inputs: Fr **32-byte big-endian** (Michelson / Tezos convention for field elems)

use crate::curve::bn254::Scalar as BnScalar;
use crate::zk::groth16::bn254::{ProofBn254, VerifyingKeyBn254};
use crate::zk::groth16::codec::sui::{
    pack_public_inputs_sui, unpack_public_inputs_sui, SuiProofBytes, SuiVkBytes,
};
use crate::zk::groth16::codec::zcash::{ZcashProofBytes, ZcashVkBytes};
use crate::zk::groth16::verify::{Groth16Result, Proof, VerifyingKey};
use alloc::vec::Vec;

/// Tezos BLS12 proof (compressed 192).
pub struct TezosProofBytes;

impl TezosProofBytes {
    pub const LEN: usize = ZcashProofBytes::LEN;

    pub fn encode_bls(proof: &Proof) -> Groth16Result<[u8; Self::LEN]> {
        ZcashProofBytes::encode(proof)
    }

    pub fn decode_bls(bytes: &[u8]) -> Groth16Result<Proof> {
        ZcashProofBytes::decode(bytes)
    }

    pub fn encode_bn254(proof: &ProofBn254) -> Groth16Result<[u8; 256]> {
        SuiProofBytes::encode(proof)
    }

    pub fn decode_bn254(bytes: &[u8]) -> Groth16Result<ProofBn254> {
        SuiProofBytes::decode(bytes)
    }
}

/// Tezos public inputs: BE Fr (32 bytes each). For BLS use LE via zcash pack if needed.
pub fn pack_public_inputs_tezos(inputs: &[BnScalar]) -> Vec<u8> {
    pack_public_inputs_sui(inputs)
}

pub fn unpack_public_inputs_tezos(bytes: &[u8]) -> Groth16Result<Vec<BnScalar>> {
    unpack_public_inputs_sui(bytes)
}

pub struct TezosVkBytes;

impl TezosVkBytes {
    pub fn encode_bls(vk: &VerifyingKey) -> Groth16Result<Vec<u8>> {
        ZcashVkBytes::encode(vk)
    }

    pub fn decode_bls(bytes: &[u8]) -> Groth16Result<VerifyingKey> {
        ZcashVkBytes::decode(bytes)
    }

    pub fn encode_bn254(vk: &VerifyingKeyBn254) -> Groth16Result<Vec<u8>> {
        SuiVkBytes::encode(vk)
    }

    pub fn decode_bn254(bytes: &[u8]) -> Groth16Result<VerifyingKeyBn254> {
        SuiVkBytes::decode(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::bn254::{G1Point, G2Point};

    #[test]
    fn tezos_bn254_proof_roundtrip() {
        let proof = ProofBn254 {
            a: G1Point::generator(),
            b: G2Point::generator(),
            c: G1Point::generator(),
        };
        let b = TezosProofBytes::encode_bn254(&proof).unwrap();
        assert_eq!(b.len(), 256);
        assert!(TezosProofBytes::decode_bn254(&b).is_ok());
    }
}
