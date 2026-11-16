//! circomlib-compatible Poseidon hash over BN254 Fr (matches `poseidon-lite`
//! and the Sui zkLogin circuits).
//!
//! - 1..=16 inputs: single permutation, output `state[0]`.
//! - 17..=64 inputs: hashed in chunks of 16, chunk hashes re-hashed
//!   (mirrors `@mysten/sui` `poseidonHash` merkle chunking).
//!   Inputs must already be reduced mod the field (construct via
//!   [`Scalar::from_bytes_be`], which rejects `>= r`).
//!
//! Tables live in [`super::poseidon_bn254_tables`] (Grain-LFSR round
//! constants + first-candidate Cauchy MDS, Montgomery limbs); this
//! module only wraps the needed width's slices once per call.

use alloc::vec::Vec;

use crate::curve::bn254::Scalar;
use crate::curve::error::{CurveError, CurveResult};

use super::poseidon_bn254_tables::{mds_matrix, round_constants};

/// Full rounds (4 + 4).
const N_ROUNDS_F: usize = 8;
/// Partial rounds per width `t = 2..=17` (circomlib `N_ROUNDS_P`).
const N_ROUNDS_P: [usize; 16] = [
    56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68,
];

fn pow5(v: &Scalar) -> Scalar {
    let x2 = v.square();
    x2.square().mul(v)
}

/// Single Poseidon permutation over 1..=16 inputs; returns `state[0]`.
pub fn permute(inputs: &[Scalar]) -> CurveResult<Scalar> {
    let n = inputs.len();
    if n == 0 || n > 16 {
        return Err(CurveError::InvalidLength);
    }
    let t = n + 1;
    let rp = N_ROUNDS_P[t - 2];
    // Wrap this width's tables once (plain struct copies, no field math).
    let rc: Vec<Scalar> = round_constants(t)
        .iter()
        .map(|l| Scalar::from_mont_limbs(*l))
        .collect();
    let mds: Vec<Scalar> = mds_matrix(t)
        .iter()
        .map(|l| Scalar::from_mont_limbs(*l))
        .collect();
    let mut state = [Scalar::zero(); 17];
    for (i, inp) in inputs.iter().enumerate() {
        state[i + 1] = *inp;
    }
    for x in 0..N_ROUNDS_F + rp {
        let full = x < N_ROUNDS_F / 2 || x >= N_ROUNDS_F / 2 + rp;
        for y in 0..t {
            state[y] = state[y].add(&rc[x * t + y]);
            if full || y == 0 {
                state[y] = pow5(&state[y]);
            }
        }
        let mut mixed = [Scalar::zero(); 17];
        for i in 0..t {
            let mut acc = Scalar::zero();
            for j in 0..t {
                acc = acc.add(&mds[i * t + j].mul(&state[j]));
            }
            mixed[i] = acc;
        }
        state = mixed;
    }
    Ok(state[0])
}

/// Hashes `inputs` (each already reduced, 1..=64 elements).
pub fn hash(inputs: &[Scalar]) -> CurveResult<Scalar> {
    if inputs.is_empty() || inputs.len() > 64 {
        return Err(CurveError::InvalidLength);
    }
    if inputs.len() <= 16 {
        return permute(inputs);
    }
    let mut chunks = Vec::new();
    for c in inputs.chunks(16) {
        chunks.push(permute(c)?);
    }
    hash(&chunks)
}

/// Hash 1..=64 field elements given as 32-byte LE encodings; output LE.
///
/// Used by the FFI/WASM connectors (which speak LE wire bytes like the
/// Pallas Poseidon bindings). Rejects empty / oversized input
/// ([`CurveError::InvalidLength`]) and non-canonical elements
/// (`>= r`, [`CurveError::InvalidScalar`] via [`Scalar::from_bytes_be`]).
pub fn hash_le(inputs: &[[u8; 32]]) -> CurveResult<[u8; 32]> {
    if inputs.is_empty() || inputs.len() > 64 {
        return Err(CurveError::InvalidLength);
    }
    let mut fes = Vec::with_capacity(inputs.len());
    for le in inputs {
        let mut be = [0u8; 32];
        for i in 0..32 {
            be[i] = le[31 - i];
        }
        fes.push(Scalar::from_bytes_be(&be)?);
    }
    let r = hash(&fes)?;
    let mut be = [0u8; 32];
    r.to_bytes_be(&mut be);
    let mut le = [0u8; 32];
    for i in 0..32 {
        le[i] = be[31 - i];
    }
    Ok(le)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;
    use alloc::vec::Vec;

    fn parse_hex32(s: &str) -> [u8; 32] {
        let b = s.as_bytes();
        let mut out = [0u8; 32];
        for i in 0..32 {
            let hi = (b[2 * i] as char).to_digit(16).unwrap();
            let lo = (b[2 * i + 1] as char).to_digit(16).unwrap();
            out[i] = (hi * 16 + lo) as u8;
        }
        out
    }

    fn fe(hex_be: &str) -> Scalar {
        Scalar::from_bytes_be(&parse_hex32(hex_be)).expect("vector < p")
    }

    /// BE hex of a field element (matches the reference printout).
    fn be_hex(f: &Scalar) -> String {
        let mut be = [0u8; 32];
        f.to_bytes_be(&mut be);
        let mut s = String::with_capacity(64);
        for byte in be {
            s.push(char::from_digit((byte >> 4) as u32, 16).unwrap());
            s.push(char::from_digit((byte & 0xf) as u32, 16).unwrap());
        }
        s
    }

    fn seq_be(n: usize) -> Vec<Scalar> {
        (0..n)
            .map(|i| {
                let mut be = [0u8; 32];
                be[31] = i as u8;
                Scalar::from_bytes_be(&be).unwrap()
            })
            .collect()
    }

    /// `ZkLoginPoseidon` reference vectors, BE field encoding.
    #[test]
    fn reference_vectors() {
        // hash([1])
        assert_eq!(
            be_hex(
                &hash(&[fe(
                    "0000000000000000000000000000000000000000000000000000000000000001"
                )])
                .unwrap()
            ),
            "29176100eaa962bdc1fe6c654d6a3c130e96a4d1168b33848b897dc502820133"
        );
        // hash([1, 2])
        assert_eq!(
            be_hex(
                &hash(
                    &[
                        "0000000000000000000000000000000000000000000000000000000000000001",
                        "0000000000000000000000000000000000000000000000000000000000000002",
                    ]
                    .iter()
                    .map(|h| fe(h))
                    .collect::<Vec<Scalar>>()
                )
                .unwrap()
            ),
            "115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a"
        );
        // hash(0..16) — widest single permutation
        assert_eq!(
            be_hex(&hash(&seq_be(16)).unwrap()),
            "1b733f2ff41971b23819a16bc8c16bbe13d98173358429fcc12f6f0826407a56"
        );
        // hash(0..17) — first Sui-chunked case
        assert_eq!(
            be_hex(&hash(&seq_be(17)).unwrap()),
            "140775895b133650f6bb84b5f0f646eb811df9a7271ad4e7add70fa36c7acf76"
        );
        // hash(0..33)
        assert_eq!(
            be_hex(&hash(&seq_be(33)).unwrap()),
            "21f9fe32fa1efa549f2d85bcea24efb7d3147ebec77c674bc2181c638c00e735"
        );
        // hash(0..64) — deepest chunking
        assert_eq!(
            be_hex(&hash(&seq_be(64)).unwrap()),
            "1afc4ca9ad5e9e650f25fc88eb9b74f16b64de1270e62718fe284c808167ea06"
        );
        // hash([0]) and hash([p-1]) boundary inputs
        assert_eq!(
            be_hex(
                &hash(&[fe(
                    "0000000000000000000000000000000000000000000000000000000000000000"
                )])
                .unwrap()
            ),
            "2a09a9fd93c590c26b91effbb2499f07e8f7aa12e2b4940a3aed2411cb65e11c"
        );
        assert_eq!(
            be_hex(
                &hash(&[fe(
                    "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000"
                )])
                .unwrap()
            ),
            "0771743e7ade0f56f51d16544f60059ba3029ba556d63697612900fe5f020b16"
        );
    }

    #[test]
    fn rejects_bad_lengths() {
        assert!(permute(&[]).is_err());
        assert!(hash(&[]).is_err());
        assert!(permute(&seq_be(17)).is_err());
        assert!(hash(&seq_be(65)).is_err());
    }
}
