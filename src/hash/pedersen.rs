//! Pedersen hash over Jubjub (Zcash Sapling).
//!
//! Spec: protocol §5.4.1.7. Generators via `find_group_hash` (BLAKE2s + cofactor).

use crate::curve::jubjub::JubJubPoint;
#[cfg(any(test, not(feature = "std")))]
use crate::curve::jubjub::Scalar;
use crate::curve::traits::CurvePoint;
use crate::hash::blake2s::{Blake2s, Blake2sTreeParams};
use crate::hash::HashResult;

/// ASCII hex of the Sapling group-hash first block (64 chars).
const GH_FIRST_BLOCK: &[u8] = b"096b36a5804bfacef1691e173c366a47ff5ba84a44f26ddd7e8d9f79d5b42df0";

const CHUNKS_PER_GENERATOR: usize = 63;
const NUM_GENERATORS: usize = 6;

/// 6-bit personalization.
#[derive(Clone, Copy, Debug)]
pub enum Personalization {
    /// Note commitment: 111111
    NoteCommitment,
    /// Merkle tree layer `layer` (0..63) little-endian 6 bits
    MerkleTree { layer: u8 },
}

impl Personalization {
    pub fn bits(self) -> [bool; 6] {
        match self {
            Personalization::NoteCommitment => [true; 6],
            Personalization::MerkleTree { layer } => {
                let mut b = [false; 6];
                for (i, bit) in b.iter_mut().enumerate() {
                    *bit = ((layer >> i) & 1) == 1;
                }
                b
            }
        }
    }
}

/// Sapling Pedersen hash.
pub struct PedersenHash {
    pub gens: [JubJubPoint; NUM_GENERATORS],
}

/// Canonical segment tables live `@generated` in
/// [`super::pedersen_tables`] (`PEDERSEN_SEG_TABLES[s][k] =
/// `[1,2,3,4]·16^k·G_s`, extended coords, zero runtime cost on every
/// target incl. `no_std`/wasm). Native hashing indexes them directly;
/// circuit synthesis reshapes them (see `generate_pedersen_windows`).
/// Single home: nothing is generated twice, nothing cached at runtime.
use super::pedersen_tables::PEDERSEN_SEG_TABLES;

impl PedersenHash {
    pub fn new() -> HashResult<Self> {
        // Official Sapling PEDERSEN_HASH_GENERATORS (canonical u,v limbs)
        const GENS: [([u64; 4], [u64; 4]); 6] = [
            // G0
            (
                [
                    0x194e42926f661b51,
                    0x2f0c718f6f0fbadd,
                    0xb5ea25de7ec0e378,
                    0x73c016a42ded9578,
                ],
                [
                    0x77bfabd432243cca,
                    0xf9472e8bc04e4632,
                    0x79c9166b837edc5e,
                    0x289e87a2d3521b57,
                ],
            ),
            // G1
            (
                [
                    0xb9819dc82d90607e,
                    0xa361ee3fd48fdf77,
                    0x52a35a8c1908dd87,
                    0x15a36d1f0f390d88,
                ],
                [
                    0x7b0dc53c4ebf1891,
                    0x1f3abeeb98fad3e8,
                    0xf7891142c001d925,
                    0x015d8c7f5b43fe33,
                ],
            ),
            // G2
            (
                [
                    0x76d6f7c2b67fc475,
                    0xbae8e5c46641ae5c,
                    0xeb69ae39f5c84210,
                    0x664321a58246e2f6,
                ],
                [
                    0x80ed502c9793d457,
                    0x8bb22a7f1784b498,
                    0xe000a46c8e8ce853,
                    0x362e1500d24eee9e,
                ],
            ),
            // G3
            (
                [
                    0x4c767804c1c4a2cc,
                    0x7d02d50e654b87f2,
                    0xedc5f4a9cff29fd5,
                    0x323a6548ce9d9876,
                ],
                [
                    0x84714beca33570e9,
                    0x5103afa1a11f6a85,
                    0x91070acbd8d947b7,
                    0x2f7ee40c4b56cad8,
                ],
            ),
            // G4
            (
                [
                    0x46809430657f82d1,
                    0xefd5931305f2f0bf,
                    0x89b64b4e03362796,
                    0x3bd2666000b54796,
                ],
                [
                    0x99968299c3658aef,
                    0xb3b9d8095859d14c,
                    0x397832381406c9e5,
                    0x494bc52103ab9d0a,
                ],
            ),
            // G5
            (
                [
                    0xcb3c023258d32079,
                    0x1d9e5ca21135ff6f,
                    0xda049746d76d3ee5,
                    0x63447b2ba31bb28a,
                ],
                [
                    0x436082119f8d629a,
                    0xa80200d2c66b13a7,
                    0x64cdb1070a136a28,
                    0x64ec4689e8bfb6e5,
                ],
            ),
        ];
        let mut gens = [JubJubPoint::identity(); NUM_GENERATORS];
        for (i, (u, v)) in GENS.iter().enumerate() {
            gens[i] = point_from_uv_limbs(*u, *v)?;
        }
        Ok(Self { gens })
    }

    /// Hash personalization ‖ input bits → Jubjub point.
    ///
    /// Table path over the generated [`PEDERSEN_SEG_TABLES`]: identical
    /// chunking and signed-digit encoding as the scalar reference below,
    /// but each chunk contributes a selected precomputed multiple (one
    /// select + add) instead of scalar accumulation + variable-base
    /// mult. No runtime state on any target (`static` constants only).
    pub fn hash(&self, personal: Personalization, input_bits: &[bool]) -> JubJubPoint {
        let total = 6 + input_bits.len();
        let bit_at = |i: usize| -> bool {
            if i < 6 {
                personal.bits()[i]
            } else {
                input_bits[i - 6]
            }
        };
        let mut result = JubJubPoint::identity();
        let mut bit_i = 0usize;
        let mut gen_idx = 0usize;
        while bit_i < total && gen_idx < NUM_GENERATORS {
            let seg = &PEDERSEN_SEG_TABLES[gen_idx];
            let mut chunks = 0usize;
            while bit_i < total && chunks < CHUNKS_PER_GENERATOR {
                let a = bit_at(bit_i);
                bit_i += 1;
                // NB: consume b/c only when present (mirrors scalar path).
                let b = if bit_i < total {
                    let v = bit_at(bit_i);
                    bit_i += 1;
                    v
                } else {
                    false
                };
                let c = if bit_i < total {
                    let v = bit_at(bit_i);
                    bit_i += 1;
                    v
                } else {
                    false
                };
                let v = 1 + (a as usize) + 2 * (b as usize);
                let p = JubJubPoint::from_extended_limbs(
                    seg[chunks][v - 1][0],
                    seg[chunks][v - 1][1],
                    seg[chunks][v - 1][2],
                    seg[chunks][v - 1][3],
                );
                result = result.add(&if c { p.neg() } else { p });
                chunks += 1;
            }
            gen_idx += 1;
        }
        result
    }

    /// Vartime fast path over compile-time dual points ( constants).
    ///
    /// Bit-identical to [`PedersenHash::hash`]; table lookups assemble
    /// ready duals with zero runtime conversion (`from_mont_limbs` wraps
    /// precomputed Montgomery limbs — no per-chunk math, no init step, no
    /// stack-resident tables, so the wasm32 stack-overflow class cannot
    /// recur). Uses dual-form mixed addition
    /// (`JubJubPoint::add_dual_vartime`, 7 vs 9 `Fe::mul` per chunk).
    /// `hash()` is untouched and remains the reference for KATs, the
    /// scalar differential test, and circuit witnesses. All connector
    /// entry points (FFI/wasm) and tree-side hashing use this path.
    #[cfg(feature = "std")]
    pub fn hash_cached(personal: Personalization, input_bits: &[bool]) -> JubJubPoint {
        use super::pedersen_tables::PEDERSEN_DUAL_TABLES;
        use crate::curve::jubjub::{Fe, JubDual};
        // (Fe is used only for Montgomery assembly below.)
        let total = 6 + input_bits.len();
        let bit_at = |i: usize| -> bool {
            if i < 6 {
                personal.bits()[i]
            } else {
                input_bits[i - 6]
            }
        };
        let mut result = JubJubPoint::identity();
        let mut bit_i = 0usize;
        let mut gen_idx = 0usize;
        while bit_i < total && gen_idx < NUM_GENERATORS {
            let mut chunks = 0usize;
            while bit_i < total && chunks < CHUNKS_PER_GENERATOR {
                let a = bit_at(bit_i);
                bit_i += 1;
                // NB: consume b/c only when present (mirrors scalar path).
                let b = if bit_i < total {
                    let v = bit_at(bit_i);
                    bit_i += 1;
                    v
                } else {
                    false
                };
                let c = if bit_i < total {
                    let v = bit_at(bit_i);
                    bit_i += 1;
                    v
                } else {
                    false
                };
                let v = 1 + (a as usize) + 2 * (b as usize);
                let t = &PEDERSEN_DUAL_TABLES[gen_idx][chunks][(v - 1) * 2 + (c as usize)];
                let q = JubDual {
                    y_minus_x: Fe::from_mont_limbs(t[0]),
                    y_plus_x: Fe::from_mont_limbs(t[1]),
                    c: Fe::from_mont_limbs(t[2]),
                };
                result = result.add_dual_vartime(&q);
                chunks += 1;
            }
            gen_idx += 1;
        }
        result
    }

    /// Legacy scalar-accumulation path (bit-identical reference for the
    /// differential test below).
    #[cfg(test)]
    fn hash_scalar(&self, personal: Personalization, input_bits: &[bool]) -> JubJubPoint {
        let mut all = alloc::vec::Vec::with_capacity(6 + input_bits.len());
        all.extend_from_slice(&personal.bits());
        all.extend_from_slice(input_bits);

        let mut result = JubJubPoint::identity();
        let mut gen_idx = 0usize;
        let mut bit_i = 0usize;

        while bit_i < all.len() && gen_idx < NUM_GENERATORS {
            let mut acc = Scalar::zero();
            let mut chunks = 0usize;
            let mut encountered = false;

            while bit_i < all.len() && chunks < CHUNKS_PER_GENERATOR {
                encountered = true;
                let a = all[bit_i];
                bit_i += 1;
                let b = if bit_i < all.len() {
                    let v = all[bit_i];
                    bit_i += 1;
                    v
                } else {
                    false
                };
                let c = if bit_i < all.len() {
                    let v = all[bit_i];
                    bit_i += 1;
                    v
                } else {
                    false
                };

                // cur = 2^{4·chunks} (Sapling 3-bit windows on 4-bit grid)
                let mut cur = Scalar::one();
                for _ in 0..(chunks * 4) {
                    cur = cur.add(&cur);
                }
                let mut tmp = cur;
                if a {
                    tmp = tmp.add(&cur);
                }
                cur = cur.add(&cur);
                if b {
                    tmp = tmp.add(&cur);
                }
                if c {
                    tmp = tmp.neg();
                }
                acc = acc.add(&tmp);
                chunks += 1;
            }
            if !encountered {
                break;
            }
            result = result.add(&self.gens[gen_idx].mul(&acc));
            gen_idx += 1;
        }
        result
    }

    /// Hash from a comma-separated bit string as in reference vectors.
    pub fn hash_bitstring(&self, personal: Personalization, bits: &str) -> JubJubPoint {
        let mut v = alloc::vec::Vec::new();
        for part in bits.split(',') {
            let p = part.trim();
            if p == "1" {
                v.push(true);
            } else if p == "0" {
                v.push(false);
            }
        }
        self.hash(personal, &v)
    }

    /// Affine (u,v) as LE hex (Sapling encoding of coordinates).
    /// LE coordinate hex (Sapling wire).
    pub fn to_uv_hex(p: &JubJubPoint) -> (alloc::string::String, alloc::string::String) {
        let mut unc = [0u8; 64];
        p.to_bytes_uncompressed(&mut unc).expect("unc");
        let mut u = [0u8; 32];
        let mut v = [0u8; 32];
        u.copy_from_slice(&unc[..32]);
        v.copy_from_slice(&unc[32..]);
        (hex_encode(&u), hex_encode(&v))
    }

    /// BE coordinate hex as used in some KATs.
    pub fn to_uv_hex_be(p: &JubJubPoint) -> (alloc::string::String, alloc::string::String) {
        let (u_le, v_le) = Self::to_uv_hex(p);
        let u: alloc::vec::Vec<u8> = (0..u_le.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&u_le[i..i + 2], 16).unwrap())
            .rev()
            .collect();
        let v: alloc::vec::Vec<u8> = (0..v_le.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&v_le[i..i + 2], 16).unwrap())
            .rev()
            .collect();
        (hex_encode(&u), hex_encode(&v))
    }
}

impl Default for PedersenHash {
    fn default() -> Self {
        Self::new().expect("pedersen gens")
    }
}

/// One-shot with NoteCommitment personalization.
pub fn pedersen_hash(msg_bits: &[bool]) -> HashResult<JubJubPoint> {
    Ok(PedersenHash::new()?.hash(Personalization::NoteCommitment, msg_bits))
}

fn point_from_uv_limbs(u: [u64; 4], v: [u64; 4]) -> HashResult<JubJubPoint> {
    fn limbs_to_fe(limbs: [u64; 4]) -> crate::curve::jubjub::Fe {
        use crate::curve::jubjub::Fe;
        let mut be = [0u8; 32];
        for (i, &limb) in limbs.iter().enumerate() {
            let o = 24 - i * 8;
            be[o..o + 8].copy_from_slice(&limb.to_be_bytes());
        }
        Fe::from_bytes_be(&be).expect("gen coord")
    }
    Ok(JubJubPoint::from_affine_coords(
        limbs_to_fe(u),
        limbs_to_fe(v),
    ))
}

/// Sapling `find_group_hash` (BLAKE2s + try-and-increment + cofactor clear).
pub fn find_group_hash(message: &[u8], personalization: &[u8; 8]) -> HashResult<JubJubPoint> {
    let mut tag = alloc::vec::Vec::from(message);
    tag.push(0);
    let i = tag.len() - 1;
    loop {
        if let Some(p) = group_hash(&tag, personalization)? {
            return Ok(p);
        }
        if tag[i] == 0xff {
            return Err(crate::hash::HashError::InvalidLength);
        }
        tag[i] += 1;
    }
}

fn group_hash(tag: &[u8], personalization: &[u8; 8]) -> HashResult<Option<JubJubPoint>> {
    let tree = Blake2sTreeParams {
        fanout: 1,
        max_depth: 1,
        leaf_size: 0,
        node_offset: 0,
        node_depth: 0,
        inner_digest_length: 0,
        last_node: false,
        salt: None,
        personal: Some(*personalization),
    };
    let mut h = Blake2s::new_with_tree(32, None, Some(&tree))?;
    h.update(GH_FIRST_BLOCK);
    h.update(tag);
    let digest = h.finalize_256()?;
    match JubJubPoint::from_bytes(&digest) {
        Ok(p) => {
            // mul_by_cofactor = double^3
            let p = p.double().double().double();
            if p.ct_is_identity() == 1 {
                Ok(None)
            } else {
                Ok(Some(p))
            }
        }
        Err(_) => Ok(None),
    }
}

fn hex_encode(b: &[u8]) -> alloc::string::String {
    use core::fmt::Write;
    let mut s = alloc::string::String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{:02x}", x);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pedersen_deterministic() {
        let ph = PedersenHash::new().unwrap();
        let bits: alloc::vec::Vec<bool> = (0..32).map(|i| i % 2 == 0).collect();
        let a = ph.hash(Personalization::NoteCommitment, &bits);
        let b = ph.hash(Personalization::NoteCommitment, &bits);
        assert_eq!(PedersenHash::to_uv_hex(&a), PedersenHash::to_uv_hex(&b));
    }

    #[test]
    fn pedersen_personalization_differs() {
        let ph = PedersenHash::new().unwrap();
        let bits = [true, false, true, true];
        let a = ph.hash(Personalization::NoteCommitment, &bits);
        let b = ph.hash(Personalization::MerkleTree { layer: 0 }, &bits);
        assert_ne!(PedersenHash::to_uv_hex(&a), PedersenHash::to_uv_hex(&b));
    }

    /// Table fast path must be bit-identical to the scalar reference
    /// across personalizations, lengths (empty, partial-chunk, exact,
    /// multi-segment, over-capacity) and bit patterns.
    #[test]
    fn pedersen_tables_match_scalar() {
        let ph = PedersenHash::new().unwrap();
        let mut lens = alloc::vec::Vec::new();
        lens.push(0usize);
        lens.push(1);
        lens.push(2);
        lens.push(3);
        lens.push(4);
        lens.push(100);
        lens.push(564);
        lens.push(565);
        lens.push(566);
        lens.push(567);
        lens.push(1000);
        lens.push(2000);
        for len in lens {
            let bits: alloc::vec::Vec<bool> = (0..len)
                .map(|i| ((i as u64).wrapping_mul(2654435761) & 7) < 4)
                .collect();
            for personal in [
                Personalization::NoteCommitment,
                Personalization::MerkleTree { layer: 0 },
                Personalization::MerkleTree { layer: 17 },
                Personalization::MerkleTree { layer: 63 },
            ] {
                let a = ph.hash_scalar(personal, &bits);
                let b = ph.hash(personal, &bits);
                assert_eq!(
                    PedersenHash::to_uv_hex(&a),
                    PedersenHash::to_uv_hex(&b),
                    "mismatch len={len} personal={personal:?}"
                );
            }
        }
    }

    /// Cached fast path must be bit-identical to the reference `hash`
    /// (R3). Same length/personalization/pattern sweep as
    /// `pedersen_tables_match_scalar`, plus the exact 510-bit tree width.
    #[cfg(feature = "std")]
    #[test]
    fn pedersen_cached_matches_reference() {
        let ph = PedersenHash::new().unwrap();
        for len in [0usize, 1, 2, 3, 4, 7, 62, 63, 64, 100, 189, 252, 378, 510, 564, 1000] {
            let bits: alloc::vec::Vec<bool> = (0..len)
                .map(|i| ((i as u64).wrapping_mul(2654435761) & 7) < 4)
                .collect();
            for personal in [
                Personalization::NoteCommitment,
                Personalization::MerkleTree { layer: 0 },
                Personalization::MerkleTree { layer: 17 },
                Personalization::MerkleTree { layer: 63 },
            ] {
                let a = ph.hash(personal, &bits);
                let b = PedersenHash::hash_cached(personal, &bits);
                assert_eq!(
                    PedersenHash::to_uv_hex(&a),
                    PedersenHash::to_uv_hex(&b),
                    "mismatch len={len} personal={personal:?}"
                );
            }
        }
    }

    /// Reference vectors: personalization size → MerkleTree layer, expect u/v LE hex.
    #[test]
    fn pedersen_vectors() {
        let ph = PedersenHash::new().unwrap();
        // personalization 0, inputBits all zeros (6 bits) from reference suite
        // reference vector: MerkleTree(0) with empty inputBits; coords reported as BE hex
        let p = ph.hash(Personalization::MerkleTree { layer: 0 }, &[]);
        let (u, v) = PedersenHash::to_uv_hex_be(&p);
        assert_eq!(
            u, "62454a957289b3930d10f3def0d512cfe0ef3de06421321221af3558de9d481d",
            "u mismatch"
        );
        assert_eq!(
            v, "0279f0aebfb66e53ff69fba16b6608dbf4319b944432f45c6e69a3dbd1f7b330",
            "v mismatch"
        );
    }
}
