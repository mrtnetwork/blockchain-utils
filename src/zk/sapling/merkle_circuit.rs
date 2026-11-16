//! Merkle authentication path R1CS (Sapling Spend).
//!
//! Layer `i`: `cur = Pedersen(MerkleTree(i), bits(ul) ‖ bits(ur)).u`
//! with `(ul, ur) = swap(cur, sibling, is_right)`.

use crate::curve::bls::Scalar;
use crate::curve::jubjub::{Fe, JubJubPoint};
use crate::hash::pedersen::Personalization;
use crate::zk::sapling::boolean::Boolean;
use crate::zk::sapling::cs::{lc_one, lc_var, Cs, Lc};
use crate::zk::sapling::num::{scalar_from_fe_le, AllocatedNum};
use crate::zk::sapling::pedersen_circuit::pedersen_hash_cs;
use alloc::vec::Vec;

fn fe_to_scalar(fe: &Fe) -> Scalar {
    let mut be = [0u8; 32];
    fe.to_bytes_be(&mut be);
    Scalar::from_bytes_be(&be).unwrap_or_else(|_| Scalar::zero())
}

fn sibling_le_to_scalar(le: &[u8; 32]) -> Scalar {
    scalar_from_fe_le(le)
}

/// One Merkle layer: returns updated `cur` (u-coordinate as Fr).
pub fn merkle_layer_cs(
    cs: &mut Cs,
    cur: &AllocatedNum,
    sibling_le: &[u8; 32],
    is_right: bool,
    layer: u8,
) -> (AllocatedNum, Boolean) {
    let is_right_b = Boolean::alloc(cs, is_right);
    let sibling = AllocatedNum::alloc(cs, sibling_le_to_scalar(sibling_le));
    let (ul, ur) = AllocatedNum::conditional_reverse(cs, cur, &sibling, &is_right_b);

    // 255-bit LE unpack with pack-equality (soundness: bits must equal Fr)
    // Non-strict bits (sapling-crypto): collision-resistant so congruency is ok.
    let ul_bits = ul.to_bits_le(cs, 255);
    let ur_bits = ur.to_bits_le(cs, 255);
    let mut preimage = Vec::with_capacity(510);
    preimage.extend(ul_bits);
    preimage.extend(ur_bits);

    let h = pedersen_hash_cs(cs, Personalization::MerkleTree { layer }, &preimage);
    // cur ← h.u
    (h.u, is_right_b)
}

/// Full path starting from an already-allocated field element (`cm.u`).
///
/// Returns `(anchor_u, position_bits)`.
pub fn merkle_path_from_u_cs(
    cs: &mut Cs,
    cm_u: &AllocatedNum,
    auth_path: &[([u8; 32], bool)],
) -> (AllocatedNum, Vec<Boolean>) {
    let mut cur = cm_u.clone();
    let mut position_bits = Vec::with_capacity(auth_path.len());
    for (layer, (sib, is_right)) in auth_path.iter().enumerate() {
        let (next, bit) = merkle_layer_cs(cs, &cur, sib, *is_right, layer as u8);
        position_bits.push(bit);
        cur = next;
    }
    (cur, position_bits)
}

/// Full path: start from note-commitment `cm` affine u, walk `auth_path`.
pub fn merkle_path_cs(
    cs: &mut Cs,
    cm: &JubJubPoint,
    auth_path: &[([u8; 32], bool)],
) -> (AllocatedNum, Vec<Boolean>) {
    let (u, _) = cm.affine_uv().expect("cm affine");
    let cur = AllocatedNum::alloc(cs, fe_to_scalar(&u));
    merkle_path_from_u_cs(cs, &cur, auth_path)
}

/// Enforce `cur == anchor` (public) when `value_num ≠ 0` is not required for
/// synthetic tests — we always bind equality: `cur - anchor = 0`.
pub fn enforce_anchor(cs: &mut Cs, cur: &AllocatedNum, anchor_le: &[u8; 32]) {
    let anchor = AllocatedNum::alloc(cs, sibling_le_to_scalar(anchor_le));
    // (cur - anchor) * 1 = 0
    let mut diff = lc_var(cur.var, Scalar::one());
    diff.add(anchor.var, Scalar::one().neg());
    cs.enforce_lc(diff, lc_one(), Lc::new());
    anchor.inputize(cs);
}

#[cfg(test)]
mod tests {
    use super::*;
    // `ScalarTrait` is used only by tests; keep the import here so
    // production builds carry no unused imports.
    use crate::curve::traits::Scalar as ScalarTrait;
    use crate::zk::sapling::constants::spending_key_generator;
    use crate::zk::sapling::cs::Cs;
    use crate::zk::sapling::native::{compute_merkle_root, compute_note_commitment, fe_to_le32};

    #[test]
    fn merkle_one_layer_matches_native() {
        let mut cs = Cs::new();
        let g = spending_key_generator();
        let cm = compute_note_commitment(10, &g, &g, &[1u8; 32]).unwrap();
        let mut sib = [0u8; 32];
        sib[0] = 7;
        let path = [(sib, false)];
        let (anchor_cs, _) = merkle_path_cs(&mut cs, &cm, &path);
        let anchor_fe = compute_merkle_root(&cm, &path).unwrap();
        let expect = fe_to_scalar(&anchor_fe);
        assert_eq!(ScalarTrait::ct_eq(&anchor_cs.value, &expect), 1);
        let (r1cs, z) = cs.into_r1cs();
        assert!(r1cs.is_satisfied(&z), "ncons={}", r1cs.constraints.len());
    }

    #[test]
    fn merkle_two_layers_matches_native() {
        let mut cs = Cs::new();
        let g = spending_key_generator();
        let cm = compute_note_commitment(10, &g, &g, &[1u8; 32]).unwrap();
        let mut s0 = [0u8; 32];
        s0[0] = 3;
        let mut s1 = [0u8; 32];
        s1[0] = 5;
        let path = [(s0, true), (s1, false)];
        let (anchor_cs, pos) = merkle_path_cs(&mut cs, &cm, &path);
        assert_eq!(pos.len(), 2);
        assert!(pos[0].value);
        assert!(!pos[1].value);
        let anchor_fe = compute_merkle_root(&cm, &path).unwrap();
        assert_eq!(
            ScalarTrait::ct_eq(&anchor_cs.value, &fe_to_scalar(&anchor_fe)),
            1
        );
        let (r1cs, z) = cs.into_r1cs();
        assert!(r1cs.is_satisfied(&z));
    }

    #[test]
    fn merkle_anchor_inputize_satisfied() {
        let mut cs = Cs::new();
        let g = spending_key_generator();
        let cm = compute_note_commitment(1, &g, &g, &[2u8; 32]).unwrap();
        let path = [([9u8; 32], false)];
        let (cur, _) = merkle_path_cs(&mut cs, &cm, &path);
        let anchor_fe = compute_merkle_root(&cm, &path).unwrap();
        let anchor_le = fe_to_le32(&anchor_fe);
        enforce_anchor(&mut cs, &cur, &anchor_le);
        let (r1cs, z) = cs.into_r1cs();
        assert_eq!(r1cs.num_public, 1);
        assert!(r1cs.is_satisfied(&z));
    }
}
