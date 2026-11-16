//! Native (non-circuit) Sapling algebra for Spend/Output statements.
//!
//! Aligns with `SaplingSpendCircuit.synthesize` / `exposeValueCommitment`
//! without R1CS boolean gadgets.

use crate::curve::error::{CurveError, CurveResult};
use crate::curve::jubjub::{Fe, JubJubPoint, Scalar};
use crate::curve::traits::CurvePoint;
use crate::hash::blake2s::{Blake2s, Blake2sTreeParams};
use crate::hash::pedersen::{pedersen_hash, PedersenHash, Personalization};
use crate::hash::HashResult;
use crate::zk::sapling::constants::{
    note_commitment_randomness_generator, nullifier_position_generator,
    proof_generation_key_generator, spending_key_generator, value_commitment_randomness_generator,
    value_commitment_value_generator,
};
use crate::zk::sapling::windows::{bytes_le_to_bits, fixed_base_mul_le_bits, u64_to_bits_le};
use alloc::vec::Vec;

fn map_hash_err(e: crate::hash::HashError) -> CurveError {
    let _ = e;
    CurveError::InvalidEncoding
}

fn scalar_from_le32(bytes: &[u8; 32]) -> CurveResult<Scalar> {
    Scalar::from_bytes_le(bytes)
}

fn fe_to_bits_le(fe: &Fe) -> [bool; 255] {
    let mut be = [0u8; 32];
    fe.to_bytes_be(&mut be);
    let mut le = [0u8; 32];
    for i in 0..32 {
        le[i] = be[31 - i];
    }
    let mut bits = [false; 255];
    for i in 0..255 {
        bits[i] = ((le[i / 8] >> (i % 8)) & 1) == 1;
    }
    bits
}

/// Zcash Sapling point representation: 255 LE bits of `v` ‖ LSB of `u` (256 bits).
pub fn point_repr_bits(p: &JubJubPoint) -> CurveResult<[bool; 256]> {
    let (u, v) = p.affine_uv()?;
    let mut out = [false; 256];
    let vbits = fe_to_bits_le(&v);
    out[..255].copy_from_slice(&vbits);
    let mut ube = [0u8; 32];
    u.to_bytes_be(&mut ube);
    // LSB of u in LE = least significant bit of u
    let ule0 = ube[31]; // low byte of LE is last of BE... wait LE byte0 = BE byte31
                        // Actually LE byte 0 is ube[31]
    out[255] = (ube[31] & 1) == 1;
    let _ = ule0;
    Ok(out)
}

fn blake2s_personal(personal: &[u8; 8], data: &[u8]) -> HashResult<[u8; 32]> {
    let tree = Blake2sTreeParams {
        fanout: 1,
        max_depth: 1,
        leaf_size: 0,
        node_offset: 0,
        node_depth: 0,
        inner_digest_length: 0,
        last_node: false,
        salt: None,
        personal: Some(*personal),
    };
    let mut h = Blake2s::new_with_tree(32, None, Some(&tree))?;
    h.update(data);
    h.finalize_256()
}

fn bits_to_bytes_le(bits: &[bool]) -> Vec<u8> {
    let mut out = vec![0u8; bits.len().div_ceil(8)];
    for (i, &b) in bits.iter().enumerate() {
        if b {
            out[i / 8] |= 1 << (i % 8);
        }
    }
    out
}

/// `cv = [value]·G_v + [rcv]·G_r`
pub fn compute_value_commitment(value: u64, rcv_le: &[u8; 32]) -> CurveResult<JubJubPoint> {
    let gv = value_commitment_value_generator();
    let gr = value_commitment_randomness_generator();
    let value_bits = u64_to_bits_le(value);
    let mut rcv_bits = bytes_le_to_bits(rcv_le);
    if rcv_bits.len() > 255 {
        rcv_bits.truncate(255);
    }
    Ok(fixed_base_mul_le_bits(&gv, &value_bits).add(&fixed_base_mul_le_bits(&gr, &rcv_bits)))
}

pub fn compute_value_commitment_scalar(value: u64, rcv_le: &[u8; 32]) -> CurveResult<JubJubPoint> {
    let mut vle = [0u8; 32];
    vle[..8].copy_from_slice(&value.to_le_bytes());
    let vs = Scalar::from_bytes_le(&vle)?;
    let rs = scalar_from_le32(rcv_le)?;
    Ok(value_commitment_value_generator()
        .mul(&vs)
        .add(&value_commitment_randomness_generator().mul(&rs)))
}

/// `rk = ak + [ar]·G`
pub fn compute_rk(ak: &JubJubPoint, ar_le: &[u8; 32]) -> CurveResult<JubJubPoint> {
    let mut ar_bits = bytes_le_to_bits(ar_le);
    if ar_bits.len() > 255 {
        ar_bits.truncate(255);
    }
    Ok(ak.add(&fixed_base_mul_le_bits(&spending_key_generator(), &ar_bits)))
}

pub fn compute_rk_scalar(ak: &JubJubPoint, ar_le: &[u8; 32]) -> CurveResult<JubJubPoint> {
    Ok(ak.add(&spending_key_generator().mul(&scalar_from_le32(ar_le)?)))
}

/// `nk = [nsk]·H`
pub fn compute_nk(nsk_le: &[u8; 32]) -> CurveResult<JubJubPoint> {
    let mut bits = bytes_le_to_bits(nsk_le);
    if bits.len() > 255 {
        bits.truncate(255);
    }
    Ok(fixed_base_mul_le_bits(
        &proof_generation_key_generator(),
        &bits,
    ))
}

/// `ivk = BLAKE2s("Zcashivk", ak‖nk)[0..255 bits]` as Fr LE.
pub fn compute_ivk(ak: &JubJubPoint, nk: &JubJubPoint) -> CurveResult<[u8; 32]> {
    let mut pre = Vec::with_capacity(64);
    pre.extend(bits_to_bytes_le(&point_repr_bits(ak)?));
    pre.extend(bits_to_bytes_le(&point_repr_bits(nk)?));
    // personal "Zcashivk" is 8 bytes
    let mut personal = [0u8; 8];
    personal.copy_from_slice(b"Zcashivk");
    let digest = blake2s_personal(&personal, &pre).map_err(map_hash_err)?;
    // clear bit 255 (capacity)
    let mut ivk = digest;
    ivk[31] &= 0x07; // keep only low 3 bits of last byte → 255 bits?
                     // 255 bits means clear top bit of byte 31: bit 7 of byte 31 is bit 255
    ivk[31] &= 0x7f;
    Ok(ivk)
}

/// `pk_d = [ivk] · g_d`
pub fn compute_pk_d(g_d: &JubJubPoint, ivk_le: &[u8; 32]) -> CurveResult<JubJubPoint> {
    Ok(g_d.mul(&scalar_from_le32(ivk_le)?))
}

/// Note commitment: Pedersen(NoteCommitment, value‖g_d‖pk_d) + [rcm]·G_rcm
pub fn compute_note_commitment(
    value: u64,
    g_d: &JubJubPoint,
    pk_d: &JubJubPoint,
    rcm_le: &[u8; 32],
) -> CurveResult<JubJubPoint> {
    let mut contents = Vec::with_capacity(64 + 256 + 256);
    contents.extend_from_slice(&u64_to_bits_le(value));
    contents.extend_from_slice(&point_repr_bits(g_d)?);
    contents.extend_from_slice(&point_repr_bits(pk_d)?);
    debug_assert_eq!(contents.len(), 576);
    let cm_base = pedersen_hash(&contents).map_err(map_hash_err)?;
    let mut rcm_bits = bytes_le_to_bits(rcm_le);
    if rcm_bits.len() > 255 {
        rcm_bits.truncate(255);
    }
    let rcm_p = fixed_base_mul_le_bits(&note_commitment_randomness_generator(), &rcm_bits);
    Ok(cm_base.add(&rcm_p))
}

/// Merkle root from note commitment `u` and auth path `(sibling_u_le, is_right)`.
pub fn compute_merkle_root(cm: &JubJubPoint, auth_path: &[([u8; 32], bool)]) -> CurveResult<Fe> {
    let (u, _) = cm.affine_uv()?;
    let mut cur = u;
    let ph = PedersenHash::new().map_err(map_hash_err)?;
    for (layer, (sibling_le, is_right)) in auth_path.iter().enumerate() {
        // sibling is Fq LE32
        let mut be = *sibling_le;
        be.reverse();
        let sib = Fe::from_bytes_be(&be).map_err(|_| CurveError::InvalidEncoding)?;
        let (ul, ur) = if *is_right { (sib, cur) } else { (cur, sib) };
        let mut preimage = Vec::with_capacity(510);
        preimage.extend_from_slice(&fe_to_bits_le(&ul));
        preimage.extend_from_slice(&fe_to_bits_le(&ur));
        let h = ph.hash(
            Personalization::MerkleTree { layer: layer as u8 },
            &preimage,
        );
        cur = h.affine_uv()?.0;
    }
    Ok(cur)
}

/// Position scalar bits from auth_path is_right flags (depth bits).
pub fn position_bits_from_path(auth_path: &[([u8; 32], bool)]) -> Vec<bool> {
    auth_path.iter().map(|(_, r)| *r).collect()
}

/// `rho = cm + [position]·J`
pub fn compute_rho(cm: &JubJubPoint, position_bits: &[bool]) -> CurveResult<JubJubPoint> {
    let pos = fixed_base_mul_le_bits(&nullifier_position_generator(), position_bits);
    Ok(cm.add(&pos))
}

/// `nf = BLAKE2s("Zcash_nf", nk_repr ‖ rho_repr)` (32 bytes).
pub fn compute_nullifier(nk: &JubJubPoint, rho: &JubJubPoint) -> CurveResult<[u8; 32]> {
    let mut pre = Vec::with_capacity(64);
    pre.extend(bits_to_bytes_le(&point_repr_bits(nk)?));
    pre.extend(bits_to_bytes_le(&point_repr_bits(rho)?));
    let mut personal = [0u8; 8];
    personal.copy_from_slice(b"Zcash_nf");
    blake2s_personal(&personal, &pre).map_err(map_hash_err)
}

pub fn point_to_public_uv(p: &JubJubPoint) -> CurveResult<([u8; 32], [u8; 32])> {
    p.affine_uv_le_bytes()
}

pub fn fe_to_le32(fe: &Fe) -> [u8; 32] {
    let mut be = [0u8; 32];
    fe.to_bytes_be(&mut be);
    let mut le = [0u8; 32];
    for i in 0..32 {
        le[i] = be[31 - i];
    }
    le
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zk::sapling::constants::proof_generation_key_generator;

    #[test]
    fn cv_window_matches_scalar() {
        let rcv = {
            let mut b = [0u8; 32];
            b[0] = 9;
            b
        };
        let a = compute_value_commitment(42, &rcv).unwrap();
        let b = compute_value_commitment_scalar(42, &rcv).unwrap();
        assert_eq!(
            a.affine_uv_le_bytes().unwrap(),
            b.affine_uv_le_bytes().unwrap()
        );
    }

    #[test]
    fn rk_window_matches_scalar() {
        let ak = proof_generation_key_generator();
        let mut ar = [0u8; 32];
        ar[0] = 3;
        assert_eq!(
            compute_rk(&ak, &ar).unwrap().affine_uv_le_bytes().unwrap(),
            compute_rk_scalar(&ak, &ar)
                .unwrap()
                .affine_uv_le_bytes()
                .unwrap()
        );
    }

    #[test]
    fn note_commit_and_nullifier_smoke() {
        let g_d = spending_key_generator();
        let ak = proof_generation_key_generator();
        let mut nsk = [0u8; 32];
        nsk[0] = 2;
        let nk = compute_nk(&nsk).unwrap();
        let ivk = compute_ivk(&ak, &nk).unwrap();
        let pk_d = compute_pk_d(&g_d, &ivk).unwrap();
        let mut rcm = [0u8; 32];
        rcm[0] = 5;
        let cm = compute_note_commitment(10, &g_d, &pk_d, &rcm).unwrap();
        assert_eq!(cm.ct_is_identity(), 0);
        let path = [([0u8; 32], false); 32];
        let _rt = compute_merkle_root(&cm, &path).unwrap();
        let pos = position_bits_from_path(&path);
        let rho = compute_rho(&cm, &pos).unwrap();
        let nf = compute_nullifier(&nk, &rho).unwrap();
        assert_ne!(nf, [0u8; 32]);
    }
}
