//! Build Spend/Output public inputs from witnesses (native algebra).

use crate::curve::bls::Scalar;
use crate::curve::error::CurveResult;
use crate::curve::jubjub::JubJubPoint;
use crate::curve::traits::CurvePoint;
use crate::zk::sapling::native::{
    compute_ivk, compute_merkle_root, compute_nk, compute_note_commitment, compute_nullifier,
    compute_pk_d, compute_rho, compute_rk, compute_value_commitment, fe_to_le32,
    point_to_public_uv, position_bits_from_path,
};
use crate::zk::sapling::spend::{
    pack_spend_public_inputs, OutputPublicInputs, SpendPublicInputs, SpendWitness,
};
use alloc::vec::Vec;

fn parse_point(compressed: &[u8; 32]) -> CurveResult<JubJubPoint> {
    JubJubPoint::from_bytes(compressed)
}

/// Derive full Spend public inputs from a witness (native, not circuit).
///
/// Produces the same 7 Fr packing order as `SaplingSpendCircuit`.
pub fn spend_public_inputs_from_witness(w: &SpendWitness) -> CurveResult<SpendPublicInputs> {
    let ak = parse_point(&w.ak)?;
    let g_d = parse_point(&w.g_d)?;

    let cv = compute_value_commitment(w.value, &w.rcv)?;
    let (cv_u, cv_v) = point_to_public_uv(&cv)?;

    let rk = compute_rk(&ak, &w.ar)?;
    let (rk_u, rk_v) = point_to_public_uv(&rk)?;

    let nk = compute_nk(&w.nsk)?;
    let ivk = compute_ivk(&ak, &nk)?;
    // Prefer witnessed pk_d if valid; else derive
    let pk_d = match parse_point(&w.pk_d) {
        Ok(p) if p.ct_is_identity() == 0 => p,
        _ => compute_pk_d(&g_d, &ivk)?,
    };

    let cm = compute_note_commitment(w.value, &g_d, &pk_d, &w.rcm)?;
    let path: alloc::vec::Vec<_> = w.auth_path.to_vec();
    let rt = compute_merkle_root(&cm, &path)?;
    let anchor = fe_to_le32(&rt);

    let pos = position_bits_from_path(&path);
    let rho = compute_rho(&cm, &pos)?;
    let nullifier = compute_nullifier(&nk, &rho)?;

    Ok(SpendPublicInputs {
        cv_u,
        cv_v,
        rk_u,
        rk_v,
        anchor,
        nullifier,
    })
}

/// Pack witness → public Fr vector (length 7).
pub fn spend_public_scalars_from_witness(w: &SpendWitness) -> CurveResult<Vec<Scalar>> {
    let pi = spend_public_inputs_from_witness(w)?;
    Ok(pack_spend_public_inputs(&pi))
}

/// Output public inputs from output fields (native).
pub fn output_public_inputs_from_parts(
    value: u64,
    rcv: &[u8; 32],
    g_d: &JubJubPoint,
    pk_d: &JubJubPoint,
    rcm: &[u8; 32],
    esk: &[u8; 32],
) -> CurveResult<OutputPublicInputs> {
    use crate::curve::jubjub::Scalar as JubScalar;
    use crate::zk::sapling::native::{compute_note_commitment, compute_value_commitment};
    use crate::zk::sapling::windows::{bytes_le_to_bits, fixed_base_mul_le_bits};

    let cv = compute_value_commitment(value, rcv)?;
    let (cv_u, cv_v) = point_to_public_uv(&cv)?;

    // epk = [esk] g_d
    let mut esk_bits = bytes_le_to_bits(esk);
    if esk_bits.len() > 255 {
        esk_bits.truncate(255);
    }
    // Use scalar mul for esk
    let esk_le = *esk;
    // ensure from_bytes works
    let epk = g_d.mul(
        &JubScalar::from_bytes_le(&esk_le)
            .map_err(|_| crate::curve::error::CurveError::InvalidEncoding)?,
    );
    let (epk_u, epk_v) = point_to_public_uv(&epk)?;

    let cm = compute_note_commitment(value, g_d, pk_d, rcm)?;
    let (cm_u, _) = point_to_public_uv(&cm)?;

    let _ = fixed_base_mul_le_bits; // silence if unused
    Ok(OutputPublicInputs {
        cv_u,
        cv_v,
        epk_u,
        epk_v,
        cm_u,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zk::sapling::constants::{proof_generation_key_generator, spending_key_generator};
    use crate::zk::sapling::spend::{SpendWitness, SPEND_NUM_PUBLIC};

    fn point_bytes(p: &JubJubPoint) -> [u8; 32] {
        let mut b = [0u8; 32];
        p.to_bytes_compressed(&mut b).unwrap();
        b
    }

    #[test]
    fn spend_builder_produces_seven_inputs() {
        let mut w = SpendWitness::synthetic();
        w.ak = point_bytes(&proof_generation_key_generator());
        w.g_d = point_bytes(&spending_key_generator());
        w.pk_d = [0u8; 32]; // force derive from ivk
        let pi = spend_public_inputs_from_witness(&w).expect("build");
        let sc = pack_spend_public_inputs(&pi);
        assert_eq!(sc.len(), SPEND_NUM_PUBLIC);
        // cv / rk not identity-ish
        assert_ne!(pi.cv_u, [0u8; 32]);
        assert_ne!(pi.nullifier, [0u8; 32]);
    }
}
