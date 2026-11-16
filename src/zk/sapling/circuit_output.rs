//! Sapling Output circuit synthesis (`SaplingOutputCircuit`).
//!
//! Public inputs (5 Fr): `cv.u, cv.v, epk.u, epk.v, cm.u`.

use crate::curve::bls::Scalar;
use crate::curve::jubjub::JubJubPoint;
use crate::curve::traits::CurvePoint;
use crate::zk::groth16::R1csBls;
use crate::zk::sapling::boolean::{fr_to_bits, u64_to_bits, Boolean};
use crate::zk::sapling::constants::{
    value_commitment_randomness_generator, value_commitment_value_generator,
};
use crate::zk::sapling::cs::Cs;
use crate::zk::sapling::edwards::{fixed_base_mul, EdwardsPoint};
use crate::zk::sapling::spend::OutputWitness;
use alloc::vec::Vec;

fn parse_point(b: &[u8; 32]) -> JubJubPoint {
    JubJubPoint::from_bytes(b).unwrap_or_else(|_| JubJubPoint::identity())
}

/// Output circuit stats (parallel to Spend). Test-only helper.
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputCircuitStats {
    pub num_constraints: usize,
    pub num_public: usize,
    pub num_variables: usize,
}

/// Synthesize Sapling Output R1CS for witness `w`.
///
/// Stages (reference order):
/// 1. `cv` fixed-base value commitment → public
/// 2. `g_d` witness + not-small-order; `epk = [esk]·g_d` → public
/// 3. `pk_d` representation into note contents
/// 4. note commitment + `[rcm]`; expose **cm.u** only
pub fn synthesize_output(w: &OutputWitness) -> (R1csBls, Vec<Scalar>) {
    let mut cs = Cs::new();

    // --- sapling-crypto Output::synthesize order (exact for ceremony LC identity) ---
    // 1. value commitment → cv public + value_bits for note
    let value_bits = u64_to_bits(&mut cs, w.value);
    let value_p = fixed_base_mul(&mut cs, &value_commitment_value_generator(), &value_bits);
    let rcv_bits = fr_to_bits(&mut cs, &w.rcv, 252);
    let rcv_p = fixed_base_mul(&mut cs, &value_commitment_randomness_generator(), &rcv_bits);
    let cv = EdwardsPoint::add(&mut cs, &value_p, &rcv_p);
    cv.inputize(&mut cs);

    let mut note_contents = value_bits;
    while note_contents.len() < 64 {
        note_contents.push(Boolean::constant(&mut cs, false));
    }
    note_contents.truncate(64);

    // 2. g_d witness → not-small-order → g_d.repr into note → esk → epk → inputize epk
    let g_d_pt = parse_point(&w.g_d);
    let g_d = EdwardsPoint::witness(&mut cs, &g_d_pt);
    g_d.assert_not_small_order(&mut cs);
    note_contents.extend(g_d.repr(&mut cs));

    let esk_bits = fr_to_bits(&mut cs, &w.esk, 252);
    let epk = EdwardsPoint::mul_bits(&mut cs, &g_d, &esk_bits);
    epk.inputize(&mut cs);

    // 3. pk_d: v LE 255 bits + u sign (no on-curve)
    {
        let pk_d_pt = parse_point(&w.pk_d);
        let (ule, vle) = pk_d_pt
            .affine_uv_le_bytes()
            .unwrap_or(([0u8; 32], [0u8; 32]));
        note_contents.extend(fr_to_bits(&mut cs, &vle, 255));
        let u_odd = (ule[0] & 1) == 1;
        note_contents.push(Boolean::alloc(&mut cs, u_odd));
    }
    assert_eq!(note_contents.len(), 64 + 256 + 256);

    // 4. note commitment: sapling-crypto order = pedersen_hash(contents) FIRST,
    //    THEN rcm bits → fixed_base → add → cm.u public.
    //    (Allocating rcm before the hash shifts dens-set and breaks ceremony.)
    let cm_base = crate::zk::sapling::pedersen_circuit::pedersen_hash_cs(
        &mut cs,
        crate::hash::pedersen::Personalization::NoteCommitment,
        &note_contents,
    );
    let rcm_bits = fr_to_bits(&mut cs, &w.rcm, 252);
    let rcm_p = crate::zk::sapling::edwards::fixed_base_mul(
        &mut cs,
        &crate::zk::sapling::constants::note_commitment_randomness_generator(),
        &rcm_bits,
    );
    let cm = EdwardsPoint::add(&mut cs, &cm_base, &rcm_p);
    cm.u.inputize(&mut cs);

    cs.into_r1cs()
}

/// Same as [`synthesize_output`], with size stats. Test-only helper.
#[cfg(test)]
pub fn synthesize_output_with_stats(
    w: &OutputWitness,
) -> (R1csBls, Vec<Scalar>, OutputCircuitStats) {
    let (r1cs, z) = synthesize_output(w);
    let stats = OutputCircuitStats {
        num_constraints: r1cs.constraints.len(),
        num_public: r1cs.num_public,
        num_variables: r1cs.num_variables,
    };
    (r1cs, z, stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    // `ScalarTrait` is used only by tests; keep the import here so
    // production builds carry no unused imports.
    use crate::curve::traits::Scalar as ScalarTrait;
    // Test-only prove/verify round-trip + native cross-check imports.
    use crate::zk::groth16::{prove_bls_with_randomness, setup_from_r1cs_synthetic, verify};
    use crate::zk::sapling::constants::spending_key_generator;
    use crate::zk::sapling::native::compute_note_commitment;
    use crate::zk::sapling::num::scalar_from_fe_le;
    use crate::zk::{note_commitment_cs, OUTPUT_NUM_PUBLIC};

    fn point_bytes(p: &JubJubPoint) -> [u8; 32] {
        let mut b = [0u8; 32];
        p.to_bytes_compressed(&mut b).unwrap();
        b
    }

    fn good_output() -> OutputWitness {
        let mut w = OutputWitness::synthetic();
        w.g_d = point_bytes(&spending_key_generator());
        w.pk_d = point_bytes(&value_commitment_value_generator());
        w
    }

    #[test]

    fn output_stage_costs() {
        use crate::zk::sapling::boolean::{fr_to_bits, u64_to_bits, Boolean};
        use crate::zk::sapling::constants::*;
        use crate::zk::sapling::cs::Cs;
        use crate::zk::sapling::edwards::{fixed_base_mul, EdwardsPoint};
        use crate::zk::sapling::pedersen_circuit::note_commitment_cs;
        let w = good_output();
        fn mark(cs: &Cs) -> usize {
            cs.constraints.len()
        }
        let mut cs = Cs::new();
        let s0 = mark(&cs);
        let value_bits = u64_to_bits(&mut cs, w.value);
        let value_p = fixed_base_mul(&mut cs, &value_commitment_value_generator(), &value_bits);
        let rcv_bits = fr_to_bits(&mut cs, &w.rcv, 252);
        let rcv_p = fixed_base_mul(&mut cs, &value_commitment_randomness_generator(), &rcv_bits);
        let cv = EdwardsPoint::add(&mut cs, &value_p, &rcv_p);
        cv.inputize(&mut cs);
        eprintln!("Output cv stage: {}", mark(&cs) - s0);

        let s1 = mark(&cs);
        let g_d_pt = parse_point(&w.g_d);
        let g_d = EdwardsPoint::witness(&mut cs, &g_d_pt);
        eprintln!("  after g_d witness: {}", mark(&cs) - s1);
        g_d.assert_not_small_order(&mut cs);
        eprintln!("  after small-order: {}", mark(&cs) - s1);
        let esk_bits = fr_to_bits(&mut cs, &w.esk, 252);
        eprintln!("  after esk bits: {}", mark(&cs) - s1);
        let epk = EdwardsPoint::mul_bits(&mut cs, &g_d, &esk_bits);
        eprintln!("  after mul_bits: {}", mark(&cs) - s1);
        epk.inputize(&mut cs);
        eprintln!("Output g_d+epk stage: {}", mark(&cs) - s1);

        let s2 = mark(&cs);
        let mut note_contents = value_bits.clone();
        while note_contents.len() < 64 {
            note_contents.push(Boolean::constant(&mut cs, false));
        }
        note_contents.truncate(64);
        note_contents.extend(g_d.repr(&mut cs));
        {
            let pk_d_pt = parse_point(&w.pk_d);
            let (ule, vle) = pk_d_pt
                .affine_uv_le_bytes()
                .unwrap_or(([0u8; 32], [0u8; 32]));
            note_contents.extend(fr_to_bits(&mut cs, &vle, 255));
            note_contents.push(Boolean::alloc(&mut cs, (ule[0] & 1) == 1));
        }
        let rcm_bits = fr_to_bits(&mut cs, &w.rcm, 252);
        let cm = note_commitment_cs(&mut cs, &note_contents, &rcm_bits);
        cm.u.inputize(&mut cs);
        eprintln!("Output note+cm stage: {}", mark(&cs) - s2);
        eprintln!("Output total: {}", mark(&cs));
    }

    #[test]
    fn output_stage_aux_breakdown() {
        use crate::zk::sapling::boolean::{fr_to_bits, u64_to_bits, Boolean};
        use crate::zk::sapling::constants::*;
        use crate::zk::sapling::cs::Cs;
        use crate::zk::sapling::edwards::{fixed_base_mul, EdwardsPoint};
        use crate::zk::sapling::pedersen_circuit::note_commitment_cs;
        let w = good_output();
        let mut cs = Cs::new();
        let snap = |cs: &Cs| (cs.constraints.len(), cs.aux.len(), cs.inputs.len());
        let mut prev = snap(&cs);
        let report = |label: &str, cs: &Cs, prev: &mut (usize, usize, usize)| {
            let now = snap(cs);
            eprintln!(
                "{label}: Δcons={} Δaux={} Δin={}  total cons={} aux={} in={}",
                now.0 - prev.0,
                now.1 - prev.1,
                now.2 - prev.2,
                now.0,
                now.1,
                now.2
            );
            *prev = now;
        };

        let value_bits = u64_to_bits(&mut cs, w.value);
        report("value_bits64", &cs, &mut prev);
        let value_p = fixed_base_mul(&mut cs, &value_commitment_value_generator(), &value_bits);
        report("fixed_base value", &cs, &mut prev);
        let rcv_bits = fr_to_bits(&mut cs, &w.rcv, 252);
        report("rcv_bits252", &cs, &mut prev);
        let rcv_p = fixed_base_mul(&mut cs, &value_commitment_randomness_generator(), &rcv_bits);
        report("fixed_base rcv", &cs, &mut prev);
        let cv = EdwardsPoint::add(&mut cs, &value_p, &rcv_p);
        report("cv add", &cs, &mut prev);
        cv.inputize(&mut cs);
        report("cv inputize", &cs, &mut prev);

        let g_d = EdwardsPoint::witness(&mut cs, &parse_point(&w.g_d));
        report("g_d witness", &cs, &mut prev);
        g_d.assert_not_small_order(&mut cs);
        report("g_d small_order", &cs, &mut prev);
        let esk_bits = fr_to_bits(&mut cs, &w.esk, 252);
        report("esk_bits252", &cs, &mut prev);
        let epk = EdwardsPoint::mul_bits(&mut cs, &g_d, &esk_bits);
        report("epk mul_bits252", &cs, &mut prev);
        epk.inputize(&mut cs);
        report("epk inputize", &cs, &mut prev);

        let mut note = value_bits.clone();
        while note.len() < 64 {
            note.push(Boolean::constant(&mut cs, false));
        }
        note.truncate(64);
        note.extend(g_d.repr(&mut cs));
        report("g_d repr", &cs, &mut prev);
        {
            let (ule, vle) = parse_point(&w.pk_d).affine_uv_le_bytes().unwrap();
            note.extend(fr_to_bits(&mut cs, &vle, 255));
            note.push(Boolean::alloc(&mut cs, (ule[0] & 1) == 1));
        }
        report("pk_d bits256", &cs, &mut prev);
        let rcm_bits = fr_to_bits(&mut cs, &w.rcm, 252);
        report("rcm_bits252", &cs, &mut prev);
        let cm = note_commitment_cs(&mut cs, &note, &rcm_bits);
        report("note_commitment", &cs, &mut prev);
        cm.u.inputize(&mut cs);
        report("cm.u inputize", &cs, &mut prev);
        eprintln!(
            "FINAL: cons={} aux={} in={} nvars≈{}",
            cs.constraints.len(),
            cs.aux.len(),
            cs.inputs.len(),
            cs.aux.len() + cs.inputs.len()
        );
    }

    #[test]
    fn synthesize_output_satisfied() {
        let w = good_output();
        let (r1cs, assignment, stats) = synthesize_output_with_stats(&w);
        assert!(
            r1cs.is_satisfied(&assignment),
            "ncons={} pub={}",
            stats.num_constraints,
            stats.num_public
        );
        assert_eq!(r1cs.num_public, OUTPUT_NUM_PUBLIC);
        eprintln!(
            "Output: constraints={} vars={} public={}",
            stats.num_constraints, stats.num_variables, stats.num_public
        );
    }

    /// cv + epk only (4 Fr) — fast Groth16 smoke for Output gadgets.
    #[test]
    fn synthesize_output_cv_epk_prove_verify() {
        let mut cs = Cs::new();
        let value_bits: Vec<_> = u64_to_bits(&mut cs, 10).into_iter().take(9).collect();
        let value_p = fixed_base_mul(&mut cs, &value_commitment_value_generator(), &value_bits);
        let mut rcv = [0u8; 32];
        rcv[0] = 1;
        let rcv_bits = fr_to_bits(&mut cs, &rcv, 9);
        let rcv_p = fixed_base_mul(&mut cs, &value_commitment_randomness_generator(), &rcv_bits);
        let cv = EdwardsPoint::add(&mut cs, &value_p, &rcv_p);
        cv.inputize(&mut cs);

        let g_d = EdwardsPoint::witness(&mut cs, &spending_key_generator());
        let mut esk = [0u8; 32];
        esk[0] = 3;
        let esk_bits = fr_to_bits(&mut cs, &esk, 8);
        let epk = EdwardsPoint::mul_bits(&mut cs, &g_d, &esk_bits);
        epk.inputize(&mut cs);

        let (r1cs, assignment) = cs.into_r1cs();
        assert!(r1cs.is_satisfied(&assignment));
        assert_eq!(r1cs.num_public, 4);
        let mut pk = setup_from_r1cs_synthetic(&r1cs);
        pk.clear_trapdoor();
        let proof = prove_bls_with_randomness(
            &pk,
            &r1cs,
            &assignment,
            &Scalar::from_u64(3),
            &Scalar::from_u64(5),
        )
        .expect("prove");
        let public: Vec<Scalar> = assignment[1..1 + r1cs.num_public].to_vec();
        verify(&pk.vk, &public, &proof).expect("verify");
        eprintln!(
            "Output cv+epk prove/verify OK (constraints={})",
            r1cs.constraints.len()
        );
    }

    #[test]
    fn output_cm_u_matches_native() {
        let w = good_output();
        let mut cs = Cs::new();
        let value_bits = u64_to_bits(&mut cs, w.value);
        let g_d = EdwardsPoint::witness(&mut cs, &parse_point(&w.g_d));
        let pk_d = EdwardsPoint::witness(&mut cs, &parse_point(&w.pk_d));
        let mut note = value_bits;
        while note.len() < 64 {
            note.push(Boolean::constant(&mut cs, false));
        }
        note.truncate(64);
        note.extend(g_d.repr(&mut cs));
        note.extend(pk_d.repr(&mut cs));
        let rcm_bits = fr_to_bits(&mut cs, &w.rcm, 252);
        let cm = note_commitment_cs(&mut cs, &note, &rcm_bits);
        let cm_n =
            compute_note_commitment(w.value, &parse_point(&w.g_d), &parse_point(&w.pk_d), &w.rcm)
                .unwrap();
        let (ule, _) = cm_n.affine_uv_le_bytes().unwrap();
        assert_eq!(ScalarTrait::ct_eq(&cm.u.value, &scalar_from_fe_le(&ule)), 1);
        let (r1cs, z) = cs.into_r1cs();
        assert!(r1cs.is_satisfied(&z));
    }
}
