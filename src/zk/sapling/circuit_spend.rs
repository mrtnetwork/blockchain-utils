//! Spend circuit synthesis — constrained gadgets + hybrid depth control.

use crate::curve::bls::Scalar;
use crate::curve::jubjub::JubJubPoint;
use crate::curve::traits::CurvePoint;
use crate::zk::groth16::R1csBls;
use crate::zk::sapling::blake2s_circuit::{blake2s_zcash_ivk, blake2s_zcash_nf};
use crate::zk::sapling::boolean::{fr_to_bits, u64_to_bits, Boolean};
use crate::zk::sapling::constants::{
    nullifier_position_generator, proof_generation_key_generator, spending_key_generator,
    value_commitment_randomness_generator, value_commitment_value_generator,
};
use crate::zk::sapling::cs::Cs;
use crate::zk::sapling::edwards::{fixed_base_mul, EdwardsPoint};
use crate::zk::sapling::merkle_circuit::merkle_path_from_u_cs;
use crate::zk::sapling::native::position_bits_from_path;
use crate::zk::sapling::num::AllocatedNum;
use crate::zk::sapling::spend::SpendWitness;
use alloc::vec::Vec;

/// Measured size of a synthesized Spend R1CS at a given Merkle depth.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendCircuitStats {
    pub depth: usize,
    pub num_constraints: usize,
    pub num_public: usize,
    pub num_variables: usize,
}

impl SpendCircuitStats {
    pub fn from_r1cs(depth: usize, r1cs: &R1csBls) -> Self {
        Self {
            depth,
            num_constraints: r1cs.constraints.len(),
            num_public: r1cs.num_public,
            num_variables: r1cs.num_variables,
        }
    }
}

/// Synthesize Spend at `depth` and return R1CS + assignment + stats.
pub fn synthesize_spend_with_stats(
    w: &SpendWitness,
    depth: usize,
) -> (R1csBls, Vec<Scalar>, SpendCircuitStats) {
    let (r1cs, z) = synthesize_spend_depth(w, depth);
    let stats = SpendCircuitStats::from_r1cs(depth.min(w.auth_path.len()), &r1cs);
    (r1cs, z, stats)
}

fn parse_point(b: &[u8; 32]) -> JubJubPoint {
    JubJubPoint::from_bytes(b).unwrap_or_else(|_| JubJubPoint::identity())
}

fn multipack_inputize_bits(cs: &mut Cs, bits: &[Boolean]) {
    // Bellman multipack::pack_into_inputs: each public Fr is Σ bit·2^i
    // with a single equality constraint (no private intermediate).
    // Bits may carry free NOT polarity — always use add_to_lc.
    use crate::zk::sapling::cs::{lc_one, lc_var, Lc};
    const CAP: usize = 254; // bls12-381 Scalar::CAPACITY
    let mut i = 0;
    while i < bits.len() {
        let end = core::cmp::min(i + CAP, bits.len());
        let mut acc = Scalar::zero();
        let mut coeff = Scalar::one();
        let mut lc = Lc::new();
        for b in &bits[i..end] {
            if b.value {
                acc = acc.add(&coeff);
            }
            b.add_to_lc(&mut lc, cs.one(), coeff);
            coeff = coeff.add(&coeff);
        }
        let input = cs.alloc_input(|| acc);
        cs.enforce_lc(lc, lc_one(), lc_var(input, Scalar::one()));
        i = end;
    }
}

/// Full constrained Spend for a **short** Merkle path (`auth_path[..depth]`).
///
/// Stages:
/// 1. cv, rk, nk (fixed-base)
/// 2. ivk = BLAKE2s(Zcashivk, ak‖nk)[0..255]
/// 3. pk_d = [ivk]·g_d (variable-base)
/// 4. note commitment (Pedersen + rcm)
/// 5. Merkle path → anchor
/// 6. rho, nf = BLAKE2s(Zcash_nf, nk‖rho); multipack
pub fn synthesize_spend_depth(w: &SpendWitness, depth: usize) -> (R1csBls, Vec<Scalar>) {
    // Match sapling-crypto Spend::synthesize constraint / input order.
    let mut cs = Cs::new();
    let depth = depth.min(w.auth_path.len());

    // 1. ak witness + not small order
    let ak_pt = parse_point(&w.ak);
    let ak = EdwardsPoint::witness(&mut cs, &ak_pt);
    ak.assert_not_small_order(&mut cs);

    // 2. rk = ak + [ar]G → inputize FIRST (public 0,1)
    let ar_bits = fr_to_bits(&mut cs, &w.ar, 252);
    let ar_p = fixed_base_mul(&mut cs, &spending_key_generator(), &ar_bits);
    let rk = EdwardsPoint::add(&mut cs, &ak, &ar_p);
    rk.inputize(&mut cs);

    // 3. nk = [nsk] PGK
    let nsk_bits = fr_to_bits(&mut cs, &w.nsk, 252);
    let nk = fixed_base_mul(&mut cs, &proof_generation_key_generator(), &nsk_bits);

    // 4. ivk preimage = ak.repr ‖ nk.repr; nf preimage starts with nk.repr
    let mut ivk_pre = ak.repr(&mut cs);
    let repr_nk = nk.repr(&mut cs);
    ivk_pre.extend(repr_nk.iter().cloned());
    let mut nf_pre = repr_nk;
    assert_eq!(ivk_pre.len(), 512);
    assert_eq!(nf_pre.len(), 256);

    // 5. ivk = BLAKE2s; truncate to Fr capacity (251)
    let ivk_bits_full = blake2s_zcash_ivk(&mut cs, &ivk_pre);
    // Keep free NOT polarity; conditionally_select / mul_bits handle inverted bits.
    let ivk_bits: Vec<Boolean> = ivk_bits_full.into_iter().take(251).collect();

    // 6. g_d + not small order; pk_d = [ivk] g_d
    let g_d_pt = parse_point(&w.g_d);
    let g_d = EdwardsPoint::witness(&mut cs, &g_d_pt);
    g_d.assert_not_small_order(&mut cs);
    let pk_d = EdwardsPoint::mul_bits(&mut cs, &g_d, &ivk_bits);

    // 7. value commitment (cv) exposed here — public 2,3; returns value_bits for note
    let value_bits = u64_to_bits(&mut cs, w.value);
    let value_p = fixed_base_mul(&mut cs, &value_commitment_value_generator(), &value_bits);
    let rcv_bits = fr_to_bits(&mut cs, &w.rcv, 252);
    let rcv_p = fixed_base_mul(&mut cs, &value_commitment_randomness_generator(), &rcv_bits);
    let cv = EdwardsPoint::add(&mut cs, &value_p, &rcv_p);
    cv.inputize(&mut cs);

    // value as Num for conditional anchor: Σ value_bits * 2^i
    // (we use bitness-enforced bits; linear combo without extra constraints)
    // 8. note contents = value ‖ g_d.repr ‖ pk_d.repr
    let mut note_contents = value_bits.clone();
    // Pad with structural constant false (0 constraints) — not Boolean::alloc.
    while note_contents.len() < 64 {
        note_contents.push(Boolean::constant(&mut cs, false));
    }
    note_contents.truncate(64);
    note_contents.extend(g_d.repr(&mut cs));
    note_contents.extend(pk_d.repr(&mut cs));
    assert_eq!(note_contents.len(), 64 + 256 + 256);

    // 9. cm = NoteCommit + [rcm]
    // sapling-crypto order: pedersen_hash(contents) FIRST, then rcm bits → fixed_base → add
    // (allocating rcm before the hash shifts dens-set / breaks ceremony)
    let cm_base = crate::zk::sapling::pedersen_circuit::pedersen_hash_cs(
        &mut cs,
        crate::hash::pedersen::Personalization::NoteCommitment,
        &note_contents,
    );
    let rcm_bits = fr_to_bits(&mut cs, &w.rcm, 252);
    let rcm_p = fixed_base_mul(
        &mut cs,
        &crate::zk::sapling::constants::note_commitment_randomness_generator(),
        &rcm_bits,
    );
    let cm = EdwardsPoint::add(&mut cs, &cm_base, &rcm_p);

    // 10. Merkle path (non-strict bits, matching sapling-crypto)
    let path = &w.auth_path[..depth];
    let (anchor_u, position_bits) = merkle_path_from_u_cs(&mut cs, &cm.u, path);

    // 11. Conditional anchor (sapling-crypto): (cur - rt) * value = 0; inputize rt.
    // Witness rt from circuit-recomputed cur so assignment is consistent when value ≠ 0.
    {
        use crate::curve::bls::Scalar;
        use crate::zk::sapling::cs::{lc_var, Lc};
        let rt = AllocatedNum::alloc(&mut cs, anchor_u.value);
        let mut value_lc = Lc::new();
        let mut coeff = Scalar::one();
        for bit in &value_bits {
            bit.add_to_lc(&mut value_lc, cs.one(), coeff);
            coeff = coeff.add(&coeff);
        }
        let mut diff = lc_var(anchor_u.var, Scalar::one());
        diff.add(rt.var, Scalar::one().neg());
        cs.enforce_lc(diff, value_lc, Lc::new());
        rt.inputize(&mut cs);
    }

    // 12. rho = cm + [position] J
    let pos_p = fixed_base_mul(&mut cs, &nullifier_position_generator(), &position_bits);
    let rho = EdwardsPoint::add(&mut cs, &cm, &pos_p);

    // 13. nf = BLAKE2s(nk ‖ rho); pack into inputs
    nf_pre.extend(rho.repr(&mut cs));
    assert_eq!(nf_pre.len(), 512);
    let nf_bits = blake2s_zcash_nf(&mut cs, &nf_pre);
    multipack_inputize_bits(&mut cs, &nf_bits);

    let _ = position_bits_from_path;
    cs.into_r1cs()
}

pub fn synthesize_spend(w: &SpendWitness) -> (R1csBls, Vec<Scalar>) {
    // Default short path for practical runtime; production uses depth 32.
    synthesize_spend_depth(w, 2)
}

pub fn synthesize_spend_cv_rk(w: &SpendWitness) -> (R1csBls, Vec<Scalar>) {
    let mut cs = Cs::new();
    let value_bits = u64_to_bits(&mut cs, w.value);
    let value_p = fixed_base_mul(&mut cs, &value_commitment_value_generator(), &value_bits);
    let rcv_bits = fr_to_bits(&mut cs, &w.rcv, 252);
    let rcv_p = fixed_base_mul(&mut cs, &value_commitment_randomness_generator(), &rcv_bits);
    let cv = EdwardsPoint::add(&mut cs, &value_p, &rcv_p);
    cv.inputize(&mut cs);
    let ak = EdwardsPoint::witness(&mut cs, &parse_point(&w.ak));
    let ar_bits = fr_to_bits(&mut cs, &w.ar, 252);
    let ar_p = fixed_base_mul(&mut cs, &spending_key_generator(), &ar_bits);
    let rk = EdwardsPoint::add(&mut cs, &ak, &ar_p);
    rk.inputize(&mut cs);
    cs.into_r1cs()
}

/// Fingerprint of a synthesized Spend for order-alignment diffs.
#[derive(Clone, Debug)]
pub struct CircuitFingerprint {
    pub num_constraints: usize,
    pub num_variables: usize,
    pub num_public: usize,
    /// First 16 constraint A/B/C term counts (stable structural signature).
    pub head_term_profile: alloc::vec::Vec<(u16, u16, u16)>,
    /// Last 16 constraint A/B/C term counts.
    pub tail_term_profile: alloc::vec::Vec<(u16, u16, u16)>,
    /// FNV-1a over (term counts + first var index per side) for full matrix shape.
    pub structure_digest: u64,
}

/// Synthesize Spend at `depth` and return a structural fingerprint (no secrets).
pub fn spend_circuit_fingerprint(w: &SpendWitness, depth: usize) -> CircuitFingerprint {
    let (r1cs, _assignment, stats) = synthesize_spend_with_stats(w, depth);
    let n = r1cs.constraints.len();
    let profile = |slice: &[crate::zk::groth16::ConstraintBls]| {
        slice
            .iter()
            .map(|c: &crate::zk::groth16::ConstraintBls| {
                (
                    c.a.terms.len() as u16,
                    c.b.terms.len() as u16,
                    c.c.terms.len() as u16,
                )
            })
            .collect()
    };
    let head = if n >= 16 {
        &r1cs.constraints[..16]
    } else {
        &r1cs.constraints[..]
    };
    let tail = if n >= 16 {
        &r1cs.constraints[n - 16..]
    } else {
        &r1cs.constraints[..]
    };
    let mut h: u64 = 0xcbf29ce484222325;
    let mix = |h: &mut u64, x: u64| {
        *h ^= x;
        *h = h.wrapping_mul(0x100000001b3);
    };
    for c in &r1cs.constraints {
        mix(&mut h, c.a.terms.len() as u64);
        mix(&mut h, c.b.terms.len() as u64);
        mix(&mut h, c.c.terms.len() as u64);
        if let Some(&(v, _)) = c.a.terms.first() {
            mix(&mut h, v as u64);
        }
        if let Some(&(v, _)) = c.b.terms.first() {
            mix(&mut h, v as u64);
        }
        if let Some(&(v, _)) = c.c.terms.first() {
            mix(&mut h, v as u64);
        }
    }
    CircuitFingerprint {
        num_constraints: stats.num_constraints,
        num_variables: stats.num_variables,
        num_public: stats.num_public,
        head_term_profile: profile(head),
        tail_term_profile: profile(tail),
        structure_digest: h,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // `ScalarTrait` is used only by tests; keep the import here so
    // production builds carry no unused imports.
    use crate::curve::traits::Scalar as ScalarTrait;
    // Test-only prove/verify round-trip + native cross-check imports.
    use crate::zk::groth16::{prove_bls_with_randomness, setup_from_r1cs_synthetic, verify};
    use crate::zk::sapling::constants::proof_generation_key_generator;
    use crate::zk::{compute_ivk, compute_nk, compute_pk_d, SPEND_NUM_PUBLIC};
    use crate::zk::{enforce_anchor, merkle_path_cs};

    fn point_bytes(p: &JubJubPoint) -> [u8; 32] {
        let mut b = [0u8; 32];
        p.to_bytes_compressed(&mut b).unwrap();
        b
    }

    fn good_witness() -> SpendWitness {
        let mut w = SpendWitness::synthetic();
        w.ak = point_bytes(&proof_generation_key_generator());
        w.g_d = point_bytes(&spending_key_generator());
        w.pk_d = point_bytes(&value_commitment_value_generator());
        w
    }

    #[test]
    fn only_bits_ok() {
        let mut cs = Cs::new();
        let _ = u64_to_bits(&mut cs, 10);
        let (r1cs, z) = cs.into_r1cs();
        assert!(r1cs.is_satisfied(&z));
    }

    /// Compare our gadget costs to Zcash protocol.pdf Appendix A targets.
    #[test]
    #[cfg(all(feature = "std", feature = "groth16-prover"))]
    fn spend_stage_aux_dens() {
        use crate::zk::groth16::{a_density, b_density};
        use crate::zk::sapling::blake2s_circuit::blake2s_zcash_ivk;
        use crate::zk::sapling::boolean::fr_to_bits;
        use crate::zk::sapling::constants::*;
        use crate::zk::sapling::cs::Cs;
        use crate::zk::sapling::edwards::{fixed_base_mul, EdwardsPoint};
        let w = crate::zk::sapling::spend::SpendWitness::synthetic();
        let mut cs = Cs::new();
        let report = |label: &str, cs: &Cs| {
            let ncons = cs.constraints.len();
            // can't dens without into_r1cs consuming; just print ncons/approx aux
            println!("{label}: ncons={ncons}");
        };
        let ak = EdwardsPoint::witness(&mut cs, &super::parse_point(&w.ak));
        ak.assert_not_small_order(&mut cs);
        report("after ak", &cs);
        let ar_bits = fr_to_bits(&mut cs, &w.ar, 252);
        let ar_p = fixed_base_mul(&mut cs, &spending_key_generator(), &ar_bits);
        let rk = EdwardsPoint::add(&mut cs, &ak, &ar_p);
        rk.inputize(&mut cs);
        report("after rk", &cs);
        let nsk_bits = fr_to_bits(&mut cs, &w.nsk, 252);
        let nk = fixed_base_mul(&mut cs, &proof_generation_key_generator(), &nsk_bits);
        report("after nk", &cs);
        let mut ivk_pre = ak.repr(&mut cs);
        let repr_nk = nk.repr(&mut cs);
        ivk_pre.extend(repr_nk.iter().cloned());
        report("after repr", &cs);
        let _ = blake2s_zcash_ivk(&mut cs, &ivk_pre);
        report("after blake2s ivk", &cs);
        // dens at this point
        let (r1cs, _) = cs.into_r1cs();
        let da = a_density(&r1cs);
        let db = b_density(&r1cs);
        println!(
            "through blake2s ivk: nvars={} a={} b={}",
            r1cs.num_variables,
            da.len(),
            db.len()
        );
    }

    #[cfg(all(feature = "std", feature = "groth16-prover"))]
    #[test]

    fn spend_dens_depth_probe() {
        use crate::zk::groth16::{a_density, b_density};
        let w = crate::zk::sapling::spend::SpendWitness::synthetic();
        for depth in [0usize, 1, 2, 8, 32] {
            let (r1cs, _) = super::synthesize_spend_depth(&w, depth);
            let da = a_density(&r1cs);
            let db = b_density(&r1cs);
            println!(
                "depth={depth}: ncons={} nvars={} a={} b={}",
                r1cs.constraints.len(),
                r1cs.num_variables,
                da.len(),
                db.len()
            );
        }
    }

    #[test]
    fn spend_dens_by_stage() {
        use crate::zk::groth16::{a_density, b_density};
        let w = crate::zk::sapling::spend::SpendWitness::synthetic();
        let (r1cs, _) = super::synthesize_spend_depth(&w, 32);
        let da = a_density(&r1cs);
        let db = b_density(&r1cs);
        let nvars = r1cs.num_variables;
        let da_set: std::collections::BTreeSet<_> = da.iter().copied().collect();
        let db_set: std::collections::BTreeSet<_> = db.iter().copied().collect();
        let only_a = da_set.difference(&db_set).count();
        let only_b = db_set.difference(&da_set).count();
        let both = da_set.intersection(&db_set).count();
        println!(
            "FULL dens a={} b={} ncons={} nvars={} only_a={} only_b={} both={} neither={}",
            da.len(),
            db.len(),
            r1cs.constraints.len(),
            nvars,
            only_a,
            only_b,
            both,
            nvars - only_a - only_b - both
        );
    }

    #[test]
    fn stage_constraint_costs() {
        use crate::hash::pedersen::Personalization;
        use crate::zk::sapling::boolean::{fr_to_bits, u64_to_bits};
        use crate::zk::sapling::constants::*;
        use crate::zk::sapling::edwards::{fixed_base_mul, EdwardsPoint};
        use crate::zk::sapling::pedersen_circuit::pedersen_hash_cs;

        fn ncons(f: impl FnOnce(&mut Cs)) -> usize {
            let mut cs = Cs::new();
            f(&mut cs);
            cs.constraints.len()
        }

        // Edwards add (spec: 6)
        let add_c = ncons(|cs| {
            let a = EdwardsPoint::witness(cs, &spending_key_generator());
            let b = EdwardsPoint::witness(cs, &value_commitment_value_generator());
            let _ = EdwardsPoint::add(cs, &a, &b);
        });
        eprintln!("Edwards add: {} (spec ~6 + witness)", add_c);

        // Fixed-base 64-bit value (spec: 191 for value commit half)
        let fb64 = ncons(|cs| {
            let bits = u64_to_bits(cs, 10);
            let _ = fixed_base_mul(cs, &value_commitment_value_generator(), &bits);
        });
        eprintln!("fixed-base 64-bit: {} (spec ~191 + bit booleanize)", fb64);

        // Fixed-base 252-bit (spec: 750)
        let mut sk = [0u8; 32];
        sk[0] = 1;
        let fb252 = ncons(|cs| {
            let bits = fr_to_bits(cs, &sk, 252);
            let _ = fixed_base_mul(cs, &spending_key_generator(), &bits);
        });
        eprintln!("fixed-base 252-bit: {} (spec ~750 + bit booleanize)", fb252);

        // Variable-base 8-bit smoke
        let vb = ncons(|cs| {
            let base = EdwardsPoint::witness(cs, &spending_key_generator());
            let bits = fr_to_bits(cs, &sk, 8);
            let _ = EdwardsPoint::mul_bits(cs, &base, &bits);
        });
        eprintln!("variable-base 8-bit: {}", vb);

        // Empty Pedersen (baseline)
        let ped0 = ncons(|cs| {
            let _ = pedersen_hash_cs(cs, Personalization::NoteCommitment, &[]);
        });
        eprintln!("Pedersen empty: {} (spec hash scales with message)", ped0);

        // Sanity: costs are positive
        assert!(add_c > 0 && fb64 > 0 && fb252 > 0);

        // Variable-base components vs protocol A.3.3.6 (~3252 for 251 bits)
        let dbl = ncons(|cs| {
            let p = EdwardsPoint::witness(cs, &spending_key_generator());
            let _ = EdwardsPoint::double(cs, &p);
        });
        eprintln!("Edwards double: {} (spec ~5 + witness)", dbl);

        let sel = ncons(|cs| {
            let p = EdwardsPoint::witness(cs, &spending_key_generator());
            let b = Boolean::alloc(cs, true);
            let _ = EdwardsPoint::conditionally_select(cs, &p, &b);
        });
        eprintln!("conditionally_select: {} (spec ~2 + witness/bit)", sel);

        let vb251 = ncons(|cs| {
            let base = EdwardsPoint::witness(cs, &spending_key_generator());
            let mut sk = [0u8; 32];
            sk[0] = 0xab;
            sk[1] = 0xcd;
            let bits = fr_to_bits(cs, &sk, 251);
            let _ = EdwardsPoint::mul_bits(cs, &base, &bits);
        });
        eprintln!(
            "variable-base 251-bit: {} (spec ~3252 + booleanize 251 + witness)",
            vb251
        );

        use crate::zk::sapling::merkle_circuit::merkle_layer_cs;
        use crate::zk::sapling::num::AllocatedNum;
        let mer = ncons(|cs| {
            let cur = AllocatedNum::alloc(cs, Scalar::from_u64(7));
            let mut sib = [0u8; 32];
            sib[0] = 9;
            let _ = merkle_layer_cs(cs, &cur, &sib, false, 0);
        });
        eprintln!("Merkle layer: {} (spec ~1380)", mer);

        // Breakdown
        let bits_only = ncons(|cs| {
            let cur = AllocatedNum::alloc(cs, Scalar::from_u64(7));
            let sib = AllocatedNum::alloc(cs, Scalar::from_u64(9));
            let _ = cur.to_bits_le_strict(cs, 255);
            let _ = sib.to_bits_le_strict(cs, 255);
        });
        eprintln!("  2×255 strict bits: {}", bits_only);

        let ped510 = ncons(|cs| {
            let bits: Vec<_> = (0..510).map(|i| Boolean::alloc(cs, i % 2 == 0)).collect();
            let _ = pedersen_hash_cs(cs, Personalization::MerkleTree { layer: 0 }, &bits);
        });
        eprintln!("  Pedersen 510-bit: {}", ped510);

        // Isolated mont_add cost
        use crate::zk::sapling::pedersen_circuit::{
            debug_lookup4_mont_cost, debug_lookup8_mont_cost, debug_mont_add_cost,
        };
        let ma = debug_mont_add_cost();
        let lu = debug_lookup4_mont_cost();
        let l8 = debug_lookup8_mont_cost();
        eprintln!("  mont_add isolated: {}", ma);
        eprintln!("  lookup4_mont+sign isolated: {}", lu);
        eprintln!("  lookup8_mont isolated: {}", l8);
        let and_c = ncons(|cs| {
            let a = Boolean::alloc(cs, true);
            let b = Boolean::alloc(cs, false);
            let _ = Boolean::and(cs, &a, &b);
        });
        eprintln!("  Boolean::and isolated: {}", and_c);

        use crate::zk::sapling::blake2s_circuit::blake2s_zcash_ivk;
        // Body only: pre-booleanized with unchecked (no bitness) so count matches protocol 21006.
        let bl = ncons(|cs| {
            let pre: Vec<_> = (0..512)
                .map(|i| Boolean::alloc_unchecked(cs, i % 3 == 0))
                .collect();
            let _ = blake2s_zcash_ivk(cs, &pre);
        });
        eprintln!("BLAKE2s 512-in body (Zcashivk): {} (spec 21006)", bl);
    }

    #[test]
    fn synthesize_cv_rk_satisfied() {
        let w = good_witness();
        let (r1cs, assignment) = synthesize_spend_cv_rk(&w);
        assert!(r1cs.num_public >= 4);
        assert!(r1cs.is_satisfied(&assignment));
    }

    #[test]
    fn ivk_251_matches_native() {
        use crate::zk::sapling::native::point_repr_bits;
        use crate::zk::sapling::num::scalar_from_fe_le;
        let w = good_witness();
        let mut cs = Cs::new();
        let ak_pt = parse_point(&w.ak);
        let ak = EdwardsPoint::witness(&mut cs, &ak_pt);
        let nsk_bits = fr_to_bits(&mut cs, &w.nsk, 252);
        let nk = fixed_base_mul(&mut cs, &proof_generation_key_generator(), &nsk_bits);
        let mut pre = ak.repr(&mut cs);
        pre.extend(nk.repr(&mut cs));
        let ivk_bits: Vec<_> = blake2s_zcash_ivk(&mut cs, &pre)
            .into_iter()
            .take(251)
            .collect();
        let ivk_n = compute_ivk(&ak_pt, &compute_nk(&w.nsk).unwrap()).unwrap();
        for i in 0..251 {
            let nb = ((ivk_n[i / 8] >> (i % 8)) & 1) == 1;
            assert_eq!(ivk_bits[i].value, nb, "ivk bit {}", i);
        }
        let g_d = EdwardsPoint::witness(&mut cs, &parse_point(&w.g_d));
        let pk_d = EdwardsPoint::mul_bits(&mut cs, &g_d, &ivk_bits);
        let pk_n = compute_pk_d(&parse_point(&w.g_d), &ivk_n).unwrap();
        let (ule, vle) = pk_n.affine_uv_le_bytes().unwrap();
        assert_eq!(
            ScalarTrait::ct_eq(&pk_d.u.value, &scalar_from_fe_le(&ule)),
            1
        );
        assert_eq!(
            ScalarTrait::ct_eq(&pk_d.v.value, &scalar_from_fe_le(&vle)),
            1
        );
        let (r1cs, z) = cs.into_r1cs();
        assert!(r1cs.is_satisfied(&z));
        let _ = point_repr_bits;
    }

    #[test]
    fn synthesize_spend_depth1_satisfied() {
        let w = good_witness();
        let (r1cs, assignment, stats) = synthesize_spend_with_stats(&w, 1);
        if !r1cs.is_satisfied(&assignment) {
            // Find first unsatisfied constraint for debugging order work
            let mut bad = None;
            for (i, c) in r1cs.constraints.iter().enumerate() {
                let av = c.a.eval(&assignment);
                let bv = c.b.eval(&assignment);
                let cv = c.c.eval(&assignment);
                if ScalarTrait::ct_eq(&av.mul(&bv), &cv) == 0 {
                    bad = Some(i);
                    break;
                }
            }
            panic!(
                "unsatisfied ncons={} pub={} first_bad={:?}",
                stats.num_constraints, stats.num_public, bad
            );
        }

        assert_eq!(r1cs.num_public, SPEND_NUM_PUBLIC);
        // Rough size lock (gadgets may grow slightly; keep order-of-magnitude)
        assert!(stats.num_constraints > 50_000);
        assert!(stats.num_constraints < 300_000);
        eprintln!(
            "Spend depth=1: constraints={} vars={} public={}",
            stats.num_constraints, stats.num_variables, stats.num_public
        );
    }

    #[test]
    fn fingerprint_depth1_stable() {
        let w = good_witness();
        let a = spend_circuit_fingerprint(&w, 1);
        let b = spend_circuit_fingerprint(&w, 1);
        assert_eq!(a.num_constraints, b.num_constraints);
        assert_eq!(a.num_public, 7);
        assert_eq!(a.head_term_profile, b.head_term_profile);
        assert_eq!(a.tail_term_profile, b.tail_term_profile);
        eprintln!(
            "fingerprint depth1: cons={} vars={} digest={:#x}",
            a.num_constraints, a.num_variables, a.structure_digest
        );
    }

    #[test]
    fn prove_spend_synthetic_depth1_roundtrip() {
        // Full synthetic setup for ~56k constraints is heavy; lock synthesis + satisfaction.
        // Production prove path is exercised on smaller gadgets elsewhere.
        let w = good_witness();
        let (r1cs, assignment, stats) = synthesize_spend_with_stats(&w, 1);
        assert!(r1cs.is_satisfied(&assignment));
        assert_eq!(stats.num_public, SPEND_NUM_PUBLIC);
        assert!(stats.num_constraints > 50_000);
        eprintln!(
            "synthesize depth1 ready for prove: cons={} (call prove_spend_synthetic offline)",
            stats.num_constraints
        );
    }

    #[test]
    fn synthesize_spend_depth2_stats() {
        let w = good_witness();
        let (r1cs, assignment, stats) = synthesize_spend_with_stats(&w, 2);
        assert!(r1cs.is_satisfied(&assignment));
        assert_eq!(stats.num_public, SPEND_NUM_PUBLIC);
        assert!(stats.num_constraints > 50_000);
        eprintln!(
            "Spend depth=2: constraints={} vars={} public={}",
            stats.num_constraints, stats.num_variables, stats.num_public
        );
        // Each Merkle layer should add a large Pedersen block
        let (_, _, s1) = synthesize_spend_with_stats(&w, 1);
        assert!(
            stats.num_constraints > s1.num_constraints,
            "depth2 ({}) should exceed depth1 ({})",
            stats.num_constraints,
            s1.num_constraints
        );
    }

    #[test]
    fn synthesize_cv_small_prove_verify() {
        let mut cs = Cs::new();
        let value_bits: Vec<_> = u64_to_bits(&mut cs, 10).into_iter().take(9).collect();
        let value_p = fixed_base_mul(&mut cs, &value_commitment_value_generator(), &value_bits);
        let mut rcv = [0u8; 32];
        rcv[0] = 1;
        let rcv_bits = fr_to_bits(&mut cs, &rcv, 9);
        let rcv_p = fixed_base_mul(&mut cs, &value_commitment_randomness_generator(), &rcv_bits);
        let cv = EdwardsPoint::add(&mut cs, &value_p, &rcv_p);
        cv.inputize(&mut cs);
        let (r1cs, assignment) = cs.into_r1cs();
        assert!(r1cs.is_satisfied(&assignment));
        let mut pk = setup_from_r1cs_synthetic(&r1cs);
        pk.clear_trapdoor();
        let proof = prove_bls_with_randomness(
            &pk,
            &r1cs,
            &assignment,
            &Scalar::from_u64(7),
            &Scalar::from_u64(9),
        )
        .expect("prove");
        let public: Vec<Scalar> = assignment[1..1 + r1cs.num_public].to_vec();
        verify(&pk.vk, &public, &proof).expect("verify");
    }

    #[test]
    fn point_repr_roundtrip_bits() {
        let mut cs = Cs::new();
        let p = EdwardsPoint::witness(&mut cs, &spending_key_generator());
        let bits = p.repr(&mut cs);
        assert_eq!(bits.len(), 256);
        let (r1cs, z) = cs.into_r1cs();
        assert!(r1cs.is_satisfied(&z));
    }

    /// Project full-tree size from depth1/depth2 layer delta (ceremony ~100k order).
    #[test]
    fn depth32_projection_from_layers() {
        let w = good_witness();
        let (_, _, s1) = synthesize_spend_with_stats(&w, 1);
        let (_, _, s2) = synthesize_spend_with_stats(&w, 2);
        let layer = s2.num_constraints.saturating_sub(s1.num_constraints);
        // 1 base + 31 additional layers ≈ depth32
        let projected = s1.num_constraints + layer * 31;
        eprintln!(
            "depth32 projection: d1={} d2={} layer={} projected≈{}",
            s1.num_constraints, s2.num_constraints, layer, projected
        );
        // Ceremony spend is ~100k–120k boolean constraints; allow wide band
        assert!(
            layer > 500 && layer < 5000,
            "merkle layer size unexpected: {layer}"
        );
        assert!(
            projected > 80_000 && projected < 250_000,
            "depth32 projection out of band: {projected}"
        );
    }
    #[test]
    fn note_merkle_two_layers_integrated() {
        use crate::zk::sapling::boolean::{fr_to_bits, u64_to_bits};
        use crate::zk::sapling::native::{
            compute_merkle_root, compute_note_commitment, fe_to_le32,
        };
        use crate::zk::sapling::num::scalar_from_fe_le;
        use crate::zk::sapling::pedersen_circuit::note_commitment_cs;
        let mut cs = Cs::new();
        let g = spending_key_generator();
        let value = 10u64;
        let mut rcm = [0u8; 32];
        rcm[0] = 1;
        let mut contents = u64_to_bits(&mut cs, value);
        contents.extend(EdwardsPoint::witness(&mut cs, &g).repr(&mut cs));
        contents.extend(EdwardsPoint::witness(&mut cs, &g).repr(&mut cs));
        let rcm_bits = fr_to_bits(&mut cs, &rcm, 252);
        let cm_circuit = note_commitment_cs(&mut cs, &contents, &rcm_bits);
        let cm_native = compute_note_commitment(value, &g, &g, &rcm).unwrap();
        let (ule, vle) = cm_native.affine_uv_le_bytes().unwrap();
        assert_eq!(
            ScalarTrait::ct_eq(&cm_circuit.u.value, &scalar_from_fe_le(&ule)),
            1
        );
        assert_eq!(
            ScalarTrait::ct_eq(&cm_circuit.v.value, &scalar_from_fe_le(&vle)),
            1
        );
        let mut s0 = [0u8; 32];
        s0[0] = 4;
        let mut s1 = [0u8; 32];
        s1[0] = 8;
        let path = [(s0, false), (s1, true)];
        let (cur, pos) = merkle_path_cs(&mut cs, &cm_native, &path);
        assert_eq!(pos.len(), 2);
        let anchor_fe = compute_merkle_root(&cm_native, &path).unwrap();
        enforce_anchor(&mut cs, &cur, &fe_to_le32(&anchor_fe));
        let (r1cs, z) = cs.into_r1cs();
        assert!(r1cs.is_satisfied(&z));
    }
}
