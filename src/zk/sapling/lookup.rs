//! 3-bit window table lookup — matches `bellman::gadgets::lookup::lookup3_xy`
//! (**3 constraints**: 1 AND + 1 for u + 1 for v).

use crate::curve::bls::Scalar;
use crate::curve::traits::Scalar as ScalarTrait;
use crate::zk::sapling::boolean::Boolean;
use crate::zk::sapling::cs::{lc_var, Cs, Lc};
use crate::zk::sapling::num::AllocatedNum;
use crate::zk::sapling::windows::WindowPoint;

/// Möbius / subset synthesis for window constants (bellman `synth`).
fn synth(constants: &[Scalar; 8]) -> [Scalar; 8] {
    let mut assignment = [Scalar::zero(); 8];
    for i in 0..8 {
        let cur = assignment[i].neg().add(&constants[i]);
        assignment[i] = cur;
        for (j, slot) in assignment.iter_mut().enumerate().skip(i + 1) {
            if (j & i) == i {
                *slot = slot.add(&cur);
            }
        }
    }
    assignment
}

fn fe_to_scalar(u: &crate::curve::jubjub::Fe) -> Scalar {
    let mut be = [0u8; 32];
    u.to_bytes_be(&mut be);
    Scalar::from_bytes_be(&be).unwrap_or_else(|_| Scalar::zero())
}

fn add_bit_coeff(cs: &Cs, lc: &mut Lc, bit: &Boolean, coeff: &Scalar) {
    if ScalarTrait::ct_eq(coeff, &Scalar::zero()) == 0 {
        bit.add_to_lc(lc, cs.one(), *coeff);
    }
}

/// Lookup affine `(u,v)` from 3 LE bits and 8 window points.
///
/// Constraint cost: **3** (precomp AND + u-enforce + v-enforce), matching bellman.
pub fn lookup3_xy(
    cs: &mut Cs,
    bits: &[Boolean; 3],
    window: &[WindowPoint; 8],
) -> (AllocatedNum, AllocatedNum) {
    let mut idx = 0usize;
    if bits[0].value {
        idx += 1;
    }
    if bits[1].value {
        idx += 2;
    }
    if bits[2].value {
        idx += 4;
    }

    let mut xu = [Scalar::zero(); 8];
    let mut xv = [Scalar::zero(); 8];
    for i in 0..8 {
        xu[i] = fe_to_scalar(&window[i].u);
        xv[i] = fe_to_scalar(&window[i].v);
    }
    let x_c = synth(&xu);
    let y_c = synth(&xv);

    let res_u = AllocatedNum::alloc(cs, xu[idx]);
    let res_v = AllocatedNum::alloc(cs, xv[idx]);

    // Keep polarity — Constant(false)=Not(ONE) stays free (Bellman).
    let b0 = &bits[0];
    let b1 = &bits[1];
    let b2 = &bits[2];
    let precomp = Boolean::and(cs, b1, b2);

    // --- u ---
    let mut a_u = Lc::new();
    a_u.add(cs.one(), x_c[0b001]);
    add_bit_coeff(cs, &mut a_u, b1, &x_c[0b011]);
    add_bit_coeff(cs, &mut a_u, b2, &x_c[0b101]);
    add_bit_coeff(cs, &mut a_u, &precomp, &x_c[0b111]);

    let mut c_u = lc_var(res_u.var, Scalar::one());
    c_u.add(cs.one(), x_c[0b000].clone().neg());
    let mut sub = Lc::new();
    add_bit_coeff(cs, &mut sub, b1, &x_c[0b010]);
    add_bit_coeff(cs, &mut sub, b2, &x_c[0b100]);
    add_bit_coeff(cs, &mut sub, &precomp, &x_c[0b110]);
    for (v, c) in sub.terms {
        c_u.add(v, c.neg());
    }
    let mut b0_lc = Lc::new();
    b0.add_to_lc(&mut b0_lc, cs.one(), Scalar::one());
    cs.enforce_lc(a_u, b0_lc, c_u);

    // --- v ---
    let mut a_v = Lc::new();
    a_v.add(cs.one(), y_c[0b001]);
    add_bit_coeff(cs, &mut a_v, b1, &y_c[0b011]);
    add_bit_coeff(cs, &mut a_v, b2, &y_c[0b101]);
    add_bit_coeff(cs, &mut a_v, &precomp, &y_c[0b111]);

    let mut c_v = lc_var(res_v.var, Scalar::one());
    c_v.add(cs.one(), y_c[0b000].clone().neg());
    let mut sub = Lc::new();
    add_bit_coeff(cs, &mut sub, b1, &y_c[0b010]);
    add_bit_coeff(cs, &mut sub, b2, &y_c[0b100]);
    add_bit_coeff(cs, &mut sub, &precomp, &y_c[0b110]);
    for (v, c) in sub.terms {
        c_v.add(v, c.neg());
    }
    let mut b0_lc2 = Lc::new();
    b0.add_to_lc(&mut b0_lc2, cs.one(), Scalar::one());
    cs.enforce_lc(a_v, b0_lc2, c_v);

    (res_u, res_v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zk::sapling::boolean::Boolean;
    use crate::zk::sapling::constants::value_commitment_value_generator;
    use crate::zk::sapling::cs::Cs;
    use crate::zk::sapling::windows::generate_circuit_windows;

    #[test]
    fn lookup3_matches_table() {
        let _cs = Cs::new();
        let wins = generate_circuit_windows(&value_commitment_value_generator());
        for idx in 0..8u8 {
            let mut cs = Cs::new();
            let bits = [
                Boolean::alloc(&mut cs, idx & 1 != 0),
                Boolean::alloc(&mut cs, idx & 2 != 0),
                Boolean::alloc(&mut cs, idx & 4 != 0),
            ];
            let (u, v) = lookup3_xy(&mut cs, &bits, &wins[0]);
            let eu = fe_to_scalar(&wins[0][idx as usize].u);
            let ev = fe_to_scalar(&wins[0][idx as usize].v);
            assert_eq!(ScalarTrait::ct_eq(&u.value, &eu), 1, "u idx={}", idx);
            assert_eq!(ScalarTrait::ct_eq(&v.value, &ev), 1, "v idx={}", idx);
            let (r1cs, z) = cs.into_r1cs();
            assert!(r1cs.is_satisfied(&z), "idx={}", idx);
            // 3 bitness + 1 AND + 2 lookup = 6 (excluding other)
            assert!(r1cs.constraints.len() <= 8, "n={}", r1cs.constraints.len());
        }
    }

    #[test]
    fn lookup3_constraint_count() {
        let mut cs = Cs::new();
        let wins = generate_circuit_windows(&value_commitment_value_generator());
        // Use already-allocated bits without counting their bitness in a fresh window:
        // measure only lookup after bits exist.
        let bits = [
            Boolean::alloc(&mut cs, true),
            Boolean::alloc(&mut cs, false),
            Boolean::alloc(&mut cs, true),
        ];
        let before = cs.constraints.len();
        let _ = lookup3_xy(&mut cs, &bits, &wins[0]);
        let added = cs.constraints.len() - before;
        assert_eq!(added, 3, "lookup must be 3 constraints, got {}", added);
    }
}
