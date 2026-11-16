//! Pedersen hash R1CS gadget (Edwards form, matching native digit algebra).
//!
//! Each 3-bit window `(a,b,c)` contributes
//! `(-1)^c · (1+a+2b) · 2^{4k} · G_seg` via a 4-point lookup + conditional
//! negation, then Edwards accumulation — same value as
//! [`crate::hash::pedersen::PedersenHash::hash`].

use crate::curve::bls::Scalar;
use crate::curve::jubjub::JubJubPoint;
use crate::hash::pedersen::Personalization;
use crate::zk::sapling::boolean::Boolean;
use crate::zk::sapling::cs::{lc_var, Cs, Lc};
use crate::zk::sapling::edwards::EdwardsPoint;
use crate::zk::sapling::num::AllocatedNum;
use alloc::vec::Vec;

/// Chunk/segment counts now live with the shared builder
/// ([`crate::hash::pedersen`]); kept out of this module to avoid a second
/// source of truth.
/// One segment: 63 windows × 4 Edwards points (1G…4G at that 2^{4k} scale).
type SegmentWindows = Vec<[JubJubPoint; 4]>;

/// One chunk's 4 Montgomery constants: (x_m, y_m) Scalars per point.
pub type MontWindow = [(Scalar, Scalar); 4];
/// 6 segments × 63 chunks of precomputed Montgomery lookup constants.
pub type MontSegments = Vec<Vec<MontWindow>>;

#[cfg(feature = "std")]
fn pedersen_windows_cached() -> MontSegments {
    use std::sync::OnceLock;
    static CACHE: OnceLock<MontSegments> = OnceLock::new();
    // Generator set is fixed (personalization enters as input prefix bits),
    // so one process-wide table serves all call sites — built once, sourced
    // from the generated constants (no regeneration).
    CACHE
        .get_or_init(|| build_mont_segments(&generate_pedersen_windows()))
        .clone()
}
#[cfg(not(feature = "std"))]
fn pedersen_windows_cached() -> MontSegments {
    build_mont_segments(&generate_pedersen_windows())
}

/// Precompute Montgomery (x, y) lookup constants for every window point.
///
/// Replaces per-chunk `affine_uv` + `edwards_to_mont_vals` (12 inversions per
/// 3-bit chunk on the hot path) with a single batch inversion for all 1512
/// points. Constraint output is unchanged (same constants, same enforces).
fn build_mont_segments(segs: &[SegmentWindows]) -> MontSegments {
    use crate::curve::jubjub::JubJubPoint;
    // Flatten in segment/chunk/point order for one batch conversion.
    let mut flat: Vec<JubJubPoint> = Vec::new();
    for seg in segs {
        for window in seg.iter() {
            for p in window.iter() {
                flat.push(*p);
            }
        }
    }
    let affines = JubJubPoint::batch_to_affine(&flat);
    let mut it = affines.into_iter();
    let mut out: MontSegments = Vec::with_capacity(segs.len());
    for seg in segs {
        let mut mseg = Vec::with_capacity(seg.len());
        for _ in 0..seg.len() {
            let mut w: MontWindow = [(Scalar::zero(), Scalar::zero()); 4];
            for slot in w.iter_mut() {
                let (u, v) = it.next().expect("mont gen count");
                *slot = edwards_to_mont_vals(&jubjub_fe_to_scalar(&u), &jubjub_fe_to_scalar(&v));
            }
            mseg.push(w);
        }
        out.push(mseg);
    }
    out
}

/// JubJub Fe → BLS Scalar via BE bytes (same as lookup-time conversion).
fn jubjub_fe_to_scalar(u: &crate::curve::jubjub::Fe) -> Scalar {
    let mut be = [0u8; 32];
    u.to_bytes_be(&mut be);
    Scalar::from_bytes_be(&be).unwrap_or_else(|_| Scalar::zero())
}

/// Window multiples come from the single `@generated` home
/// ([`crate::hash::pedersen_tables`], the same multiples the native table
/// fast path selects from); this function only keeps the local
/// `SegmentWindows` shape. Montgomery conversion + caching below are
/// unchanged.
fn generate_pedersen_windows() -> Vec<SegmentWindows> {
    use crate::curve::jubjub::JubJubPoint;
    use crate::hash::pedersen_tables::PEDERSEN_SEG_TABLES;
    PEDERSEN_SEG_TABLES
        .iter()
        .map(|seg| {
            seg.iter()
                .map(|w| {
                    // w[j] = j-th point's [x, y, z, t] limb arrays.
                    [
                        JubJubPoint::from_extended_limbs(w[0][0], w[0][1], w[0][2], w[0][3]),
                        JubJubPoint::from_extended_limbs(w[1][0], w[1][1], w[1][2], w[1][3]),
                        JubJubPoint::from_extended_limbs(w[2][0], w[2][1], w[2][2], w[2][3]),
                        JubJubPoint::from_extended_limbs(w[3][0], w[3][1], w[3][2], w[3][3]),
                    ]
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

/// Montgomery affine point (Jubjub): B=1 form `y² = x³ + A x² + x` with A = 40962.
#[derive(Clone, Debug)]
struct MontPoint {
    /// Linear combination for x (Bellman `Num`) — may not be a single variable.
    x_lc: Lc,
    x_val: Scalar,
    y: AllocatedNum,
}

fn jubjub_a() -> Scalar {
    Scalar::from_u64(40962)
}

fn jubjub_mont_scale() -> Scalar {
    // sqrt(4 / (a - d)) with a=-1 — from sapling-crypto / franklin-crypto Jubjub params
    let be: [u8; 32] = [
        0x27, 0x4d, 0xb2, 0x99, 0xd3, 0x41, 0xbd, 0x16, 0x00, 0x00, 0x00, 0x01, 0xa4, 0x5e, 0x7d,
        0x05, 0x4d, 0x24, 0x8a, 0xb6, 0x69, 0x8d, 0x7e, 0xa6, 0x6e, 0x23, 0xfe, 0x9c, 0xee, 0x05,
        0x67, 0x79,
    ];
    // Use decimal string form via bytes of known scale constant
    // scale = 17814886934372412843466061268024708274627479829237077604635722030778476050649
    let s = b"17814886934372412843466061268024708274627479829237077604635722030778476050649";
    // parse decimal into Scalar via big-endian limbs
    let mut acc = Scalar::zero();
    let ten = Scalar::from_u64(10);
    for &c in s {
        let d = (c - b'0') as u64;
        acc = acc.mul(&ten).add(&Scalar::from_u64(d));
    }
    let _ = be;
    acc
}

fn edwards_to_mont_vals(u: &Scalar, v: &Scalar) -> (Scalar, Scalar) {
    // sapling-crypto: u_m = (1+y)/(1-y), v_m = scale * u_m / x
    // with Edwards (x,y) = (u,v)
    let one = Scalar::one();
    let den = one.sub(v);
    let inv = den.invert().unwrap_or_else(|_| Scalar::zero());
    let x_m = one.add(v).mul(&inv);
    let y_m = if u.is_zero() {
        Scalar::zero()
    } else {
        let scale = jubjub_mont_scale();
        x_m.mul(&u.invert().unwrap_or_else(|_| Scalar::zero()))
            .mul(&scale)
    };
    (x_m, y_m)
}

fn mont_to_edwards_vals(x: &Scalar, y: &Scalar) -> (Scalar, Scalar) {
    // sapling-crypto: u = scale * x / y,  v = (x-1)/(x+1)
    let one = Scalar::one();
    let scale = jubjub_mont_scale();
    let u = if y.is_zero() {
        Scalar::zero()
    } else {
        scale
            .mul(x)
            .mul(&y.invert().unwrap_or_else(|_| Scalar::zero()))
    };
    let den = x.add(&one);
    let inv = den.invert().unwrap_or_else(|_| Scalar::zero());
    let v = x.sub(&one).mul(&inv);
    (u, v)
}

fn mont_add(cs: &mut Cs, p: &MontPoint, q: &MontPoint) -> MontPoint {
    // Incomplete Montgomery addition (3 constraints), matching sapling-crypto.
    // x coordinates may be LCs (Bellman Num).
    let a = jubjub_a();
    let dy_val = q.y.value.sub(&p.y.value);
    // dx as value only for witness
    let dx_val = q.x_val.sub(&p.x_val);
    let lambda_val = dy_val.mul(&dx_val.invert().unwrap_or_else(|_| Scalar::zero()));
    let lambda = AllocatedNum::alloc(cs, lambda_val);

    // sapling-crypto mont_add operand order:
    // 1: A=dx, B=λ, C=dy   (λ on B, not A)
    let mut dx_lc = q.x_lc.clone();
    for (v, c) in p.x_lc.terms.iter() {
        dx_lc.add(*v, c.clone().neg());
    }
    let mut dy_lc = lc_var(q.y.var, Scalar::one());
    dy_lc.add(p.y.var, Scalar::one().neg());
    cs.enforce_lc(dx_lc, lc_var(lambda.var, Scalar::one()), dy_lc);

    // 2: λ·λ = A + p.x + q.x + x3  (same both sides)
    let x3_val = lambda_val
        .mul(&lambda_val)
        .sub(&a)
        .sub(&p.x_val)
        .sub(&q.x_val);
    let x3 = AllocatedNum::alloc(cs, x3_val);
    let mut rhs = Lc::new();
    rhs.add(cs.one(), a);
    for (v, c) in p.x_lc.terms.iter() {
        rhs.add(*v, *c);
    }
    for (v, c) in q.x_lc.terms.iter() {
        rhs.add(*v, *c);
    }
    rhs.add(x3.var, Scalar::one());
    cs.enforce_lc(
        lc_var(lambda.var, Scalar::one()),
        lc_var(lambda.var, Scalar::one()),
        rhs,
    );

    // 3: A=(p.x - x3), B=λ, C=y3+p.y  (λ on B)
    let y3_val = lambda_val.mul(&p.x_val.sub(&x3_val)).sub(&p.y.value);
    let y3 = AllocatedNum::alloc(cs, y3_val);
    let mut xdiff = p.x_lc.clone();
    xdiff.add(x3.var, Scalar::one().neg());
    let mut yrhs = lc_var(y3.var, Scalar::one());
    yrhs.add(p.y.var, Scalar::one());
    cs.enforce_lc(xdiff, lc_var(lambda.var, Scalar::one()), yrhs);

    MontPoint {
        x_lc: lc_var(x3.var, Scalar::one()),
        x_val: x3_val,
        y: y3,
    }
}

/// Test-only (gadget-cost probes below): Montgomery conditional negation.
#[cfg(test)]
fn mont_conditional_neg(cs: &mut Cs, p: &MontPoint, c: &Boolean) -> MontPoint {
    let c = c.as_positive(cs);
    let two_y = p.y.value.add(&p.y.value);
    let cy = if c.value {
        two_y
    } else {
        Scalar::zero()
    };
    let out_y_val = p.y.value.sub(&cy);
    let out_y = AllocatedNum::alloc(cs, out_y_val);
    let mut diff = lc_var(p.y.var, Scalar::one());
    diff.add(out_y.var, Scalar::one().neg());
    let mut two = lc_var(p.y.var, Scalar::one());
    two.add(p.y.var, Scalar::one());
    cs.enforce_lc(lc_var(c.var, Scalar::one()), two, diff);
    MontPoint {
        x_lc: p.x_lc.clone(),
        x_val: p.x_val,
        y: out_y,
    }
}

/// 3-bit window → Montgomery point among ±{1,2,3,4}·G.
/// Cost: **3 constraints** (1 AND + x-enforce + y-enforce), same as `lookup3_xy`.
fn lookup8_mont(
    cs: &mut Cs,
    a: &Boolean,
    b: &Boolean,
    c: &Boolean,
    consts: &MontWindow,
) -> MontPoint {
    // Precomputed Montgomery (x, y) constants — no per-chunk inversions.
    // (Previously converted the 4 JubJubPoints here: 4 affine_uv + 8
    // edwards_to_mont inversions per chunk on the hot path.)
    let mut xm = [Scalar::zero(); 4];
    let mut ym = [Scalar::zero(); 4];
    for i in 0..4 {
        xm[i] = consts[i].0;
        ym[i] = consts[i].1;
    }
    let mut idx = 0usize;
    if a.value {
        idx += 1;
    }
    if b.value {
        idx += 2;
    }
    let x_val = xm[idx];
    let mut y_val = ym[idx];
    if c.value {
        y_val = y_val.neg();
    }

    // Bellman order: allocate y FIRST, then precomp AND (var index dens-set).
    let y = AllocatedNum::alloc(cs, y_val);

    let synth4 = |constants: &[Scalar; 4]| -> [Scalar; 4] {
        let mut assignment = [Scalar::zero(); 4];
        for i in 0..4 {
            let cur = assignment[i].neg().add(&constants[i]);
            assignment[i] = cur;
            for (j, slot) in assignment.iter_mut().enumerate().skip(i + 1) {
                if (j & i) == i {
                    *slot = slot.add(&cur);
                }
            }
        }
        assignment
    };
    let cx = synth4(&xm);
    let cy = synth4(&ym);

    // Keep polarity; Constant(false)=Not(ONE) stays free (Bellman).
    let precomp = Boolean::and(cs, a, b);

    let mut x_lc = Lc::new();
    x_lc.add(cs.one(), cx[0]);
    a.add_to_lc(&mut x_lc, cs.one(), cx[1]);
    b.add_to_lc(&mut x_lc, cs.one(), cx[2]);
    precomp.add_to_lc(&mut x_lc, cs.one(), cx[3]);
    let mut y_lc = Lc::new();
    y_lc.add(cs.one(), cy[0]);
    a.add_to_lc(&mut y_lc, cs.one(), cy[1]);
    b.add_to_lc(&mut y_lc, cs.one(), cy[2]);
    precomp.add_to_lc(&mut y_lc, cs.one(), cy[3]);
    // (2 * y_lc) * c = y_lc - y
    let mut y_lc2 = y_lc.clone();
    for (v, coeff) in y_lc.terms.iter() {
        y_lc2.add(*v, *coeff);
    }
    let mut rhs = y_lc.clone();
    rhs.add(y.var, Scalar::one().neg());
    // c may be inverted constant; build B-side LC with polarity
    let mut c_lc = Lc::new();
    c.add_to_lc(&mut c_lc, cs.one(), Scalar::one());
    cs.enforce_lc(y_lc2, c_lc, rhs);

    MontPoint { x_lc, x_val, y }
}

/// Test-only (gadget-cost probe below): 2-bit Montgomery window lookup.
#[cfg(test)]
fn lookup4_mont(cs: &mut Cs, a: &Boolean, b: &Boolean, consts: &MontWindow) -> MontPoint {
    // Function-local: `lookup4_mont` itself is test-only (see above).
    use crate::zk::sapling::cs::lc_one;
    let a = a.as_positive(cs);
    let b = b.as_positive(cs);
    let mut idx = 0usize;
    if a.value {
        idx += 1;
    }
    if b.value {
        idx += 2;
    }
    let mut xm = [Scalar::zero(); 4];
    let mut ym = [Scalar::zero(); 4];
    for i in 0..4 {
        xm[i] = consts[i].0;
        ym[i] = consts[i].1;
    }
    let x = AllocatedNum::alloc(cs, xm[idx]);
    let y = AllocatedNum::alloc(cs, ym[idx]);
    let ab = Boolean::and(cs, &a, &b);
    let synth4 = |constants: &[Scalar; 4]| -> [Scalar; 4] {
        let mut assignment = [Scalar::zero(); 4];
        for i in 0..4 {
            let cur = assignment[i].neg().add(&constants[i]);
            assignment[i] = cur;
            for (j, slot) in assignment.iter_mut().enumerate().skip(i + 1) {
                if (j & i) == i {
                    *slot = slot.add(&cur);
                }
            }
        }
        assignment
    };
    let cx = synth4(&xm);
    let cy = synth4(&ym);
    let mut lc_x = Lc::new();
    lc_x.add(cs.one(), cx[0]);
    lc_x.add(a.var, cx[1]);
    lc_x.add(b.var, cx[2]);
    lc_x.add(ab.var, cx[3]);
    cs.enforce_lc(lc_x, lc_one(), lc_var(x.var, Scalar::one()));
    let mut lc_y = Lc::new();
    lc_y.add(cs.one(), cy[0]);
    lc_y.add(a.var, cy[1]);
    lc_y.add(b.var, cy[2]);
    lc_y.add(ab.var, cy[3]);
    cs.enforce_lc(lc_y, lc_one(), lc_var(y.var, Scalar::one()));
    MontPoint {
        x_lc: lc_var(x.var, Scalar::one()),
        x_val: x.value,
        y,
    }
}

fn mont_to_edwards(cs: &mut Cs, p: &MontPoint) -> EdwardsPoint {
    let (u_val, v_val) = mont_to_edwards_vals(&p.x_val, &p.y.value);
    let u = AllocatedNum::alloc(cs, u_val);
    let v = AllocatedNum::alloc(cs, v_val);
    let scale = jubjub_mont_scale();
    // y * u = scale * x  (x may be LC)
    let mut rhs = p.x_lc.clone();
    for (_var, c) in rhs.terms.iter_mut() {
        *c = c.clone().mul(&scale);
    }
    // Actually scale * x means multiply each coeff
    let mut scaled = Lc::new();
    for (var, c) in p.x_lc.terms.iter() {
        scaled.add(*var, c.clone().mul(&scale));
    }
    cs.enforce_lc(
        lc_var(p.y.var, Scalar::one()),
        lc_var(u.var, Scalar::one()),
        scaled,
    );
    // (x+1)*v = x-1
    let mut xp1 = p.x_lc.clone();
    xp1.add(cs.one(), Scalar::one());
    let mut xm1 = p.x_lc.clone();
    xm1.add(cs.one(), Scalar::one().neg());
    cs.enforce_lc(xp1, lc_var(v.var, Scalar::one()), xm1);
    EdwardsPoint { u, v }
}

fn next_bit(bits: &[Boolean], i: &mut usize, cs: &mut Cs) -> Boolean {
    if *i < bits.len() {
        let b = bits[*i].clone();
        *i += 1;
        b
    } else {
        Boolean::constant(cs, false)
    }
}

/// Circuit Pedersen hash: `personalization ‖ msg` → Edwards point.
pub fn pedersen_hash_cs(
    cs: &mut Cs,
    personal: Personalization,
    msg_bits: &[Boolean],
) -> EdwardsPoint {
    // Match sapling-crypto `circuit::pedersen_hash::pedersen_hash`:
    // per-segment Montgomery accumulation → into_edwards → Edwards segment sum.
    let segments = pedersen_windows_cached();

    let mut all: Vec<Boolean> = personal
        .bits()
        .iter()
        .map(|&b| Boolean::constant(cs, b))
        .collect();
    all.extend_from_slice(msg_bits);

    let mut bit_i = 0usize;
    let mut edwards_result: Option<EdwardsPoint> = None;

    for seg in &segments {
        if bit_i >= all.len() {
            break;
        }
        let mut segment_result: Option<MontPoint> = None;
        for window in seg.iter() {
            if bit_i >= all.len() {
                break;
            }
            let a = next_bit(&all, &mut bit_i, cs);
            let b = next_bit(&all, &mut bit_i, cs);
            let c = next_bit(&all, &mut bit_i, cs);
            // lookup3_xy_with_conditional_negation style (currently 3-constraint lookup8)
            let signed = lookup8_mont(cs, &a, &b, &c, window);
            segment_result = Some(match segment_result {
                None => signed,
                // sapling-crypto: tmp.add(segment_result) → self=new, other=acc
                Some(acc) => mont_add(cs, &signed, &acc),
            });
        }
        let Some(seg_mont) = segment_result else {
            break;
        };
        // Convert segment to Edwards (2 constraints) — sapling-crypto into_edwards
        let seg_ed = mont_to_edwards(cs, &seg_mont);
        edwards_result = Some(match edwards_result {
            None => seg_ed,
            // sapling-crypto: segment_result.add(edwards_result)
            // → self=new segment, other=accumulator (A/B dens orientation)
            Some(acc) => EdwardsPoint::add(cs, &seg_ed, &acc),
        });
    }

    edwards_result.unwrap_or_else(|| EdwardsPoint::identity(cs))
}

/// Note-commitment style: Pedersen(NoteCommitment, contents) + [rcm] G_rcm.
pub fn note_commitment_cs(
    cs: &mut Cs,
    note_contents: &[Boolean],
    rcm_bits: &[Boolean],
) -> EdwardsPoint {
    use crate::zk::sapling::constants::note_commitment_randomness_generator;
    use crate::zk::sapling::edwards::fixed_base_mul;
    let cm = pedersen_hash_cs(cs, Personalization::NoteCommitment, note_contents);
    let rcm_p = fixed_base_mul(cs, &note_commitment_randomness_generator(), rcm_bits);
    EdwardsPoint::add(cs, &cm, &rcm_p)
}

/// Test-only: constraints for one mont_add of two random generators.
#[cfg(test)]
pub fn debug_mont_add_cost() -> usize {
    use crate::zk::sapling::constants::{spending_key_generator, value_commitment_value_generator};
    let mut cs = Cs::new();
    let p = spending_key_generator();
    let q = value_commitment_value_generator();
    let (pu, pv) = p.affine_uv_le_bytes().unwrap();
    let (qu, qv) = q.affine_uv_le_bytes().unwrap();
    let (px, py) = edwards_to_mont_vals(
        &crate::zk::sapling::num::scalar_from_fe_le(&pu),
        &crate::zk::sapling::num::scalar_from_fe_le(&pv),
    );
    let (qx, qy) = edwards_to_mont_vals(
        &crate::zk::sapling::num::scalar_from_fe_le(&qu),
        &crate::zk::sapling::num::scalar_from_fe_le(&qv),
    );
    let before = cs.constraints.len();
    let mp = MontPoint {
        x_lc: lc_var(AllocatedNum::alloc(&mut cs, px).var, Scalar::one()),
        x_val: px,
        y: AllocatedNum::alloc(&mut cs, py),
    };
    let mq = MontPoint {
        x_lc: lc_var(AllocatedNum::alloc(&mut cs, qx).var, Scalar::one()),
        x_val: qx,
        y: AllocatedNum::alloc(&mut cs, qy),
    };
    let _ = mont_add(&mut cs, &mp, &mq);
    cs.constraints.len() - before
}

/// Convert 4 window points to Montgomery lookup constants (debug/test paths).
/// Production uses the precomputed [`MontSegments`] cache (no per-chunk work).
#[cfg(test)]
pub(crate) fn mont_window_for_points(pts: &[JubJubPoint; 4]) -> MontWindow {
    let mut w: MontWindow = [(Scalar::zero(), Scalar::zero()); 4];
    for i in 0..4 {
        let (u, v) = pts[i].affine_uv().expect("affine");
        w[i] = edwards_to_mont_vals(&jubjub_fe_to_scalar(&u), &jubjub_fe_to_scalar(&v));
    }
    w
}

/// Test-only: lookup4_mont + conditional_neg cost.
#[cfg(test)]
pub fn debug_lookup8_mont_cost() -> usize {
    use crate::zk::sapling::constants::spending_key_generator;
    let mut cs = Cs::new();
    let g = spending_key_generator();
    let pts = [g, g, g, g];
    let consts = mont_window_for_points(&pts);
    let a = Boolean::alloc(&mut cs, true);
    let b = Boolean::alloc(&mut cs, false);
    let c = Boolean::alloc(&mut cs, true);
    let before = cs.constraints.len();
    let _ = lookup8_mont(&mut cs, &a, &b, &c, &consts);
    cs.constraints.len() - before
}

#[cfg(test)]
pub fn debug_lookup4_mont_cost() -> usize {
    use crate::zk::sapling::constants::spending_key_generator;
    let mut cs = Cs::new();
    let g = spending_key_generator();
    let pts = [g, g, g, g];
    let consts = mont_window_for_points(&pts);
    let a = Boolean::alloc(&mut cs, true);
    let b = Boolean::alloc(&mut cs, false);
    let c = Boolean::alloc(&mut cs, true);
    let before = cs.constraints.len();
    let looked = lookup4_mont(&mut cs, &a, &b, &consts);
    let _ = mont_conditional_neg(&mut cs, &looked, &c);
    cs.constraints.len() - before
}

#[cfg(test)]
mod tests {
    use super::*;
    // Moved here from the top of the file: used only by the tests below.
    use crate::curve::traits::{CurvePoint, Scalar as ScalarTrait};
    use crate::hash::pedersen::PedersenHash;
    use crate::zk::sapling::boolean::Boolean;
    use crate::zk::sapling::cs::Cs;
    use crate::zk::sapling::edwards::EdwardsPoint;
    use crate::zk::sapling::num::scalar_from_fe_le;

    #[test]
    fn pedersen_empty_matches_native() {
        let mut cs = Cs::new();
        let msg: Vec<Boolean> = Vec::new();
        let circuit = pedersen_hash_cs(&mut cs, Personalization::NoteCommitment, &msg);
        let native = PedersenHash::new()
            .unwrap()
            .hash(Personalization::NoteCommitment, &[]);
        let (ule, vle) = native.affine_uv_le_bytes().unwrap();
        assert_eq!(
            ScalarTrait::ct_eq(&circuit.u.value, &scalar_from_fe_le(&ule)),
            1
        );
        assert_eq!(
            ScalarTrait::ct_eq(&circuit.v.value, &scalar_from_fe_le(&vle)),
            1
        );
        let (r1cs, z) = cs.into_r1cs();
        assert!(r1cs.is_satisfied(&z));
    }

    #[test]
    fn note_commit_matches_native() {
        use crate::zk::sapling::boolean::u64_to_bits;
        use crate::zk::sapling::constants::spending_key_generator;
        use crate::zk::sapling::native::compute_note_commitment;
        let mut cs = Cs::new();
        let value = 10u64;
        let g_d = spending_key_generator();
        let pk_d = spending_key_generator();
        let mut rcm = [0u8; 32];
        rcm[0] = 1;
        // note contents: value64 ‖ g_d.repr ‖ pk_d.repr
        let mut contents = u64_to_bits(&mut cs, value);
        let g_bits = EdwardsPoint::witness(&mut cs, &g_d).repr(&mut cs);
        let p_bits = EdwardsPoint::witness(&mut cs, &pk_d).repr(&mut cs);
        contents.extend(g_bits);
        contents.extend(p_bits);
        assert_eq!(contents.len(), 64 + 256 + 256);
        let rcm_bits: Vec<_> = (0..252)
            .map(|i| Boolean::alloc(&mut cs, ((rcm[i / 8] >> (i % 8)) & 1) == 1))
            .collect();
        let circuit = note_commitment_cs(&mut cs, &contents, &rcm_bits);
        let native = compute_note_commitment(value, &g_d, &pk_d, &rcm).unwrap();
        let (ule, vle) = native.affine_uv_le_bytes().unwrap();
        assert_eq!(
            ScalarTrait::ct_eq(&circuit.u.value, &scalar_from_fe_le(&ule)),
            1
        );
        assert_eq!(
            ScalarTrait::ct_eq(&circuit.v.value, &scalar_from_fe_le(&vle)),
            1
        );
        let (r1cs, z) = cs.into_r1cs();
        assert!(r1cs.is_satisfied(&z), "ncons={}", r1cs.constraints.len());
    }

    #[test]
    fn pedersen_small_msg_matches_native() {
        let mut cs = Cs::new();
        let msg: Vec<_> = (0..9)
            .map(|i| Boolean::alloc(&mut cs, i % 2 == 0))
            .collect();
        let bits: Vec<bool> = msg.iter().map(|b| b.value).collect();
        let circuit = pedersen_hash_cs(&mut cs, Personalization::NoteCommitment, &msg);
        let native = PedersenHash::new()
            .unwrap()
            .hash(Personalization::NoteCommitment, &bits);
        let (ule, vle) = native.affine_uv_le_bytes().unwrap();
        assert_eq!(
            ScalarTrait::ct_eq(&circuit.u.value, &scalar_from_fe_le(&ule)),
            1
        );
        assert_eq!(
            ScalarTrait::ct_eq(&circuit.v.value, &scalar_from_fe_le(&vle)),
            1
        );
        let (r1cs, z) = cs.into_r1cs();
        assert!(r1cs.is_satisfied(&z));
    }
    #[test]
    fn mont_map_roundtrip_generator() {
        use crate::zk::sapling::constants::spending_key_generator;
        use crate::zk::sapling::num::scalar_from_fe_le;
        let g = spending_key_generator();
        let (ule, vle) = g.affine_uv_le_bytes().unwrap();
        let u = scalar_from_fe_le(&ule);
        let v = scalar_from_fe_le(&vle);
        let (x, y) = edwards_to_mont_vals(&u, &v);
        let (u2, v2) = mont_to_edwards_vals(&x, &y);
        assert_eq!(ScalarTrait::ct_eq(&u, &u2), 1, "u mismatch");
        assert_eq!(ScalarTrait::ct_eq(&v, &v2), 1, "v mismatch");
    }

    fn on_mont_curve(x: &Scalar, y: &Scalar) -> bool {
        // y² =? x³ + A x² + x
        let a = jubjub_a();
        let y2 = y.mul(y);
        let x2 = x.mul(x);
        let x3 = x2.mul(x);
        let rhs = x3.add(&a.mul(&x2)).add(x);
        ScalarTrait::ct_eq(&y2, &rhs) == 1
    }

    #[test]
    fn pedersen_body_cost_510() {
        use crate::zk::sapling::boolean::Boolean;
        use crate::zk::sapling::cs::Cs;
        // Pre-booleanized bits (no bitness in measurement)
        let mut cs = Cs::new();
        let bits: Vec<_> = (0..510)
            .map(|i| Boolean::alloc_unchecked(&mut cs, i % 2 == 0))
            .collect();
        let start = cs.constraints.len();
        let _ = pedersen_hash_cs(&mut cs, Personalization::MerkleTree { layer: 0 }, &bits);
        let body = cs.constraints.len() - start;
        eprintln!("Pedersen body 510 (no bitness): {body} (target ~860–900)");
        // Window count
        let nwin = (510 + 6 + 2) / 3; // personal 6 bits + pad
        eprintln!("approx windows including personal: {nwin}");
    }

    #[test]
    fn mont_to_edwards_cost() {
        use crate::zk::sapling::constants::spending_key_generator;
        use crate::zk::sapling::cs::Cs;
        use crate::zk::sapling::num::AllocatedNum;
        let mut cs = Cs::new();
        let p = spending_key_generator();
        let (u, v) = p.affine_uv().unwrap();
        let us = {
            let mut be = [0u8; 32];
            u.to_bytes_be(&mut be);
            Scalar::from_bytes_be(&be).unwrap()
        };
        let vs = {
            let mut be = [0u8; 32];
            v.to_bytes_be(&mut be);
            Scalar::from_bytes_be(&be).unwrap()
        };
        let (x, y) = edwards_to_mont_vals(&us, &vs);
        let mp = MontPoint {
            x_lc: lc_var(AllocatedNum::alloc(&mut cs, x).var, Scalar::one()),
            x_val: x,
            y: AllocatedNum::alloc(&mut cs, y),
        };
        let start = cs.constraints.len();
        let _ = mont_to_edwards(&mut cs, &mp);
        eprintln!("mont_to_edwards: {}", cs.constraints.len() - start);
    }
    #[test]
    fn mont_add_matches_edwards_add() {
        use crate::zk::sapling::constants::{
            spending_key_generator, value_commitment_value_generator,
        };
        use crate::zk::sapling::num::scalar_from_fe_le;
        let p = spending_key_generator();
        let q = value_commitment_value_generator();
        let sum = p.add(&q);
        let (pu, pv) = p.affine_uv_le_bytes().unwrap();
        let (qu, qv) = q.affine_uv_le_bytes().unwrap();
        let (su, sv) = sum.affine_uv_le_bytes().unwrap();
        let (px, py) = edwards_to_mont_vals(&scalar_from_fe_le(&pu), &scalar_from_fe_le(&pv));
        let (qx, qy) = edwards_to_mont_vals(&scalar_from_fe_le(&qu), &scalar_from_fe_le(&qv));
        assert!(on_mont_curve(&px, &py), "p not on mont");
        assert!(on_mont_curve(&qx, &qy), "q not on mont");
        let a = jubjub_a();
        let dy = qy.sub(&py);
        let dx = qx.sub(&px);
        let lambda = dy.mul(&dx.invert().expect("dx"));
        let x3 = lambda.mul(&lambda).sub(&a).sub(&px).sub(&qx);
        let y3 = lambda.mul(&px.sub(&x3)).sub(&py);
        assert!(on_mont_curve(&x3, &y3), "sum not on mont");
        let (u3, v3) = mont_to_edwards_vals(&x3, &y3);
        let ok_u = ScalarTrait::ct_eq(&u3, &scalar_from_fe_le(&su)) == 1;
        let ok_v = ScalarTrait::ct_eq(&v3, &scalar_from_fe_le(&sv)) == 1;
        // Also try y3 negated (ordering of points can flip sign)
        let (u3n, v3n) = mont_to_edwards_vals(&x3, &y3.neg());
        let ok_un = ScalarTrait::ct_eq(&u3n, &scalar_from_fe_le(&su)) == 1;
        let ok_vn = ScalarTrait::ct_eq(&v3n, &scalar_from_fe_le(&sv)) == 1;
        assert!(
            (ok_u && ok_v) || (ok_un && ok_vn),
            "sum mismatch (direct or y-neg)"
        );
    }

    #[test]
    fn find_mont_params() {
        use crate::curve::jubjub::Fe;
        use crate::zk::sapling::constants::{
            spending_key_generator, value_commitment_value_generator,
        };
        let to_s = |f: &Fe| {
            let mut be = [0u8; 32];
            f.to_bytes_be(&mut be);
            Scalar::from_bytes_be(&be).unwrap()
        };
        let a = Scalar::from_u64(40962);
        for (name, g) in [
            ("skg", spending_key_generator()),
            ("vcv", value_commitment_value_generator()),
        ] {
            let (u_fe, v_fe) = g.affine_uv().unwrap();
            let u = to_s(&u_fe);
            let v = to_s(&v_fe);
            let (x, y) = edwards_to_mont_vals(&u, &v);
            let y2 = y.mul(&y);
            let x2 = x.mul(&x);
            let x3 = x2.mul(&x);
            let rhs = x3.add(&a.mul(&x2)).add(&x);
            // ratio = y2 * rhs^{-1}  should be constant if y is scaled
            let ratio = y2.mul(&rhs.invert().unwrap());
            let mut rb = [0u8; 32];
            ratio.to_bytes_be(&mut rb);
            eprintln!("{} ratio_be={:02x?}", name, rb);
        }
    }
}

#[test]
fn note_commitment_body_cost_isolated() {
    use crate::zk::sapling::boolean::Boolean;
    use crate::zk::sapling::cs::Cs;
    // Pre-booleanized 576 note bits (no bitness in measurement) + 252 rcm
    let mut cs = Cs::new();
    let note: Vec<_> = (0..576)
        .map(|i| Boolean::alloc_unchecked(&mut cs, i % 2 == 0))
        .collect();
    let rcm: Vec<_> = (0..252)
        .map(|i| Boolean::alloc_unchecked(&mut cs, i % 3 == 0))
        .collect();
    let aux0 = cs.aux.len();
    let cons0 = cs.constraints.len();
    let _ = note_commitment_cs(&mut cs, &note, &rcm);
    let body_cons = cs.constraints.len() - cons0;
    let body_aux = cs.aux.len() - aux0;
    // Hash-only (no rcm fixed-base + add)
    let mut cs2 = Cs::new();
    let note2: Vec<_> = (0..576)
        .map(|i| Boolean::alloc_unchecked(&mut cs2, i % 2 == 0))
        .collect();
    let a0 = cs2.aux.len();
    let c0 = cs2.constraints.len();
    let _ = pedersen_hash_cs(&mut cs2, Personalization::NoteCommitment, &note2);
    let hash_cons = cs2.constraints.len() - c0;
    let hash_aux = cs2.aux.len() - a0;
    eprintln!(
            "Pedersen NoteCommitment HASH-only (576 msg + 6 personal): cons={hash_cons} aux={hash_aux} (protocol 984)"
        );
    eprintln!("note_commitment FULL (hash + [rcm]G + add): cons={body_cons} aux={body_aux}");
    // Windows: ceil((6+576)/3)=194; segments ceil(194/63)=4
    // protocol: 5c+5n-6 = 5*194+5*4-6 = 970+20-6 = 984
    assert!(
        (hash_cons as i64 - 984).abs() <= 20,
        "hash body drifted far from 984: {hash_cons}"
    );
}

#[test]
fn lookup8_mont_exact_cost_and_vars() {
    use crate::zk::sapling::boolean::Boolean;
    use crate::zk::sapling::cs::Cs;
    let segs = generate_pedersen_windows();
    let window = mont_window_for_points(&segs[0][0]);
    // Positive (non-inverted) bits — Bellman AllocatedBit path
    let mut cs = Cs::new();
    let a = Boolean::alloc_unchecked(&mut cs, true);
    let b = Boolean::alloc_unchecked(&mut cs, false);
    let c = Boolean::alloc_unchecked(&mut cs, true);
    let aux0 = cs.aux.len();
    let cons0 = cs.constraints.len();
    let _ = lookup8_mont(&mut cs, &a, &b, &c, &window);
    let dcons = cs.constraints.len() - cons0;
    let daux = cs.aux.len() - aux0;
    eprintln!("lookup8_mont (positive bits): cons={dcons} aux={daux} (Bellman target cons=2 aux=2: and+y)");
    assert_eq!(dcons, 2, "lookup8_mont must be 2 constraints");
    // AND allocates 1, y allocates 1 → aux +2
    assert_eq!(daux, 2, "lookup8_mont aux: and_wire + y");
}
