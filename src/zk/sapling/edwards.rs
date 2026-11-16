//! Edwards point gadgets + fixed-base mul (circuit).
//!
//! Addition matches the reference implementation.add` / sapling-crypto affine formulas
//! for twisted Edwards with \(a = -1\):
//!
//! ```text
//! U = (u1+v1)(u2+v2)
//! A = u1·v2,  B = u2·v1,  C = d·A·B
//! u3 = (A+B)/(1+C),  v3 = (U-A-B)/(1-C)
//! ```

use crate::curve::bls::Scalar;
use crate::curve::jubjub::JubJubPoint;
use crate::zk::sapling::boolean::Boolean;
use crate::zk::sapling::cs::{lc_one, lc_var, Cs, Lc};
use crate::zk::sapling::lookup::lookup3_xy;
use crate::zk::sapling::num::{scalar_from_fe_le, AllocatedNum};
use crate::zk::sapling::windows::windows_for_base;
use alloc::vec::Vec;

/// Jubjub Edwards `d` as circuit Fr (same modulus as Jubjub base field).
pub(crate) fn edwards_d_scalar() -> Scalar {
    // Canonical Jubjub Edwards `d` (same as curve::jubjub D_LIMBS).
    let be: [u8; 32] = [
        0x2a, 0x93, 0x18, 0xe7, 0x4b, 0xfa, 0x2b, 0x48, 0xf5, 0xfd, 0x92, 0x07, 0xe6, 0xbd, 0x7f,
        0xd4, 0x29, 0x2d, 0x7f, 0x6d, 0x37, 0x57, 0x9d, 0x26, 0x01, 0x06, 0x5f, 0xd6, 0xd6, 0x34,
        0x3e, 0xb1,
    ];
    Scalar::from_bytes_be(&be).expect("edwards d")
}

#[derive(Clone, Debug)]
pub struct EdwardsPoint {
    pub u: AllocatedNum,
    pub v: AllocatedNum,
}

impl EdwardsPoint {
    pub fn witness(cs: &mut Cs, p: &JubJubPoint) -> Self {
        let (ule, vle) = p.affine_uv_le_bytes().expect("affine");
        let u = AllocatedNum::alloc(cs, scalar_from_fe_le(&ule));
        let v = AllocatedNum::alloc(cs, scalar_from_fe_le(&vle));
        Self::interpret(cs, &u, &v)
    }

    /// On-curve check: `-u² + v² = 1 + d·u²·v²` (sapling-crypto `interpret`).
    pub fn interpret(cs: &mut Cs, u: &AllocatedNum, v: &AllocatedNum) -> Self {
        let d = edwards_d_scalar();
        let u2 = AllocatedNum::mul(cs, u, u);
        let v2 = AllocatedNum::mul(cs, v, v);
        let u2v2 = AllocatedNum::mul(cs, &u2, &v2);
        // (-u2 + v2) * 1 = 1 + d*u2v2
        let mut lhs = lc_var(v2.var, Scalar::one());
        lhs.add(u2.var, Scalar::one().neg());
        let mut rhs = lc_one();
        rhs.add(u2v2.var, d);
        cs.enforce_lc(lhs, lc_one(), rhs);
        Self {
            u: u.clone(),
            v: v.clone(),
        }
    }

    pub fn identity(cs: &mut Cs) -> Self {
        Self {
            u: AllocatedNum::alloc(cs, Scalar::zero()),
            v: AllocatedNum::alloc(cs, Scalar::one()),
        }
    }

    pub fn inputize(&self, cs: &mut Cs) {
        self.u.inputize(cs);
        self.v.inputize(cs);
    }

    /// Compressed representation: `v` LE bits (255) ‖ `u` LSB.
    /// Constraint order matches sapling-crypto: unpack **u** first, then **v**,
    /// then emit `v ‖ u[0]`.
    pub fn repr(&self, cs: &mut Cs) -> Vec<Boolean> {
        // Bellman/sapling-crypto: full u + v LE strict bits, then y‖x_sign.
        // Must match exactly for ceremony matrix identity (do not optimise sign-only).
        let u_bits = self.u.to_bits_le_strict(cs, 255);
        let v_bits = self.v.to_bits_le_strict(cs, 255);
        let mut out = v_bits;
        out.push(u_bits[0].clone());
        out
    }

    /// `8·P` has nonzero u (not small order).
    pub fn assert_not_small_order(&self, cs: &mut Cs) {
        let mut tmp = Self::double(cs, self);
        tmp = Self::double(cs, &tmp);
        tmp = Self::double(cs, &tmp);
        tmp.u.assert_nonzero(cs);
    }

    /// `condition ? self : identity` (sapling-crypto LC shape).
    pub fn conditionally_select(cs: &mut Cs, p: &Self, condition: &Boolean) -> Self {
        // sapling-crypto EdwardsPoint::conditionally_select:
        //   A = coordinate, B = condition.lc(), C = result side
        //   condition.lc: Is → var; Not → (1 - var)
        let logical = condition.value;
        let make_cond_lc = || -> Lc {
            if condition.inverted {
                let mut lc = lc_one();
                lc.add(condition.var, Scalar::one().neg());
                lc
            } else {
                lc_var(condition.var, Scalar::one())
            }
        };

        // u' = u if condition else 0
        // A=u, B=condition.lc, C=u'
        let up_val = if logical {
            p.u.value
        } else {
            Scalar::zero()
        };
        let u_prime = AllocatedNum::alloc(cs, up_val);
        cs.enforce_lc(
            lc_var(p.u.var, Scalar::one()),
            make_cond_lc(),
            lc_var(u_prime.var, Scalar::one()),
        );

        // v' = v if condition else 1
        // A=v, B=condition.lc, C=v' - not(condition).lc
        let vp_val = if logical {
            p.v.value
        } else {
            Scalar::one()
        };
        let v_prime = AllocatedNum::alloc(cs, vp_val);
        let mut c_v = lc_var(v_prime.var, Scalar::one());
        if condition.inverted {
            // not(Not)=Is → lc = wire; C = v' - wire
            c_v.add(condition.var, Scalar::one().neg());
        } else {
            // not(Is)=Not → lc = 1-wire; C = v' - (1-wire) = v' - 1 + wire
            c_v.add(cs.one(), Scalar::one().neg());
            c_v.add(condition.var, Scalar::one());
        }
        cs.enforce_lc(lc_var(p.v.var, Scalar::one()), make_cond_lc(), c_v);

        Self {
            u: u_prime,
            v: AllocatedNum {
                var: v_prime.var,
                value: vp_val,
            },
        }
    }

    /// Variable-base scalar mul: `self * bits` (LSB-first), `GEdwardsPoint.mul`.
    pub fn mul_bits(cs: &mut Cs, base: &Self, bits: &[Boolean]) -> Self {
        assert!(!bits.is_empty());
        let mut cur_base: Option<Self> = None;
        let mut result: Option<Self> = None;
        for bit in bits {
            cur_base = Some(match cur_base {
                None => base.clone(),
                Some(cb) => Self::double(cs, &cb),
            });
            let this_base = Self::conditionally_select(cs, cur_base.as_ref().unwrap(), bit);
            result = Some(match result {
                None => this_base,
                Some(r) => Self::add(cs, &r, &this_base),
            });
        }
        result.unwrap()
    }

    /// Affine twisted-Edwards addition with full R1CS constraints (`add`).
    pub fn add(cs: &mut Cs, p: &Self, q: &Self) -> Self {
        let d = edwards_d_scalar();

        // U = (u1+v1)*(u2+v2)
        let u_sum1 = p.u.value.add(&p.v.value);
        let u_sum2 = q.u.value.add(&q.v.value);
        let u_val = u_sum1.mul(&u_sum2);
        let uppercase_u = AllocatedNum::alloc(cs, u_val);
        let mut lc_l = lc_var(p.u.var, Scalar::one());
        lc_l.add(p.v.var, Scalar::one());
        let mut lc_r = lc_var(q.u.var, Scalar::one());
        lc_r.add(q.v.var, Scalar::one());
        cs.enforce_lc(lc_l, lc_r, lc_var(uppercase_u.var, Scalar::one()));

        // A = v2 * u1  (sapling-crypto operand order)
        let a = AllocatedNum::mul(cs, &q.v, &p.u);
        // B = u2 * v1
        let b = AllocatedNum::mul(cs, &q.u, &p.v);

        // C = d * A * B  →  (d·A) * B = C
        let c_val = a.value.mul(&b.value).mul(&d);
        let c = AllocatedNum::alloc(cs, c_val);
        cs.enforce_lc(
            lc_var(a.var, d),
            lc_var(b.var, Scalar::one()),
            lc_var(c.var, Scalar::one()),
        );

        // u3 = (A+B)/(1+C)  →  (1+C)*u3 = A+B
        let u3_val = {
            let num = a.value.add(&b.value);
            let den = Scalar::one().add(&c.value);
            num.mul(&den.invert().expect("1+C"))
        };
        let u3 = AllocatedNum::alloc(cs, u3_val);
        let mut den_u = lc_one();
        den_u.add(c.var, Scalar::one());
        let mut num_u = lc_var(a.var, Scalar::one());
        num_u.add(b.var, Scalar::one());
        cs.enforce_lc(den_u, lc_var(u3.var, Scalar::one()), num_u);

        // v3 = (U-A-B)/(1-C)  →  (1-C)*v3 = U-A-B
        let v3_val = {
            let num = uppercase_u.value.sub(&a.value).sub(&b.value);
            let den = Scalar::one().sub(&c.value);
            num.mul(&den.invert().expect("1-C"))
        };
        let v3 = AllocatedNum::alloc(cs, v3_val);
        let mut den_v = lc_one();
        den_v.add(c.var, Scalar::one().neg());
        let mut num_v = lc_var(uppercase_u.var, Scalar::one());
        num_v.add(a.var, Scalar::one().neg());
        num_v.add(b.var, Scalar::one().neg());
        cs.enforce_lc(den_v, lc_var(v3.var, Scalar::one()), num_v);

        Self { u: u3, v: v3 }
    }

    /// Affine doubling with full constraints (`double`, a=-1).
    pub fn double(cs: &mut Cs, p: &Self) -> Self {
        let d = edwards_d_scalar();

        // T = (u+v)^2
        let t_val = p.u.value.add(&p.v.value);
        let t_val = t_val.mul(&t_val);
        let t = AllocatedNum::alloc(cs, t_val);
        let mut uv = lc_var(p.u.var, Scalar::one());
        uv.add(p.v.var, Scalar::one());
        cs.enforce_lc(uv.clone(), uv, lc_var(t.var, Scalar::one()));

        // A = u * v
        let a = AllocatedNum::mul(cs, &p.u, &p.v);

        // C = d * A * A
        let c_val = a.value.mul(&a.value).mul(&d);
        let c = AllocatedNum::alloc(cs, c_val);
        cs.enforce_lc(
            lc_var(a.var, d),
            lc_var(a.var, Scalar::one()),
            lc_var(c.var, Scalar::one()),
        );

        // u3 = (2A)/(1+C)
        let two = Scalar::one().add(&Scalar::one());
        let u3_val = a
            .value
            .mul(&two)
            .mul(&Scalar::one().add(&c.value).invert().expect("1+C"));
        let u3 = AllocatedNum::alloc(cs, u3_val);
        let mut den = lc_one();
        den.add(c.var, Scalar::one());
        let mut num = lc_var(a.var, Scalar::one());
        num.add(a.var, Scalar::one()); // 2A
        cs.enforce_lc(den, lc_var(u3.var, Scalar::one()), num);

        // v3 = (T - 2A)/(1-C)
        let v3_val = t
            .value
            .sub(&a.value.mul(&two))
            .mul(&Scalar::one().sub(&c.value).invert().expect("1-C"));
        let v3 = AllocatedNum::alloc(cs, v3_val);
        let mut den_v = lc_one();
        den_v.add(c.var, Scalar::one().neg());
        let mut num_v = lc_var(t.var, Scalar::one());
        num_v.add(a.var, Scalar::one().neg());
        num_v.add(a.var, Scalar::one().neg());
        cs.enforce_lc(den_v, lc_var(v3.var, Scalar::one()), num_v);

        Self { u: u3, v: v3 }
    }
}

/// Fixed-base multiplication with 3-bit windows (`fixedBaseMultiplication`).
pub fn fixed_base_mul(cs: &mut Cs, base: &JubJubPoint, bits: &[Boolean]) -> EdwardsPoint {
    // sapling-crypto: zip(chunks(3), windows) — extra bits beyond table ignored.
    // Official generators use a process-wide OnceLock table (Bellman-style constants).
    #[cfg(feature = "std")]
    {
        if let Some(windows) = crate::zk::sapling::windows::windows_for_base_ref(base) {
            return fixed_base_mul_with_windows(cs, windows, bits);
        }
    }
    let windows = windows_for_base(base);
    fixed_base_mul_with_windows(cs, &windows, bits)
}

fn fixed_base_mul_with_windows(
    cs: &mut Cs,
    windows: &[[crate::zk::sapling::windows::WindowPoint; 8]],
    bits: &[Boolean],
) -> EdwardsPoint {
    let mut result: Option<EdwardsPoint> = None;
    for (chunk, window) in bits.chunks(3).zip(windows.iter()) {
        let a = chunk
            .first()
            .cloned()
            .unwrap_or_else(|| Boolean::constant(cs, false));
        let b = chunk
            .get(1)
            .cloned()
            .unwrap_or_else(|| Boolean::constant(cs, false));
        let c = chunk
            .get(2)
            .cloned()
            .unwrap_or_else(|| Boolean::constant(cs, false));
        let (u, v) = lookup3_xy(cs, &[a, b, c], window);
        let p = EdwardsPoint { u, v };
        result = Some(match result {
            None => p,
            Some(r) => EdwardsPoint::add(cs, &r, &p),
        });
    }
    result.unwrap_or_else(|| EdwardsPoint::identity(cs))
}

#[cfg(test)]
mod tests {
    use super::*;
    // `ScalarTrait` is used only by tests (trait-method KATs); keep the
    // import here so production builds carry no unused imports.
    use crate::curve::traits::{CurvePoint, Scalar as ScalarTrait};
    use crate::zk::sapling::boolean::Boolean;
    use crate::zk::sapling::constants::{spending_key_generator, value_commitment_value_generator};
    use crate::zk::sapling::cs::Cs;

    #[test]
    fn add_constraints_satisfied() {
        let mut cs = Cs::new();
        let g = value_commitment_value_generator();
        let p = EdwardsPoint::witness(&mut cs, &g);
        let q = EdwardsPoint::witness(&mut cs, &spending_key_generator());
        let r = EdwardsPoint::add(&mut cs, &p, &q);
        let native = g.add(&spending_key_generator());
        let (ule, vle) = native.affine_uv_le_bytes().unwrap();
        assert_eq!(ScalarTrait::ct_eq(&r.u.value, &scalar_from_fe_le(&ule)), 1);
        assert_eq!(ScalarTrait::ct_eq(&r.v.value, &scalar_from_fe_le(&vle)), 1);
        let (r1cs, z) = cs.into_r1cs();
        assert!(r1cs.is_satisfied(&z));
    }

    #[test]
    fn variable_base_mul_matches_native() {
        use crate::zk::sapling::boolean::fr_to_bits;
        use crate::zk::sapling::constants::spending_key_generator;
        use crate::zk::sapling::native::compute_pk_d;
        let mut cs = Cs::new();
        let base_pt = spending_key_generator();
        let base = EdwardsPoint::witness(&mut cs, &base_pt);
        let mut sk = [0u8; 32];
        sk[0] = 10;
        let bits = fr_to_bits(&mut cs, &sk, 8);
        let circuit = EdwardsPoint::mul_bits(&mut cs, &base, &bits);
        let native = compute_pk_d(&base_pt, &sk).unwrap();
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
    fn fixed_base_small_satisfied() {
        let mut cs = Cs::new();
        let bits: Vec<_> = (0..3).map(|i| Boolean::alloc(&mut cs, i == 0)).collect();
        let p = fixed_base_mul(&mut cs, &value_commitment_value_generator(), &bits);
        p.inputize(&mut cs);
        let (r1cs, z) = cs.into_r1cs();
        assert!(r1cs.is_satisfied(&z), "ncons={}", r1cs.constraints.len());
    }

    /// Fingerprint isolated Edwards add: count + first-term shapes.
    #[test]
    fn add_constraint_stream() {
        let mut cs = Cs::new();
        let g = value_commitment_value_generator();
        let p = EdwardsPoint::witness(&mut cs, &g);
        let q = EdwardsPoint::witness(&mut cs, &spending_key_generator());
        let before = cs.constraints.len();
        let _ = EdwardsPoint::add(&mut cs, &p, &q);
        let n = cs.constraints.len() - before;
        // U, A=mul, B=mul, C, u3, v3 → 6 constraints (muls count as 1 each)
        assert_eq!(n, 6, "Edwards add should be 6 constraints, got {n}");
        let (r1cs, z) = cs.into_r1cs();
        assert!(r1cs.is_satisfied(&z));
    }

    #[test]
    fn double_constraint_stream() {
        let mut cs = Cs::new();
        let g = value_commitment_value_generator();
        let p = EdwardsPoint::witness(&mut cs, &g);
        let before = cs.constraints.len();
        let _ = EdwardsPoint::double(&mut cs, &p);
        let n = cs.constraints.len() - before;
        // T, A=mul, C, u3, v3 → 5
        assert_eq!(n, 5, "Edwards double should be 5 constraints, got {n}");
        let (r1cs, z) = cs.into_r1cs();
        assert!(r1cs.is_satisfied(&z));
    }
}
