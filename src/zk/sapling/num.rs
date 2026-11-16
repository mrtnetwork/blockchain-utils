//! Allocated field elements.

use crate::curve::bls::Scalar;
use crate::zk::sapling::boolean::Boolean;
use crate::zk::sapling::cs::{lc_one, lc_var, Cs, Lc, Var};
use alloc::vec::Vec;

#[derive(Clone, Debug)]
pub struct AllocatedNum {
    pub var: Var,
    pub value: Scalar,
}

impl AllocatedNum {
    pub fn alloc(cs: &mut Cs, value: Scalar) -> Self {
        let var = cs.alloc(|| value);
        Self { var, value }
    }

    pub fn inputize(&self, cs: &mut Cs) {
        let input = cs.alloc_input(|| self.value);
        cs.enforce_lc(
            lc_var(input, Scalar::one()),
            lc_one(),
            lc_var(self.var, Scalar::one()),
        );
    }

    pub fn from_bits_le(cs: &mut Cs, bits: &[Boolean]) -> Self {
        let mut acc = Scalar::zero();
        let mut coeff = Scalar::one();
        let mut lc = Lc::new();
        for bit in bits {
            if bit.value {
                acc = acc.add(&coeff);
            }
            lc.add(bit.var, coeff);
            coeff = coeff.add(&coeff);
        }
        let var = cs.alloc(|| acc);
        // Bellman: A=0,B=0,C=sum-var
        lc.add(var, Scalar::one().neg());
        cs.enforce_lc(Lc::new(), Lc::new(), lc);
        Self { var, value: acc }
    }

    pub fn mul(cs: &mut Cs, a: &Self, b: &Self) -> Self {
        let value = a.value.mul(&b.value);
        let var = cs.alloc(|| value);
        cs.enforce_lc(
            lc_var(a.var, Scalar::one()),
            lc_var(b.var, Scalar::one()),
            lc_var(var, Scalar::one()),
        );
        Self { var, value }
    }

    pub fn add(cs: &mut Cs, a: &Self, b: &Self) -> Self {
        let value = a.value.add(&b.value);
        let var = cs.alloc(|| value);
        // Bellman linear form: (a + b - c) * 1 = 0  → result on A (not only C)
        let mut lc = lc_var(a.var, Scalar::one());
        lc.add(b.var, Scalar::one());
        lc.add(var, Scalar::one().neg());
        cs.enforce_lc(lc, lc_one(), Lc::new());
        Self { var, value }
    }

    /// Unpack LE bits and enforce `Σ bit_i·2^i = self` (Bellman `to_bits_le`).
    ///
    /// Booleanity of each bit is enforced by [`Boolean::alloc`].
    /// Pack constraint is a single LC equality (no intermediate variable).
    pub fn to_bits_le(&self, cs: &mut Cs, nbits: usize) -> Vec<Boolean> {
        let mut be = [0u8; 32];
        self.value.to_bytes_be(&mut be);
        let mut le = be;
        le.reverse();
        let bits = crate::zk::sapling::boolean::fr_to_bits(cs, &le, nbits);
        let mut lc = Lc::new();
        let mut coeff = Scalar::one();
        for bit in &bits {
            bit.add_to_lc(&mut lc, cs.one(), coeff);
            coeff = coeff.add(&coeff);
        }
        // Bellman packing: A=0, B=0, C = sum - self
        lc.add(self.var, Scalar::one().neg());
        cs.enforce_lc(Lc::new(), Lc::new(), lc);
        bits
    }

    /// Bellman `AllocatedNum::to_bits_le_strict`: LE bits with field-membership
    /// (`≤ r−1`) via runs-of-ones / `alloc_conditionally` / k-ary AND.
    ///
    /// Returns little-endian bits (index 0 = LSB). `nbits` is ignored for the
    /// strict path — always uses full Fr characteristic bit length (255).
    pub fn to_bits_le_strict(&self, cs: &mut Cs, _nbits: usize) -> Vec<Boolean> {
        // Bits of a (value) and of (r-1) = -1, little-endian then process BE.
        let mut a_be = [0u8; 32];
        self.value.to_bytes_be(&mut a_be);
        // LE bit i of value
        let a_bit_at = |i: usize| -> bool {
            let byte = a_be[31 - i / 8];
            ((byte >> (i % 8)) & 1) == 1
        };
        // r-1 = -1 as LE bits
        let mut m1_be = [0u8; 32];
        Scalar::one().neg().to_bytes_be(&mut m1_be);
        let m1_bit_at = |i: usize| -> bool {
            let byte = m1_be[31 - i / 8];
            ((byte >> (i % 8)) & 1) == 1
        };

        // Process modulus bits in big-endian order (MSB first), matching Bellman.
        let mut result_be: Vec<Boolean> = Vec::with_capacity(255);
        let mut last_run: Option<Boolean> = None;
        let mut current_run: Vec<Boolean> = Vec::new();
        let mut found_one = false;
        let mut i = 0usize; // counts emitted bits in BE walk

        // Walk bit positions from 254 down to 0 (MSB of 255-bit field first)
        for pos in (0..255).rev() {
            let b = m1_bit_at(pos);
            let a_b = a_bit_at(pos);

            found_one |= b;
            if !found_one {
                // Leading zeros of r-1; a must also be 0 (not constrained as AllocatedBit)
                continue;
            }

            if b {
                // Run of ones in r-1: unconstrained bitness alloc
                let bit = Boolean::alloc(cs, a_b);
                current_run.push(bit.clone());
                result_be.push(bit);
            } else {
                // Start of a run of zeros: fold current_run with last_run via k-ary AND
                if !current_run.is_empty() {
                    if let Some(ref lr) = last_run {
                        current_run.push(lr.clone());
                    }
                    last_run = Some(kary_and(cs, &current_run));
                    current_run.clear();
                }
                let cond = last_run.as_ref().expect("char always starts with a one");
                let bit = Boolean::alloc_conditionally(cs, a_b, cond);
                result_be.push(bit);
            }
            i += 1;
        }
        let _ = i;
        assert!(current_run.is_empty(), "char is prime → ends on zeros run");

        // result_be is big-endian order of the emitted bits; reverse → LE
        let result_le: Vec<Boolean> = result_be.into_iter().rev().collect();

        // Packing: Σ bit_i · 2^i = self
        let mut lc = Lc::new();
        let mut coeff = Scalar::one();
        for bit in &result_le {
            bit.add_to_lc(&mut lc, cs.one(), coeff);
            coeff = coeff.add(&coeff);
        }
        // Bellman packing: A=0, B=0, C = sum - self
        lc.add(self.var, Scalar::one().neg());
        cs.enforce_lc(Lc::new(), Lc::new(), lc);
        result_le
    }
}

/// k-ary AND of allocated bits (Bellman helper inside to_bits_le_strict).
fn kary_and(cs: &mut Cs, v: &[Boolean]) -> Boolean {
    assert!(!v.is_empty());
    let mut cur = v[0].clone();
    for (i, b) in v.iter().enumerate().skip(1) {
        let _ = i;
        cur = Boolean::and(cs, &cur, b);
    }
    cur
}

impl AllocatedNum {
    /// If `c`: return `(b, a)`, else `(a, b)`.
    pub fn conditional_reverse(
        cs: &mut Cs,
        a: &Self,
        b: &Self,
        condition: &Boolean,
    ) -> (Self, Self) {
        // Bellman AllocatedNum::conditionally_reverse:
        //   (a - b) * condition = (a - c)
        //   (b - a) * condition = (b - d)
        // with condition.lc (Is → var; Not → 1-var)
        let out0_v = if condition.value {
            b.value
        } else {
            a.value
        };
        let out1_v = if condition.value {
            a.value
        } else {
            b.value
        };
        let out0 = cs.alloc(|| out0_v);
        let out1 = cs.alloc(|| out1_v);
        // condition.lc
        let cond_lc = if condition.inverted {
            let mut lc = lc_one();
            lc.add(condition.var, Scalar::one().neg());
            lc
        } else {
            lc_var(condition.var, Scalar::one())
        };
        // (a - b) * condition = (a - out0)
        let mut a_minus_b = lc_var(a.var, Scalar::one());
        a_minus_b.add(b.var, Scalar::one().neg());
        let mut a_minus_c = lc_var(a.var, Scalar::one());
        a_minus_c.add(out0, Scalar::one().neg());
        cs.enforce_lc(a_minus_b, cond_lc.clone(), a_minus_c);
        // (b - a) * condition = (b - out1)
        let mut b_minus_a = lc_var(b.var, Scalar::one());
        b_minus_a.add(a.var, Scalar::one().neg());
        let mut b_minus_d = lc_var(b.var, Scalar::one());
        b_minus_d.add(out1, Scalar::one().neg());
        cs.enforce_lc(b_minus_a, cond_lc, b_minus_d);
        (
            AllocatedNum {
                var: out0,
                value: out0_v,
            },
            AllocatedNum {
                var: out1,
                value: out1_v,
            },
        )
    }

    /// Enforce `self ≠ 0` via inverse: `self * inv = 1`.
    pub fn assert_nonzero(&self, cs: &mut Cs) {
        let inv = self.value.invert().unwrap_or_else(|_| Scalar::zero());
        let inv_v = AllocatedNum::alloc(cs, inv);
        cs.enforce_lc(
            lc_var(self.var, Scalar::one()),
            lc_var(inv_v.var, Scalar::one()),
            lc_one(),
        );
    }
}

pub fn scalar_from_fe_le(le: &[u8; 32]) -> Scalar {
    let mut be = *le;
    be.reverse();
    Scalar::from_bytes_be(&be).unwrap_or_else(|_| Scalar::zero())
}

#[cfg(test)]
mod strict_tests {
    use super::*;
    use crate::zk::sapling::cs::Cs;

    #[test]
    fn strict_unpack_cost_one_fr() {
        let mut cs = Cs::new();
        // Use a typical Jubjub coordinate-like value
        let mut be = [0u8; 32];
        be[31] = 7;
        let v = Scalar::from_bytes_be(&be).unwrap();
        let n = AllocatedNum::alloc(&mut cs, v);
        let a0 = cs.aux.len();
        let c0 = cs.constraints.len();
        let bits = n.to_bits_le_strict(&mut cs, 255);
        let da = cs.aux.len() - a0;
        let dc = cs.constraints.len() - c0;
        eprintln!(
            "strict one Fr: bits={} Δcons={} Δaux={} (naive would be ~256 cons / 255 aux)",
            bits.len(),
            dc,
            da
        );
        // Count r-1 ones/zeros
        let mut m1 = [0u8; 32];
        Scalar::one().neg().to_bytes_be(&mut m1);
        let mut ones = 0;
        let mut zeros = 0;
        for pos in 0..255 {
            let byte = m1[31 - pos / 8];
            if ((byte >> (pos % 8)) & 1) == 1 {
                ones += 1
            } else {
                zeros += 1
            }
        }
        eprintln!("r-1 LE: ones={ones} zeros={zeros}");
    }
}

#[cfg(test)]
mod packing_tests {
    use super::*;
    use crate::zk::sapling::cs::Cs;

    #[test]
    fn packing_form_is_bellman_c_only() {
        // to_bits_le must emit a single constraint with A=0, B=0, C=sum-bits.
        let mut cs = Cs::new();
        let n = AllocatedNum::alloc(&mut cs, Scalar::from_u64(7));
        let before = cs.constraints.len();
        let bits = n.to_bits_le(&mut cs, 8);
        assert_eq!(bits.len(), 8);
        assert_eq!(cs.constraints.len(), before + 1 + 8); // 8 bitness + 1 pack
        let (a, b, c) = &cs.constraints[before + 8];
        assert!(a.terms.is_empty(), "pack A must be empty");
        assert!(b.terms.is_empty(), "pack B must be empty");
        assert!(!c.terms.is_empty(), "pack C must hold sum-self");
        println!("packing form: A=0 B=0 C-terms={} OK", c.terms.len());
    }
}

#[cfg(test)]
mod strict_cost {
    use super::*;
    use crate::zk::sapling::cs::Cs;
    #[test]
    fn strict_cost_print() {
        let mut cs = Cs::new();
        let n = AllocatedNum::alloc(&mut cs, Scalar::from_u64(1));
        let before = cs.constraints.len();
        let bits = n.to_bits_le_strict(&mut cs, 255);
        println!(
            "strict: bits={} Δcons={}",
            bits.len(),
            cs.constraints.len() - before
        );
    }
}
