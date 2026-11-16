//! 32-bit integer gadgets for BLAKE2s (LE bit order).

use crate::curve::bls::Scalar;
use crate::zk::sapling::boolean::Boolean;
use crate::zk::sapling::cs::{lc_var, Cs, Lc, MultiEq};
use alloc::vec::Vec;

/// Bellman-style single-bit XOR with free polarity.
fn xor_bit(cs: &mut Cs, a: &Boolean, b: &Boolean) -> Boolean {
    // Bellman Boolean::xor:
    //   const shortcuts; mixed Is/Not → xor(is, not.not()).not() free;
    //   Is/Is or Not/Not → AllocatedBit::xor on underlying wires → Is result.
    match (a.structural_const(cs), b.structural_const(cs)) {
        (Some(false), _) => return b.clone(),
        (_, Some(false)) => return a.clone(),
        (Some(true), Some(true)) => return Boolean::constant(cs, false),
        (Some(true), None) => return b.not(),
        (None, Some(true)) => return a.not(),
        _ => {}
    }
    match (a.inverted, b.inverted) {
        // mixed: a XOR (NOT b) = NOT(a XOR b) with free NOTs
        (false, true) | (true, false) => {
            let is = if a.inverted { b } else { a };
            let not = if a.inverted { a } else { b };
            // not.not() is free Is on same wire
            let unnot = not.not();
            let x = xor_bit_allocated(cs, is, &unnot);
            x.not()
        }
        // both Is or both Not: XOR underlying positive wires → Is
        // (NOT a) XOR (NOT b) = a XOR b
        (false, false) | (true, true) => xor_bit_allocated(cs, a, b),
    }
}

/// AllocatedBit::xor: (a+a)*b = a+b-c, result always Is polarity.
fn xor_bit_allocated(cs: &mut Cs, a: &Boolean, b: &Boolean) -> Boolean {
    let logical = a.value ^ b.value;
    // Underlying wires: for Not polarity, wire stores !value; Bellman passes
    // AllocatedBit refs which always store the positive boolean. Our Not uses
    // inverted=true with wire=!value, so for both-Not we need positive wires:
    // positive value on wire for AllocatedBit::xor is the AllocatedBit value.
    // When inverted, wire = !logical_value of the Boolean; the underlying bit
    // value Bellman uses is the AllocatedBit's value = wire content for Is,
    // and for Not the AllocatedBit is the pre-not bit.
    // We represent Not as {var, value: logical, inverted: true} with var holding !logical.
    // For both-Not, Bellman xors the two AllocatedBits (positive). Equivalent
    // positive wire values are !a.value and !b.value stored on var...
    // Actually a.var holds !a.value when inverted. AllocatedBit value = a.var content.
    // Bellman: xor(Not(a), Not(b)) uses AllocatedBit a and b where a.value is the
    // bit before not. Our a.var when inverted holds !logical = AllocatedBit value.
    // For both Not: logical_a = a.value, wire = !a.value = AllocatedBit.
    // xor of AllocatedBits = xor of wire values = xor(!la, !lb) = xor(la, lb) = logical result.
    // constraint on wires, result Is with logical = a.value ^ b.value. Good.
    let c = Boolean::alloc_unchecked(cs, logical);
    let mut a2 = lc_var(a.var, Scalar::one());
    a2.add(a.var, Scalar::one());
    let mut rhs = lc_var(a.var, Scalar::one());
    rhs.add(b.var, Scalar::one());
    rhs.add(c.var, Scalar::one().neg());
    cs.enforce_lc(a2, lc_var(b.var, Scalar::one()), rhs);
    Boolean {
        var: c.var,
        value: logical,
        inverted: false,
    }
}

#[derive(Clone, Debug)]
pub struct UInt32 {
    pub bits: Vec<Boolean>,
    pub value: u32,
}

impl UInt32 {
    pub fn constant(cs: &mut Cs, value: u32) -> Self {
        let mut bits = Vec::with_capacity(32);
        let mut tmp = value;
        for _ in 0..32 {
            bits.push(Boolean::constant(cs, (tmp & 1) == 1));
            tmp >>= 1;
        }
        Self { bits, value }
    }

    pub fn from_bits_pad(cs: &mut Cs, bits: &[Boolean]) -> Self {
        let mut b = bits.to_vec();
        while b.len() < 32 {
            b.push(Boolean::constant(cs, false));
        }
        b.truncate(32);
        let mut value = 0u32;
        for (i, bit) in b.iter().enumerate() {
            if bit.value {
                value |= 1u32 << i;
            }
        }
        Self { bits: b, value }
    }

    #[allow(clippy::wrong_self_convention)] // Name matches the upstream gadget/Boolean API; method borrows to preserve the value.
    pub fn into_bits(&self) -> Vec<Boolean> {
        self.bits.clone()
    }

    fn is_constant(&self, cs: &Cs) -> bool {
        self.bits.iter().all(|b| b.structural_const(cs).is_some())
    }

    /// Bitwise XOR (Bellman `Boolean::xor` polarity rules).
    ///
    /// Constants elided; free NOT when XORing with 1; general case is **one**
    /// constraint on the underlying wires with result polarity `inv_a ⊕ inv_b`
    /// (never materializes `as_positive` — that was inflating BLAKE2s).
    pub fn xor(cs: &mut Cs, a: &Self, b: &Self) -> Self {
        let value = a.value ^ b.value;
        if a.is_constant(cs) && b.is_constant(cs) {
            return Self::constant(cs, value);
        }
        let mut bits = Vec::with_capacity(32);
        for i in 0..32 {
            bits.push(xor_bit(cs, &a.bits[i], &b.bits[i]));
        }
        Self { bits, value }
    }

    pub fn rotr(&self, by: usize) -> Self {
        let shift = by % 32;
        let mut bits = Vec::with_capacity(32);
        for i in 0..32 {
            bits.push(self.bits[(i + shift) % 32].clone());
        }
        Self {
            bits,
            value: self.value.rotate_right(shift as u32),
        }
    }

    /// Modular 2^32 sum with constrained carry chain (supports up to ~3 addends).
    /// All-constant operands → constant result (0 constraints).
    /// Test-only helper (unit tests below).
    #[cfg(test)]
    pub fn add_many(cs: &mut Cs, ops: &[&Self]) -> Self {
        // Function-local: `add_many` is test-only (see above).
        use super::cs::lc_one;
        use crate::curve::traits::Scalar as ScalarTrait;
        assert!(!ops.is_empty());
        let mut acc = 0u64;
        for o in ops {
            acc = acc.wrapping_add(o.value as u64);
        }
        let result_val = (acc & 0xffff_ffff) as u32;

        if ops.iter().all(|o| o.is_constant(cs)) {
            return Self::constant(cs, result_val);
        }

        // Two-operand path (Bellman density ~34): one weighted-sum + bitness on outs + cout.
        // Structural-constant operand bits fold into the constant term of the LC (matches MultiEq savings partially).
        if ops.len() == 2 {
            let a = ops[0];
            let b = ops[1];
            let mut result_bits = Vec::with_capacity(32);
            let mut pow = Scalar::one();
            let mut lhs = Lc::new();
            let mut rhs = Lc::new();
            let mut const_lhs = Scalar::zero();
            for bit_i in 0..32 {
                let out_bit = ((result_val >> bit_i) & 1) == 1;
                let out = Boolean::alloc(cs, out_bit);
                // fold constant bits of a,b into const_lhs
                match a.bits[bit_i].structural_const(cs) {
                    Some(true) => const_lhs = const_lhs.add(&pow),
                    Some(false) => {}
                    None => a.bits[bit_i].add_to_lc(&mut lhs, cs.one(), pow),
                }
                match b.bits[bit_i].structural_const(cs) {
                    Some(true) => const_lhs = const_lhs.add(&pow),
                    Some(false) => {}
                    None => b.bits[bit_i].add_to_lc(&mut lhs, cs.one(), pow),
                }
                rhs.add(out.var, pow);
                result_bits.push(out);
                pow = pow.add(&pow);
            }
            if ScalarTrait::ct_eq(&const_lhs, &Scalar::zero()) == 0 {
                lhs.add(cs.one(), const_lhs);
            }
            let cout_val = ((a.value as u64) + (b.value as u64)) >= (1u64 << 32);
            let cout = Boolean::alloc(cs, cout_val);
            rhs.add(cout.var, pow); // 2^32 * cout
            cs.enforce_lc(lhs, lc_one(), rhs);
            let _ = cout;
            return Self {
                bits: result_bits,
                value: result_val,
            };
        }

        // 3+ operands: weighted field sum + bitness on out + 2-bit overflow.
        // Constant operand bits fold into the constant term of the LC.
        let mut result_bits = Vec::with_capacity(32);
        let mut pow = Scalar::one();
        let mut lhs = Lc::new();
        let mut rhs = Lc::new();
        let mut const_lhs = Scalar::zero();
        for bit_i in 0..32 {
            let out_bit = ((result_val >> bit_i) & 1) == 1;
            let out = Boolean::alloc(cs, out_bit);
            for o in ops {
                match o.bits[bit_i].structural_const(cs) {
                    Some(true) => const_lhs = const_lhs.add(&pow),
                    Some(false) => {}
                    None => o.bits[bit_i].add_to_lc(&mut lhs, cs.one(), pow),
                }
            }
            rhs.add(out.var, pow);
            result_bits.push(out);
            pow = pow.add(&pow);
        }
        if ScalarTrait::ct_eq(&const_lhs, &Scalar::zero()) == 0 {
            lhs.add(cs.one(), const_lhs);
        }
        let total: u64 = ops.iter().map(|o| o.value as u64).sum();
        let overflow = total >> 32;
        let c0 = Boolean::alloc(cs, (overflow & 1) == 1);
        let c1 = Boolean::alloc(cs, ((overflow >> 1) & 1) == 1);
        rhs.add(c0.var, pow);
        let pow2 = pow.add(&pow);
        rhs.add(c1.var, pow2);
        cs.enforce_lc(lhs, lc_one(), rhs);
        let _ = (c0, c1);
        Self {
            bits: result_bits,
            value: result_val,
        }
    }

    /// Bellman-compatible `addmany` under [`MultiEq`]:
    /// allocate full-width result bits (incl. carry), pack one equality, truncate to 32.
    pub fn add_many_eq(meq: &mut MultiEq<'_>, ops: &[&Self]) -> Self {
        assert!(ops.len() >= 2 && ops.len() <= 10);
        let mut result_value: u64 = 0;
        for o in ops {
            result_value = result_value.wrapping_add(o.value as u64);
        }
        let modular_value = result_value as u32;

        {
            let cs = meq.cs();
            if ops.iter().all(|o| o.is_constant(cs)) {
                return Self::constant(cs, modular_value);
            }
        }

        let mut max_value = (ops.len() as u64) * (u32::MAX as u64);
        let (bits, lhs, rhs, eq_bits) = {
            let cs = meq.cs();
            let mut lhs = Lc::new();
            for o in ops {
                let mut pow = Scalar::one();
                for bit_i in 0..32 {
                    match o.bits[bit_i].structural_const(cs) {
                        Some(true) => lhs.add(cs.one(), pow),
                        Some(false) => {}
                        None => o.bits[bit_i].add_to_lc(&mut lhs, cs.one(), pow),
                    }
                    pow = pow.add(&pow);
                }
            }
            let mut result_bits = Vec::new();
            let mut result_lc = Lc::new();
            let mut pow = Scalar::one();
            let mut i = 0u32;
            while max_value != 0 {
                let bit_val = ((result_value >> i) & 1) == 1;
                let b = Boolean::alloc(cs, bit_val);
                result_lc.add(b.var, pow);
                result_bits.push(b);
                max_value >>= 1;
                i += 1;
                pow = pow.add(&pow);
            }
            let eq_bits = result_bits.len();
            (result_bits, lhs, result_lc, eq_bits)
        };
        meq.enforce_equal(eq_bits, &lhs, &rhs);
        let mut bits = bits;
        bits.truncate(32);
        Self {
            bits,
            value: modular_value,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(feature = "std", feature = "groth16-prover"))]
    #[test]
    fn add_many_dens_probe() {
        use crate::zk::groth16::{a_density, b_density};
        use crate::zk::sapling::boolean::Boolean;
        use crate::zk::sapling::cs::{Cs, MultiEq};
        let mut cs = Cs::new();
        let make = |cs: &mut Cs, v: u32| {
            let bits: Vec<_> = (0..32)
                .map(|i| Boolean::alloc(cs, ((v >> i) & 1) == 1))
                .collect();
            UInt32 { bits, value: v }
        };
        let a = make(&mut cs, 0x12345678);
        let b = make(&mut cs, 0x9abcdef0);
        let pre = cs.constraints.len();
        {
            let mut meq = MultiEq::new(&mut cs);
            let _ = UInt32::add_many_eq(&mut meq, &[&a, &b]);
        }
        let body = cs.constraints.len() - pre;
        let (r1cs, _) = cs.into_r1cs();
        let da = a_density(&r1cs);
        let db = b_density(&r1cs);
        println!(
            "add_many dens a={} b={} ncons={} body_cons={} nvars={}",
            da.len(),
            db.len(),
            r1cs.constraints.len(),
            body,
            r1cs.num_variables
        );
    }
}
