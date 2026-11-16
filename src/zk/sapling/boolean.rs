//! Boolean / bit gadgets (Bellman-compatible free NOT via polarity).

use crate::curve::bls::Scalar;
use crate::zk::sapling::cs::{lc_one, lc_var, Cs, Lc, Var};

#[derive(Clone, Debug)]
pub struct Boolean {
    pub var: Var,
    pub value: bool,
    /// If true, the logical bit is `1 - wire` (Bellman `Boolean::Not`).
    pub inverted: bool,
}

impl Boolean {
    pub fn constant(cs: &mut Cs, v: bool) -> Self {
        if v {
            // Constant true = public ONE (Bellman Constant(true)).
            Boolean {
                var: cs.one(),
                value: true,
                inverted: false,
            }
        } else {
            // Constant false = Not(ONE) — **zero constraints** (Bellman Constant(false)).
            // Avoids Cs::zero_bit()'s 1-constraint allocation that inflated BLAKE2s by 1.
            Boolean {
                var: cs.one(),
                value: false,
                inverted: true,
            }
        }
    }

    pub fn alloc(cs: &mut Cs, value: bool) -> Self {
        let s = if value { Scalar::one() } else { Scalar::zero() };
        let var = cs.alloc(|| s);
        // (1 - b) * b = 0
        let mut a = lc_one();
        a.add(var, Scalar::one().neg());
        cs.enforce_lc(a, lc_var(var, Scalar::one()), Lc::new());
        Boolean {
            var,
            value,
            inverted: false,
        }
    }

    /// Allocate without bitness (result of XOR/linear ops that already force 0/1).
    pub fn alloc_unchecked(cs: &mut Cs, value: bool) -> Self {
        let s = if value { Scalar::one() } else { Scalar::zero() };
        let var = cs.alloc(|| s);
        Boolean {
            var,
            value,
            inverted: false,
        }
    }

    /// Bellman `AllocatedBit::alloc_conditionally` — **one** constraint:
    /// `(1 - must_be_false - a) * a = 0`.
    ///
    /// If `must_be_false` is true → forces `a = 0`; if false → ordinary bitness.
    pub fn alloc_conditionally(cs: &mut Cs, value: bool, must_be_false: &Boolean) -> Self {
        let s = if value { Scalar::one() } else { Scalar::zero() };
        let var = cs.alloc(|| s);
        // must_be_false must be a positive-polarity wire (AllocatedBit).
        let mbf = must_be_false.as_positive(cs);
        // (1 - must_be_false - a) * a = 0
        let mut lhs = lc_one();
        lhs.add(mbf.var, Scalar::one().neg());
        lhs.add(var, Scalar::one().neg());
        cs.enforce_lc(lhs, lc_var(var, Scalar::one()), Lc::new());
        Boolean {
            var,
            value,
            inverted: false,
        }
    }

    /// Free logical NOT (Bellman `Boolean::not`) — no new constraint.
    pub fn not(&self) -> Self {
        Boolean {
            var: self.var,
            value: !self.value,
            inverted: !self.inverted,
        }
    }

    /// Linear combination term for this logical bit: `coeff * logical`.
    /// logical = wire if !inverted, else (1 - wire).
    pub fn lc_term(&self, coeff: Scalar) -> Lc {
        let mut lc = Lc::new();
        if self.inverted {
            // coeff * (1 - var) = coeff - coeff*var
            // Use Input(0)=one for constant term — caller must use cs.one()
            // We only have var here; constant part handled by add_to_lc.
            lc.add(self.var, coeff.clone().neg());
            // constant +coeff must be added by caller via one()
        } else {
            lc.add(self.var, coeff);
        }
        lc
    }

    /// Add this logical bit · coeff into `lc`, using `one` for inverted constant term.
    pub fn add_to_lc(&self, lc: &mut Lc, one: Var, coeff: Scalar) {
        if self.inverted {
            lc.add(one, coeff);
            lc.add(self.var, coeff.neg());
        } else {
            lc.add(self.var, coeff);
        }
    }

    /// `Some(true/false)` if structural constant (CS one / zero_bit, not inverted).
    pub fn structural_const(&self, cs: &Cs) -> Option<bool> {
        if self.inverted {
            // inverted one => false, inverted zero => true
            if self.var == cs.one() {
                return Some(false);
            }
            if cs.is_zero_var(self.var) {
                return Some(true);
            }
            return None;
        }
        if self.var == cs.one() {
            return Some(true);
        }
        if cs.is_zero_var(self.var) {
            return Some(false);
        }
        None
    }

    /// Logical AND — Bellman `Boolean::and` match table (Is/Not/Constant).
    ///
    /// - false AND x → Constant(false)
    /// - true AND x → x
    /// - Is ∧ Is → AllocatedBit::and  (a)*(b)=c
    /// - Is ∧ Not → and_not            a*(1-b)=c
    /// - Not ∧ Not → nor               (1-a)*(1-b)=c
    pub fn and(cs: &mut Cs, a: &Boolean, b: &Boolean) -> Self {
        match (a.structural_const(cs), b.structural_const(cs)) {
            (Some(false), _) | (_, Some(false)) => return Boolean::constant(cs, false),
            (Some(true), _) => return b.clone(),
            (_, Some(true)) => return a.clone(),
            _ => {}
        }
        let value = a.value & b.value;
        let var = cs.alloc(|| if value { Scalar::one() } else { Scalar::zero() });
        match (a.inverted, b.inverted) {
            (false, false) => {
                // a * b = c
                cs.enforce_lc(
                    lc_var(a.var, Scalar::one()),
                    lc_var(b.var, Scalar::one()),
                    lc_var(var, Scalar::one()),
                );
            }
            (false, true) => {
                // a * (1 - b) = c
                let mut one_minus_b = lc_one();
                one_minus_b.add(b.var, Scalar::one().neg());
                cs.enforce_lc(
                    lc_var(a.var, Scalar::one()),
                    one_minus_b,
                    lc_var(var, Scalar::one()),
                );
            }
            (true, false) => {
                // (1 - a) * b = c
                let mut one_minus_a = lc_one();
                one_minus_a.add(a.var, Scalar::one().neg());
                cs.enforce_lc(
                    one_minus_a,
                    lc_var(b.var, Scalar::one()),
                    lc_var(var, Scalar::one()),
                );
            }
            (true, true) => {
                // (1 - a) * (1 - b) = c
                let mut one_minus_a = lc_one();
                one_minus_a.add(a.var, Scalar::one().neg());
                let mut one_minus_b = lc_one();
                one_minus_b.add(b.var, Scalar::one().neg());
                cs.enforce_lc(one_minus_a, one_minus_b, lc_var(var, Scalar::one()));
            }
        }
        Boolean {
            var,
            value,
            inverted: false,
        }
    }

    /// Return a non-inverted Boolean equal to self (allocates if inverted).
    ///
    /// Bellman `Constant(false)` is **free** (no wire). `Not(ONE)` is returned
    /// unchanged so LC builders must use [`add_to_lc`] / [`structural_const`].
    pub fn as_positive(&self, cs: &mut Cs) -> Self {
        if !self.inverted {
            return self.clone();
        }
        // Constant false = Not(ONE): stay free — no allocation (Bellman Constant(false)).
        if self.var == cs.one() && !self.value {
            return self.clone();
        }
        // General inverted wire: c = 1 - var
        let c = Boolean::alloc_unchecked(cs, self.value);
        let mut lhs = lc_var(c.var, Scalar::one());
        lhs.add(self.var, Scalar::one());
        cs.enforce_lc(lhs, lc_one(), lc_one());
        c
    }
}

pub fn u64_to_bits(cs: &mut Cs, v: u64) -> alloc::vec::Vec<Boolean> {
    (0..64)
        .map(|i| Boolean::alloc(cs, ((v >> i) & 1) == 1))
        .collect()
}

pub fn fr_to_bits(cs: &mut Cs, le: &[u8; 32], nbits: usize) -> alloc::vec::Vec<Boolean> {
    let mut out = alloc::vec::Vec::with_capacity(nbits);
    for i in 0..nbits {
        let bit = ((le[i / 8] >> (i % 8)) & 1) == 1;
        out.push(Boolean::alloc(cs, bit));
    }
    out
}
