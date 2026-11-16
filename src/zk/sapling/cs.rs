//! Bellman-style constraint system → [`R1csBls`].
//!
//! Constraints store **tagged** [`Var`] handles; global indices are assigned
//! only in [`Cs::into_r1cs`] so `alloc_input` never invalidates prior enforces.

use crate::curve::bls::Scalar;
use crate::zk::groth16::{ConstraintBls, LinearCombinationBls, R1csBls};
use alloc::vec;
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Var {
    Input(usize),
    Aux(usize),
}

#[derive(Clone, Debug, Default)]
pub struct Lc {
    pub terms: Vec<(Var, Scalar)>,
}

impl Lc {
    pub fn new() -> Self {
        Self { terms: Vec::new() }
    }
    pub fn add(&mut self, v: Var, c: Scalar) {
        // Merge like Bellman LinearCombination: one term per variable.
        for (existing, coeff) in self.terms.iter_mut() {
            if *existing == v {
                *coeff = coeff.add(&c);
                return;
            }
        }
        self.terms.push((v, c));
    }

    /// Sort terms by (input/aux, index) for stable R1CS export vs Bellman.
    pub fn canonicalize(&mut self) {
        self.terms.sort_by(|a, b| {
            let ka = match a.0 {
                Var::Input(i) => (0u8, i),
                Var::Aux(i) => (1u8, i),
            };
            let kb = match b.0 {
                Var::Input(i) => (0u8, i),
                Var::Aux(i) => (1u8, i),
            };
            ka.cmp(&kb)
        });
        self.terms
            .retain(|(_, c)| crate::curve::traits::Scalar::ct_eq(c, &Scalar::zero()) == 0);
    }
    pub fn from_var(v: Var, c: Scalar) -> Self {
        let mut lc = Self::new();
        lc.add(v, c);
        lc
    }
    pub fn one() -> Self {
        Self::from_var(Var::Input(0), Scalar::one())
    }
}

#[derive(Clone, Debug)]
pub struct Cs {
    pub dens_a_aux: alloc::vec::Vec<bool>,
    pub dens_b_aux: alloc::vec::Vec<bool>,
    pub inputs: Vec<Option<Scalar>>,
    pub aux: Vec<Option<Scalar>>,
    /// Tagged constraints (resolved in `into_r1cs`).
    pub constraints: Vec<(Lc, Lc, Lc)>,
    zero_bit: Option<Var>,
}

impl Cs {
    pub fn new() -> Self {
        Self {
            dens_a_aux: alloc::vec::Vec::new(),
            dens_b_aux: alloc::vec::Vec::new(),
            inputs: vec![Some(Scalar::one())],
            aux: Vec::new(),
            constraints: Vec::new(),
            zero_bit: None,
        }
    }

    pub fn one(&self) -> Var {
        Var::Input(0)
    }

    pub fn num_public(&self) -> usize {
        self.inputs.len().saturating_sub(1)
    }

    pub fn alloc<F: FnOnce() -> Scalar>(&mut self, f: F) -> Var {
        let local = self.aux.len();
        self.aux.push(Some(f()));
        self.dens_a_aux.push(false);
        self.dens_b_aux.push(false);
        Var::Aux(local)
    }

    pub fn alloc_input<F: FnOnce() -> Scalar>(&mut self, f: F) -> Var {
        let local = self.inputs.len();
        self.inputs.push(Some(f()));
        Var::Input(local)
    }

    pub fn enforce_lc(&mut self, mut a: Lc, mut b: Lc, mut c: Lc) {
        // Enforce-time dens (Bellman DensityTracker style: mark before merge)
        for &(v, ref coeff) in &a.terms {
            if crate::curve::traits::Scalar::ct_eq(coeff, &Scalar::zero()) == 0 {
                if let Var::Aux(i) = v {
                    if i < self.dens_a_aux.len() {
                        self.dens_a_aux[i] = true;
                    }
                }
            }
        }
        for &(v, ref coeff) in &b.terms {
            if crate::curve::traits::Scalar::ct_eq(coeff, &Scalar::zero()) == 0 {
                if let Var::Aux(i) = v {
                    if i < self.dens_b_aux.len() {
                        self.dens_b_aux[i] = true;
                    }
                }
            }
        }
        a.canonicalize();
        b.canonicalize();
        c.canonicalize();
        self.constraints.push((a, b, c));
    }

    /// Shared false bit (one constraint for all constant zeros).
    pub fn zero_bit(&mut self) -> Var {
        if let Some(z) = self.zero_bit {
            return z;
        }
        let z = self.alloc(Scalar::zero);
        self.enforce_lc(
            Lc::from_var(Var::Input(0), Scalar::one()),
            Lc::from_var(z, Scalar::one()),
            Lc::new(),
        );
        self.zero_bit = Some(z);
        z
    }

    pub fn is_zero_var(&self, v: Var) -> bool {
        self.zero_bit == Some(v)
    }

    fn global(&self, v: Var) -> usize {
        match v {
            Var::Input(i) => i,
            Var::Aux(i) => self.inputs.len() + i,
        }
    }

    fn lc_to_global(&self, lc: &Lc) -> LinearCombinationBls {
        let mut out = LinearCombinationBls::new();
        for &(v, ref c) in &lc.terms {
            out.add_term(self.global(v), *c);
        }
        out
    }

    pub fn into_r1cs(mut self) -> (R1csBls, Vec<Scalar>) {
        // Bellman prover/generator: after synthesize, for each public input (incl. ONE):
        //   enforce input_i * 0 = 0
        // so all inputs have full A-density and QAP row count matches ceremony CRS.
        let n_inputs = self.inputs.len();
        for i in 0..n_inputs {
            let a = Lc::from_var(Var::Input(i), Scalar::one());
            self.constraints.push((a, Lc::new(), Lc::new()));
        }

        let mut assignment = Vec::with_capacity(self.inputs.len() + self.aux.len());
        for o in &self.inputs {
            assignment.push((*o).unwrap_or_else(Scalar::zero));
        }
        for o in &self.aux {
            assignment.push((*o).unwrap_or_else(Scalar::zero));
        }
        let constraints = self
            .constraints
            .iter()
            .map(|(a, b, c)| ConstraintBls {
                a: self.lc_to_global(a),
                b: self.lc_to_global(b),
                c: self.lc_to_global(c),
            })
            .collect();
        (
            R1csBls {
                num_public: self.inputs.len() - 1,
                num_variables: assignment.len(),
                constraints,
            },
            assignment,
        )
    }
}

impl Default for Cs {
    fn default() -> Self {
        Self::new()
    }
}

pub fn lc_var(v: Var, c: Scalar) -> Lc {
    Lc::from_var(v, c)
}

pub fn lc_one() -> Lc {
    Lc::one()
}

/// Pack multiple linear equalities `lhs = rhs` into fewer R1CS constraints
/// (Bellman `gadgets::multieq::MultiEq`).
///
/// Each equation claims `num_bits` of field capacity; when capacity would be
/// exceeded the accumulator is flushed as a single constraint
/// `Σ 2^{off_i}·lhs_i = Σ 2^{off_i}·rhs_i`.
pub struct MultiEq<'a> {
    cs: &'a mut Cs,
    bits_used: usize,
    lhs: Lc,
    rhs: Lc,
}

/// BLS12-381 scalar capacity used by Bellman packing (≈254).
const FIELD_CAPACITY: usize = 254; // bls12-381 Scalar::CAPACITY = NUM_BITS-1

impl<'a> MultiEq<'a> {
    pub fn new(cs: &'a mut Cs) -> Self {
        Self {
            cs,
            bits_used: 0,
            lhs: Lc::new(),
            rhs: Lc::new(),
        }
    }

    fn accumulate(&mut self) {
        if self.bits_used == 0 {
            return;
        }
        let lhs = core::mem::replace(&mut self.lhs, Lc::new());
        let rhs = core::mem::replace(&mut self.rhs, Lc::new());
        // Bellman MultiEq: A=lhs, B=ONE, C=rhs
        self.cs.enforce_lc(lhs, lc_one(), rhs);
        self.bits_used = 0;
    }

    /// Enforce `lhs = rhs` where both sides fit in `num_bits` bits.
    pub fn enforce_equal(&mut self, num_bits: usize, lhs: &Lc, rhs: &Lc) {
        // Bellman `MultiEq::enforce_equal`:
        //   if CAPACITY <= bits_used + num_bits { accumulate }
        //   assert CAPACITY > bits_used + num_bits
        if FIELD_CAPACITY <= self.bits_used + num_bits {
            self.accumulate();
        }
        assert!(
            FIELD_CAPACITY > self.bits_used + num_bits,
            "equation too wide for field capacity"
        );
        // coeff = 2^{bits_used}
        let mut coeff = Scalar::one();
        for _ in 0..self.bits_used {
            coeff = coeff.add(&coeff);
        }
        for &(v, ref c) in &lhs.terms {
            self.lhs.add(v, c.mul(&coeff));
        }
        for &(v, ref c) in &rhs.terms {
            self.rhs.add(v, c.mul(&coeff));
        }
        self.bits_used += num_bits;
    }

    pub fn cs(&mut self) -> &mut Cs {
        self.cs
    }
}

impl<'a> Drop for MultiEq<'a> {
    fn drop(&mut self) {
        self.accumulate();
    }
}
