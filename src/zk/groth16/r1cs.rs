//! Minimal R1CS for Groth16 prover.

#![cfg(feature = "groth16-prover")]

use crate::curve::bn254::Scalar;
use alloc::vec::Vec;

/// Sparse linear combination: Σ coeff_i · variable_i
#[derive(Clone, Debug, Default)]
pub struct LinearCombination {
    /// (variable index, coefficient)
    pub terms: Vec<(usize, Scalar)>,
}

impl LinearCombination {
    pub fn new() -> Self {
        Self { terms: Vec::new() }
    }
    pub fn add_term(&mut self, var: usize, coeff: Scalar) {
        self.terms.push((var, coeff));
    }
    /// Evaluate on assignment.
    pub fn eval(&self, assignment: &[Scalar]) -> Scalar {
        let mut acc = Scalar::zero();
        for &(i, ref c) in &self.terms {
            acc = acc.add(&c.mul(&assignment[i]));
        }
        acc
    }
}

/// One R1CS constraint: ⟨A,z⟩ · ⟨B,z⟩ = ⟨C,z⟩
#[derive(Clone, Debug)]
pub struct Constraint {
    pub a: LinearCombination,
    pub b: LinearCombination,
    pub c: LinearCombination,
}

/// R1CS system.
#[derive(Clone, Debug)]
pub struct R1cs {
    /// Number of public inputs (not counting the constant `1` at index 0).
    pub num_public: usize,
    /// Total variables including constant-1 and private witness.
    pub num_variables: usize,
    pub constraints: Vec<Constraint>,
}

impl R1cs {
    /// Trivial multiplication circuit: public `out`, private `a,b` with `a * b = out`.
    ///
    /// Variables: `[1, out, a, b]` — indices 0=const, 1=public out, 2..=3 private.
    pub fn mult_circuit() -> Self {
        let mut a = LinearCombination::new();
        a.add_term(2, Scalar::one()); // a
        let mut b = LinearCombination::new();
        b.add_term(3, Scalar::one()); // b
        let mut c = LinearCombination::new();
        c.add_term(1, Scalar::one()); // out
        Self {
            num_public: 1,
            num_variables: 4,
            constraints: alloc::vec![Constraint { a, b, c }],
        }
    }

    /// Check assignment satisfies all constraints.
    pub fn is_satisfied(&self, assignment: &[Scalar]) -> bool {
        if assignment.len() != self.num_variables {
            return false;
        }
        // index 0 must be one
        if assignment[0].ct_eq(&Scalar::one()) == 0 {
            return false;
        }
        for c in &self.constraints {
            let av = c.a.eval(assignment);
            let bv = c.b.eval(assignment);
            let cv = c.c.eval(assignment);
            if av.mul(&bv).ct_eq(&cv) == 0 {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mult_circuit_satisfied() {
        let cs = R1cs::mult_circuit();
        // 1 * out=6, a=2, b=3
        let z = [
            Scalar::one(),
            Scalar::from_u64(6),
            Scalar::from_u64(2),
            Scalar::from_u64(3),
        ];
        assert!(cs.is_satisfied(&z));
    }
}
