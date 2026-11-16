//! Multi-scalar multiplication (G1 BN254).

#![cfg(feature = "groth16-prover")]

use crate::curve::bn254::{G1Point, Scalar};
use crate::curve::traits::CurvePoint;

/// Multi-scalar mul: Σ scalars[i] · bases[i].
pub fn msm_g1(bases: &[G1Point], scalars: &[Scalar]) -> G1Point {
    assert_eq!(bases.len(), scalars.len());
    let mut acc = G1Point::identity();
    for (base, scalar) in bases.iter().zip(scalars.iter()) {
        acc = acc.add(&base.mul(scalar));
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msm_matches_naive() {
        let g = G1Point::generator();
        let bases = [g, g, g];
        let scalars = [
            Scalar::from_u64(2),
            Scalar::from_u64(3),
            Scalar::from_u64(5),
        ];
        let got = msm_g1(&bases, &scalars);
        let expect = g.mul(&Scalar::from_u64(10));
        assert_eq!(got.add(&expect.neg()).ct_is_identity(), 1);
    }
}
