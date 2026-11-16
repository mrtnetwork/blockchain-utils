//! Implements plonk/vanishing logic (vanishing argument).
//! Randomness via explicit `FieldRng`. Bounds/`assert!` become `Err`.

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

use crate::zk::orchard_halo2::curve::VestaAffine;
use crate::zk::orchard_halo2::error::{Halo2Error, Halo2Result};
use crate::zk::orchard_halo2::field::PallasFp;
use crate::zk::orchard_halo2::plonk::key::PlonkVerifyingKey;
use crate::zk::orchard_halo2::poly::commitment::commitment::CommitmentReference;
use crate::zk::orchard_halo2::poly::commitment::msm::Msm;
use crate::zk::orchard_halo2::poly::domain::EvaluationDomain;
use crate::zk::orchard_halo2::poly::evaluator::{Ast, AstContextResult, Evaluator, ExtendedOps};
use crate::zk::orchard_halo2::poly::multiopen::{ProverQuery, VerifierQuery};
use crate::zk::orchard_halo2::poly::params::PolyParams;
use crate::zk::orchard_halo2::poly::poly::Polynomial;
use crate::zk::orchard_halo2::rng::BlindRng;
use crate::zk::orchard_halo2::transcript::transcript::{TranscriptReader, TranscriptWriter};
use crate::zk::orchard_halo2::utility::utils::eval_polynomial;

pub struct VanishingCommitted {
    pub random_poly: Polynomial<PallasFp>,
    pub random_blind: PallasFp,
}

impl VanishingCommitted {
    pub fn commit(
        params: &PolyParams,
        domain: &EvaluationDomain,
        transcript: &mut TranscriptWriter,
        rng: &mut dyn BlindRng,
    ) -> Halo2Result<Self> {
        let mut poly = domain.empty_coeff();
        for v in poly.values.iter_mut() {
            *v = rng.next_pallas();
        }
        let blind = rng.next_pallas();
        let c = params.commit(&poly, blind)?;
        transcript.write_point(&c.to_compressed()?)?;
        Ok(Self {
            random_poly: poly,
            random_blind: blind,
        })
    }

    #[allow(clippy::too_many_arguments)] // Gate API mirrors upstream halo2 circuit signatures; regrouping args would churn call sites.
    pub fn construct(
        &self,
        params: &PolyParams,
        domain: &EvaluationDomain,
        evaluator: &Evaluator,
        expressions: Vec<Ast>,
        y: PallasFp,
        transcript: &mut TranscriptWriter,
        rng: &mut dyn BlindRng,
        result: Option<AstContextResult>,
    ) -> Halo2Result<VanishingConstructed> {
        let ops = ExtendedOps;
        let _ = &ops;
        let mut h_poly = match result {
            None => {
                let ast = Ast::DistributePowers(expressions, y);
                evaluator.evaluate(&ast, domain)?
            }
            Some(r) => evaluator.combine(&r, domain)?,
        };
        h_poly = domain.divide_by_vanishing_poly(h_poly)?;
        let coeff_vals = domain.extended_to_coeff(h_poly)?;
        let coeff_poly = Polynomial::new(
            coeff_vals,
            crate::zk::orchard_halo2::poly::poly::Basis::Coeff,
        );
        let mut h_pieces: Vec<Polynomial<PallasFp>> = Vec::new();
        let mut i = 0usize;
        while i < coeff_poly.values.len() {
            let end = core::cmp::min(i + params.n, coeff_poly.values.len());
            let chunk = coeff_poly.values[i..end].to_vec();
            if chunk.len() != params.n {
                return Err(Halo2Error::operation_failed(
                    "vanishing::split",
                    "piece length",
                ));
            }
            h_pieces.push(domain.coeff_from_vec(chunk)?);
            i += params.n;
        }
        let mut h_blinds = Vec::with_capacity(h_pieces.len());
        let mut h_commitments = Vec::with_capacity(h_pieces.len());
        for piece in h_pieces.iter() {
            let b = rng.next_pallas();
            let c = params.commit(piece, b)?;
            let (x, y, ident) = c.to_affine_le()?;
            h_commitments.push(if ident {
                VestaAffine::identity()
            } else {
                VestaAffine::from_le_xy(x, y)?
            });
            h_blinds.push(b);
        }
        for c in h_commitments.iter() {
            transcript.write_point(&c.to_compressed()?)?;
        }

        Ok(VanishingConstructed {
            h_pieces,
            h_blinds,
            committed_random_poly: self.random_poly.clone(),
            committed_random_blind: self.random_blind,
        })
    }
}

pub struct VanishingConstructed {
    pub h_pieces: Vec<Polynomial<PallasFp>>,
    pub h_blinds: Vec<PallasFp>,
    pub committed_random_poly: Polynomial<PallasFp>,
    pub committed_random_blind: PallasFp,
}

impl VanishingConstructed {
    pub fn evaluate(
        &self,
        x: PallasFp,
        xn: PallasFp,
        domain: &EvaluationDomain,
        transcript: &mut TranscriptWriter,
    ) -> Halo2Result<VanishingEvaluated> {
        let mut h_poly = domain.empty_coeff();
        for piece in self.h_pieces.iter().rev() {
            h_poly.scale_in_place(xn);
            h_poly.add_in_place(piece)?;
        }
        let mut h_blind = PallasFp::zero();
        for b in self.h_blinds.iter().rev() {
            h_blind = h_blind.mul_vartime(&xn).add_vartime(b);
        }
        let random_eval = eval_polynomial(&self.committed_random_poly.values, x);
        transcript.write_scalar_le(&random_eval.to_le_bytes())?;
        Ok(VanishingEvaluated {
            h_poly,
            h_blind,
            random_poly: self.committed_random_poly.clone(),
            random_blind: self.committed_random_blind,
        })
    }
}

pub struct VanishingEvaluated {
    pub h_poly: Polynomial<PallasFp>,
    pub h_blind: PallasFp,
    pub random_poly: Polynomial<PallasFp>,
    pub random_blind: PallasFp,
}

impl VanishingEvaluated {
    pub fn open(&self, x: PallasFp) -> Vec<ProverQuery> {
        vec![
            ProverQuery {
                point: x,
                poly: self.h_poly.clone(),
                blind: self.h_blind,
            },
            ProverQuery {
                point: x,
                poly: self.random_poly.clone(),
                blind: self.random_blind,
            },
        ]
    }
}

pub struct VanishingReadCommitted {
    pub random_poly_commitment: VestaAffine,
}

impl VanishingReadCommitted {
    pub fn read_before_y(transcript: &mut TranscriptReader<'_>) -> Halo2Result<Self> {
        Ok(Self {
            random_poly_commitment: VestaAffine::from_compressed(&transcript.read_point()?)?,
        })
    }

    pub fn read_after_y(
        &self,
        vk: &PlonkVerifyingKey,
        transcript: &mut TranscriptReader<'_>,
    ) -> Halo2Result<VanishingReadConstructed> {
        let mut h_commitments = Vec::with_capacity(vk.domain.quotient_poly_degree);
        for _ in 0..vk.domain.quotient_poly_degree {
            h_commitments.push(VestaAffine::from_compressed(&transcript.read_point()?)?);
        }
        Ok(VanishingReadConstructed {
            h_commitments,
            random_poly_commitment: self.random_poly_commitment,
        })
    }
}

pub struct VanishingReadConstructed {
    pub h_commitments: Vec<VestaAffine>,
    pub random_poly_commitment: VestaAffine,
}

impl VanishingReadConstructed {
    pub fn evaluate_after_x(
        &self,
        transcript: &mut TranscriptReader<'_>,
    ) -> Halo2Result<VanishingPartiallyEvaluated> {
        Ok(VanishingPartiallyEvaluated {
            h_commitments: self.h_commitments.clone(),
            random_poly_commitment: self.random_poly_commitment,
            random_eval: PallasFp::from_le_array(&transcript.read_scalar_le()?)?,
        })
    }
}

pub struct VanishingPartiallyEvaluated {
    pub h_commitments: Vec<VestaAffine>,
    pub random_poly_commitment: VestaAffine,
    pub random_eval: PallasFp,
}

impl VanishingPartiallyEvaluated {
    pub fn verify<'a>(
        &self,
        params: &'a PolyParams,
        expressions: &[PallasFp],
        y: PallasFp,
        xn: PallasFp,
    ) -> Halo2Result<VanishingVerifyEvaluated<'a>> {
        let mut expected = PallasFp::zero();
        for v in expressions.iter() {
            expected = expected.mul_vartime(&y).add_vartime(v);
        }
        expected = expected.mul_vartime(&xn.sub_vartime(&PallasFp::one()).invert()?);
        let mut h_commitment = Msm::new(params);
        for c in self.h_commitments.iter().rev() {
            h_commitment.scale(xn);
            h_commitment.append_term(PallasFp::one(), c)?;
        }
        Ok(VanishingVerifyEvaluated {
            h_commitment,
            poly_commitment: self.random_poly_commitment,
            expected_h_eval: expected,
            random_eval: self.random_eval,
        })
    }
}

pub struct VanishingVerifyEvaluated<'a> {
    pub h_commitment: Msm<'a>,
    pub poly_commitment: VestaAffine,
    pub expected_h_eval: PallasFp,
    pub random_eval: PallasFp,
}

impl<'a> VanishingVerifyEvaluated<'a> {
    /// Consume into verifier queries (moves the MSM accumulator).
    pub fn into_queries(self, x: PallasFp) -> Vec<VerifierQuery<'a>> {
        vec![
            VerifierQuery {
                point: x,
                commitment: CommitmentReference::Msm(self.h_commitment),
                eval: self.expected_h_eval,
            },
            VerifierQuery {
                point: x,
                commitment: CommitmentReference::Commitment(self.poly_commitment),
                eval: self.random_eval,
            },
        ]
    }

    #[cfg(feature = "alloc")]
    pub fn to_debug_string(&self) -> String {
        alloc::string::String::from("VanishingVerifyEvaluated")
    }
}
