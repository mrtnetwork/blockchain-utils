//! Implements poly/evaluator logic (AST evaluation over chunks).
//! Basis is a runtime tag; chunk length mismatches are `Halo2Result`.
//! Debug via `format!`.

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

use crate::zk::orchard_halo2::error::{Halo2Error, Halo2Result};
use crate::zk::orchard_halo2::field::PallasFp;
use crate::zk::orchard_halo2::poly::domain::EvaluationDomain;
use crate::zk::orchard_halo2::poly::poly::{Basis, Polynomial, Rotation};

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AstLeaf {
    pub index: usize,
    pub rotation: Rotation,
}

impl AstLeaf {
    pub fn with_rotation(&self, rotation: Rotation) -> Self {
        Self {
            index: self.index,
            rotation,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum Ast {
    Poly(AstLeaf),
    Add(Box<Ast>, Box<Ast>),
    Mul(Box<Ast>, Box<Ast>),
    Scale(Box<Ast>, PallasFp),
    DistributePowers(Vec<Ast>, PallasFp),
    LinearTerm(PallasFp),
    ConstantTerm(PallasFp),
}

impl Ast {
    pub fn neg(&self) -> Self {
        Self::Scale(Box::new(self.clone()), PallasFp::one().neg())
    }

    pub fn add(&self, o: &Ast) -> Self {
        Self::Add(Box::new(self.clone()), Box::new(o.clone()))
    }

    pub fn add_leaf(&self, leaf: &AstLeaf) -> Self {
        self.add(&Ast::Poly(*leaf))
    }

    pub fn sub(&self, o: &Ast) -> Self {
        self.add(&o.neg())
    }

    pub fn mul(&self, o: &Ast) -> Self {
        Self::Mul(Box::new(self.clone()), Box::new(o.clone()))
    }

    pub fn mul_leaf(&self, leaf: &AstLeaf) -> Self {
        self.mul(&Ast::Poly(*leaf))
    }

    pub fn scale(&self, f: PallasFp) -> Self {
        Self::Scale(Box::new(self.clone()), f)
    }

    pub fn scale_fp(&self, f: PallasFp) -> Self {
        self.scale(f)
    }
}

pub struct AstContext<'a> {
    pub domain: &'a EvaluationDomain,
    pub poly_len: usize,
    pub chunk_size: usize,
    pub chunk_index: usize,
    pub num_threads: usize,
}

pub struct AstContextResult {
    pub poly_len: usize,
    pub chunk_size: usize,
    pub num_threads: usize,
    pub values: Vec<Vec<PallasFp>>,
}

pub trait BasisOps {
    fn empty_poly(&self, domain: &EvaluationDomain) -> Polynomial<PallasFp>;
    fn constant_term(
        &self,
        poly_len: usize,
        chunk_size: usize,
        chunk_index: usize,
        scalar: PallasFp,
    ) -> Vec<PallasFp>;
    fn linear_term(
        &self,
        domain: &EvaluationDomain,
        poly_len: usize,
        chunk_size: usize,
        chunk_index: usize,
        scalar: PallasFp,
    ) -> Vec<PallasFp>;
    fn chunk_of_rotated(
        &self,
        domain: &EvaluationDomain,
        chunk_size: usize,
        chunk_index: usize,
        poly: &Polynomial<PallasFp>,
        rotation: Rotation,
    ) -> Halo2Result<Vec<PallasFp>>;
}

pub struct CoeffOps;
pub struct LagrangeOps;
pub struct ExtendedOps;

fn clamp_chunk(poly_len: usize, chunk_size: usize, chunk_index: usize) -> usize {
    poly_len
        .saturating_sub(chunk_size.saturating_mul(chunk_index))
        .min(chunk_size)
}

fn pow_u64_field(base: PallasFp, mut e: u64) -> PallasFp {
    let mut acc = PallasFp::one();
    let mut b = base;
    while e > 0 {
        if (e & 1) == 1 {
            acc = acc.mul_vartime(&b);
        }
        b = b.square_vartime();
        e >>= 1;
    }
    acc
}

impl BasisOps for CoeffOps {
    fn empty_poly(&self, domain: &EvaluationDomain) -> Polynomial<PallasFp> {
        domain.empty_coeff()
    }

    fn constant_term(
        &self,
        poly_len: usize,
        chunk_size: usize,
        chunk_index: usize,
        scalar: PallasFp,
    ) -> Vec<PallasFp> {
        let size = clamp_chunk(poly_len, chunk_size, chunk_index);
        let mut chunk = vec![PallasFp::zero(); size];
        if chunk_index == 0 && !chunk.is_empty() {
            chunk[0] = scalar;
        }
        chunk
    }

    fn linear_term(
        &self,
        _domain: &EvaluationDomain,
        poly_len: usize,
        chunk_size: usize,
        chunk_index: usize,
        scalar: PallasFp,
    ) -> Vec<PallasFp> {
        let size = clamp_chunk(poly_len, chunk_size, chunk_index);
        let mut chunk = vec![PallasFp::zero(); size];
        if chunk_size == 1 && chunk_index == 1 && !chunk.is_empty() {
            chunk[0] = scalar;
        } else if chunk_index == 0 && chunk.len() > 1 {
            chunk[1] = scalar;
        }
        chunk
    }

    fn chunk_of_rotated(
        &self,
        _domain: &EvaluationDomain,
        _chunk_size: usize,
        _chunk_index: usize,
        _poly: &Polynomial<PallasFp>,
        _rotation: Rotation,
    ) -> Halo2Result<Vec<PallasFp>> {
        Err(Halo2Error::operation_failed(
            "evaluator::coeff_chunk",
            "unsupported",
        ))
    }
}

impl BasisOps for LagrangeOps {
    fn empty_poly(&self, domain: &EvaluationDomain) -> Polynomial<PallasFp> {
        domain.empty_lagrange()
    }

    fn constant_term(
        &self,
        poly_len: usize,
        chunk_size: usize,
        chunk_index: usize,
        scalar: PallasFp,
    ) -> Vec<PallasFp> {
        vec![scalar; clamp_chunk(poly_len, chunk_size, chunk_index)]
    }

    fn linear_term(
        &self,
        domain: &EvaluationDomain,
        poly_len: usize,
        chunk_size: usize,
        chunk_index: usize,
        scalar: PallasFp,
    ) -> Vec<PallasFp> {
        let omega = domain.omega;
        let start = chunk_size.saturating_mul(chunk_index);
        let size = clamp_chunk(poly_len, chunk_size, chunk_index);
        let mut acc = pow_u64_field(omega, start as u64).mul_vartime(&scalar);
        let mut out = Vec::with_capacity(size);
        for _ in 0..size {
            out.push(acc);
            acc = acc.mul_vartime(&omega);
        }
        out
    }

    fn chunk_of_rotated(
        &self,
        _domain: &EvaluationDomain,
        chunk_size: usize,
        chunk_index: usize,
        poly: &Polynomial<PallasFp>,
        rotation: Rotation,
    ) -> Halo2Result<Vec<PallasFp>> {
        poly.chunk_of_rotation(rotation, chunk_size, chunk_index)
    }
}

impl BasisOps for ExtendedOps {
    fn empty_poly(&self, domain: &EvaluationDomain) -> Polynomial<PallasFp> {
        domain.empty_extended()
    }

    fn constant_term(
        &self,
        poly_len: usize,
        chunk_size: usize,
        chunk_index: usize,
        scalar: PallasFp,
    ) -> Vec<PallasFp> {
        vec![scalar; clamp_chunk(poly_len, chunk_size, chunk_index)]
    }

    fn linear_term(
        &self,
        domain: &EvaluationDomain,
        poly_len: usize,
        chunk_size: usize,
        chunk_index: usize,
        scalar: PallasFp,
    ) -> Vec<PallasFp> {
        let omega = domain.extended_omega;
        let start = chunk_size.saturating_mul(chunk_index);
        let size = clamp_chunk(poly_len, chunk_size, chunk_index);
        let mut acc = pow_u64_field(omega, start as u64)
            .mul_vartime(&PallasFp::zeta())
            .mul_vartime(&scalar);
        let mut out = Vec::with_capacity(size);
        for _ in 0..size {
            out.push(acc);
            acc = acc.mul_vartime(&omega);
        }
        out
    }

    fn chunk_of_rotated(
        &self,
        domain: &EvaluationDomain,
        chunk_size: usize,
        chunk_index: usize,
        poly: &Polynomial<PallasFp>,
        rotation: Rotation,
    ) -> Halo2Result<Vec<PallasFp>> {
        domain.chunk_of_rotated_extended(poly, rotation, chunk_size, chunk_index)
    }
}

pub struct Evaluator {
    pub basis: Basis,
    pub polys: Vec<Polynomial<PallasFp>>,
}

impl Evaluator {
    pub fn new(basis: Basis) -> Self {
        Self {
            basis,
            polys: Vec::new(),
        }
    }

    pub fn register_poly(&mut self, poly: Polynomial<PallasFp>) -> AstLeaf {
        let index = self.polys.len();
        self.polys.push(poly);
        AstLeaf {
            index,
            rotation: Rotation::cur(),
        }
    }

    pub fn chunk_params(poly_len: usize, num_threads: usize) -> (usize, usize) {
        let threads = core::cmp::max(num_threads, 1);
        let num_chunks = threads.saturating_mul(4).max(1);
        let chunk_size = (poly_len + num_chunks - 1) / num_chunks.max(1);
        let chunk_size = chunk_size.max(1);
        let adjusted = poly_len.div_ceil(chunk_size);
        (chunk_size, adjusted.max(1))
    }

    fn ops(&self) -> Halo2Result<Ops<'_>> {
        match self.basis {
            Basis::Coeff => Ok(Ops::Coeff(CoeffOps)),
            Basis::Lagrange => Ok(Ops::Lagrange(LagrangeOps)),
            Basis::Extended => Ok(Ops::Extended(ExtendedOps)),
        }
    }

    pub fn evaluate(
        &self,
        ast: &Ast,
        domain: &EvaluationDomain,
    ) -> Halo2Result<Polynomial<PallasFp>> {
        if self.polys.is_empty() {
            return Err(Halo2Error::operation_failed(
                "evaluator::evaluate",
                "no polys",
            ));
        }
        let poly_len = self.polys[0].values.len();
        // Thread-scaled chunks (more workers => finer split); values identical.
        let (chunk_size, _) = Self::chunk_params(poly_len, crate::multicore::num_threads());
        let ops = self.ops()?;
        let mut result = ops.empty_poly(domain);
        let num_chunks = poly_len.div_ceil(chunk_size);
        // Parallel chunks for large evals (halo2 evaluates chunked too);
        // chunks are independent (disjoint rows), combine order fixed.
        if crate::multicore::num_threads() > 1 && poly_len >= 4096 {
            let results: alloc::vec::Vec<Halo2Result<()>> = crate::multicore::scope(|s| {
                let mut guards = alloc::vec::Vec::new();
                for (chunk_index, slot) in result.values.chunks_mut(chunk_size).enumerate() {
                    // Rebuild owned ops per worker (the shared `Ops` may borrow
                    // a `dyn BasisOps`, which is not `Send`).
                    let (ast, ctx_polys, domain, basis) = (ast, &self.polys, domain, self.basis);
                    guards.push(s.spawn(move || {
                        let ctx_ops = match basis {
                            Basis::Coeff => Ops::Coeff(CoeffOps),
                            Basis::Lagrange => Ops::Lagrange(LagrangeOps),
                            Basis::Extended => Ops::Extended(ExtendedOps),
                        };
                        let ctx = AstContext {
                            domain,
                            poly_len,
                            chunk_size,
                            chunk_index,
                            num_threads: 1,
                        };
                        let chunk = recurse(ast, &ctx, ctx_polys, &ctx_ops)?;
                        if chunk.len() != slot.len() {
                            return Err(Halo2Error::operation_failed(
                                "evaluator::evaluate",
                                "chunk length",
                            ));
                        }
                        slot.copy_from_slice(&chunk);
                        Ok(())
                    }));
                }
                guards
                    .into_iter()
                    .map(crate::multicore::Scope::join)
                    .collect()
            });
            for r in results.into_iter() {
                r?;
            }
            return Ok(result);
        }
        for chunk_index in 0..num_chunks {
            let ctx = AstContext {
                domain,
                poly_len,
                chunk_size,
                chunk_index,
                num_threads: 1,
            };
            let chunk = recurse(ast, &ctx, &self.polys, &ops)?;
            let start = chunk_index * chunk_size;
            for (i, v) in chunk.into_iter().enumerate() {
                let slot = result.values.get_mut(start + i).ok_or_else(|| {
                    Halo2Error::operation_failed("evaluator::evaluate", "chunk overflow")
                })?;
                *slot = v;
            }
        }
        Ok(result)
    }

    pub fn combine(
        &self,
        ctx: &AstContextResult,
        domain: &EvaluationDomain,
    ) -> Halo2Result<Polynomial<PallasFp>> {
        if self.polys.is_empty() {
            return Err(Halo2Error::operation_failed(
                "evaluator::combine",
                "no polys",
            ));
        }
        let ops = self.ops()?;
        let mut result = ops.empty_poly(domain);
        let num_chunks = (ctx.poly_len + ctx.chunk_size - 1) / ctx.chunk_size.max(1);
        for chunk_index in 0..num_chunks {
            let chunk = ctx.values.get(chunk_index).ok_or_else(|| {
                Halo2Error::operation_failed("evaluator::combine", "missing chunk")
            })?;
            let start = chunk_index * ctx.chunk_size;
            for (i, v) in chunk.iter().enumerate() {
                let slot = result.values.get_mut(start + i).ok_or_else(|| {
                    Halo2Error::operation_failed("evaluator::combine", "chunk overflow")
                })?;
                *slot = *v;
            }
        }
        Ok(result)
    }

    #[cfg(feature = "alloc")]
    pub fn to_debug_string(&self) -> String {
        alloc::format!(
            "Evaluator(polys: {}, basis: {:?})",
            self.polys.len(),
            self.basis
        )
    }
}

/// Operator-set tag for [`recurse`] (crate-internal).
pub(crate) enum Ops<'a> {
    Coeff(CoeffOps),
    Lagrange(LagrangeOps),
    Extended(ExtendedOps),
    #[allow(dead_code)]
    Borrowed(&'a dyn BasisOps),
}

impl<'a> Ops<'a> {
    fn empty_poly(&self, domain: &EvaluationDomain) -> Polynomial<PallasFp> {
        match self {
            Self::Coeff(o) => o.empty_poly(domain),
            Self::Lagrange(o) => o.empty_poly(domain),
            Self::Extended(o) => o.empty_poly(domain),
            Self::Borrowed(o) => o.empty_poly(domain),
        }
    }

    fn constant_term(
        &self,
        poly_len: usize,
        chunk_size: usize,
        chunk_index: usize,
        v: PallasFp,
    ) -> Vec<PallasFp> {
        match self {
            Self::Coeff(o) => o.constant_term(poly_len, chunk_size, chunk_index, v),
            Self::Lagrange(o) => o.constant_term(poly_len, chunk_size, chunk_index, v),
            Self::Extended(o) => o.constant_term(poly_len, chunk_size, chunk_index, v),
            Self::Borrowed(o) => o.constant_term(poly_len, chunk_size, chunk_index, v),
        }
    }

    fn linear_term(
        &self,
        domain: &EvaluationDomain,
        poly_len: usize,
        chunk_size: usize,
        chunk_index: usize,
        v: PallasFp,
    ) -> Vec<PallasFp> {
        match self {
            Self::Coeff(o) => o.linear_term(domain, poly_len, chunk_size, chunk_index, v),
            Self::Lagrange(o) => o.linear_term(domain, poly_len, chunk_size, chunk_index, v),
            Self::Extended(o) => o.linear_term(domain, poly_len, chunk_size, chunk_index, v),
            Self::Borrowed(o) => o.linear_term(domain, poly_len, chunk_size, chunk_index, v),
        }
    }

    fn chunk_of_rotated(
        &self,
        domain: &EvaluationDomain,
        chunk_size: usize,
        chunk_index: usize,
        poly: &Polynomial<PallasFp>,
        rotation: Rotation,
    ) -> Halo2Result<Vec<PallasFp>> {
        match self {
            Self::Coeff(o) => o.chunk_of_rotated(domain, chunk_size, chunk_index, poly, rotation),
            Self::Lagrange(o) => {
                o.chunk_of_rotated(domain, chunk_size, chunk_index, poly, rotation)
            }
            Self::Extended(o) => {
                o.chunk_of_rotated(domain, chunk_size, chunk_index, poly, rotation)
            }
            Self::Borrowed(o) => {
                o.chunk_of_rotated(domain, chunk_size, chunk_index, poly, rotation)
            }
        }
    }
}

/// Internal AST evaluator (`Ops` is intentionally crate-private).
pub(crate) fn recurse(
    node: &Ast,
    ctx: &AstContext<'_>,
    polys: &[Polynomial<PallasFp>],
    ops: &Ops<'_>,
) -> Halo2Result<Vec<PallasFp>> {
    match node {
        Ast::Poly(leaf) => {
            let poly = polys.get(leaf.index).ok_or_else(|| {
                Halo2Error::operation_failed("evaluator::recurse", "bad poly index")
            })?;
            ops.chunk_of_rotated(
                ctx.domain,
                ctx.chunk_size,
                ctx.chunk_index,
                poly,
                leaf.rotation,
            )
        }
        Ast::Add(a, b) => {
            let mut lhs = recurse(a, ctx, polys, ops)?;
            let rhs = recurse(b, ctx, polys, ops)?;
            if lhs.len() != rhs.len() {
                return Err(Halo2Error::operation_failed(
                    "evaluator::add",
                    "length mismatch",
                ));
            }
            for (x, y) in lhs.iter_mut().zip(rhs.iter()) {
                *x = x.add_vartime(y);
            }
            Ok(lhs)
        }
        Ast::Mul(a, b) => {
            let mut lhs = recurse(a, ctx, polys, ops)?;
            let rhs = recurse(b, ctx, polys, ops)?;
            if lhs.len() != rhs.len() {
                return Err(Halo2Error::operation_failed(
                    "evaluator::mul",
                    "length mismatch",
                ));
            }
            for (x, y) in lhs.iter_mut().zip(rhs.iter()) {
                *x = x.mul_vartime(y);
            }
            Ok(lhs)
        }
        Ast::Scale(a, f) => {
            let mut lhs = recurse(a, ctx, polys, ops)?;
            for x in lhs.iter_mut() {
                *x = x.mul_vartime(f);
            }
            Ok(lhs)
        }
        Ast::DistributePowers(terms, base) => {
            let mut acc = ops.constant_term(
                ctx.poly_len,
                ctx.chunk_size,
                ctx.chunk_index,
                PallasFp::zero(),
            );
            for t in terms.iter() {
                let tv = recurse(t, ctx, polys, ops)?;
                if tv.len() != acc.len() {
                    return Err(Halo2Error::operation_failed(
                        "evaluator::dist",
                        "length mismatch",
                    ));
                }
                for (x, y) in acc.iter_mut().zip(tv.iter()) {
                    *x = x.mul_vartime(base).add_vartime(y);
                }
            }
            Ok(acc)
        }
        Ast::LinearTerm(c) => Ok(ops.linear_term(
            ctx.domain,
            ctx.poly_len,
            ctx.chunk_size,
            ctx.chunk_index,
            *c,
        )),
        Ast::ConstantTerm(v) => {
            Ok(ops.constant_term(ctx.poly_len, ctx.chunk_size, ctx.chunk_index, *v))
        }
    }
}
