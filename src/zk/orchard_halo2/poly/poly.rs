//! Implements poly/poly logic (`Rotation`, `Basis`, `Polynomial`).
//! `Polynomial<F>` is generic over coefficient type (`PallasFp`, `Assigned`);
//! basis is a runtime tag (Coeff/Lagrange/Extended). Chunked rotation helpers
//! return `Err` instead of `assert!`. Debug via `format!`.

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

use crate::zk::orchard_halo2::error::{Halo2Error, Halo2Result};
use crate::zk::orchard_halo2::field::PallasFp;
use crate::zk::orchard_halo2::plonk::assigned::Assigned;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Rotation {
    pub location: i32,
}

impl Rotation {
    pub const fn cur() -> Self {
        Self { location: 0 }
    }

    pub const fn prev() -> Self {
        Self { location: -1 }
    }

    pub const fn next() -> Self {
        Self { location: 1 }
    }

    pub fn is_current(&self) -> bool {
        self.location == 0
    }

    #[cfg(feature = "alloc")]
    pub fn to_debug_string(&self) -> String {
        alloc::format!("Rotation({})", self.location)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Basis {
    Coeff,
    Lagrange,
    Extended,
}

#[derive(Clone, PartialEq, Eq)]
pub struct Polynomial<F: Clone> {
    pub values: Vec<F>,
    pub basis: Basis,
}

impl<F: Clone> Polynomial<F> {
    pub fn new(values: Vec<F>, basis: Basis) -> Self {
        Self { values, basis }
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Chunked rotated access (`getChunkOfRotatedHelper`). Bounds → Err.
    pub fn chunk_of_rotated(
        &self,
        rotation_negative: bool,
        rotation_abs: usize,
        chunk_size: usize,
        chunk_index: usize,
    ) -> Halo2Result<Vec<F>> {
        let n = self.values.len();
        if chunk_size == 0 {
            return Err(Halo2Error::operation_failed(
                "chunk_of_rotated",
                "zero chunk",
            ));
        }
        let (mid, k) = if rotation_negative {
            if rotation_abs > n {
                return Err(Halo2Error::operation_failed(
                    "chunk_of_rotated",
                    "rotation too large",
                ));
            }
            (n - rotation_abs, rotation_abs)
        } else {
            if rotation_abs > n {
                return Err(Halo2Error::operation_failed(
                    "chunk_of_rotated",
                    "rotation too large",
                ));
            }
            (rotation_abs, n - rotation_abs)
        };
        let chunk_start = chunk_size
            .checked_mul(chunk_index)
            .ok_or_else(|| Halo2Error::operation_failed("chunk_of_rotated", "offset overflow"))?;
        let chunk_end = core::cmp::min(chunk_start.saturating_add(chunk_size), n);
        if chunk_start > n {
            return Err(Halo2Error::operation_failed(
                "chunk_of_rotated",
                "chunk out of range",
            ));
        }
        if chunk_end <= k {
            Ok(self.values[mid + chunk_start..mid + chunk_end].to_vec())
        } else if chunk_start >= k {
            Ok(self.values[chunk_start - k..chunk_end - k].to_vec())
        } else {
            let mut out: Vec<F> = Vec::new();
            out.extend_from_slice(&self.values[mid + chunk_start..]);
            out.extend_from_slice(&self.values[..chunk_end - k]);
            if out.len() > chunk_size {
                return Err(Halo2Error::operation_failed(
                    "chunk_of_rotated",
                    "chunk too large",
                ));
            }
            Ok(out)
        }
    }

    pub fn chunk_of_rotation(
        &self,
        rotation: Rotation,
        chunk_size: usize,
        chunk_index: usize,
    ) -> Halo2Result<Vec<F>> {
        self.chunk_of_rotated(
            rotation.location < 0,
            rotation.location.unsigned_abs() as usize,
            chunk_size,
            chunk_index,
        )
    }
}

impl Polynomial<PallasFp> {
    /// In-place scale (`operator *` mutates and returns self).
    pub fn scale_in_place(&mut self, rhs: PallasFp) {
        for v in self.values.iter_mut() {
            *v = v.mul_vartime(&rhs);
        }
    }

    /// In-place add (`operator +` mutates and returns self).
    pub fn add_in_place(&mut self, o: &Self) -> Halo2Result<()> {
        if self.values.len() != o.values.len() {
            return Err(Halo2Error::operation_failed("poly::add", "length mismatch"));
        }
        for (a, b) in self.values.iter_mut().zip(o.values.iter()) {
            *a = a.add_vartime(b);
        }
        Ok(())
    }

    #[cfg(feature = "alloc")]
    pub fn to_debug_string(&self) -> String {
        alloc::format!(
            "Polynomial(len: {}, basis: {:?})",
            self.values.len(),
            self.basis
        )
    }
}

impl Polynomial<Assigned> {
    /// `invert`: numerator * invDenom per element.
    pub fn invert_assigned(
        poly: &Polynomial<Assigned>,
        inv_denoms: &[PallasFp],
    ) -> Halo2Result<Polynomial<PallasFp>> {
        if poly.values.len() != inv_denoms.len() {
            return Err(Halo2Error::operation_failed(
                "poly::invert",
                "length mismatch",
            ));
        }
        let values = poly
            .values
            .iter()
            .zip(inv_denoms.iter())
            .map(|(a, d)| a.numerator().mul_vartime(d))
            .collect();
        Ok(Polynomial {
            values,
            basis: poly.basis,
        })
    }

    /// `batchInvertAssigned`: gather non-null denominators, batch invert,
    /// write back, apply. Uses one for trivial denominators.
    pub fn batch_invert_assigned(
        polys: &[Polynomial<Assigned>],
    ) -> Halo2Result<Vec<Polynomial<PallasFp>>> {
        let mut denoms: Vec<Vec<Option<PallasFp>>> = Vec::with_capacity(polys.len());
        for p in polys {
            denoms.push(p.values.iter().map(|v| v.denominator()).collect());
        }
        let mut to_invert: Vec<PallasFp> = Vec::new();
        for row in denoms.iter() {
            for d in row.iter().flatten() {
                to_invert.push(*d);
            }
        }
        crate::zk::orchard_halo2::utility::utils::batch_invert(&mut to_invert)?;
        let mut it = to_invert.into_iter();
        for row in denoms.iter_mut() {
            for d in row.iter_mut() {
                if d.is_some() {
                    *d = Some(it.next().ok_or_else(|| {
                        Halo2Error::operation_failed("poly::batch_invert", "missing inverse")
                    })?);
                }
            }
        }
        let one = PallasFp::one();
        let mut out = Vec::with_capacity(polys.len());
        for (p, row) in polys.iter().zip(denoms.iter()) {
            let invs: Vec<PallasFp> = row.iter().map(|d| d.unwrap_or(one)).collect();
            out.push(Self::invert_assigned(p, &invs)?);
        }
        Ok(out)
    }
}
