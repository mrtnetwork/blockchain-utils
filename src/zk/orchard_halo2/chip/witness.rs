//! Implements chip/witness logic (witness-point gates).
//! Curve equation `y² = x³ + 5` over Pallas. Points cross as `PallasAffine`
//! (LE); identity allowed only under `q_point`.

#[cfg(feature = "alloc")]
use alloc::string::String;
// `Vec` is prelude under `std`; import from `alloc` only for `no_std`.
#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::vec::Vec;

use crate::zk::orchard_halo2::chip::ecc::EccPoint;
use crate::zk::orchard_halo2::curve::PallasAffine;
use crate::zk::orchard_halo2::error::{Halo2Error, Halo2Result};
use crate::zk::orchard_halo2::field::PallasFp;
use crate::zk::orchard_halo2::plonk::assigned::Assigned;
use crate::zk::orchard_halo2::plonk::column::AssignmentColumn;
use crate::zk::orchard_halo2::plonk::column::Selector;
use crate::zk::orchard_halo2::plonk::constraint::{ConstraintSystem, Constraints, VirtualCells};
use crate::zk::orchard_halo2::plonk::expression::Expression;
use crate::zk::orchard_halo2::poly::poly::Rotation;
use crate::zk::orchard_halo2::utility::layouter::{AssignedCell, Region};

#[derive(Clone, Copy)]
pub struct WitnessPointConfig {
    pub q_point: Selector,
    pub q_point_non_id: Selector,
    pub x: AssignmentColumn,
    pub y: AssignmentColumn,
}

impl WitnessPointConfig {
    pub fn configure(
        meta: &mut ConstraintSystem,
        x: AssignmentColumn,
        y: AssignmentColumn,
    ) -> Halo2Result<Self> {
        let config = Self {
            q_point: meta.selector(),
            q_point_non_id: meta.selector(),
            x,
            y,
        };
        config.create_gate(meta)?;
        Ok(config)
    }

    fn curve_eqn(
        meta: &mut VirtualCells<'_>,
        x_col: AssignmentColumn,
        y_col: AssignmentColumn,
    ) -> Halo2Result<Expression> {
        let x = meta.query_advice(x_col, Rotation::cur());
        let y = meta.query_advice(y_col, Rotation::cur());
        let b = Expression::constant(PallasFp::from_u64(5));
        y.square()?
            .try_sub(&x.square()?.try_mul_expr(&x)?)?
            .try_sub(&b)
    }

    fn create_gate(&self, meta: &mut ConstraintSystem) -> Halo2Result<()> {
        let (x, y) = (self.x, self.y);
        meta.create_gate(&mut |meta: &mut VirtualCells<'_>| {
            let q = meta.query_selector(self.q_point);
            let xe = meta.query_advice(x, Rotation::cur());
            let ye = meta.query_advice(y, Rotation::cur());
            let eqn = Self::curve_eqn(meta, x, y)?;
            Ok(Constraints {
                selector: None,
                constraints: vec![
                    q.try_mul_expr(&xe)?.try_mul_expr(&eqn)?,
                    q.try_mul_expr(&ye)?.try_mul_expr(&eqn)?,
                ],
            })
        })?;
        meta.create_gate(&mut |meta: &mut VirtualCells<'_>| {
            let q = meta.query_selector(self.q_point_non_id);
            let eqn = Self::curve_eqn(meta, x, y)?;
            Ok(Constraints {
                selector: Some(q),
                constraints: vec![eqn],
            })
        })
    }

    fn assign_xy(
        &self,
        value: Option<(Assigned, Assigned)>,
        offset: usize,
        region: &mut Region<'_>,
    ) -> Halo2Result<(AssignedCell<Assigned>, AssignedCell<Assigned>)> {
        let (vx, vy) = match value {
            Some((a, b)) => (Some(a), Some(b)),
            None => (None, None),
        };
        let x_cell = region.assign_advice(self.x, offset, &mut || vx)?;
        let y_cell = region.assign_advice(self.y, offset, &mut || vy)?;
        Ok((x_cell, y_cell))
    }

    fn assigned_of(aff: &PallasAffine) -> Halo2Result<(Assigned, Assigned)> {
        let (xb, yb, _) = aff.to_affine_le()?;
        Ok((
            Assigned::Trivial(PallasFp::from_le_array(&xb)?),
            Assigned::Trivial(PallasFp::from_le_array(&yb)?),
        ))
    }

    pub fn point(
        &self,
        value: Option<PallasAffine>,
        offset: usize,
        region: &mut Region<'_>,
    ) -> Halo2Result<EccPoint> {
        self.q_point.enable(region, offset)?;
        let v = match value {
            None => None,
            Some(a) => {
                if a.is_identity() {
                    Some((Assigned::Zero, Assigned::Zero))
                } else {
                    Some(Self::assigned_of(&a)?)
                }
            }
        };
        let (x, y) = self.assign_xy(v, offset, region)?;
        Ok(EccPoint { x, y })
    }

    pub fn point_non_id(
        &self,
        value: Option<PallasAffine>,
        offset: usize,
        region: &mut Region<'_>,
    ) -> Halo2Result<EccPoint> {
        self.q_point_non_id.enable(region, offset)?;
        if let Some(a) = &value {
            if a.is_identity() {
                return Err(Halo2Error::operation_failed(
                    "witness::non_id",
                    "identity point",
                ));
            }
        }
        let v = match value {
            Some(a) => Some(Self::assigned_of(&a)?),
            None => None,
        };
        let (x, y) = self.assign_xy(v, offset, region)?;
        Ok(EccPoint { x, y })
    }

    pub fn constant_point(
        &self,
        value: PallasAffine,
        offset: usize,
        region: &mut Region<'_>,
    ) -> Halo2Result<EccPoint> {
        self.q_point.enable(region, offset)?;
        let v = if value.is_identity() {
            (Assigned::Zero, Assigned::Zero)
        } else {
            Self::assigned_of(&value)?
        };
        let (x, y) = self.assign_xy(Some(v), offset, region)?;
        Ok(EccPoint { x, y })
    }

    #[cfg(feature = "alloc")]
    pub fn to_debug_string(&self) -> String {
        alloc::string::String::from("WitnessPointConfig")
    }
}
