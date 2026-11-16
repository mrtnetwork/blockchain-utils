//! Implements orchard/configs/add logic (`OrchardAddConfig`: a+b=c).

#[cfg(feature = "alloc")]
use alloc::string::String;
// `Vec` is prelude under `std`; import from `alloc` only for `no_std`.
#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::vec::Vec;

use crate::zk::orchard_halo2::error::Halo2Result;
use crate::zk::orchard_halo2::field::PallasFp;
use crate::zk::orchard_halo2::plonk::column::{AssignmentColumn, Selector};
use crate::zk::orchard_halo2::plonk::constraint::{ConstraintSystem, Constraints, VirtualCells};
use crate::zk::orchard_halo2::poly::poly::Rotation;
use crate::zk::orchard_halo2::utility::layouter::{AssignedCell, Layouter, Region};

#[derive(Clone, Copy)]
pub struct OrchardAddConfig {
    pub a: AssignmentColumn,
    pub b: AssignmentColumn,
    pub c: AssignmentColumn,
    pub q_add: Selector,
}

impl OrchardAddConfig {
    pub fn configure(
        a: AssignmentColumn,
        b: AssignmentColumn,
        c: AssignmentColumn,
        meta: &mut ConstraintSystem,
    ) -> Halo2Result<Self> {
        let q_add = meta.selector();
        meta.create_gate(&mut |meta: &mut VirtualCells<'_>| {
            let q = meta.query_selector(q_add);
            let ea = meta.query_advice(a, Rotation::cur());
            let eb = meta.query_advice(b, Rotation::cur());
            let ec = meta.query_advice(c, Rotation::cur());
            Ok(Constraints {
                selector: Some(q),
                constraints: vec![ea.try_add(&eb)?.try_sub(&ec)?],
            })
        })?;
        Ok(Self { a, b, c, q_add })
    }

    pub fn add<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        a: &AssignedCell<PallasFp>,
        b: &AssignedCell<PallasFp>,
    ) -> Halo2Result<AssignedCell<PallasFp>> {
        layouter.assign_region(&mut |region: &mut Region<'_>| {
            self.q_add.enable(region, 0)?;
            a.copy_advice(region, self.a, 0)?;
            b.copy_advice(region, self.b, 0)?;
            let scalar: Option<PallasFp> = match (a.value, b.value) {
                (Some(x), Some(y)) => Some(x.add_vartime(&y)),
                _ => None,
            };
            region.assign_advice(self.c, 0, &mut || scalar)
        })
    }

    #[cfg(feature = "alloc")]
    pub fn to_debug_string(&self) -> String {
        alloc::string::String::from("OrchardAddConfig")
    }
}
