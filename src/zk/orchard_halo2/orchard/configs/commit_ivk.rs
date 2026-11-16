//! Implements orchard/configs/commit_ivk logic (CommitIvk canonicity).

#[cfg(feature = "alloc")]
use alloc::string::String;
// `Vec` is prelude under `std`; import from `alloc` only for `no_std`.
#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::vec::Vec;

use crate::zk::orchard_halo2::error::Halo2Result;
use crate::zk::orchard_halo2::field::{PallasFp, T_P_LE};
use crate::zk::orchard_halo2::plonk::column::{AssignmentColumn, Selector};
use crate::zk::orchard_halo2::plonk::constraint::{ConstraintSystem, Constraints, VirtualCells};
use crate::zk::orchard_halo2::plonk::expression::Expression;
use crate::zk::orchard_halo2::poly::poly::Rotation;
use crate::zk::orchard_halo2::utility::layouter::{AssignedCell, Layouter, Region};
use crate::zk::orchard_halo2::utility::range_constrained::RangeConstrained;
use crate::zk::orchard_halo2::utility::utils::bool_check_expr;

#[derive(Clone)]
pub struct GateCells {
    pub a: AssignedCell<PallasFp>,
    pub b: AssignedCell<PallasFp>,
    pub c: AssignedCell<PallasFp>,
    pub d: AssignedCell<PallasFp>,
    pub ak: AssignedCell<PallasFp>,
    pub nk: AssignedCell<PallasFp>,
    pub b0: RangeConstrained<AssignedCell<PallasFp>>,
    pub b1: RangeConstrained<Option<PallasFp>>,
    pub b2: RangeConstrained<AssignedCell<PallasFp>>,
    pub d0: RangeConstrained<AssignedCell<PallasFp>>,
    pub d1: RangeConstrained<Option<PallasFp>>,
    pub z13_a: AssignedCell<PallasFp>,
    pub a_prime: AssignedCell<PallasFp>,
    pub z13_a_prime: AssignedCell<PallasFp>,
    pub z13_c: AssignedCell<PallasFp>,
    pub b2_c_prime: AssignedCell<PallasFp>,
    pub z14_b2_c_prime: AssignedCell<PallasFp>,
}

#[derive(Clone, Copy)]
pub struct CommitIvkConfig {
    pub q_commit_ivk: Selector,
    pub advices: [AssignmentColumn; 9],
}

impl CommitIvkConfig {
    pub fn configure(
        meta: &mut ConstraintSystem,
        advices: [AssignmentColumn; 9],
    ) -> Halo2Result<Self> {
        let q_commit_ivk = meta.selector();
        let config = Self {
            q_commit_ivk,
            advices,
        };
        meta.create_gate(&mut |meta: &mut VirtualCells<'_>| {
            let q = meta.query_selector(config.q_commit_ivk);
            let two_pow_4 = PallasFp::from_u64(1u64 << 4);
            let two_pow_5 = PallasFp::from_u64(1u64 << 5);
            let two_pow_9 = two_pow_4.mul_vartime(&two_pow_5);
            let two_pow_250 = PallasFp::from_u64(2).pow_u64(250);
            let two_pow_254 = PallasFp::from_u64(2).pow_u64(254);

            let ak = meta.query_advice(config.advices[0], Rotation::cur());
            let nk = meta.query_advice(config.advices[0], Rotation::next());
            let a = meta.query_advice(config.advices[1], Rotation::cur());
            let b_whole = meta.query_advice(config.advices[2], Rotation::cur());
            let c = meta.query_advice(config.advices[1], Rotation::next());
            let d_whole = meta.query_advice(config.advices[2], Rotation::next());

            let b0 = meta.query_advice(config.advices[3], Rotation::cur());
            let b1 = meta.query_advice(config.advices[4], Rotation::cur());
            let b2 = meta.query_advice(config.advices[5], Rotation::cur());
            let b_decomp = b_whole.try_sub(
                &b0.try_add(&b1.scale(two_pow_4))?
                    .try_add(&b2.scale(two_pow_5))?,
            )?;

            let d0 = meta.query_advice(config.advices[3], Rotation::next());
            let d1 = meta.query_advice(config.advices[4], Rotation::next());
            let d_decomp = d_whole.try_sub(&d0.try_add(&d1.scale(two_pow_9))?)?;

            let b1_bool = bool_check_expr(b1.clone())?;
            let d1_bool = bool_check_expr(d1.clone())?;

            let ak_decomp = a
                .try_add(&b0.scale(two_pow_250))?
                .try_add(&b1.scale(two_pow_254))?
                .try_sub(&ak)?;

            let two_pow_245 = PallasFp::from_u64(2).pow_u64(245);
            let nk_decomp = b2
                .try_add(&c.scale(two_pow_5))?
                .try_add(&d0.scale(two_pow_245))?
                .try_add(&d1.scale(two_pow_254))?
                .try_sub(&nk)?;

            let z13_a = meta.query_advice(config.advices[6], Rotation::cur());
            let a_prime = meta.query_advice(config.advices[7], Rotation::cur());
            let z13_a_prime = meta.query_advice(config.advices[8], Rotation::cur());
            let two_pow_130 = Expression::constant(PallasFp::from_u64(2).pow_u64(130));
            let t_p = Expression::constant(PallasFp::from_le_array(&T_P_LE)?);
            let b0_canon = b1.try_mul_expr(&b0)?;
            let z13a_check = b1.try_mul_expr(&z13_a)?;
            let a_prime_check = a.try_add(&two_pow_130)?.try_sub(&t_p)?.try_sub(&a_prime)?;
            let z13a_prime_check = b1.try_mul_expr(&z13_a_prime)?;

            let z13_c = meta.query_advice(config.advices[6], Rotation::next());
            let b2_c_prime = meta.query_advice(config.advices[7], Rotation::next());
            let z14 = meta.query_advice(config.advices[8], Rotation::next());
            let two_pow_140 = Expression::constant(PallasFp::from_u64(2).pow_u64(140));
            let c0_canon = d1.try_mul_expr(&d0)?;
            let z13c_check = d1.try_mul_expr(&z13_c)?;
            let b2c_check = b2
                .try_add(&c.scale(two_pow_5))?
                .try_add(&two_pow_140)?
                .try_sub(&t_p)?
                .try_sub(&b2_c_prime)?;
            let z14_check = d1.try_mul_expr(&z14)?;

            Ok(Constraints {
                selector: Some(q),
                constraints: vec![
                    b1_bool,
                    d1_bool,
                    b_decomp,
                    d_decomp,
                    ak_decomp,
                    nk_decomp,
                    b0_canon,
                    z13a_check,
                    a_prime_check,
                    z13a_prime_check,
                    c0_canon,
                    z13c_check,
                    b2c_check,
                    z14_check,
                ],
            })
        })?;
        Ok(config)
    }

    pub fn assign_gate<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        cells: &GateCells,
    ) -> Halo2Result<()> {
        layouter.assign_region(&mut |region: &mut Region<'_>| {
            self.q_commit_ivk.enable(region, 0)?;
            cells.ak.copy_advice(region, self.advices[0], 0)?;
            cells.a.copy_advice(region, self.advices[1], 0)?;
            cells.b.copy_advice(region, self.advices[2], 0)?;
            cells.b0.inner.copy_advice(region, self.advices[3], 0)?;
            region.assign_advice(self.advices[4], 0, &mut || cells.b1.inner)?;
            cells.b2.inner.copy_advice(region, self.advices[5], 0)?;
            cells.z13_a.copy_advice(region, self.advices[6], 0)?;
            cells.a_prime.copy_advice(region, self.advices[7], 0)?;
            cells.z13_a_prime.copy_advice(region, self.advices[8], 0)?;
            cells.nk.copy_advice(region, self.advices[0], 1)?;
            cells.c.copy_advice(region, self.advices[1], 1)?;
            cells.d.copy_advice(region, self.advices[2], 1)?;
            cells.d0.inner.copy_advice(region, self.advices[3], 1)?;
            region.assign_advice(self.advices[4], 1, &mut || cells.d1.inner)?;
            cells.z13_c.copy_advice(region, self.advices[6], 1)?;
            cells.b2_c_prime.copy_advice(region, self.advices[7], 1)?;
            cells
                .z14_b2_c_prime
                .copy_advice(region, self.advices[8], 1)?;
            Ok(())
        })
    }

    #[cfg(feature = "alloc")]
    pub fn to_debug_string(&self) -> String {
        alloc::string::String::from("CommitIvkConfig")
    }
}
