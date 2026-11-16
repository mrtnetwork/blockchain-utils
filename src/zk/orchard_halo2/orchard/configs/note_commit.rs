//! Implements orchard/configs/note_commit logic (note-commit gates).
//! All `assert!` on lengths become `Err`; `invert()!` propagates.

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

use crate::zk::orchard_halo2::chip::ecc::EccPoint;
use crate::zk::orchard_halo2::chip::lookup::LookupRangeCheckConfig;
use crate::zk::orchard_halo2::error::Halo2Result;
use crate::zk::orchard_halo2::field::{PallasFp, T_P_LE};
use crate::zk::orchard_halo2::plonk::column::{AssignmentColumn, Selector};
use crate::zk::orchard_halo2::plonk::constraint::{ConstraintSystem, Constraints, VirtualCells};
use crate::zk::orchard_halo2::plonk::expression::Expression;
use crate::zk::orchard_halo2::poly::poly::Rotation;
use crate::zk::orchard_halo2::sinsemilla::merkle::SinsemillaConfig;
use crate::zk::orchard_halo2::sinsemilla::message::SinsemillaMessagePiece;
use crate::zk::orchard_halo2::utility::layouter::{AssignedCell, Layouter, Region};
use crate::zk::orchard_halo2::utility::range_constrained::RangeConstrained;
use crate::zk::orchard_halo2::utility::utils::bool_check_expr;

// Note-commitment subpiece bundles: (message piece, range checks).
type DecomposeBParts = (
    SinsemillaMessagePiece,
    RangeConstrained<AssignedCell<PallasFp>>,
    RangeConstrained<Option<PallasFp>>,
    RangeConstrained<Option<PallasFp>>,
    RangeConstrained<AssignedCell<PallasFp>>,
);
type DecomposeDParts = (
    SinsemillaMessagePiece,
    RangeConstrained<Option<PallasFp>>,
    RangeConstrained<Option<PallasFp>>,
    RangeConstrained<AssignedCell<PallasFp>>,
);
type DecomposeEParts = (
    SinsemillaMessagePiece,
    RangeConstrained<AssignedCell<PallasFp>>,
    RangeConstrained<AssignedCell<PallasFp>>,
);
type DecomposeGParts = (
    SinsemillaMessagePiece,
    RangeConstrained<Option<PallasFp>>,
    RangeConstrained<AssignedCell<PallasFp>>,
);
type DecomposeHParts = (
    SinsemillaMessagePiece,
    RangeConstrained<AssignedCell<PallasFp>>,
    RangeConstrained<Option<PallasFp>>,
);

fn pow2(e: u32) -> PallasFp {
    PallasFp::from_u64(2).pow_u64(e as u64)
}

// —— DecomposeB ——

#[derive(Clone, Copy)]
pub struct DecomposeB {
    pub q: Selector,
    pub col_l: AssignmentColumn,
    pub col_m: AssignmentColumn,
    pub col_r: AssignmentColumn,
}

impl DecomposeB {
    pub fn configure(
        meta: &mut ConstraintSystem,
        col_l: AssignmentColumn,
        col_m: AssignmentColumn,
        col_r: AssignmentColumn,
        two_pow_4: PallasFp,
        two_pow_5: PallasFp,
        two_pow_6: PallasFp,
    ) -> Halo2Result<Self> {
        let q = meta.selector();
        meta.create_gate(&mut |meta: &mut VirtualCells<'_>| {
            let qs = meta.query_selector(q);
            let b = meta.query_advice(col_l, Rotation::cur());
            let b0 = meta.query_advice(col_m, Rotation::cur());
            let b1 = meta.query_advice(col_r, Rotation::cur());
            let b2 = meta.query_advice(col_m, Rotation::next());
            let b3 = meta.query_advice(col_r, Rotation::next());
            let decomp = b.try_sub(
                &b0.try_add(&b1.scale(two_pow_4))?
                    .try_add(&b2.scale(two_pow_5))?
                    .try_add(&b3.scale(two_pow_6))?,
            )?;
            Ok(Constraints {
                selector: Some(qs),
                constraints: vec![bool_check_expr(b1)?, bool_check_expr(b2)?, decomp],
            })
        })?;
        Ok(Self {
            q,
            col_l,
            col_m,
            col_r,
        })
    }

    pub fn decompose<L: Layouter + ?Sized>(
        &self,
        lookup: &LookupRangeCheckConfig,
        chip: &SinsemillaConfig,
        layouter: &mut L,
        g_d: &EccPoint,
        pk_d: &EccPoint,
    ) -> Halo2Result<DecomposeBParts> {
        let gd_x = g_d.get_x();
        let gd_y = g_d.get_y();
        let b0 = lookup.witness_short(layouter, gd_x.value, 250, 254)?;
        let b1 = RangeConstrained::bitrange_of(gd_x.value, 254, 255);
        let b2 = RangeConstrained::bitrange_of(gd_y.value, 0, 1);
        let b3 = lookup.witness_short(layouter, pk_d.get_x().value, 0, 4)?;
        let b = SinsemillaMessagePiece::from_subpieces(
            chip,
            layouter,
            vec![b0.value(), b1.clone(), b2.clone(), b3.value()],
        )?;
        Ok((b, b0, b1, b2, b3))
    }

    pub fn assign<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        b: &SinsemillaMessagePiece,
        b0: &RangeConstrained<AssignedCell<PallasFp>>,
        b1: &RangeConstrained<Option<PallasFp>>,
        b2: &RangeConstrained<AssignedCell<PallasFp>>,
        b3: &RangeConstrained<AssignedCell<PallasFp>>,
    ) -> Halo2Result<AssignedCell<PallasFp>> {
        layouter.assign_region(&mut |region: &mut Region<'_>| {
            self.q.enable(region, 0)?;
            b.cell_value.copy_advice(region, self.col_l, 0)?;
            b0.inner.copy_advice(region, self.col_m, 0)?;
            let assigned_b1 = region.assign_advice(self.col_r, 0, &mut || b1.inner)?;
            b2.inner.copy_advice(region, self.col_m, 1)?;
            b3.inner.copy_advice(region, self.col_r, 1)?;
            Ok(assigned_b1)
        })
    }
}

// —— DecomposeD ——

#[derive(Clone, Copy)]
pub struct DecomposeD {
    pub q: Selector,
    pub col_l: AssignmentColumn,
    pub col_m: AssignmentColumn,
    pub col_r: AssignmentColumn,
}

impl DecomposeD {
    pub fn configure(
        meta: &mut ConstraintSystem,
        col_l: AssignmentColumn,
        col_m: AssignmentColumn,
        col_r: AssignmentColumn,
        two: PallasFp,
        two_pow_2: PallasFp,
        two_pow_10: PallasFp,
    ) -> Halo2Result<Self> {
        let q = meta.selector();
        meta.create_gate(&mut |meta: &mut VirtualCells<'_>| {
            let qs = meta.query_selector(q);
            let d = meta.query_advice(col_l, Rotation::cur());
            let d0 = meta.query_advice(col_m, Rotation::cur());
            let d1 = meta.query_advice(col_r, Rotation::cur());
            let d2 = meta.query_advice(col_m, Rotation::next());
            let d3 = meta.query_advice(col_r, Rotation::next());
            let decomp = d.try_sub(
                &d0.try_add(&d1.scale(two))?
                    .try_add(&d2.scale(two_pow_2))?
                    .try_add(&d3.scale(two_pow_10))?,
            )?;
            Ok(Constraints {
                selector: Some(qs),
                constraints: vec![bool_check_expr(d0)?, bool_check_expr(d1)?, decomp],
            })
        })?;
        Ok(Self {
            q,
            col_l,
            col_m,
            col_r,
        })
    }

    pub fn decompose<L: Layouter + ?Sized>(
        &self,
        lookup: &LookupRangeCheckConfig,
        chip: &SinsemillaConfig,
        layouter: &mut L,
        pk_d: &EccPoint,
        value: &AssignedCell<PallasFp>,
    ) -> Halo2Result<DecomposeDParts> {
        let d0 = RangeConstrained::bitrange_of(pk_d.get_x().value, 254, 255);
        let d1 = RangeConstrained::bitrange_of(pk_d.get_y().value, 0, 1);
        let d2 = lookup.witness_short(layouter, value.value, 0, 8)?;
        let d3 = RangeConstrained::bitrange_of(value.value, 8, 58);
        let d = SinsemillaMessagePiece::from_subpieces(
            chip,
            layouter,
            vec![d0.clone(), d1.clone(), d2.value(), d3],
        )?;
        Ok((d, d0, d1, d2))
    }

    pub fn assign<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        d: &SinsemillaMessagePiece,
        d0: &RangeConstrained<Option<PallasFp>>,
        d1: &RangeConstrained<AssignedCell<PallasFp>>,
        d2: &RangeConstrained<AssignedCell<PallasFp>>,
        z1_d: &AssignedCell<PallasFp>,
    ) -> Halo2Result<AssignedCell<PallasFp>> {
        layouter.assign_region(&mut |region: &mut Region<'_>| {
            self.q.enable(region, 0)?;
            d.cell_value.copy_advice(region, self.col_l, 0)?;
            let d0a = region.assign_advice(self.col_m, 0, &mut || d0.inner)?;
            d1.inner.copy_advice(region, self.col_r, 0)?;
            d2.inner.copy_advice(region, self.col_m, 1)?;
            z1_d.copy_advice(region, self.col_r, 1)?;
            Ok(d0a)
        })
    }
}

// —— DecomposeE ——

#[derive(Clone, Copy)]
pub struct DecomposeE {
    pub q: Selector,
    pub col_l: AssignmentColumn,
    pub col_m: AssignmentColumn,
    pub col_r: AssignmentColumn,
}

impl DecomposeE {
    pub fn configure(
        meta: &mut ConstraintSystem,
        col_l: AssignmentColumn,
        col_m: AssignmentColumn,
        col_r: AssignmentColumn,
        two_pow_6: PallasFp,
    ) -> Halo2Result<Self> {
        let q = meta.selector();
        meta.create_gate(&mut |meta: &mut VirtualCells<'_>| {
            let qs = meta.query_selector(q);
            let e = meta.query_advice(col_l, Rotation::cur());
            let e0 = meta.query_advice(col_m, Rotation::cur());
            let e1 = meta.query_advice(col_r, Rotation::cur());
            let decomp = e.try_sub(&e0.try_add(&e1.scale(two_pow_6))?)?;
            Ok(Constraints {
                selector: Some(qs),
                constraints: vec![decomp],
            })
        })?;
        Ok(Self {
            q,
            col_l,
            col_m,
            col_r,
        })
    }

    pub fn decompose<L: Layouter + ?Sized>(
        &self,
        lookup: &LookupRangeCheckConfig,
        chip: &SinsemillaConfig,
        layouter: &mut L,
        value: &AssignedCell<PallasFp>,
        rho: &AssignedCell<PallasFp>,
    ) -> Halo2Result<DecomposeEParts> {
        let e0 = lookup.witness_short(layouter, value.value, 58, 64)?;
        let e1 = lookup.witness_short(layouter, rho.value, 0, 4)?;
        let e =
            SinsemillaMessagePiece::from_subpieces(chip, layouter, vec![e0.value(), e1.value()])?;
        Ok((e, e0, e1))
    }

    pub fn assign<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        e: &SinsemillaMessagePiece,
        e0: &RangeConstrained<AssignedCell<PallasFp>>,
        e1: &RangeConstrained<AssignedCell<PallasFp>>,
    ) -> Halo2Result<()> {
        layouter.assign_region(&mut |region: &mut Region<'_>| {
            self.q.enable(region, 0)?;
            e.cell_value.copy_advice(region, self.col_l, 0)?;
            e0.inner.copy_advice(region, self.col_m, 0)?;
            e1.inner.copy_advice(region, self.col_r, 0)?;
            Ok(())
        })
    }
}

// —— DecomposeG ——

#[derive(Clone, Copy)]
pub struct DecomposeG {
    pub q: Selector,
    pub col_l: AssignmentColumn,
    pub col_m: AssignmentColumn,
}

impl DecomposeG {
    pub fn configure(
        meta: &mut ConstraintSystem,
        col_l: AssignmentColumn,
        col_m: AssignmentColumn,
        two: PallasFp,
        two_pow_10: PallasFp,
    ) -> Halo2Result<Self> {
        let q = meta.selector();
        meta.create_gate(&mut |meta: &mut VirtualCells<'_>| {
            let qs = meta.query_selector(q);
            let g = meta.query_advice(col_l, Rotation::cur());
            let g0 = meta.query_advice(col_m, Rotation::cur());
            let g1 = meta.query_advice(col_l, Rotation::next());
            let g2 = meta.query_advice(col_m, Rotation::next());
            let decomp = g.try_sub(&g0.try_add(&g1.scale(two))?.try_add(&g2.scale(two_pow_10))?)?;
            Ok(Constraints {
                selector: Some(qs),
                constraints: vec![bool_check_expr(g0)?, decomp],
            })
        })?;
        Ok(Self { q, col_l, col_m })
    }

    pub fn decompose<L: Layouter + ?Sized>(
        &self,
        lookup: &LookupRangeCheckConfig,
        chip: &SinsemillaConfig,
        layouter: &mut L,
        rho: &AssignedCell<PallasFp>,
        psi: &AssignedCell<PallasFp>,
    ) -> Halo2Result<DecomposeGParts> {
        let g0 = RangeConstrained::bitrange_of(rho.value, 254, 255);
        let g1 = lookup.witness_short(layouter, psi.value, 0, 9)?;
        let g2 = RangeConstrained::bitrange_of(psi.value, 9, 249);
        let g = SinsemillaMessagePiece::from_subpieces(
            chip,
            layouter,
            vec![g0.clone(), g1.value(), g2],
        )?;
        Ok((g, g0, g1))
    }

    pub fn assign<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        g: &SinsemillaMessagePiece,
        g0: &RangeConstrained<Option<PallasFp>>,
        g1: &RangeConstrained<AssignedCell<PallasFp>>,
        z1_g: &AssignedCell<PallasFp>,
    ) -> Halo2Result<AssignedCell<PallasFp>> {
        layouter.assign_region(&mut |region: &mut Region<'_>| {
            self.q.enable(region, 0)?;
            g.cell_value.copy_advice(region, self.col_l, 0)?;
            let a0 = region.assign_advice(self.col_m, 0, &mut || g0.inner)?;
            g1.inner.copy_advice(region, self.col_l, 1)?;
            z1_g.copy_advice(region, self.col_m, 1)?;
            Ok(a0)
        })
    }
}

// —— DecomposeH ——

#[derive(Clone, Copy)]
pub struct DecomposeH {
    pub q: Selector,
    pub col_l: AssignmentColumn,
    pub col_m: AssignmentColumn,
    pub col_r: AssignmentColumn,
}

impl DecomposeH {
    pub fn configure(
        meta: &mut ConstraintSystem,
        col_l: AssignmentColumn,
        col_m: AssignmentColumn,
        col_r: AssignmentColumn,
        two_pow_5: PallasFp,
    ) -> Halo2Result<Self> {
        let q = meta.selector();
        meta.create_gate(&mut |meta: &mut VirtualCells<'_>| {
            let qs = meta.query_selector(q);
            let h = meta.query_advice(col_l, Rotation::cur());
            let h0 = meta.query_advice(col_m, Rotation::cur());
            let h1 = meta.query_advice(col_r, Rotation::cur());
            let decomp = h.try_sub(&h0.try_add(&h1.scale(two_pow_5))?)?;
            Ok(Constraints {
                selector: Some(qs),
                constraints: vec![bool_check_expr(h1)?, decomp],
            })
        })?;
        Ok(Self {
            q,
            col_l,
            col_m,
            col_r,
        })
    }

    pub fn decompose<L: Layouter + ?Sized>(
        &self,
        lookup: &LookupRangeCheckConfig,
        chip: &SinsemillaConfig,
        layouter: &mut L,
        psi: &AssignedCell<PallasFp>,
    ) -> Halo2Result<DecomposeHParts> {
        let h0 = lookup.witness_short(layouter, psi.value, 249, 254)?;
        let h1 = RangeConstrained::bitrange_of(psi.value, 254, 255);
        let h2 = RangeConstrained::bitrange_of(Some(PallasFp::zero()), 0, 4);
        let h = SinsemillaMessagePiece::from_subpieces(
            chip,
            layouter,
            vec![h0.value(), h1.clone(), h2],
        )?;
        Ok((h, h0, h1))
    }

    pub fn assign<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        h: &SinsemillaMessagePiece,
        h0: &RangeConstrained<AssignedCell<PallasFp>>,
        h1: &RangeConstrained<Option<PallasFp>>,
    ) -> Halo2Result<AssignedCell<PallasFp>> {
        layouter.assign_region(&mut |region: &mut Region<'_>| {
            self.q.enable(region, 0)?;
            h.cell_value.copy_advice(region, self.col_l, 0)?;
            h0.inner.copy_advice(region, self.col_m, 0)?;
            let a = region.assign_advice(self.col_r, 0, &mut || h1.inner)?;
            Ok(a)
        })
    }
}

// —— canonicity gates ——

#[derive(Clone, Copy)]
pub struct GdCanonicity {
    pub q: Selector,
    pub col_l: AssignmentColumn,
    pub col_m: AssignmentColumn,
    pub col_r: AssignmentColumn,
    pub col_z: AssignmentColumn,
}

impl GdCanonicity {
    #[allow(clippy::too_many_arguments)] // Gate API mirrors upstream halo2 circuit signatures; regrouping args would churn call sites.
    pub fn configure(
        meta: &mut ConstraintSystem,
        col_l: AssignmentColumn,
        col_m: AssignmentColumn,
        col_r: AssignmentColumn,
        col_z: AssignmentColumn,
        two_pow_130: Expression,
        two_pow_250: PallasFp,
        two_pow_254: PallasFp,
        t_p: Expression,
    ) -> Halo2Result<Self> {
        let q = meta.selector();
        meta.create_gate(&mut |meta: &mut VirtualCells<'_>| {
            let qs = meta.query_selector(q);
            let gd_x = meta.query_advice(col_l, Rotation::cur());
            let b0 = meta.query_advice(col_m, Rotation::cur());
            let b1 = meta.query_advice(col_m, Rotation::next());
            let a = meta.query_advice(col_r, Rotation::cur());
            let a_prime = meta.query_advice(col_r, Rotation::next());
            let z13_a = meta.query_advice(col_z, Rotation::cur());
            let z13_a_prime = meta.query_advice(col_z, Rotation::next());
            let decomp = a
                .try_add(&b0.scale(two_pow_250))?
                .try_add(&b1.scale(two_pow_254))?
                .try_sub(&gd_x)?;
            let a_prime_check = a.try_add(&two_pow_130)?.try_sub(&t_p)?.try_sub(&a_prime)?;
            Ok(Constraints {
                selector: Some(qs),
                constraints: vec![
                    decomp,
                    a_prime_check,
                    b1.try_mul_expr(&b0)?,
                    b1.try_mul_expr(&z13_a)?,
                    b1.try_mul_expr(&z13_a_prime)?,
                ],
            })
        })?;
        Ok(Self {
            q,
            col_l,
            col_m,
            col_r,
            col_z,
        })
    }

    #[allow(clippy::too_many_arguments)] // Gate API mirrors upstream halo2 circuit signatures; regrouping args would churn call sites.
    pub fn assign<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        g_d: &EccPoint,
        a: &SinsemillaMessagePiece,
        b0: &RangeConstrained<AssignedCell<PallasFp>>,
        b1: &AssignedCell<PallasFp>,
        a_prime: &AssignedCell<PallasFp>,
        z13_a: &AssignedCell<PallasFp>,
        z13_a_prime: &AssignedCell<PallasFp>,
    ) -> Halo2Result<()> {
        layouter.assign_region(&mut |region: &mut Region<'_>| {
            g_d.get_x().copy_advice(region, self.col_l, 0)?;
            b0.inner.copy_advice(region, self.col_m, 0)?;
            b1.copy_advice(region, self.col_m, 1)?;
            a.cell_value.copy_advice(region, self.col_r, 0)?;
            a_prime.copy_advice(region, self.col_r, 1)?;
            z13_a.copy_advice(region, self.col_z, 0)?;
            z13_a_prime.copy_advice(region, self.col_z, 1)?;
            self.q.enable(region, 0)
        })
    }
}

#[derive(Clone, Copy)]
pub struct PkdCanonicity {
    pub q: Selector,
    pub col_l: AssignmentColumn,
    pub col_m: AssignmentColumn,
    pub col_r: AssignmentColumn,
    pub col_z: AssignmentColumn,
}

impl PkdCanonicity {
    #[allow(clippy::too_many_arguments)] // Gate API mirrors upstream halo2 circuit signatures; regrouping args would churn call sites.
    pub fn configure(
        meta: &mut ConstraintSystem,
        col_l: AssignmentColumn,
        col_m: AssignmentColumn,
        col_r: AssignmentColumn,
        col_z: AssignmentColumn,
        two_pow_4: PallasFp,
        two_pow_140: Expression,
        two_pow_254: PallasFp,
        t_p: Expression,
    ) -> Halo2Result<Self> {
        let q = meta.selector();
        meta.create_gate(&mut |meta: &mut VirtualCells<'_>| {
            let qs = meta.query_selector(q);
            let pkd_x = meta.query_advice(col_l, Rotation::cur());
            let b3 = meta.query_advice(col_m, Rotation::cur());
            let d0 = meta.query_advice(col_m, Rotation::next());
            let c = meta.query_advice(col_r, Rotation::cur());
            let b3_c_prime = meta.query_advice(col_r, Rotation::next());
            let z13_c = meta.query_advice(col_z, Rotation::cur());
            let z14 = meta.query_advice(col_z, Rotation::next());
            let decomp = b3
                .try_add(&c.scale(two_pow_4))?
                .try_add(&d0.scale(two_pow_254))?
                .try_sub(&pkd_x)?;
            let b3c_check = b3
                .try_add(&c.scale(two_pow_4))?
                .try_add(&two_pow_140)?
                .try_sub(&t_p)?
                .try_sub(&b3_c_prime)?;
            Ok(Constraints {
                selector: Some(qs),
                constraints: vec![
                    decomp,
                    b3c_check,
                    d0.try_mul_expr(&z13_c)?,
                    d0.try_mul_expr(&z14)?,
                ],
            })
        })?;
        Ok(Self {
            q,
            col_l,
            col_m,
            col_r,
            col_z,
        })
    }

    #[allow(clippy::too_many_arguments)] // Gate API mirrors upstream halo2 circuit signatures; regrouping args would churn call sites.
    pub fn assign<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        pk_d: &EccPoint,
        b3: &RangeConstrained<AssignedCell<PallasFp>>,
        c: &SinsemillaMessagePiece,
        d0: &AssignedCell<PallasFp>,
        b3_c_prime: &AssignedCell<PallasFp>,
        z13_c: &AssignedCell<PallasFp>,
        z14: &AssignedCell<PallasFp>,
    ) -> Halo2Result<()> {
        layouter.assign_region(&mut |region: &mut Region<'_>| {
            pk_d.get_x().copy_advice(region, self.col_l, 0)?;
            b3.inner.copy_advice(region, self.col_m, 0)?;
            d0.copy_advice(region, self.col_m, 1)?;
            c.cell_value.copy_advice(region, self.col_r, 0)?;
            b3_c_prime.copy_advice(region, self.col_r, 1)?;
            z13_c.copy_advice(region, self.col_z, 0)?;
            z14.copy_advice(region, self.col_z, 1)?;
            self.q.enable(region, 0)
        })
    }
}

#[derive(Clone, Copy)]
pub struct ValueCanonicity {
    pub q: Selector,
    pub col_l: AssignmentColumn,
    pub col_m: AssignmentColumn,
    pub col_r: AssignmentColumn,
    pub col_z: AssignmentColumn,
}

impl ValueCanonicity {
    pub fn configure(
        meta: &mut ConstraintSystem,
        col_l: AssignmentColumn,
        col_m: AssignmentColumn,
        col_r: AssignmentColumn,
        col_z: AssignmentColumn,
        two_pow_8: PallasFp,
        two_pow_58: PallasFp,
    ) -> Halo2Result<Self> {
        let q = meta.selector();
        meta.create_gate(&mut |meta: &mut VirtualCells<'_>| {
            let qs = meta.query_selector(q);
            let value = meta.query_advice(col_l, Rotation::cur());
            let d2 = meta.query_advice(col_m, Rotation::cur());
            let z1_d = meta.query_advice(col_r, Rotation::cur());
            let e0 = meta.query_advice(col_z, Rotation::cur());
            let check = d2
                .try_add(&z1_d.scale(two_pow_8))?
                .try_add(&e0.scale(two_pow_58))?
                .try_sub(&value)?;
            Ok(Constraints {
                selector: Some(qs),
                constraints: vec![check],
            })
        })?;
        Ok(Self {
            q,
            col_l,
            col_m,
            col_r,
            col_z,
        })
    }

    pub fn assign<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        value: &AssignedCell<PallasFp>,
        d2: &RangeConstrained<AssignedCell<PallasFp>>,
        z1_d: &AssignedCell<PallasFp>,
        e0: &RangeConstrained<AssignedCell<PallasFp>>,
    ) -> Halo2Result<()> {
        layouter.assign_region(&mut |region: &mut Region<'_>| {
            value.copy_advice(region, self.col_l, 0)?;
            d2.inner.copy_advice(region, self.col_m, 0)?;
            z1_d.copy_advice(region, self.col_r, 0)?;
            e0.inner.copy_advice(region, self.col_z, 0)?;
            self.q.enable(region, 0)
        })
    }
}

#[derive(Clone, Copy)]
pub struct RhoCanonicity {
    pub q: Selector,
    pub col_l: AssignmentColumn,
    pub col_m: AssignmentColumn,
    pub col_r: AssignmentColumn,
    pub col_z: AssignmentColumn,
}

impl RhoCanonicity {
    #[allow(clippy::too_many_arguments)] // Gate API mirrors upstream halo2 circuit signatures; regrouping args would churn call sites.
    pub fn configure(
        meta: &mut ConstraintSystem,
        col_l: AssignmentColumn,
        col_m: AssignmentColumn,
        col_r: AssignmentColumn,
        col_z: AssignmentColumn,
        two_pow_4: PallasFp,
        two_pow_140: Expression,
        two_pow_254: PallasFp,
        t_p: Expression,
    ) -> Halo2Result<Self> {
        let q = meta.selector();
        meta.create_gate(&mut |meta: &mut VirtualCells<'_>| {
            let qs = meta.query_selector(q);
            let rho = meta.query_advice(col_l, Rotation::cur());
            let e1 = meta.query_advice(col_m, Rotation::cur());
            let g0 = meta.query_advice(col_m, Rotation::next());
            let f = meta.query_advice(col_r, Rotation::cur());
            let e1_f_prime = meta.query_advice(col_r, Rotation::next());
            let z13_f = meta.query_advice(col_z, Rotation::cur());
            let z14 = meta.query_advice(col_z, Rotation::next());
            let decomp = e1
                .try_add(&f.scale(two_pow_4))?
                .try_add(&g0.scale(two_pow_254))?
                .try_sub(&rho)?;
            let prime = e1
                .try_add(&f.scale(two_pow_4))?
                .try_add(&two_pow_140)?
                .try_sub(&t_p)?
                .try_sub(&e1_f_prime)?;
            Ok(Constraints {
                selector: Some(qs),
                constraints: vec![
                    decomp,
                    prime,
                    g0.try_mul_expr(&z13_f)?,
                    g0.try_mul_expr(&z14)?,
                ],
            })
        })?;
        Ok(Self {
            q,
            col_l,
            col_m,
            col_r,
            col_z,
        })
    }

    #[allow(clippy::too_many_arguments)] // Gate API mirrors upstream halo2 circuit signatures; regrouping args would churn call sites.
    pub fn assign<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        rho: &AssignedCell<PallasFp>,
        e1: &RangeConstrained<AssignedCell<PallasFp>>,
        f: &SinsemillaMessagePiece,
        g0: &AssignedCell<PallasFp>,
        e1_f_prime: &AssignedCell<PallasFp>,
        z13_f: &AssignedCell<PallasFp>,
        z14: &AssignedCell<PallasFp>,
    ) -> Halo2Result<()> {
        layouter.assign_region(&mut |region: &mut Region<'_>| {
            rho.copy_advice(region, self.col_l, 0)?;
            e1.inner.copy_advice(region, self.col_m, 0)?;
            g0.copy_advice(region, self.col_m, 1)?;
            f.cell_value.copy_advice(region, self.col_r, 0)?;
            e1_f_prime.copy_advice(region, self.col_r, 1)?;
            z13_f.copy_advice(region, self.col_z, 0)?;
            z14.copy_advice(region, self.col_z, 1)?;
            self.q.enable(region, 0)
        })
    }
}

#[derive(Clone, Copy)]
pub struct PsiCanonicity {
    pub q: Selector,
    pub col_l: AssignmentColumn,
    pub col_m: AssignmentColumn,
    pub col_r: AssignmentColumn,
    pub col_z: AssignmentColumn,
}

impl PsiCanonicity {
    #[allow(clippy::too_many_arguments)] // Gate API mirrors upstream halo2 circuit signatures; regrouping args would churn call sites.
    pub fn configure(
        meta: &mut ConstraintSystem,
        col_l: AssignmentColumn,
        col_m: AssignmentColumn,
        col_r: AssignmentColumn,
        col_z: AssignmentColumn,
        two_pow_9: PallasFp,
        two_pow_130: Expression,
        two_pow_249: PallasFp,
        two_pow_254: PallasFp,
        t_p: Expression,
    ) -> Halo2Result<Self> {
        let q = meta.selector();
        meta.create_gate(&mut |meta: &mut VirtualCells<'_>| {
            let qs = meta.query_selector(q);
            let psi = meta.query_advice(col_l, Rotation::cur());
            let h0 = meta.query_advice(col_l, Rotation::next());
            let g1 = meta.query_advice(col_m, Rotation::cur());
            let h1 = meta.query_advice(col_m, Rotation::next());
            let z1_g = meta.query_advice(col_r, Rotation::cur());
            let g1_g2_prime = meta.query_advice(col_r, Rotation::next());
            let z13_g = meta.query_advice(col_z, Rotation::cur());
            let z13_prime = meta.query_advice(col_z, Rotation::next());
            let decomp = g1
                .try_add(&z1_g.scale(two_pow_9))?
                .try_add(&h0.scale(two_pow_249))?
                .try_add(&h1.scale(two_pow_254))?
                .try_sub(&psi)?;
            let prime = g1
                .try_add(&z1_g.scale(two_pow_9))?
                .try_add(&two_pow_130)?
                .try_sub(&t_p)?
                .try_sub(&g1_g2_prime)?;
            Ok(Constraints {
                selector: Some(qs),
                constraints: vec![
                    decomp,
                    prime,
                    h1.try_mul_expr(&h0)?,
                    h1.try_mul_expr(&z13_g)?,
                    h1.try_mul_expr(&z13_prime)?,
                ],
            })
        })?;
        Ok(Self {
            q,
            col_l,
            col_m,
            col_r,
            col_z,
        })
    }

    #[allow(clippy::too_many_arguments)] // Gate API mirrors upstream halo2 circuit signatures; regrouping args would churn call sites.
    pub fn assign<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        psi: &AssignedCell<PallasFp>,
        g1: &RangeConstrained<AssignedCell<PallasFp>>,
        z1_g: &AssignedCell<PallasFp>,
        h0: &RangeConstrained<AssignedCell<PallasFp>>,
        h1: &AssignedCell<PallasFp>,
        g1_g2_prime: &AssignedCell<PallasFp>,
        z13_g: &AssignedCell<PallasFp>,
        z13_prime: &AssignedCell<PallasFp>,
    ) -> Halo2Result<()> {
        layouter.assign_region(&mut |region: &mut Region<'_>| {
            psi.copy_advice(region, self.col_l, 0)?;
            h0.inner.copy_advice(region, self.col_l, 1)?;
            g1.inner.copy_advice(region, self.col_m, 0)?;
            h1.copy_advice(region, self.col_m, 1)?;
            z1_g.copy_advice(region, self.col_r, 0)?;
            g1_g2_prime.copy_advice(region, self.col_r, 1)?;
            z13_g.copy_advice(region, self.col_z, 0)?;
            z13_prime.copy_advice(region, self.col_z, 1)?;
            self.q.enable(region, 0)
        })
    }
}

#[derive(Clone, Copy)]
pub struct YCanonicity {
    pub q: Selector,
    pub advices: [AssignmentColumn; 10],
}

impl YCanonicity {
    #[allow(clippy::too_many_arguments)] // Gate API mirrors upstream halo2 circuit signatures; regrouping args would churn call sites.
    pub fn configure(
        meta: &mut ConstraintSystem,
        advices: [AssignmentColumn; 10],
        two: PallasFp,
        two_pow_10: PallasFp,
        two_pow_130: Expression,
        two_pow_250: PallasFp,
        two_pow_254: PallasFp,
        t_p: Expression,
    ) -> Halo2Result<Self> {
        let q = meta.selector();
        meta.create_gate(&mut |meta: &mut VirtualCells<'_>| {
            let qs = meta.query_selector(q);
            let y = meta.query_advice(advices[5], Rotation::cur());
            let lsb = meta.query_advice(advices[6], Rotation::cur());
            let k0 = meta.query_advice(advices[7], Rotation::cur());
            let k2 = meta.query_advice(advices[8], Rotation::cur());
            let k3 = meta.query_advice(advices[9], Rotation::cur());
            let j = meta.query_advice(advices[5], Rotation::next());
            let z1_j = meta.query_advice(advices[6], Rotation::next());
            let z13_j = meta.query_advice(advices[7], Rotation::next());
            let j_prime = meta.query_advice(advices[8], Rotation::next());
            let z13_j_prime = meta.query_advice(advices[9], Rotation::next());
            let k1 = z1_j.clone();
            let j_check = j.try_sub(
                &lsb.try_add(&k0.scale(two))?
                    .try_add(&k1.scale(two_pow_10))?,
            )?;
            let y_check = y.try_sub(
                &j.try_add(&k2.scale(two_pow_250))?
                    .try_add(&k3.scale(two_pow_254))?,
            )?;
            let j_prime_check = j.try_add(&two_pow_130)?.try_sub(&t_p)?.try_sub(&j_prime)?;
            let k3_check = bool_check_expr(k3.clone())?;
            Ok(Constraints {
                selector: Some(qs),
                constraints: vec![
                    k3_check,
                    j_check,
                    y_check,
                    j_prime_check,
                    k3.try_mul_expr(&k2)?,
                    k3.try_mul_expr(&z13_j)?,
                    k3.try_mul_expr(&z13_j_prime)?,
                ],
            })
        })?;
        Ok(Self { q, advices })
    }

    #[allow(clippy::too_many_arguments)] // Gate API mirrors upstream halo2 circuit signatures; regrouping args would churn call sites.
    pub fn assign<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        y: &AssignedCell<PallasFp>,
        lsb: &RangeConstrained<Option<PallasFp>>,
        k0: &RangeConstrained<AssignedCell<PallasFp>>,
        k2: &RangeConstrained<AssignedCell<PallasFp>>,
        k3: &RangeConstrained<Option<PallasFp>>,
        j: &AssignedCell<PallasFp>,
        z1_j: &AssignedCell<PallasFp>,
        z13_j: &AssignedCell<PallasFp>,
        j_prime: &AssignedCell<PallasFp>,
        z13_j_prime: &AssignedCell<PallasFp>,
    ) -> Halo2Result<RangeConstrained<AssignedCell<PallasFp>>> {
        layouter.assign_region(&mut |region: &mut Region<'_>| {
            self.q.enable(region, 0)?;
            y.copy_advice(region, self.advices[5], 0)?;
            let assigned_lsb = region.assign_advice(self.advices[6], 0, &mut || lsb.inner)?;
            let lsb_assigned = RangeConstrained {
                inner: assigned_lsb,
                num_bits: lsb.num_bits,
            };
            k0.inner.copy_advice(region, self.advices[7], 0)?;
            k2.inner.copy_advice(region, self.advices[8], 0)?;
            region.assign_advice(self.advices[9], 0, &mut || k3.inner)?;
            j.copy_advice(region, self.advices[5], 1)?;
            z1_j.copy_advice(region, self.advices[6], 1)?;
            z13_j.copy_advice(region, self.advices[7], 1)?;
            j_prime.copy_advice(region, self.advices[8], 1)?;
            z13_j_prime.copy_advice(region, self.advices[9], 1)?;
            Ok(lsb_assigned)
        })
    }
}

#[derive(Clone)]
pub struct NoteCommitConfig {
    pub b: DecomposeB,
    pub d: DecomposeD,
    pub e: DecomposeE,
    pub g: DecomposeG,
    pub h: DecomposeH,
    pub g_d: GdCanonicity,
    pub pk_d: PkdCanonicity,
    pub value: ValueCanonicity,
    pub rho: RhoCanonicity,
    pub psi: PsiCanonicity,
    pub y_canon: YCanonicity,
    pub advices: Vec<AssignmentColumn>,
    pub sinsemilla_config: SinsemillaConfig,
}

impl NoteCommitConfig {
    pub fn configure(
        meta: &mut ConstraintSystem,
        advices: Vec<AssignmentColumn>,
        sinsemilla_config: &SinsemillaConfig,
    ) -> Halo2Result<Self> {
        let two = PallasFp::from_u64(2);
        let two_pow_2 = PallasFp::from_u64(4);
        let two_pow_4 = PallasFp::from_u64(16);
        let two_pow_5 = PallasFp::from_u64(32);
        let two_pow_6 = PallasFp::from_u64(64);
        let two_pow_8 = PallasFp::from_u64(256);
        let two_pow_9 = PallasFp::from_u64(512);
        let two_pow_10 = PallasFp::from_u64(1024);
        let two_pow_58 = pow2(58);
        let two_pow_130 = Expression::constant(pow2(130));
        let two_pow_140 = Expression::constant(pow2(140));
        let two_pow_249 = pow2(249);
        let two_pow_250 = pow2(250);
        let two_pow_254 = pow2(254);
        let t_p = Expression::constant(PallasFp::from_le_array(&T_P_LE)?);

        let col = |i: usize| -> Halo2Result<AssignmentColumn> {
            advices.get(i).copied().ok_or_else(|| {
                crate::zk::orchard_halo2::error::Halo2Error::operation_failed(
                    "note_commit::configure",
                    "short advices",
                )
            })
        };
        let (col_l, col_m, col_r, col_z) = (col(6)?, col(7)?, col(8)?, col(9)?);
        let b = DecomposeB::configure(meta, col_l, col_m, col_r, two_pow_4, two_pow_5, two_pow_6)?;
        let d = DecomposeD::configure(meta, col_l, col_m, col_r, two, two_pow_2, two_pow_10)?;
        let e = DecomposeE::configure(meta, col_l, col_m, col_r, two_pow_6)?;
        let g = DecomposeG::configure(meta, col_l, col_m, two, two_pow_10)?;
        let h = DecomposeH::configure(meta, col_l, col_m, col_r, two_pow_5)?;
        let g_d = GdCanonicity::configure(
            meta,
            col_l,
            col_m,
            col_r,
            col_z,
            two_pow_130.clone(),
            two_pow_250,
            two_pow_254,
            t_p.clone(),
        )?;
        let pk_d = PkdCanonicity::configure(
            meta,
            col_l,
            col_m,
            col_r,
            col_z,
            two_pow_4,
            two_pow_140.clone(),
            two_pow_254,
            t_p.clone(),
        )?;
        let value =
            ValueCanonicity::configure(meta, col_l, col_m, col_r, col_z, two_pow_8, two_pow_58)?;
        let rho = RhoCanonicity::configure(
            meta,
            col_l,
            col_m,
            col_r,
            col_z,
            two_pow_4,
            two_pow_140,
            two_pow_254,
            t_p.clone(),
        )?;
        let psi = PsiCanonicity::configure(
            meta,
            col_l,
            col_m,
            col_r,
            col_z,
            two_pow_9,
            two_pow_130.clone(),
            two_pow_249,
            two_pow_254,
            t_p.clone(),
        )?;
        let mut full_advices = [advices[0]; 10];
        for (i, a) in advices.iter().take(10).enumerate() {
            full_advices[i] = *a;
        }
        let y_canon = YCanonicity::configure(
            meta,
            full_advices,
            two,
            two_pow_10,
            two_pow_130,
            two_pow_250,
            two_pow_254,
            t_p,
        )?;
        Ok(Self {
            b,
            d,
            e,
            g,
            h,
            g_d,
            pk_d,
            value,
            rho,
            psi,
            y_canon,
            advices,
            sinsemilla_config: sinsemilla_config.clone(),
        })
    }

    #[cfg(feature = "alloc")]
    pub fn to_debug_string(&self) -> String {
        alloc::string::String::from("NoteCommitConfig")
    }
}
