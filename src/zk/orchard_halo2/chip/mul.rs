//! Implements chip/mul logic (variable-base scalar mul).
//! Bit ranges, running sums and overflow checks mirrored exactly; all
//! `assert!`/throws become `Halo2Result`.

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

use crate::zk::orchard_halo2::chip::add::AddConfig;
use crate::zk::orchard_halo2::chip::ecc::{EccPoint, ScalarVar, ScalarVarBaseFieldElem};
use crate::zk::orchard_halo2::chip::lookup::LookupRangeCheckConfig;
use crate::zk::orchard_halo2::error::{Halo2Error, Halo2Result};
use crate::zk::orchard_halo2::field::{u256_add_le, PallasFp, T_Q_LE};
use crate::zk::orchard_halo2::plonk::assigned::Assigned;
use crate::zk::orchard_halo2::plonk::column::{AssignmentColumn, Selector};
use crate::zk::orchard_halo2::plonk::constraint::{ConstraintSystem, Constraints, VirtualCells};
use crate::zk::orchard_halo2::plonk::expression::Expression;
use crate::zk::orchard_halo2::poly::poly::Rotation;
use crate::zk::orchard_halo2::utility::layouter::{AssignedCell, Layouter, Region};
use crate::zk::orchard_halo2::utility::utils::{bool_check_expr, ternary_expr, PALLAS_NUM_BITS};

// Unpacked double-and-add loop state: (x, y, running-sum cells).
type DoubleAddState = (
    AssignedCell<Assigned>,
    AssignedCell<Assigned>,
    Vec<AssignedCell<PallasFp>>,
);

#[derive(Clone, Copy)]
pub struct IntRange {
    pub start: usize,
    pub end: usize,
}

impl IntRange {
    #[allow(clippy::len_without_is_empty)] // Length API mirrors the upstream range gadget; no emptiness query is needed.
    pub fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }
}

#[derive(Clone, Copy)]
pub struct DoubleAndAdd {
    pub x_a: AssignmentColumn,
    pub x_p: AssignmentColumn,
    pub lambda1: AssignmentColumn,
    pub lambda2: AssignmentColumn,
}

impl DoubleAndAdd {
    pub fn x_r(&self, meta: &mut VirtualCells<'_>, rotation: Rotation) -> Halo2Result<Expression> {
        let x_a = meta.query_advice(self.x_a, rotation);
        let x_p = meta.query_advice(self.x_p, rotation);
        let l1 = meta.query_advice(self.lambda1, rotation);
        l1.square()?.try_sub(&x_a)?.try_sub(&x_p)
    }

    pub fn y_a(&self, meta: &mut VirtualCells<'_>, rotation: Rotation) -> Halo2Result<Expression> {
        let x_a = meta.query_advice(self.x_a, rotation);
        let l1 = meta.query_advice(self.lambda1, rotation);
        let l2 = meta.query_advice(self.lambda2, rotation);
        l1.try_add(&l2)?
            .try_mul_expr(&x_a.try_sub(&self.x_r(meta, rotation)?)?)
    }
}

#[derive(Clone, Copy)]
pub struct MulIncompleteConfig {
    pub q_mul1: Selector,
    pub q_mul2: Selector,
    pub q_mul3: Selector,
    pub z: AssignmentColumn,
    pub double_and_add: DoubleAndAdd,
    pub y_p: AssignmentColumn,
    pub bitlen: usize,
}

impl MulIncompleteConfig {
    #[allow(clippy::too_many_arguments)] // Gate API mirrors upstream halo2 circuit signatures; regrouping args would churn call sites.
    pub fn configure(
        meta: &mut ConstraintSystem,
        z: AssignmentColumn,
        x_a: AssignmentColumn,
        x_p: AssignmentColumn,
        y_p: AssignmentColumn,
        lambda1: AssignmentColumn,
        lambda2: AssignmentColumn,
        bitlen: usize,
    ) -> Halo2Result<Self> {
        meta.enable_equality(z);
        meta.enable_equality(lambda1);
        let config = Self {
            q_mul1: meta.selector(),
            q_mul2: meta.selector(),
            q_mul3: meta.selector(),
            z,
            double_and_add: DoubleAndAdd {
                x_a,
                x_p,
                lambda1,
                lambda2,
            },
            y_p,
            bitlen,
        };
        config.create_gate(meta)?;
        Ok(config)
    }

    fn create_gate(&self, meta: &mut ConstraintSystem) -> Halo2Result<()> {
        // qMul1: y_witnessed == y_a(next)
        meta.create_gate(&mut |meta: &mut VirtualCells<'_>| {
            let q = meta.query_selector(self.q_mul1);
            let y_next = self
                .double_and_add
                .y_a(meta, Rotation::next())?
                .scale(PallasFp::two_inv());
            let y_wit = meta.query_advice(self.double_and_add.lambda1, Rotation::cur());
            Ok(Constraints {
                selector: Some(q),
                constraints: vec![y_wit.try_sub(&y_next)?],
            })
        })?;
        // qMul2: x/y constancy + loop constraints
        meta.create_gate(&mut |meta: &mut VirtualCells<'_>| {
            let q = meta.query_selector(self.q_mul2);
            let y_next = self
                .double_and_add
                .y_a(meta, Rotation::next())?
                .scale(PallasFp::two_inv());
            let x_p_cur = meta.query_advice(self.double_and_add.x_p, Rotation::cur());
            let x_p_next = meta.query_advice(self.double_and_add.x_p, Rotation::next());
            let y_p_cur = meta.query_advice(self.y_p, Rotation::cur());
            let y_p_next = meta.query_advice(self.y_p, Rotation::next());
            let mut constraints = vec![x_p_cur.try_sub(&x_p_next)?, y_p_cur.try_sub(&y_p_next)?];
            constraints.extend(self.for_loop(meta, y_next)?);
            Ok(Constraints {
                selector: Some(q),
                constraints,
            })
        })?;
        // qMul3: final loop constraints
        meta.create_gate(&mut |meta: &mut VirtualCells<'_>| {
            let q = meta.query_selector(self.q_mul3);
            let y_final = meta.query_advice(self.double_and_add.lambda1, Rotation::next());
            Ok(Constraints {
                selector: Some(q),
                constraints: self.for_loop(meta, y_final)?,
            })
        })
    }

    fn for_loop(
        &self,
        meta: &mut VirtualCells<'_>,
        y_a_next: Expression,
    ) -> Halo2Result<Vec<Expression>> {
        let one = Expression::constant(PallasFp::one());
        let z_cur = meta.query_advice(self.z, Rotation::cur());
        let z_prev = meta.query_advice(self.z, Rotation::prev());
        let x_a_cur = meta.query_advice(self.double_and_add.x_a, Rotation::cur());
        let x_a_next = meta.query_advice(self.double_and_add.x_a, Rotation::next());
        let x_p_cur = meta.query_advice(self.double_and_add.x_p, Rotation::cur());
        let y_p_cur = meta.query_advice(self.y_p, Rotation::cur());
        let l1_cur = meta.query_advice(self.double_and_add.lambda1, Rotation::cur());
        let l2_cur = meta.query_advice(self.double_and_add.lambda2, Rotation::cur());
        let y_a_cur = self
            .double_and_add
            .y_a(meta, Rotation::cur())?
            .scale(PallasFp::two_inv());

        let k = z_cur.try_sub(&z_prev.scale(PallasFp::from_u64(2)))?;
        let bool_check = bool_check_expr(k.clone())?;
        let gradient1 = l1_cur
            .try_mul_expr(&x_a_cur.try_sub(&x_p_cur)?)?
            .try_sub(&y_a_cur)?
            .try_add(
                &k.scale(PallasFp::from_u64(2))
                    .try_sub(&one)?
                    .try_mul_expr(&y_p_cur)?,
            )?;
        let secant = l2_cur
            .square()?
            .try_sub(&x_a_next)?
            .try_sub(&self.double_and_add.x_r(meta, Rotation::cur())?)?
            .try_sub(&x_a_cur)?;
        let gradient2 = l2_cur
            .try_mul_expr(&x_a_cur.try_sub(&x_a_next)?)?
            .try_sub(&y_a_cur)?
            .try_sub(&y_a_next)?;
        Ok(vec![bool_check, gradient1, secant, gradient2])
    }

    pub fn double_add(
        &self,
        region: &mut Region<'_>,
        offset: usize,
        base: &EccPoint,
        bits: &[Option<bool>],
        acc: (
            AssignedCell<Assigned>,
            AssignedCell<Assigned>,
            AssignedCell<PallasFp>,
        ),
        // Fixed-circuit base anchor (official `AnchoredBase`): at loop row 0,
        // copy the real base into `x_p`/`y_p` so `q_mul_2` constancy propagates
        // it to every row. Insecure circuits assign the running values.
        anchored: bool,
    ) -> Halo2Result<DoubleAddState> {
        if bits.len() != self.bitlen {
            return Err(Halo2Error::operation_failed(
                "mul::double_add",
                "bit length",
            ));
        }
        let xp = base.x.value;
        let yp = base.y.value;
        let xa = acc.0.value;
        let ya = acc.1.value;
        if let (Some(a), Some(b), Some(c), Some(d)) = (xa, ya, xp, yp) {
            if (a.is_zero() && b.is_zero()) || (c.is_zero() && d.is_zero()) || a.assigned_eq(&c) {
                return Err(Halo2Error::operation_failed(
                    "mul::double_add",
                    "zero point",
                ));
            }
        }
        self.q_mul1.enable(region, offset)?;
        let c_offset = offset + 1;
        for idx in 0..self.bitlen.saturating_sub(1) {
            self.q_mul2.enable(region, c_offset + idx)?;
        }
        self.q_mul3.enable(region, c_offset + self.bitlen - 1)?;

        let mut z = acc.2.copy_advice(region, self.z, offset)?;
        let mut x_a_new = acc
            .0
            .copy_advice(region, self.double_and_add.x_a, offset + 1)?;
        let mut y_a_new = acc
            .1
            .copy_advice(region, self.double_and_add.lambda1, offset)?
            .value;
        let mut off = offset + 1;
        let mut zs: Vec<AssignedCell<PallasFp>> = Vec::new();

        for k in bits.iter() {
            let z_val: Option<PallasFp> = match (z.value, k) {
                (Some(zv), Some(b)) => Some(
                    zv.mul_vartime(&PallasFp::from_u64(2))
                        .add_vartime(&PallasFp::from_u64(*b as u64)),
                ),
                _ => None,
            };
            z = region.assign_advice(self.z, off, &mut || z_val)?;
            zs.push(z);
            // Anchor row: copy base instead of assigning running values.
            // `off == offset + 1` is the first loop row (`off` starts there).
            if anchored && off == offset + 1 {
                base.x.copy_advice(region, self.double_and_add.x_p, off)?;
                base.y.copy_advice(region, self.y_p, off)?;
            } else {
                region.assign_advice(self.double_and_add.x_p, off, &mut || xp)?;
                region.assign_advice(self.y_p, off, &mut || yp)?;
            }
            let y_p_adj: Option<Assigned> = match (yp, k) {
                (Some(v), Some(true)) => Some(v),
                (Some(v), Some(false)) => Some(v.neg()),
                _ => None,
            };
            let lambda1: Option<Assigned> = match (y_a_new, y_p_adj, x_a_new.value, xp) {
                (Some(a), Some(b), Some(xa), Some(xp)) => {
                    Some(a.try_sub(&b).try_mul(&xa.try_sub(&xp).invert()))
                }
                _ => None,
            };
            region.assign_advice(self.double_and_add.lambda1, off, &mut || lambda1)?;
            let x_r: Option<Assigned> = match (lambda1, x_a_new.value, xp) {
                (Some(l), Some(xa), Some(xp)) => Some(l.square().try_sub(&xa).try_sub(&xp)),
                _ => None,
            };
            let lambda2: Option<Assigned> = match (lambda1, y_a_new, x_a_new.value, x_r) {
                (Some(l), Some(a), Some(xa), Some(xr)) => {
                    let two_a = a.try_mul(&Assigned::Trivial(PallasFp::from_u64(2)));
                    Some(two_a.try_mul(&xa.try_sub(&xr).invert()).try_sub(&l))
                }
                _ => None,
            };
            region.assign_advice(self.double_and_add.lambda2, off, &mut || lambda2)?;
            let x_a_next: Option<Assigned> = match (lambda2, x_a_new.value, x_r) {
                (Some(l), Some(xa), Some(xr)) => Some(l.square().try_sub(&xa).try_sub(&xr)),
                _ => None,
            };
            if let (Some(l), Some(xa), Some(xn), Some(a)) =
                (lambda2, x_a_new.value, x_a_next, y_a_new)
            {
                y_a_new = Some(l.try_mul(&xa.try_sub(&xn)).try_sub(&a));
            }
            x_a_new = region.assign_advice(self.double_and_add.x_a, off + 1, &mut || x_a_next)?;
            off += 1;
        }
        // Witness final y_a (loop fusion: off == offset + bitlen).
        let y_c = region.assign_advice(self.double_and_add.lambda1, off, &mut || y_a_new)?;
        Ok((x_a_new, y_c, zs))
    }
}

#[derive(Clone, Copy)]
pub struct MulCompleteConfig {
    pub q_mul_decompose_var: Selector,
    pub z_complete: AssignmentColumn,
    pub add_config: AddConfig,
}

impl MulCompleteConfig {
    pub fn configure(
        meta: &mut ConstraintSystem,
        z_complete: AssignmentColumn,
        add_config: AddConfig,
    ) -> Halo2Result<Self> {
        meta.enable_equality(z_complete);
        let config = Self {
            q_mul_decompose_var: meta.selector(),
            z_complete,
            add_config,
        };
        config.create_gate(meta)?;
        Ok(config)
    }

    fn create_gate(&self, meta: &mut ConstraintSystem) -> Halo2Result<()> {
        meta.create_gate(&mut |meta: &mut VirtualCells<'_>| {
            let q = meta.query_selector(self.q_mul_decompose_var);
            let z_prev = meta.query_advice(self.z_complete, Rotation { location: -1 });
            let z_next = meta.query_advice(self.z_complete, Rotation::next());
            let k = z_next
                .try_sub(&Expression::constant(PallasFp::from_u64(2)).try_mul_expr(&z_prev)?)?;
            let bool_check = bool_check_expr(k.clone())?;
            let base_y = meta.query_advice(self.z_complete, Rotation::cur());
            let y_p = meta.query_advice(self.add_config.y_p, Rotation { location: -1 });
            let y_switch = ternary_expr(&k, &base_y.try_sub(&y_p)?, &base_y.try_add(&y_p)?)?;
            Ok(Constraints {
                selector: Some(q),
                constraints: vec![bool_check, y_switch],
            })
        })
    }

    #[allow(clippy::too_many_arguments)] // Gate API mirrors upstream halo2 circuit signatures; regrouping args would churn call sites.
    pub fn assign_region(
        &self,
        region: &mut Region<'_>,
        offset: usize,
        bits: &[Option<bool>],
        base: &EccPoint,
        x_a: AssignedCell<Assigned>,
        y_a: AssignedCell<Assigned>,
        z: AssignedCell<PallasFp>,
    ) -> Halo2Result<(EccPoint, Vec<AssignedCell<PallasFp>>)> {
        if bits.len() != 3 {
            return Err(Halo2Error::operation_failed(
                "mul_complete::assign",
                "bit length",
            ));
        }
        for (i, _) in bits.iter().enumerate() {
            self.q_mul_decompose_var
                .enable(region, 2 * i + offset + 1)?;
        }
        let mut acc = EccPoint { x: x_a, y: y_a };
        let mut z = z.copy_advice(region, self.z_complete, offset)?;
        let mut zs = Vec::new();
        for (iter, k) in bits.iter().enumerate() {
            let row = 2 * iter;
            let z_val: Option<PallasFp> = match (z.value, k) {
                (Some(zv), Some(b)) => Some(
                    zv.mul_vartime(&PallasFp::from_u64(2))
                        .add_vartime(&PallasFp::from_u64(*b as u64)),
                ),
                _ => None,
            };
            z = region.assign_advice(self.z_complete, row + offset + 2, &mut || z_val)?;
            zs.push(z);
            let base_y_cell = base
                .y
                .copy_advice(region, self.z_complete, row + offset + 1)?;
            let y_p_val: Option<Assigned> = match (base_y_cell.value, k) {
                (Some(v), Some(true)) => Some(v),
                (Some(v), Some(false)) => Some(v.neg()),
                _ => None,
            };
            let y_p_cell =
                region.assign_advice(self.add_config.y_p, row + offset, &mut || y_p_val)?;
            let u = EccPoint {
                x: base.x,
                y: y_p_cell,
            };
            let tmp = self
                .add_config
                .assign_region(&u, &acc, row + offset, region)?;
            acc = self
                .add_config
                .assign_region(&acc, &tmp, row + offset + 1, region)?;
        }
        Ok((acc, zs))
    }
}

#[derive(Clone, Copy)]
pub struct MulOverflowConfig {
    pub q_mul_overflow: Selector,
    pub lookup_config: LookupRangeCheckConfig,
    pub advices: [AssignmentColumn; 3],
}

impl MulOverflowConfig {
    pub fn configure(
        meta: &mut ConstraintSystem,
        lookup_config: LookupRangeCheckConfig,
        advices: [AssignmentColumn; 3],
    ) -> Halo2Result<Self> {
        for a in advices.iter() {
            meta.enable_equality(*a);
        }
        let config = Self {
            q_mul_overflow: meta.selector(),
            lookup_config,
            advices,
        };
        config.create_gate(meta)?;
        Ok(config)
    }

    fn create_gate(&self, meta: &mut ConstraintSystem) -> Halo2Result<()> {
        meta.create_gate(&mut |meta: &mut VirtualCells<'_>| {
            let q = meta.query_selector(self.q_mul_overflow);
            let one = Expression::constant(PallasFp::one());
            let two_pow_124 = Expression::constant(PallasFp::from_u64(2).pow_u64(124));
            let two_pow_130 =
                two_pow_124.try_mul_expr(&Expression::constant(PallasFp::from_u64(64)))?;
            let z0 = meta.query_advice(self.advices[0], Rotation { location: -1 });
            let z130 = meta.query_advice(self.advices[0], Rotation::cur());
            let eta = meta.query_advice(self.advices[0], Rotation::next());
            let k254 = meta.query_advice(self.advices[1], Rotation { location: -1 });
            let alpha = meta.query_advice(self.advices[1], Rotation::cur());
            let s_minus = meta.query_advice(self.advices[1], Rotation::next());
            let s = meta.query_advice(self.advices[2], Rotation::cur());
            let s_check = s.try_sub(&alpha.try_add(&k254.try_mul_expr(&two_pow_130)?)?)?;
            let t_q = Expression::constant(PallasFp::from_le_array(&T_Q_LE)?);
            let recovery = z0.try_sub(&alpha)?.try_sub(&t_q)?;
            let lo_zero = k254.try_mul_expr(&z130.try_sub(&two_pow_124)?)?;
            let s_minus_check = k254.try_mul_expr(&s_minus)?;
            let canonicity = one
                .try_sub(&k254)?
                .try_mul_expr(&one.try_sub(&z130.try_mul_expr(&eta)?)?)?
                .try_mul_expr(&s_minus)?;
            Ok(Constraints {
                selector: Some(q),
                constraints: vec![s_check, recovery, lo_zero, s_minus_check, canonicity],
            })
        })
    }

    pub fn overflow_check<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        alpha: &AssignedCell<PallasFp>,
        zs: &[AssignedCell<PallasFp>],
    ) -> Halo2Result<()> {
        if zs.len() < 255 {
            return Err(Halo2Error::operation_failed("mul::overflow", "short zs"));
        }
        let k254 = &zs[254];
        let s_val: Option<PallasFp> = match (alpha.value, k254.value) {
            (Some(a), Some(k)) => {
                Some(a.add_vartime(&k.mul_vartime(&PallasFp::from_u64(2).pow_u64(130))))
            }
            _ => None,
        };
        let s = layouter.assign_region(&mut |region: &mut Region<'_>| {
            region.assign_advice(self.advices[0], 0, &mut || s_val)
        })?;
        let s_minus = self.s_minus_lo130(layouter, &s)?;
        layouter.assign_region(&mut |region: &mut Region<'_>| {
            self.q_mul_overflow.enable(region, 1)?;
            zs[0].copy_advice(region, self.advices[0], 0)?;
            zs[130].copy_advice(region, self.advices[0], 1)?;
            let eta: Option<Assigned> = zs[130].value.map(|v| Assigned::Trivial(v).invert());
            region.assign_advice(self.advices[0], 2, &mut || eta)?;
            zs[254].copy_advice(region, self.advices[1], 0)?;
            alpha.copy_advice(region, self.advices[1], 1)?;
            s_minus.copy_advice(region, self.advices[1], 2)?;
            s.copy_advice(region, self.advices[2], 1)?;
            Ok(())
        })
    }

    fn s_minus_lo130<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        s: &AssignedCell<PallasFp>,
    ) -> Halo2Result<AssignedCell<PallasFp>> {
        let zs = self.lookup_config.copy_check(layouter, s, 13, false)?;
        zs.last()
            .copied()
            .ok_or_else(|| Halo2Error::operation_failed("mul::s_minus", "empty range"))
    }
}

#[derive(Clone, Copy)]
pub struct MulConfig {
    pub q_mul_lsb: Selector,
    pub add_config: AddConfig,
    pub hi_config: MulIncompleteConfig,
    pub lo_config: MulIncompleteConfig,
    pub complete_config: MulCompleteConfig,
    pub overflow_config: MulOverflowConfig,
    pub hi: IntRange,
    pub lo: IntRange,
    pub complete: IntRange,
}

impl MulConfig {
    pub fn configure(
        meta: &mut ConstraintSystem,
        add_config: AddConfig,
        lookup_config: LookupRangeCheckConfig,
        advices: [AssignmentColumn; 10],
    ) -> Halo2Result<Self> {
        let hi_config = MulIncompleteConfig::configure(
            meta, advices[9], advices[3], advices[0], advices[1], advices[4], advices[5], 125,
        )?;
        let lo_config = MulIncompleteConfig::configure(
            meta, advices[6], advices[7], advices[0], advices[1], advices[8], advices[2], 126,
        )?;
        let complete_config = MulCompleteConfig::configure(meta, advices[9], add_config)?;
        let overflow_config = MulOverflowConfig::configure(
            meta,
            lookup_config,
            [advices[6], advices[7], advices[8]],
        )?;
        let config = Self {
            q_mul_lsb: meta.selector(),
            add_config,
            hi_config,
            lo_config,
            complete_config,
            overflow_config,
            hi: IntRange { start: 0, end: 125 },
            lo: IntRange {
                start: 125,
                end: 251,
            },
            complete: IntRange {
                start: 251,
                end: 254,
            },
        };
        if config.hi_config.double_and_add.x_p != config.lo_config.double_and_add.x_p
            || config.hi_config.y_p != config.lo_config.y_p
        {
            return Err(Halo2Error::operation_failed(
                "mul::configure",
                "config mismatch",
            ));
        }
        let outputs = [config.add_config.x_qr, config.add_config.y_qr];
        for e in [
            config.hi_config.z,
            config.hi_config.double_and_add.lambda1,
            config.lo_config.z,
            config.lo_config.double_and_add.lambda1,
        ] {
            if outputs.contains(&e) {
                return Err(Halo2Error::operation_failed("mul::configure", "overlap"));
            }
        }
        config.create_gate(meta)?;
        Ok(config)
    }

    fn create_gate(&self, meta: &mut ConstraintSystem) -> Halo2Result<()> {
        meta.create_gate(&mut |meta: &mut VirtualCells<'_>| {
            let q = meta.query_selector(self.q_mul_lsb);
            let z1 = meta.query_advice(self.complete_config.z_complete, Rotation::cur());
            let z0 = meta.query_advice(self.complete_config.z_complete, Rotation::next());
            let x_p = meta.query_advice(self.add_config.x_p, Rotation::cur());
            let y_p = meta.query_advice(self.add_config.y_p, Rotation::cur());
            let base_x = meta.query_advice(self.add_config.x_p, Rotation::next());
            let base_y = meta.query_advice(self.add_config.y_p, Rotation::next());
            let lsb = z0.try_sub(&z1.scale(PallasFp::from_u64(2)))?;
            let bool_check = bool_check_expr(lsb.clone())?;
            let lsb_x = ternary_expr(&lsb, &x_p, &x_p.try_sub(&base_x)?)?;
            let lsb_y = ternary_expr(&lsb, &y_p, &y_p.try_add(&base_y)?)?;
            Ok(Constraints {
                selector: Some(q),
                constraints: vec![bool_check, lsb_x, lsb_y],
            })
        })
    }

    /// MSB-first 255-bit decomposition of `scalar + tQ` (`decomposeForScalarMul`).
    pub fn decompose_for_scalar_mul(scalar: Option<PallasFp>) -> Vec<Option<bool>> {
        match scalar {
            None => vec![None; PALLAS_NUM_BITS],
            Some(v) => {
                let sum = u256_add_le(&v.to_le_bytes(), &T_Q_LE);
                let mut bits: Vec<bool> = Vec::with_capacity(256);
                for byte in sum.iter() {
                    for i in 0..8 {
                        bits.push(((byte >> i) & 1) == 1);
                    }
                }
                bits.into_iter()
                    .take(PALLAS_NUM_BITS)
                    .rev()
                    .map(Some)
                    .collect()
            }
        }
    }

    fn process_lsb(
        &self,
        region: &mut Region<'_>,
        offset: usize,
        base: &EccPoint,
        acc: &EccPoint,
        z1: &AssignedCell<PallasFp>,
        lsb: Option<bool>,
    ) -> Halo2Result<(EccPoint, AssignedCell<PallasFp>)> {
        self.q_mul_lsb.enable(region, offset)?;
        let z0_val: Option<PallasFp> = match (z1.value, lsb) {
            (Some(z), Some(b)) => Some(
                z.mul_vartime(&PallasFp::from_u64(2))
                    .add_vartime(&PallasFp::from_u64(b as u64)),
            ),
            _ => None,
        };
        let z0_cell =
            region.assign_advice(self.complete_config.z_complete, offset + 1, &mut || z0_val)?;
        base.x
            .copy_advice(region, self.add_config.x_p, offset + 1)?;
        base.y
            .copy_advice(region, self.add_config.y_p, offset + 1)?;
        let (mut x_val, mut y_val): (Option<Assigned>, Option<Assigned>) = (None, None);
        if let Some(b) = lsb {
            if !b {
                x_val = base.x.value;
                y_val = base.y.value.map(|v| v.neg());
            } else {
                x_val = Some(Assigned::Zero);
                y_val = Some(Assigned::Zero);
            }
        }
        let x_cell = region.assign_advice(self.add_config.x_p, offset, &mut || x_val)?;
        let y_cell = region.assign_advice(self.add_config.y_p, offset, &mut || y_val)?;
        let p = EccPoint {
            x: x_cell,
            y: y_cell,
        };
        let result = self.add_config.assign_region(&p, acc, offset, region)?;
        Ok((result, z0_cell))
    }

    pub fn assign<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        alpha: AssignedCell<PallasFp>,
        base: &EccPoint,
        anchored: bool,
    ) -> Halo2Result<(EccPoint, ScalarVar)> {
        let base_point = EccPoint {
            x: base.x,
            y: base.y,
        };
        let out = layouter.assign_region(&mut |region: &mut Region<'_>| {
            let mut offset = 0usize;
            let bits = Self::decompose_for_scalar_mul(alpha.value);
            let bits_hi = bits[self.hi.start..self.hi.end].to_vec();
            let bits_lo = bits[self.lo.start..self.lo.end].to_vec();
            let lsb = bits.get(PALLAS_NUM_BITS - 1).copied().flatten();
            let acc = self
                .add_config
                .assign_region(&base_point, &base_point, offset, region)?;
            offset += 1;
            let z_init =
                region.assign_advice_from_constant(self.hi_config.z, offset, PallasFp::zero())?;
            let (mut xa, mut ya, zs_hi) = self.hi_config.double_add(
                region,
                offset,
                base,
                &bits_hi,
                (acc.x, acc.y, z_init),
                anchored,
            )?;
            let z = zs_hi
                .last()
                .copied()
                .ok_or_else(|| Halo2Error::operation_failed("mul::assign", "empty hi zs"))?;
            let (xa2, ya2, zs_lo) =
                self.lo_config
                    .double_add(region, offset, base, &bits_lo, (xa, ya, z), anchored)?;
            xa = xa2;
            ya = ya2;
            offset += self.lo.len() + 2;
            let z_last = zs_lo
                .last()
                .copied()
                .ok_or_else(|| Halo2Error::operation_failed("mul::assign", "empty lo zs"))?;
            let bits_complete = bits[self.complete.start..self.complete.end].to_vec();
            let (acc_complete, zs_complete) = self.complete_config.assign_region(
                region,
                offset,
                &bits_complete,
                &base_point,
                xa,
                ya,
                z_last,
            )?;
            offset += self.complete.len() * 2;
            let z1 = zs_complete
                .last()
                .copied()
                .ok_or_else(|| Halo2Error::operation_failed("mul::assign", "empty complete zs"))?;
            let (result, z0) = self.process_lsb(region, offset, base, &acc_complete, &z1, lsb)?;
            let mut zs: Vec<AssignedCell<PallasFp>> = Vec::with_capacity(PALLAS_NUM_BITS + 1);
            zs.push(z_init);
            zs.extend(zs_hi);
            zs.extend(zs_lo);
            zs.extend(zs_complete);
            zs.push(z0);
            if zs.len() != PALLAS_NUM_BITS + 1 {
                return Err(Halo2Error::operation_failed("mul::assign", "zs length"));
            }
            zs.reverse();
            Ok((result, zs))
        })?;
        let (result, zs) = out;
        self.overflow_config.overflow_check(layouter, &alpha, &zs)?;
        Ok((
            result,
            ScalarVar::BaseFieldElem(ScalarVarBaseFieldElem { cell: alpha }),
        ))
    }

    #[cfg(feature = "alloc")]
    pub fn to_debug_string(&self) -> String {
        alloc::string::String::from("MulConfig")
    }
}
