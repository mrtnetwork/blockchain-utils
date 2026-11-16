//! Implements chip/mul_fixed logic (fixed-base scalar mul).
//! Window tables + Lagrange coefficients are derived per call from the
//! compile-time LE base tables (mirrors the reference implementation
//! `assert!`/throws become `Halo2Result`.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::zk::orchard_halo2::chip::add::{AddConfig, AddIncompleteConfig};
use crate::zk::orchard_halo2::chip::ecc::{
    EccBaseFieldElemFixed, EccPoint, EccScalarFixed, EccScalarFixedShort,
};
use crate::zk::orchard_halo2::chip::lookup::{LookupRangeCheckConfig, RunningSumConfig};
use crate::zk::orchard_halo2::curve::{PallasAffine, PallasScalar};
use crate::zk::orchard_halo2::error::{Halo2Error, Halo2Result};
use crate::zk::orchard_halo2::field::{PallasFp, VestaFq};
use crate::zk::orchard_halo2::orchard::constants::fixed_bases::{FixedBase, FullBase};
use crate::zk::orchard_halo2::orchard::constants::fixed_bases::{NullifierK, ValueCommitV};
use crate::zk::orchard_halo2::plonk::assigned::Assigned;
use crate::zk::orchard_halo2::plonk::column::{AssignmentColumn, Selector};
use crate::zk::orchard_halo2::plonk::constraint::{ConstraintSystem, Constraints, VirtualCells};
use crate::zk::orchard_halo2::plonk::expression::Expression;
use crate::zk::orchard_halo2::poly::poly::Rotation;
use crate::zk::orchard_halo2::utility::layouter::{AssignedCell, Layouter, Region};
use crate::zk::orchard_halo2::utility::utils::{
    bitrange_subset, bool_check_expr, decompose_word_vesta, range_check_expr, H, L_SCALAR_SHORT,
    NUM_WINDOWS, NUM_WINDOW_SHORT,
};

// —— scalar abstractions ——

#[derive(Clone)]
pub enum ScalarFixed {
    FullWidth(EccScalarFixed),
    Short(EccScalarFixedShort),
    BaseFieldElem(EccBaseFieldElemFixed),
}

impl ScalarFixed {
    pub fn windows_field(&self) -> Halo2Result<Vec<Option<VestaFq>>> {
        match self {
            Self::FullWidth(inner) => {
                let windows = inner.windows.as_ref().ok_or_else(|| {
                    Halo2Error::operation_failed("scalar_fixed::windows", "missing windows")
                })?;
                let mut out = Vec::with_capacity(windows.len());
                for e in windows.iter() {
                    match e.value {
                        Some(v) => {
                            out.push(Some(VestaFq::from_le_bytes_checked(&v.to_le_bytes())?))
                        }
                        None => out.push(None),
                    }
                }
                Ok(out)
            }
            Self::Short(inner) => {
                let rs = inner.running_sum.as_ref().ok_or_else(|| {
                    Halo2Error::operation_failed("scalar_fixed::windows", "missing running sum")
                })?;
                windows_from_running_sum(rs)
            }
            Self::BaseFieldElem(inner) => windows_from_running_sum(&inner.running_sum),
        }
    }

    pub fn windows_usize(&self) -> Halo2Result<Vec<Option<usize>>> {
        let fields = self.windows_field()?;
        let mut out = Vec::with_capacity(fields.len());
        for e in fields.into_iter() {
            match e {
                Some(v) => {
                    let mut bits = [false; 256];
                    v.to_bits_le(&mut bits);
                    let mut size = 0usize;
                    for b in bits[..3].iter().rev() {
                        size = 2 * size + (*b as usize);
                    }
                    out.push(Some(size));
                }
                None => out.push(None),
            }
        }
        Ok(out)
    }
}

fn windows_from_running_sum(zs: &[AssignedCell<PallasFp>]) -> Halo2Result<Vec<Option<VestaFq>>> {
    if zs.len() < 2 {
        return Err(Halo2Error::operation_failed(
            "scalar_fixed::windows",
            "short sum",
        ));
    }
    let hp = PallasFp::from_u64(H as u64);
    let mut out = Vec::with_capacity(zs.len() - 1);
    for i in 0..zs.len() - 1 {
        match (zs[i].value, zs[i + 1].value) {
            (Some(cur), Some(next)) => {
                let word = cur.sub_vartime(&next.mul_vartime(&hp));
                out.push(Some(VestaFq::from_le_bytes_checked(&word.to_le_bytes())?));
            }
            _ => out.push(None),
        }
    }
    Ok(out)
}

// —— MulFixedConfig ——

#[derive(Clone, Copy)]
pub struct MulFixedConfig {
    pub running_sum_config: RunningSumConfig,
    /// Fixed Lagrange interpolation columns for `x_p` (8, from wiring).
    pub lagrange_coeffs: [AssignmentColumn; 8],
    pub fixed_z: AssignmentColumn,
    pub window: AssignmentColumn,
    pub u: AssignmentColumn,
    pub add_config: AddConfig,
    pub add_incomplete_config: AddIncompleteConfig,
}

impl MulFixedConfig {
    pub fn configure(
        meta: &mut ConstraintSystem,
        lagrange_coeffs: [AssignmentColumn; 8],
        window: AssignmentColumn,
        u: AssignmentColumn,
        add_config: AddConfig,
        add_incomplete_config: AddIncompleteConfig,
    ) -> Halo2Result<Self> {
        meta.enable_equality(window);
        meta.enable_equality(u);
        let q_running = meta.selector();
        let running_sum_config = RunningSumConfig::configure(meta, q_running, window)?;
        let fixed_z = meta.fixed_column();
        let config = Self {
            running_sum_config,
            lagrange_coeffs,
            fixed_z,
            window,
            u,
            add_config,
            add_incomplete_config,
        };
        if config.add_config.x_p != config.add_incomplete_config.x_p
            || config.add_config.y_p != config.add_incomplete_config.y_p
        {
            return Err(Halo2Error::operation_failed(
                "mul_fixed::configure",
                "config mismatch",
            ));
        }
        for advice in [config.window, config.u] {
            if advice == config.add_config.x_qr || advice == config.add_config.y_qr {
                return Err(Halo2Error::operation_failed(
                    "mul_fixed::configure",
                    "overlap",
                ));
            }
        }
        config.running_sum_coords_gate(meta)?;
        Ok(config)
    }

    fn running_sum_coords_gate(&self, meta: &mut ConstraintSystem) -> Halo2Result<()> {
        meta.create_gate(&mut |meta: &mut VirtualCells<'_>| {
            let q = meta.query_selector(self.running_sum_config.q_range_check);
            let z_cur = meta.query_advice(self.window, Rotation::cur());
            let z_next = meta.query_advice(self.window, Rotation::next());
            let word = z_cur.try_sub(&z_next.scale(PallasFp::from_u64(H as u64)))?;
            Ok(Constraints {
                selector: Some(q),
                constraints: self.coords_check(meta, word)?,
            })
        })
    }

    pub fn coords_check(
        &self,
        meta: &mut VirtualCells<'_>,
        window: Expression,
    ) -> Halo2Result<Vec<Expression>> {
        let y_p = meta.query_advice(self.add_config.y_p, Rotation::cur());
        let x_p = meta.query_advice(self.add_config.x_p, Rotation::cur());
        let z = meta.query_fixed(self.fixed_z);
        let u = meta.query_advice(self.u, Rotation::cur());
        // window_pow[i] = window^i.
        let mut window_pow = Expression::constant(PallasFp::one());
        let mut interpolated = Expression::constant(PallasFp::zero());
        for col in self.lagrange_coeffs.iter().take(H) {
            let c = meta.query_fixed(*col);
            interpolated = interpolated.try_add(&window_pow.try_mul_expr(&c)?)?;
            window_pow = window_pow.try_mul_expr(&window)?;
        }
        let x_check = interpolated.try_sub(&x_p)?;
        let y_check = u.square()?.try_sub(&y_p)?.try_sub(&z)?;
        let on_curve = y_p
            .square()?
            .try_sub(&x_p.square()?.try_mul_expr(&x_p)?)?
            .try_sub(&Expression::constant(PallasFp::from_u64(5)))?;
        Ok(vec![x_check, y_check, on_curve])
    }

    pub fn assign_region_inner<B: FixedBase>(
        &self,
        region: &mut Region<'_>,
        offset: usize,
        scalar: ScalarFixed,
        base: &B,
        coords_toggle: Selector,
    ) -> Halo2Result<(EccPoint, EccPoint)> {
        self.assign_fixed_constants(region, offset, base, coords_toggle)?;
        let mut acc = self.initialize_accumulator(region, offset, base, &scalar)?;
        acc = self.add_incomplete(region, offset, acc, base, &scalar)?;
        let mul_b = self.process_msb(region, offset, base, &scalar)?;
        Ok((acc, mul_b))
    }

    pub fn add_incomplete<B: FixedBase>(
        &self,
        region: &mut Region<'_>,
        offset: usize,
        mut acc: EccPoint,
        base: &B,
        scalar: &ScalarFixed,
    ) -> Halo2Result<EccPoint> {
        let fields = scalar.windows_field()?;
        let usizes = scalar.windows_usize()?;
        if fields.len() != base.num_windows() {
            return Err(Halo2Error::operation_failed(
                "mul_fixed::add_incomplete",
                "window count",
            ));
        }
        for w in 1..base.num_windows().saturating_sub(1) {
            let mul_b = self.process_lower_bits(region, offset, w, fields[w], usizes[w], base)?;
            acc = self
                .add_incomplete_config
                .assign_region(&mul_b, &acc, offset + w, region)?;
        }
        Ok(acc)
    }

    pub fn assign_fixed_constants<B: FixedBase>(
        &self,
        region: &mut Region<'_>,
        offset: usize,
        base: &B,
        coords_toggle: Selector,
    ) -> Halo2Result<()> {
        let lagrange = base.lagrange_le();
        let z = base.z();
        if lagrange.len() != base.num_windows() {
            return Err(Halo2Error::operation_failed(
                "mul_fixed::constants",
                "table size",
            ));
        }
        for (window, lag_row) in lagrange.iter().enumerate().take(base.num_windows()) {
            coords_toggle.enable(region, window + offset)?;
            for (k, col) in self.lagrange_coeffs.iter().enumerate().take(H) {
                let val = PallasFp::from_le_array(&lag_row[k])?;
                region.assign_fixed(*col, window + offset, &mut || Some(Assigned::Trivial(val)))?;
            }
            let zv = *z.get(window).ok_or_else(|| {
                Halo2Error::operation_failed("mul_fixed::constants", "z overflow")
            })?;
            region.assign_fixed(self.fixed_z, window + offset, &mut || {
                Some(Assigned::Trivial(PallasFp::from_u64(zv as u64)))
            })?;
        }
        Ok(())
    }

    pub fn process_window<B: FixedBase>(
        &self,
        region: &mut Region<'_>,
        offset: usize,
        w: usize,
        k_usize: Option<usize>,
        window_scalar: Option<VestaFq>,
        base: &B,
    ) -> Halo2Result<EccPoint> {
        // Generator from Montgomery limbs (unchecked trusted const; no decode).
        let gm = base.generator_mont();
        let gen_proj = PallasAffine::from_affine_mont_limbs(gm[0], gm[1]);
        let mut x_val: Option<Assigned> = None;
        let mut y_val: Option<Assigned> = None;
        if let Some(s) = window_scalar {
            // Single scalar mul (the old code evaluated it twice).
            let (ax, ay, ident) = gen_proj
                .mul_vartime(&PallasScalar::from_bytes_le(&s.to_le_bytes())?)
                .to_affine_le()?;
            if ident {
                return Err(Halo2Error::operation_failed(
                    "mul_fixed::window",
                    "identity",
                ));
            }
            let x = PallasFp::from_le_array(&ax)?;
            let y = PallasFp::from_le_array(&ay)?;
            if x.is_zero() || y.is_zero() {
                return Err(Halo2Error::operation_failed(
                    "mul_fixed::window",
                    "zero point",
                ));
            }
            x_val = Some(Assigned::Trivial(x));
            y_val = Some(Assigned::Trivial(y));
        }
        let x_cell = region.assign_advice(self.add_config.x_p, offset + w, &mut || x_val)?;
        let y_cell = region.assign_advice(self.add_config.y_p, offset + w, &mut || y_val)?;
        if let Some(k) = k_usize {
            let row = base.u_le(w)?;
            let uv = PallasFp::from_le_array(&row[k])?;
            region.assign_advice(self.u, offset + w, &mut || Some(uv))?;
        } else {
            region.assign_advice(self.u, offset + w, &mut || None::<PallasFp>)?;
        }
        Ok(EccPoint {
            x: x_cell,
            y: y_cell,
        })
    }

    pub fn initialize_accumulator<B: FixedBase>(
        &self,
        region: &mut Region<'_>,
        offset: usize,
        base: &B,
        scalar: &ScalarFixed,
    ) -> Halo2Result<EccPoint> {
        let fields = scalar.windows_field()?;
        let usizes = scalar.windows_usize()?;
        let k0 = fields.first().copied().flatten();
        let k0u = usizes.first().copied().flatten();
        self.process_lower_bits(region, offset, 0, k0, k0u, base)
    }

    pub fn process_lower_bits<B: FixedBase>(
        &self,
        region: &mut Region<'_>,
        offset: usize,
        w: usize,
        k: Option<VestaFq>,
        k_usize: Option<usize>,
        base: &B,
    ) -> Halo2Result<EccPoint> {
        let scalar: Option<VestaFq> = k.map(|v| {
            v.add_vartime(&VestaFq::from_u64(2))
                .mul_vartime(&VestaFq::from_u64(H as u64).pow_u64(w as u64))
        });
        self.process_window(region, offset, w, k_usize, scalar, base)
    }

    pub fn process_msb<B: FixedBase>(
        &self,
        region: &mut Region<'_>,
        offset: usize,
        base: &B,
        scalar: &ScalarFixed,
    ) -> Halo2Result<EccPoint> {
        let usizes = scalar.windows_usize()?;
        let fields = scalar.windows_field()?;
        let last = base.num_windows().saturating_sub(1);
        let k_usize = usizes.get(last).copied().flatten();
        let two = VestaFq::from_u64(2);
        let h = VestaFq::from_u64(H as u64);
        let mut acc_off = VestaFq::zero();
        for w in 0..last {
            acc_off = acc_off.add_vartime(&two.pow_u64((3 * w + 1) as u64));
        }
        let mut window_scalar: Option<VestaFq> = None;
        if let Some(Some(sc)) = fields.get(last) {
            window_scalar = Some(
                sc.mul_vartime(&h.pow_u64(last as u64))
                    .sub_vartime(&acc_off),
            );
        }
        self.process_window(region, offset, last, k_usize, window_scalar, base)
    }
}

// —— full-width ——

#[derive(Clone, Copy)]
pub struct MulFixedFullConfig {
    pub q_mul_fixed_full: Selector,
    pub super_config: MulFixedConfig,
}

impl MulFixedFullConfig {
    pub fn configure(
        meta: &mut ConstraintSystem,
        super_config: MulFixedConfig,
    ) -> Halo2Result<Self> {
        let config = Self {
            q_mul_fixed_full: meta.selector(),
            super_config,
        };
        config.create_gate(meta)?;
        Ok(config)
    }

    fn create_gate(&self, meta: &mut ConstraintSystem) -> Halo2Result<()> {
        meta.create_gate(&mut |meta: &mut VirtualCells<'_>| {
            let q = meta.query_selector(self.q_mul_fixed_full);
            let window = meta.query_advice(self.super_config.window, Rotation::cur());
            let mut constraints = self.super_config.coords_check(meta, window.clone())?;
            constraints.push(range_check_expr(window, H)?);
            Ok(Constraints {
                selector: Some(q),
                constraints,
            })
        })
    }

    pub fn decompose_scalar_fixed(
        &self,
        scalar: Option<VestaFq>,
        offset: usize,
        region: &mut Region<'_>,
    ) -> Halo2Result<Vec<AssignedCell<PallasFp>>> {
        for idx in 0..NUM_WINDOWS {
            self.q_mul_fixed_full.enable(region, offset + idx)?;
        }
        let windows: Vec<Option<PallasFp>> = match scalar {
            Some(s) => decompose_word_vesta(s, 255, 3)?
                .into_iter()
                .map(|w| Some(PallasFp::from_u64(w as u64)))
                .collect(),
            None => vec![None; NUM_WINDOWS],
        };
        if windows.len() != NUM_WINDOWS {
            return Err(Halo2Error::operation_failed(
                "mul_fixed::decompose",
                "window count",
            ));
        }
        let mut out = Vec::with_capacity(NUM_WINDOWS);
        for (idx, w) in windows.into_iter().enumerate() {
            out.push(region.assign_advice(self.super_config.window, offset + idx, &mut || w)?);
        }
        Ok(out)
    }

    pub fn witness(
        &self,
        region: &mut Region<'_>,
        offset: usize,
        scalar: Option<VestaFq>,
    ) -> Halo2Result<EccScalarFixed> {
        let windows = self.decompose_scalar_fixed(scalar, offset, region)?;
        EccScalarFixed::with_windows(scalar, windows)
    }

    pub fn assign<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        scalar: EccScalarFixed,
        base: FullBase,
    ) -> Halo2Result<(EccPoint, EccScalarFixed)> {
        let out = layouter.assign_region(&mut |region: &mut Region<'_>| {
            let witnessed = match &scalar.windows {
                None => self.witness(region, 0, scalar.value)?,
                Some(_) => {
                    return Err(Halo2Error::operation_failed(
                        "mul_fixed::assign",
                        "pre-witnessed",
                    ));
                }
            };
            let (acc, mul_b) = self.super_config.assign_region_inner(
                region,
                0,
                ScalarFixed::FullWidth(witnessed.clone()),
                &base,
                self.q_mul_fixed_full,
            )?;
            Ok((witnessed, acc, mul_b))
        })?;
        let (witnessed, acc, mul_b) = out;
        let result = layouter.assign_region(&mut |region: &mut Region<'_>| {
            self.super_config
                .add_config
                .assign_region(&mul_b, &acc, 0, region)
        })?;
        Ok((result, witnessed))
    }
}

// —— short ——

#[derive(Clone, Copy)]
pub struct MulFixedShortConfig {
    pub q_mul_fixed_short: Selector,
    pub super_config: MulFixedConfig,
}

impl MulFixedShortConfig {
    pub fn configure(
        meta: &mut ConstraintSystem,
        super_config: MulFixedConfig,
    ) -> Halo2Result<Self> {
        let config = Self {
            q_mul_fixed_short: meta.selector(),
            super_config,
        };
        config.create_gate(meta)?;
        Ok(config)
    }

    fn create_gate(&self, meta: &mut ConstraintSystem) -> Halo2Result<()> {
        meta.create_gate(&mut |meta: &mut VirtualCells<'_>| {
            let q = meta.query_selector(self.q_mul_fixed_short);
            let y_p = meta.query_advice(self.super_config.add_config.y_p, Rotation::cur());
            let y_a = meta.query_advice(self.super_config.add_config.y_qr, Rotation::cur());
            let last_window = meta.query_advice(self.super_config.u, Rotation::cur());
            let sign = meta.query_advice(self.super_config.window, Rotation::cur());
            let one = Expression::constant(PallasFp::one());
            let last_check = bool_check_expr(last_window)?;
            let sign_check = sign.square()?.try_sub(&one)?;
            let y_check = y_p.try_sub(&y_a)?.try_mul_expr(&y_p.try_add(&y_a)?)?;
            let neg_check = sign.try_mul_expr(&y_p)?.try_sub(&y_a)?;
            Ok(Constraints {
                selector: Some(q),
                constraints: vec![last_check, sign_check, y_check, neg_check],
            })
        })
    }

    pub fn assign_scalar_sign<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        sign: &AssignedCell<PallasFp>,
        point: &EccPoint,
    ) -> Halo2Result<EccPoint> {
        layouter.assign_region(&mut |region: &mut Region<'_>| {
            self.q_mul_fixed_short.enable(region, 0)?;
            region.assign_advice_from_constant(self.super_config.u, 0, PallasFp::zero())?;
            sign.copy_advice(region, self.super_config.window, 0)?;
            point
                .y
                .copy_advice(region, self.super_config.add_config.y_qr, 0)?;
            let signed_y: Option<Assigned> = match (sign.value, point.y.value) {
                (Some(s), Some(y)) => {
                    if s == PallasFp::one().neg() {
                        Some(y.neg())
                    } else {
                        Some(y)
                    }
                }
                _ => None,
            };
            let y_cell =
                region.assign_advice(self.super_config.add_config.y_p, 0, &mut || signed_y)?;
            Ok(EccPoint {
                x: point.x,
                y: y_cell,
            })
        })
    }

    pub fn decompose(
        &self,
        region: &mut Region<'_>,
        offset: usize,
        magnitude: &AssignedCell<PallasFp>,
        sign: &AssignedCell<PallasFp>,
    ) -> Halo2Result<EccScalarFixedShort> {
        let running_sum = self.super_config.running_sum_config.copy_decompose(
            region,
            offset,
            magnitude,
            true,
            L_SCALAR_SHORT,
            NUM_WINDOW_SHORT,
        )?;
        EccScalarFixedShort::with_running_sum(*magnitude, *sign, running_sum)
            .map_err(|_| Halo2Error::operation_failed("mul_fixed::decompose", "bad sum"))
    }

    pub fn assign<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        scalar: EccScalarFixedShort,
        base: ValueCommitV,
    ) -> Halo2Result<(EccPoint, EccScalarFixedShort)> {
        let out = layouter.assign_region(&mut |region: &mut Region<'_>| {
            let decomposed = match &scalar.running_sum {
                None => self.decompose(region, 0, &scalar.magnitude, &scalar.sign)?,
                Some(_) => {
                    return Err(Halo2Error::operation_failed(
                        "mul_fixed::assign",
                        "pre-witnessed",
                    ));
                }
            };
            let (acc, mul_b) = self.super_config.assign_region_inner(
                region,
                0,
                ScalarFixed::Short(decomposed.clone()),
                &base,
                self.super_config.running_sum_config.q_range_check,
            )?;
            Ok((decomposed, acc, mul_b))
        })?;
        let (decomposed, acc, mul_b) = out;
        let result = layouter.assign_region(&mut |region: &mut Region<'_>| {
            let magnitude_mul = self
                .super_config
                .add_config
                .assign_region(&mul_b, &acc, 0, region)?;
            let sign_cell = decomposed
                .sign
                .copy_advice(region, self.super_config.window, 1)?;
            let z21 = decomposed
                .running_sum
                .as_ref()
                .and_then(|rs| rs.get(21).copied());
            match z21 {
                Some(z) => {
                    z.copy_advice(region, self.super_config.u, 1)?;
                }
                None => {
                    region.assign_advice(self.super_config.u, 1, &mut || None::<PallasFp>)?;
                }
            }
            let y_val: Option<Assigned> = match (sign_cell.value, magnitude_mul.y.value) {
                (Some(s), Some(y)) => {
                    if s == PallasFp::one().neg() {
                        Some(y.neg())
                    } else {
                        Some(y)
                    }
                }
                _ => None,
            };
            self.q_mul_fixed_short.enable(region, 1)?;
            let y_var = region.assign_advice(self.super_config.add_config.y_p, 1, &mut || y_val)?;
            Ok(EccPoint {
                x: magnitude_mul.x,
                y: y_var,
            })
        })?;
        Ok((result, decomposed))
    }
}

// —— base-field ——

#[derive(Clone, Copy)]
pub struct MulFixedBaseFieldConfig {
    pub q_mul_fixed_base_field: Selector,
    pub canon_advices: [AssignmentColumn; 3],
    pub lookup_config: LookupRangeCheckConfig,
    pub super_config: MulFixedConfig,
}

impl MulFixedBaseFieldConfig {
    pub fn configure(
        meta: &mut ConstraintSystem,
        canon_advices: [AssignmentColumn; 3],
        lookup_config: LookupRangeCheckConfig,
        super_config: MulFixedConfig,
    ) -> Halo2Result<Self> {
        for a in canon_advices.iter() {
            meta.enable_equality(*a);
        }
        let incomplete_cols = [
            super_config.add_incomplete_config.x_p,
            super_config.add_incomplete_config.y_p,
            super_config.add_incomplete_config.x_qr,
            super_config.add_incomplete_config.y_qr,
        ];
        for c in canon_advices.iter() {
            if incomplete_cols.contains(c) {
                return Err(Halo2Error::operation_failed("mul_fixed::canon", "overlap"));
            }
        }
        let config = Self {
            q_mul_fixed_base_field: meta.selector(),
            canon_advices,
            lookup_config,
            super_config,
        };
        config.create_gate(meta)?;
        Ok(config)
    }

    fn create_gate(&self, meta: &mut ConstraintSystem) -> Halo2Result<()> {
        meta.create_gate(&mut |meta: &mut VirtualCells<'_>| {
            let q = meta.query_selector(self.q_mul_fixed_base_field);
            let alpha = meta.query_advice(self.canon_advices[0], Rotation { location: -1 });
            let z84 = meta.query_advice(self.canon_advices[2], Rotation { location: -1 });
            let alpha1 = meta.query_advice(self.canon_advices[1], Rotation::cur());
            let alpha2 = meta.query_advice(self.canon_advices[2], Rotation::cur());
            let alpha0_prime = meta.query_advice(self.canon_advices[0], Rotation::cur());
            let z13 = meta.query_advice(self.canon_advices[0], Rotation::next());
            let z44 = meta.query_advice(self.canon_advices[1], Rotation::next());
            let z43 = meta.query_advice(self.canon_advices[2], Rotation::next());

            let alpha0 =
                alpha.try_sub(&z84.scale(PallasFp::from_u64(2).pow_u64(126).square_vartime()))?;
            let alpha1_range = range_check_expr(alpha1.clone(), 1 << 2)?;
            let alpha2_range = bool_check_expr(alpha2.clone())?;
            let z84_check = z84.try_sub(&alpha1.try_add(&alpha2.scale(PallasFp::from_u64(4)))?)?;
            let two_pow_130 = Expression::constant(PallasFp::from_u64(2).pow_u64(130));
            let t_p = Expression::constant(PallasFp::from_le_array(
                &crate::zk::orchard_halo2::field::T_P_LE,
            )?);
            let alpha0_prime_check =
                alpha0_prime.try_sub(&alpha0.try_add(&two_pow_130)?.try_sub(&t_p)?)?;
            let pow60 = PallasFp::from_u64(2).pow_u64(60);
            let alpha0_hi120 =
                z44.try_sub(&z84.try_mul_expr(&Expression::constant(pow60.square_vartime()))?)?;
            let a43 = z43.try_sub(&z44.scale(PallasFp::from_u64(H as u64)))?;
            let canon: Vec<Expression> = vec![
                alpha2.try_mul_expr(&alpha1)?,
                alpha2.try_mul_expr(&alpha0_hi120)?,
                alpha2.try_mul_expr(&bool_check_expr(a43)?)?,
                alpha2.try_mul_expr(&z13)?,
            ];
            let mut constraints = canon;
            constraints.push(alpha1_range);
            constraints.push(alpha2_range);
            constraints.push(z84_check);
            constraints.push(alpha0_prime_check);
            Ok(Constraints {
                selector: Some(q),
                constraints,
            })
        })
    }

    pub fn assign<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        scalar: &AssignedCell<PallasFp>,
        base: NullifierK,
    ) -> Halo2Result<EccPoint> {
        let (ecc_scalar, acc, mul_b) = layouter.assign_region(&mut |region: &mut Region<'_>| {
            let running_sum = self.super_config.running_sum_config.copy_decompose(
                region,
                0,
                scalar,
                true,
                255,
                base.num_windows(),
            )?;
            let ecc_scalar = EccBaseFieldElemFixed::new(running_sum[0], running_sum)
                .map_err(|_| Halo2Error::operation_failed("mul_fixed::canon", "bad sum"))?;
            let (acc, mul_b) = self.super_config.assign_region_inner(
                region,
                0,
                ScalarFixed::BaseFieldElem(ecc_scalar.clone()),
                &base,
                self.super_config.running_sum_config.q_range_check,
            )?;
            Ok((ecc_scalar, acc, mul_b))
        })?;
        let result = layouter.assign_region(&mut |region: &mut Region<'_>| {
            self.super_config
                .add_config
                .assign_region(&mul_b, &acc, 0, region)
        })?;
        let alpha = ecc_scalar.base_field_elem;
        let running_sum = ecc_scalar.running_sum.clone();
        let (z43, z44, z84) = (
            running_sum.get(43).copied(),
            running_sum.get(44).copied(),
            running_sum.get(84).copied(),
        );
        let (z43, z44, z84) = match (z43, z44, z84) {
            (Some(a), Some(b), Some(c)) => (a, b, c),
            _ => {
                return Err(Halo2Error::operation_failed(
                    "mul_fixed::canon",
                    "missing z",
                ));
            }
        };
        let alpha0: Option<PallasFp> = match (alpha.value, z84.value) {
            (Some(a), Some(z)) => Some(
                a.sub_vartime(&z.mul_vartime(&PallasFp::from_u64(2).pow_u64(126).square_vartime())),
            ),
            _ => None,
        };
        let alpha0_prime: Option<PallasFp> = alpha0.map(|a| {
            a.add_vartime(&PallasFp::from_u64(2).pow_u64(130))
                .sub_vartime(
                    &PallasFp::from_le_array(&crate::zk::orchard_halo2::field::T_P_LE)
                        .unwrap_or(PallasFp::zero()),
                )
        });
        let zs = self
            .lookup_config
            .witness_check(layouter, alpha0_prime, 13, false)?;
        let z13 = zs
            .get(13)
            .copied()
            .ok_or_else(|| Halo2Error::operation_failed("mul_fixed::canon", "missing z13"))?;
        let alpha0_prime_cell = zs
            .first()
            .copied()
            .ok_or_else(|| Halo2Error::operation_failed("mul_fixed::canon", "missing alpha0"))?;
        layouter.assign_region(&mut |region: &mut Region<'_>| {
            self.q_mul_fixed_base_field.enable(region, 1)?;
            alpha.copy_advice(region, self.canon_advices[0], 0)?;
            z84.copy_advice(region, self.canon_advices[2], 0)?;
            alpha0_prime_cell.copy_advice(region, self.canon_advices[0], 1)?;
            let alpha1: Option<PallasFp> = alpha
                .value
                .map(|a| bitrange_subset(a, 252, 254).unwrap_or(PallasFp::zero()));
            region.assign_advice(self.canon_advices[1], 1, &mut || alpha1)?;
            let alpha2: Option<PallasFp> = alpha
                .value
                .map(|a| bitrange_subset(a, 254, 255).unwrap_or(PallasFp::zero()));
            region.assign_advice(self.canon_advices[2], 1, &mut || alpha2)?;
            z13.copy_advice(region, self.canon_advices[0], 2)?;
            z44.copy_advice(region, self.canon_advices[1], 2)?;
            z43.copy_advice(region, self.canon_advices[2], 2)?;
            Ok(())
        })?;
        Ok(result)
    }
}
