//! Implements chip/ecc logic — types first, `EccConfig` wiring after the
//! sub-chips land. `EccPoint` holds `Assigned` cells (exact semantics).

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

use crate::zk::orchard_halo2::error::{Halo2Error, Halo2Result};
use crate::zk::orchard_halo2::field::{PallasFp, VestaFq};
use crate::zk::orchard_halo2::plonk::assigned::Assigned;
use crate::zk::orchard_halo2::utility::layouter::{AssignedCell, Layouter, Region};

pub type MagnitudeCell = AssignedCell<PallasFp>;
pub type SignCell = AssignedCell<PallasFp>;

#[derive(Clone)]
pub struct EccPoint {
    pub x: AssignedCell<Assigned>,
    pub y: AssignedCell<Assigned>,
}

impl EccPoint {
    pub fn get_x(&self) -> AssignedCell<PallasFp> {
        AssignedCell {
            value: self.x.value.as_ref().map(|v| v.evaluate()),
            cell: self.x.cell,
        }
    }

    pub fn get_y(&self) -> AssignedCell<PallasFp> {
        AssignedCell {
            value: self.y.value.as_ref().map(|v| v.evaluate()),
            cell: self.y.cell,
        }
    }

    /// To affine pair; zero coordinates → Err (never infinity in circuit).
    pub fn to_point(&self) -> Halo2Result<Option<(PallasFp, PallasFp)>> {
        match (self.x.value, self.y.value) {
            (Some(x), Some(y)) => {
                let xv = x.evaluate();
                let yv = y.evaluate();
                if xv.is_zero() || yv.is_zero() {
                    return Err(Halo2Error::operation_failed(
                        "ecc::to_point",
                        "identity point",
                    ));
                }
                Ok(Some((xv, yv)))
            }
            _ => Ok(None),
        }
    }

    #[cfg(feature = "alloc")]
    pub fn to_debug_string(&self) -> String {
        alloc::string::String::from("EccPoint")
    }
}

#[derive(Clone)]
pub enum ScalarVar {
    BaseFieldElem(ScalarVarBaseFieldElem),
    FullWidth,
}

#[derive(Clone)]
pub struct ScalarVarBaseFieldElem {
    pub cell: AssignedCell<PallasFp>,
}

#[derive(Clone)]
pub struct EccScalarFixed {
    pub value: Option<VestaFq>,
    pub windows: Option<Vec<AssignedCell<PallasFp>>>,
}

impl EccScalarFixed {
    pub fn new(value: Option<VestaFq>) -> Self {
        Self {
            value,
            windows: None,
        }
    }

    pub fn with_windows(
        value: Option<VestaFq>,
        windows: Vec<AssignedCell<PallasFp>>,
    ) -> Halo2Result<Self> {
        if windows.len() != 85 {
            return Err(Halo2Error::operation_failed(
                "ecc::scalar_fixed",
                "bad windows",
            ));
        }
        Ok(Self {
            value,
            windows: Some(windows),
        })
    }
}

#[derive(Clone)]
pub struct EccScalarFixedShort {
    pub magnitude: MagnitudeCell,
    pub sign: SignCell,
    pub running_sum: Option<Vec<AssignedCell<PallasFp>>>,
}

impl EccScalarFixedShort {
    pub fn new(magnitude: MagnitudeCell, sign: SignCell) -> Self {
        Self {
            magnitude,
            sign,
            running_sum: None,
        }
    }

    pub fn with_running_sum(
        magnitude: MagnitudeCell,
        sign: SignCell,
        running_sum: Vec<AssignedCell<PallasFp>>,
    ) -> Halo2Result<Self> {
        if running_sum.len() != 23 {
            return Err(Halo2Error::operation_failed(
                "ecc::scalar_short",
                "bad running sum",
            ));
        }
        Ok(Self {
            magnitude,
            sign,
            running_sum: Some(running_sum),
        })
    }
}

#[derive(Clone)]
pub struct EccBaseFieldElemFixed {
    pub base_field_elem: AssignedCell<PallasFp>,
    pub running_sum: Vec<AssignedCell<PallasFp>>,
}

impl EccBaseFieldElemFixed {
    pub fn new(
        base_field_elem: AssignedCell<PallasFp>,
        running_sum: Vec<AssignedCell<PallasFp>>,
    ) -> Halo2Result<Self> {
        if running_sum.len() != 86 {
            return Err(Halo2Error::operation_failed(
                "ecc::base_field",
                "bad running sum",
            ));
        }
        Ok(Self {
            base_field_elem,
            running_sum,
        })
    }
}

// —— EccConfig (chip aggregator) ——

use crate::zk::orchard_halo2::chip::add::{AddConfig, AddIncompleteConfig};
use crate::zk::orchard_halo2::chip::lookup::LookupRangeCheckConfig;
use crate::zk::orchard_halo2::chip::mul::MulConfig;
use crate::zk::orchard_halo2::chip::mul_fixed::{
    MulFixedBaseFieldConfig, MulFixedConfig, MulFixedFullConfig, MulFixedShortConfig,
};
use crate::zk::orchard_halo2::chip::witness::WitnessPointConfig;
use crate::zk::orchard_halo2::curve::PallasAffine;
use crate::zk::orchard_halo2::orchard::constants::fixed_bases::{
    FullBase, NullifierK, ValueCommitV,
};
use crate::zk::orchard_halo2::plonk::column::AssignmentColumn;
use crate::zk::orchard_halo2::plonk::constraint::ConstraintSystem;

#[derive(Clone, Copy)]
pub struct EccConfig {
    pub add_incomplete_config: AddIncompleteConfig,
    pub add_config: AddConfig,
    pub mul_config: MulConfig,
    pub mul_fixed_full_config: MulFixedFullConfig,
    pub mul_fixed_short_config: MulFixedShortConfig,
    pub mul_fixed_base_field_config: MulFixedBaseFieldConfig,
    pub witness_point_config: WitnessPointConfig,
    pub lookup_config: LookupRangeCheckConfig,
}

impl EccConfig {
    pub fn configure(
        meta: &mut ConstraintSystem,
        advices: [AssignmentColumn; 10],
        lagrange_coeffs: [AssignmentColumn; 8],
        range_check: LookupRangeCheckConfig,
    ) -> Halo2Result<Self> {
        let witness_point = WitnessPointConfig::configure(meta, advices[0], advices[1])?;
        let add_incomplete =
            AddIncompleteConfig::configure(meta, advices[0], advices[1], advices[2], advices[3])?;
        let add = AddConfig::configure(
            meta, advices[0], advices[1], advices[2], advices[3], advices[4], advices[5],
            advices[6], advices[7], advices[8],
        )?;
        let mul = MulConfig::configure(meta, add, range_check, advices)?;
        let mul_fixed = MulFixedConfig::configure(
            meta,
            lagrange_coeffs,
            advices[4],
            advices[5],
            add,
            add_incomplete,
        )?;
        let mul_fixed_full = MulFixedFullConfig::configure(meta, mul_fixed)?;
        let mul_fixed_short = MulFixedShortConfig::configure(meta, mul_fixed)?;
        let mul_fixed_base_field = MulFixedBaseFieldConfig::configure(
            meta,
            [advices[6], advices[7], advices[8]],
            range_check,
            mul_fixed,
        )?;
        Ok(Self {
            add_incomplete_config: add_incomplete,
            add_config: add,
            mul_config: mul,
            mul_fixed_full_config: mul_fixed_full,
            mul_fixed_short_config: mul_fixed_short,
            mul_fixed_base_field_config: mul_fixed_base_field,
            witness_point_config: witness_point,
            lookup_config: range_check,
        })
    }

    pub fn constrain_equal<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        a: &EccPoint,
        b: &EccPoint,
    ) -> Halo2Result<()> {
        layouter.assign_region(&mut |region: &mut Region<'_>| {
            region.constrain_equal(a.get_x().cell, b.get_x().cell)?;
            region.constrain_equal(a.get_y().cell, b.get_y().cell)
        })
    }

    pub fn witness_point<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        value: Option<PallasAffine>,
    ) -> Halo2Result<EccPoint> {
        layouter.assign_region(&mut |region: &mut Region<'_>| {
            self.witness_point_config.point(value, 0, region)
        })
    }

    pub fn witness_point_from_constant<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        value: PallasAffine,
    ) -> Halo2Result<EccPoint> {
        layouter.assign_region(&mut |region: &mut Region<'_>| {
            self.witness_point_config.constant_point(value, 0, region)
        })
    }

    pub fn witness_point_non_id<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        value: Option<PallasAffine>,
    ) -> Halo2Result<EccPoint> {
        layouter.assign_region(&mut |region: &mut Region<'_>| {
            self.witness_point_config.point_non_id(value, 0, region)
        })
    }

    pub fn witness_scalar_fixed(&self, value: Option<VestaFq>) -> EccScalarFixed {
        EccScalarFixed::new(value)
    }

    pub fn scalar_fixed_from_signed_short(
        &self,
        magnitude: MagnitudeCell,
        sign: SignCell,
    ) -> EccScalarFixedShort {
        EccScalarFixedShort::new(magnitude, sign)
    }

    pub fn extract_p(&self, point: &EccPoint) -> AssignedCell<PallasFp> {
        point.get_x()
    }

    pub fn add_incomplete<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        a: &EccPoint,
        b: &EccPoint,
    ) -> Halo2Result<EccPoint> {
        layouter.assign_region(&mut |region: &mut Region<'_>| {
            self.add_incomplete_config.assign_region(a, b, 0, region)
        })
    }

    pub fn add<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        a: &EccPoint,
        b: &EccPoint,
    ) -> Halo2Result<EccPoint> {
        layouter.assign_region(&mut |region: &mut Region<'_>| {
            self.add_config.assign_region(a, b, 0, region)
        })
    }

    pub fn mul_sign<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        sign: &AssignedCell<PallasFp>,
        point: &EccPoint,
    ) -> Halo2Result<EccPoint> {
        self.mul_fixed_short_config
            .assign_scalar_sign(layouter, sign, point)
    }

    pub fn mul<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        scalar: &AssignedCell<PallasFp>,
        base: &EccPoint,
        anchored: bool,
    ) -> Halo2Result<(EccPoint, ScalarVar)> {
        let (point, _) = self
            .mul_config
            .assign(layouter, *scalar, base, anchored)?;
        Ok((
            point,
            ScalarVar::BaseFieldElem(
                crate::zk::orchard_halo2::chip::ecc::ScalarVarBaseFieldElem {
                    cell: *scalar,
                },
            ),
        ))
    }

    pub fn mul_fixed<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        scalar: EccScalarFixed,
        base: FullBase,
    ) -> Halo2Result<(EccPoint, EccScalarFixed)> {
        self.mul_fixed_full_config.assign(layouter, scalar, base)
    }

    pub fn mul_fixed_short<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        scalar: EccScalarFixedShort,
        base: ValueCommitV,
    ) -> Halo2Result<(EccPoint, EccScalarFixedShort)> {
        self.mul_fixed_short_config.assign(layouter, scalar, base)
    }

    pub fn mul_fixed_base_field_elem<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        scalar: &AssignedCell<PallasFp>,
        base: NullifierK,
    ) -> Halo2Result<EccPoint> {
        self.mul_fixed_base_field_config
            .assign(layouter, scalar, base)
    }

    pub fn scalar_var_from_base(&self, cell: AssignedCell<PallasFp>) -> ScalarVar {
        ScalarVar::BaseFieldElem(ScalarVarBaseFieldElem { cell })
    }
}

#[derive(Clone)]
pub struct EccPointWithConfig {
    pub chip: EccConfig,
    pub inner: EccPoint,
}

impl EccPointWithConfig {
    pub fn extract_p(&self) -> AssignedCell<PallasFp> {
        self.inner.get_x()
    }

    pub fn add<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        other: &EccPointWithConfig,
    ) -> Halo2Result<EccPointWithConfig> {
        Ok(EccPointWithConfig {
            chip: self.chip,
            inner: self.chip.add(layouter, &self.inner, &other.inner)?,
        })
    }

    pub fn constrain_equal<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        other: &EccPointWithConfig,
    ) -> Halo2Result<()> {
        self.chip
            .constrain_equal(layouter, &self.inner, &other.inner)
    }
}
