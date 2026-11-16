//! Implements chip/lookup logic (lookup range-check + running sum).
//! `assert!` on lengths becomes `Err`; `invert()!` (provably non-zero)
//! propagates as `Err` instead of panicking.

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

use crate::zk::orchard_halo2::curve::PallasAffine;
use crate::zk::orchard_halo2::error::{Halo2Error, Halo2Result};
use crate::zk::orchard_halo2::field::PallasFp;
use crate::zk::orchard_halo2::plonk::assigned::Assigned;
use crate::zk::orchard_halo2::plonk::column::{AssignmentColumn, Selector, TableColumn};
use crate::zk::orchard_halo2::plonk::constraint::{ConstraintSystem, Constraints, VirtualCells};
use crate::zk::orchard_halo2::plonk::expression::Expression;
use crate::zk::orchard_halo2::poly::poly::Rotation;
use crate::zk::orchard_halo2::sinsemilla::table::GeneratorTableConfig;
use crate::zk::orchard_halo2::utility::layouter::{AssignedCell, Layouter, Region};
use crate::zk::orchard_halo2::utility::range_constrained::RangeConstrained;
use crate::zk::orchard_halo2::utility::utils::{
    bitrange_subset, decompose_word, range_check_expr, PALLAS_CAPACITY_BITS, SINSEMILLA_K,
};

#[derive(Clone, Copy)]
pub struct LookupRangeCheckConfig {
    pub q_lookup: Selector,
    pub q_running: Selector,
    pub q_bitshift: Selector,
    pub running_sum: AssignmentColumn,
    pub table_idx: TableColumn,
}

impl LookupRangeCheckConfig {
    pub fn configure(
        meta: &mut ConstraintSystem,
        running_sum: AssignmentColumn,
        table_idx: TableColumn,
        _k: u32,
    ) -> Halo2Result<Self> {
        meta.enable_equality(running_sum);
        let config = Self {
            q_lookup: meta.complex_selector(),
            q_running: meta.complex_selector(),
            q_bitshift: meta.selector(),
            running_sum,
            table_idx,
        };
        let one = Expression::constant(PallasFp::one());
        meta.lookup(&mut |meta: &mut VirtualCells<'_>| {
            let q_lookup = meta.query_selector(config.q_lookup);
            let q_running = meta.query_selector(config.q_running);
            let z_cur = meta.query_advice(config.running_sum, Rotation::cur());
            let z_next = meta.query_advice(config.running_sum, Rotation::next());
            let running_word =
                z_cur.try_sub(&z_next.scale(PallasFp::from_u64(1u64 << SINSEMILLA_K)))?;
            let running_lookup = q_running.try_mul_expr(&running_word)?;
            let short_lookup = one.try_sub(&q_running)?.try_mul_expr(&z_cur)?;
            Ok(vec![(
                q_lookup.try_mul_expr(&running_lookup.try_add(&short_lookup)?)?,
                config.table_idx,
            )])
        })?;
        meta.create_gate(&mut |meta: &mut VirtualCells<'_>| {
            let q = meta.query_selector(config.q_bitshift);
            let word = meta.query_advice(config.running_sum, Rotation { location: -1 });
            let shifted = meta.query_advice(config.running_sum, Rotation::cur());
            let inv = meta.query_advice(config.running_sum, Rotation::next());
            let constraint = word
                .scale(PallasFp::from_u64(1u64 << SINSEMILLA_K))
                .try_mul_expr(&inv)?
                .try_sub(&shifted)?;
            Ok(Constraints {
                selector: Some(q),
                constraints: vec![constraint],
            })
        })?;
        Ok(config)
    }

    /// Fill the generator table (idx, x, y) for all of `sinsemilla_s`.
    pub fn load_table<L: Layouter + ?Sized>(
        &self,
        table_config: &GeneratorTableConfig,
        layouter: &mut L,
        sinsemilla_s: &[PallasAffine],
    ) -> Halo2Result<()> {
        let _ = self;
        layouter.assign_table(&mut |table| {
            for (index, point) in sinsemilla_s.iter().enumerate() {
                let (xb, yb, _) = point.to_affine_le()?;
                let x = PallasFp::from_le_array(&xb)?;
                let y = PallasFp::from_le_array(&yb)?;
                table.assign_cell(table_config.table_idx, index, &mut || {
                    Some(Assigned::Trivial(PallasFp::from_u64(index as u64)))
                })?;
                table.assign_cell(table_config.table_x, index, &mut || {
                    Some(Assigned::Trivial(x))
                })?;
                table.assign_cell(table_config.table_y, index, &mut || {
                    Some(Assigned::Trivial(y))
                })?;
            }
            Ok(())
        })
    }

    pub fn copy_check<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        element: &AssignedCell<PallasFp>,
        num_words: usize,
        strict: bool,
    ) -> Halo2Result<Vec<AssignedCell<PallasFp>>> {
        layouter.assign_region(&mut |region: &mut Region<'_>| {
            let z0 = element.copy_advice(region, self.running_sum, 0)?;
            self.range_check(region, &z0, num_words, strict)
        })
    }

    pub fn witness_check<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        value: Option<PallasFp>,
        num_words: usize,
        strict: bool,
    ) -> Halo2Result<Vec<AssignedCell<PallasFp>>> {
        layouter.assign_region(&mut |region: &mut Region<'_>| {
            let z0 = region.assign_advice(self.running_sum, 0, &mut || value)?;
            self.range_check(region, &z0, num_words, strict)
        })
    }

    pub fn range_check(
        &self,
        region: &mut Region<'_>,
        element: &AssignedCell<PallasFp>,
        num_words: usize,
        strict: bool,
    ) -> Halo2Result<Vec<AssignedCell<PallasFp>>> {
        if num_words * SINSEMILLA_K > PALLAS_CAPACITY_BITS {
            return Err(Halo2Error::operation_failed(
                "lookup::range_check",
                "too many bits",
            ));
        }
        let num_bits = num_words * SINSEMILLA_K;
        let mut words: Vec<Option<PallasFp>> = vec![None; num_words];
        if let Some(v) = element.value {
            let mut bits = [false; 256];
            v.to_bits_le(&mut bits);
            for (i, w) in words.iter_mut().enumerate() {
                let mut acc = PallasFp::zero();
                for b in (0..SINSEMILLA_K).rev() {
                    acc = acc.double();
                    if bits[i * SINSEMILLA_K + b] {
                        acc = acc.add_vartime(&PallasFp::one());
                    }
                }
                *w = Some(acc);
            }
            let _ = num_bits;
        }
        let mut zs: Vec<AssignedCell<PallasFp>> = vec![*element];
        let mut z = *element;
        let inv_two_pow_k = PallasFp::from_u64(1u64 << SINSEMILLA_K).invert()?;
        for (idx, word) in words.into_iter().enumerate() {
            self.q_lookup.enable(region, idx)?;
            self.q_running.enable(region, idx)?;
            let z_next_val: Option<PallasFp> = match (z.value, word) {
                (Some(zv), Some(w)) => Some(zv.sub_vartime(&w).mul_vartime(&inv_two_pow_k)),
                _ => None,
            };
            z = region.assign_advice(self.running_sum, idx + 1, &mut || z_next_val)?;
            zs.push(z);
        }
        if strict {
            let last = zs
                .last()
                .ok_or_else(|| Halo2Error::operation_failed("lookup::range_check", "empty zs"))?;
            region.constrain_constant(last.cell, Assigned::Trivial(PallasFp::zero()))?;
        }
        Ok(zs)
    }

    pub fn witness_short<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        value: Option<PallasFp>,
        start: usize,
        end: usize,
    ) -> Halo2Result<RangeConstrained<AssignedCell<PallasFp>>> {
        use crate::zk::orchard_halo2::utility::range_constrained::RangeConstrained;
        let num_bits = end.saturating_sub(start);
        if num_bits >= SINSEMILLA_K {
            return Err(Halo2Error::operation_failed(
                "lookup::witness_short",
                "too many bits",
            ));
        }
        let sub = match value {
            Some(v) => Some(bitrange_subset(v, start, end)?),
            None => None,
        };
        let inner = self.witness_short_check(layouter, sub, num_bits)?;
        Ok(RangeConstrained { inner, num_bits })
    }

    pub fn short_range_check(
        &self,
        region: &mut Region<'_>,
        element: &AssignedCell<PallasFp>,
        num_bits: usize,
    ) -> Halo2Result<()> {
        self.q_lookup.enable(region, 0)?;
        self.q_lookup.enable(region, 1)?;
        self.q_bitshift.enable(region, 1)?;
        let shifted: Option<Assigned> = element.value.map(|v| {
            Assigned::Trivial(
                v.mul_vartime(&PallasFp::from_u64(2).pow_u64((SINSEMILLA_K - num_bits) as u64)),
            )
        });
        region.assign_advice(self.running_sum, 1, &mut || shifted)?;
        let inv = PallasFp::from_u64(1u64 << num_bits).invert()?;
        region.assign_advice_from_constant(self.running_sum, 2, inv)?;
        Ok(())
    }

    pub fn witness_short_check<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        element: Option<PallasFp>,
        num_bits: usize,
    ) -> Halo2Result<AssignedCell<PallasFp>> {
        if num_bits > SINSEMILLA_K {
            return Err(Halo2Error::operation_failed(
                "lookup::short_check",
                "too many bits",
            ));
        }
        layouter.assign_region(&mut |region: &mut Region<'_>| {
            let assigned = region.assign_advice(self.running_sum, 0, &mut || element)?;
            self.short_range_check(region, &assigned, num_bits)?;
            Ok(assigned)
        })
    }
}

#[derive(Clone, Copy)]
pub struct RunningSumConfig {
    pub z: AssignmentColumn,
    pub q_range_check: Selector,
}

impl RunningSumConfig {
    pub fn configure(
        meta: &mut ConstraintSystem,
        q_range_check: Selector,
        z: AssignmentColumn,
    ) -> Halo2Result<Self> {
        meta.enable_equality(z);
        let config = Self { z, q_range_check };
        meta.create_gate(&mut |meta: &mut VirtualCells<'_>| {
            let q = meta.query_selector(config.q_range_check);
            let z_cur = meta.query_advice(config.z, Rotation::cur());
            let z_next = meta.query_advice(config.z, Rotation::next());
            let word = z_cur.try_sub(&z_next.scale(PallasFp::from_u64(8)))?;
            Ok(Constraints {
                selector: Some(q),
                constraints: vec![range_check_expr(word, 8)?],
            })
        })?;
        Ok(config)
    }

    pub fn witness_decompose(
        &self,
        region: &mut Region<'_>,
        offset: usize,
        alpha: Option<PallasFp>,
        strict: bool,
        word_num_bits: usize,
        num_windows: usize,
    ) -> Halo2Result<Vec<AssignedCell<PallasFp>>> {
        let z0 = region.assign_advice(self.z, offset, &mut || alpha)?;
        self.decompose(region, offset, &z0, strict, word_num_bits, num_windows)
    }

    pub fn copy_decompose(
        &self,
        region: &mut Region<'_>,
        offset: usize,
        alpha: &AssignedCell<PallasFp>,
        strict: bool,
        word_num_bits: usize,
        num_windows: usize,
    ) -> Halo2Result<Vec<AssignedCell<PallasFp>>> {
        let z0 = alpha.copy_advice(region, self.z, offset)?;
        self.decompose(region, offset, &z0, strict, word_num_bits, num_windows)
    }

    pub fn decompose(
        &self,
        region: &mut Region<'_>,
        offset: usize,
        z0: &AssignedCell<PallasFp>,
        strict: bool,
        word_num_bits: usize,
        num_windows: usize,
    ) -> Halo2Result<Vec<AssignedCell<PallasFp>>> {
        if 3 * num_windows >= word_num_bits + 3 {
            return Err(Halo2Error::operation_failed(
                "lookup::decompose",
                "too many windows",
            ));
        }
        for idx in 0..num_windows {
            self.q_range_check.enable(region, offset + idx)?;
        }
        let words: Vec<Option<u8>> = match z0.value {
            Some(v) => decompose_word(v, word_num_bits, 3)?
                .into_iter()
                .map(Some)
                .collect(),
            None => vec![None; num_windows],
        };
        if words.len() != num_windows {
            return Err(Halo2Error::operation_failed(
                "lookup::decompose",
                "word count",
            ));
        }
        let mut zs: Vec<AssignedCell<PallasFp>> = vec![*z0];
        let mut z = *z0;
        let inv8 = PallasFp::from_u64(8).invert()?;
        for w in words.into_iter() {
            let z_next_val: Option<PallasFp> = match (w, z.value) {
                (Some(word), Some(zv)) => Some(
                    zv.sub_vartime(&PallasFp::from_u64(word as u64))
                        .mul_vartime(&inv8),
                ),
                _ => None,
            };
            let z_next = region.assign_advice(self.z, offset + zs.len(), &mut || z_next_val)?;
            z = z_next;
            zs.push(z);
        }
        if zs.len() != num_windows + 1 {
            return Err(Halo2Error::operation_failed(
                "lookup::decompose",
                "zs length",
            ));
        }
        if strict {
            let last = &zs[zs.len() - 1];
            region.constrain_constant(last.cell, Assigned::Trivial(PallasFp::zero()))?;
        }
        Ok(zs)
    }

    #[cfg(feature = "alloc")]
    pub fn to_debug_string(&self) -> String {
        alloc::string::String::from("RunningSumConfig")
    }
}
