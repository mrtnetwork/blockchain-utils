//! Implements plonk/assignment logic (`PlonkAssembly`).
//! Row bounds become `Halo2Result` (no throws). Debug via `format!`.

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

use crate::zk::orchard_halo2::error::{Halo2Error, Halo2Result};
use crate::zk::orchard_halo2::field::PallasFp;
use crate::zk::orchard_halo2::plonk::assigned::Assigned;
use crate::zk::orchard_halo2::plonk::column::Selector;
use crate::zk::orchard_halo2::plonk::column::{AnyAssignmentColumn, AssignmentColumn};
use crate::zk::orchard_halo2::plonk::permutation::PermutationAssembly;
use crate::zk::orchard_halo2::poly::poly::{Basis, Polynomial};
use crate::zk::orchard_halo2::utility::layouter::Assignment;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct UsableRows {
    pub start: usize,
    pub end: usize,
}

impl UsableRows {
    pub fn contains(&self, row: usize) -> bool {
        row >= self.start && row < self.end
    }

    pub fn skip(&self, from: usize) -> UsableRowIter {
        UsableRowIter {
            cur: core::cmp::max(from, self.start),
            end: self.end,
        }
    }
}

pub struct UsableRowIter {
    cur: usize,
    end: usize,
}

impl Iterator for UsableRowIter {
    type Item = usize;
    fn next(&mut self) -> Option<usize> {
        if self.cur < self.end {
            let r = self.cur;
            self.cur += 1;
            Some(r)
        } else {
            None
        }
    }
}

pub struct PlonkAssembly {
    pub k: u32,
    pub fixed: Vec<Polynomial<Assigned>>,
    pub permutation: PermutationAssembly,
    pub selectors: Vec<Vec<bool>>,
    pub usable_rows: UsableRows,
}

impl PlonkAssembly {
    #[cfg(feature = "alloc")]
    pub fn to_debug_string(&self) -> String {
        alloc::format!("PlonkAssembly(k: {})", self.k)
    }
}

impl Assignment for PlonkAssembly {
    fn enable_selector(&mut self, selector: Selector, row: usize) -> Halo2Result<()> {
        if !self.usable_rows.contains(row) {
            return Err(Halo2Error::operation_failed(
                "assembly::enable_selector",
                "row out of range",
            ));
        }
        let col = self.selectors.get_mut(selector.offset).ok_or_else(|| {
            Halo2Error::operation_failed("assembly::enable_selector", "selector out of range")
        })?;
        let cell = col.get_mut(row).ok_or_else(|| {
            Halo2Error::operation_failed("assembly::enable_selector", "row out of range")
        })?;
        *cell = true;
        Ok(())
    }

    fn query_instance(
        &self,
        _column: AssignmentColumn,
        row: usize,
    ) -> Halo2Result<Option<PallasFp>> {
        if !self.usable_rows.contains(row) {
            return Err(Halo2Error::operation_failed(
                "assembly::query_instance",
                "row out of range",
            ));
        }
        Ok(None)
    }

    fn assign_advice(
        &mut self,
        _column: AssignmentColumn,
        _row: usize,
        _to: &mut dyn FnMut() -> Option<Assigned>,
    ) -> Halo2Result<()> {
        Ok(())
    }

    fn assign_fixed(
        &mut self,
        column: AssignmentColumn,
        row: usize,
        to: &mut dyn FnMut() -> Option<Assigned>,
    ) -> Halo2Result<()> {
        if !self.usable_rows.contains(row) {
            return Err(Halo2Error::operation_failed(
                "assembly::assign_fixed",
                "row out of range",
            ));
        }
        let col = self.fixed.get_mut(column.index).ok_or_else(|| {
            Halo2Error::operation_failed("assembly::assign_fixed", "column out of range")
        })?;
        let v = to().ok_or_else(|| {
            Halo2Error::operation_failed("assembly::assign_fixed", "missing value")
        })?;
        let slot = col.values.get_mut(row).ok_or_else(|| {
            Halo2Error::operation_failed("assembly::assign_fixed", "row out of range")
        })?;
        *slot = v;
        Ok(())
    }

    fn copy(
        &mut self,
        left_column: AnyAssignmentColumn,
        left_row: usize,
        right_column: AnyAssignmentColumn,
        right_row: usize,
    ) -> Halo2Result<()> {
        if !self.usable_rows.contains(left_row) || !self.usable_rows.contains(right_row) {
            return Err(Halo2Error::operation_failed(
                "assembly::copy",
                "row out of range",
            ));
        }
        self.permutation
            .copy(left_column, left_row, right_column, right_row)
    }

    fn fill_from_row(
        &mut self,
        column: AssignmentColumn,
        from_row: usize,
        to: Option<Assigned>,
    ) -> Halo2Result<()> {
        if !self.usable_rows.contains(from_row) {
            return Err(Halo2Error::operation_failed(
                "assembly::fill_from_row",
                "row out of range",
            ));
        }
        let v = to.ok_or_else(|| {
            Halo2Error::operation_failed("assembly::fill_from_row", "missing value")
        })?;
        let col = self.fixed.get_mut(column.index).ok_or_else(|| {
            Halo2Error::operation_failed("assembly::fill_from_row", "column out of range")
        })?;
        for row in self.usable_rows.skip(from_row) {
            let slot = col.values.get_mut(row).ok_or_else(|| {
                Halo2Error::operation_failed("assembly::fill_from_row", "row out of range")
            })?;
            *slot = v;
        }
        Ok(())
    }
}

pub fn empty_fixed_lagrange(n: usize) -> Polynomial<Assigned> {
    Polynomial::new(vec![Assigned::Zero; n], Basis::Lagrange)
}
