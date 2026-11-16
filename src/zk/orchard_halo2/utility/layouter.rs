//! Implements utility/layouter logic (regions, cells, layouters).
//! Closures become `FnMut() -> Option<Assigned>`; fallible ops return
//! `Halo2Result` instead of throwing. Debug via `format!`.

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

use crate::zk::orchard_halo2::error::{Halo2Error, Halo2Result};
use crate::zk::orchard_halo2::field::PallasFp;
use crate::zk::orchard_halo2::plonk::assigned::Assigned;
use crate::zk::orchard_halo2::plonk::column::{
    AnyAssignmentColumn, AssignmentColumn, ColumnType, Selector, TableColumn,
};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct CellInfo {
    pub region_index: usize,
    pub row_offset: usize,
    pub column: AnyAssignmentColumn,
}

impl CellInfo {
    #[cfg(feature = "alloc")]
    pub fn to_debug_string(&self) -> String {
        alloc::format!(
            "Cell(region: {}, row: {}, col: {:?}/{})",
            self.region_index,
            self.row_offset,
            self.column.column_type,
            self.column.index
        )
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AssignedCell<F: Clone> {
    pub value: Option<F>,
    pub cell: CellInfo,
}

impl<F: Clone> AssignedCell<F> {
    pub fn has_value(&self) -> bool {
        self.value.is_some()
    }

    pub fn get_value(&self) -> Option<F> {
        self.value.clone()
    }

    pub fn get_value_or_err(&self, op: &'static str) -> Halo2Result<F> {
        self.value
            .clone()
            .ok_or_else(|| Halo2Error::operation_failed(op, "value missing"))
    }

    /// `AssignedCell.copyAdvice`: copy into `column` at `offset` and
    /// constrain equal. Returns the new cell.
    pub fn copy_advice(
        &self,
        region: &mut Region<'_>,
        column: AssignmentColumn,
        offset: usize,
    ) -> Halo2Result<AssignedCell<F>>
    where
        F: Clone + IntoAssigned,
    {
        let mut taken: Option<F> = None;
        let new_cell = region.inner.assign_advice(column, offset, &mut || {
            let v = self.value.clone();
            taken = v.clone();
            v.map(|x| x.into_assigned()).unwrap_or(None)
        })?;
        region.inner.constrain_equal(new_cell, self.cell)?;
        Ok(AssignedCell {
            value: taken,
            cell: new_cell,
        })
    }

    #[cfg(feature = "alloc")]
    pub fn to_debug_string(&self, inner: &str) -> String {
        alloc::format!("AssignedCell({}, has_value: {})", inner, self.has_value())
    }
}

pub trait RegionLayouter {
    fn enable_selector(&mut self, selector: Selector, offset: usize) -> Halo2Result<()>;
    fn assign_advice(
        &mut self,
        column: AssignmentColumn,
        offset: usize,
        to: &mut dyn FnMut() -> Option<Assigned>,
    ) -> Halo2Result<CellInfo>;
    fn assign_advice_from_constant(
        &mut self,
        column: AssignmentColumn,
        offset: usize,
        constant: Assigned,
    ) -> Halo2Result<CellInfo>;
    fn assign_advice_from_instance(
        &mut self,
        instance: AssignmentColumn,
        row: usize,
        advice: AssignmentColumn,
        offset: usize,
    ) -> Halo2Result<(CellInfo, Option<PallasFp>)>;
    fn instance_value(&self, instance: AssignmentColumn, row: usize) -> Option<PallasFp>;
    fn assign_fixed(
        &mut self,
        column: AssignmentColumn,
        offset: usize,
        to: &mut dyn FnMut() -> Option<Assigned>,
    ) -> Halo2Result<CellInfo>;
    fn constrain_constant(&mut self, cell: CellInfo, constant: Assigned) -> Halo2Result<()>;
    fn constrain_equal(&mut self, left: CellInfo, right: CellInfo) -> Halo2Result<()>;
}

pub trait Layouter {
    fn assign_region<AR>(
        &mut self,
        assignment: &mut dyn FnMut(&mut Region<'_>) -> Halo2Result<AR>,
    ) -> Halo2Result<AR>;
    fn assign_table(
        &mut self,
        assignment: &mut dyn FnMut(&mut dyn TableLayouter) -> Halo2Result<()>,
    ) -> Halo2Result<()>;
    fn constrain_instance(
        &mut self,
        cell: CellInfo,
        column: AssignmentColumn,
        row: usize,
    ) -> Halo2Result<()>;
}

pub trait TableLayouter {
    fn assign_cell(
        &mut self,
        column: TableColumn,
        offset: usize,
        to: &mut dyn FnMut() -> Option<Assigned>,
    ) -> Halo2Result<()>;
}

pub trait Assignment {
    fn enable_selector(&mut self, selector: Selector, row: usize) -> Halo2Result<()>;
    fn query_instance(&self, column: AssignmentColumn, row: usize)
        -> Halo2Result<Option<PallasFp>>;
    fn assign_advice(
        &mut self,
        column: AssignmentColumn,
        row: usize,
        to: &mut dyn FnMut() -> Option<Assigned>,
    ) -> Halo2Result<()>;
    fn assign_fixed(
        &mut self,
        column: AssignmentColumn,
        row: usize,
        to: &mut dyn FnMut() -> Option<Assigned>,
    ) -> Halo2Result<()>;
    fn copy(
        &mut self,
        left_column: AnyAssignmentColumn,
        left_row: usize,
        right_column: AnyAssignmentColumn,
        right_row: usize,
    ) -> Halo2Result<()>;
    fn fill_from_row(
        &mut self,
        column: AssignmentColumn,
        from_row: usize,
        to: Option<Assigned>,
    ) -> Halo2Result<()>;
}

#[derive(Clone, PartialEq, Eq)]
pub enum RegionColumn {
    Column(AnyAssignmentColumn),
    Selector(Selector),
}

impl PartialOrd for RegionColumn {
    fn partial_cmp(&self, o: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(o))
    }
}

impl Ord for RegionColumn {
    fn cmp(&self, o: &Self) -> core::cmp::Ordering {
        match (self, o) {
            (Self::Column(a), Self::Column(b)) => match a.column_type.cmp(&b.column_type) {
                core::cmp::Ordering::Equal => a.index.cmp(&b.index),
                x => x,
            },
            (Self::Selector(a), Self::Selector(b)) => a.offset.cmp(&b.offset),
            (Self::Column(_), Self::Selector(_)) => core::cmp::Ordering::Less,
            (Self::Selector(_), Self::Column(_)) => core::cmp::Ordering::Greater,
        }
    }
}

/// Shape tracker (`RegionShape`): records columns + row count only.
#[derive(Clone)]
pub struct RegionShape {
    pub region_index: usize,
    pub columns: Vec<RegionColumn>,
    row_count: usize,
}

impl RegionShape {
    pub fn new(region_index: usize) -> Self {
        Self {
            region_index,
            columns: Vec::new(),
            row_count: 0,
        }
    }

    pub fn clone_shape(&self) -> Self {
        self.clone()
    }

    pub fn row_count(&self) -> usize {
        self.row_count
    }

    fn track_column(&mut self, c: RegionColumn, offset: usize) {
        if !self.columns.contains(&c) {
            self.columns.push(c);
        }
        self.row_count = core::cmp::max(self.row_count, offset + 1);
    }

    fn any_of(col: AssignmentColumn) -> AnyAssignmentColumn {
        col.to_any()
    }
}

impl RegionLayouter for RegionShape {
    fn enable_selector(&mut self, selector: Selector, offset: usize) -> Halo2Result<()> {
        self.track_column(RegionColumn::Selector(selector), offset);
        Ok(())
    }

    fn assign_advice(
        &mut self,
        column: AssignmentColumn,
        offset: usize,
        _to: &mut dyn FnMut() -> Option<Assigned>,
    ) -> Halo2Result<CellInfo> {
        if column.column_type != ColumnType::Advice {
            return Err(Halo2Error::operation_failed(
                "region::assign_advice",
                "not advice",
            ));
        }
        let c = Self::any_of(column);
        self.track_column(RegionColumn::Column(c), offset);
        Ok(CellInfo {
            region_index: self.region_index,
            row_offset: offset,
            column: c,
        })
    }

    fn assign_advice_from_constant(
        &mut self,
        column: AssignmentColumn,
        offset: usize,
        _constant: Assigned,
    ) -> Halo2Result<CellInfo> {
        self.assign_advice(column, offset, &mut || None)
    }

    fn assign_advice_from_instance(
        &mut self,
        _instance: AssignmentColumn,
        _row: usize,
        advice: AssignmentColumn,
        offset: usize,
    ) -> Halo2Result<(CellInfo, Option<PallasFp>)> {
        let c = Self::any_of(advice);
        self.track_column(RegionColumn::Column(c), offset);
        Ok((
            CellInfo {
                region_index: self.region_index,
                row_offset: offset,
                column: c,
            },
            None,
        ))
    }

    fn instance_value(&self, _instance: AssignmentColumn, _row: usize) -> Option<PallasFp> {
        None
    }

    fn assign_fixed(
        &mut self,
        column: AssignmentColumn,
        offset: usize,
        _to: &mut dyn FnMut() -> Option<Assigned>,
    ) -> Halo2Result<CellInfo> {
        if column.column_type != ColumnType::Fixed {
            return Err(Halo2Error::operation_failed(
                "region::assign_fixed",
                "not fixed",
            ));
        }
        let c = Self::any_of(column);
        self.track_column(RegionColumn::Column(c), offset);
        Ok(CellInfo {
            region_index: self.region_index,
            row_offset: offset,
            column: c,
        })
    }

    fn constrain_constant(&mut self, _cell: CellInfo, _constant: Assigned) -> Halo2Result<()> {
        Ok(())
    }

    fn constrain_equal(&mut self, _left: CellInfo, _right: CellInfo) -> Halo2Result<()> {
        Ok(())
    }
}

/// Value-bearing region wrapper (`Region`): converts `F` values to
/// `Assigned` through caller closures.
pub struct Region<'a> {
    pub inner: &'a mut dyn RegionLayouter,
}

impl<'a> Region<'a> {
    pub fn new(inner: &'a mut dyn RegionLayouter) -> Self {
        Self { inner }
    }

    pub fn enable_selector(&mut self, selector: Selector, offset: usize) -> Halo2Result<()> {
        self.inner.enable_selector(selector, offset)
    }

    pub fn assign_advice<F: Clone + IntoAssigned>(
        &mut self,
        column: AssignmentColumn,
        offset: usize,
        to: &mut dyn FnMut() -> Option<F>,
    ) -> Halo2Result<AssignedCell<F>> {
        let mut value: Option<F> = None;
        let cell = self.inner.assign_advice(column, offset, &mut || {
            let v = to();
            value = v.clone();
            v.map(|x| x.into_assigned()).unwrap_or(None)
        })?;
        Ok(AssignedCell { value, cell })
    }

    pub fn assign_advice_from_constant<F: Clone + IntoAssigned>(
        &mut self,
        column: AssignmentColumn,
        offset: usize,
        constant: F,
    ) -> Halo2Result<AssignedCell<F>> {
        let a = constant.clone().into_assigned().ok_or_else(|| {
            Halo2Error::operation_failed("region::assign_constant", "unconvertible")
        })?;
        let cell = self.inner.assign_advice_from_constant(column, offset, a)?;
        Ok(AssignedCell {
            value: Some(constant),
            cell,
        })
    }

    pub fn assign_advice_from_instance(
        &mut self,
        instance: AssignmentColumn,
        row: usize,
        advice: AssignmentColumn,
        offset: usize,
    ) -> Halo2Result<AssignedCell<PallasFp>> {
        let (cell, value) = self
            .inner
            .assign_advice_from_instance(instance, row, advice, offset)?;
        Ok(AssignedCell { value, cell })
    }

    pub fn instance_value(&self, _instance: AssignmentColumn, _row: usize) -> Option<PallasFp> {
        None
    }

    pub fn assign_fixed<F: Clone + IntoAssigned>(
        &mut self,
        column: AssignmentColumn,
        offset: usize,
        to: &mut dyn FnMut() -> Option<F>,
    ) -> Halo2Result<AssignedCell<F>> {
        let mut value: Option<F> = None;
        let cell = self.inner.assign_fixed(column, offset, &mut || {
            let v = to();
            value = v.clone();
            v.map(|x| x.into_assigned()).unwrap_or(None)
        })?;
        Ok(AssignedCell { value, cell })
    }

    pub fn constrain_constant(&mut self, cell: CellInfo, constant: Assigned) -> Halo2Result<()> {
        self.inner.constrain_constant(cell, constant)
    }

    pub fn constrain_equal(&mut self, left: CellInfo, right: CellInfo) -> Halo2Result<()> {
        self.inner.constrain_equal(left, right)
    }
}

/// Convert witness values into `Assigned` (`Assigned.from`).
pub trait IntoAssigned {
    fn into_assigned(self) -> Option<Assigned>;
}

impl IntoAssigned for PallasFp {
    fn into_assigned(self) -> Option<Assigned> {
        Some(Assigned::Trivial(self))
    }
}

impl IntoAssigned for u64 {
    fn into_assigned(self) -> Option<Assigned> {
        Some(Assigned::Trivial(PallasFp::from_u64(self)))
    }
}

impl IntoAssigned for Assigned {
    fn into_assigned(self) -> Option<Assigned> {
        Some(self)
    }
}

impl IntoAssigned for [u8; 32] {
    fn into_assigned(self) -> Option<Assigned> {
        PallasFp::from_le_bytes_checked(&self)
            .ok()
            .map(Assigned::Trivial)
    }
}
