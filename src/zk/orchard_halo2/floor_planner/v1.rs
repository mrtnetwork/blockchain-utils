//! Implements floor_planner/v1 logic (passes, regions, tables).
//! The top-level `synthesize` driver (needs the Orchard circuit) is added in
//! the orchard pass. All bounds are `Halo2Result`, no `assert!`.

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

use crate::zk::orchard_halo2::error::{Halo2Error, Halo2Result};
use crate::zk::orchard_halo2::field::PallasFp;
use crate::zk::orchard_halo2::plonk::assigned::Assigned;
use crate::zk::orchard_halo2::plonk::column::{
    AssignmentColumn, ColumnType, Selector, TableColumn,
};
use crate::zk::orchard_halo2::utility::layouter::{
    Assignment, CellInfo, Layouter, Region, RegionLayouter, RegionShape, TableLayouter,
};

pub struct V1Plan<'a> {
    pub cs: &'a mut dyn Assignment,
    pub regions: Vec<usize>,
    pub constants: Vec<(Assigned, CellInfo)>,
    pub table_column: Vec<TableColumn>,
}

impl<'a> V1Plan<'a> {
    pub fn new(cs: &'a mut dyn Assignment) -> Self {
        Self {
            cs,
            regions: Vec::new(),
            constants: Vec::new(),
            table_column: Vec::new(),
        }
    }

    #[cfg(feature = "alloc")]
    pub fn to_debug_string(&self) -> String {
        alloc::format!("V1Plan(regions: {})", self.regions.len())
    }
}

pub struct MeasurementPass {
    pub regions: Vec<RegionShape>,
}

impl MeasurementPass {
    pub fn new() -> Self {
        Self {
            regions: Vec::new(),
        }
    }

    pub fn assign_region<AR>(
        &mut self,
        assignment: &mut dyn FnMut(&mut Region<'_>) -> Halo2Result<AR>,
    ) -> Halo2Result<AR> {
        let region_index = self.regions.len();
        let mut shape = RegionShape::new(region_index);
        let mut region = Region::new(&mut shape);
        let result = assignment(&mut region)?;
        self.regions.push(shape);
        Ok(result)
    }
}

impl Default for MeasurementPass {
    fn default() -> Self {
        Self::new()
    }
}

pub struct AssignmentPass<'a, 'b> {
    pub plan: &'b mut V1Plan<'a>,
    region_index: usize,
}

impl<'a, 'b> AssignmentPass<'a, 'b> {
    pub fn new(plan: &'b mut V1Plan<'a>) -> Self {
        Self {
            plan,
            region_index: 0,
        }
    }

    pub fn assign_region<AR>(
        &mut self,
        assignment: &mut dyn FnMut(&mut Region<'_>) -> Halo2Result<AR>,
    ) -> Halo2Result<AR> {
        let current = self.region_index;
        self.region_index += 1;
        let mut region_impl = V1Region {
            plan: &mut *self.plan,
            region_index: current,
        };
        let mut region = Region::new(&mut region_impl);
        assignment(&mut region)
    }

    pub fn assign_table<AR>(
        &mut self,
        assignment: &mut dyn FnMut(&mut dyn TableLayouter) -> Halo2Result<AR>,
    ) -> Halo2Result<AR> {
        let used = self.plan.table_column.clone();
        let mut table = SimpleTableLayouter::new(&mut *self.plan.cs, used);
        let result = assignment(&mut table)?;
        let first_unused = compute_table_lengths(&table.entries)?;
        for col in table.entries.iter().map(|e| e.column) {
            if !self.plan.table_column.contains(&col) {
                self.plan.table_column.push(col);
            }
        }
        for entry in table.entries.iter() {
            // Default may be null under witness collection (its `fill_from_row`
            // ignores nulls, mirroring the reference); keygen assembly rejects nulls.
            self.plan
                .cs
                .fill_from_row(entry.column.inner, first_unused, entry.default)?;
        }
        Ok(result)
    }

    pub fn constrain_instance(
        &mut self,
        cell: CellInfo,
        instance: AssignmentColumn,
        row: usize,
    ) -> Halo2Result<()> {
        if instance.column_type != ColumnType::Instance {
            return Err(Halo2Error::operation_failed(
                "v1::constrain_instance",
                "not instance",
            ));
        }
        let abs = self
            .plan
            .regions
            .get(cell.region_index)
            .copied()
            .ok_or_else(|| Halo2Error::operation_failed("v1::constrain_instance", "bad region"))?
            + cell.row_offset;
        self.plan.cs.copy(cell.column, abs, instance.to_any(), row)
    }
}

struct TableEntry {
    column: TableColumn,
    default: Option<Assigned>,
    assigned: Vec<bool>,
}

struct SimpleTableLayouter<'a> {
    cs: &'a mut dyn Assignment,
    used_columns: Vec<TableColumn>,
    entries: Vec<TableEntry>,
}

impl<'a> SimpleTableLayouter<'a> {
    fn new(cs: &'a mut dyn Assignment, used_columns: Vec<TableColumn>) -> Self {
        Self {
            cs,
            used_columns,
            entries: Vec::new(),
        }
    }
}

impl<'a> TableLayouter for SimpleTableLayouter<'a> {
    fn assign_cell(
        &mut self,
        column: TableColumn,
        offset: usize,
        to: &mut dyn FnMut() -> Option<Assigned>,
    ) -> Halo2Result<()> {
        if self.used_columns.contains(&column) {
            return Err(Halo2Error::operation_failed("v1::table", "column reused"));
        }
        let idx = match self.entries.iter().position(|e| e.column == column) {
            Some(i) => i,
            None => {
                self.entries.push(TableEntry {
                    column,
                    default: None,
                    assigned: Vec::new(),
                });
                self.entries.len() - 1
            }
        };
        let mut value: Option<Assigned> = None;
        self.cs.assign_fixed(column.inner, offset, &mut || {
            let v = to();
            value = v;
            v
        })?;
        let entry = &mut self.entries[idx];
        if value.is_some() && offset == 0 {
            if entry.default.is_some() {
                return Err(Halo2Error::operation_failed("v1::table", "bad offset"));
            }
            entry.default = value;
        }
        if offset > entry.assigned.len() {
            return Err(Halo2Error::operation_failed("v1::table", "bad offset"));
        }
        if offset == entry.assigned.len() {
            entry.assigned.push(true);
        } else {
            entry.assigned[offset] = true;
        }
        Ok(())
    }
}

fn compute_table_lengths(entries: &[TableEntry]) -> Halo2Result<usize> {
    let mut first_len: Option<usize> = None;
    for e in entries.iter() {
        if e.assigned.is_empty() || e.assigned.iter().any(|b| !b) {
            return Err(Halo2Error::operation_failed(
                "v1::table",
                "column not assigned",
            ));
        }
        match first_len {
            None => first_len = Some(e.assigned.len()),
            Some(l) => {
                if l != e.assigned.len() {
                    return Err(Halo2Error::operation_failed("v1::table", "length mismatch"));
                }
            }
        }
    }
    Ok(first_len.unwrap_or(0))
}

pub struct V1Region<'a, 'b> {
    plan: &'b mut V1Plan<'a>,
    region_index: usize,
}

impl<'a, 'b> V1Region<'a, 'b> {
    fn absolute_row(&self, offset: usize) -> Halo2Result<usize> {
        self.plan
            .regions
            .get(self.region_index)
            .copied()
            .ok_or_else(|| Halo2Error::operation_failed("v1::region", "bad region"))
            .map(|base| base + offset)
    }
}

impl<'a, 'b> RegionLayouter for V1Region<'a, 'b> {
    fn enable_selector(&mut self, selector: Selector, offset: usize) -> Halo2Result<()> {
        let row = self.absolute_row(offset)?;
        self.plan.cs.enable_selector(selector, row)
    }

    fn assign_advice(
        &mut self,
        column: AssignmentColumn,
        offset: usize,
        to: &mut dyn FnMut() -> Option<Assigned>,
    ) -> Halo2Result<CellInfo> {
        let row = self.absolute_row(offset)?;
        self.plan.cs.assign_advice(column, row, to)?;
        Ok(CellInfo {
            region_index: self.region_index,
            row_offset: offset,
            column: column.to_any(),
        })
    }

    fn assign_advice_from_constant(
        &mut self,
        column: AssignmentColumn,
        offset: usize,
        constant: Assigned,
    ) -> Halo2Result<CellInfo> {
        let cell = self.assign_advice(column, offset, &mut || Some(constant))?;
        self.constrain_constant(cell, constant)?;
        Ok(cell)
    }

    fn assign_advice_from_instance(
        &mut self,
        instance: AssignmentColumn,
        row: usize,
        advice: AssignmentColumn,
        offset: usize,
    ) -> Halo2Result<(CellInfo, Option<PallasFp>)> {
        let value = self.plan.cs.query_instance(instance, row)?;
        let cell = self.assign_advice(advice, offset, &mut || value.map(Assigned::Trivial))?;
        let abs = self.absolute_row(offset)?;
        self.plan
            .cs
            .copy(cell.column, abs, instance.to_any(), row)?;
        Ok((cell, value))
    }

    fn instance_value(&self, _instance: AssignmentColumn, _row: usize) -> Option<PallasFp> {
        None
    }

    fn assign_fixed(
        &mut self,
        column: AssignmentColumn,
        offset: usize,
        to: &mut dyn FnMut() -> Option<Assigned>,
    ) -> Halo2Result<CellInfo> {
        let row = self.absolute_row(offset)?;
        self.plan.cs.assign_fixed(column, row, to)?;
        Ok(CellInfo {
            region_index: self.region_index,
            row_offset: offset,
            column: column.to_any(),
        })
    }

    fn constrain_constant(&mut self, cell: CellInfo, constant: Assigned) -> Halo2Result<()> {
        self.plan.constants.push((constant, cell));
        Ok(())
    }

    fn constrain_equal(&mut self, left: CellInfo, right: CellInfo) -> Halo2Result<()> {
        let lrow = self
            .plan
            .regions
            .get(left.region_index)
            .copied()
            .ok_or_else(|| Halo2Error::operation_failed("v1::equal", "bad region"))?
            + left.row_offset;
        let rrow = self
            .plan
            .regions
            .get(right.region_index)
            .copied()
            .ok_or_else(|| Halo2Error::operation_failed("v1::equal", "bad region"))?
            + right.row_offset;
        self.plan.cs.copy(left.column, lrow, right.column, rrow)
    }
}

pub enum V1Pass<'a, 'b> {
    Measure(&'a mut MeasurementPass),
    Assign(AssignmentPass<'a, 'b>),
}

impl<'a, 'b> Layouter for V1Pass<'a, 'b> {
    fn assign_region<AR>(
        &mut self,
        assignment: &mut dyn FnMut(&mut Region<'_>) -> Halo2Result<AR>,
    ) -> Halo2Result<AR> {
        match self {
            Self::Measure(m) => m.assign_region(assignment),
            Self::Assign(a) => a.assign_region(assignment),
        }
    }

    fn assign_table(
        &mut self,
        assignment: &mut dyn FnMut(&mut dyn TableLayouter) -> Halo2Result<()>,
    ) -> Halo2Result<()> {
        match self {
            Self::Measure(_) => Ok(()),
            Self::Assign(a) => a.assign_table(assignment).map(|_| ()),
        }
    }

    fn constrain_instance(
        &mut self,
        cell: CellInfo,
        column: AssignmentColumn,
        row: usize,
    ) -> Halo2Result<()> {
        match self {
            Self::Measure(_) => Ok(()),
            Self::Assign(a) => a.constrain_instance(cell, column, row),
        }
    }
}

// —— top-level synthesize driver (needs the Orchard circuit) ——

use crate::zk::orchard_halo2::crypto_context::DefaultCryptoContext;
use crate::zk::orchard_halo2::floor_planner::strategy::FloorPlannerUtils;
use crate::zk::orchard_halo2::orchard::circuit::{OrchardCircuit, OrchardCircuitConfig};
use crate::zk::orchard_halo2::utility::layouter::RegionColumn;

/// Full V1 synthesis: measure → slot regions → assign → place constants.
/// mirrors the reference implementation
pub fn v1_synthesize(
    cs: &mut dyn Assignment,
    circuit: &OrchardCircuit,
    config: &OrchardCircuitConfig,
    constants: Vec<AssignmentColumn>,
    _context: &DefaultCryptoContext,
) -> Halo2Result<()> {
    // First pass: measure regions.
    let mut measure = MeasurementPass::new();
    {
        let default_circuit = OrchardCircuit::default_config(circuit.version);
        let _ = &default_circuit;
        circuit.synthesize(config, &mut V1Pass::Measure(&mut measure))?;
    }
    // Plan: slot biggest-advice-first (legacy pdqsort, as Orchard uses).
    let (regions, column_allocations) =
        FloorPlannerUtils::slot_in_biggest_advice_first(measure.regions, true)?;
    let first_unassigned_row = column_allocations
        .iter()
        .map(|(_, a)| a.unbounded_interval_start())
        .max()
        .unwrap_or(0);

    // Fixed allocations for constants.
    let mut fixed_allocations: Vec<(
        AssignmentColumn,
        crate::zk::orchard_halo2::floor_planner::strategy::AllocationsRegion,
    )> = Vec::new();
    for c in constants.into_iter() {
        let key = RegionColumn::Column(c.to_any());
        let alloc = column_allocations
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, a)| a.clone())
            .unwrap_or_default();
        fixed_allocations.push((c, alloc));
    }
    let mut constant_positions: Vec<(AssignmentColumn, usize)> = Vec::new();
    for (c, a) in fixed_allocations.iter() {
        for space in a.free_intervals(0, Some(first_unassigned_row)) {
            if let Some(end) = space.end {
                for i in space.start..end {
                    constant_positions.push((*c, i));
                }
            }
        }
    }

    let mut plan = V1Plan::new(cs);
    plan.regions = regions;
    {
        let pass = AssignmentPass::new(&mut plan);
        let mut v1 = V1Pass::Assign(pass);
        // Reborrow dance: run synthesis through a fresh pass handle.
        circuit.synthesize(config, &mut v1)?;
    }
    // Assign constants into free fixed cells.
    if constant_positions.len() < plan.constants.len() {
        return Err(Halo2Error::operation_failed(
            "v1::synthesize",
            "no room for constants",
        ));
    }
    for (i, (value, advice)) in plan.constants.iter().enumerate() {
        let (fixed_column, fixed_row) = constant_positions[i];
        plan.cs
            .assign_fixed(fixed_column, fixed_row, &mut || Some(*value))?;
        let abs = plan.regions[advice.region_index] + advice.row_offset;
        plan.cs
            .copy(fixed_column.to_any(), fixed_row, advice.column, abs)?;
    }
    Ok(())
}
