//! Implements plonk/constraint logic (gates, `ConstraintSystem`).
//! All throws/`assert!` become `Halo2Result`. Debug via `format!` with BE
//! `0x` field hex (mirrors the reference implementation

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

use crate::zk::orchard_halo2::error::{Halo2Error, Halo2Result};
use crate::zk::orchard_halo2::field::PallasFp;
use crate::zk::orchard_halo2::plonk::column::{
    AnyAssignmentColumn, AnyColumn, AssignmentColumn, ColumnType, Selector, TableColumn,
};
use crate::zk::orchard_halo2::plonk::compress_selectors::{process_selectors, SelectorDescription};
use crate::zk::orchard_halo2::plonk::expression::{Expression, Query};
use crate::zk::orchard_halo2::plonk::lookup::LookupArgument;
use crate::zk::orchard_halo2::plonk::permutation::PermutationArgument;
use crate::zk::orchard_halo2::poly::poly::Rotation;

#[derive(Clone, PartialEq, Eq)]
pub struct VirtualCell {
    pub column: AnyAssignmentColumn,
    pub rotation: Rotation,
}

#[derive(Clone, PartialEq, Eq)]
pub struct Gate {
    pub polys: Vec<Expression>,
    pub queried_selectors: Vec<Selector>,
    pub queried_cells: Vec<VirtualCell>,
}

#[derive(Clone)]
pub struct ConstraintSystem {
    num_fixed_columns: usize,
    num_advice_columns: usize,
    num_instance_columns: usize,
    num_selectors: usize,
    pub selector_map: Vec<AssignmentColumn>,
    pub gates: Vec<Gate>,
    pub advice_queries: Vec<(AssignmentColumn, Rotation)>,
    num_advice_queries: Vec<usize>,
    pub instance_queries: Vec<(AssignmentColumn, Rotation)>,
    pub fixed_queries: Vec<(AssignmentColumn, Rotation)>,
    pub permutation: PermutationArgument,
    pub lookups: Vec<LookupArgument>,
    pub constants: Vec<AssignmentColumn>,
    pub minimum_degree: Option<usize>,
}

impl ConstraintSystem {
    pub fn default_config() -> Self {
        Self {
            num_fixed_columns: 0,
            num_advice_columns: 0,
            num_instance_columns: 0,
            num_selectors: 0,
            selector_map: Vec::new(),
            gates: Vec::new(),
            advice_queries: Vec::new(),
            num_advice_queries: Vec::new(),
            instance_queries: Vec::new(),
            fixed_queries: Vec::new(),
            permutation: PermutationArgument::new(),
            lookups: Vec::new(),
            constants: Vec::new(),
            minimum_degree: None,
        }
    }

    pub fn num_fixed_columns(&self) -> usize {
        self.num_fixed_columns
    }
    pub fn num_advice_columns(&self) -> usize {
        self.num_advice_columns
    }
    pub fn num_instance_columns(&self) -> usize {
        self.num_instance_columns
    }
    pub fn num_selectors(&self) -> usize {
        self.num_selectors
    }

    #[cfg(feature = "alloc")]
    pub fn to_debug_string(&self) -> String {
        let gates: Vec<String> = self
            .gates
            .iter()
            .flat_map(|g| g.polys.iter().map(|e| e.to_debug_string()))
            .collect();
        let query_dbg = |qs: &[(AssignmentColumn, Rotation)]| -> String {
            qs.iter()
                .map(|(c, r)| alloc::format!("({}, {})", c.to_debug_string(), r.to_debug_string()))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let constants: Vec<String> = self.constants.iter().map(|c| c.to_debug_string()).collect();
        alloc::format!(
            "PinnedConstraintSystem {{ num_fixed_columns: {}, num_advice_columns: {}, num_instance_columns: {}, num_selectors: {}, gates: [{}], advice_queries: [{}], instance_queries: [{}], fixed_queries: [{}], permutation: {}, lookups: [{}], constants: [{}], minimum_degree: {} }}",
            self.num_fixed_columns,
            self.num_advice_columns,
            self.num_instance_columns,
            self.num_selectors,
            gates.join(", "),
            query_dbg(&self.advice_queries),
            query_dbg(&self.instance_queries),
            query_dbg(&self.fixed_queries),
            self.permutation.to_debug_string(),
            self.lookups.iter().map(|l| l.to_debug_string()).collect::<Vec<_>>().join(", "),
            constants.join(", "),
            match self.minimum_degree {
                Some(d) => alloc::format!("{}", d),
                None => alloc::string::String::from("None"),
            }
        )
    }

    pub fn enable_constant(&mut self, column: AssignmentColumn) {
        if !self.constants.contains(&column) {
            self.constants.push(column);
            self.enable_equality_any(column.to_any());
        }
    }

    pub fn enable_equality(&mut self, column: AssignmentColumn) {
        let c = column.to_any();
        let _ = self.query_any_index(c, Rotation::cur());
        self.permutation.add_column(c);
    }

    fn enable_equality_any(&mut self, c: AnyAssignmentColumn) {
        let _ = self.query_any_index(c, Rotation::cur());
        self.permutation.add_column(c);
    }

    pub fn instance_column(&mut self) -> AssignmentColumn {
        let c = AssignmentColumn::new(self.num_instance_columns, ColumnType::Instance);
        self.num_instance_columns += 1;
        c
    }

    pub fn advice_column(&mut self) -> AssignmentColumn {
        let c = AssignmentColumn::new(self.num_advice_columns, ColumnType::Advice);
        self.num_advice_columns += 1;
        self.num_advice_queries.push(0);
        c
    }

    pub fn fixed_column(&mut self) -> AssignmentColumn {
        let c = AssignmentColumn::new(self.num_fixed_columns, ColumnType::Fixed);
        self.num_fixed_columns += 1;
        c
    }

    pub fn lookup_table_column(&mut self) -> TableColumn {
        TableColumn {
            inner: self.fixed_column(),
        }
    }

    pub fn selector(&mut self) -> Selector {
        let s = Selector::new(self.num_selectors, true);
        self.num_selectors += 1;
        s
    }

    pub fn complex_selector(&mut self) -> Selector {
        let s = Selector::new(self.num_selectors, false);
        self.num_selectors += 1;
        s
    }

    pub fn query_fixed_index(&mut self, column: AssignmentColumn) -> usize {
        let key = (column, Rotation::cur());
        if let Some(i) = self.fixed_queries.iter().position(|q| *q == key) {
            return i;
        }
        let len = self.fixed_queries.len();
        self.fixed_queries.push(key);
        len
    }

    pub fn query_advice_index(&mut self, column: AssignmentColumn, at: Rotation) -> usize {
        let key = (column, at);
        if let Some(i) = self.advice_queries.iter().position(|q| *q == key) {
            return i;
        }
        let len = self.advice_queries.len();
        self.advice_queries.push(key);
        if let Some(n) = self.num_advice_queries.get_mut(column.index) {
            *n += 1;
        }
        len
    }

    pub fn query_instance_index(&mut self, column: AssignmentColumn, at: Rotation) -> usize {
        let key = (column, at);
        if let Some(i) = self.instance_queries.iter().position(|q| *q == key) {
            return i;
        }
        let len = self.instance_queries.len();
        self.instance_queries.push(key);
        len
    }

    pub fn query_any_index(&mut self, column: AnyAssignmentColumn, at: Rotation) -> usize {
        match column.column_type {
            AnyColumn::Advice => {
                self.query_advice_index(AssignmentColumn::new(column.index, ColumnType::Advice), at)
            }
            AnyColumn::Fixed => {
                self.query_fixed_index(AssignmentColumn::new(column.index, ColumnType::Fixed))
            }
            AnyColumn::Instance => self.query_instance_index(
                AssignmentColumn::new(column.index, ColumnType::Instance),
                at,
            ),
        }
    }

    pub fn get_advice_query_index(
        &self,
        column: AssignmentColumn,
        at: Rotation,
    ) -> Halo2Result<usize> {
        self.advice_queries
            .iter()
            .position(|q| *q == (column, at))
            .ok_or_else(|| Halo2Error::operation_failed("get_advice_query", "missing query"))
    }

    pub fn get_fixed_query_index(
        &self,
        column: AssignmentColumn,
        at: Rotation,
    ) -> Halo2Result<usize> {
        self.fixed_queries
            .iter()
            .position(|q| *q == (column, at))
            .ok_or_else(|| Halo2Error::operation_failed("get_fixed_query", "missing query"))
    }

    pub fn get_instance_query_index(
        &self,
        column: AssignmentColumn,
        at: Rotation,
    ) -> Halo2Result<usize> {
        self.instance_queries
            .iter()
            .position(|q| *q == (column, at))
            .ok_or_else(|| Halo2Error::operation_failed("get_instance_query", "missing query"))
    }

    pub fn get_any_query_index(&self, column: AnyAssignmentColumn) -> Halo2Result<usize> {
        let cur = Rotation::cur();
        match column.column_type {
            AnyColumn::Advice => self.get_advice_query_index(
                AssignmentColumn::new(column.index, ColumnType::Advice),
                cur,
            ),
            AnyColumn::Fixed => self
                .get_fixed_query_index(AssignmentColumn::new(column.index, ColumnType::Fixed), cur),
            AnyColumn::Instance => self.get_instance_query_index(
                AssignmentColumn::new(column.index, ColumnType::Instance),
                cur,
            ),
        }
    }

    pub fn create_gate(
        &mut self,
        builder: &mut dyn FnMut(&mut VirtualCells<'_>) -> Halo2Result<Constraints>,
    ) -> Halo2Result<()> {
        let (constraints, queried_selectors, queried_cells) = {
            let mut cells = VirtualCells::new(self);
            let cs = builder(&mut cells)?;
            let out = cs.get_constraints()?;
            (
                out,
                cells.queried_selectors.clone(),
                cells.queried_cells.clone(),
            )
        };
        if constraints.is_empty() {
            return Err(Halo2Error::operation_failed("create_gate", "empty gate"));
        }
        self.gates.push(Gate {
            polys: constraints,
            queried_selectors,
            queried_cells,
        });
        Ok(())
    }

    // `FnMut` sugar elides a higher-ranked lifetime that a named alias would
    // unify with the outer borrow, breaking borrowck; keep inline signature.
    #[allow(clippy::type_complexity)]
    pub fn lookup(
        &mut self,
        table_map: &mut dyn FnMut(
            &mut VirtualCells<'_>,
        ) -> Halo2Result<Vec<(Expression, TableColumn)>>,
    ) -> Halo2Result<usize> {
        let mapped: Vec<(Expression, Expression)> = {
            let mut cells = VirtualCells::new(self);
            let pairs = table_map(&mut cells)?;
            let mut out = Vec::with_capacity(pairs.len());
            for (input, table) in pairs.into_iter() {
                if input.contains_simple_selector() {
                    return Err(Halo2Error::operation_failed(
                        "lookup",
                        "simple selector in lookup",
                    ));
                }
                let table_query = cells.query_fixed(table.inner);
                out.push((input, table_query));
            }
            out
        };
        let index = self.lookups.len();
        self.lookups.push(LookupArgument::new(
            mapped.iter().map(|p| p.0.clone()).collect(),
            mapped.iter().map(|p| p.1.clone()).collect(),
        ));
        Ok(index)
    }

    pub fn blinding_factors(&self) -> usize {
        let mut factors = self.num_advice_queries.iter().copied().max().unwrap_or(1);
        if factors < 3 {
            factors = 3;
        }
        factors + 1 + 1
    }

    pub fn degree(&self) -> Halo2Result<usize> {
        let mut degree = self.permutation.required_degree();
        let mut lookup_max = 1usize;
        for l in self.lookups.iter() {
            lookup_max = core::cmp::max(lookup_max, l.required_degree()?);
        }
        degree = core::cmp::max(degree, lookup_max);
        let mut gate_max = 0usize;
        for g in self.gates.iter() {
            for p in g.polys.iter() {
                gate_max = core::cmp::max(gate_max, p.degree());
            }
        }
        degree = core::cmp::max(degree, gate_max);
        let floor = self.minimum_degree.unwrap_or(1);
        Ok(core::cmp::max(degree, floor))
    }

    pub fn minimum_rows(&self) -> usize {
        self.blinding_factors() + 3
    }

    /// Compress simple selectors (`compressSelectors`). Selector count
    /// mismatch and missing replacements are `Err`, never `assert!`.
    pub fn compress_selectors(
        &mut self,
        selectors: Vec<Vec<bool>>,
    ) -> Halo2Result<Vec<Vec<PallasFp>>> {
        if selectors.len() != self.num_selectors {
            return Err(Halo2Error::operation_failed(
                "compress_selectors",
                "selector count mismatch",
            ));
        }
        let mut degrees = vec![0usize; selectors.len()];
        for gate in self.gates.iter() {
            for expr in gate.polys.iter() {
                if let Some(s) = expr.extract_simple_selector()? {
                    degrees[s.offset] = core::cmp::max(degrees[s.offset], expr.degree());
                }
            }
        }
        let max_degree = self.degree()?;
        let mut new_columns: Vec<AssignmentColumn> = Vec::new();
        let descs: Vec<SelectorDescription> = selectors
            .into_iter()
            .enumerate()
            .map(|(i, activations)| SelectorDescription {
                selector: i,
                activations,
                max_degree: degrees[i],
            })
            .collect();
        let (polys, assignments) = {
            let this = &mut *self;
            process_selectors(descs, max_degree, &mut || {
                let col = this.fixed_column();
                new_columns.push(col);
                let idx = this.query_fixed_index(col);
                Expression::Fixed(Query {
                    index: idx,
                    column_index: col.index,
                    rotation: Rotation::cur(),
                })
            })?
        };
        let mut replacements: Vec<Option<Expression>> = vec![None; assignments.len().max(1)];
        let mut selector_map: Vec<Option<AssignmentColumn>> = vec![None; assignments.len().max(1)];
        // Size by selector count (assignments cover every selector).
        let n_sel = self.num_selectors;
        replacements = vec![None; n_sel];
        selector_map = vec![None; n_sel];
        for a in assignments.into_iter() {
            let col = *new_columns.get(a.combination_index).ok_or_else(|| {
                Halo2Error::operation_failed("compress_selectors", "bad combination")
            })?;
            replacements[a.selector] = Some(a.expression);
            selector_map[a.selector] = Some(col);
        }
        let mut final_reps: Vec<Expression> = Vec::with_capacity(n_sel);
        for r in replacements.into_iter() {
            final_reps.push(r.ok_or_else(|| {
                Halo2Error::operation_failed("compress_selectors", "missing replacement")
            })?);
        }
        for gate in self.gates.iter_mut() {
            let mut next = Vec::with_capacity(gate.polys.len());
            for e in gate.polys.iter() {
                next.push(replace_selectors(e, &final_reps, false)?);
            }
            gate.polys = next;
        }
        let mut next_lookups = Vec::with_capacity(self.lookups.len());
        for l in self.lookups.drain(..) {
            let mut ins = Vec::with_capacity(l.input_expressions.len());
            for e in l.input_expressions.iter() {
                ins.push(replace_selectors(e, &final_reps, true)?);
            }
            let mut tab = Vec::with_capacity(l.table_expressions.len());
            for e in l.table_expressions.iter() {
                tab.push(replace_selectors(e, &final_reps, true)?);
            }
            next_lookups.push(LookupArgument::new(ins, tab));
        }
        self.lookups = next_lookups;
        let _ = selector_map;
        Ok(polys)
    }
}

fn replace_selectors(
    expr: &Expression,
    reps: &[Expression],
    must_be_non_simple: bool,
) -> Halo2Result<Expression> {
    match expr {
        Expression::Constant(v) => Ok(Expression::Constant(*v)),
        Expression::Selector(s) => {
            if must_be_non_simple && s.is_simple {
                return Err(Halo2Error::operation_failed(
                    "compress_selectors",
                    "simple selector in lookup",
                ));
            }
            reps.get(s.offset)
                .cloned()
                .ok_or_else(|| Halo2Error::operation_failed("compress_selectors", "bad selector"))
        }
        Expression::Fixed(q) => Ok(Expression::Fixed(*q)),
        Expression::Advice(q) => Ok(Expression::Advice(*q)),
        Expression::Instance(q) => Ok(Expression::Instance(*q)),
        Expression::Negated(p) => Ok(replace_selectors(p, reps, must_be_non_simple)?.neg()),
        Expression::Sum(a, b) => {
            let x = replace_selectors(a, reps, must_be_non_simple)?;
            let y = replace_selectors(b, reps, must_be_non_simple)?;
            x.try_add(&y)
        }
        Expression::Product(a, b) => {
            let x = replace_selectors(a, reps, must_be_non_simple)?;
            let y = replace_selectors(b, reps, must_be_non_simple)?;
            x.try_mul_expr(&y)
        }
        Expression::Scaled(p, f) => Ok(replace_selectors(p, reps, must_be_non_simple)?.scale(*f)),
    }
}

pub struct VirtualCells<'a> {
    meta: &'a mut ConstraintSystem,
    pub queried_selectors: Vec<Selector>,
    pub queried_cells: Vec<VirtualCell>,
}

impl<'a> VirtualCells<'a> {
    pub fn new(meta: &'a mut ConstraintSystem) -> Self {
        Self {
            meta,
            queried_selectors: Vec::new(),
            queried_cells: Vec::new(),
        }
    }

    pub fn query_selector(&mut self, selector: Selector) -> Expression {
        self.queried_selectors.push(selector);
        Expression::Selector(selector)
    }

    pub fn query_fixed(&mut self, column: AssignmentColumn) -> Expression {
        self.queried_cells.push(VirtualCell {
            column: column.to_any(),
            rotation: Rotation::cur(),
        });
        let index = self.meta.query_fixed_index(column);
        Expression::Fixed(Query {
            index,
            column_index: column.index,
            rotation: Rotation::cur(),
        })
    }

    pub fn query_advice(&mut self, column: AssignmentColumn, at: Rotation) -> Expression {
        self.queried_cells.push(VirtualCell {
            column: column.to_any(),
            rotation: at,
        });
        let index = self.meta.query_advice_index(column, at);
        Expression::Advice(Query {
            index,
            column_index: column.index,
            rotation: at,
        })
    }

    pub fn query_instance(&mut self, column: AssignmentColumn, at: Rotation) -> Expression {
        self.queried_cells.push(VirtualCell {
            column: column.to_any(),
            rotation: at,
        });
        let index = self.meta.query_instance_index(column, at);
        Expression::Instance(Query {
            index,
            column_index: column.index,
            rotation: at,
        })
    }

    pub fn query_any(
        &mut self,
        column: AnyAssignmentColumn,
        at: Rotation,
    ) -> Halo2Result<Expression> {
        match column.column_type {
            AnyColumn::Advice => {
                Ok(self.query_advice(AssignmentColumn::new(column.index, ColumnType::Advice), at))
            }
            AnyColumn::Fixed => {
                if !at.is_current() {
                    return Err(Halo2Error::operation_failed(
                        "query_any",
                        "fixed at non-current rotation",
                    ));
                }
                Ok(self.query_fixed(AssignmentColumn::new(column.index, ColumnType::Fixed)))
            }
            AnyColumn::Instance => Ok(self.query_instance(
                AssignmentColumn::new(column.index, ColumnType::Instance),
                at,
            )),
        }
    }
}

pub struct Constraints {
    pub selector: Option<Expression>,
    pub constraints: Vec<Expression>,
}

impl Constraints {
    pub fn get_constraints(&self) -> Halo2Result<Vec<Expression>> {
        match &self.selector {
            None => Ok(self.constraints.clone()),
            Some(s) => {
                let mut out = Vec::with_capacity(self.constraints.len());
                for e in self.constraints.iter() {
                    out.push(s.try_mul_expr(e)?);
                }
                Ok(out)
            }
        }
    }
}
