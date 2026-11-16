//! Implements plonk/proof logic (witness collection, AST leaves).
//! Row bounds become `Halo2Result`. Debug via `format!`.

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

use crate::zk::orchard_halo2::error::{Halo2Error, Halo2Result};
use crate::zk::orchard_halo2::field::PallasFp;
use crate::zk::orchard_halo2::plonk::assigned::Assigned;
use crate::zk::orchard_halo2::plonk::assignment::UsableRows;
use crate::zk::orchard_halo2::plonk::column::{AssignmentColumn, Selector};
use crate::zk::orchard_halo2::plonk::key::PlonkProvingKey;
use crate::zk::orchard_halo2::poly::evaluator::{AstLeaf, Evaluator};
use crate::zk::orchard_halo2::poly::poly::{Basis, Polynomial};
use crate::zk::orchard_halo2::utility::layouter::Assignment;

pub struct PolyInstanceSingle {
    pub instance_values: Vec<Polynomial<PallasFp>>,
    pub instance_polys: Vec<Polynomial<PallasFp>>,
    pub instance_cosets: Vec<Polynomial<PallasFp>>,
}

pub struct PolyAdviceSingle {
    pub advice_values: Vec<Polynomial<PallasFp>>,
    pub advice_polys: Vec<Polynomial<PallasFp>>,
    pub advice_cosets: Vec<Polynomial<PallasFp>>,
    pub advice_blinds: Vec<PallasFp>,
}

pub struct PlonkWitnessCollection {
    pub k: u32,
    pub advice: Vec<Polynomial<Assigned>>,
    pub instances: Vec<Vec<PallasFp>>,
    pub usable_rows: UsableRows,
}

impl Assignment for PlonkWitnessCollection {
    fn enable_selector(&mut self, _selector: Selector, _row: usize) -> Halo2Result<()> {
        Ok(())
    }

    fn query_instance(
        &self,
        column: AssignmentColumn,
        row: usize,
    ) -> Halo2Result<Option<PallasFp>> {
        if !self.usable_rows.contains(row) {
            return Err(Halo2Error::operation_failed(
                "witness::query_instance",
                "row out of range",
            ));
        }
        let col = self.instances.get(column.index).ok_or_else(|| {
            Halo2Error::operation_failed("witness::query_instance", "column out of range")
        })?;
        col.get(row)
            .copied()
            .ok_or_else(|| Halo2Error::operation_failed("witness::query_instance", "row overflow"))
            .map(Some)
    }

    fn assign_advice(
        &mut self,
        column: AssignmentColumn,
        row: usize,
        to: &mut dyn FnMut() -> Option<Assigned>,
    ) -> Halo2Result<()> {
        if !self.usable_rows.contains(row) {
            return Err(Halo2Error::operation_failed(
                "witness::assign_advice",
                "row out of range",
            ));
        }
        let v = to().ok_or_else(|| {
            Halo2Error::operation_failed("witness::assign_advice", "missing value")
        })?;
        let col = self.advice.get_mut(column.index).ok_or_else(|| {
            Halo2Error::operation_failed("witness::assign_advice", "column out of range")
        })?;
        let slot = col.values.get_mut(row).ok_or_else(|| {
            Halo2Error::operation_failed("witness::assign_advice", "row overflow")
        })?;
        *slot = v;
        Ok(())
    }

    fn assign_fixed(
        &mut self,
        _column: AssignmentColumn,
        _row: usize,
        _to: &mut dyn FnMut() -> Option<Assigned>,
    ) -> Halo2Result<()> {
        Ok(())
    }

    fn copy(
        &mut self,
        _left_column: crate::zk::orchard_halo2::plonk::column::AnyAssignmentColumn,
        _left_row: usize,
        _right_column: crate::zk::orchard_halo2::plonk::column::AnyAssignmentColumn,
        _right_row: usize,
    ) -> Halo2Result<()> {
        Ok(())
    }

    fn fill_from_row(
        &mut self,
        _column: AssignmentColumn,
        _from_row: usize,
        _to: Option<Assigned>,
    ) -> Halo2Result<()> {
        Ok(())
    }
}

pub struct AstLeaves {
    pub advice: Vec<PolyAdviceSingle>,
    pub instance: Vec<PolyInstanceSingle>,
    pub value_evaluator: Evaluator,
    pub coset_evaluator: Evaluator,
    pub fixed_values: Vec<AstLeaf>,
    pub advice_values: Vec<Vec<AstLeaf>>,
    pub instance_values: Vec<Vec<AstLeaf>>,
    pub fixed_cosets: Vec<AstLeaf>,
    pub advice_cosets: Vec<Vec<AstLeaf>>,
    pub instance_cosets: Vec<Vec<AstLeaf>>,
    pub permutation_cosets: Vec<AstLeaf>,
    pub l0: AstLeaf,
    pub l_blind: AstLeaf,
    pub l_last: AstLeaf,
}

impl AstLeaves {
    pub fn build(
        pk: &PlonkProvingKey,
        advice: Vec<PolyAdviceSingle>,
        instance: Vec<PolyInstanceSingle>,
    ) -> Self {
        let mut value_evaluator = Evaluator::new(Basis::Lagrange);
        let fixed_values: Vec<AstLeaf> = pk
            .fixed_values
            .iter()
            .map(|p| value_evaluator.register_poly(p.clone()))
            .collect();
        let advice_values: Vec<Vec<AstLeaf>> = advice
            .iter()
            .map(|a| {
                a.advice_values
                    .iter()
                    .map(|p| value_evaluator.register_poly(p.clone()))
                    .collect()
            })
            .collect();
        let instance_values: Vec<Vec<AstLeaf>> = instance
            .iter()
            .map(|ins| {
                ins.instance_values
                    .iter()
                    .map(|p| value_evaluator.register_poly(p.clone()))
                    .collect()
            })
            .collect();
        let mut coset_evaluator = Evaluator::new(Basis::Extended);
        let fixed_cosets: Vec<AstLeaf> = pk
            .fixed_cosets
            .iter()
            .map(|p| coset_evaluator.register_poly(p.clone()))
            .collect();
        let advice_cosets: Vec<Vec<AstLeaf>> = advice
            .iter()
            .map(|a| {
                a.advice_cosets
                    .iter()
                    .map(|p| coset_evaluator.register_poly(p.clone()))
                    .collect()
            })
            .collect();
        let instance_cosets: Vec<Vec<AstLeaf>> = instance
            .iter()
            .map(|ins| {
                ins.instance_cosets
                    .iter()
                    .map(|p| coset_evaluator.register_poly(p.clone()))
                    .collect()
            })
            .collect();
        let permutation_cosets: Vec<AstLeaf> = pk
            .permutation
            .cosets
            .iter()
            .map(|p| coset_evaluator.register_poly(p.clone()))
            .collect();
        let l0 = coset_evaluator.register_poly(pk.l0.clone());
        let l_blind = coset_evaluator.register_poly(pk.l_blind.clone());
        let l_last = coset_evaluator.register_poly(pk.l_last.clone());
        Self {
            advice,
            instance,
            value_evaluator,
            coset_evaluator,
            fixed_values,
            advice_values,
            instance_values,
            fixed_cosets,
            advice_cosets,
            instance_cosets,
            permutation_cosets,
            l0,
            l_blind,
            l_last,
        }
    }

    #[cfg(feature = "alloc")]
    pub fn to_debug_string(&self) -> String {
        alloc::string::String::from("AstLeaves")
    }
}
