//! Implements plonk/compress_selectors logic.
//! `assert`s become `Halo2Result`. Combination expressions built with
//! `try_*` operators; fixed queries carry no simple selectors so they
//! cannot fail, but errors still propagate instead of panicking.

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

use crate::zk::orchard_halo2::error::{Halo2Error, Halo2Result};
use crate::zk::orchard_halo2::field::PallasFp;
use crate::zk::orchard_halo2::plonk::expression::Expression;

pub struct SelectorDescription {
    pub selector: usize,
    pub activations: Vec<bool>,
    pub max_degree: usize,
}

pub struct SelectorAssignment {
    pub selector: usize,
    pub combination_index: usize,
    pub expression: Expression,
}

impl SelectorAssignment {
    #[cfg(feature = "alloc")]
    pub fn to_debug_string(&self) -> String {
        alloc::format!(
            "SelectorAssignment(selector: {}, combination: {}, expr: {})",
            self.selector,
            self.combination_index,
            self.expression.to_debug_string()
        )
    }
}

/// `SelectorDescription.process`: returns (combination polys, assignments).
pub fn process_selectors(
    mut selectors: Vec<SelectorDescription>,
    max_degree: usize,
    allocate_fixed_column: &mut dyn FnMut() -> Expression,
) -> Halo2Result<(Vec<Vec<PallasFp>>, Vec<SelectorAssignment>)> {
    if selectors.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }
    let n = selectors[0].activations.len();
    for s in selectors.iter() {
        if s.activations.len() != n {
            return Err(Halo2Error::operation_failed(
                "compress::process",
                "row mismatch",
            ));
        }
    }
    let mut combination_assignments: Vec<Vec<PallasFp>> = Vec::new();
    let mut selector_assignments: Vec<SelectorAssignment> = Vec::new();

    // Degree-0 selectors first.
    let mut rest: Vec<SelectorDescription> = Vec::new();
    for s in selectors.drain(..) {
        if s.max_degree == 0 {
            let expression = allocate_fixed_column();
            let combo: Vec<PallasFp> = s
                .activations
                .iter()
                .map(|b| {
                    if *b {
                        PallasFp::one()
                    } else {
                        PallasFp::zero()
                    }
                })
                .collect();
            let idx = combination_assignments.len();
            combination_assignments.push(combo);
            selector_assignments.push(SelectorAssignment {
                selector: s.selector,
                combination_index: idx,
                expression,
            });
        } else {
            rest.push(s);
        }
    }
    selectors = rest;

    // Exclusion matrix (lower triangular).
    let mut exclusion: Vec<Vec<bool>> = (0..selectors.len()).map(|i| vec![false; i]).collect();
    for i in 0..selectors.len() {
        for j in 0..i {
            let mut conflict = false;
            for k in 0..n {
                if selectors[i].activations[k] && selectors[j].activations[k] {
                    conflict = true;
                    break;
                }
            }
            if conflict {
                exclusion[i][j] = true;
            }
        }
    }

    let mut added = vec![false; selectors.len()];
    for i in 0..selectors.len() {
        if added[i] {
            continue;
        }
        if selectors[i].max_degree > max_degree {
            return Err(Halo2Error::operation_failed(
                "compress::process",
                "degree overflow",
            ));
        }
        added[i] = true;
        let mut d = selectors[i].max_degree.saturating_sub(1);
        let mut combination: Vec<usize> = vec![i];

        for j in (i + 1)..selectors.len() {
            if d + combination.len() == max_degree {
                break;
            }
            if added[j] {
                continue;
            }
            let mut excluded = false;
            for k in combination.iter() {
                let (a, b) = if j > *k { (j, *k) } else { (*k, j) };
                if a != b && exclusion[a][b] {
                    excluded = true;
                    break;
                }
            }
            if excluded {
                continue;
            }
            let new_d = core::cmp::max(d, selectors[j].max_degree.saturating_sub(1));
            if new_d + combination.len() + 1 > max_degree {
                continue;
            }
            d = new_d;
            combination.push(j);
            added[j] = true;
        }

        let mut combo_assign = vec![PallasFp::zero(); n];
        let combo_len = combination.len();
        let combo_index = combination_assignments.len();
        let query = allocate_fixed_column();
        let mut assigned_root = PallasFp::one();

        for sel_idx in combination.iter() {
            let sel = &selectors[*sel_idx];
            let mut expression = query.clone();
            let mut root = PallasFp::one();
            for _ in 0..combo_len {
                if root != assigned_root {
                    let diff = Expression::constant(root).try_sub(&query)?;
                    expression = expression.try_mul_expr(&diff)?;
                }
                root = root.add_vartime(&PallasFp::one());
            }
            for (r, slot) in combo_assign.iter_mut().enumerate().take(n) {
                if sel.activations[r] {
                    *slot = assigned_root;
                }
            }
            selector_assignments.push(SelectorAssignment {
                selector: sel.selector,
                combination_index: combo_index,
                expression,
            });
            assigned_root = assigned_root.add_vartime(&PallasFp::one());
        }
        combination_assignments.push(combo_assign);
    }

    Ok((combination_assignments, selector_assignments))
}
