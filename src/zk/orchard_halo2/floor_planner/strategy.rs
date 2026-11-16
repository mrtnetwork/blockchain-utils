//! Implements floor_planner/strategy logic (first-fit region packing).
//! `SplayTreeSet` → sorted `Vec`; `assert!` on slack → `Err` path.
//! Debug via `format!`.

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

use crate::zk::orchard_halo2::error::{Halo2Error, Halo2Result};
use crate::zk::orchard_halo2::floor_planner::pdqsort::quicksort;
use crate::zk::orchard_halo2::plonk::column::AnyColumn;
use crate::zk::orchard_halo2::utility::layouter::{RegionColumn, RegionShape};

// Packed region placements: (column, allocation) pairs per region.
type SlotAllocations = Vec<(RegionColumn, AllocationsRegion)>;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AllocatedRegion {
    pub start: usize,
    pub length: usize,
}

impl AllocatedRegion {
    pub fn end(&self) -> usize {
        self.start + self.length
    }
}

// Ordered by start only (length excluded on purpose: regions are keyed by
// position, so derived lexicographic order would be wrong).
#[allow(clippy::non_canonical_partial_ord_impl)]
impl PartialOrd for AllocatedRegion {
    fn partial_cmp(&self, o: &Self) -> Option<core::cmp::Ordering> {
        Some(self.start.cmp(&o.start))
    }
}

impl Ord for AllocatedRegion {
    fn cmp(&self, o: &Self) -> core::cmp::Ordering {
        self.start.cmp(&o.start)
    }
}

#[derive(Clone, Copy)]
pub struct EmptySpace {
    pub start: usize,
    pub end: Option<usize>,
}

#[derive(Clone, Default)]
pub struct AllocationsRegion {
    regions: Vec<AllocatedRegion>,
}

impl AllocationsRegion {
    pub fn new() -> Self {
        Self {
            regions: Vec::new(),
        }
    }

    pub fn unbounded_interval_start(&self) -> usize {
        self.regions.last().map(|r| r.start + r.length).unwrap_or(0)
    }

    pub fn free_intervals(&self, start: usize, end: Option<usize>) -> Vec<EmptySpace> {
        let mut out = Vec::new();
        let mut row = start;
        for region in self.regions.iter() {
            if let Some(e) = end {
                if region.start >= e {
                    break;
                }
            }
            if row < region.start {
                out.push(EmptySpace {
                    start: row,
                    end: Some(region.start),
                });
            }
            row = core::cmp::max(row, region.end());
        }
        if end.is_none() || row < end.unwrap_or(usize::MAX) {
            out.push(EmptySpace { start: row, end });
        }
        out
    }

    pub fn add(&mut self, start: usize, length: usize) {
        let r = AllocatedRegion { start, length };
        let pos = self
            .regions
            .iter()
            .position(|x| *x > r)
            .unwrap_or(self.regions.len());
        self.regions.insert(pos, r);
    }
}

pub struct FloorPlannerUtils;

impl FloorPlannerUtils {
    pub fn first_fit_region(
        allocations: &mut Vec<(RegionColumn, AllocationsRegion)>,
        region_columns: &[RegionColumn],
        region_length: usize,
        start: usize,
        slack: Option<usize>,
    ) -> Halo2Result<Option<usize>> {
        if region_columns.is_empty() {
            return Ok(Some(start));
        }
        let c = region_columns[0].clone();
        let rest = &region_columns[1..];
        let end = slack.map(|s| start + region_length + s);
        let idx = match allocations.iter().position(|(k, _)| *k == c) {
            Some(i) => i,
            None => {
                allocations.push((c, AllocationsRegion::new()));
                allocations.len() - 1
            }
        };
        // Snapshot free intervals (recursion may extend allocations).
        let spaces = allocations[idx].1.free_intervals(start, end);
        for space in spaces.into_iter() {
            // Signed: a space smaller than the region yields negative slack
            // (skip), exactly like reference. Never saturate to zero.
            let s_slack_i = space
                .end
                .map(|e| e as i64 - space.start as i64 - region_length as i64);
            if s_slack_i.unwrap_or(1 << 30) >= 0 {
                let s_slack = s_slack_i.map(|v| v as usize);
                let row =
                    Self::first_fit_region(allocations, rest, region_length, space.start, s_slack)?;
                if let Some(row) = row {
                    allocations[idx].1.add(row, region_length);
                    return Ok(Some(row));
                }
            }
        }
        Ok(None)
    }

    pub fn slot_in(
        shapes: &[RegionShape],
    ) -> Halo2Result<(Vec<(usize, usize)>, SlotAllocations)> {
        let mut allocations: Vec<(RegionColumn, AllocationsRegion)> = Vec::new();
        let mut regions: Vec<(usize, usize)> = Vec::new();
        for (i, region) in shapes.iter().enumerate() {
            let mut cols = region.columns.clone();
            cols.sort();
            let start =
                Self::first_fit_region(&mut allocations, &cols, region.row_count(), 0, None)?
                    .ok_or_else(|| Halo2Error::operation_failed("planner::slot_in", "no fit"))?;
            regions.push((start, i));
        }
        Ok((regions, allocations))
    }

    fn sort_key(shape: &RegionShape) -> usize {
        let advice_cols = shape
            .columns
            .iter()
            .filter(
                |c| matches!(c, RegionColumn::Column(col) if col.column_type == AnyColumn::Advice),
            )
            .count();
        advice_cols * shape.row_count()
    }

    pub fn slot_in_biggest_advice_first(
        shapes: Vec<RegionShape>,
        legacy_pdqsort: bool,
    ) -> Halo2Result<(Vec<usize>, SlotAllocations)> {
        let n = shapes.len();
        let mut order: Vec<usize> = (0..n).collect();
        if legacy_pdqsort {
            let mut keyed: Vec<(usize, usize)> = order
                .iter()
                .map(|i| (Self::sort_key(&shapes[*i]), *i))
                .collect();
            quicksort(&mut keyed, &|a: &(usize, usize), b: &(usize, usize)| {
                a.0 < b.0
            });
            order = keyed.into_iter().map(|(_, i)| i).collect();
        } else {
            order.sort_by(|a, b| {
                Self::sort_key(&shapes[*a])
                    .cmp(&Self::sort_key(&shapes[*a]))
                    .then(a.cmp(b))
            });
        }
        order.reverse();
        let sorted: Vec<RegionShape> = order.iter().map(|i| shapes[*i].clone_shape()).collect();
        let (placed, allocations) = Self::slot_in(&sorted)?;
        // Un-sort: `placed[k]` belongs to `sorted[k]`, i.e. original `order[k]`.
        let mut result = vec![0usize; n];
        for (k, (start, _)) in placed.into_iter().enumerate() {
            result[order[k]] = start;
        }
        Ok((result, allocations))
    }

    #[cfg(feature = "alloc")]
    pub fn to_debug_string() -> String {
        alloc::string::String::from("FloorPlannerUtils")
    }
}
