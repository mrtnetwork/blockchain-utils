//! Implements utility/range_constrained logic.
//! `bitrange_of` uses LE bit selection; no throws.

#[cfg(feature = "alloc")]
use alloc::string::String;

use crate::zk::orchard_halo2::field::PallasFp;
use crate::zk::orchard_halo2::utility::layouter::AssignedCell;
use crate::zk::orchard_halo2::utility::utils::bitrange_subset;

#[derive(Clone)]
pub struct RangeConstrained<F> {
    pub inner: F,
    pub num_bits: usize,
}

impl RangeConstrained<Option<PallasFp>> {
    pub fn bitrange_of(value: Option<PallasFp>, start: usize, end: usize) -> Self {
        let num_bits = end.saturating_sub(start);
        match value {
            None => Self {
                inner: None,
                num_bits,
            },
            Some(v) => Self {
                inner: Some(bitrange_subset(v, start, end).unwrap_or(PallasFp::zero())),
                num_bits,
            },
        }
    }
}

impl RangeConstrained<AssignedCell<PallasFp>> {
    pub fn value(&self) -> RangeConstrained<Option<PallasFp>> {
        RangeConstrained {
            inner: self.inner.value,
            num_bits: self.num_bits,
        }
    }
}

pub struct RangeConstrainedAssigned {
    pub inner: AssignedCell<PallasFp>,
    pub num_bits: usize,
}

impl RangeConstrainedAssigned {
    pub fn value(&self) -> RangeConstrained<Option<PallasFp>> {
        RangeConstrained {
            inner: self.inner.value,
            num_bits: self.num_bits,
        }
    }

    #[cfg(feature = "alloc")]
    pub fn to_debug_string(&self) -> String {
        alloc::format!("RangeConstrained(bits: {})", self.num_bits)
    }
}
