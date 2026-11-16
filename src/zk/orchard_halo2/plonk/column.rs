//! Implements plonk/column logic (column types, selectors).
//! Debug via `format!`; `from_value` returns `Result` (no throw).

#[cfg(feature = "alloc")]
use alloc::string::String;

use crate::zk::orchard_halo2::error::{Halo2Error, Halo2Result};
use crate::zk::orchard_halo2::poly::poly::Rotation;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ColumnTypeName {
    Advice = 0,
    Fixed = 1,
    Instance = 2,
    AnyInstance = 3,
    AnyAdvice = 4,
    AnyFixed = 5,
}

impl ColumnTypeName {
    pub fn from_value(v: i32) -> Halo2Result<Self> {
        match v {
            0 => Ok(Self::Advice),
            1 => Ok(Self::Fixed),
            2 => Ok(Self::Instance),
            3 => Ok(Self::AnyInstance),
            4 => Ok(Self::AnyAdvice),
            5 => Ok(Self::AnyFixed),
            _ => Err(Halo2Error::operation_failed("column_type", "unknown value")),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ColumnType {
    Advice,
    Fixed,
    Instance,
}

impl ColumnType {
    pub fn to_any(&self) -> AnyColumn {
        match self {
            Self::Advice => AnyColumn::Advice,
            Self::Fixed => AnyColumn::Fixed,
            Self::Instance => AnyColumn::Instance,
        }
    }

    #[cfg(feature = "alloc")]
    pub fn to_debug_string(&self) -> String {
        match self {
            Self::Advice => alloc::string::String::from("Advice"),
            Self::Fixed => alloc::string::String::from("Fixed"),
            Self::Instance => alloc::string::String::from("Instance"),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum AnyColumn {
    Instance,
    Advice,
    Fixed,
}

impl AnyColumn {
    pub fn rank(&self) -> u8 {
        match self {
            Self::Instance => 0,
            Self::Advice => 1,
            Self::Fixed => 2,
        }
    }

    #[cfg(feature = "alloc")]
    pub fn to_debug_string(&self) -> String {
        match self {
            Self::Instance => alloc::string::String::from("Instance"),
            Self::Advice => alloc::string::String::from("Advice"),
            Self::Fixed => alloc::string::String::from("Fixed"),
        }
    }
}

// Ordered by rank only (derived lexicographic order over variants would
// impose a meaningless order on column kinds).
#[allow(clippy::non_canonical_partial_ord_impl)]
impl PartialOrd for AnyColumn {
    fn partial_cmp(&self, o: &Self) -> Option<core::cmp::Ordering> {
        Some(self.rank().cmp(&o.rank()))
    }
}

impl Ord for AnyColumn {
    fn cmp(&self, o: &Self) -> core::cmp::Ordering {
        self.rank().cmp(&o.rank())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct AssignmentColumn {
    pub index: usize,
    pub column_type: ColumnType,
}

impl AssignmentColumn {
    pub fn new(index: usize, column_type: ColumnType) -> Self {
        Self { index, column_type }
    }

    #[cfg(feature = "alloc")]
    pub fn to_debug_string(&self) -> String {
        alloc::format!(
            "Column {{ index: {}, column_type: {} }}",
            self.index,
            self.column_type.to_debug_string()
        )
    }

    pub fn to_any(&self) -> AnyAssignmentColumn {
        AnyAssignmentColumn {
            index: self.index,
            column_type: self.column_type.to_any(),
        }
    }
}

impl PartialOrd for AssignmentColumn {
    fn partial_cmp(&self, o: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(o))
    }
}

impl Ord for AssignmentColumn {
    fn cmp(&self, o: &Self) -> core::cmp::Ordering {
        match self.column_type.to_any().cmp(&o.column_type.to_any()) {
            core::cmp::Ordering::Equal => self.index.cmp(&o.index),
            x => x,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct AnyAssignmentColumn {
    pub index: usize,
    pub column_type: AnyColumn,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ColumnWithRotation {
    pub column: AssignmentColumn,
    pub rotation: Rotation,
}

impl ColumnWithRotation {
    #[cfg(feature = "alloc")]
    pub fn to_debug_string(&self) -> String {
        alloc::format!(
            "({}, {})",
            self.column.to_debug_string(),
            self.rotation.to_debug_string()
        )
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct TableColumn {
    pub inner: AssignmentColumn,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Selector {
    pub offset: usize,
    pub is_simple: bool,
}

impl Selector {
    pub fn new(offset: usize, is_simple: bool) -> Self {
        Self { offset, is_simple }
    }

    pub fn enable(
        &self,
        region: &mut crate::zk::orchard_halo2::utility::layouter::Region<'_>,
        offset: usize,
    ) -> crate::zk::orchard_halo2::error::Halo2Result<()> {
        region.enable_selector(*self, offset)
    }

    #[cfg(feature = "alloc")]
    pub fn to_debug_string(&self) -> String {
        alloc::format!("Selector({}, {})", self.offset, self.is_simple)
    }
}
