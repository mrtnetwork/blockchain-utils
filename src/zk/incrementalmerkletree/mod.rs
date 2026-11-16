//! Incremental Merkle tree (frontier) — zero-dependency port of the Rust
//! `incrementalmerkletree 0.8` API shape, with the `merkle/types`
//! grouping (`NonEmptyFrontier`, `Frontier`, `CommitmentTree`,
//! `Retention`, `Marking`, `MerklePath`, …).
//!
//! Layout mirrors the Rust crate 1:1: this module (`lib.rs`: tree
//! coordinates, `MerklePath`, `Hashable`, errors), [`frontier`]
//! (`frontier.rs`: frontiers, commitment tree), [`witness`]
//! (`witness.rs`: incremental witnesses), [`bridge`] (Sapling/Orchard node
//! types for anchor trees).
//!
//! # Error handling
//!
//! Every fallible operation returns [`Result`]; this port contains no
//! `panic!`, `assert!`, `unwrap`, or `expect` on reachable paths. Where the
//! Rust API panics, this port documents the deviation inline:
//!
//! - [`Position`] subtraction saturates at zero instead of panicking on
//!   underflow; [`Position::checked_sub`] reports it as an error.
//! - [`Level`] `+`/`-` wrap instead of panicking; tree depths involved never
//!   approach the `u8` bounds.
//! - Bit shifts at levels `>= 64` are treated as out-of-range (empty) instead
//!   of panicking; real depths are `<= 32`.
//! - [`CommitmentTree::to_frontier`](frontier::CommitmentTree::to_frontier)
//!   returns [`Result`] instead of panicking on inconsistent trees.
//! - [`MerklePath::from_parts`] reports
//!   [`MerkleError::LengthMismatch`] instead of `()`.
//! - [`CommitmentTree::append`](frontier::CommitmentTree::append) and
//!   [`IncrementalWitness::append`](witness::IncrementalWitness::append)
//!   report [`MerkleError::TreeFull`] instead of `()`.
//! - Bridge [`Hashable::combine`](Hashable::combine) implementations are
//!   infallible by trait shape; the underlying hash cannot fail for the fixed
//!   protocol domains — a zero node is produced only on the
//!   cryptographically unreachable identity edge (see [`bridge`]).
//!
//! # Feature gates
//!
//! The core is `alloc`-only (`no_std` clean). [`bridge`] items are gated:
//! Sapling needs `groth16-prover`, Orchard needs `halo2`.

use alloc::vec::Vec;
use core::cmp::Ordering;
use core::fmt;
use core::num::TryFromIntError;
use core::ops::{Add, AddAssign, Range, Sub};

pub mod bridge;
pub mod contexts;
pub mod frontier;
pub mod witness;

/// Errors for incremental Merkle tree operations. Every fallible API in this
/// module returns [`Result<_, MerkleError>`]; nothing panics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MerkleError {
    /// Frontier ommer count does not match the position.
    PositionMismatch {
        /// Required ommer count for the position.
        expected_ommers: u8,
    },
    /// The tree would exceed the maximum statically allowed depth.
    MaxDepthExceeded {
        /// Minimum depth the tree would require.
        depth: u8,
    },
    /// A part list has the wrong length (paths, tree parts).
    LengthMismatch {
        /// Required length.
        expected: usize,
        /// Provided length.
        found: usize,
    },
    /// The tree is full; no more leaves can be appended.
    TreeFull,
    /// A reconstructed tree is internally inconsistent.
    InconsistentTree,
    /// Requested data is absent (unknown checkpoint, unwitnessable range).
    Missing,
    /// A node encoding is invalid.
    InvalidEncoding,
    /// A position would underflow.
    PositionUnderflow,
    /// A leaf position does not fit in the tree depth.
    PositionOutOfRange {
        /// Tree depth in levels.
        depth: u8,
    },
}

impl fmt::Display for MerkleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MerkleError::PositionMismatch { expected_ommers } => write!(
                f,
                "frontier ommer count mismatch: expected {expected_ommers}"
            ),
            MerkleError::MaxDepthExceeded { depth } => {
                write!(f, "tree exceeds maximum depth (needs {depth})")
            }
            MerkleError::LengthMismatch { expected, found } => {
                write!(f, "length mismatch: expected {expected}, found {found}")
            }
            MerkleError::TreeFull => write!(f, "tree is full"),
            MerkleError::InconsistentTree => write!(f, "inconsistent tree parts"),
            MerkleError::Missing => write!(f, "requested checkpoint or witness data is absent"),
            MerkleError::InvalidEncoding => write!(f, "invalid node encoding"),
            MerkleError::PositionUnderflow => write!(f, "position underflow"),
            MerkleError::PositionOutOfRange { depth } => {
                write!(f, "position does not fit in depth {depth}")
            }
        }
    }
}

impl core::error::Error for MerkleError {}

/// Minimal `Either` (mirrors the `either` crate used upstream).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Either<L, R> {
    /// Left value.
    Left(L),
    /// Right value.
    Right(R),
}

impl<L, R> Either<L, R> {
    /// Returns `true` for [`Either::Left`].
    pub fn is_left(&self) -> bool {
        matches!(self, Either::Left(_))
    }

    /// Returns `true` for [`Either::Right`].
    pub fn is_right(&self) -> bool {
        matches!(self, Either::Right(_))
    }

    /// Left value, if present.
    pub fn left(self) -> Option<L> {
        match self {
            Either::Left(l) => Some(l),
            Either::Right(_) => None,
        }
    }

    /// Right value, if present.
    pub fn right(self) -> Option<R> {
        match self {
            Either::Left(_) => None,
            Either::Right(r) => Some(r),
        }
    }
}

/// Marking for checkpoint retention handling.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Marking {
    /// A checkpoint with `Marked` marking will have `Marked` retention after `Checkpoint`
    /// retention is removed.
    Marked,
    /// A checkpoint with `Reference` marking will have `Reference` retention after `Checkpoint`
    /// retention is removed.
    Reference,
    /// A checkpoint with `None` marking will have `Ephemeral` retention after `Checkpoint`
    /// retention is removed.
    None,
}

/// Metadata that determines when and how a leaf can be pruned from a tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Retention<C> {
    /// Pruned whenever its sibling is also an `Ephemeral` leaf.
    Ephemeral,
    /// Position retained during pruning; value may be merged. Removing the
    /// checkpoint yields `Ephemeral`, `Marked`, or `Reference` per `marking`.
    Checkpoint { id: C, marking: Marking },
    /// Retained during pruning; only explicitly removed.
    Marked,
    /// Retained during pruning; removed when overwritten by a node with
    /// `Ephemeral`, `Checkpoint`, or `Marked` retention.
    Reference,
}

impl<C> Retention<C> {
    /// Returns whether this is [`Retention::Checkpoint`].
    pub fn is_checkpoint(&self) -> bool {
        matches!(self, Retention::Checkpoint { .. })
    }

    /// Returns whether this is [`Retention::Marked`] or a `Checkpoint` with
    /// [`Marking::Marked`] marking.
    pub fn is_marked(&self) -> bool {
        matches!(
            self,
            Retention::Marked
                | Retention::Checkpoint {
                    marking: Marking::Marked,
                    ..
                }
        )
    }

    /// Maps a checkpoint identifier, preserving structure.
    pub fn map<'a, D, F: Fn(&'a C) -> D>(&'a self, f: F) -> Retention<D> {
        match self {
            Retention::Ephemeral => Retention::Ephemeral,
            Retention::Checkpoint { id, marking } => Retention::Checkpoint {
                id: f(id),
                marking: *marking,
            },
            Retention::Marked => Retention::Marked,
            Retention::Reference => Retention::Reference,
        }
    }
}

/// Whether a witness sibling comes from the frontier's past or future.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Source {
    /// Sibling derived from the frontier at the contained ommer index.
    Past(u8),
    /// Sibling must come from nodes added after the witnessed leaf.
    Future,
}

#[must_use = "iterators are lazy and do nothing unless consumed"]
struct WitnessAddrsIter {
    root_level: Level,
    current: Address,
    ommer_count: u8,
}

impl Iterator for WitnessAddrsIter {
    type Item = (Address, Source);

    fn next(&mut self) -> Option<(Address, Source)> {
        if self.current.level() < self.root_level {
            let current = self.current;
            let source = if current.is_right_child() {
                Source::Past(self.ommer_count)
            } else {
                Source::Future
            };

            self.current = current.parent();
            if matches!(source, Source::Past(_)) {
                self.ommer_count = self.ommer_count.saturating_add(1);
            }

            Some((current.sibling(), source))
        } else {
            None
        }
    }
}

/// Position of a leaf in a Merkle tree.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Position(u64);

impl Position {
    /// Whether this is the right-hand child of a level-1 subtree.
    pub fn is_right_child(&self) -> bool {
        self.0 & 0x1 == 1
    }

    /// Minimum root level of a binary tree holding at least `self + 1` leaves.
    pub fn root_level(&self) -> Level {
        Level((u64::BITS - self.0.leading_zeros()) as u8)
    }

    /// Cousins/ommers needed for an authentication path to a tree with
    /// `self + 1` leaves.
    pub fn past_ommer_count(&self) -> u8 {
        // At most 64 bits set; always fits u8.
        (0..self.root_level().0)
            .filter(|i| (self.0 >> i) & 0x1 == 1)
            .count() as u8
    }

    /// Whether the tree with `self` as rightmost leaf contains a perfect
    /// balanced subtree rooted at `root_level` containing that leaf.
    pub fn is_complete_subtree(&self, root_level: Level) -> bool {
        !(0..(root_level.0)).any(|l| {
            if l >= 64 {
                // Bits beyond the u64 position are zero (out of range).
                true
            } else {
                self.0 & (1 << l) == 0
            }
        })
    }

    /// Addresses of nodes required to witness this position, from the leaf's
    /// sibling up to the sibling required for `root_level`.
    pub fn witness_addrs(&self, root_level: Level) -> impl Iterator<Item = (Address, Source)> {
        WitnessAddrsIter {
            root_level,
            current: Address::from(*self),
            ommer_count: 0,
        }
    }

    /// Checked subtraction; [`MerkleError::PositionUnderflow`] instead of panicking.
    pub fn checked_sub(self, other: u64) -> Result<Position, MerkleError> {
        self.0
            .checked_sub(other)
            .map(Position)
            .ok_or(MerkleError::PositionUnderflow)
    }
}

impl From<Position> for u64 {
    fn from(p: Position) -> Self {
        p.0
    }
}

impl From<u64> for Position {
    fn from(sz: u64) -> Self {
        Self(sz)
    }
}

impl Add<u64> for Position {
    type Output = Position;
    fn add(self, other: u64) -> Self {
        Position(self.0.saturating_add(other))
    }
}

impl AddAssign<u64> for Position {
    fn add_assign(&mut self, other: u64) {
        self.0 = self.0.saturating_add(other);
    }
}

impl Sub<u64> for Position {
    type Output = Position;
    fn sub(self, other: u64) -> Self {
        // Deviation: saturates at zero instead of panicking on underflow;
        // use checked_sub to detect it. Unreachable for valid tree positions.
        Position(self.0.saturating_sub(other))
    }
}

impl TryFrom<usize> for Position {
    type Error = TryFromIntError;
    fn try_from(sz: usize) -> Result<Self, Self::Error> {
        <u64>::try_from(sz).map(Self)
    }
}

impl TryFrom<Position> for usize {
    type Error = TryFromIntError;
    fn try_from(p: Position) -> Result<Self, Self::Error> {
        <usize>::try_from(p.0)
    }
}

/// Index into tree levels (leaves are level 0). Depths involved never
/// approach the `u8` bounds; arithmetic wraps instead of panicking.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Level(u8);

impl Level {
    /// Leaf level.
    pub const ZERO: Self = Level(0);

    /// Wrap a raw level value.
    pub const fn new(value: u8) -> Self {
        Self(value)
    }

    /// Iterate levels `[self, other)`.
    pub fn iter_to(self, other: Level) -> impl Iterator<Item = Self> {
        (self.0..other.0).map(Level)
    }
}

impl Add<u8> for Level {
    type Output = Self;
    fn add(self, value: u8) -> Self {
        Self(self.0.wrapping_add(value))
    }
}

impl From<u8> for Level {
    fn from(value: u8) -> Self {
        Self(value)
    }
}

impl From<Level> for u8 {
    fn from(level: Level) -> u8 {
        level.0
    }
}

impl From<Level> for u32 {
    fn from(level: Level) -> u32 {
        level.0.into()
    }
}

impl From<Level> for u64 {
    fn from(level: Level) -> u64 {
        level.0.into()
    }
}

impl From<Level> for usize {
    fn from(level: Level) -> usize {
        // Sub-8-bit platforms are unsupported.
        level.0 as usize
    }
}

impl TryFrom<usize> for Level {
    type Error = TryFromIntError;
    fn try_from(sz: usize) -> Result<Self, Self::Error> {
        <u8>::try_from(sz).map(Self)
    }
}

impl Sub<u8> for Level {
    type Output = Self;
    fn sub(self, value: u8) -> Self {
        // Deviation: saturates instead of panicking on underflow.
        Self(self.0.saturating_sub(value))
    }
}

/// Address of a tree node. At level 0 the index is the leaf position.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address {
    level: Level,
    index: u64,
}

impl Address {
    /// Construct from parts.
    pub fn from_parts(level: Level, index: u64) -> Self {
        Address { level, index }
    }

    /// Address at `level` containing `position`.
    pub fn above_position(level: Level, position: Position) -> Self {
        Address {
            level,
            index: position.0 >> level.0,
        }
    }

    /// Node level.
    pub fn level(&self) -> Level {
        self.level
    }

    /// Node index: count of same-level subtrees to the left.
    pub fn index(&self) -> u64 {
        self.index
    }

    /// Parent address.
    pub fn parent(&self) -> Address {
        Address {
            level: self.level + 1,
            index: self.index >> 1,
        }
    }

    /// Sibling address (shares the parent).
    pub fn sibling(&self) -> Address {
        Address {
            level: self.level,
            index: self.index ^ 1,
        }
    }

    /// Immediate children, or `None` at level 0.
    pub fn children(&self) -> Option<(Address, Address)> {
        if self.level == Level::from(0) {
            None
        } else {
            let left = Address {
                level: self.level - 1,
                index: self.index.checked_shl(1).unwrap_or(u64::MAX),
            };
            let right = Address {
                level: self.level - 1,
                index: self
                    .index
                    .checked_shl(1)
                    .unwrap_or(u64::MAX)
                    .wrapping_add(1),
            };
            Some((left, right))
        }
    }

    /// Whether this address is an ancestor of `addr`.
    pub fn is_ancestor_of(&self, addr: &Self) -> bool {
        self.level > addr.level && { addr.index >> (self.level.0 - addr.level.0) == self.index }
    }

    /// Smallest-level common ancestor of two addresses.
    pub fn common_ancestor(&self, other: &Self) -> Self {
        let (higher, lower) = if self.level >= other.level {
            (self, other)
        } else {
            (other, self)
        };
        let lower_ancestor_idx = lower.index >> (higher.level.0 - lower.level.0);
        let index_delta = higher.index ^ lower_ancestor_idx;
        // Deviation: shifts >= 64 saturate the delta instead of panicking;
        // unreachable for real addresses.
        let level_delta = (u64::BITS - index_delta.leading_zeros()).min(63) as u8;
        Address {
            level: higher.level + level_delta,
            index: core::cmp::max(higher.index, lower_ancestor_idx) >> level_delta,
        }
    }

    /// Whether this address is an ancestor of, or equal to, `addr`.
    pub fn contains(&self, addr: &Self) -> bool {
        self == addr || self.is_ancestor_of(addr)
    }

    /// Minimum leaf position under this address.
    pub fn position_range_start(&self) -> Position {
        // Deviation: saturates instead of panicking on huge levels.
        self.index
            .checked_shl(self.level.0.into())
            .map(Position::from)
            .unwrap_or(Position(u64::MAX))
    }

    /// Exclusive end of leaf positions under this address.
    pub fn position_range_end(&self) -> Position {
        // Deviation: saturating arithmetic instead of panicking.
        self.index
            .saturating_add(1)
            .checked_shl(self.level.0.into())
            .map(Position::from)
            .unwrap_or(Position(u64::MAX))
    }

    /// Maximum leaf position under this address.
    pub fn max_position(&self) -> Position {
        self.position_range_end() - 1
    }

    /// End-exclusive leaf position range under this address.
    pub fn position_range(&self) -> Range<Position> {
        Range {
            start: self.position_range_start(),
            end: self.position_range_end(),
        }
    }

    /// Ancestor of this address at `level`, or the range of level-`level`
    /// subtree indices inside this address's subtree.
    pub fn context(&self, level: Level) -> Either<Address, Range<u64>> {
        if level >= self.level {
            Either::Left(Address {
                level,
                index: self.index >> (level.0 - self.level.0),
            })
        } else {
            let shift = self.level.0 - level.0;
            Either::Right(Range {
                start: self.index.checked_shl(shift.into()).unwrap_or(u64::MAX),
                end: self
                    .index
                    .saturating_add(1)
                    .checked_shl(shift.into())
                    .unwrap_or(u64::MAX),
            })
        }
    }

    /// Whether a same-level greater/lesser address holds `pos`.
    pub fn position_cmp(&self, pos: Position) -> Ordering {
        let range = self.position_range();
        if range.start > pos {
            Ordering::Greater
        } else if range.end <= pos {
            Ordering::Less
        } else {
            Ordering::Equal
        }
    }

    /// Whether this address is its parent's left child.
    pub fn is_left_child(&self) -> bool {
        self.index & 0x1 == 0
    }

    /// Whether this address is its parent's right child.
    pub fn is_right_child(&self) -> bool {
        self.index & 0x1 == 1
    }

    /// Nearest address at or above this one whose subtree is incomplete.
    pub fn current_incomplete(&self) -> Address {
        // Deviation: bounded loop with a fallback instead of `unreachable!`;
        // terminates within 64 iterations for real addresses.
        let mut index = self.index;
        for level in self.level.0..self.level.0.saturating_add(64) {
            if index & 0x1 == 1 {
                index >>= 1;
            } else {
                return Address {
                    level: Level(level),
                    index,
                };
            }
        }
        Address {
            level: self.level,
            index: self.index,
        }
    }

    /// Parent address at which this address's subtree becomes incomplete.
    pub fn next_incomplete_parent(&self) -> Address {
        if self.is_right_child() {
            self.current_incomplete()
        } else {
            let complete = Address {
                level: self.level,
                index: self.index.saturating_add(1),
            };
            complete.current_incomplete()
        }
    }

    /// This address's index plus one, same level.
    pub fn next_at_level(&self) -> Address {
        Address {
            level: self.level,
            index: self.index.saturating_add(1),
        }
    }
}

impl From<Position> for Address {
    fn from(p: Position) -> Self {
        Address {
            level: 0.into(),
            index: p.into(),
        }
    }
}

impl<'a> From<&'a Position> for Address {
    fn from(p: &'a Position) -> Self {
        Address {
            level: 0.into(),
            index: (*p).into(),
        }
    }
}

impl From<Address> for Option<Position> {
    fn from(addr: Address) -> Self {
        if addr.level == 0.into() {
            Some(addr.index.into())
        } else {
            None
        }
    }
}

/// Path from a leaf position to the tree root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerklePath<H, const DEPTH: u8> {
    path_elems: Vec<H>,
    position: Position,
}

impl<H, const DEPTH: u8> MerklePath<H, DEPTH> {
    /// Build from parts; [`MerkleError::LengthMismatch`] unless exactly
    /// `DEPTH` elements are provided.
    pub fn from_parts(path_elems: Vec<H>, position: Position) -> Result<Self, MerkleError> {
        if path_elems.len() == usize::from(DEPTH) {
            Ok(MerklePath {
                path_elems,
                position,
            })
        } else {
            Err(MerkleError::LengthMismatch {
                expected: usize::from(DEPTH),
                found: path_elems.len(),
            })
        }
    }

    /// Sibling hashes from leaf level upward.
    pub fn path_elems(&self) -> &[H] {
        &self.path_elems
    }

    /// Witnessed leaf position.
    pub fn position(&self) -> Position {
        self.position
    }
}

impl<H: Hashable, const DEPTH: u8> MerklePath<H, DEPTH> {
    /// Root for `leaf` at [`MerklePath::position`].
    pub fn root(&self, leaf: H) -> H {
        self.path_elems
            .iter()
            .zip(0u8..)
            .fold(leaf, |root, (h, i)| {
                if (self.position.0 >> i) & 0x1 == 0 {
                    H::combine(i.into(), &root, h)
                } else {
                    H::combine(i.into(), h, &root)
                }
            })
    }
}

/// Operations making a type usable as a tree leaf/node value.
pub trait Hashable: fmt::Debug {
    /// Value of an empty leaf.
    fn empty_leaf() -> Self;

    /// Combine two level-`level` nodes into their level-`level+1` parent.
    fn combine(level: Level, a: &Self, b: &Self) -> Self;

    /// Empty-subtree root at `level` (iterated self-combine).
    fn empty_root(level: Level) -> Self
    where
        Self: Sized,
    {
        Level::from(0)
            .iter_to(level)
            .fold(Self::empty_leaf(), |v, lvl| Self::combine(lvl, &v, &v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;
    use alloc::vec::Vec;
    use core::ops::Range;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Cat(String);

    impl Hashable for Cat {
        fn empty_leaf() -> Self {
            Cat(String::new())
        }
        fn combine(_level: Level, a: &Self, b: &Self) -> Self {
            let mut s = a.0.clone();
            s.push_str(&b.0);
            Cat(s)
        }
    }

    fn s(v: &str) -> Cat {
        Cat(String::from(v))
    }

    #[test]
    fn position_is_complete_subtree() {
        assert!(Position(0).is_complete_subtree(Level(0)));
        assert!(Position(1).is_complete_subtree(Level(1)));
        assert!(!Position(2).is_complete_subtree(Level(1)));
        assert!(!Position(2).is_complete_subtree(Level(2)));
        assert!(Position(3).is_complete_subtree(Level(2)));
        assert!(!Position(4).is_complete_subtree(Level(2)));
        assert!(Position(7).is_complete_subtree(Level(3)));
        assert!(Position(u32::MAX as u64).is_complete_subtree(Level(32)));
    }

    #[test]
    fn position_past_ommer_count() {
        assert_eq!(0, Position(0).past_ommer_count());
        assert_eq!(1, Position(1).past_ommer_count());
        assert_eq!(1, Position(2).past_ommer_count());
        assert_eq!(2, Position(3).past_ommer_count());
        assert_eq!(1, Position(4).past_ommer_count());
        assert_eq!(3, Position(7).past_ommer_count());
        assert_eq!(1, Position(8).past_ommer_count());
    }

    #[test]
    fn position_root_level() {
        assert_eq!(Level(0), Position(0).root_level());
        assert_eq!(Level(1), Position(1).root_level());
        assert_eq!(Level(2), Position(2).root_level());
        assert_eq!(Level(2), Position(3).root_level());
        assert_eq!(Level(3), Position(4).root_level());
        assert_eq!(Level(3), Position(7).root_level());
        assert_eq!(Level(4), Position(8).root_level());
    }

    #[test]
    fn position_witness_addrs() {
        use Source::*;
        let path_elem = |l, i, s| (Address::from_parts(Level::from(l), i), s);
        assert_eq!(
            alloc::vec![path_elem(0, 1, Future), path_elem(1, 1, Future),],
            Position::from(0)
                .witness_addrs(Level::from(2))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            alloc::vec![path_elem(0, 3, Future), path_elem(1, 0, Past(0)),],
            Position::from(2)
                .witness_addrs(Level::from(2))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            alloc::vec![
                path_elem(0, 2, Past(0)),
                path_elem(1, 0, Past(1)),
                path_elem(2, 1, Future),
            ],
            Position::from(3)
                .witness_addrs(Level::from(3))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            alloc::vec![
                path_elem(0, 5, Future),
                path_elem(1, 3, Future),
                path_elem(2, 0, Past(0)),
                path_elem(3, 1, Future),
            ],
            Position::from(4)
                .witness_addrs(Level::from(4))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn address_current_incomplete() {
        let addr = |l, i| Address::from_parts(Level(l), i);
        assert_eq!(addr(0, 0), addr(0, 0).current_incomplete());
        assert_eq!(addr(1, 0), addr(0, 1).current_incomplete());
        assert_eq!(addr(0, 2), addr(0, 2).current_incomplete());
        assert_eq!(addr(2, 0), addr(0, 3).current_incomplete());
    }

    #[test]
    fn address_next_incomplete_parent() {
        let addr = |l, i| Address::from_parts(Level(l), i);
        assert_eq!(addr(1, 0), addr(0, 0).next_incomplete_parent());
        assert_eq!(addr(1, 0), addr(0, 1).next_incomplete_parent());
        assert_eq!(addr(2, 0), addr(0, 2).next_incomplete_parent());
        assert_eq!(addr(2, 0), addr(0, 3).next_incomplete_parent());
        assert_eq!(addr(3, 0), addr(2, 0).next_incomplete_parent());
        assert_eq!(addr(1, 2), addr(0, 4).next_incomplete_parent());
        assert_eq!(addr(3, 0), addr(1, 2).next_incomplete_parent());
    }

    #[test]
    fn addr_is_ancestor() {
        let l0 = Level(0);
        let l1 = Level(1);
        assert!(Address::from_parts(l1, 0).is_ancestor_of(&Address::from_parts(l0, 0)));
        assert!(Address::from_parts(l1, 0).is_ancestor_of(&Address::from_parts(l0, 1)));
        assert!(!Address::from_parts(l1, 0).is_ancestor_of(&Address::from_parts(l0, 2)));
    }

    #[test]
    fn addr_position_range() {
        assert_eq!(
            Address::from_parts(Level(0), 0).position_range(),
            Range {
                start: Position(0),
                end: Position(1)
            }
        );
        assert_eq!(
            Address::from_parts(Level(1), 0).position_range(),
            Range {
                start: Position(0),
                end: Position(2)
            }
        );
        assert_eq!(
            Address::from_parts(Level(2), 1).position_range(),
            Range {
                start: Position(4),
                end: Position(8)
            }
        );
    }

    #[test]
    fn addr_above_position() {
        assert_eq!(
            Address::above_position(Level(3), Position(9)),
            Address::from_parts(Level(3), 1)
        );
    }

    #[test]
    fn addr_children() {
        assert_eq!(Address::from_parts(Level(0), 1).children(), None);
        assert_eq!(
            Address::from_parts(Level(3), 1).children(),
            Some((
                Address::from_parts(Level(2), 2),
                Address::from_parts(Level(2), 3),
            ))
        );
    }

    #[test]
    fn addr_is_ancestor_of() {
        assert!(Address::from_parts(Level(3), 1).is_ancestor_of(&Address::from_parts(Level(2), 2)));
        assert!(Address::from_parts(Level(3), 1).is_ancestor_of(&Address::from_parts(Level(1), 7)));
        assert!(!Address::from_parts(Level(3), 1).is_ancestor_of(&Address::from_parts(Level(1), 8)));
    }

    #[test]
    fn addr_common_ancestor() {
        assert_eq!(
            Address::from_parts(Level(2), 1).common_ancestor(&Address::from_parts(Level(3), 2)),
            Address::from_parts(Level(5), 0)
        );
        assert_eq!(
            Address::from_parts(Level(2), 2).common_ancestor(&Address::from_parts(Level(1), 7)),
            Address::from_parts(Level(3), 1)
        );
        assert_eq!(
            Address::from_parts(Level(2), 2).common_ancestor(&Address::from_parts(Level(1), 6)),
            Address::from_parts(Level(3), 1)
        );
        assert_eq!(
            Address::from_parts(Level(2), 2).common_ancestor(&Address::from_parts(Level(2), 2)),
            Address::from_parts(Level(2), 2)
        );
        assert_eq!(
            Address::from_parts(Level(2), 2).common_ancestor(&Address::from_parts(Level(0), 9)),
            Address::from_parts(Level(2), 2)
        );
        assert_eq!(
            Address::from_parts(Level(0), 9).common_ancestor(&Address::from_parts(Level(2), 2)),
            Address::from_parts(Level(2), 2)
        );
        assert_eq!(
            Address::from_parts(Level(0), 12).common_ancestor(&Address::from_parts(Level(0), 15)),
            Address::from_parts(Level(2), 3)
        );
    }

    #[test]
    fn addr_context() {
        assert_eq!(
            Address::from_parts(Level(3), 1).context(Level(0)),
            Either::Right(Range { start: 8, end: 16 })
        );
        assert_eq!(
            Address::from_parts(Level(3), 4).context(Level(5)),
            Either::Left(Address::from_parts(Level(5), 1))
        );
    }

    #[test]
    fn merkle_path_root() {
        let path: MerklePath<Cat, 3> =
            MerklePath::from_parts(alloc::vec![s("a"), s("cd"), s("efgh")], Position(1)).unwrap();
        assert_eq!(path.root(s("b")), s("abcdefgh"));
        let path: MerklePath<Cat, 3> =
            MerklePath::from_parts(alloc::vec![s("d"), s("ab"), s("efgh")], Position(2)).unwrap();
        assert_eq!(path.root(s("c")), s("abcdefgh"));
    }

    #[test]
    fn from_parts_length_mismatch_errors() {
        assert!(MerklePath::<Cat, 3>::from_parts(alloc::vec![s("a")], Position(0)).is_err());
        assert!(MerklePath::<Cat, 0>::from_parts(alloc::vec![], Position(0)).is_ok());
    }

    #[test]
    fn no_panic_edges() {
        // Saturating / guarded arithmetic never panics, even absurd.
        let _ = Position(0) - 5;
        assert!(Position(3).checked_sub(4).is_err());
        assert_eq!(Position(u64::MAX) + 1, Position(u64::MAX));
        let _ = Level(255) + 1;
        let _ = Level(0) - 1;
        assert!(!Position(u64::MAX).is_complete_subtree(Level(200)));
        let a = Address::from_parts(Level(200), u64::MAX);
        let _ = a.position_range_start();
        let _ = a.position_range_end();
        let _ = a.max_position();
        let _ = a.context(Level(250));
        let _ = a.common_ancestor(&Address::from_parts(Level(200), 0));
        let _ = a.next_at_level();
        let _ = a.current_incomplete();
        let _ = a.next_incomplete_parent();
    }

    #[test]
    fn retention_helpers() {
        assert!(!Retention::<u8>::Ephemeral.is_checkpoint());
        assert!(Retention::Checkpoint {
            id: 1u8,
            marking: Marking::Marked
        }
        .is_marked());
        assert!(!Retention::Checkpoint {
            id: 1u8,
            marking: Marking::None
        }
        .is_marked());
        assert!(Retention::<u8>::Marked.is_marked());
        assert_eq!(
            Retention::Checkpoint {
                id: 2u8,
                marking: Marking::Reference
            }
            .map(|i| i + 1),
            Retention::Checkpoint {
                id: 3u8,
                marking: Marking::Reference
            }
        );
        assert!(Either::Left::<u8, u8>(1).is_left());
        assert!(Either::Right::<u8, u8>(1).right() == Some(1));
    }
}
