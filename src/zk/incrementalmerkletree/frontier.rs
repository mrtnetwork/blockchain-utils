//! Frontier representation and legacy commitment tree
//! (mirrors Rust `frontier.rs`).

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::iter::repeat;

use super::{Address, Hashable, Level, MerkleError, MerklePath, Position, Source};

/// Frontier construction errors (mirrors Rust `FrontierError`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrontierError {
    /// Ommer count does not match the position.
    PositionMismatch {
        /// Required ommer count for the position.
        expected_ommers: u8,
    },
    /// The frontier would exceed the maximum statically allowed depth.
    MaxDepthExceeded {
        /// Minimum depth the tree would require.
        depth: u8,
    },
}

impl core::fmt::Display for FrontierError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FrontierError::PositionMismatch { expected_ommers } => write!(
                f,
                "frontier ommer count mismatch: expected {expected_ommers}"
            ),
            FrontierError::MaxDepthExceeded { depth } => {
                write!(f, "frontier exceeds maximum depth (needs {depth})")
            }
        }
    }
}

impl core::error::Error for FrontierError {}

impl From<FrontierError> for MerkleError {
    fn from(e: FrontierError) -> Self {
        match e {
            FrontierError::PositionMismatch { expected_ommers } => {
                MerkleError::PositionMismatch { expected_ommers }
            }
            FrontierError::MaxDepthExceeded { depth } => MerkleError::MaxDepthExceeded { depth },
        }
    }
}

/// Reduced Merkle tree: newest leaf plus ommers for its witness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NonEmptyFrontier<H> {
    position: Position,
    leaf: H,
    ommers: Vec<H>,
}

impl<H> NonEmptyFrontier<H> {
    /// Frontier with `leaf` at position 0.
    pub fn new(leaf: H) -> Self {
        Self {
            position: 0.into(),
            leaf,
            ommers: Vec::new(),
        }
    }

    /// Build from parts; [`FrontierError::PositionMismatch`] unless
    /// `ommers.len()` equals the position's ommer count.
    pub fn from_parts(position: Position, leaf: H, ommers: Vec<H>) -> Result<Self, FrontierError> {
        let expected_ommers = position.past_ommer_count();
        if ommers.len() == expected_ommers.into() {
            Ok(Self {
                position,
                leaf,
                ommers,
            })
        } else {
            Err(FrontierError::PositionMismatch { expected_ommers })
        }
    }

    /// Decompose into parts.
    pub fn into_parts(self) -> (Position, H, Vec<H>) {
        (self.position, self.leaf, self.ommers)
    }

    /// Position of the newest leaf.
    pub fn position(&self) -> Position {
        self.position
    }

    /// Newest leaf.
    pub fn leaf(&self) -> &H {
        &self.leaf
    }

    /// Past hashes for the newest leaf's witness.
    pub fn ommers(&self) -> &[H] {
        &self.ommers
    }
}

impl<H: Hashable + Clone> NonEmptyFrontier<H> {
    /// Append a leaf, recomputing ommers by hashing full subtrees.
    pub fn append(&mut self, leaf: H) {
        let prior_position = self.position;
        let prior_leaf = self.leaf.clone();
        self.position += 1;
        self.leaf = leaf;
        if self.position.is_right_child() {
            self.ommers.insert(0, prior_leaf);
        } else {
            let new_root_level = self.position.root_level();

            let mut carry = Some((prior_leaf, 0.into()));
            let mut new_ommers = Vec::with_capacity(self.position.past_ommer_count().into());
            for (addr, source) in prior_position.witness_addrs(new_root_level) {
                if let Source::Past(i) = source {
                    if let Some((carry_ommer, carry_lvl)) = carry.as_ref() {
                        if *carry_lvl == addr.level() {
                            carry = Some((
                                H::combine(addr.level(), &self.ommers[usize::from(i)], carry_ommer),
                                addr.level() + 1,
                            ))
                        } else {
                            new_ommers.push(carry_ommer.clone());
                            new_ommers.push(self.ommers[usize::from(i)].clone());
                            carry = None;
                        }
                    } else {
                        new_ommers.push(self.ommers[usize::from(i)].clone());
                    }
                }
            }

            if let Some((carry_ommer, _)) = carry {
                new_ommers.push(carry_ommer);
            }

            self.ommers = new_ommers;
        }
    }

    /// Tree root by hashing against empty subtree roots.
    pub fn root(&self, root_level: Option<Level>) -> H {
        let max_level = root_level.unwrap_or_else(|| self.position.root_level());
        self.position
            .witness_addrs(max_level)
            .fold(
                (self.leaf.clone(), Level::from(0)),
                |(digest, complete_lvl), (addr, source)| {
                    let digest = complete_lvl
                        .iter_to(addr.level())
                        .fold(digest, |d, l| H::combine(l, &d, &H::empty_root(l)));

                    let res_digest = match source {
                        Source::Past(i) => {
                            H::combine(addr.level(), &self.ommers[usize::from(i)], &digest)
                        }
                        Source::Future => {
                            H::combine(addr.level(), &digest, &H::empty_root(addr.level()))
                        }
                    };

                    (res_digest, addr.level() + 1)
                },
            )
            .0
    }

    /// Witness for the tip leaf; missing complements report their [`Address`].
    pub fn witness<F>(&self, depth: u8, complement_nodes: F) -> Result<Vec<H>, Address>
    where
        F: Fn(Address) -> Option<H>,
    {
        self.position()
            .witness_addrs(depth.into())
            .map(|(addr, source)| match source {
                Source::Past(i) => Ok(self.ommers[usize::from(i)].clone()),
                Source::Future => complement_nodes(addr).ok_or(addr),
            })
            .collect::<Result<Vec<_>, _>>()
    }
}

/// Fixed-depth frontier (empty or non-empty).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frontier<H, const DEPTH: u8> {
    frontier: Option<NonEmptyFrontier<H>>,
}

impl<H, const DEPTH: u8> TryFrom<NonEmptyFrontier<H>> for Frontier<H, DEPTH> {
    type Error = FrontierError;
    fn try_from(f: NonEmptyFrontier<H>) -> Result<Self, FrontierError> {
        if f.position.root_level() <= Level::from(DEPTH) {
            Ok(Frontier { frontier: Some(f) })
        } else {
            Err(FrontierError::MaxDepthExceeded {
                depth: f.position.root_level().into(),
            })
        }
    }
}

impl<H, const DEPTH: u8> Frontier<H, DEPTH> {
    /// Empty frontier.
    pub fn empty() -> Self {
        Self { frontier: None }
    }

    /// Build from parts; errors on depth overflow or ommer mismatch.
    pub fn from_parts(position: Position, leaf: H, ommers: Vec<H>) -> Result<Self, FrontierError> {
        NonEmptyFrontier::from_parts(position, leaf, ommers).and_then(Self::try_from)
    }

    /// Wrapped frontier, or `None` when empty.
    pub fn value(&self) -> Option<&NonEmptyFrontier<H>> {
        self.frontier.as_ref()
    }

    /// Consume into the wrapped frontier.
    pub fn take(self) -> Option<NonEmptyFrontier<H>> {
        self.frontier
    }

    /// Dynamically allocated bytes held by ommers.
    pub fn dynamic_memory_usage(&self) -> usize {
        self.frontier.as_ref().map_or(0, |f| {
            size_of::<usize>() + (f.ommers.capacity() + 1) * size_of::<H>()
        })
    }

    /// Number of leaves in the tree.
    pub fn tree_size(&self) -> u64 {
        self.frontier
            .as_ref()
            .map_or(0, |f| u64::from(f.position()) + 1)
    }
}

impl<H: Hashable + Clone, const DEPTH: u8> Frontier<H, DEPTH> {
    /// Append a value; `false` if the frontier would exceed maximum depth.
    pub fn append(&mut self, value: H) -> bool {
        if let Some(frontier) = self.frontier.as_mut() {
            if frontier.position().is_complete_subtree(DEPTH.into()) {
                false
            } else {
                frontier.append(value);
                true
            }
        } else {
            self.frontier = Some(NonEmptyFrontier::new(value));
            true
        }
    }

    /// Current root (empty-subtree root when empty).
    pub fn root(&self) -> H {
        self.frontier
            .as_ref()
            .map_or(H::empty_root(DEPTH.into()), |frontier| {
                frontier.root(Some(DEPTH.into()))
            })
    }

    /// [`MerklePath`] to the tip leaf; `Ok(None)` when empty, or the
    /// failing [`Address`] on missing complements.
    pub fn witness<F>(&self, complement_nodes: F) -> Result<Option<MerklePath<H, DEPTH>>, Address>
    where
        F: Fn(Address) -> Option<H>,
    {
        self.frontier
            .as_ref()
            .map(|f| {
                f.witness(DEPTH, complement_nodes).map(|path_elems| {
                    // Deviation: `Ok(None)` instead of panicking; unreachable
                    // because `witness_addrs` yields exactly DEPTH elements.
                    MerklePath::from_parts(path_elems, f.position()).ok()
                })
            })
            .transpose()
            .map(|opt| opt.flatten())
    }
}

/// Filler for [`CommitmentTree::root_at_depth`]: queued nodes, else empty roots.
pub struct PathFiller<H> {
    queue: VecDeque<H>,
}

impl<H: Hashable> PathFiller<H> {
    /// Filler yielding only empty roots.
    pub fn empty() -> Self {
        PathFiller {
            queue: VecDeque::new(),
        }
    }

    /// Filler yielding queued nodes first.
    pub fn new(queue: VecDeque<H>) -> Self {
        Self { queue }
    }

    /// Next node at `level`, or that level's empty root.
    pub fn next(&mut self, level: Level) -> H {
        self.queue
            .pop_front()
            .unwrap_or_else(|| H::empty_root(level))
    }
}

/// Legacy Merkle tree of note commitments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitmentTree<H, const DEPTH: u8> {
    pub(crate) left: Option<H>,
    pub(crate) right: Option<H>,
    pub(crate) parents: Vec<Option<H>>,
}

impl<H, const DEPTH: u8> CommitmentTree<H, DEPTH> {
    /// Empty tree.
    pub fn empty() -> Self {
        CommitmentTree {
            left: None,
            right: None,
            parents: Vec::new(),
        }
    }

    /// Build from parts; [`MerkleError::LengthMismatch`] when `parents`
    /// holds `DEPTH` or more entries.
    pub fn from_parts(
        left: Option<H>,
        right: Option<H>,
        parents: Vec<Option<H>>,
    ) -> Result<Self, MerkleError> {
        if parents.len() < usize::from(DEPTH) {
            Ok(CommitmentTree {
                left,
                right,
                parents,
            })
        } else {
            Err(MerkleError::LengthMismatch {
                expected: usize::from(DEPTH).saturating_sub(1),
                found: parents.len(),
            })
        }
    }

    /// Whether no leaves are present.
    pub fn is_empty(&self) -> bool {
        self.left.is_none() && self.right.is_none()
    }

    /// Leftmost leaf slot.
    pub fn left(&self) -> &Option<H> {
        &self.left
    }

    /// Second leaf slot.
    pub fn right(&self) -> &Option<H> {
        &self.right
    }

    /// Parent ommers by level.
    pub fn parents(&self) -> &Vec<Option<H>> {
        &self.parents
    }

    /// Newest leaf.
    pub fn leaf(&self) -> Option<&H> {
        self.right.as_ref().or(self.left.as_ref())
    }

    /// Ommers from leaf level upward.
    pub fn ommers_iter(&self) -> Box<dyn Iterator<Item = &'_ H> + '_> {
        if self.right.is_some() {
            Box::new(
                self.left
                    .iter()
                    .chain(self.parents.iter().filter_map(|v| v.as_ref())),
            )
        } else {
            Box::new(self.parents.iter().filter_map(|v| v.as_ref()))
        }
    }

    /// Leaf count. A right-without-left tree (inconsistent) counts as
    /// empty rather than panicking.
    pub fn size(&self) -> usize {
        self.parents.iter().enumerate().fold(
            match (self.left.as_ref(), self.right.as_ref()) {
                (None, None) => 0,
                (Some(_), None) => 1,
                (Some(_), Some(_)) => 2,
                (None, Some(_)) => 0,
            },
            |acc, (i, p)| {
                // Deviation: shifts beyond the platform width saturate the
                // count instead of panicking; unreachable for real depths.
                let bit = 1usize.checked_shl((i + 1) as u32).unwrap_or(0);
                acc + if p.is_some() { bit } else { 0 }
            },
        )
    }

    pub(crate) fn is_complete(&self, depth: u8) -> bool {
        if depth == 0 {
            self.left.is_some() && self.right.is_none() && self.parents.is_empty()
        } else {
            self.left.is_some()
                && self.right.is_some()
                && self
                    .parents
                    .iter()
                    .chain(repeat(&None))
                    .take(depth.saturating_sub(1).into())
                    .all(|p| p.is_some())
        }
    }
}

impl<H: Hashable + Clone, const DEPTH: u8> CommitmentTree<H, DEPTH> {
    /// Rebuild from a frontier (ommer order preserved).
    pub fn from_frontier(frontier: &Frontier<H, DEPTH>) -> Self {
        frontier.value().map_or_else(Self::empty, |f| {
            let mut ommers_iter = f.ommers().iter().cloned();
            let (left, right) = if f.position().is_right_child() {
                // Deviation: graceful empty-tree fallback instead of
                // panicking; unreachable because validated frontiers hold
                // exactly `past_ommer_count` ommers (>= 1 here).
                let first = match ommers_iter.next() {
                    Some(o) => o,
                    None => return Self::empty(),
                };
                (first, Some(f.leaf().clone()))
            } else {
                (f.leaf().clone(), None)
            };

            Self {
                left: Some(left),
                right,
                parents: (1u8..DEPTH)
                    .map(|i| {
                        // Shifts beyond the platform width read as unset;
                        // unreachable for real depths.
                        let bit = 1u64.checked_shl(i.into()).unwrap_or(0);
                        if u64::from(f.position()) & bit == 0 {
                            None
                        } else {
                            ommers_iter.next()
                        }
                    })
                    .collect(),
            }
        })
    }

    /// Convert to a frontier; [`MerkleError::InconsistentTree`] instead of
    /// panicking when parts cannot form a valid frontier.
    pub fn to_frontier(&self) -> Result<Frontier<H, DEPTH>, MerkleError> {
        if self.size() == 0 {
            return Ok(Frontier::empty());
        }
        let ommers_iter = self.parents.iter().filter_map(|v| v.as_ref()).cloned();
        let (leaf, ommers) = match (self.left.as_ref(), self.right.as_ref()) {
            (Some(a), None) => (a.clone(), ommers_iter.collect()),
            (Some(a), Some(b)) => (
                b.clone(),
                Some(a.clone()).into_iter().chain(ommers_iter).collect(),
            ),
            _ => return Err(MerkleError::InconsistentTree),
        };

        let position = Position::try_from(self.size().saturating_sub(1))
            .map_err(|_| MerkleError::InconsistentTree)?;
        Frontier::from_parts(position, leaf, ommers).map_err(MerkleError::from)
    }

    /// Append a leaf; [`MerkleError::TreeFull`] when complete.
    pub fn append(&mut self, node: H) -> Result<(), MerkleError> {
        if self.is_complete(DEPTH) {
            return Err(MerkleError::TreeFull);
        }

        match (&self.left, &self.right) {
            (None, _) => self.left = Some(node),
            (_, None) => self.right = Some(node),
            (Some(l), Some(r)) => {
                let mut combined = H::combine(0.into(), l, r);
                self.left = Some(node);
                self.right = None;

                for i in 0..DEPTH {
                    let i_usize = usize::from(i);
                    if i_usize < self.parents.len() {
                        if let Some(p) = &self.parents[i_usize] {
                            combined = H::combine((i + 1).into(), p, &combined);
                            self.parents[i_usize] = None;
                        } else {
                            self.parents[i_usize] = Some(combined);
                            break;
                        }
                    } else {
                        self.parents.push(Some(combined));
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    /// Current root.
    pub fn root(&self) -> H {
        self.root_at_depth(DEPTH, PathFiller::empty())
    }

    /// Root at `depth`, filling gaps from `filler` (depth 0 yields the
    /// empty leaf; real depths are always positive).
    pub fn root_at_depth(&self, depth: u8, mut filler: PathFiller<H>) -> H {
        if depth == 0 {
            return H::empty_leaf();
        }
        let leaf_root = H::combine(
            0.into(),
            &self
                .left
                .as_ref()
                .map_or_else(|| filler.next(0.into()), |n| n.clone()),
            &self
                .right
                .as_ref()
                .map_or_else(|| filler.next(0.into()), |n| n.clone()),
        );

        self.parents
            .iter()
            .chain(repeat(&None))
            .take(depth.saturating_sub(1).into())
            .zip(0u8..)
            .fold(leaf_root, |root, (p, i)| {
                let level = Level::from(i + 1);
                match p {
                    Some(node) => H::combine(level, node, &root),
                    None => H::combine(level, &root, &filler.next(level)),
                }
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zk::incrementalmerkletree::{Address, Hashable, Level, MerkleError, Position};
    use alloc::string::String;
    use alloc::vec::Vec;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Cat(String);

    impl Hashable for Cat {
        fn empty_leaf() -> Self {
            Cat(String::new())
        }
        fn combine(_level: Level, a: &Self, b: &Self) -> Self {
            let mut s = String::from("(");
            s.push_str(&a.0);
            s.push_str(&b.0);
            s.push(')');
            Cat(s)
        }
    }

    fn c(v: &str) -> Cat {
        Cat(String::from(v))
    }

    #[test]
    fn empty_frontier_root_is_empty_root() {
        let f = Frontier::<Cat, 3>::empty();
        assert_eq!(f.tree_size(), 0);
        assert_eq!(f.root(), Cat::empty_root(3.into()));
        assert!(f.value().is_none());
        assert!(f.take().is_none());
    }

    #[test]
    fn append_root_sequence() {
        // Roots fold left siblings first, empty roots above.
        let mut f = Frontier::<Cat, 3>::empty();
        // Vectors from the real incrementalmerkletree 0.8.1 crate.
        assert!(f.append(c("a")));
        assert_eq!(f.tree_size(), 1);
        assert_eq!(f.root(), c("(((a)())(()()))"));
        assert!(f.append(c("b")));
        assert_eq!(f.tree_size(), 2);
        assert_eq!(f.root(), c("(((ab)())(()()))"));
        assert!(f.append(c("c")));
        assert_eq!(f.root(), c("(((ab)(c))(()()))"));
        assert!(f.append(c("d")));
        assert_eq!(f.root(), c("(((ab)(cd))(()()))"));
        assert!(f.append(c("e")));
        assert_eq!(f.root(), c("(((ab)(cd))((e)()))"));
    }

    #[test]
    fn full_frontier_rejects_append() {
        let mut f = Frontier::<Cat, 2>::empty();
        for ch in ["a", "b", "c", "d"] {
            assert!(f.append(c(ch)));
        }
        assert_eq!(f.tree_size(), 4);
        assert!(!f.append(c("e")));
        assert_eq!(f.tree_size(), 4);
    }

    #[test]
    fn from_parts_validation() {
        assert!(Frontier::<Cat, 3>::from_parts(Position::from(0), c("a"), Vec::new()).is_ok());
        assert!(
            Frontier::<Cat, 3>::from_parts(Position::from(1), c("b"), alloc::vec![c("a")]).is_ok()
        );
        // Wrong ommer count.
        assert_eq!(
            Frontier::<Cat, 3>::from_parts(Position::from(1), c("b"), Vec::new()),
            Err(FrontierError::PositionMismatch { expected_ommers: 1 })
        );
        // Depth overflow: position 8 needs root level 4 > DEPTH 3
        // (ommer count 1 is correct, so the depth gate fires).
        assert_eq!(
            Frontier::<Cat, 3>::from_parts(Position::from(8), c("x"), alloc::vec![c("o")]),
            Err(FrontierError::MaxDepthExceeded { depth: 4 })
        );
    }

    #[test]
    fn empty_roots_match_oracle() {
        assert_eq!(Cat::empty_root(Level::from(0)), c(""));
        assert_eq!(Cat::empty_root(Level::from(1)), c("()"));
        assert_eq!(Cat::empty_root(Level::from(2)), c("(()())"));
        assert_eq!(Cat::empty_root(Level::from(3)), c("((()())(()()))"));
    }

    /// Cross-check: frontier root equals a naive full-tree fold for 0..9 leaves.
    #[test]
    fn root_matches_naive_fold() {
        fn naive(leaves: &[Cat], depth: u8) -> Cat {
            let n = 1usize << depth;
            let mut level: Vec<Cat> = leaves.to_vec();
            level.resize_with(n, Cat::empty_leaf);
            let mut lvl = 0u8;
            while level.len() > 1 {
                let mut next = Vec::with_capacity(level.len() / 2);
                for pair in level.chunks(2) {
                    next.push(Cat::combine(Level::from(lvl), &pair[0], &pair[1]));
                }
                level = next;
                lvl += 1;
            }
            level.into_iter().next().unwrap()
        }
        for n in 0..9usize {
            let mut f = Frontier::<Cat, 3>::empty();
            let mut leaves = Vec::new();
            for ch in "abcdefghi".chars().take(n) {
                let leaf = c(&ch.to_string());
                leaves.push(leaf.clone());
                assert!(f.append(leaf));
            }
            assert_eq!(f.root(), naive(&leaves, 3), "n={n}");
        }
    }

    #[test]
    fn nonempty_witness_needs_complements() {
        let mut f = Frontier::<Cat, 2>::empty();
        f.append(c("a"));
        f.append(c("b"));
        // Tip is position 1: needs sibling at level 0 (past) — none stored
        // for position 1? position 1 is right child: ommer[0] = "a".
        // Level-1 sibling is future: complement required.
        // Tip position 1 in a depth-2 tree needs past "a" plus the
        // level-1 empty complement.
        let w = f
            .witness(|addr| Some(Cat::empty_root(addr.level())))
            .expect("ok");
        let path = w.expect("nonempty");
        assert_eq!(path.position(), Position::from(1));
        assert_eq!(path.path_elems(), &[c("a"), c("()")]);
        assert_eq!(path.root(c("b")), f.root());
        // Missing complement reports the address.
        let err = f.witness(|_| None).expect_err("missing complement");
        assert_eq!(err, Address::from_parts(Level::from(1), 1));
        // Empty frontier witnesses nothing.
        let e = Frontier::<Cat, 2>::empty();
        assert_eq!(e.witness(|_| None).expect("ok"), None);
    }

    #[test]
    fn commitment_tree_roundtrip() {
        let mut f = Frontier::<Cat, 4>::empty();
        for ch in ["a", "b", "c", "d", "e"] {
            assert!(f.append(c(ch)));
        }
        let t = CommitmentTree::from_frontier(&f);
        assert_eq!(t.size(), 5);
        assert!(!t.is_empty());
        let f2 = t.to_frontier().expect("roundtrip");
        assert_eq!(f2.tree_size(), 5);
        assert_eq!(f2.root(), f.root());
        // Witness through the converted tree matches direct fold.
        let w = f2
            .witness(|_addr| Some(c("F")))
            .expect("ok")
            .expect("nonempty");
        assert_eq!(w.path_elems().len(), 4);
    }

    #[test]
    fn commitment_tree_append_and_root_at_depth() {
        let mut t = CommitmentTree::<Cat, 4>::empty();
        assert!(t.is_empty());
        assert!(t.append(c("a")).is_ok());
        assert!(t.append(c("b")).is_ok());
        assert_eq!(t.size(), 2);
        assert_eq!(t.leaf(), Some(&c("b")));
        let filler = PathFiller::empty();
        let _ = t.root_at_depth(4, filler);
        // from_parts length guard.
        assert!(CommitmentTree::<Cat, 2>::from_parts(None, None, alloc::vec![None, None]).is_err());
        assert!(
            CommitmentTree::<Cat, 2>::from_parts(Some(c("a")), None, alloc::vec![None]).is_ok()
        );
    }

    #[test]
    fn error_mapping() {
        let e = FrontierError::PositionMismatch { expected_ommers: 2 };
        assert_eq!(
            MerkleError::from(e),
            MerkleError::PositionMismatch { expected_ommers: 2 }
        );
        let e = FrontierError::MaxDepthExceeded { depth: 9 };
        assert_eq!(
            MerkleError::from(e),
            MerkleError::MaxDepthExceeded { depth: 9 }
        );
    }
}
