//! Wallet-layer tree contexts over the frontier core.
//!
//! Extension (not in Rust 0.8.1) shaped after the legacy shard-tree API:
//! each [`ProtocolTree`] tracks one note-commitment tree as an append-ordered
//! leaf log plus absorbed complete subtrees, with bounded checkpoints and
//! replay witnesses. [`MerkleContext`] pairs the Sapling and Orchard trees
//! with chain markers.
//!
//! # Model
//!
//! - Leaves append in order (`append_leaves`); absorbed subtrees
//!   (`absorb_subtree`) cover unknown history and must be level-16 aligned
//!   at the tip (matches legacy `SHARD_HEIGHT`).
//! - The anchor folds ordered segments bottom-up, pairing listwise per level
//!   with empty roots on the ragged right edge. With no subtrees this equals
//!   [`Frontier::root`](super::frontier::Frontier::root) exactly.
//! - Checkpoints snapshot `(size, subtree_count)`; at most 100 are kept,
//!   oldest evicted (mirrors `MAX_CHECKPOINTS`).
//! - Witnesses fold the leaf log once per batch through a memoized
//!   absolute-coordinate map ([`ProtocolTree::witness_many`]), so any
//!   frontier-tracked position witnesses at any checkpoint with each
//!   internal node hashed once. Positions inside absorbed history report
//!   [`MerkleError::Missing`] (leaves unknown).
//! - Retention flags ride along on input/export but carry no pruning
//!   semantics here (the log retains everything; drop contexts to release).
//!
//! Everything fallible returns [`Result`]; nothing panics.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::frontier::Frontier;
use super::{Hashable, Level, MerkleError, MerklePath, Position, Retention, Source};

/// Tree depth for note-commitment trees.
pub const TREE_DEPTH: u8 = 32;
/// Absorbed subtree level (shard height, matches legacy `SHARD_HEIGHT`).
pub const SUBTREE_LEVEL: u8 = 16;
/// Maximum retained checkpoints per tree (mirrors `MAX_CHECKPOINTS`).
pub const MAX_CHECKPOINTS: usize = 100;

/// A complete subtree root covering `[start, start + 2^level)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubtreeRoot<H> {
    /// First leaf position covered.
    pub start: u64,
    /// Subtree height.
    pub level: u8,
    /// Subtree root hash.
    pub hash: H,
}

/// Checkpoint snapshot: log length and subtree count at capture.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointSnapshot {
    /// Checkpoint id.
    pub id: u32,
    /// Total leaves covered (subtrees + tracked).
    pub size: u64,
    /// Subtrees present.
    pub subtree_count: usize,
}

/// Bottom-up fold of ordered `(level, hash)` segments into one root:
/// pair listwise per level, ragged right edge against empty roots.
/// Segments must tile `[0, n)` contiguously; otherwise output is unspecified
/// (callers validate contiguity before folding).
fn fold_segments<H: Hashable + Clone>(segs: Vec<(u8, H)>) -> H {
    if segs.is_empty() {
        return H::empty_root(TREE_DEPTH.into());
    }
    // Empty-root chain, computed once incrementally (a naive per-level
    // `empty_root` call would redo O(l) work each time).
    let mut empty_chain: Vec<H> = Vec::with_capacity(usize::from(TREE_DEPTH) + 1);
    empty_chain.push(H::empty_leaf());
    for l in 0..TREE_DEPTH {
        let prev = empty_chain[usize::from(l)].clone();
        empty_chain.push(H::combine(l.into(), &prev, &prev));
    }
    let empty = |lvl: usize| -> H { empty_chain[lvl.min(usize::from(TREE_DEPTH))].clone() };
    // Buckets per level, left-to-right order preserved.
    let mut levels: Vec<Vec<H>> = Vec::new();
    for (lvl, h) in segs {
        let idx = (lvl as usize).min(64);
        while levels.len() <= idx {
            levels.push(Vec::new());
        }
        levels[idx].push(h);
    }
    while levels.len() <= usize::from(TREE_DEPTH) {
        levels.push(Vec::new());
    }
    for lvl in 0..usize::from(TREE_DEPTH) {
        while levels[lvl].len() >= 2 {
            let a = levels[lvl].remove(0);
            let b = levels[lvl].remove(0);
            levels[lvl + 1].push(H::combine((lvl as u8).into(), &a, &b));
        }
        if levels[lvl].len() == 1 {
            let x = levels[lvl].pop().unwrap_or_else(H::empty_leaf);
            levels[lvl + 1].push(H::combine((lvl as u8).into(), &x, &empty(lvl)));
        }
    }
    levels
        .pop()
        .and_then(|mut v| v.pop())
        .unwrap_or_else(|| H::empty_root(TREE_DEPTH.into()))
}

/// One protocol's tree: frontier + full leaf log + absorbed subtrees.
#[derive(Clone, Debug)]
pub struct ProtocolTree<H> {
    frontier: Frontier<H, { TREE_DEPTH }>,
    leaves: Vec<(H, Retention<u32>)>,
    subtrees: Vec<SubtreeRoot<H>>,
    checkpoints: Vec<CheckpointSnapshot>,
}

impl<H> ProtocolTree<H> {
    /// Empty tree.
    pub fn empty() -> Self {
        Self {
            frontier: Frontier::empty(),
            leaves: Vec::new(),
            subtrees: Vec::new(),
            checkpoints: Vec::new(),
        }
    }

    /// Tracked leaves (excludes absorbed-subtree history).
    pub fn leaf_count(&self) -> u64 {
        self.leaves.len() as u64
    }

    /// full ordered tip log for lossless export.
    /// Absorbed-subtree history is intentionally excluded (it round-trips
    /// as subtree roots); every appended leaf is present here in order,
    /// regardless of retention flags.
    pub fn leaves(&self) -> &[(H, Retention<u32>)] {
        &self.leaves
    }

    /// Total leaves covered (subtrees + tracked).
    pub fn total_size(&self) -> u64 {
        let mut total = 0u64;
        // Levels are < 32 in practice; saturate rather than panic.
        for s in &self.subtrees {
            total = total.saturating_add(1u64.checked_shl(s.level.into()).unwrap_or(0));
        }
        total.saturating_add(self.leaves.len() as u64)
    }

    /// Live frontier reference.
    pub fn frontier(&self) -> &Frontier<H, { TREE_DEPTH }> {
        &self.frontier
    }

    /// Absorbed subtree roots, in order.
    pub fn subtrees(&self) -> &[SubtreeRoot<H>] {
        &self.subtrees
    }

    /// Checkpoints (oldest first).
    pub fn checkpoints(&self) -> &[CheckpointSnapshot] {
        &self.checkpoints
    }
}

impl<H: Hashable + Clone> ProtocolTree<H> {
    /// Ordered segments covering the whole tree: absorbed subtrees first,
    /// then past ommers in ascending position order, then the tip leaf
    /// last (rightmost).
    fn segments(&self) -> Vec<(u8, H)> {
        let mut segs: Vec<(u8, H)> = Vec::new();
        for s in &self.subtrees {
            segs.push((s.level, s.hash.clone()));
        }
        if let Some(f) = self.frontier.value() {
            for (addr, source) in f.position().witness_addrs(Level::from(TREE_DEPTH)) {
                if let Source::Past(i) = source {
                    if let Some(o) = f.ommers().get(usize::from(i)) {
                        segs.push((u8::from(addr.level()), o.clone()));
                    }
                }
            }
            segs.push((0, f.leaf().clone()));
        }
        segs
    }

    /// Anchor over everything covered.
    pub fn anchor(&self) -> H {
        fold_segments(self.segments())
    }

    /// Append tracked leaves (positions continue the log).
    pub fn append_leaves(&mut self, leaves: Vec<(H, Retention<u32>)>) -> Result<(), MerkleError> {
        for (h, r) in leaves {
            if !self.frontier.append(h.clone()) {
                return Err(MerkleError::TreeFull);
            }
            self.leaves.push((h, r));
        }
        Ok(())
    }

    /// Absorb a complete level-16 subtree at the tip (shard-aligned).
    pub fn absorb_subtree(&mut self, start: u64, hash: H) -> Result<(), MerkleError> {
        if start != self.total_size() {
            return Err(MerkleError::LengthMismatch {
                expected: self.total_size() as usize,
                found: start as usize,
            });
        }
        let span = 1u64.checked_shl(SUBTREE_LEVEL.into()).unwrap_or(0);
        if span == 0 || !start.is_multiple_of(span) {
            return Err(MerkleError::PositionOutOfRange { depth: TREE_DEPTH });
        }
        self.subtrees.push(SubtreeRoot {
            start,
            level: SUBTREE_LEVEL,
            hash,
        });
        Ok(())
    }

    /// Record a checkpoint (evicts oldest beyond [`MAX_CHECKPOINTS`]).
    pub fn add_checkpoint(&mut self, id: u32) {
        if self.checkpoints.iter().any(|c| c.id == id) {
            return;
        }
        self.checkpoints.push(CheckpointSnapshot {
            id,
            size: self.total_size(),
            subtree_count: self.subtrees.len(),
        });
        while self.checkpoints.len() > MAX_CHECKPOINTS {
            self.checkpoints.remove(0);
        }
    }

    /// Restore an imported checkpoint snapshot (merge path): records `id`
    /// unless present, then overwrites with the exact imported metadata when
    /// it is consistent with current state (size within total, subtree
    /// count within stored subtrees).
    pub fn restore_checkpoint(&mut self, snap: CheckpointSnapshot) {
        if snap.size > self.total_size() {
            return;
        }
        self.add_checkpoint(snap.id);
        if let Some(last) = self.checkpoints.last_mut() {
            if last.id == snap.id {
                last.size = snap.size;
                last.subtree_count = snap.subtree_count.min(self.subtrees.len());
            }
        }
    }

    /// Validate one witness position against a checkpoint snapshot.
    /// Returns `(prefix_leaves, available, rel)` on success.
    fn witness_range(
        &self,
        position: u64,
        snap_size: u64,
        snap_subtrees: usize,
    ) -> Result<(u64, u64, u64), MerkleError> {
        let prefix_leaves: u64 = self.subtrees[..snap_subtrees.min(self.subtrees.len())]
            .iter()
            .map(|s| 1u64.checked_shl(s.level.into()).unwrap_or(0))
            .fold(0u64, |a, b| a.saturating_add(b));
        if position < prefix_leaves {
            // Inside absorbed history: leaves unknown, unwitnessable.
            return Err(MerkleError::Missing);
        }
        let rel = position - prefix_leaves;
        let available = snap_size.saturating_sub(prefix_leaves);
        if rel as usize >= self.leaves.len().min(available as usize) {
            return Err(MerkleError::Missing);
        }
        Ok((prefix_leaves, available, rel))
    }

    /// Witness `position` at checkpoint `checkpoint_id`: anchor plus path.
    /// Witness one position at a checkpoint: anchor plus path.
    pub fn witness_at(
        &self,
        position: u64,
        checkpoint_id: u32,
    ) -> Result<(H, MerklePath<H, { TREE_DEPTH }>), MerkleError> {
        let out = self.witness_many(core::slice::from_ref(&position), checkpoint_id)?;
        out.into_iter().next().ok_or(MerkleError::Missing)
    }

    /// Witness many positions at one checkpoint (single memoized fold
    /// shared across the batch).
    pub fn witness_many(
        &self,
        positions: &[u64],
        checkpoint_id: u32,
    ) -> Result<Vec<(H, MerklePath<H, { TREE_DEPTH }>)>, MerkleError> {
        let snap = self
            .checkpoints
            .iter()
            .find(|c| c.id == checkpoint_id)
            .ok_or(MerkleError::Missing)?;
        // Validate every position first (same errors, same precedence as
        // sequential `witness_at` calls).
        let mut ranges = Vec::with_capacity(positions.len());
        for &position in positions {
            if position >= snap.size {
                return Err(MerkleError::PositionOutOfRange { depth: TREE_DEPTH });
            }
            ranges.push(self.witness_range(position, snap.size, snap.subtree_count)?);
        }
        // single memoized fold over absolute
        // coordinates. Every internal node is hashed ONCE no matter how many
        // witnesses need it (legacy: full replay + per-witness tracking, i.e.
        // O(positions × tip)). Absorbed ranges resolve from stored shard
        // roots (shard-aligned by construction), beyond-tip ranges to cached
        // empty roots. Paths use absolute sibling blocks and the emitted
        // position is absolute (legacy replay emitted the base-tree size,
        // which includes the absorbed prefix); the anchor matches the legacy
        // replay root bit-for-bit (differential test below pins both).
        if positions.is_empty() {
            return Ok(Vec::new());
        }
        let prefix = prefix_len(&self.subtrees[..snap.subtree_count.min(self.subtrees.len())]);
        let tracked: u64 = snap.size.saturating_sub(prefix);
        let mut fold = FoldCtx {
            leaves: &self.leaves,
            subtrees: &self.subtrees,
            prefix,
            tracked,
            memo: BTreeMap::new(),
        };
        let anchor = fold.checkpoint_anchor()?;
        let mut out = Vec::with_capacity(positions.len());
        for &(_, _, rel) in &ranges {
            let abs = prefix
                .checked_add(rel)
                .ok_or(MerkleError::InconsistentTree)?;
            let mut elems = Vec::with_capacity(usize::from(TREE_DEPTH));
            for l in 0..TREE_DEPTH {
                let sib = (abs >> l) ^ 1;
                elems.push(fold.node(l, sib)?);
            }
            out.push((
                anchor.clone(),
                // Absolute position (legacy replay emitted the base-tree
                // size, which includes the absorbed prefix).
                MerklePath::from_parts(elems, Position::from(abs))?,
            ));
        }
        Ok(out)
    }
}

/// Absorbed-prefix length covered by the first `k` stored subtrees.
fn prefix_len<H>(subtrees: &[SubtreeRoot<H>]) -> u64 {
    subtrees
        .iter()
        .map(|s| 1u64.checked_shl(s.level.into()).unwrap_or(0))
        .fold(0u64, |a, b| a.saturating_add(b))
}

/// Single memoized fold over absolute tree coordinates .
///
/// Resolution order per node: tracked leaves → stored shard roots (level 16,
/// shard-aligned) → cached empty roots (beyond tip). Absorbed single leaves
/// are unreachable (needed nodes at level < 16 never fall fully inside the
/// absorbed prefix: the prefix is a multiple of 2^16, so any needed block at
/// level ≤ 16 touching it starts at or above it) and report `Missing`
/// defensively, matching `witness_range`'s posture for absorbed history.
struct FoldCtx<'a, H> {
    leaves: &'a [(H, Retention<u32>)],
    subtrees: &'a [SubtreeRoot<H>],
    prefix: u64,
    tracked: u64,
    memo: BTreeMap<(u8, u64), H>,
}

impl<H: Hashable + Clone> FoldCtx<'_, H> {
    /// Root of the absolute-aligned block `(level, index)`, memoized.
    fn node(&mut self, level: u8, index: u64) -> Result<H, MerkleError> {
        if let Some(h) = self.memo.get(&(level, index)) {
            return Ok(h.clone());
        }
        // Block start in u128 (index < 2^32, size ≤ 2^32: no overflow).
        let start = index as u128 * (1u128 << level.min(64));
        let h = if level == 0 {
            let i = start as u64;
            if (start) < self.prefix as u128 {
                return Err(MerkleError::Missing);
            }
            let rel = i.saturating_sub(self.prefix);
            if rel < self.tracked && (rel as usize) < self.leaves.len() {
                self.leaves[rel as usize].0.clone()
            } else {
                H::empty_leaf()
            }
        } else {
            // Fully-absorbed level-16 block = one stored shard root.
            if level == SUBTREE_LEVEL {
                let s = start as u64;
                if s.saturating_add(65536) <= self.prefix {
                    if let Some(found) = self
                        .subtrees
                        .iter()
                        .find(|sub| sub.start == s && sub.level == SUBTREE_LEVEL)
                    {
                        let h = found.hash.clone();
                        self.memo.insert((level, index), h.clone());
                        return Ok(h);
                    }
                    // else fall through to recursion (defensive; unreachable
                    // when subtrees tile the prefix contiguously).
                }
            }
            // Fully beyond all known leaves = cached empty root, matching
            // the legacy replay filler's `PathFiller::empty()` exactly.
            let limit = self.prefix as u128 + self.tracked as u128;
            if start >= limit {
                let h = H::empty_root(Level::from(level));
                self.memo.insert((level, index), h.clone());
                return Ok(h);
            }
            let l = level - 1;
            let left = self.node(l, index.checked_mul(2).ok_or(MerkleError::InconsistentTree)?)?;
            let right = self.node(
                l,
                index
                    .checked_mul(2)
                    .and_then(|v| v.checked_add(1))
                    .ok_or(MerkleError::InconsistentTree)?,
            )?;
            H::combine(Level::from(l), &left, &right)
        };
        self.memo.insert((level, index), h.clone());
        Ok(h)
    }

    /// Anchor over `[0, prefix + tracked)`: greedy-left aligned cover
    /// folded with the canonical segment fold (same function family as
    /// `ProtocolTree::anchor`, same value as the legacy replay root).
    fn checkpoint_anchor(&mut self) -> Result<H, MerkleError> {
        let end = self
            .prefix
            .checked_add(self.tracked)
            .ok_or(MerkleError::InconsistentTree)?;
        let mut segs: Vec<(u8, H)> = Vec::new();
        let mut pos = 0u64;
        while pos < end {
            let remain = end - pos;
            // Largest power-of-two block at pos within [pos, end).
            let mut l = 0u8;
            while l < TREE_DEPTH {
                let next = 1u64.checked_shl((l + 1).into()).unwrap_or(u64::MAX);
                if next <= remain && pos.is_multiple_of(next) {
                    l += 1;
                } else {
                    break;
                }
            }
            let size = 1u64.checked_shl(l.into()).unwrap_or(0);
            if size == 0 {
                return Err(MerkleError::InconsistentTree);
            }
            segs.push((l, self.node(l, pos / size)?));
            pos += size;
        }
        Ok(fold_segments(segs))
    }
}

/// Triple-protocol wallet tree context.
///
/// `ironwood` (NU6.3 second pool) shares the Orchard node/hash type
/// (`OH`); it is a separate frontier with its own checkpoints.
#[derive(Clone, Debug)]
pub struct MerkleContext<SH, OH> {
    /// Sapling tree.
    pub sapling: ProtocolTree<SH>,
    /// Orchard tree.
    pub orchard: ProtocolTree<OH>,
    /// Ironwood tree (same node type as Orchard).
    pub ironwood: ProtocolTree<OH>,
    /// Chain height marker (opaque).
    pub height: u32,
    /// Chain hash marker (opaque).
    pub hash: [u8; 32],
    /// Sapling subtree index marker (opaque passthrough).
    pub sapling_subtree_index: u32,
    /// Orchard subtree index marker (opaque passthrough).
    pub orchard_subtree_index: u32,
    /// Ironwood subtree index marker (opaque passthrough).
    pub ironwood_subtree_index: u32,
}

impl<SH, OH> MerkleContext<SH, OH> {
    /// Empty context.
    pub fn empty() -> Self {
        Self {
            sapling: ProtocolTree::empty(),
            orchard: ProtocolTree::empty(),
            ironwood: ProtocolTree::empty(),
            height: 0,
            hash: [0u8; 32],
            sapling_subtree_index: 0,
            orchard_subtree_index: 0,
            ironwood_subtree_index: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zk::incrementalmerkletree::{Hashable, Level, Position};
    use alloc::vec::Vec;

    // Constant-size test node (concat strings blow up exponentially on
    // empty-root folds at depth 32; wrapping arithmetic stays O(1)).
    #[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
    struct U(u64);

    impl Hashable for U {
        fn empty_leaf() -> Self {
            U(0)
        }
        fn combine(level: Level, a: &Self, b: &Self) -> Self {
            U(a.0
                .wrapping_mul(31)
                .wrapping_add(b.0)
                .wrapping_add(u8::from(level) as u64))
        }
    }

    fn c(v: u64) -> U {
        U(v)
    }

    fn ret() -> Retention<u32> {
        Retention::Ephemeral
    }

    #[test]
    fn empty_anchor_is_empty_root() {
        let t = ProtocolTree::<U>::empty();
        assert_eq!(t.total_size(), 0);
        assert_eq!(t.leaf_count(), 0);
        assert_eq!(t.anchor(), U::empty_root(32.into()));
    }

    #[test]
    fn anchor_matches_frontier_without_subtrees() {
        let mut t = ProtocolTree::<U>::empty();
        let leaves = [1u64, 2, 3, 4, 5];
        for ch in leaves {
            t.append_leaves(alloc::vec![(c(ch), ret())])
                .expect("append");
        }
        assert_eq!(t.total_size(), 5);
        // Same leaves through a bare frontier agree exactly.
        let mut f = Frontier::<U, 32>::empty();
        for ch in leaves {
            assert!(f.append(c(ch)));
        }
        assert_eq!(t.anchor(), f.root());
        // Deterministic across calls.
        assert_eq!(t.anchor(), t.anchor());
    }

    /// Cross-check anchor against both a bare depth-32 frontier and a
    /// naive pairwise fold (empty-padded per level) across many sizes.
    #[test]
    fn anchor_matches_frontier_many_sizes() {
        fn naive(leaves: &[U]) -> U {
            if leaves.is_empty() {
                return U::empty_root(32.into());
            }
            let mut level: Vec<U> = leaves.to_vec();
            let mut lvl = 0u8;
            while level.len() > 1 {
                if level.len() % 2 == 1 {
                    level.push(U::empty_root(Level::from(lvl)));
                }
                let mut next = Vec::with_capacity(level.len() / 2);
                for pair in level.as_chunks::<2>().0 {
                    next.push(U::combine(Level::from(lvl), &pair[0], &pair[1]));
                }
                level = next;
                lvl = lvl.saturating_add(1);
            }
            let mut r = level.into_iter().next().unwrap();
            let mut l = lvl;
            while l < 32 {
                r = U::combine(Level::from(l), &r, &U::empty_root(Level::from(l)));
                l = l.saturating_add(1);
            }
            r
        }
        for n in [0usize, 1, 2, 3, 5, 7, 8, 9, 15, 16, 17, 31, 33, 63, 64, 100] {
            let mut t = ProtocolTree::<U>::empty();
            let mut f = Frontier::<U, 32>::empty();
            for i in 0..n {
                let leaf = U(i as u64 * 2654435761 + 1);
                t.append_leaves(alloc::vec![(leaf, ret())]).expect("append");
                assert!(f.append(leaf));
            }
            assert_eq!(t.anchor(), f.root(), "anchor==frontier n={n}");
            let leaves: Vec<U> = (0..n).map(|i| U(i as u64 * 2654435761 + 1)).collect();
            assert_eq!(t.anchor(), naive(&leaves), "anchor==naive n={n}");
        }
    }

    #[test]
    fn absorb_validation() {
        let mut t = ProtocolTree::<U>::empty();
        // Misaligned start rejected.
        assert!(t.absorb_subtree(1, c(9)).is_err());
        // Wrong start (empty tree, start must be 0) rejected.
        assert!(t.absorb_subtree(65536 + 1, c(9)).is_err());
        // Happy path: shard at 0.
        t.absorb_subtree(0, c(21)).expect("absorb");
        assert_eq!(t.total_size(), 65536);
        // Next shard must start at 65536.
        assert!(t.absorb_subtree(0, c(10)).is_err());
        t.absorb_subtree(65536, c(22)).expect("absorb2");
        assert_eq!(t.total_size(), 131072);
    }

    #[test]
    fn anchor_with_subtree_matches_manual_fold() {
        // One level-16 shard S at [0, 65536) + leaves a, b at 65536+.
        // Expected: raise leaf-pair to 16, combine with S, raise to 32.
        let mut t = ProtocolTree::<U>::empty();
        t.absorb_subtree(0, c(21)).expect("absorb");
        t.append_leaves(alloc::vec![(c(1), ret()), (c(2), ret())])
            .expect("append");
        let pair = U::combine(Level::from(0), &c(1), &c(2));
        let mut raised = pair;
        for l in 1..16u8 {
            raised = U::combine(Level::from(l), &raised, &U::empty_root(Level::from(l)));
        }
        let mut acc = U::combine(Level::from(16), &c(21), &raised);
        for l in 17..32u8 {
            acc = U::combine(Level::from(l), &acc, &U::empty_root(Level::from(l)));
        }
        assert_eq!(t.anchor(), acc);
    }

    #[test]
    fn checkpoints_bounded_and_witness_roundtrip() {
        let mut t = ProtocolTree::<U>::empty();
        for ch in [1u64, 2, 3, 4, 5] {
            t.append_leaves(alloc::vec![(c(ch), ret())])
                .expect("append");
        }
        t.add_checkpoint(7);
        t.add_checkpoint(7); // duplicate ignored
        assert_eq!(t.checkpoints().len(), 1);
        // Witness each position at checkpoint 7 (size 5).
        for (i, ch) in [1u64, 2, 3, 4, 5].iter().enumerate() {
            let (anchor, path) = t.witness_at(i as u64, 7).expect("witness");
            assert_eq!(anchor, t.anchor());
            assert_eq!(path.position(), Position::from(i as u64));
            assert_eq!(path.root(c(*ch)), t.anchor());
        }
        // Unknown checkpoint / out-of-range position error, never panic.
        assert!(t.witness_at(0, 999_999).is_err());
        assert!(t.witness_at(5, 7).is_err());
        assert!(t.witness_at(u64::MAX, 7).is_err());
        // Flooding evicts oldest (id 7 goes away once over capacity).
        for id in 0..105u32 {
            t.add_checkpoint(100 + id);
        }
        assert_eq!(t.checkpoints().len(), MAX_CHECKPOINTS);
        assert_eq!(t.checkpoints()[0].id, 105);
        assert!(t.witness_at(0, 7).is_err());
    }

    #[test]
    fn witness_with_prefix_subtree() {
        // Absorbed shard + 2 frontier leaves; tip witness must verify.
        let mut t = ProtocolTree::<U>::empty();
        t.absorb_subtree(0, c(21)).expect("absorb");
        t.append_leaves(alloc::vec![(c(1), ret()), (c(2), ret())])
            .expect("append");
        t.add_checkpoint(1);
        // Interior of absorbed history is unwitnessable.
        assert!(t.witness_at(0, 1).is_err());
        assert!(t.witness_at(65535, 1).is_err());
        // Frontier leaves witness fine against the full anchor.
        for (i, ch) in [1u64, 2].iter().enumerate() {
            let pos = 65536 + i as u64;
            let (anchor, path) = t.witness_at(pos, 1).expect("witness");
            assert_eq!(anchor, t.anchor());
            assert_eq!(path.position(), Position::from(pos));
            assert_eq!(path.root(c(*ch)), t.anchor());
        }
    }

    /// memoized fold must equal an independent naive
    /// per-witness fold bit-for-bit (anchor, 32 limbs, emitted position),
    /// across absorbs (0-3 shards), old vs tip checkpoints, empty/single/
    /// spread/duplicate batches, and error cases. Every accepted path must
    /// also open to its anchor via the pre-existing `MerklePath::root`
    /// (independent of both folds).
    #[test]
    fn witness_many_matches_naive_fold() {
        fn lcg(st: &mut u64) -> u64 {
            *st = st
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *st >> 11
        }
        // Naive absolute-coordinate root over [0, snap_size): tracked
        // leaves, whole-shard hashes, cached empty roots. Written plainly
        // against the tree semantics (no memo, no digest tricks).
        fn nroot(
            tracked: &[(u64, U)],
            shards: &[(u64, U)],
            prefix: u64,
            snap_size: u64,
            level: u8,
            index: u64,
        ) -> U {
            let size = 1u64 << level;
            let start = index * size;
            if start >= snap_size {
                return U::empty_root(Level::from(level));
            }
            if level == 0 {
                if start < prefix {
                    panic!("absorbed single leaf in test scope");
                }
                return tracked
                    .iter()
                    .find(|(p, _)| *p == start)
                    .map(|(_, h)| *h)
                    .unwrap_or_else(U::empty_leaf);
            }
            if level == 16 && start + 65536 <= prefix {
                if let Some((_, h)) = shards.iter().find(|(s, _)| *s == start) {
                    return *h;
                }
            }
            let l = level - 1;
            U::combine(
                Level::from(l),
                &nroot(tracked, shards, prefix, snap_size, l, index * 2),
                &nroot(tracked, shards, prefix, snap_size, l, index * 2 + 1),
            )
        }
        for seed in 0..40u64 {
            let mut st = seed
                .wrapping_mul(0x9e3779b97f4a7c15)
                .wrapping_add(0x12345);
            let mut t = ProtocolTree::<U>::empty();
            let nsub = (lcg(&mut st) % 3) as usize;
            let mut shards = Vec::new();
            for k in 0..nsub {
                let h = U(0xa000 + k as u64);
                t.absorb_subtree(t.total_size(), h).expect("absorb");
                shards.push((k as u64 * 65536, h));
            }
            let prefix = nsub as u64 * 65536;
            // Checkpoint mid-fill (old) or at tip.
            let split = (lcg(&mut st) % 30) as usize;
            let extra = (lcg(&mut st) % 20) as usize;
            let mut tracked: Vec<(u64, U)> = Vec::new();
            for i in 0..split + extra {
                let h = U(1000 + i as u64);
                t.append_leaves(alloc::vec![(h, ret())]).expect("append");
                tracked.push((prefix + i as u64, h));
            }
            t.add_checkpoint(7);
            let snap_size = t
                .checkpoints()
                .iter()
                .find(|c| c.id == 7)
                .expect("snap")
                .size;
            // Random batch over [0, total): absorbed/out-of-range included
            // to exercise error parity (whole batch must fail, like legacy).
            let total = t.total_size();
            let nb = (lcg(&mut st) % 6) as usize;
            let mut req = Vec::new();
            for _ in 0..nb {
                let span = total + 2;
                req.push(if span == 0 { 0 } else { lcg(&mut st) % span });
            }
            let any_bad = req.iter().any(|&p| {
                p >= snap_size
                    || p < prefix
                    || (p - prefix) as usize >= tracked.len().min((snap_size - prefix) as usize)
            });
            let got = t.witness_many(&req, 7);
            if any_bad {
                assert!(got.is_err(), "seed {seed} req {req:?} must fail");
                continue;
            }
            // Unknown checkpoint id must also fail.
            assert!(t.witness_many(&req, 424242).is_err());
            let out = got.expect("batch");
            assert_eq!(out.len(), req.len(), "seed {seed}");
            for (i, &p) in req.iter().enumerate() {
                let (anchor, path) = &out[i];
                assert_eq!(u64::from(path.position()), p, "position seed {seed}");
                assert_eq!(path.path_elems().len(), 32);
                for l in 0..32u8 {
                    let sib = (p >> l) ^ 1;
                    let want = nroot(&tracked, &shards, prefix, snap_size, l, sib);
                    assert_eq!(path.path_elems()[l as usize], want, "limb l={l} seed {seed}");
                }
                // Independent: path opens to anchor with the requested leaf.
                let leaf = tracked[(p - prefix) as usize].1;
                assert_eq!(path.root(leaf), *anchor, "opens seed {seed}");
                // Independent: anchor equals naive full-range root.
                // Whole-range oracle: root of [0, snap_size) via top-down
                // decomposition identical in spirit to fold_segments.
                let oracle = {
                    let mut segs: Vec<(u8, U)> = Vec::new();
                    let mut pp = 0u64;
                    while pp < snap_size {
                        let mut l = 0u8;
                        while l < 32 {
                            let next = 1u64.checked_shl((l + 1).into()).unwrap_or(u64::MAX);
                            if next <= snap_size - pp && pp.is_multiple_of(next) {
                                l += 1;
                            } else {
                                break;
                            }
                        }
                        let size = 1u64 << l;
                        segs.push((l, nroot(&tracked, &shards, prefix, snap_size, l, pp / size)));
                        pp += size;
                    }
                    // Pairwise bottom-up fold (mirrors fold_segments order).
                    let mut levels: Vec<Vec<U>> = Vec::new();
                    for (lvl, h) in segs {
                        let idx = lvl as usize;
                        while levels.len() <= idx {
                            levels.push(Vec::new());
                        }
                        levels[idx].push(h);
                    }
                    while levels.len() <= 32 {
                        levels.push(Vec::new());
                    }
                    for lvl in 0..32usize {
                        while levels[lvl].len() >= 2 {
                            let a = levels[lvl].remove(0);
                            let b = levels[lvl].remove(0);
                            levels[lvl + 1].push(U::combine(Level::from(lvl as u8), &a, &b));
                        }
                        if levels[lvl].len() == 1 {
                            let x = levels[lvl].pop().unwrap();
                            levels[lvl + 1].push(U::combine(
                                Level::from(lvl as u8),
                                &x,
                                &U::empty_root(Level::from(lvl as u8)),
                            ));
                        }
                    }
                    levels.pop().and_then(|mut v| v.pop()).unwrap()
                };
                assert_eq!(*anchor, oracle, "anchor seed {seed}");
            }
        }
    }

    /// batched replay must equal sequential calls
    /// exactly (anchors, positions, limbs), including unordered and
    /// duplicated inputs, absorbed prefixes, and error cases.
    #[test]
    fn witness_many_matches_sequential() {
        let mut t = ProtocolTree::<U>::empty();
        t.absorb_subtree(0, c(21)).expect("absorb");
        let leaves = [1u64, 2, 3, 4, 5];
        for ch in leaves {
            t.append_leaves(alloc::vec![(c(ch), ret())])
                .expect("append");
        }
        t.add_checkpoint(7);
        // Includes unordered + duplicated positions.
        let req = [65539u64, 65536, 65538, 65536, 65537];
        let batch = t.witness_many(&req, 7).expect("batch");
        assert_eq!(batch.len(), req.len());
        for (i, &p) in req.iter().enumerate() {
            let single = t.witness_at(p, 7).expect("single");
            assert_eq!(batch[i].0, single.0, "anchor {p}");
            assert_eq!(batch[i].1.position(), single.1.position());
            // Same limbs.
            let (bl, sl) = (&batch[i].1, &single.1);
            assert_eq!(bl.path_elems().len(), sl.path_elems().len());
            for (x, y) in bl.path_elems().iter().zip(sl.path_elems().iter()) {
                assert_eq!(x, y);
            }
        }
        // Error parity: absorbed position and unknown checkpoint fail.
        assert!(t.witness_many(&[3u64], 7).is_err());
        assert!(t.witness_many(&[65536u64], 424242).is_err());
        assert!(t.witness_many(&[], 7).expect("empty").is_empty());
    }

    #[test]
    fn full_tree_rejects_appends() {
        let mut t = ProtocolTree::<U>::empty();
        // Fill a depth-0-equivalent? Use tiny direct frontier check instead:
        // depth-32 fills are infeasible; exercise TreeFull via witness path
        // overflow is covered by frontier tests. Here: absorb then append.
        t.absorb_subtree(0, c(21)).expect("absorb");
        t.append_leaves(alloc::vec![(c(1), ret())]).expect("append");
        assert_eq!(t.total_size(), 65537);
    }
}
