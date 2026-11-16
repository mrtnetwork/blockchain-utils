//! Incremental witnesses (mirrors Rust `witness.rs`).

use alloc::vec::Vec;
use core::iter::repeat;

use super::frontier::{CommitmentTree, PathFiller};
use super::{Hashable, Level, MerkleError, MerklePath, Position, Source};

/// Witness to a leaf path that tracks tree appends.
///
/// Appending the same leaves in the same order to both the original
/// [`CommitmentTree`] and this witness yields a witness to the path from the
/// target position to the updated root.
#[derive(Clone, Debug)]
pub struct IncrementalWitness<H, const DEPTH: u8> {
    tree: CommitmentTree<H, DEPTH>,
    filled: Vec<H>,
    cursor_depth: u8,
    cursor: Option<CommitmentTree<H, DEPTH>>,
}

impl<H, const DEPTH: u8> IncrementalWitness<H, DEPTH> {
    /// Witness the newest leaf of `tree`; `None` when `tree` is empty.
    pub fn from_tree(tree: CommitmentTree<H, DEPTH>) -> Option<Self> {
        (!tree.is_empty()).then(|| IncrementalWitness {
            tree,
            filled: Vec::new(),
            cursor_depth: 0,
            cursor: None,
        })
    }

    /// Build from parts; `None` when `tree` is empty.
    pub fn from_parts(
        tree: CommitmentTree<H, DEPTH>,
        filled: Vec<H>,
        cursor: Option<CommitmentTree<H, DEPTH>>,
    ) -> Option<Self> {
        (!tree.is_empty()).then(|| {
            let mut witness = IncrementalWitness {
                tree,
                filled,
                cursor_depth: 0,
                cursor,
            };

            witness.cursor_depth = witness.next_depth();

            witness
        })
    }

    /// Witnessed tree.
    pub fn tree(&self) -> &CommitmentTree<H, DEPTH> {
        &self.tree
    }

    /// Filled ommers.
    pub fn filled(&self) -> &Vec<H> {
        &self.filled
    }

    /// Cursor subtree, if any.
    pub fn cursor(&self) -> &Option<CommitmentTree<H, DEPTH>> {
        &self.cursor
    }

    /// Witnessed leaf position.
    pub fn witnessed_position(&self) -> Position {
        // Deviation: saturating instead of panicking; construction guarantees
        // a non-empty tree, so the size is at least 1 in practice.
        Position::try_from(self.tree.size().saturating_sub(1)).unwrap_or(Position::from(0))
    }

    /// Position of the last appended leaf.
    pub fn tip_position(&self) -> Position {
        let leaves_to_cursor_start = self
            .witnessed_position()
            .witness_addrs(Level::from(DEPTH))
            .filter_map(|(addr, source)| {
                if source == Source::Future {
                    Some(addr)
                } else {
                    None
                }
            })
            .take(self.filled.len())
            .fold(0u64, |acc, addr| {
                // Deviation: saturating instead of panicking on absurd levels.
                let bit = 1u64.checked_shl(u8::from(addr.level()).into()).unwrap_or(0);
                acc.saturating_add(bit)
            });

        let cursor_size = self.cursor.as_ref().map_or(0, |c| c.size() as u64);
        Position::from(
            u64::from(self.witnessed_position())
                .saturating_add(leaves_to_cursor_start)
                .saturating_add(cursor_size),
        )
    }

    /// Next unfilled-subtree depth.
    fn next_depth(&self) -> u8 {
        // Deviation: saturating instead of panicking; lengths involved are
        // bounded by real tree depths.
        let mut skip: u8 = self.filled.len().try_into().unwrap_or(u8::MAX);

        if self.tree.left.is_none() {
            if skip > 0 {
                skip -= 1;
            } else {
                return 0;
            }
        }

        if self.tree.right.is_none() {
            if skip > 0 {
                skip -= 1;
            } else {
                return 0;
            }
        }

        let mut d = 1;
        for p in &self.tree.parents {
            if p.is_none() {
                if skip > 0 {
                    skip -= 1;
                } else {
                    return d;
                }
            }
            d = d.saturating_add(1);
        }

        d.saturating_add(skip)
    }
}

impl<H: Hashable + Clone, const DEPTH: u8> IncrementalWitness<H, DEPTH> {
    fn filler(&self) -> PathFiller<H> {
        let cursor_root = self
            .cursor
            .as_ref()
            .map(|c| c.root_at_depth(self.cursor_depth, PathFiller::empty()));

        PathFiller::new(self.filled.iter().cloned().chain(cursor_root).collect())
    }

    /// Track an appended leaf; [`MerkleError::TreeFull`] when full.
    /// (Deviation: the original panics on an overfull cursor; here that
    /// surfaces as [`MerkleError::TreeFull`].)
    pub fn append(&mut self, node: H) -> Result<(), MerkleError> {
        if let Some(mut cursor) = self.cursor.take() {
            cursor.append(node)?;
            if cursor.is_complete(self.cursor_depth) {
                self.filled
                    .push(cursor.root_at_depth(self.cursor_depth, PathFiller::empty()));
            } else {
                self.cursor = Some(cursor);
            }
        } else {
            self.cursor_depth = self.next_depth();
            if self.cursor_depth >= DEPTH {
                return Err(MerkleError::TreeFull);
            }

            if self.cursor_depth == 0 {
                self.filled.push(node);
            } else {
                let mut cursor = CommitmentTree::empty();
                cursor.append(node)?;
                self.cursor = Some(cursor);
            }
        }

        Ok(())
    }

    /// Current root of the witnessed tree.
    pub fn root(&self) -> H {
        self.tree.root_at_depth(DEPTH, self.filler())
    }

    /// Current witness, or `None` when the tree is empty.
    pub fn path(&self) -> Option<MerklePath<H, DEPTH>> {
        self.path_inner(DEPTH)
    }

    fn path_inner(&self, depth: u8) -> Option<MerklePath<H, DEPTH>> {
        let mut filler = self.filler();
        let mut auth_path = Vec::new();

        if let Some(node) = &self.tree.left {
            if self.tree.right.is_some() {
                auth_path.push(node.clone());
            } else {
                auth_path.push(filler.next(0.into()));
            }
        } else {
            return None;
        }

        for (p, i) in self
            .tree
            .parents
            .iter()
            .chain(repeat(&None))
            .take(depth.saturating_sub(1).into())
            .zip(0u8..)
        {
            auth_path.push(match p {
                Some(node) => node.clone(),
                None => filler.next(Level::from(i + 1)),
            });
        }

        // Deviation: `None` instead of panicking on length mismatch;
        // unreachable because exactly `depth` elements are pushed.
        if auth_path.len() != usize::from(depth) {
            return None;
        }
        MerklePath::from_parts(auth_path, self.witnessed_position()).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zk::incrementalmerkletree::frontier::CommitmentTree;
    use crate::zk::incrementalmerkletree::{Hashable, Level, Position};
    use alloc::string::String;

    impl Hashable for String {
        fn empty_leaf() -> Self {
            String::new()
        }
        fn combine(_level: Level, a: &Self, b: &Self) -> Self {
            let mut s = a.clone();
            s.push_str(b);
            s
        }
    }

    #[test]
    fn witness_tip_position() {
        // Port of the Rust crate's witness test (String nodes stand in for hashes).
        let mut base_tree = CommitmentTree::<String, 6>::empty();
        for c in 'a'..'h' {
            base_tree.append(c.to_string()).unwrap();
        }
        let mut witness = IncrementalWitness::from_tree(base_tree).unwrap();
        for c in 'h'..'z' {
            witness.append(c.to_string()).unwrap();
        }

        assert_eq!(witness.tip_position(), Position::from(24));
    }

    #[test]
    fn from_tree_empty_is_none() {
        assert!(IncrementalWitness::<String, 4>::from_tree(CommitmentTree::empty()).is_none());
        assert!(IncrementalWitness::<String, 4>::from_parts(
            CommitmentTree::empty(),
            alloc::vec![],
            None
        )
        .is_none());
    }

    #[test]
    fn full_witness_rejects_append() {
        // Depth-1 tree holds 2 leaves; the witness fills after both.
        let mut tree = CommitmentTree::<String, 1>::empty();
        tree.append(String::from("a")).unwrap();
        let mut w = IncrementalWitness::from_tree(tree).unwrap();
        w.append(String::from("b")).unwrap();
        assert!(w.append(String::from("c")).is_err());
    }

    #[test]
    fn path_root_agrees_with_tree() {
        let mut tree = CommitmentTree::<String, 3>::empty();
        for ch in ['a', 'b', 'c'] {
            tree.append(ch.to_string()).unwrap();
        }
        let w = IncrementalWitness::from_tree(tree).unwrap();
        let path = w.path().expect("path");
        assert_eq!(path.position(), Position::from(2));
        assert_eq!(path.path_elems().len(), 3);
        assert_eq!(path.root(String::from("c")), w.root());
        assert_eq!(w.witnessed_position(), Position::from(2));
        assert_eq!(w.tip_position(), Position::from(2));
        assert_eq!(w.filled().len(), 0);
        assert!(w.cursor().is_none());
    }
}
