//! Sapling / Orchard anchor-tree bridges.
//!
//! [`SaplingNode`] and [`OrchardNode`] implement [`Hashable`](super::Hashable)
//! over the trees' native 32-byte node encodings, so the generic
//! [`Frontier`](super::frontier::Frontier) / [`CommitmentTree`](super::frontier::CommitmentTree) /
//! [`IncrementalWitness`](super::witness::IncrementalWitness) machinery works
//! directly for anchor computation and witness export. Conversions to the
//! legacy circuit path shape (`siblings` + `position_bits`) are provided.
//!
//! # Error handling
//!
//! [`Hashable::combine`](super::Hashable::combine) is infallible by trait
//! shape. Both combines funnel into hash functions that cannot fail for the
//! fixed protocol domains; the only theoretical failure is an identity
//! intermediate point (probability ~2^-252 per hash). On that unreachable
//! path a zero node is produced. Code handling adversarial input must use
//! the fallible circuit APIs (`verify_merkle_path`, constraint checks),
//! not raw tree folds.
//!
//! Byte conversion ([`SaplingNode::from_bytes`], [`OrchardNode::from_bytes`])
//! validates canonical field encoding and reports
//! [`MerkleError::InvalidEncoding`](super::MerkleError::InvalidEncoding).
//!
//! Sapling items need `groth16-prover` (or `zcash-incrementalmerkle`);
//! Orchard items need `halo2` (or `zcash-incrementalmerkle`, via the
//! standalone MerkleCRH).

use alloc::vec::Vec;

use super::{Hashable, Level, MerkleError, MerklePath};

/// Sapling note-commitment tree depth (protocol MerkleCRH height).
pub const SAPLING_DEPTH: u8 = 32;
/// Orchard note-commitment tree depth (protocol constant 32).
#[cfg(any(feature = "orchard-halo2", feature = "zcash-incrementalmerkle"))]
pub const ORCHARD_DEPTH: u8 = 32;

/// Sapling tree node: jubjub base-field element, little-endian 32 bytes
/// (x-coordinate, same encoding as `sapling-crypto` tree `Node`).
#[cfg(any(feature = "groth16-prover", feature = "zcash-incrementalmerkle"))]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct SaplingNode(pub [u8; 32]);

#[cfg(any(feature = "groth16-prover", feature = "zcash-incrementalmerkle"))]
impl SaplingNode {
    /// Zero node (also the combine fallback; see module docs).
    pub const ZERO: Self = Self([0u8; 32]);

    /// Decode canonical field bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, MerkleError> {
        use crate::curve::jubjub::Fe;
        let mut be = [0u8; 32];
        for i in 0..32 {
            be[i] = bytes[31 - i];
        }
        Fe::from_bytes_be(&be)
            .map(|_| Self(*bytes))
            .map_err(|_| MerkleError::InvalidEncoding)
    }

    /// Raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Little-endian bits of the field value (low 255).
    fn bits_le(bytes: &[u8; 32]) -> [bool; 255] {
        let mut bits = [false; 255];
        for i in 0..255 {
            bits[i] = ((bytes[i / 8] >> (i % 8)) & 1) == 1;
        }
        bits
    }
}

#[cfg(any(feature = "groth16-prover", feature = "zcash-incrementalmerkle"))]
impl Hashable for SaplingNode {
    fn empty_leaf() -> Self {
        let mut b = [0u8; 32];
        b[0] = 1;
        Self(b)
    }

    /// Cached empty-subtree roots (single shared chain; bit-identical to
    /// the default iterative fold — see differential test below).
    fn empty_root(level: Level) -> Self {
        #[cfg(feature = "std")]
        {
            let l = u8::from(level) as usize;
            if l <= 32 {
                return Self(SAPLING_EMPTY_CHAIN[l]);
            }
        }
        Level::from(0)
            .iter_to(level)
            .fold(Self::empty_leaf(), |v, lvl| Self::combine(lvl, &v, &v))
    }

    fn combine(level: Level, a: &Self, b: &Self) -> Self {
        use crate::hash::pedersen::{PedersenHash, Personalization};
        let mut preimage = Vec::with_capacity(510);
        preimage.extend_from_slice(&Self::bits_le(&a.0));
        preimage.extend_from_slice(&Self::bits_le(&b.0));
        let lvl: u8 = level.into();
        // std: vartime fast path over runtime-once points .
        // no_std/wasm: unchanged reference path (R1).
        #[cfg(feature = "std")]
        let hash = PedersenHash::hash_cached(
            Personalization::MerkleTree { layer: lvl },
            &preimage,
        );
        #[cfg(not(feature = "std"))]
        let hash = {
            match PedersenHash::new().ok() {
                Some(ph) => ph.hash(Personalization::MerkleTree { layer: lvl }, &preimage),
                None => return Self([0u8; 32]),
            }
        };
        let node = hash
            .affine_uv()
            .ok()
            .map(|(u, _)| {
                let mut be = [0u8; 32];
                u.to_bytes_be(&mut be);
                let mut le = [0u8; 32];
                for i in 0..32 {
                    le[i] = be[31 - i];
                }
                le
            })
            .unwrap_or([0u8; 32]);
        Self(node)
    }
}

/// Orchard tree node: Pallas base-field element, little-endian 32 bytes
/// (x-coordinate, same encoding as the Orchard tree layer values).
#[cfg(any(feature = "orchard-halo2", feature = "zcash-incrementalmerkle"))]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct OrchardNode(pub [u8; 32]);

#[cfg(any(feature = "orchard-halo2", feature = "zcash-incrementalmerkle"))]
impl OrchardNode {
    /// Zero node (also the combine fallback; see module docs).
    pub const ZERO: Self = Self([0u8; 32]);

    /// Decode canonical field bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, MerkleError> {
        use crate::curve::pallas::Fe;
        let mut be = [0u8; 32];
        for i in 0..32 {
            be[i] = bytes[31 - i];
        }
        Fe::from_bytes_be(&be)
            .map(|_| Self(*bytes))
            .map_err(|_| MerkleError::InvalidEncoding)
    }

    /// Raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[cfg(any(feature = "orchard-halo2", feature = "zcash-incrementalmerkle"))]
impl Hashable for OrchardNode {
    fn empty_leaf() -> Self {
        // Uncommitted leaf `[2, 0, ..]` (protocol constant; matches the
        // Halo2 helper, see equivalence test).
        let mut le = [0u8; 32];
        le[0] = 2;
        Self(le)
    }

    /// Cached empty-subtree roots (see SaplingNode variant above).
    fn empty_root(level: Level) -> Self {
        #[cfg(feature = "std")]
        {
            let l = u8::from(level) as usize;
            if l <= 32 {
                return Self(ORCHARD_EMPTY_CHAIN[l]);
            }
        }
        Level::from(0)
            .iter_to(level)
            .fold(Self::empty_leaf(), |v, lvl| Self::combine(lvl, &v, &v))
    }

    fn combine(level: Level, a: &Self, b: &Self) -> Self {
        let lvl: u8 = level.into();
        Self(orchard_merkle_crh_standalone(lvl, &a.0, &b.0))
    }
}

#[cfg(any(feature = "orchard-halo2", feature = "zcash-incrementalmerkle"))]
pub(super) use crate::hash::pedersen_tables::ORCHARD_EMPTY_CHAIN;
/// Empty-subtree chains from the `@generated` constants
/// (`hash::pedersen_tables::{SAPLING,ORCHARD}_EMPTY_CHAIN`): zero runtime
/// cost on every target, no per-pool `OnceLock`s, no recomputation.
#[cfg(any(feature = "groth16-prover", feature = "zcash-incrementalmerkle"))]
pub(super) use crate::hash::pedersen_tables::SAPLING_EMPTY_CHAIN;

/// Node bytes accessor for path export.
pub trait NodeBytes {
    /// Raw 32-byte node encoding.
    fn node_bytes(&self) -> &[u8; 32];
}

#[cfg(any(feature = "groth16-prover", feature = "zcash-incrementalmerkle"))]
impl NodeBytes for SaplingNode {
    fn node_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[cfg(any(feature = "orchard-halo2", feature = "zcash-incrementalmerkle"))]
impl NodeBytes for OrchardNode {
    fn node_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Orchard MerkleCRH without Halo2, for standalone
/// (`zcash-incrementalmerkle`) builds: `SinsemillaHash(
/// "z.cash:Orchard-MerkleCRH", l/u(10) || left_255 || right_255)` x-coordinate
/// (top bits cleared), zeros on degenerate input. Bit layout mirrors
/// the Orchard MerkleCRH (Sinsemilla-based) bit-for-bit.
pub(crate) fn orchard_merkle_crh_standalone(
    level: u8,
    left: &[u8; 32],
    right: &[u8; 32],
) -> [u8; 32] {
    use crate::curve::pallas::to_bytes_pasta;
    use crate::hash::sinsemilla::K;
    // l/u layer prefix (10 bits) + low 255 bits of each hash (top bits
    // dropped, exactly like the Halo2 helper), padded to a K multiple.
    let mut bits = alloc::vec::Vec::with_capacity(10 + 255 + 255);
    for i in 0..10 {
        bits.push(((level as u16 >> i) & 1) == 1);
    }
    for h in [left, right] {
        for i in 0..255 {
            bits.push(((h[i / 8] >> (i % 8)) & 1) == 1);
        }
    }
    while bits.len() % K != 0 {
        bits.push(false);
    }
    // Single compile-time domain point (no per-call derivation, no cache).
    match crate::hash::sinsemilla::MERKLE_CRH.try_hash_bits(&bits) {
        Some(p) => {
            let mut x = to_bytes_pasta(&p);
            x[31] &= 0x7f;
            x
        }
        None => [0u8; 32],
    }
}

/// Split a generic witness path into legacy circuit inputs
/// (`siblings` leaf-to-root + `position_bits` LSB-first).
/// Returns [`MerkleError::LengthMismatch`] when the position does not fit
/// in `DEPTH` bits (unreachable for real trees).
pub fn split_path<N: NodeBytes, const DEPTH: u8>(
    path: &MerklePath<N, DEPTH>,
) -> Result<(Vec<[u8; 32]>, Vec<bool>), MerkleError> {
    let pos = u64::from(path.position());
    if DEPTH < 64 && pos >= (1u64.checked_shl(DEPTH.into()).unwrap_or(u64::MAX)) {
        return Err(MerkleError::PositionOutOfRange { depth: DEPTH });
    }
    let siblings = path.path_elems().iter().map(|n| *n.node_bytes()).collect();
    let bits: Vec<bool> = (0..DEPTH).map(|i| ((pos >> i) & 1) == 1).collect();
    Ok((siblings, bits))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zk::incrementalmerkletree::{Hashable, Level, Position};

    /// Standalone Orchard MerkleCRH must equal the Halo2 helper bit-for-bit
    /// (this is what lets `zcash-incrementalmerkle` builds skip Halo2).
    #[cfg(feature = "groth16-prover")]
    #[test]
    fn sapling_combine_matches_native_path() {
        use crate::zk::sapling::compute_merkle_root;
        use crate::zk::sapling::spending_key_generator;
        // Nodes are x-coordinate field bytes (like sapling-crypto tree Node).
        let gen = spending_key_generator();
        let (u, _) = gen.affine_uv().expect("affine");
        let mut ube = [0u8; 32];
        u.to_bytes_be(&mut ube);
        let mut cm_b = [0u8; 32];
        for i in 0..32 {
            cm_b[i] = ube[31 - i];
        }
        let mut sib = [0u8; 32];
        sib[0] = 7;
        let native = compute_merkle_root(&gen, &[(sib, false)]).expect("native root");
        let got = SaplingNode::combine(Level::from(0), &SaplingNode(cm_b), &SaplingNode(sib));
        // Native root is a jubjub Fe; bridge node is its LE bytes.
        let mut want_be = [0u8; 32];
        native.to_bytes_be(&mut want_be);
        let mut got_be = [0u8; 32];
        for (i, slot) in got_be.iter_mut().enumerate() {
            *slot = got.0[31 - i];
        }
        assert_eq!(got_be, want_be);
    }

    #[test]
    fn node_bytes_reject_noncanonical() {
        // Field moduli are < 2^255; all-ones limbs are non-canonical.
        #[cfg(feature = "groth16-prover")]
        assert!(SaplingNode::from_bytes(&[0xFFu8; 32]).is_err());
        #[cfg(feature = "orchard-halo2")]
        assert!(OrchardNode::from_bytes(&[0xFFu8; 32]).is_err());
        #[cfg(feature = "groth16-prover")]
        assert!(SaplingNode::from_bytes(&[0u8; 32]).is_ok());
        #[cfg(feature = "orchard-halo2")]
        assert!(OrchardNode::from_bytes(&[0u8; 32]).is_ok());
    }

    /// cached empty chains must equal an independent
    /// iterative fold at every level (both pools). The fold below never
    /// touches the cache or `empty_root`, so this guards chain indexing
    /// and layer personalization (combine itself is covered by KATs).
    #[test]
    fn empty_roots_match_iterative_fold() {
        #[cfg(any(feature = "groth16-prover", feature = "zcash-incrementalmerkle"))]
        {
            let mut e = SaplingNode::empty_leaf();
            for l in 0..33u8 {
                assert_eq!(
                    SaplingNode::empty_root(Level::from(l)),
                    e,
                    "sapling empty root mismatch at level {l}"
                );
                e = SaplingNode::combine(Level::from(l), &e, &e);
            }
        }
        #[cfg(any(feature = "orchard-halo2", feature = "zcash-incrementalmerkle"))]
        {
            let mut e = OrchardNode::empty_leaf();
            for l in 0..33u8 {
                assert_eq!(
                    OrchardNode::empty_root(Level::from(l)),
                    e,
                    "orchard empty root mismatch at level {l}"
                );
                e = OrchardNode::combine(Level::from(l), &e, &e);
            }
        }
    }

    #[test]
    fn split_path_rejects_out_of_range() {
        use crate::zk::incrementalmerkletree::MerklePath;
        #[cfg(feature = "orchard-halo2")]
        {
            let path = MerklePath::<OrchardNode, 4>::from_parts(
                alloc::vec![OrchardNode([0u8; 32]); 4],
                Position::from(u64::MAX),
            )
            .expect("parts");
            assert!(split_path(&path).is_err());
        }
    }
}
