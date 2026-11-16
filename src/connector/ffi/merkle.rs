//! Frontier-model Merkle contexts C ABI (features `ffi` + `groth16-prover` + `halo2`).
//!
//! Eight operations over a global id-keyed registry (global codes `ZK_*`):
//! create / close / get / insert-chain-state / update-state /
//! update-subtree / merge-state / create-witness.
//!
//! `kind`: 0 = Sapling, 1 = Orchard (else `ZK_ERR_INPUT`).
//!
//! Packed layouts (little-endian; all lengths validated, never panics):
//! ```text
//! FrontierState: has_u8 | [pos_u64 | leaf[32] | nommers_u32 | ommers[n][32]]
//! ProtocolState: frontier_state | nleaves_u32 | leaves[n][32]
//!   | nsub_u32 | subtrees[n][start_u64 | level_u8 | hash[32]]
//!   | nckpt_u32 | checkpoints[n][id_u32 | size_u64 | nsub_u32]
//! ContextState: sapling_state | orchard_state | height_u32 | hash[32]
//!   | sap_idx_u32 | orch_idx_u32
//! MergeState: nckpt_u32 | checkpoints[n][id_u32 | size_u64 | nsub_u32]
//!   | nsub_u32 | subtrees[n][start_u64 | level_u8 | hash[32]]
//! WitnessOut: anchor[32] | npaths_u32 | paths[n][pos_u64 | limbs[32][32]]
//! ```
//!
//! blobs carry FULL state — live frontier, full
//! ordered tip log, absorbed subtrees, checkpoints. Restore replays
//! subtrees + leaves (deterministically rebuilding the identical
//! frontier), verifies it against the imported frontier
//! (`InconsistentTree` on mismatch — storage corruption is never
//! silently accepted), then installs checkpoints. Legacy blobs (empty
//! frontier + zero leaves) import exactly as before.
//!
//! Model notes (mirror the core docs): leaves append in order; subtrees must
//! be level-16 aligned at the tip; checkpoints cap at 100 (oldest evicted);
//! witnesses replay the leaf log (`O(checkpoint size)`); positions inside
//! absorbed history are unwitnessable; retention flags are not carried
//! (import defaults to `Ephemeral`; witness correctness never depends on
//! retention).

#![cfg(all(
    feature = "ffi",
    any(
        feature = "zcash-incrementalmerkle",
        all(feature = "groth16-prover", feature = "orchard-halo2")
    )
))]

use super::zkcodes::{
    ZK_ERR_ENCODING, ZK_ERR_INPUT, ZK_ERR_INTERNAL, ZK_ERR_MERKLE, ZK_ERR_MISSING, ZK_OK,
};
use crate::zk::incrementalmerkletree::bridge::{OrchardNode, SaplingNode};
use crate::zk::incrementalmerkletree::contexts::{
    CheckpointSnapshot, MerkleContext, ProtocolTree, SubtreeRoot,
};
use crate::zk::incrementalmerkletree::frontier::Frontier;
use crate::zk::incrementalmerkletree::{Hashable, MerkleError, Position, Retention};
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ptr;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{OnceLock, RwLock};

type Context = MerkleContext<SaplingNode, OrchardNode>;

fn registry() -> &'static RwLock<HashMap<u32, Box<Context>>> {
    static REG: OnceLock<RwLock<HashMap<u32, Box<Context>>>> = OnceLock::new();
    REG.get_or_init(|| RwLock::new(HashMap::new()))
}

static NEXT_ID: AtomicU32 = AtomicU32::new(1);

fn alloc_ctx_id() -> u32 {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    if id == 0 {
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    } else {
        id
    }
}

fn map_err(e: MerkleError) -> i32 {
    match e {
        MerkleError::PositionMismatch { .. }
        | MerkleError::LengthMismatch { .. }
        | MerkleError::PositionOutOfRange { .. }
        | MerkleError::PositionUnderflow => ZK_ERR_INPUT,
        MerkleError::MaxDepthExceeded { .. }
        | MerkleError::TreeFull
        | MerkleError::InconsistentTree => ZK_ERR_MERKLE,
        MerkleError::Missing => ZK_ERR_MISSING,
        MerkleError::InvalidEncoding => ZK_ERR_ENCODING,
    }
}

// ---------------------------------------------------------------------------
// Packed codecs.
// ---------------------------------------------------------------------------

struct Reader<'a> {
    buf: &'a [u8],
    off: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, off: 0 }
    }

    fn rest(&self) -> usize {
        self.buf.len().saturating_sub(self.off)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], i32> {
        if self.rest() < n {
            return Err(ZK_ERR_INPUT);
        }
        let s = &self.buf[self.off..self.off + n];
        self.off += n;
        Ok(s)
    }

    fn u8v(&mut self) -> Result<u8, i32> {
        Ok(self.take(1)?[0])
    }

    fn u32v(&mut self) -> Result<u32, i32> {
        let mut a = [0u8; 4];
        a.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(a))
    }

    fn u64v(&mut self) -> Result<u64, i32> {
        let mut a = [0u8; 8];
        a.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(a))
    }

    fn bytes32(&mut self) -> Result<[u8; 32], i32> {
        let mut a = [0u8; 32];
        a.copy_from_slice(self.take(32)?);
        Ok(a)
    }
}

struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    fn new() -> Self {
        Self { buf: Vec::new() }
    }

    fn u8v(&mut self, v: u8) {
        self.buf.push(v);
    }

    fn u32v(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn u64v(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn bytes32(&mut self, b: &[u8; 32]) {
        self.buf.extend_from_slice(b);
    }

    fn finish(self) -> Vec<u8> {
        self.buf
    }
}

fn parse_frontier<H: Clone>(
    r: &mut Reader<'_>,
    decode: impl Fn([u8; 32]) -> Result<H, MerkleError>,
) -> Result<Frontier<H, 32>, MerkleError> {
    let has = r.u8v().map_err(|_| MerkleError::LengthMismatch {
        expected: 1,
        found: 0,
    })?;
    if has == 0 {
        return Ok(Frontier::empty());
    }
    if has != 1 {
        return Err(MerkleError::LengthMismatch {
            expected: 1,
            found: 1,
        });
    }
    let pos = r.u64v().map_err(|_| MerkleError::LengthMismatch {
        expected: 8,
        found: 0,
    })?;
    let leaf_b = r.bytes32().map_err(|_| MerkleError::LengthMismatch {
        expected: 32,
        found: 0,
    })?;
    let n = r.u32v().map_err(|_| MerkleError::LengthMismatch {
        expected: 4,
        found: 0,
    })?;
    if n > 64 {
        return Err(MerkleError::LengthMismatch {
            expected: 64,
            found: n as usize,
        });
    }
    let mut ommers = Vec::with_capacity(n as usize);
    for _ in 0..n {
        let b = r.bytes32().map_err(|_| MerkleError::LengthMismatch {
            expected: 32,
            found: 0,
        })?;
        ommers.push(decode(b)?);
    }
    Frontier::from_parts(Position::from(pos), decode(leaf_b)?, ommers).map_err(MerkleError::from)
}

fn decode_sapling(b: [u8; 32]) -> Result<SaplingNode, MerkleError> {
    SaplingNode::from_bytes(&b)
}

fn decode_orchard(b: [u8; 32]) -> Result<OrchardNode, MerkleError> {
    OrchardNode::from_bytes(&b)
}

fn write_tree<H: Clone>(
    w: &mut Writer,
    tree: &ProtocolTree<H>,
    bytes_of: impl Fn(&H) -> [u8; 32] + Copy,
) {
    // full state export. Frontier AND tip leaves are
    // written, so a blob round-trips losslessly: restore replays
    // subtrees + leaves and verifies the frontier (see `parse_tree`).
    // Retention flags are intentionally not serialized (import defaults to
    // `Ephemeral`; witness correctness never depends on retention).
    match tree.frontier().value() {
        Some(f) => {
            w.u8v(1);
            w.u64v(u64::from(f.position()));
            w.bytes32(&bytes_of(f.leaf()));
            let om = f.ommers();
            w.u32v(om.len() as u32);
            for o in om {
                w.bytes32(&bytes_of(o));
            }
        }
        None => {
            w.u8v(0);
        }
    }
    let leaves = tree.leaves();
    w.u32v(leaves.len() as u32);
    for (h, _) in leaves {
        w.bytes32(&bytes_of(h));
    }
    let subs = tree.subtrees();
    w.u32v(subs.len() as u32);
    for s in subs {
        w.u64v(s.start);
        w.u8v(s.level);
        w.bytes32(&bytes_of(&s.hash));
    }
    let ck = tree.checkpoints();
    w.u32v(ck.len() as u32);
    for c in ck {
        w.u32v(c.id);
        w.u64v(c.size);
        w.u32v(c.subtree_count as u32);
    }
}

fn parse_tree<H: Hashable + Clone>(
    r: &mut Reader<'_>,
    decode: impl Fn([u8; 32]) -> Result<H, MerkleError> + Copy,
    bytes_of: impl Fn(&H) -> [u8; 32] + Copy,
) -> Result<ProtocolTree<H>, MerkleError> {
    let frontier = parse_frontier(r, decode)?;
    let nleaves = r.u32v().map_err(|_| MerkleError::LengthMismatch {
        expected: 4,
        found: 0,
    })?;
    // Allocation safety: every leaf costs 32 blob bytes; refuse claims the
    // input cannot back (prevents huge Vec reservations on corrupt input).
    if nleaves as usize > r.rest() / 32 {
        return Err(MerkleError::LengthMismatch {
            expected: 32,
            found: r.rest(),
        });
    }
    let mut leaf_buf = Vec::with_capacity(nleaves as usize);
    for _ in 0..nleaves {
        let b = r.bytes32().map_err(|_| MerkleError::LengthMismatch {
            expected: 32,
            found: 0,
        })?;
        leaf_buf.push(decode(b)?);
    }
    let nsub = r.u32v().map_err(|_| MerkleError::LengthMismatch {
        expected: 4,
        found: 0,
    })?;
    if nsub > 4096 {
        return Err(MerkleError::LengthMismatch {
            expected: 4096,
            found: nsub as usize,
        });
    }
    let mut subtrees = Vec::with_capacity(nsub as usize);
    for _ in 0..nsub {
        let start = r.u64v().map_err(|_| MerkleError::LengthMismatch {
            expected: 8,
            found: 0,
        })?;
        let level = r.u8v().map_err(|_| MerkleError::LengthMismatch {
            expected: 1,
            found: 0,
        })?;
        let hash_b = r.bytes32().map_err(|_| MerkleError::LengthMismatch {
            expected: 32,
            found: 0,
        })?;
        subtrees.push(SubtreeRoot {
            start,
            level,
            hash: decode(hash_b)?,
        });
    }
    let nckpt = r.u32v().map_err(|_| MerkleError::LengthMismatch {
        expected: 4,
        found: 0,
    })?;
    if nckpt > 1024 {
        return Err(MerkleError::LengthMismatch {
            expected: 1024,
            found: nckpt as usize,
        });
    }
    let mut checkpoints = Vec::with_capacity(nckpt as usize);
    for _ in 0..nckpt {
        let id = r.u32v().map_err(|_| MerkleError::LengthMismatch {
            expected: 4,
            found: 0,
        })?;
        let size = r.u64v().map_err(|_| MerkleError::LengthMismatch {
            expected: 8,
            found: 0,
        })?;
        let nsub = r.u32v().map_err(|_| MerkleError::LengthMismatch {
            expected: 4,
            found: 0,
        })?;
        checkpoints.push(CheckpointSnapshot {
            id,
            size,
            subtree_count: nsub as usize,
        });
    }
    // rebuild replays subtrees in order, then tip
    // leaves in order (deterministically reconstructing the identical
    // frontier), verifies it against the imported frontier, then installs
    // checkpoints. Legacy blobs (empty frontier + zero leaves) restore
    // exactly as before.
    let mut tree = ProtocolTree::<H>::empty();
    for s in subtrees {
        if s.level != crate::zk::incrementalmerkletree::contexts::SUBTREE_LEVEL {
            return Err(MerkleError::LengthMismatch {
                expected: 16,
                found: s.level as usize,
            });
        }
        tree.absorb_subtree(s.start, s.hash)?;
    }
    if !leaf_buf.is_empty() {
        let replay: Vec<(H, Retention<u32>)> = leaf_buf
            .into_iter()
            .map(|h| (h, Retention::Ephemeral))
            .collect();
        tree.append_leaves(replay)?;
    }
    // Frontier verification: a non-empty imported frontier must match the
    // replayed one exactly (position, tip leaf, ommers); anything else is
    // storage corruption, never silently accepted.
    match (frontier.value(), tree.frontier().value()) {
        (None, None) => {}
        (Some(a), Some(b)) => {
            if u64::from(a.position()) != u64::from(b.position())
                || bytes_of(a.leaf()) != bytes_of(b.leaf())
            {
                return Err(MerkleError::InconsistentTree);
            }
            let (ao, bo) = (a.ommers(), b.ommers());
            if ao.len() != bo.len()
                || ao
                    .iter()
                    .zip(bo.iter())
                    .any(|(x, y)| bytes_of(x) != bytes_of(y))
            {
                return Err(MerkleError::InconsistentTree);
            }
        }
        _ => return Err(MerkleError::InconsistentTree),
    }
    for c in checkpoints {
        tree.restore_checkpoint(c);
    }
    Ok(tree)
}

fn write_context(w: &mut Writer, ctx: &Context) {
    write_tree(w, &ctx.sapling, |h| h.0);
    write_tree(w, &ctx.orchard, |h| h.0);
    w.u32v(ctx.height);
    w.bytes32(&ctx.hash);
    w.u32v(ctx.sapling_subtree_index);
    w.u32v(ctx.orchard_subtree_index);
    // Ironwood tail (absent in legacy blobs): tree + subtree index.
    write_tree(w, &ctx.ironwood, |h| h.0);
    w.u32v(ctx.ironwood_subtree_index);
}

fn parse_context(r: &mut Reader<'_>) -> Result<Context, MerkleError> {
    let sapling = parse_tree(r, decode_sapling, |h: &SaplingNode| h.0)?;
    let orchard = parse_tree(r, decode_orchard, |h: &OrchardNode| h.0)?;
    let height = r.u32v().map_err(|_| MerkleError::LengthMismatch {
        expected: 4,
        found: 0,
    })?;
    let hash = r.bytes32().map_err(|_| MerkleError::LengthMismatch {
        expected: 32,
        found: 0,
    })?;
    let sapling_subtree_index = r.u32v().map_err(|_| MerkleError::LengthMismatch {
        expected: 4,
        found: 0,
    })?;
    let orchard_subtree_index = r.u32v().map_err(|_| MerkleError::LengthMismatch {
        expected: 4,
        found: 0,
    })?;
    // Legacy blobs end here; new blobs append ironwood tree + index.
    let (ironwood, ironwood_subtree_index) = if r.rest() == 0 {
        (ProtocolTree::empty(), 0)
    } else {
        let t = parse_tree(r, decode_orchard, |h: &OrchardNode| h.0)?;
        let idx = r.u32v().map_err(|_| MerkleError::LengthMismatch {
            expected: 4,
            found: 0,
        })?;
        (t, idx)
    };
    if r.rest() != 0 {
        return Err(MerkleError::LengthMismatch {
            expected: 0,
            found: r.rest(),
        });
    }
    Ok(Context {
        sapling,
        orchard,
        ironwood,
        height,
        hash,
        sapling_subtree_index,
        orchard_subtree_index,
        ironwood_subtree_index,
    })
}

fn with_context<T>(id: u32, f: impl FnOnce(&mut Context) -> Result<T, i32>) -> Result<T, i32> {
    let mut guard = registry().write().map_err(|_| ZK_ERR_INTERNAL)?;
    match guard.get_mut(&id) {
        Some(ctx) => f(ctx),
        None => Err(ZK_ERR_MISSING),
    }
}

fn emit_bytes(out: *mut u8, out_len: *mut usize, data: &[u8]) -> i32 {
    if out_len.is_null() {
        return ZK_ERR_INPUT;
    }
    unsafe {
        if out.is_null() || *out_len < data.len() {
            *out_len = data.len();
            return ZK_ERR_INPUT;
        }
        ptr::copy_nonoverlapping(data.as_ptr(), out, data.len());
        *out_len = data.len();
    }
    ZK_OK
}

/// Create an empty wallet context; returns the id (0 on internal error).
#[no_mangle]
pub extern "C" fn bu_merkle_create_context() -> u32 {
    let id = alloc_ctx_id();
    if id == 0 {
        return 0;
    }
    match registry().write() {
        Ok(mut guard) => {
            guard.insert(id, Box::new(Context::empty()));
            id
        }
        Err(_) => 0,
    }
}

/// Drop a context.
#[no_mangle]
pub extern "C" fn bu_merkle_close_context(id: u32) -> i32 {
    match registry().write() {
        Ok(mut guard) => {
            if guard.remove(&id).is_some() {
                ZK_OK
            } else {
                ZK_ERR_MISSING
            }
        }
        Err(_) => ZK_ERR_INTERNAL,
    }
}

/// Export a context (length-query pattern on `out_len`).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_merkle_get_context(id: u32, out: *mut u8, out_len: *mut usize) -> i32 {
    if out_len.is_null() {
        return ZK_ERR_INPUT;
    }
    let bytes = match with_context(id, |ctx| {
        let mut w = Writer::new();
        write_context(&mut w, ctx);
        Ok::<Vec<u8>, i32>(w.finish())
    }) {
        Ok(b) => b,
        Err(e) => return e,
    };
    unsafe {
        if out.is_null() || *out_len < bytes.len() {
            *out_len = bytes.len();
            return ZK_ERR_INPUT;
        }
        ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len());
        *out_len = bytes.len();
    }
    ZK_OK
}

/// Restore a context from an exported blob (replaces state).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_merkle_insert_chain_state(
    id: u32,
    blob: *const u8,
    blob_len: usize,
) -> i32 {
    if blob.is_null() && blob_len > 0 {
        return ZK_ERR_INPUT;
    }
    let bytes = core::slice::from_raw_parts(blob, blob_len);
    let mut r = Reader::new(bytes);
    match parse_context(&mut r) {
        Ok(ctx) => match with_context(id, |slot| {
            *slot = ctx;
            Ok::<(), i32>(())
        }) {
            Ok(()) => ZK_OK,
            Err(e) => e,
        },
        Err(e) => map_err(e),
    }
}

/// Append `n = len/32` leaves to a protocol tree (`kind` 0 sapling,
/// 1 orchard, 2 ironwood — ironwood shares the Orchard node type).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_merkle_update_state(
    id: u32,
    kind: u32,
    leaves: *const u8,
    leaves_len: usize,
) -> i32 {
    if leaves.is_null() && leaves_len > 0 {
        return ZK_ERR_INPUT;
    }
    if !leaves_len.is_multiple_of(32) {
        return ZK_ERR_INPUT;
    }
    let bytes = core::slice::from_raw_parts(leaves, leaves_len);
    let mut items: Vec<([u8; 32], crate::zk::incrementalmerkletree::Retention<u32>)> =
        Vec::with_capacity(leaves_len / 32);
    for chunk in bytes.as_chunks::<32>().0 {
        let mut a = [0u8; 32];
        a.copy_from_slice(chunk);
        items.push((a, crate::zk::incrementalmerkletree::Retention::Ephemeral));
    }
    match with_context(id, |ctx| match kind {
        0 => {
            let nodes: Result<Vec<_>, _> = items
                .iter()
                .map(|(b, r)| SaplingNode::from_bytes(b).map(|h| (h, *r)).map_err(map_err))
                .collect();
            match nodes {
                Ok(v) => ctx.sapling.append_leaves(v).map_err(map_err),
                Err(e) => Err(e),
            }
        }
        1 => {
            let nodes: Result<Vec<_>, _> = items
                .iter()
                .map(|(b, r)| OrchardNode::from_bytes(b).map_err(map_err).map(|h| (h, *r)))
                .collect();
            match nodes {
                Ok(v) => ctx.orchard.append_leaves(v).map_err(map_err),
                Err(e) => Err(e),
            }
        }
        2 => {
            let nodes: Result<Vec<_>, _> = items
                .iter()
                .map(|(b, r)| OrchardNode::from_bytes(b).map_err(map_err).map(|h| (h, *r)))
                .collect();
            match nodes {
                Ok(v) => ctx.ironwood.append_leaves(v).map_err(map_err),
                Err(e) => Err(e),
            }
        }
        _ => Err(ZK_ERR_INPUT),
    }) {
        Ok(()) => ZK_OK,
        Err(e) => e,
    }
}

/// Absorb one level-16 subtree root at `start` (must equal current size).
/// `roots` holds a single 32-byte hash.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_merkle_update_subtree(
    id: u32,
    kind: u32,
    start: u64,
    roots: *const u8,
    roots_len: usize,
) -> i32 {
    if roots.is_null() && roots_len > 0 {
        return ZK_ERR_INPUT;
    }
    if roots_len != 32 {
        return ZK_ERR_INPUT;
    }
    let bytes = core::slice::from_raw_parts(roots, roots_len);
    let mut h = [0u8; 32];
    h.copy_from_slice(bytes);
    match with_context(id, |ctx| match kind {
        0 => match SaplingNode::from_bytes(&h) {
            Ok(n) => ctx.sapling.absorb_subtree(start, n).map_err(map_err),
            Err(e) => Err(map_err(e)),
        },
        1 => match OrchardNode::from_bytes(&h) {
            Ok(n) => ctx.orchard.absorb_subtree(start, n).map_err(map_err),
            Err(e) => Err(map_err(e)),
        },
        2 => match OrchardNode::from_bytes(&h) {
            Ok(n) => ctx.ironwood.absorb_subtree(start, n).map_err(map_err),
            Err(e) => Err(map_err(e)),
        },
        _ => Err(ZK_ERR_INPUT),
    }) {
        Ok(()) => ZK_OK,
        Err(e) => e,
    }
}

/// Merge checkpoints + contiguous subtrees from an exported merge blob:
/// `nckpt_u32 | checkpoints[n][id_u32 | size_u64 | nsub_u32]`
/// `| nsub_u32 | subtrees[n][start_u64 | level_u8 | hash[32]]`.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_merkle_merge_state(
    id: u32,
    kind: u32,
    blob: *const u8,
    blob_len: usize,
) -> i32 {
    if blob.is_null() && blob_len > 0 {
        return ZK_ERR_INPUT;
    }
    let bytes = core::slice::from_raw_parts(blob, blob_len);
    let mut r = Reader::new(bytes);
    let res: Result<(), i32> = (|| {
        let nckpt = r.u32v()?;
        if nckpt > 1024 {
            return Err(ZK_ERR_INPUT);
        }
        let mut ckpts = Vec::with_capacity(nckpt as usize);
        for _ in 0..nckpt {
            ckpts.push((r.u32v()?, r.u64v()?, r.u32v()?));
        }
        let nsub = r.u32v()?;
        if nsub > 4096 {
            return Err(ZK_ERR_INPUT);
        }
        let mut subs = Vec::with_capacity(nsub as usize);
        for _ in 0..nsub {
            let start = r.u64v()?;
            let level = r.u8v()?;
            let hash = r.bytes32()?;
            subs.push((start, level, hash));
        }
        if r.rest() != 0 {
            return Err(ZK_ERR_INPUT);
        }
        with_context(id, |ctx| {
            match kind {
                0 => {
                    for (cid, size, nsub) in &ckpts {
                        ctx.sapling.restore_checkpoint(CheckpointSnapshot {
                            id: *cid,
                            size: *size,
                            subtree_count: *nsub as usize,
                        });
                    }
                }
                1 => {
                    for (cid, size, nsub) in &ckpts {
                        ctx.orchard.restore_checkpoint(CheckpointSnapshot {
                            id: *cid,
                            size: *size,
                            subtree_count: *nsub as usize,
                        });
                    }
                }
                2 => {
                    for (cid, size, nsub) in &ckpts {
                        ctx.ironwood.restore_checkpoint(CheckpointSnapshot {
                            id: *cid,
                            size: *size,
                            subtree_count: *nsub as usize,
                        });
                    }
                }
                _ => return Err(ZK_ERR_INPUT),
            };
            for (start, level, hash) in &subs {
                if *level != crate::zk::incrementalmerkletree::contexts::SUBTREE_LEVEL {
                    return Err(ZK_ERR_INPUT);
                }
                let rc = match kind {
                    0 => SaplingNode::from_bytes(hash)
                        .map_err(map_err)
                        .and_then(|h| ctx.sapling.absorb_subtree(*start, h).map_err(map_err)),
                    1 => OrchardNode::from_bytes(hash)
                        .map_err(map_err)
                        .and_then(|h| ctx.orchard.absorb_subtree(*start, h).map_err(map_err)),
                    2 => OrchardNode::from_bytes(hash)
                        .map_err(map_err)
                        .and_then(|h| ctx.ironwood.absorb_subtree(*start, h).map_err(map_err)),
                    _ => Err(ZK_ERR_INPUT),
                };
                // Contiguity violations are skipped (partial merge), not fatal.
                let _ = rc;
            }
            Ok(())
        })
    })();
    match res {
        Ok(()) => ZK_OK,
        Err(e) => e,
    }
}

/// Snapshot all trees under `checkpoint` (evicts oldest beyond cap).
#[no_mangle]
pub extern "C" fn bu_merkle_checkpoint(id: u32, checkpoint: u32) -> i32 {
    match with_context(id, |ctx| {
        ctx.sapling.add_checkpoint(checkpoint);
        ctx.orchard.add_checkpoint(checkpoint);
        ctx.ironwood.add_checkpoint(checkpoint);
        Ok::<(), i32>(())
    }) {
        Ok(()) => ZK_OK,
        Err(e) => e,
    }
}

/// Witness `positions` (n×u64le) at `checkpoint`: anchor[32] +
/// `npaths_u32` + paths `[pos_u64 | limbs[32][32]]`.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_merkle_create_witness(
    id: u32,
    kind: u32,
    checkpoint: u32,
    positions: *const u8,
    positions_len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> i32 {
    if positions.is_null() && positions_len > 0 {
        return ZK_ERR_INPUT;
    }
    if !positions_len.is_multiple_of(8) {
        return ZK_ERR_INPUT;
    }
    let bytes = core::slice::from_raw_parts(positions, positions_len);
    let mut pos = Vec::with_capacity(positions_len / 8);
    for chunk in bytes.as_chunks::<8>().0 {
        let mut a = [0u8; 8];
        a.copy_from_slice(chunk);
        pos.push(u64::from_le_bytes(a));
    }
    // one replay per call no matter how many positions
    // are requested (was: one full replay per position). Anchors agree
    // across the batch by construction (same checkpoint); the first one
    // is emitted.
    fn emit_all<H: Clone>(
        items: &[(H, crate::zk::incrementalmerkletree::MerklePath<H, 32>)],
        bytes_of: impl Fn(&H) -> [u8; 32],
    ) -> Vec<u8> {
        let mut w = Writer::new();
        let mut first = true;
        for (anchor, path) in items {
            if first {
                w.bytes32(&bytes_of(anchor));
                // Count placeholder; patched below.
                w.u32v(0);
                first = false;
            }
            // Positions are absolute (witness_many preserves input order).
            w.u64v(u64::from(path.position()));
            for e in path.path_elems() {
                w.bytes32(&bytes_of(e));
            }
        }
        let mut out = w.finish();
        let n = items.len() as u32;
        // Empty batch: no anchor was written; keep the empty body (callers
        // treat short output as an error, exactly as before).
        if !items.is_empty() {
            out[32..36].copy_from_slice(&n.to_le_bytes());
        }
        out
    }
    let res: Result<Vec<u8>, i32> = with_context(id, |ctx| match kind {
        0 => {
            let items = ctx
                .sapling
                .witness_many(&pos, checkpoint)
                .map_err(map_err)?;
            Ok(emit_all(&items, |h: &SaplingNode| h.0))
        }
        1 => {
            let items = ctx
                .orchard
                .witness_many(&pos, checkpoint)
                .map_err(map_err)?;
            Ok(emit_all(&items, |h: &OrchardNode| h.0))
        }
        2 => {
            let items = ctx
                .ironwood
                .witness_many(&pos, checkpoint)
                .map_err(map_err)?;
            Ok(emit_all(&items, |h: &OrchardNode| h.0))
        }
        _ => Err(ZK_ERR_INPUT),
    });
    match res {
        Ok(bytes) => emit_bytes(out, out_len, &bytes),
        Err(e) => e,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> u32 {
        let id = bu_merkle_create_context();
        assert_ne!(id, 0);
        id
    }

    #[test]
    fn create_close_missing() {
        let id = ctx();
        assert_eq!(bu_merkle_close_context(id), ZK_OK);
        assert_eq!(bu_merkle_close_context(id), ZK_ERR_MISSING);
        assert_eq!(bu_merkle_close_context(u32::MAX), ZK_ERR_MISSING);
    }

    #[test]
    fn update_witness_roundtrip_sapling() {
        let id = ctx();
        // Two canonical leaves.
        let mut leaves = [1u8; 32];
        leaves[0] = 3;
        let mut leaves2 = [2u8; 32];
        leaves2[0] = 5;
        let mut blob = Vec::new();
        blob.extend_from_slice(&leaves);
        blob.extend_from_slice(&leaves2);
        unsafe {
            assert_eq!(
                bu_merkle_update_state(id, 0, blob.as_ptr(), blob.len()),
                ZK_OK
            );
            // Bad kind rejected.
            assert_eq!(
                bu_merkle_update_state(id, 7, blob.as_ptr(), blob.len()),
                ZK_ERR_INPUT
            );
            // Witness tip (no checkpoint yet → missing).
            let mut pos = 1u64.to_le_bytes();
            let mut out = alloc::vec![0u8; 4096];
            let mut out_len = out.len();
            // No checkpoint: witness errors (missing), never panics.
            assert_eq!(
                bu_merkle_create_witness(
                    id,
                    0,
                    99,
                    pos.as_mut_ptr(),
                    pos.len(),
                    out.as_mut_ptr(),
                    &mut out_len
                ),
                ZK_ERR_MISSING
            );
        }
        bu_merkle_close_context(id);
    }

    #[test]
    fn get_insert_roundtrip() {
        let id = ctx();
        let mut out = alloc::vec![0u8; 8192];
        let mut out_len = out.len();
        unsafe {
            assert_eq!(
                bu_merkle_get_context(id, out.as_mut_ptr(), &mut out_len),
                ZK_OK
            );
            assert!(out_len > 0);
            // Re-insert into a second context.
            let id2 = ctx();
            assert_eq!(
                bu_merkle_insert_chain_state(id2, out.as_ptr(), out_len),
                ZK_OK
            );
            let mut out2 = alloc::vec![0u8; 8192];
            let mut out2_len = out2.len();
            assert_eq!(
                bu_merkle_get_context(id2, out2.as_mut_ptr(), &mut out2_len),
                ZK_OK
            );
            assert_eq!(&out[..out_len], &out2[..out2_len]);
            bu_merkle_close_context(id);
            bu_merkle_close_context(id2);
        }
    }

    #[test]
    fn witness_end_to_end_sapling() {
        let id = ctx();
        // Three small canonical leaves.
        let mut blob = Vec::new();
        for v in [3u8, 5u8, 9u8] {
            let mut l = [0u8; 32];
            l[0] = v;
            blob.extend_from_slice(&l);
        }
        unsafe {
            assert_eq!(
                bu_merkle_update_state(id, 0, blob.as_ptr(), blob.len()),
                ZK_OK
            );
            assert_eq!(bu_merkle_checkpoint(id, 41), ZK_OK);
            // Witness all three positions.
            let mut pos = Vec::new();
            for p in [0u64, 1, 2] {
                pos.extend_from_slice(&p.to_le_bytes());
            }
            let mut out = alloc::vec![0u8; 4096];
            let mut out_len = out.len();
            assert_eq!(
                bu_merkle_create_witness(
                    id,
                    0,
                    41,
                    pos.as_ptr(),
                    pos.len(),
                    out.as_mut_ptr(),
                    &mut out_len
                ),
                ZK_OK
            );
            assert_eq!(out_len, 32 + 4 + 3 * (8 + 32 * 32));
            // Unknown checkpoint fails closed.
            let mut out_len2 = out.len();
            assert_eq!(
                bu_merkle_create_witness(
                    id,
                    0,
                    42,
                    pos.as_ptr(),
                    pos.len(),
                    out.as_mut_ptr(),
                    &mut out_len2
                ),
                ZK_ERR_MISSING
            );
            // Bad kind fails closed.
            assert_eq!(
                bu_merkle_create_witness(
                    id,
                    9,
                    41,
                    pos.as_ptr(),
                    pos.len(),
                    out.as_mut_ptr(),
                    &mut out_len2
                ),
                ZK_ERR_INPUT
            );
        }
        bu_merkle_close_context(id);
    }

    #[test]
    fn subtree_and_merge_validation() {
        let id = ctx();
        unsafe {
            // Wrong size rejected.
            assert_eq!(
                bu_merkle_update_subtree(id, 0, 0, [0u8; 16].as_ptr(), 16),
                ZK_ERR_INPUT
            );
            // Misaligned start rejected (empty tree, start must be 0).
            assert_eq!(
                bu_merkle_update_subtree(id, 0, 1, [0u8; 32].as_ptr(), 32),
                ZK_ERR_INPUT
            );
            // Merge garbage rejected.
            assert_eq!(
                bu_merkle_merge_state(id, 0, [0u8; 10].as_ptr(), 10),
                ZK_ERR_INPUT
            );
            // Merge empty blob ok (no-op).
            let mut empty = [0u8; 8];
            empty[0..4].copy_from_slice(&0u32.to_le_bytes());
            empty[4..8].copy_from_slice(&0u32.to_le_bytes());
            assert_eq!(
                bu_merkle_merge_state(id, 0, empty.as_ptr(), empty.len()),
                ZK_OK
            );
        }
        bu_merkle_close_context(id);
    }

    /// full-state blob round-trip. Subtree +
    /// tip leaves + checkpoint + frontier export, byte-identical
    /// re-export after restore, and identical witnesses pre/post.
    #[test]
    fn full_state_roundtrip_with_leaves() {
        let id = ctx();
        // Absorb one completed subtree, then 3 tip leaves.
        let mut root = [0u8; 32];
        root[0] = 0xAA;
        let mut blob = Vec::new();
        for v in [3u8, 5u8, 9u8] {
            let mut l = [0u8; 32];
            l[0] = v;
            blob.extend_from_slice(&l);
        }
        unsafe {
            assert_eq!(
                bu_merkle_update_subtree(id, 0, 0, root.as_ptr(), root.len()),
                ZK_OK
            );
            assert_eq!(
                bu_merkle_update_state(id, 0, blob.as_ptr(), blob.len()),
                ZK_OK
            );
            assert_eq!(bu_merkle_checkpoint(id, 41), ZK_OK);
            // Export full state.
            let mut out = alloc::vec![0u8; 1 << 20];
            let mut out_len = out.len();
            assert_eq!(
                bu_merkle_get_context(id, out.as_mut_ptr(), &mut out_len),
                ZK_OK
            );
            assert!(out_len > 0);
            // Witness tip positions pre-restore.
            let witness_before = {
                let mut pos = Vec::new();
                for p in [65536u64, 65537, 65538] {
                    pos.extend_from_slice(&p.to_le_bytes());
                }
                let mut w = alloc::vec![0u8; 8192];
                let mut wlen = w.len();
                assert_eq!(
                    bu_merkle_create_witness(
                        id,
                        0,
                        41,
                        pos.as_ptr(),
                        pos.len(),
                        w.as_mut_ptr(),
                        &mut wlen
                    ),
                    ZK_OK
                );
                w[..wlen].to_vec()
            };
            // Restore into a fresh context: byte-identical re-export.
            let id2 = ctx();
            assert_eq!(
                bu_merkle_insert_chain_state(id2, out.as_ptr(), out_len),
                ZK_OK
            );
            let mut out2 = alloc::vec![0u8; 1 << 20];
            let mut out2_len = out2.len();
            assert_eq!(
                bu_merkle_get_context(id2, out2.as_mut_ptr(), &mut out2_len),
                ZK_OK
            );
            assert_eq!(&out[..out_len], &out2[..out2_len]);
            // Identical witnesses post-restore.
            let mut pos = Vec::new();
            for p in [65536u64, 65537, 65538] {
                pos.extend_from_slice(&p.to_le_bytes());
            }
            let mut w = alloc::vec![0u8; 8192];
            let mut wlen = w.len();
            assert_eq!(
                bu_merkle_create_witness(
                    id2,
                    0,
                    41,
                    pos.as_ptr(),
                    pos.len(),
                    w.as_mut_ptr(),
                    &mut wlen
                ),
                ZK_OK
            );
            assert_eq!(&w[..wlen], &witness_before[..]);
            bu_merkle_close_context(id2);
        }
        bu_merkle_close_context(id);
    }

    /// Tampered tip bytes must fail restore (never silently accepted).
    #[test]
    fn tampered_state_rejected() {
        let id = ctx();
        let mut blob = Vec::new();
        for v in [3u8, 5u8] {
            let mut l = [0u8; 32];
            l[0] = v;
            blob.extend_from_slice(&l);
        }
        unsafe {
            assert_eq!(
                bu_merkle_update_state(id, 0, blob.as_ptr(), blob.len()),
                ZK_OK
            );
            let mut out = alloc::vec![0u8; 1 << 20];
            let mut out_len = out.len();
            assert_eq!(
                bu_merkle_get_context(id, out.as_mut_ptr(), &mut out_len),
                ZK_OK
            );
            // Flip a byte inside the exported tip-leaf log (offset 90:
            // has(1) + pos(8) + leaf(32) + nommers(4) + ommer(32) +
            // nleaves(4) + 9). The replayed frontier then mismatches the
            // imported one and restore must fail.
            let mut bad = out[..out_len].to_vec();
            bad[90] ^= 0x01;
            let id2 = ctx();
            let rc = bu_merkle_insert_chain_state(id2, bad.as_ptr(), bad.len());
            assert_ne!(rc, ZK_OK);
            bu_merkle_close_context(id2);
        }
        bu_merkle_close_context(id);
    }

    #[test]
    fn ironwood_kind_end_to_end() {
        let id = ctx();
        let mut blob = Vec::new();
        for v in [3u8, 5u8, 9u8] {
            let mut l = [0u8; 32];
            l[0] = v;
            blob.extend_from_slice(&l);
        }
        unsafe {
            // Unknown kind rejected everywhere.
            assert_eq!(
                bu_merkle_update_state(id, 7, blob.as_ptr(), blob.len()),
                ZK_ERR_INPUT
            );
            // Ironwood append + checkpoint + witness.
            assert_eq!(
                bu_merkle_update_state(id, 2, blob.as_ptr(), blob.len()),
                ZK_OK
            );
            assert_eq!(bu_merkle_checkpoint(id, 41), ZK_OK);
            let mut pos = Vec::new();
            for p in [0u64, 1, 2] {
                pos.extend_from_slice(&p.to_le_bytes());
            }
            let mut out = alloc::vec![0u8; 4096];
            let mut out_len = out.len();
            assert_eq!(
                bu_merkle_create_witness(
                    id,
                    2,
                    41,
                    pos.as_ptr(),
                    pos.len(),
                    out.as_mut_ptr(),
                    &mut out_len
                ),
                ZK_OK
            );
            assert_eq!(out_len, 32 + 4 + 3 * (8 + 32 * 32));
            // Blob round-trip over absorbed subtrees (live tip frontiers are
            // re-appended by the caller, never imported).
            let mut root = [0u8; 32];
            root[0] = 0xAA;
            assert_eq!(
                bu_merkle_update_subtree(id, 2, 0, root.as_ptr(), root.len()),
                ZK_ERR_INPUT
            ); // tip present: start must equal size (3), not 0
            let id3 = ctx();
            assert_eq!(
                bu_merkle_update_subtree(id3, 2, 0, root.as_ptr(), root.len()),
                ZK_OK
            );
            assert_eq!(bu_merkle_checkpoint(id3, 7), ZK_OK);
            let mut cbuf = alloc::vec![0u8; 1 << 20];
            let mut clen = cbuf.len();
            assert_eq!(
                bu_merkle_get_context(id3, cbuf.as_mut_ptr(), &mut clen),
                ZK_OK
            );
            let id2 = ctx();
            assert_eq!(
                bu_merkle_insert_chain_state(id2, cbuf.as_ptr(), clen),
                ZK_OK
            );
            // Same export bytes again: deterministic codec.
            let mut cbuf2 = alloc::vec![0u8; 1 << 20];
            let mut clen2 = cbuf2.len();
            assert_eq!(
                bu_merkle_get_context(id2, cbuf2.as_mut_ptr(), &mut clen2),
                ZK_OK
            );
            assert_eq!(&cbuf[..clen], &cbuf2[..clen2]);
            // Re-appended tip leaves witness fine on the restored mirror.
            // Absorbed prefix spans [0, 65536), so the 3 leaves land at
            // 65536..65539; snapshot them under a fresh checkpoint.
            assert_eq!(
                bu_merkle_update_state(id2, 2, blob.as_ptr(), blob.len()),
                ZK_OK
            );
            assert_eq!(bu_merkle_checkpoint(id2, 8), ZK_OK);
            let mut pos2 = Vec::new();
            for p in [65536u64, 65537, 65538] {
                pos2.extend_from_slice(&p.to_le_bytes());
            }
            let mut out3 = alloc::vec![0u8; 4096];
            let mut out_len3 = out3.len();
            assert_eq!(
                bu_merkle_create_witness(
                    id2,
                    2,
                    8,
                    pos2.as_ptr(),
                    pos2.len(),
                    out3.as_mut_ptr(),
                    &mut out_len3
                ),
                ZK_OK
            );
            assert_eq!(out_len3, out_len);
            // Legacy blob (ironwood tail stripped from a fresh, empty
            // export: empty frontier + no leaves/subtrees/checkpoints = 17
            // tail bytes) still imports.
            let id0 = ctx();
            let mut c0 = alloc::vec![0u8; 1 << 20];
            let mut c0len = c0.len();
            assert_eq!(
                bu_merkle_get_context(id0, c0.as_mut_ptr(), &mut c0len),
                ZK_OK
            );
            let legacy_len = c0len - 17;
            let id4 = ctx();
            assert_eq!(
                bu_merkle_insert_chain_state(id4, c0.as_ptr(), legacy_len),
                ZK_OK
            );
            bu_merkle_close_context(id4);
            bu_merkle_close_context(id0);
            bu_merkle_close_context(id2);
            bu_merkle_close_context(id3);
        }
        bu_merkle_close_context(id);
    }
}
