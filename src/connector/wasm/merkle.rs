//! Frontier-model Merkle context WASM exports (`BuWasm.merkle*`).
//!
//! Mirrors the C ABI (`connector::ffi::merkle`) over a `u32` id table:
//! create / close / get / insert-chain-state / update-state /
//! update-subtree / merge-state / create-witness. Packed layouts match the
//! FFI docs. Witness output: `anchor[32] | npaths_u32 |
//! paths[pos_u64 | limbs[32][32]]`.

#![cfg(all(
    feature = "wasm",
    any(
        feature = "zcash-incrementalmerkle",
        all(feature = "groth16-prover", feature = "orchard-halo2")
    )
))]

use std::cell::RefCell;
use std::collections::HashMap;

use wasm_bindgen::prelude::*;

use super::handles::alloc_id;
use crate::zk::incrementalmerkletree::bridge::{OrchardNode, SaplingNode};
use crate::zk::incrementalmerkletree::contexts::{
    CheckpointSnapshot, MerkleContext, ProtocolTree, SubtreeRoot,
};
use crate::zk::incrementalmerkletree::frontier::Frontier;
use crate::zk::incrementalmerkletree::{Hashable, MerkleError, Position, Retention};

type Context = MerkleContext<SaplingNode, OrchardNode>;

thread_local! {
    static CONTEXTS: RefCell<HashMap<u32, Context>> = RefCell::new(HashMap::new());
}

fn copy(u: &[u8]) -> Vec<u8> {
    let mut v = vec![0u8; u.len() as usize];
    v.copy_from_slice(u);
    v
}

fn to_js(v: &[u8]) -> Vec<u8> {
    (v).to_vec()
}

fn err(e: MerkleError) -> JsValue {
    JsValue::from_str(match e {
        MerkleError::PositionMismatch { .. }
        | MerkleError::LengthMismatch { .. }
        | MerkleError::PositionOutOfRange { .. }
        | MerkleError::PositionUnderflow => "E3:input",
        MerkleError::MaxDepthExceeded { .. }
        | MerkleError::TreeFull
        | MerkleError::InconsistentTree => "E6:merkle",
        MerkleError::Missing => "E8:missing",
        MerkleError::InvalidEncoding => "E2:encoding",
    })
}

fn with_context<T>(
    id: u32,
    f: impl FnOnce(&mut Context) -> Result<T, MerkleError>,
) -> Result<T, JsValue> {
    CONTEXTS.with(|m| {
        let mut m = m.borrow_mut();
        match m.get_mut(&id) {
            Some(ctx) => f(ctx).map_err(err),
            None => Err(JsValue::from_str("E8:missing")),
        }
    })
}

/// Create an empty wallet context; returns its id.
#[wasm_bindgen(js_name = merkleCreateContext)]
pub fn merkle_create_context() -> u32 {
    let id = alloc_id();
    CONTEXTS.with(|m| {
        m.borrow_mut().insert(id, Context::empty());
    });
    id
}

/// Drop a context; true when the id was live.
#[wasm_bindgen(js_name = merkleCloseContext)]
pub fn merkle_close_context(id: u32) -> bool {
    CONTEXTS.with(|m| m.borrow_mut().remove(&id).is_some())
}

/// Append `leaves.len()/32` leaves to tree `kind` (0 sapling, 1 orchard, 2 ironwood).
/// Err `E3:input` on bad length/kind, `E2:encoding` on bad node bytes, `E8:missing` on bad handle.
#[wasm_bindgen(js_name = merkleUpdateState)]
pub fn merkle_update_state(handle: u32, kind: u32, leaves: &[u8]) -> Result<(), JsValue> {
    let buf = copy(leaves);
    if buf.len() % 32 != 0 {
        return Err(JsValue::from_str("E3:input"));
    }
    with_context(handle, |ctx| {
        let mut items = Vec::with_capacity(buf.len() / 32);
        for chunk in buf.chunks_exact(32) {
            let mut a = [0u8; 32];
            a.copy_from_slice(chunk);
            items.push(a);
        }
        match kind {
            0 => {
                let nodes: Result<Vec<_>, _> = items
                    .iter()
                    .map(|b| SaplingNode::from_bytes(b).map(|h| (h, Retention::Ephemeral)))
                    .collect();
                let nodes = nodes?;
                ctx.sapling.append_leaves(nodes)
            }
            1 => {
                let nodes: Result<Vec<_>, _> = items
                    .iter()
                    .map(|b| OrchardNode::from_bytes(b).map(|h| (h, Retention::Ephemeral)))
                    .collect();
                let nodes = nodes?;
                ctx.orchard.append_leaves(nodes)
            }
            2 => {
                let nodes: Result<Vec<_>, _> = items
                    .iter()
                    .map(|b| OrchardNode::from_bytes(b).map(|h| (h, Retention::Ephemeral)))
                    .collect();
                let nodes = nodes?;
                ctx.ironwood.append_leaves(nodes)
            }
            _ => {
                return Err(MerkleError::LengthMismatch {
                    expected: 2,
                    found: kind as usize,
                })
            }
        }
    })
}

/// Absorb one level-16 subtree root (`root`: 32 bytes) at `start` (must equal current size).
/// Err `E3:input` on bad size/kind, `E2:encoding` on bad hash, `E8:missing` on bad handle.
#[wasm_bindgen(js_name = merkleUpdateSubtree)]
pub fn merkle_update_subtree(
    handle: u32,
    kind: u32,
    // u32 (not u64): JS numbers cannot carry full u64; 2^32 subtrees is
    // orders of magnitude beyond any real chain (level-16 => 2^48 leaves).
    start: u32,
    root: &[u8],
) -> Result<(), JsValue> {
    let bytes = copy(root);
    if bytes.len() != 32 {
        return Err(JsValue::from_str("E3:input"));
    }
    let mut h = [0u8; 32];
    h.copy_from_slice(&bytes);
    let start = start as u64;
    with_context(handle, |ctx| match kind {
        0 => {
            let n = SaplingNode::from_bytes(&h)?;
            ctx.sapling.absorb_subtree(start, n)
        }
        1 => {
            let n = OrchardNode::from_bytes(&h)?;
            ctx.orchard.absorb_subtree(start, n)
        }
        2 => {
            let n = OrchardNode::from_bytes(&h)?;
            ctx.ironwood.absorb_subtree(start, n)
        }
        _ => Err(MerkleError::LengthMismatch {
            expected: 2,
            found: kind as usize,
        }),
    })
}

/// Snapshot all trees under `id` (evicts oldest beyond cap). Err `E8:missing` on bad handle.
#[wasm_bindgen(js_name = merkleCheckpoint)]
pub fn merkle_checkpoint(handle: u32, id: u32) -> Result<(), JsValue> {
    // WASM-side convenience (no legacy equivalent): snapshot both trees.
    with_context(handle, |ctx| {
        ctx.sapling.add_checkpoint(id);
        ctx.orchard.add_checkpoint(id);
        ctx.ironwood.add_checkpoint(id);
        Ok(())
    })
}

/// Witness `positions` (n×u64le) at `checkpoint`; returns `anchor[32] | npaths_u32 | paths[pos_u64 | limbs[32][32]]`.
/// Err `E3:input` on bad positions length, `E8:missing` on bad handle/checkpoint.
#[wasm_bindgen(js_name = merkleCreateWitness)]
pub fn merkle_create_witness(
    handle: u32,
    kind: u32,
    checkpoint: u32,
    positions: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let bytes = copy(positions);
    if bytes.len() % 8 != 0 {
        return Err(JsValue::from_str("E3:input"));
    }
    let mut pos = Vec::with_capacity(bytes.len() / 8);
    for chunk in bytes.chunks_exact(8) {
        let mut a = [0u8; 8];
        a.copy_from_slice(chunk);
        pos.push(u64::from_le_bytes(a));
    }
    with_context(handle, |ctx| {
        let mut out = Vec::new();
        let mut first = true;
        let push_path = |out: &mut Vec<u8>,
                         anchor: &[u8; 32],
                         position: u64,
                         elems: &[[u8; 32]],
                         is_first: &mut bool| {
            if *is_first {
                out.extend_from_slice(anchor);
                out.extend_from_slice(&(pos.len() as u32).to_le_bytes());
                *is_first = false;
            }
            out.extend_from_slice(&position.to_le_bytes());
            for e in elems {
                out.extend_from_slice(e);
            }
        };
        match kind {
            0 => {
                // One memoized fold for the whole batch (was: one full
                // replay per position via witness_at).
                let items = ctx.sapling.witness_many(&pos, checkpoint)?;
                for (anchor, path) in &items {
                    let elems: Vec<[u8; 32]> = path.path_elems().iter().map(|n| n.0).collect();
                    push_path(
                        &mut out,
                        &anchor.0,
                        u64::from(path.position()),
                        &elems,
                        &mut first,
                    );
                }
                Ok(to_js(&out))
            }
            1 => {
                let items = ctx.orchard.witness_many(&pos, checkpoint)?;
                for (anchor, path) in &items {
                    let elems: Vec<[u8; 32]> = path.path_elems().iter().map(|n| n.0).collect();
                    push_path(
                        &mut out,
                        &anchor.0,
                        u64::from(path.position()),
                        &elems,
                        &mut first,
                    );
                }
                Ok(to_js(&out))
            }
            2 => {
                let items = ctx.ironwood.witness_many(&pos, checkpoint)?;
                for (anchor, path) in &items {
                    let elems: Vec<[u8; 32]> = path.path_elems().iter().map(|n| n.0).collect();
                    push_path(
                        &mut out,
                        &anchor.0,
                        u64::from(path.position()),
                        &elems,
                        &mut first,
                    );
                }
                Ok(to_js(&out))
            }
            _ => Err(MerkleError::LengthMismatch {
                expected: 2,
                found: kind as usize,
            }),
        }
    })
}

// ---------------------------------------------------------------------------
// Export / restore codec.
//
// Packed layouts mirror `connector::ffi::merkle` exactly (little-endian):
// FrontierState: has_u8 | [pos_u64 | leaf[32] | nommers_u32 | ommers[n][32]]
// ProtocolState: frontier_state | nleaves_u32 | leaves[n][32]
//   | nsub_u32 | subtrees[n][start_u64 | level_u8 | hash[32]]
//   | nckpt_u32 | checkpoints[n][id_u32 | size_u64 | nsub_u32]
// ContextState: sapling_state | orchard_state | height_u32 | hash[32]
//   | sap_idx_u32 | orch_idx_u32
// MergeState: nckpt_u32 | checkpoints[n][id_u32 | size_u64 | nsub_u32]
//   | nsub_u32 | subtrees[n][start_u64 | level_u8 | hash[32]]
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

    fn take(&mut self, n: usize) -> Result<&'a [u8], MerkleError> {
        if self.rest() < n {
            return Err(MerkleError::LengthMismatch {
                expected: n,
                found: self.rest(),
            });
        }
        let s = &self.buf[self.off..self.off + n];
        self.off += n;
        Ok(s)
    }

    fn u8v(&mut self) -> Result<u8, MerkleError> {
        Ok(self.take(1)?[0])
    }

    fn u32v(&mut self) -> Result<u32, MerkleError> {
        let mut a = [0u8; 4];
        a.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(a))
    }

    fn u64v(&mut self) -> Result<u64, MerkleError> {
        let mut a = [0u8; 8];
        a.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(a))
    }

    fn bytes32(&mut self) -> Result<[u8; 32], MerkleError> {
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

fn write_frontier(w: &mut Writer, get: impl Fn() -> (bool, u64, [u8; 32], Vec<[u8; 32]>)) {
    let (has, pos, leaf, ommers) = get();
    w.u8v(u8::from(has));
    if has {
        w.u64v(pos);
        w.bytes32(&leaf);
        w.u32v(ommers.len() as u32);
        for o in &ommers {
            w.bytes32(o);
        }
    }
}

fn parse_frontier<H: Clone>(
    r: &mut Reader<'_>,
    decode: impl Fn([u8; 32]) -> Result<H, MerkleError>,
) -> Result<Frontier<H, 32>, MerkleError> {
    let has = r.u8v()?;
    if has == 0 {
        return Ok(Frontier::empty());
    }
    if has != 1 {
        return Err(MerkleError::LengthMismatch {
            expected: 1,
            found: 1,
        });
    }
    let pos = r.u64v()?;
    let leaf_b = r.bytes32()?;
    let n = r.u32v()?;
    if n > 64 {
        return Err(MerkleError::LengthMismatch {
            expected: 64,
            found: n as usize,
        });
    }
    let mut ommers = Vec::with_capacity(n as usize);
    for _ in 0..n {
        ommers.push(decode(r.bytes32()?)?);
    }
    Frontier::from_parts(Position::from(pos), decode(leaf_b)?, ommers).map_err(MerkleError::from)
}

fn write_tree<H: Clone>(w: &mut Writer, tree: &ProtocolTree<H>, bytes_of: impl Fn(&H) -> [u8; 32]) {
    // Frontier is always written empty: tip leaves are re-appended by the
    // caller after restore (positions are absolute, so contiguity is
    // checkable). A non-empty frontier is unimportable by design
    // (`parse_tree` rejects it: witnesses replay from the leaf log, which
    // blobs intentionally do not carry).
    write_frontier(w, || (false, 0, [0u8; 32], Vec::new()));
    w.u32v(0);
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
) -> Result<ProtocolTree<H>, MerkleError> {
    let frontier = parse_frontier(r, decode)?;
    let nleaves = r.u32v()?;
    if nleaves != 0 {
        return Err(MerkleError::LengthMismatch {
            expected: 0,
            found: nleaves as usize,
        });
    }
    let nsub = r.u32v()?;
    if nsub > 4096 {
        return Err(MerkleError::LengthMismatch {
            expected: 4096,
            found: nsub as usize,
        });
    }
    let mut subtrees = Vec::with_capacity(nsub as usize);
    for _ in 0..nsub {
        let start = r.u64v()?;
        let level = r.u8v()?;
        let hash_b = r.bytes32()?;
        subtrees.push(SubtreeRoot {
            start,
            level,
            hash: decode(hash_b)?,
        });
    }
    let nckpt = r.u32v()?;
    if nckpt > 1024 {
        return Err(MerkleError::LengthMismatch {
            expected: 1024,
            found: nckpt as usize,
        });
    }
    let mut checkpoints = Vec::with_capacity(nckpt as usize);
    for _ in 0..nckpt {
        checkpoints.push(CheckpointSnapshot {
            id: r.u32v()?,
            size: r.u64v()?,
            subtree_count: r.u32v()? as usize,
        });
    }
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
    if frontier.value().is_some() {
        return Err(MerkleError::InconsistentTree);
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

fn parse_context(buf: &[u8]) -> Result<Context, MerkleError> {
    let mut r = Reader::new(buf);
    let sapling = parse_tree(&mut r, |b| SaplingNode::from_bytes(&b))?;
    let orchard = parse_tree(&mut r, |b| OrchardNode::from_bytes(&b))?;
    let height = r.u32v()?;
    let hash = r.bytes32()?;
    let sapling_subtree_index = r.u32v()?;
    let orchard_subtree_index = r.u32v()?;
    // Legacy blobs end here; new blobs append ironwood tree + index.
    let (ironwood, ironwood_subtree_index) = if r.rest() == 0 {
        (ProtocolTree::<OrchardNode>::empty(), 0)
    } else {
        let t = parse_tree(&mut r, |b| OrchardNode::from_bytes(&b))?;
        let idx = r.u32v()?;
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

/// Export a context as a packed ContextState blob. Err `E8:missing` on bad handle.
#[wasm_bindgen(js_name = merkleGetContext)]
pub fn merkle_get_context(handle: u32) -> Result<Vec<u8>, JsValue> {
    with_context(handle, |ctx| {
        let mut w = Writer::new();
        write_context(&mut w, ctx);
        Ok(to_js(&w.finish()))
    })
}

/// Restore a context from an exported blob (replaces state). Err `E3:input`/`E2:encoding` on bad blob, `E8:missing` on bad handle.
#[wasm_bindgen(js_name = merkleInsertChainState)]
pub fn merkle_insert_chain_state(handle: u32, blob: &[u8]) -> Result<(), JsValue> {
    let bytes = copy(blob);
    let ctx = parse_context(&bytes).map_err(err)?;
    with_context(handle, |slot| {
        *slot = ctx;
        Ok(())
    })
}

/// Merge checkpoints + contiguous subtrees from a merge blob (non-contiguous roots skipped, not fatal).
/// Err `E3:input` on bad blob/kind, `E8:missing` on bad handle.
#[wasm_bindgen(js_name = merkleMergeState)]
pub fn merkle_merge_state(handle: u32, kind: u32, blob: &[u8]) -> Result<(), JsValue> {
    let bytes = copy(blob);
    let mut r = Reader::new(&bytes);
    let nckpt = r.u32v().map_err(err)?;
    if nckpt > 1024 {
        return Err(err(MerkleError::LengthMismatch {
            expected: 1024,
            found: nckpt as usize,
        }));
    }
    let mut ckpts = Vec::with_capacity(nckpt as usize);
    for _ in 0..nckpt {
        let (cid, size, ns) = (
            r.u32v().map_err(err)?,
            r.u64v().map_err(err)?,
            r.u32v().map_err(err)?,
        );
        ckpts.push((cid, size, ns));
    }
    let nsub = r.u32v().map_err(err)?;
    if nsub > 4096 {
        return Err(err(MerkleError::LengthMismatch {
            expected: 4096,
            found: nsub as usize,
        }));
    }
    let mut subs = Vec::with_capacity(nsub as usize);
    for _ in 0..nsub {
        subs.push((
            r.u64v().map_err(err)?,
            r.u8v().map_err(err)?,
            r.bytes32().map_err(err)?,
        ));
    }
    if r.rest() != 0 {
        return Err(err(MerkleError::LengthMismatch {
            expected: 0,
            found: r.rest(),
        }));
    }
    with_context(handle, |ctx| {
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
            _ => {
                return Err(MerkleError::LengthMismatch {
                    expected: 2,
                    found: kind as usize,
                });
            }
        };
        for (start, level, hash) in &subs {
            if *level != crate::zk::incrementalmerkletree::contexts::SUBTREE_LEVEL {
                return Err(MerkleError::LengthMismatch {
                    expected: 16,
                    found: *level as usize,
                });
            }
            let rc = match kind {
                0 => SaplingNode::from_bytes(hash)
                    .and_then(|h| ctx.sapling.absorb_subtree(*start, h)),
                1 => OrchardNode::from_bytes(hash)
                    .and_then(|h| ctx.orchard.absorb_subtree(*start, h)),
                2 => OrchardNode::from_bytes(hash)
                    .and_then(|h| ctx.ironwood.absorb_subtree(*start, h)),
                _ => Err(MerkleError::LengthMismatch {
                    expected: 2,
                    found: kind as usize,
                }),
            };
            // Contiguity violations are skipped (partial merge), not fatal.
            let _ = rc;
        }
        Ok(())
    })
}
