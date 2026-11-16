//! Monero Bulletproofs+ WASM exports (`BuWasm.monero*`).
//!
//! Same blob/batch encoding as the C ABI (`connector::ffi::monero`):
//! one proof blob is `m: u8 | V[m][32] | A A1 B R1 S1 D1 | n_lr: u8 |
//! L[n_lr][32] | R[n_lr][32]`; a batch is `n: u32 LE | len: u32 LE |
//! blob * n`.

#![cfg(all(feature = "wasm", feature = "monero"))]

use wasm_bindgen::prelude::*;

use crate::monero::bulletproofs_plus::{
    bp_plus_prove_amounts, bp_plus_prove_scalars, bp_plus_verify, emit_proof, pack_proofs,
    unpack_proofs,
};

fn u8_vec(a: &[u8]) -> Vec<u8> {
    let mut v = vec![0u8; a.len() as usize];
    v.copy_from_slice(a);
    v
}

fn to_u8(v: &[u8]) -> Vec<u8> {
    v.to_vec()
}

fn read32(v: &[u8]) -> Result<[u8; 32], JsValue> {
    if v.len() != 32 {
        return Err(JsValue::from_str("need 32 bytes"));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(v);
    Ok(out)
}

fn read_chunks(v: &[u8], n: usize) -> Result<Vec<[u8; 32]>, JsValue> {
    if v.len() != n * 32 {
        return Err(JsValue::from_str("bad chunk length"));
    }
    let mut out = Vec::with_capacity(n);
    for c in v.chunks_exact(32) {
        let mut b = [0u8; 32];
        b.copy_from_slice(c);
        out.push(b);
    }
    Ok(out)
}

/// Verify a packed batch. Returns `true` iff every proof is valid.
/// Throws on malformed input.
#[wasm_bindgen(js_name = moneroBpPlusVerify)]
pub fn monero_bp_plus_verify(packed: &[u8]) -> Result<bool, JsValue> {
    let proofs = unpack_proofs(&u8_vec(packed)).map_err(|_| JsValue::from_str("parse"))?;
    let seed = [0u8; 32];
    bp_plus_verify(&proofs, &seed).map_err(|_| JsValue::from_str("verify"))
}

/// Prove for `n` amounts (`amounts` = n×8 LE bytes) with `n` gamma masks
/// (`gamma` = n×32 bytes) and a 32-byte `seed`. Returns one proof blob.
#[wasm_bindgen(js_name = moneroBpPlusProveAmounts)]
pub fn monero_bp_plus_prove_amounts(
    amounts: &[u8],
    gamma: &[u8],
    seed: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let a = u8_vec(amounts);
    if a.len() % 8 != 0 || a.is_empty() || a.len() / 8 > 16 {
        return Err(JsValue::from_str("bad amounts"));
    }
    let n = a.len() / 8;
    let gammas = read_chunks(&u8_vec(gamma), n)?;
    let mut amts = Vec::with_capacity(n);
    for c in a.chunks_exact(8) {
        let mut b = [0u8; 8];
        b.copy_from_slice(c);
        amts.push(u64::from_le_bytes(b));
    }
    let proof = bp_plus_prove_amounts(&amts, &gammas, &read32(&u8_vec(seed))?)
        .map_err(|_| JsValue::from_str("prove"))?;
    Ok(to_u8(
        &emit_proof(&proof).map_err(|_| JsValue::from_str("encode"))?,
    ))
}

/// Prove for `n` raw bit-scalars (`sv` = n×32) with `n` gamma masks.
/// Returns one proof blob.
#[wasm_bindgen(js_name = moneroBpPlusProveScalars)]
pub fn monero_bp_plus_prove_scalars(
    sv: &[u8],
    gamma: &[u8],
    seed: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let s = u8_vec(sv);
    if s.len() % 32 != 0 || s.is_empty() || s.len() / 32 > 16 {
        return Err(JsValue::from_str("bad scalars"));
    }
    let n = s.len() / 32;
    let svs = read_chunks(&s, n)?;
    let gammas = read_chunks(&u8_vec(gamma), n)?;
    let proof = bp_plus_prove_scalars(&svs, &gammas, &read32(&u8_vec(seed))?)
        .map_err(|_| JsValue::from_str("prove"))?;
    Ok(to_u8(
        &emit_proof(&proof).map_err(|_| JsValue::from_str("encode"))?,
    ))
}

/// Pack several proof blobs (`concat of len: u32 LE | blob`) into one batch.
#[wasm_bindgen(js_name = moneroBpPlusPack)]
pub fn monero_bp_plus_pack(blobs: &[u8]) -> Result<Vec<u8>, JsValue> {
    let raw = u8_vec(blobs);
    let mut off = 0usize;
    let mut proofs = Vec::new();
    while off < raw.len() {
        if off + 4 > raw.len() {
            return Err(JsValue::from_str("parse"));
        }
        let mut lb = [0u8; 4];
        lb.copy_from_slice(&raw[off..off + 4]);
        off += 4;
        let len = u32::from_le_bytes(lb) as usize;
        if off + len > raw.len() {
            return Err(JsValue::from_str("parse"));
        }
        let p = crate::monero::bulletproofs_plus::parse_proof(&raw[off..off + len])
            .map_err(|_| JsValue::from_str("parse"))?;
        proofs.push(p);
        off += len;
    }
    if proofs.is_empty() {
        return Err(JsValue::from_str("empty"));
    }
    pack_proofs(&proofs)
        .map(|b| to_u8(&b))
        .map_err(|_| JsValue::from_str("encode"))
}

/// Batch output scan (fast unlock). Same semantics as
/// `bu_monero_unlock_batch`: packed keys in, packed 76-byte match records
/// (`out_idx u32LE | acc_idx u32LE | addr_pos u32LE | derivation[32] |
/// derived_pk[32]`) out.
///
/// - `spendCountsLe`: `acc_count` u32 LE entries.
/// - `additionalPresent`: `out_count` bytes (0/1); empty = none.
/// - `viewTagsLe`: `out_count` int32 LE entries (`-1` = absent); empty = none.
/// - `outIndicesLe`: `out_count` u32 LE entries (real output index within its
///   transaction); empty = use batch position (single-tx callers only).
#[wasm_bindgen(js_name = moneroUnlockBatch)]
pub fn monero_unlock_batch(
    view_secs: &[u8],
    spend_pubs: &[u8],
    spend_counts_le: &[u8],
    out_keys: &[u8],
    tx_pubs: &[u8],
    additional: &[u8],
    additional_present: &[u8],
    view_tags_le: &[u8],
    out_indices_le: &[u8],
    out_count: u32,
    acc_count: u32,
) -> Result<Vec<u8>, JsValue> {
    use crate::monero::scan::{unlock_outputs_batch, ScanAccount, ScanOutput};

    let bad = |m: &str| JsValue::from_str(m);
    let n_out = out_count as usize;
    let n_acc = acc_count as usize;
    if n_out > 1_000_000 || n_acc > 100_000 {
        return Err(bad("too many outputs/accounts"));
    }
    let views = u8_vec(view_secs);
    let spends = u8_vec(spend_pubs);
    let counts_raw = u8_vec(spend_counts_le);
    let outs = u8_vec(out_keys);
    let txs = u8_vec(tx_pubs);
    let adds = u8_vec(additional);
    let mask = u8_vec(additional_present);
    let tags_raw = u8_vec(view_tags_le);
    let indices_raw = u8_vec(out_indices_le);
    if views.len() != n_acc * 32
        || outs.len() != n_out * 32
        || txs.len() != n_out * 32
        || counts_raw.len() != n_acc * 4
    {
        return Err(bad("bad input length"));
    }
    if !mask.is_empty() && (mask.len() != n_out || adds.len() != n_out * 32) {
        return Err(bad("bad additional length"));
    }
    if !tags_raw.is_empty() && tags_raw.len() != n_out * 4 {
        return Err(bad("bad tags length"));
    }
    if !indices_raw.is_empty() && indices_raw.len() != n_out * 4 {
        return Err(bad("bad indices length"));
    }
    let to32 = |v: &[u8]| -> Result<Vec<[u8; 32]>, JsValue> { read_chunks(v, v.len() / 32) };
    let views = to32(&views)?;
    let spends = to32(&spends)?;
    let outs = to32(&outs)?;
    let txs = to32(&txs)?;
    let adds = if mask.is_empty() {
        Vec::new()
    } else {
        to32(&adds)?
    };
    let mut counts = Vec::with_capacity(n_acc);
    for c in counts_raw.chunks_exact(4) {
        let mut b = [0u8; 4];
        b.copy_from_slice(c);
        counts.push(u32::from_le_bytes(b));
    }
    let mut tags = Vec::with_capacity(n_out);
    if !tags_raw.is_empty() {
        for c in tags_raw.chunks_exact(4) {
            let mut b = [0u8; 4];
            b.copy_from_slice(c);
            tags.push(i32::from_le_bytes(b));
        }
    }
    let mut indices = Vec::with_capacity(n_out);
    if !indices_raw.is_empty() {
        for c in indices_raw.chunks_exact(4) {
            let mut b = [0u8; 4];
            b.copy_from_slice(c);
            indices.push(u32::from_le_bytes(b));
        }
    }
    let mut accounts = Vec::with_capacity(n_acc);
    let mut off = 0usize;
    for a in 0..n_acc {
        let k = counts[a] as usize;
        if off + k > spends.len() || off + k > 1_000_000 {
            return Err(bad("bad spend counts"));
        }
        accounts.push(ScanAccount {
            view_secret: &views[a],
            spend_pubs: &spends[off..off + k],
        });
        off += k;
    }
    let mut outputs = Vec::with_capacity(n_out);
    for o in 0..n_out {
        let add_pub = if !mask.is_empty() && mask[o] != 0 {
            Some(&adds[o])
        } else {
            None
        };
        let tag = if tags.is_empty() {
            None
        } else if tags[o] < 0 {
            None
        } else {
            Some(tags[o] as u8)
        };
        let index = if indices.is_empty() { o as u32 } else { indices[o] };
        outputs.push(ScanOutput {
            out_key: &outs[o],
            tx_pub: &txs[o],
            additional_pub: add_pub,
            view_tag: tag,
            out_index: index,
        });
    }
    let mut blob = Vec::new();
    for m in unlock_outputs_batch(&accounts, &outputs) {
        blob.extend_from_slice(&m.out_index.to_le_bytes());
        blob.extend_from_slice(&m.account_index.to_le_bytes());
        blob.extend_from_slice(&m.address_pos.to_le_bytes());
        blob.extend_from_slice(&m.derivation);
        blob.extend_from_slice(&m.derived_pk);
    }
    Ok(to_u8(&blob))
}
