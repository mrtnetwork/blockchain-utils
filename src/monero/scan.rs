//! Monero output scanning: key derivation, view tags, batch unlock.
//!
//! Pure `no_std` + `alloc` port of `onchain_crypto_c/on_chain_crypto.c`
//! semantics (itself wallet2's scan loop), with one security upgrade: the
//! ECDH with the **secret view key** uses constant-time [`CurvePoint::mul`]
//! while the C uses vartime `ge_scalarmult` (timing-leaks the view key).
//! Point decodes stay vartime — all decoded points here are public data.
//!
//! Per (account, output) flow, mirroring `wallet2::is_out_to_acc`:
//! `D = 8·v·R` → optional view-tag check → for each subaddress spend key
//! `P = B + Hs(D‖varint(i))·G`, compare against the output key.

use crate::curve::ed25519::monero as ed_mono;
use crate::curve::ed25519::Ed25519Point;
use crate::curve::traits::CurvePoint;
use crate::monero::{
    keccak256, pt_decode, pt_encode, sc_from_bytes, sc_reduce, varint, MoneroResult, Scalar, S32,
};
use alloc::vec::Vec;

/// View-tag hash domain: ASCII `"view_tag"`.
pub const VIEW_TAG_DOMAIN: &[u8; 8] = b"view_tag";

/// `D = 8·v·R`: shared derivation from tx pubkey `R` and secret view key `v`.
///
/// Rejects non-canonical `v`. Uses CT scalar mult (see module docs).
pub fn generate_key_derivation(tx_pub: &S32, view_secret: &S32) -> MoneroResult<S32> {
    let p = pt_decode(tx_pub)?;
    let v = sc_from_bytes(view_secret)?;
    let q = p.mul(&v);
    pt_encode(&ed_mono::mul_by_cofactor(&q))
}

/// `Hs(D‖varint(i))`: output scalar, keccak then reduce mod L.
pub fn derivation_to_scalar(derivation: &S32, out_index: u32) -> MoneroResult<Scalar> {
    let mut data = Vec::with_capacity(32 + 5);
    data.extend_from_slice(derivation);
    data.extend_from_slice(&varint(out_index as u64));
    let h = keccak256(&data)?;
    Ok(sc_reduce(&h))
}

/// `P = B + Hs(D‖varint(i))·G`: re-derive the one-time output key.
///
/// The `Hs(D‖i)·G` mult is variable-time fixed-base (like the C's
/// `ge_scalarmult_base`): the scalar is single-use per output, so timing
/// samples cannot be averaged across scans the way a reused key would
/// allow. The secret view key never touches a vartime op (see
/// [`generate_key_derivation`]).
pub fn derive_output_public_key(
    derivation: &S32,
    out_index: u32,
    spend_pub: &S32,
) -> MoneroResult<S32> {
    let base = pt_decode(spend_pub)?;
    derive_output_public_key_predecoded(derivation, out_index, &base)
}

/// [`derive_output_public_key`] with the spend point already decoded —
/// batch callers decode each account's spend keys once, not per output.
pub fn derive_output_public_key_predecoded(
    derivation: &S32,
    out_index: u32,
    spend_point: &Ed25519Point,
) -> MoneroResult<S32> {
    let s = derivation_to_scalar(derivation, out_index)?;
    let sg = Ed25519Point::mul_vartime_base(&s);
    pt_encode(&spend_point.add(&sg))
}

/// `Hs("view_tag"‖D‖varint(i))[0]`: one-byte prefilter (v0.18+ outputs).
pub fn derive_view_tag(derivation: &S32, out_index: u32) -> MoneroResult<u8> {
    let mut data = Vec::with_capacity(8 + 32 + 5);
    data.extend_from_slice(VIEW_TAG_DOMAIN);
    data.extend_from_slice(derivation);
    data.extend_from_slice(&varint(out_index as u64));
    Ok(keccak256(&data)?[0])
}

/// Candidate-output check: `None` when the output is not ours OR when the
/// tx pubkey fails to decode (mirrors the C's `return 1` skip path).
/// `view_tag = None` skips the tag check (C passes `-1`, `null`).
pub fn is_account_output(
    view_secret: &S32,
    tx_pub: &S32,
    view_tag: Option<u8>,
    out_index: u32,
) -> MoneroResult<Option<S32>> {
    let d = match generate_key_derivation(tx_pub, view_secret) {
        Ok(d) => d,
        Err(_) => return Ok(None),
    };
    if let Some(t) = view_tag {
        if derive_view_tag(&d, out_index)? != t {
            return Ok(None);
        }
    }
    Ok(Some(d))
}

/// One account's scan keys: secret view key + subaddress spend pubkeys.
/// `address_pos` in matches is the position in `spend_pubs` (caller maps it
/// to the subaddress minor index, like the C's `spend_index_counts` layout).
pub struct ScanAccount<'a> {
    pub view_secret: &'a S32,
    pub spend_pubs: &'a [S32],
}

/// One output's scan data. `additional_pub` is the per-output additional tx
/// pubkey for subaddress sends (`None` when absent — C passes `NULL`).
/// `out_index` is the real output index within its transaction: it feeds
/// `Hs(D‖i)` and the view-tag hash, so callers batching several transactions
/// must pass each output's own vout index here (NOT its position in a
/// flattened array).
pub struct ScanOutput<'a> {
    pub out_key: &'a S32,
    pub tx_pub: &'a S32,
    pub additional_pub: Option<&'a S32>,
    pub view_tag: Option<u8>,
    pub out_index: u32,
}

/// A matched output. `derivation` + `derived_pk` are returned because the
/// caller needs them downstream (amount decode, key image). `out_index` is
/// the output's position in the caller's `outputs` slice (routing key);
/// the transaction-local vout index lives on the caller's side.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MatchedOutput {
    pub out_index: u32,
    pub account_index: u32,
    pub address_pos: u32,
    pub derivation: S32,
    pub derived_pk: S32,
}

/// Check one (account, output, derivation) candidate: optional view-tag
/// prefilter, then stealth-key recompute for every subaddress spend key.
/// `spends` holds the account's pre-decoded spend points with their original
/// positions (undecodable keys are filtered by the caller — they could never
/// match, same as the per-output skip). Pushes on match. Never fails
/// (every per-candidate failure is a skip).
#[inline]
fn match_candidate(
    out: &mut Vec<MatchedOutput>,
    acc_idx: usize,
    out_pos: usize,
    spends: &[(usize, Ed25519Point)],
    o: &ScanOutput<'_>,
    d: S32,
) {
    let i = o.out_index;
    if let Some(t) = o.view_tag {
        match derive_view_tag(&d, i) {
            Ok(tag) if tag == t => {}
            _ => return,
        }
    }
    for (pos, spend) in spends {
        let p = match derive_output_public_key_predecoded(&d, i, spend) {
            Ok(p) => p,
            Err(_) => continue,
        };
        if p == *o.out_key {
            out.push(MatchedOutput {
                out_index: out_pos as u32,
                account_index: acc_idx as u32,
                address_pos: *pos as u32,
                derivation: d,
                derived_pk: p,
            });
        }
    }
}

/// Batch scan over accounts × outputs. Infallible at the top level (every
/// per-candidate failure is a skip, like the C): returns all matches.
///
/// Derivation cache: `D` depends only on `(view_secret, tx_pub), so outputs
/// sharing one tx pubkey (the common case: every output of a transaction)
/// derive once and reuse. One `(tx_pub → Option<D>)` slot per account is
/// enough because callers group a transaction's outputs adjacently; the
/// `None` (undecodable pubkey) outcome is cached too.
///
/// Parallelism (crate feature `multicore`, native only): outputs are split
/// into contiguous ranges, each worker running all accounts over its range
/// with a private cache. Chunk results concatenate in order, so the match
/// sequence is bit-identical to the serial run. Small batches (< 256
/// outputs) and non-`multicore` builds always take the serial path.
pub fn unlock_outputs_batch(
    accounts: &[ScanAccount<'_>],
    outputs: &[ScanOutput<'_>],
) -> Vec<MatchedOutput> {
    const SERIAL_CUTOFF: usize = 256;
    let threads = crate::multicore::num_threads();
    if threads <= 1 || outputs.len() < SERIAL_CUTOFF {
        return unlock_outputs_batch_range(accounts, outputs, 0);
    }
    let chunks = threads.min(outputs.len());
    let chunk_len = outputs.len().div_ceil(chunks);
    crate::multicore::scope(|s| {
        let mut handles = Vec::with_capacity(chunks);
        for (c, outs) in outputs.chunks(chunk_len).enumerate() {
            let base = c * chunk_len;
            handles.push(s.spawn(move || {
                unlock_outputs_batch_range(accounts, outs, base)
            }));
        }
        let mut out = Vec::new();
        for h in handles {
            out.extend(crate::multicore::Scope::join(h));
        }
        out
    })
}

/// Serial scan of an output slice; `base_pos` is added to each match's
/// `out_index` so chunked (parallel) runs route exactly like serial ones.
fn unlock_outputs_batch_range(
    accounts: &[ScanAccount<'_>],
    outputs: &[ScanOutput<'_>],
    base_pos: usize,
) -> Vec<MatchedOutput> {
    let mut out = Vec::new();
    for (acc_idx, acc) in accounts.iter().enumerate() {
        // Decode the account's spend keys once: an undecodable spend key can
        // never match, so dropping it here equals the old per-output skip.
        let spends: Vec<(usize, Ed25519Point)> = acc
            .spend_pubs
            .iter()
            .enumerate()
            .filter_map(|(pos, s)| pt_decode(s).ok().map(|p| (pos, p)))
            .collect();
        let mut cache: Option<(S32, Option<S32>)> = None;
        for (out_pos, o) in outputs.iter().enumerate() {
            let out_pos = base_pos + out_pos;
            // Primary tx pubkey: cached derivation.
            let d = match cache {
                Some((p, d)) if p == *o.tx_pub => d,
                _ => {
                let r = generate_key_derivation(o.tx_pub, acc.view_secret).ok();
                    cache = Some((*o.tx_pub, r));
                    r
                }
            };
            if let Some(d) = d {
                match_candidate(&mut out, acc_idx, out_pos, &spends, o, d);
            }
            // Per-output additional pubkey: distinct per output, uncached.
            if let Some(add) = o.additional_pub {
                if let Ok(d) = generate_key_derivation(add, acc.view_secret) {
                    match_candidate(&mut out, acc_idx, out_pos, &spends, o, d);
                }
            }
        }
    }
    out
}
