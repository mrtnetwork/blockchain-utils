//! Monero Bulletproofs+ C ABI (`feature = "ffi"`, needs `monero`).
//!
//! One proof blob (all integers little-endian):
//! ```text
//! m: u8 (1..=16) | V[m][32] | A A1 B R1 S1 D1 (6x32)
//! | n_lr: u8 (= 6 + log2(ceil_pow2(m))) | L[n_lr][32] | R[n_lr][32]
//! ```
//! A batch ("packed") is `n: u32 LE` followed by `n` entries of
//! `len: u32 LE | blob[len]`.
//!
//! - [`bu_monero_bp_plus_verify`]: `0` = valid, `1` = invalid equation,
//!   negative = malformed input.
//! - [`bu_monero_bp_plus_prove_amounts`] / [`bu_monero_bp_plus_prove_scalars`]:
//!   emit one proof blob with the `emit_bytes` size-query convention
//!   (`out == null` or too small → required size written, LENGTH error).
//!   Randomness comes from an explicit caller-supplied 32-byte `rng_seed`
//!   (deterministic per seed; pass fresh randomness per proof).

#![cfg(all(feature = "ffi", feature = "monero"))]

use crate::monero::bulletproofs_plus::{
    bp_plus_prove_amounts, bp_plus_prove_scalars, bp_plus_verify, emit_proof, unpack_proofs,
};

/// Success.
pub const BU_MONERO_OK: i32 = 0;
/// Proof is well-formed but the verification equation failed.
pub const BU_MONERO_INVALID: i32 = 1;
/// Null pointer argument.
pub const BU_MONERO_ERR_NULL: i32 = -1;
/// Bad length / buffer too small (required size written back).
pub const BU_MONERO_ERR_LENGTH: i32 = -2;
/// Malformed proof / batch encoding.
pub const BU_MONERO_ERR_PARSE: i32 = -3;
/// Invalid point / scalar / proof math failure.
pub const BU_MONERO_ERR_CRYPTO: i32 = -4;
/// Internal error.
pub const BU_MONERO_ERR_INTERNAL: i32 = -5;

fn emit_bytes(out: *mut u8, out_len: *mut usize, data: &[u8]) -> i32 {
    if out_len.is_null() {
        return BU_MONERO_ERR_NULL;
    }
    unsafe {
        if out.is_null() || *out_len < data.len() {
            *out_len = data.len();
            return BU_MONERO_ERR_LENGTH;
        }
        core::ptr::copy_nonoverlapping(data.as_ptr(), out, data.len());
        *out_len = data.len();
    }
    BU_MONERO_OK
}

fn map_crypto<T, E>(r: Result<T, E>) -> Result<T, i32> {
    r.map_err(|_| BU_MONERO_ERR_CRYPTO)
}

/// Verify a packed batch of Bulletproofs+ proofs.
///
/// Returns [`BU_MONERO_OK`] (valid), [`BU_MONERO_INVALID`] (well-formed but
/// failed), or a negative error code.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_monero_bp_plus_verify(packed: *const u8, packed_len: usize) -> i32 {
    if packed.is_null() || packed_len == 0 {
        return BU_MONERO_ERR_NULL;
    }
    let buf = unsafe { core::slice::from_raw_parts(packed, packed_len) };
    let proofs = match unpack_proofs(buf) {
        Ok(p) => p,
        Err(_) => return BU_MONERO_ERR_PARSE,
    };
    // Fixed zero seed for the batch weight RNG (any nonzero stream works;
    // determinism keeps verify reproducible).
    let seed = [0u8; 32];
    match map_crypto(bp_plus_verify(&proofs, &seed)) {
        Ok(true) => BU_MONERO_OK,
        Ok(false) => BU_MONERO_INVALID,
        Err(e) => e,
    }
}

fn read_seed(ptr: *const u8) -> Result<[u8; 32], i32> {
    if ptr.is_null() {
        return Err(BU_MONERO_ERR_NULL);
    }
    let mut seed = [0u8; 32];
    unsafe {
        core::ptr::copy_nonoverlapping(ptr, seed.as_mut_ptr(), 32);
    }
    Ok(seed)
}

/// Prove a Bulletproofs+ for `n` amounts (`u64 LE` each) with `n` gamma
/// masks (`n * 32` bytes). Emits one proof blob.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_monero_bp_plus_prove_amounts(
    amounts: *const u64,
    gamma: *const u8,
    n: usize,
    rng_seed: *const u8,
    out: *mut u8,
    out_len: *mut usize,
) -> i32 {
    if amounts.is_null() || gamma.is_null() || n == 0 || n > 16 {
        return BU_MONERO_ERR_LENGTH;
    }
    let seed = match read_seed(rng_seed) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let mut amts = alloc::vec::Vec::with_capacity(n);
    unsafe {
        for i in 0..n {
            amts.push(*amounts.add(i));
        }
    }
    let gbytes = unsafe { core::slice::from_raw_parts(gamma, n * 32) };
    let mut gammas = alloc::vec::Vec::with_capacity(n);
    for chunk in gbytes.as_chunks::<32>().0 {
        let mut g = [0u8; 32];
        g.copy_from_slice(chunk);
        gammas.push(g);
    }
    let proof = match map_crypto(bp_plus_prove_amounts(&amts, &gammas, &seed)) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let blob = match map_crypto(emit_proof(&proof)) {
        Ok(b) => b,
        Err(e) => return e,
    };
    emit_bytes(out, out_len, &blob)
}

/// Prove a Bulletproofs+ for `n` raw bit-scalar vectors (`n * 32` bytes)
/// with `n` gamma masks (`n * 32` bytes). Emits one proof blob.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_monero_bp_plus_prove_scalars(
    sv: *const u8,
    gamma: *const u8,
    n: usize,
    rng_seed: *const u8,
    out: *mut u8,
    out_len: *mut usize,
) -> i32 {
    if sv.is_null() || gamma.is_null() || n == 0 || n > 16 {
        return BU_MONERO_ERR_LENGTH;
    }
    let seed = match read_seed(rng_seed) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let svb = unsafe { core::slice::from_raw_parts(sv, n * 32) };
    let gbytes = unsafe { core::slice::from_raw_parts(gamma, n * 32) };
    let mut svs = alloc::vec::Vec::with_capacity(n);
    let mut gammas = alloc::vec::Vec::with_capacity(n);
    for chunk in svb.as_chunks::<32>().0 {
        let mut s = [0u8; 32];
        s.copy_from_slice(chunk);
        svs.push(s);
    }
    for chunk in gbytes.as_chunks::<32>().0 {
        let mut g = [0u8; 32];
        g.copy_from_slice(chunk);
        gammas.push(g);
    }
    let proof = match map_crypto(bp_plus_prove_scalars(&svs, &gammas, &seed)) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let blob = match map_crypto(emit_proof(&proof)) {
        Ok(b) => b,
        Err(e) => return e,
    };
    emit_bytes(out, out_len, &blob)
}

/// Packed match record length: `out_idx u32LE | acc_idx u32LE | addr_pos u32LE
/// | derivation[32] | derived_pk[32]` = 76 bytes.
pub const BU_MONERO_UNLOCK_RECORD_LEN: usize = 76;

/// Batch output scan (fast unlock). Mirrors
/// `onchain_crypto_c:monero_unlock_outputs_batch_compact`.
///
/// Layouts (all little-endian, all 32-byte keys raw):
/// - `view_secs`: `acc_count * 32` secret view keys.
/// - `spend_pubs`: `sum(spend_counts) * 32` subaddress spend pubkeys, flat.
/// - `spend_counts`: `acc_count` u32 entries (spend keys per account).
/// - `out_keys` / `tx_pubs`: `out_count * 32` each.
/// - `additional` + `additional_present`: `out_count * 32` per-output
///   additional tx pubkeys + `out_count` presence bytes (0/1). Both may be
///   null together (no additional keys); otherwise both required.
/// - `view_tags`: `out_count` int32 entries (`-1` = absent). May be null
///   (all absent).
/// - `out_indices`: `out_count` u32 entries: each output's real index within
///   its transaction (feeds `Hs(D‖i)` and the view tag). May be null, in
///   which case the output's position in the batch is used (correct only
///   for a single transaction scanned with no skipped outputs).
///
/// Emits packed 76-byte records via the `emit_bytes` size-query convention.
/// Bounds: `out_count <= 1_000_000`, `acc_count <= 100_000`,
/// `sum(spend_counts) <= 1_000_000` (else `BU_MONERO_ERR_LENGTH`).
#[no_mangle]
#[allow(clippy::too_many_arguments)]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_monero_unlock_batch(
    view_secs: *const u8,
    spend_pubs: *const u8,
    spend_counts: *const u32,
    out_keys: *const u8,
    tx_pubs: *const u8,
    additional: *const u8,
    additional_present: *const u8,
    view_tags: *const i32,
    out_indices: *const u32,
    out_count: u32,
    acc_count: u32,
    out: *mut u8,
    out_len: *mut usize,
) -> i32 {
    use crate::monero::scan::{unlock_outputs_batch, MatchedOutput, ScanAccount, ScanOutput};

    let n_out = out_count as usize;
    let n_acc = acc_count as usize;
    if n_out > 1_000_000 || n_acc > 100_000 {
        return BU_MONERO_ERR_LENGTH;
    }
    if n_out > 0 && (view_secs.is_null() || out_keys.is_null() || tx_pubs.is_null()) {
        return BU_MONERO_ERR_NULL;
    }
    if n_acc > 0 && (view_secs.is_null() || spend_counts.is_null()) {
        return BU_MONERO_ERR_NULL;
    }
    let has_add = !additional.is_null() || !additional_present.is_null();
    if has_add && (additional.is_null() || additional_present.is_null()) {
        return BU_MONERO_ERR_NULL;
    }
    if n_acc > 0 && !spend_pubs.is_null() && spend_counts.is_null() {
        return BU_MONERO_ERR_NULL;
    }

    let counts: &[u32] = if n_acc == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(spend_counts, n_acc) }
    };
    let mut total_spend: u64 = 0;
    for c in counts {
        total_spend += *c as u64;
        if total_spend > 1_000_000 {
            return BU_MONERO_ERR_LENGTH;
        }
    }
    let total_spend = total_spend as usize;
    if total_spend > 0 && spend_pubs.is_null() {
        return BU_MONERO_ERR_NULL;
    }

    fn chunks32(ptr: *const u8, n: usize) -> alloc::vec::Vec<[u8; 32]> {
        if n == 0 {
            return alloc::vec::Vec::new();
        }
        let raw = unsafe { core::slice::from_raw_parts(ptr, n * 32) };
        let mut v = alloc::vec::Vec::with_capacity(n);
        for c in raw.as_chunks::<32>().0 {
            let mut b = [0u8; 32];
            b.copy_from_slice(c);
            v.push(b);
        }
        v
    }

    let views = chunks32(view_secs, n_acc);
    let spends = chunks32(spend_pubs, total_spend);
    let outs = chunks32(out_keys, n_out);
    let txs = chunks32(tx_pubs, n_out);
    let adds = chunks32(additional, if has_add { n_out } else { 0 });
    let mask: &[u8] = if has_add {
        unsafe { core::slice::from_raw_parts(additional_present, n_out) }
    } else {
        &[]
    };
    let tags: &[i32] = if view_tags.is_null() {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(view_tags, n_out) }
    };
    let indices: &[u32] = if out_indices.is_null() {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(out_indices, n_out) }
    };

    let mut accounts = alloc::vec::Vec::with_capacity(n_acc);
    let mut off = 0usize;
    for a in 0..n_acc {
        let k = counts[a] as usize;
        if off + k > spends.len() {
            return BU_MONERO_ERR_LENGTH;
        }
        accounts.push(ScanAccount {
            view_secret: &views[a],
            spend_pubs: &spends[off..off + k],
        });
        off += k;
    }
    let mut outputs = alloc::vec::Vec::with_capacity(n_out);
    for o in 0..n_out {
        let add_pub = if has_add && mask[o] != 0 {
            Some(&adds[o])
        } else {
            None
        };
        let tag = if tags.is_empty() || tags[o] < 0 {
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

    let matches: alloc::vec::Vec<MatchedOutput> = unlock_outputs_batch(&accounts, &outputs);
    let mut blob = alloc::vec::Vec::with_capacity(matches.len() * BU_MONERO_UNLOCK_RECORD_LEN);
    for m in &matches {
        blob.extend_from_slice(&m.out_index.to_le_bytes());
        blob.extend_from_slice(&m.account_index.to_le_bytes());
        blob.extend_from_slice(&m.address_pos.to_le_bytes());
        blob.extend_from_slice(&m.derivation);
        blob.extend_from_slice(&m.derived_pk);
    }
    emit_bytes(out, out_len, &blob)
}
