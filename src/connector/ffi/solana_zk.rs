//! Solana confidential-transfer ZK C ABI (`feature = "ffi"`).
//!
//! /// Dalek-compatible surface (NOT Monero Bulletproofs+):
//! validation is real (length + Ristretto decode); ElGamal, all Sigma proofs,
//! aggregated range proofs, withdraw/transfer/fee bundles and AES-GCM-SIV
//! are fully implemented zero-dep provers under on-chain instruction
//! transcripts. Same `emit_bytes` size-query convention as
//! `connector::ffi::monero` so the external connector shares plumbing.

#![cfg(feature = "ffi")]

use crate::solana_zk::sigma_proofs::{
    prove_batched_grouped_validity_2, prove_batched_grouped_validity_3,
    prove_ciphertext_ciphertext_equality, prove_ciphertext_commitment_equality,
    prove_grouped_validity_2, prove_grouped_validity_3, prove_percentage_with_cap,
    prove_pubkey_validity, prove_zero_ciphertext,
    verify_batched_grouped_validity_2, verify_batched_grouped_validity_3,
    verify_ciphertext_ciphertext_equality, verify_ciphertext_commitment_equality,
    verify_grouped_validity_2, verify_grouped_validity_3,
    verify_percentage_with_cap, verify_pubkey_validity, verify_zero_ciphertext,
    BATCHED_GROUPED_VALIDITY_2_PROOF_LEN, BATCHED_GROUPED_VALIDITY_3_PROOF_LEN,
    CIPHERTEXT_EQUALITY_PROOF_LEN, CTX_BATCHED_GROUPED_VALIDITY_2,
    CTX_BATCHED_GROUPED_VALIDITY_3, CTX_CIPHERTEXT_CIPHERTEXT_EQUALITY,
    CTX_CIPHERTEXT_COMMITMENT_EQUALITY, CTX_GROUPED_VALIDITY_2,
    CTX_GROUPED_VALIDITY_3, CTX_PERCENTAGE_WITH_CAP, CTX_PUBKEY_VALIDITY,
    CTX_ZERO_CIPHERTEXT, EQUALITY_PROOF_LEN,
    GROUPED_VALIDITY_2_PROOF_LEN, GROUPED_VALIDITY_3_PROOF_LEN,
    PERCENTAGE_WITH_CAP_PROOF_LEN, PUBKEY_VALIDITY_PROOF_LEN,
    ZERO_CIPHERTEXT_PROOF_LEN,
};
use crate::solana_zk::{
    ae_ciphertext_from_bytes, elgamal_ciphertext_from_bytes, elgamal_decrypt_u32,
    elgamal_encrypt_with, elgamal_pubkey_from_bytes, elgamal_pubkey_from_secret,
    prove_batched_range, prove_transfer, prove_transfer_with_fee,
    prove_withdraw, verify_batched_range, AE_CIPHERTEXT_LEN,
    ELGAMAL_CIPHERTEXT_LEN, ELGAMAL_PUBKEY_LEN, MAX_BATCH,
};

/// Success.
pub const BU_SOLANA_ZK_OK: i32 = 0;
/// Null pointer argument.
pub const BU_SOLANA_ZK_ERR_NULL: i32 = -1;
/// Bad length / buffer too small (required size written back).
pub const BU_SOLANA_ZK_ERR_LENGTH: i32 = -2;
/// Malformed encoding (reserved; curve failures use CRYPTO).
pub const BU_SOLANA_ZK_ERR_PARSE: i32 = -3;
/// Invalid point / curve decode failure.
pub const BU_SOLANA_ZK_ERR_CRYPTO: i32 = -4;
/// Internal error.
pub const BU_SOLANA_ZK_ERR_INTERNAL: i32 = -5;
/// Backend-internal error (unreachable in normal operation;
/// also returned when the native backend is absent on the caller side).
pub const BU_SOLANA_ZK_ERR_BACKEND: i32 = -6;

/// `emit_bytes` size-query helper (mirrors monero FFI).
fn emit_bytes(out: *mut u8, out_len: *mut usize, data: &[u8]) -> i32 {
    if out_len.is_null() {
        return BU_SOLANA_ZK_ERR_NULL;
    }
    unsafe {
        if out.is_null() || *out_len < data.len() {
            *out_len = data.len();
            return BU_SOLANA_ZK_ERR_LENGTH;
        }
        core::ptr::copy_nonoverlapping(data.as_ptr(), out, data.len());
        *out_len = data.len();
    }
    BU_SOLANA_ZK_OK
}

/// Map [`crate::solana_zk::SolanaZkError`] to C codes.
fn map_err(e: crate::solana_zk::SolanaZkError) -> i32 {
    match e {
        crate::solana_zk::SolanaZkError::InvalidLength => BU_SOLANA_ZK_ERR_LENGTH,
        crate::solana_zk::SolanaZkError::InvalidPoint => BU_SOLANA_ZK_ERR_CRYPTO,
        crate::solana_zk::SolanaZkError::InvalidProof => BU_SOLANA_ZK_ERR_PARSE,
        crate::solana_zk::SolanaZkError::BackendNotLinked => BU_SOLANA_ZK_ERR_BACKEND,
    }
}

/// Validate a 32-byte ElGamal pubkey. Returns OK or an error.
#[no_mangle]
/// # Safety
/// Pointer must be non-null and address 32 readable bytes.
pub unsafe extern "C" fn bu_solana_zk_validate_pubkey(
    ptr: *const u8,
) -> i32 {
    if ptr.is_null() {
        return BU_SOLANA_ZK_ERR_NULL;
    }
    let bytes = unsafe { core::slice::from_raw_parts(ptr, 32) };
    match elgamal_pubkey_from_bytes(bytes) {
        Ok(_) => BU_SOLANA_ZK_OK,
        Err(e) => map_err(e),
    }
}

/// Validate a 64-byte ElGamal ciphertext. Returns OK or error.
#[no_mangle]
/// # Safety
/// Pointer must be non-null and address 64 readable bytes.
pub unsafe extern "C" fn bu_solana_zk_validate_ciphertext(
    ptr: *const u8,
) -> i32 {
    if ptr.is_null() {
        return BU_SOLANA_ZK_ERR_NULL;
    }
    let bytes = unsafe { core::slice::from_raw_parts(ptr, 64) };
    match elgamal_ciphertext_from_bytes(bytes) {
        Ok(_) => BU_SOLANA_ZK_OK,
        Err(e) => map_err(e),
    }
}

/// Derive `P = s^{-1} * H` from a 32-byte secret into
/// 32-byte `out`. Returns OK or an error.
#[no_mangle]
/// # Safety
/// Both pointers must be non-null; `secret` addresses 32 readable bytes,
/// `out` 32 writable bytes.
pub unsafe extern "C" fn bu_solana_zk_pubkey_from_secret(
    secret: *const u8,
    out: *mut u8,
) -> i32 {
    if secret.is_null() || out.is_null() {
        return BU_SOLANA_ZK_ERR_NULL;
    }
    let mut s = [0u8; 32];
    unsafe {
        core::ptr::copy_nonoverlapping(secret, s.as_mut_ptr(), 32);
    }
    match elgamal_pubkey_from_secret(&s) {
        Ok(p) => {
            unsafe {
                core::ptr::copy_nonoverlapping(p.as_ptr(), out, 32);
            }
            BU_SOLANA_ZK_OK
        }
        Err(e) => map_err(e),
    }
}

/// Deterministic encrypt-with-opening: `pubkey` (32),
/// `amount` (u64 value), `opening` (32) into 64-byte `out`.
/// Returns OK or an error.
#[no_mangle]
/// # Safety
/// Pointers must be non-null; `pubkey`/`opening` address 32 readable bytes
/// each, `out` 64 writable bytes.
pub unsafe extern "C" fn bu_solana_zk_encrypt_with(
    pubkey: *const u8,
    amount: u64,
    opening: *const u8,
    out: *mut u8,
) -> i32 {
    if pubkey.is_null() || opening.is_null() || out.is_null() {
        return BU_SOLANA_ZK_ERR_NULL;
    }
    let mut p = [0u8; ELGAMAL_PUBKEY_LEN];
    let mut r = [0u8; 32];
    unsafe {
        core::ptr::copy_nonoverlapping(pubkey, p.as_mut_ptr(), ELGAMAL_PUBKEY_LEN);
        core::ptr::copy_nonoverlapping(opening, r.as_mut_ptr(), 32);
    }
    match elgamal_encrypt_with(&p, amount, &r) {
        Ok(ct) => {
            unsafe {
                core::ptr::copy_nonoverlapping(ct.as_ptr(), out, ELGAMAL_CIPHERTEXT_LEN);
            }
            BU_SOLANA_ZK_OK
        }
        Err(e) => map_err(e),
    }
}

/// Decrypt a 64-byte ciphertext with a 32-byte secret.
/// On success writes the u32-range amount to `out_amount` and returns OK;
/// returns INVALID (1) when well-formed but out of u32 range.
#[no_mangle]
/// # Safety
/// Pointers must be non-null; `secret` 32 readable bytes, `ciphertext` 64
/// readable bytes, `out_amount` one writable u64.
pub unsafe extern "C" fn bu_solana_zk_decrypt_u32(
    secret: *const u8,
    ciphertext: *const u8,
    out_amount: *mut u64,
) -> i32 {
    if secret.is_null() || ciphertext.is_null() || out_amount.is_null() {
        return BU_SOLANA_ZK_ERR_NULL;
    }
    let mut s = [0u8; 32];
    let mut ct = [0u8; ELGAMAL_CIPHERTEXT_LEN];
    unsafe {
        core::ptr::copy_nonoverlapping(secret, s.as_mut_ptr(), 32);
        core::ptr::copy_nonoverlapping(ciphertext, ct.as_mut_ptr(), ELGAMAL_CIPHERTEXT_LEN);
    }
    match elgamal_decrypt_u32(&s, &ct) {
        Ok(m) => {
            unsafe {
                *out_amount = m;
            }
            BU_SOLANA_ZK_OK
        }
        Err(crate::solana_zk::SolanaZkError::InvalidProof) => 1,
        Err(e) => map_err(e),
    }
}

/// Validate a 36-byte AES decryptable balance (length gate).
/// Returns OK or an error.
#[no_mangle]
/// # Safety
/// Pointer must be non-null and address 32 readable bytes.
pub unsafe extern "C" fn bu_solana_zk_validate_ae(ptr: *const u8) -> i32 {
    if ptr.is_null() {
        return BU_SOLANA_ZK_ERR_NULL;
    }
    let bytes = unsafe { core::slice::from_raw_parts(ptr, AE_CIPHERTEXT_LEN) };
    match ae_ciphertext_from_bytes(bytes) {
        Ok(_) => BU_SOLANA_ZK_OK,
        Err(e) => map_err(e),
    }
}

/// Prove pubkey-validity: `secret` (32) + `seed` (32) +
/// `context` (`ctx_len` bytes) into 64-byte `out`. Fully implemented.
#[no_mangle]
/// # Safety
/// Pointers must be non-null; `secret`/`seed` address 32 readable bytes,
/// `context` `ctx_len` readable bytes, `out` 64 writable bytes.
pub unsafe extern "C" fn bu_solana_zk_prove_pubkey_validity(
    secret: *const u8,
    seed32: *const u8,
    out: *mut u8,
) -> i32 {
    if secret.is_null() || seed32.is_null() || out.is_null() {
        return BU_SOLANA_ZK_ERR_NULL;
    }
    let mut s = [0u8; 32];
    let mut sd = [0u8; 32];
    unsafe {
        core::ptr::copy_nonoverlapping(secret, s.as_mut_ptr(), 32);
        core::ptr::copy_nonoverlapping(seed32, sd.as_mut_ptr(), 32);
    }
    match prove_pubkey_validity(&s, &sd, CTX_PUBKEY_VALIDITY) {
        Ok(proof) => {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    proof.as_ptr(),
                    out,
                    PUBKEY_VALIDITY_PROOF_LEN,
                );
            }
            BU_SOLANA_ZK_OK
        }
        Err(e) => map_err(e),
    }
}

/// Verify pubkey-validity: `pubkey` (32) + `proof` (64) +
/// `context`. Returns OK, INVALID (1) when well-formed but failed, or a
/// negative error code.
#[no_mangle]
/// # Safety
/// Pointers must be non-null with the documented readable lengths.
pub unsafe extern "C" fn bu_solana_zk_verify_pubkey_validity(
    pubkey: *const u8,
    proof: *const u8,
) -> i32 {
    if pubkey.is_null() || proof.is_null() {
        return BU_SOLANA_ZK_ERR_NULL;
    }
    let mut p = [0u8; ELGAMAL_PUBKEY_LEN];
    let mut pf = [0u8; PUBKEY_VALIDITY_PROOF_LEN];
    unsafe {
        core::ptr::copy_nonoverlapping(pubkey, p.as_mut_ptr(), ELGAMAL_PUBKEY_LEN);
        core::ptr::copy_nonoverlapping(
            proof,
            pf.as_mut_ptr(),
            PUBKEY_VALIDITY_PROOF_LEN,
        );
    }
    match verify_pubkey_validity(&p, &pf, CTX_PUBKEY_VALIDITY) {
        Ok(()) => BU_SOLANA_ZK_OK,
        Err(crate::solana_zk::sigma_proofs::SigmaError::AlgebraicRelation) => 1,
        Err(crate::solana_zk::sigma_proofs::SigmaError::IdentityPoint) => 1,
        Err(crate::solana_zk::sigma_proofs::SigmaError::Deserialization) => {
            BU_SOLANA_ZK_ERR_PARSE
        }
    }
}

/// Read a 32-byte seed (caller-supplied prover RNG).
fn read_seed(ptr: *const u8) -> Result<[u8; 32], i32> {
    if ptr.is_null() {
        return Err(BU_SOLANA_ZK_ERR_NULL);
    }
    let mut seed = [0u8; 32];
    unsafe {
        core::ptr::copy_nonoverlapping(ptr, seed.as_mut_ptr(), 32);
    }
    Ok(seed)
}

/// Prove batched range for `n` amounts (`amounts_le` =
/// `n * 8` LE bytes) with `n` 32-byte openings, under the exact on-chain
/// instruction transcript. Emits `proof || pod_commitments(256) ||
/// pod_bit_lengths(8)` via the `emit_bytes` size-query convention.
#[no_mangle]
/// # Safety
/// Pointers must be non-null and address readable/writable memory of at
/// least the documented lengths. Null pointers are rejected with an error
/// code; short buffers follow the size-query convention.
pub unsafe extern "C" fn bu_solana_zk_prove_batched_range(
    amounts_le: *const u8,
    openings: *const u8,
    n: usize,
    seed32: *const u8,
    out: *mut u8,
    out_len: *mut usize,
) -> i32 {
    if amounts_le.is_null() || openings.is_null() {
        return BU_SOLANA_ZK_ERR_NULL;
    }
    if n == 0 || n > MAX_BATCH {
        return BU_SOLANA_ZK_ERR_LENGTH;
    }
    let seed = match read_seed(seed32) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let a_bytes = unsafe { core::slice::from_raw_parts(amounts_le, n * 8) };
    let o_bytes = unsafe { core::slice::from_raw_parts(openings, n * 32) };
    let mut amounts = alloc::vec::Vec::with_capacity(n);
    for c in a_bytes.as_chunks::<8>().0 {
        let mut b = [0u8; 8];
        b.copy_from_slice(c);
        amounts.push(b);
    }
    let mut ops = alloc::vec::Vec::with_capacity(n);
    for c in o_bytes.as_chunks::<32>().0 {
        let mut b = [0u8; 32];
        b.copy_from_slice(c);
        ops.push(b);
    }
    match prove_batched_range(&amounts, &ops, &seed) {
        Ok((blob, pod_commitments, pod_bit_lengths)) => {
            let mut flat = alloc::vec::Vec::with_capacity(
                blob.len() + pod_commitments.len() + pod_bit_lengths.len(),
            );
            flat.extend_from_slice(&blob);
            flat.extend_from_slice(&pod_commitments);
            flat.extend_from_slice(&pod_bit_lengths);
            emit_bytes(out, out_len, &flat)
        }
        Err(e) => map_err(e),
    }
}

/// Verify a batched range proof: `proof` (`proof_len` bytes)
/// against `n` 32-byte commitments under the exact on-chain instruction
/// transcript (pod context rebuilt identically: zero-padded commitments, 64
/// per active bit length). Returns OK, INVALID (1) when well-formed but
/// failed, or a negative error code.
/// # Safety
/// Pointers must be non-null with the documented readable lengths.
#[no_mangle]
pub unsafe extern "C" fn bu_solana_zk_verify_batched_range(
    proof: *const u8,
    proof_len: usize,
    commitments: *const u8,
    n: usize,
) -> i32 {
    if proof.is_null() || commitments.is_null() {
        return BU_SOLANA_ZK_ERR_NULL;
    }
    if n == 0 || n > MAX_BATCH {
        return BU_SOLANA_ZK_ERR_LENGTH;
    }
    let pf = unsafe { core::slice::from_raw_parts(proof, proof_len) };
    let c_bytes = unsafe { core::slice::from_raw_parts(commitments, n * 32) };
    let mut pod_commitments = [0u8; 256];
    for (i, c) in c_bytes.as_chunks::<32>().0.iter().enumerate() {
        pod_commitments[i * 32..i * 32 + 32].copy_from_slice(c);
    }
    let mut pod_bit_lengths = [0u8; 8];
    for b in pod_bit_lengths.iter_mut().take(n) {
        *b = 64;
    }
    match verify_batched_range(pf, &pod_commitments, &pod_bit_lengths) {
        Ok(()) => BU_SOLANA_ZK_OK,
        Err(crate::solana_zk::SolanaZkError::InvalidProof) => 1,
        Err(e) => map_err(e),
    }
}

/// Prove withdraw bundle into a fixed 1256-byte `out`:
/// `equality(192) || range_proof(672) || pod_commitments(256) ||
/// pod_bit_lengths(8) || remaining_commitment(32) || remaining_opening(32) ||
/// remaining_ciphertext(64)`. All components under on-chain instruction
/// transcripts; fails when `withdraw_amount > current_balance`.
#[no_mangle]
/// # Safety
/// Pointers must be non-null with the documented readable lengths;
/// `out` addresses 1256 writable bytes.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn bu_solana_zk_prove_withdraw(
    source_secret: *const u8,
    source_pubkey: *const u8,
    current_ciphertext: *const u8,
    current_balance: u64,
    withdraw_amount: u64,
    seed32: *const u8,
    out: *mut u8,
) -> i32 {
    if source_secret.is_null()
        || source_pubkey.is_null()
        || current_ciphertext.is_null()
        || out.is_null()
    {
        return BU_SOLANA_ZK_ERR_NULL;
    }
    let mut ss = [0u8; 32];
    let mut sp = [0u8; ELGAMAL_PUBKEY_LEN];
    let mut cc = [0u8; ELGAMAL_CIPHERTEXT_LEN];
    unsafe {
        core::ptr::copy_nonoverlapping(source_secret, ss.as_mut_ptr(), 32);
        core::ptr::copy_nonoverlapping(source_pubkey, sp.as_mut_ptr(), ELGAMAL_PUBKEY_LEN);
        core::ptr::copy_nonoverlapping(
            current_ciphertext,
            cc.as_mut_ptr(),
            ELGAMAL_CIPHERTEXT_LEN,
        );
    }
    let seed = match read_seed(seed32) {
        Ok(s) => s,
        Err(e) => return e,
    };
    match prove_withdraw(&ss, &sp, &cc, current_balance, withdraw_amount, &seed) {
        Ok(b) => {
            let mut o = out;
            unsafe {
                o = emit(&b.equality_proof, o);
                o = emit(&b.range_proof, o);
                o = emit(&b.range_commitments, o);
                o = emit(&b.range_bit_lengths, o);
                o = emit(&b.remaining_commitment, o);
                o = emit(&b.remaining_opening, o);
                o = emit(&b.remaining_ciphertext, o);
                let _ = o;
            }
            BU_SOLANA_ZK_OK
        }
        Err(e) => map_err(e),
    }
}

/// Prove transfer bundle into a fixed 1896-byte `out`:
/// `equality(192) || validity3(192) || range_proof(736) ||
/// pod_commitments(256) || pod_bit_lengths(8) || grouped_lo(128) ||
/// grouped_hi(128) || remaining_commitment(32) || remaining_opening(32) ||
/// remaining_ciphertext(64) || auditor_lo(64) || auditor_hi(64)`.
/// `auditor_pubkey` may be 32 zero bytes (identity = no auditor).
#[no_mangle]
/// # Safety
/// Pointers must be non-null with the documented readable lengths;
/// `out` addresses 1896 writable bytes.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn bu_solana_zk_prove_transfer(
    source_secret: *const u8,
    source_pubkey: *const u8,
    dest_pubkey: *const u8,
    auditor_pubkey: *const u8,
    current_ciphertext: *const u8,
    current_balance: u64,
    transfer_amount: u64,
    seed32: *const u8,
    out: *mut u8,
) -> i32 {
    if source_secret.is_null()
        || source_pubkey.is_null()
        || dest_pubkey.is_null()
        || auditor_pubkey.is_null()
        || current_ciphertext.is_null()
        || out.is_null()
    {
        return BU_SOLANA_ZK_ERR_NULL;
    }
    let mut ss = [0u8; 32];
    let mut sp = [0u8; ELGAMAL_PUBKEY_LEN];
    let mut dp = [0u8; ELGAMAL_PUBKEY_LEN];
    let mut ap = [0u8; ELGAMAL_PUBKEY_LEN];
    let mut cc = [0u8; ELGAMAL_CIPHERTEXT_LEN];
    unsafe {
        core::ptr::copy_nonoverlapping(source_secret, ss.as_mut_ptr(), 32);
        core::ptr::copy_nonoverlapping(source_pubkey, sp.as_mut_ptr(), ELGAMAL_PUBKEY_LEN);
        core::ptr::copy_nonoverlapping(dest_pubkey, dp.as_mut_ptr(), ELGAMAL_PUBKEY_LEN);
        core::ptr::copy_nonoverlapping(auditor_pubkey, ap.as_mut_ptr(), ELGAMAL_PUBKEY_LEN);
        core::ptr::copy_nonoverlapping(
            current_ciphertext,
            cc.as_mut_ptr(),
            ELGAMAL_CIPHERTEXT_LEN,
        );
    }
    let seed = match read_seed(seed32) {
        Ok(s) => s,
        Err(e) => return e,
    };
    match prove_transfer(
        &ss, &sp, &dp, &ap, &cc, current_balance, transfer_amount, &seed,
    ) {
        Ok(b) => {
            unsafe {
                let mut o = out;
                o = emit(&b.equality_proof, o);
                o = emit(&b.validity_proof, o);
                o = emit(&b.range_proof, o);
                o = emit(&b.range_commitments, o);
                o = emit(&b.range_bit_lengths, o);
                o = emit(&b.grouped_lo, o);
                o = emit(&b.grouped_hi, o);
                o = emit(&b.remaining_commitment, o);
                o = emit(&b.remaining_opening, o);
                o = emit(&b.remaining_ciphertext, o);
                o = emit(&b.auditor_lo, o);
                o = emit(&b.auditor_hi, o);
                let _ = o;
            }
            BU_SOLANA_ZK_OK
        }
        Err(e) => map_err(e),
    }
}

/// Prove transfer-with-fee bundle into a fixed 2576-byte
/// `out`: `equality(192) || validity3(192) || percentage(256) ||
/// fee_validity2(160) || range_proof(800) || pod_commitments(256) ||
/// pod_bit_lengths(8) || transfer_lo(128) || transfer_hi(128) ||
/// fee_lo(96) || fee_hi(96) || remaining_commitment(32) ||
/// remaining_opening(32) || remaining_ciphertext(64) || fee_commitment(32) ||
/// delta_commitment(32) || claimed_commitment(32) || net_commitment(32) ||
/// max_fee(8 LE)`.
#[no_mangle]
/// # Safety
/// Pointers must be non-null with the documented readable lengths;
/// `out` addresses 2576 writable bytes.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn bu_solana_zk_prove_transfer_with_fee(
    source_secret: *const u8,
    source_pubkey: *const u8,
    dest_pubkey: *const u8,
    auditor_pubkey: *const u8,
    authority_pubkey: *const u8,
    current_ciphertext: *const u8,
    current_balance: u64,
    transfer_amount: u64,
    fee_rate_basis_points: u16,
    maximum_fee: u64,
    seed32: *const u8,
    out: *mut u8,
) -> i32 {
    if source_secret.is_null()
        || source_pubkey.is_null()
        || dest_pubkey.is_null()
        || auditor_pubkey.is_null()
        || authority_pubkey.is_null()
        || current_ciphertext.is_null()
        || out.is_null()
    {
        return BU_SOLANA_ZK_ERR_NULL;
    }
    let mut ss = [0u8; 32];
    let mut sp = [0u8; ELGAMAL_PUBKEY_LEN];
    let mut dp = [0u8; ELGAMAL_PUBKEY_LEN];
    let mut ap = [0u8; ELGAMAL_PUBKEY_LEN];
    let mut wp = [0u8; ELGAMAL_PUBKEY_LEN];
    let mut cc = [0u8; ELGAMAL_CIPHERTEXT_LEN];
    unsafe {
        core::ptr::copy_nonoverlapping(source_secret, ss.as_mut_ptr(), 32);
        core::ptr::copy_nonoverlapping(source_pubkey, sp.as_mut_ptr(), ELGAMAL_PUBKEY_LEN);
        core::ptr::copy_nonoverlapping(dest_pubkey, dp.as_mut_ptr(), ELGAMAL_PUBKEY_LEN);
        core::ptr::copy_nonoverlapping(auditor_pubkey, ap.as_mut_ptr(), ELGAMAL_PUBKEY_LEN);
        core::ptr::copy_nonoverlapping(authority_pubkey, wp.as_mut_ptr(), ELGAMAL_PUBKEY_LEN);
        core::ptr::copy_nonoverlapping(
            current_ciphertext,
            cc.as_mut_ptr(),
            ELGAMAL_CIPHERTEXT_LEN,
        );
    }
    let seed = match read_seed(seed32) {
        Ok(s) => s,
        Err(e) => return e,
    };
    match prove_transfer_with_fee(
        &ss, &sp, &dp, &ap, &wp, &cc, current_balance, transfer_amount,
        fee_rate_basis_points, maximum_fee, &seed,
    ) {
        Ok(b) => {
            unsafe {
                let mut o = out;
                o = emit(&b.equality_proof, o);
                o = emit(&b.validity_proof, o);
                o = emit(&b.percentage_proof, o);
                o = emit(&b.fee_validity_proof, o);
                o = emit(&b.range_proof, o);
                o = emit(&b.range_commitments, o);
                o = emit(&b.range_bit_lengths, o);
                o = emit(&b.grouped_lo, o);
                o = emit(&b.grouped_hi, o);
                o = emit(&b.fee_grouped_lo, o);
                o = emit(&b.fee_grouped_hi, o);
                o = emit(&b.remaining_commitment, o);
                o = emit(&b.remaining_opening, o);
                o = emit(&b.remaining_ciphertext, o);
                o = emit(&b.fee_commitment, o);
                o = emit(&b.delta_commitment, o);
                o = emit(&b.claimed_commitment, o);
                o = emit(&b.net_commitment, o);
                o = emit(&b.max_fee.to_le_bytes(), o);
                let _ = o;
            }
            BU_SOLANA_ZK_OK
        }
        Err(e) => map_err(e),
    }
}

/// Copy `src` to `dst`, returning the advanced pointer.
unsafe fn emit(src: &[u8], dst: *mut u8) -> *mut u8 {
    unsafe {
        core::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len());
        dst.add(src.len())
    }
}

/// Prove zero-ciphertext: `secret` (32) + `pubkey` (32) +
/// `ciphertext` (64) + `seed` (32) + `context` into 96-byte `out`.
#[no_mangle]
/// # Safety
/// Pointers must be non-null with the documented readable lengths;
/// `out` addresses 96 writable bytes.
pub unsafe extern "C" fn bu_solana_zk_prove_zero_ciphertext(
    secret: *const u8,
    pubkey: *const u8,
    ciphertext: *const u8,
    seed32: *const u8,
    out: *mut u8,
) -> i32 {
    if secret.is_null()
        || pubkey.is_null()
        || ciphertext.is_null()
        || out.is_null()
    {
        return BU_SOLANA_ZK_ERR_NULL;
    }
    let mut s = [0u8; 32];
    let mut p = [0u8; ELGAMAL_PUBKEY_LEN];
    let mut ct = [0u8; ELGAMAL_CIPHERTEXT_LEN];
    unsafe {
        core::ptr::copy_nonoverlapping(secret, s.as_mut_ptr(), 32);
        core::ptr::copy_nonoverlapping(pubkey, p.as_mut_ptr(), ELGAMAL_PUBKEY_LEN);
        core::ptr::copy_nonoverlapping(ciphertext, ct.as_mut_ptr(), ELGAMAL_CIPHERTEXT_LEN);
    }
    let seed = match read_seed(seed32) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match prove_zero_ciphertext(&s, &p, &ct, &seed, CTX_ZERO_CIPHERTEXT) {
        Ok(proof) => {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    proof.as_ptr(),
                    out,
                    ZERO_CIPHERTEXT_PROOF_LEN,
                );
            }
            BU_SOLANA_ZK_OK
        }
        Err(e) => map_err(e),
    }
}

/// Verify zero-ciphertext. Returns OK, INVALID (1) when
/// well-formed but failed, or a negative error code.
#[no_mangle]
/// # Safety
/// Pointers must be non-null with the documented readable lengths.
pub unsafe extern "C" fn bu_solana_zk_verify_zero_ciphertext(
    pubkey: *const u8,
    ciphertext: *const u8,
    proof: *const u8,
) -> i32 {
    if pubkey.is_null() || ciphertext.is_null() || proof.is_null() {
        return BU_SOLANA_ZK_ERR_NULL;
    }
    let mut p = [0u8; ELGAMAL_PUBKEY_LEN];
    let mut ct = [0u8; ELGAMAL_CIPHERTEXT_LEN];
    let mut pf = [0u8; ZERO_CIPHERTEXT_PROOF_LEN];
    unsafe {
        core::ptr::copy_nonoverlapping(pubkey, p.as_mut_ptr(), ELGAMAL_PUBKEY_LEN);
        core::ptr::copy_nonoverlapping(ciphertext, ct.as_mut_ptr(), ELGAMAL_CIPHERTEXT_LEN);
        core::ptr::copy_nonoverlapping(
            proof,
            pf.as_mut_ptr(),
            ZERO_CIPHERTEXT_PROOF_LEN,
        );
    }
    match verify_zero_ciphertext(&p, &ct, &pf, CTX_ZERO_CIPHERTEXT) {
        Ok(()) => BU_SOLANA_ZK_OK,
        Err(crate::solana_zk::sigma_proofs::SigmaError::AlgebraicRelation) => 1,
        Err(crate::solana_zk::sigma_proofs::SigmaError::IdentityPoint) => 1,
        Err(crate::solana_zk::sigma_proofs::SigmaError::Deserialization) => {
            BU_SOLANA_ZK_ERR_PARSE
        }
    }
}

/// Prove ciphertext-commitment equality: `secret` (32) +
/// `pubkey` (32) + `ciphertext` (64) + `commitment` (32) + `opening` (32) +
/// `amount` (u64) + `seed` (32) + `context` into 192-byte `out`.
#[no_mangle]
/// # Safety
/// Pointers must be non-null with the documented readable lengths;
/// `out` addresses 192 writable bytes.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn bu_solana_zk_prove_equality(
    secret: *const u8,
    pubkey: *const u8,
    ciphertext: *const u8,
    commitment: *const u8,
    opening: *const u8,
    amount: u64,
    seed32: *const u8,
    out: *mut u8,
) -> i32 {
    if secret.is_null()
        || pubkey.is_null()
        || ciphertext.is_null()
        || commitment.is_null()
        || opening.is_null()
        || out.is_null()
    {
        return BU_SOLANA_ZK_ERR_NULL;
    }
    let mut s = [0u8; 32];
    let mut p = [0u8; ELGAMAL_PUBKEY_LEN];
    let mut ct = [0u8; ELGAMAL_CIPHERTEXT_LEN];
    let mut cm = [0u8; 32];
    let mut r = [0u8; 32];
    unsafe {
        core::ptr::copy_nonoverlapping(secret, s.as_mut_ptr(), 32);
        core::ptr::copy_nonoverlapping(pubkey, p.as_mut_ptr(), ELGAMAL_PUBKEY_LEN);
        core::ptr::copy_nonoverlapping(ciphertext, ct.as_mut_ptr(), ELGAMAL_CIPHERTEXT_LEN);
        core::ptr::copy_nonoverlapping(commitment, cm.as_mut_ptr(), 32);
        core::ptr::copy_nonoverlapping(opening, r.as_mut_ptr(), 32);
    }
    let seed = match read_seed(seed32) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match prove_ciphertext_commitment_equality(&s, &p, &ct, &cm, &r, amount, &seed, CTX_CIPHERTEXT_COMMITMENT_EQUALITY) {
        Ok(proof) => {
            unsafe {
                core::ptr::copy_nonoverlapping(proof.as_ptr(), out, EQUALITY_PROOF_LEN);
            }
            BU_SOLANA_ZK_OK
        }
        Err(e) => map_err(e),
    }
}

/// Verify ciphertext-commitment equality. Returns OK,
/// INVALID (1) when well-formed but failed, or a negative error code.
#[no_mangle]
/// # Safety
/// Pointers must be non-null with the documented readable lengths.
pub unsafe extern "C" fn bu_solana_zk_verify_equality(
    pubkey: *const u8,
    ciphertext: *const u8,
    commitment: *const u8,
    proof: *const u8,
) -> i32 {
    if pubkey.is_null()
        || ciphertext.is_null()
        || commitment.is_null()
        || proof.is_null()
    {
        return BU_SOLANA_ZK_ERR_NULL;
    }
    let mut p = [0u8; ELGAMAL_PUBKEY_LEN];
    let mut ct = [0u8; ELGAMAL_CIPHERTEXT_LEN];
    let mut cm = [0u8; 32];
    let mut pf = [0u8; EQUALITY_PROOF_LEN];
    unsafe {
        core::ptr::copy_nonoverlapping(pubkey, p.as_mut_ptr(), ELGAMAL_PUBKEY_LEN);
        core::ptr::copy_nonoverlapping(ciphertext, ct.as_mut_ptr(), ELGAMAL_CIPHERTEXT_LEN);
        core::ptr::copy_nonoverlapping(commitment, cm.as_mut_ptr(), 32);
        core::ptr::copy_nonoverlapping(proof, pf.as_mut_ptr(), EQUALITY_PROOF_LEN);
    }
    match verify_ciphertext_commitment_equality(&p, &ct, &cm, &pf, CTX_CIPHERTEXT_COMMITMENT_EQUALITY) {
        Ok(()) => BU_SOLANA_ZK_OK,
        Err(crate::solana_zk::sigma_proofs::SigmaError::AlgebraicRelation) => 1,
        Err(crate::solana_zk::sigma_proofs::SigmaError::IdentityPoint) => 1,
        Err(crate::solana_zk::sigma_proofs::SigmaError::Deserialization) => {
            BU_SOLANA_ZK_ERR_PARSE
        }
    }
}

/// Prove ciphertext-ciphertext equality (transfer validity core).
/// `first_secret` (32) + `first_pubkey` (32) + `second_pubkey` (32) +
/// `first_ciphertext` (64) + `second_ciphertext` (64) + `second_opening` (32) +
/// `amount` (u64) + `seed` (32) + `context` into 224-byte `out`.
#[no_mangle]
/// # Safety
/// Pointers must be non-null with the documented readable lengths;
/// `out` addresses 224 writable bytes.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn bu_solana_zk_prove_ciphertext_equality(
    first_secret: *const u8,
    first_pubkey: *const u8,
    second_pubkey: *const u8,
    first_ciphertext: *const u8,
    second_ciphertext: *const u8,
    second_opening: *const u8,
    amount: u64,
    seed32: *const u8,
    out: *mut u8,
) -> i32 {
    if first_secret.is_null()
        || first_pubkey.is_null()
        || second_pubkey.is_null()
        || first_ciphertext.is_null()
        || second_ciphertext.is_null()
        || second_opening.is_null()
        || out.is_null()
    {
        return BU_SOLANA_ZK_ERR_NULL;
    }
    let mut fs = [0u8; 32];
    let mut p1 = [0u8; ELGAMAL_PUBKEY_LEN];
    let mut p2 = [0u8; ELGAMAL_PUBKEY_LEN];
    let mut c1 = [0u8; ELGAMAL_CIPHERTEXT_LEN];
    let mut c2 = [0u8; ELGAMAL_CIPHERTEXT_LEN];
    let mut r = [0u8; 32];
    unsafe {
        core::ptr::copy_nonoverlapping(first_secret, fs.as_mut_ptr(), 32);
        core::ptr::copy_nonoverlapping(first_pubkey, p1.as_mut_ptr(), ELGAMAL_PUBKEY_LEN);
        core::ptr::copy_nonoverlapping(second_pubkey, p2.as_mut_ptr(), ELGAMAL_PUBKEY_LEN);
        core::ptr::copy_nonoverlapping(first_ciphertext, c1.as_mut_ptr(), ELGAMAL_CIPHERTEXT_LEN);
        core::ptr::copy_nonoverlapping(second_ciphertext, c2.as_mut_ptr(), ELGAMAL_CIPHERTEXT_LEN);
        core::ptr::copy_nonoverlapping(second_opening, r.as_mut_ptr(), 32);
    }
    let seed = match read_seed(seed32) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match prove_ciphertext_ciphertext_equality(
        &fs, &p1, &p2, &c1, &c2, &r, amount, &seed, CTX_CIPHERTEXT_CIPHERTEXT_EQUALITY,
    ) {
        Ok(proof) => {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    proof.as_ptr(),
                    out,
                    CIPHERTEXT_EQUALITY_PROOF_LEN,
                );
            }
            BU_SOLANA_ZK_OK
        }
        Err(e) => map_err(e),
    }
}

/// Verify ciphertext-ciphertext equality. Returns OK,
/// INVALID (1) when well-formed but failed, or a negative error code.
#[no_mangle]
/// # Safety
/// Pointers must be non-null with the documented readable lengths.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn bu_solana_zk_verify_ciphertext_equality(
    first_pubkey: *const u8,
    second_pubkey: *const u8,
    first_ciphertext: *const u8,
    second_ciphertext: *const u8,
    proof: *const u8,
) -> i32 {
    if first_pubkey.is_null()
        || second_pubkey.is_null()
        || first_ciphertext.is_null()
        || second_ciphertext.is_null()
        || proof.is_null()
    {
        return BU_SOLANA_ZK_ERR_NULL;
    }
    let mut p1 = [0u8; ELGAMAL_PUBKEY_LEN];
    let mut p2 = [0u8; ELGAMAL_PUBKEY_LEN];
    let mut c1 = [0u8; ELGAMAL_CIPHERTEXT_LEN];
    let mut c2 = [0u8; ELGAMAL_CIPHERTEXT_LEN];
    let mut pf = [0u8; CIPHERTEXT_EQUALITY_PROOF_LEN];
    unsafe {
        core::ptr::copy_nonoverlapping(first_pubkey, p1.as_mut_ptr(), ELGAMAL_PUBKEY_LEN);
        core::ptr::copy_nonoverlapping(second_pubkey, p2.as_mut_ptr(), ELGAMAL_PUBKEY_LEN);
        core::ptr::copy_nonoverlapping(first_ciphertext, c1.as_mut_ptr(), ELGAMAL_CIPHERTEXT_LEN);
        core::ptr::copy_nonoverlapping(second_ciphertext, c2.as_mut_ptr(), ELGAMAL_CIPHERTEXT_LEN);
        core::ptr::copy_nonoverlapping(
            proof,
            pf.as_mut_ptr(),
            CIPHERTEXT_EQUALITY_PROOF_LEN,
        );
    }
    match verify_ciphertext_ciphertext_equality(&p1, &p2, &c1, &c2, &pf, CTX_CIPHERTEXT_CIPHERTEXT_EQUALITY) {
        Ok(()) => BU_SOLANA_ZK_OK,
        Err(crate::solana_zk::sigma_proofs::SigmaError::AlgebraicRelation) => 1,
        Err(crate::solana_zk::sigma_proofs::SigmaError::IdentityPoint) => 1,
        Err(crate::solana_zk::sigma_proofs::SigmaError::Deserialization) => {
            BU_SOLANA_ZK_ERR_PARSE
        }
    }
}

/// Prove 2-handle grouped validity: `first_pubkey` (32) +
/// `second_pubkey` (32) + `grouped` (96) + `amount` + `opening` (32) +
/// `seed` (32) + `context` into 160-byte `out`.
#[no_mangle]
/// # Safety
/// Pointers must be non-null with the documented readable lengths;
/// `out` addresses 160 writable bytes.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn bu_solana_zk_prove_grouped_validity_2(
    first_pubkey: *const u8,
    second_pubkey: *const u8,
    grouped: *const u8,
    amount: u64,
    opening: *const u8,
    seed32: *const u8,
    out: *mut u8,
) -> i32 {
    if first_pubkey.is_null()
        || second_pubkey.is_null()
        || grouped.is_null()
        || opening.is_null()
        || out.is_null()
    {
        return BU_SOLANA_ZK_ERR_NULL;
    }
    let mut p1 = [0u8; ELGAMAL_PUBKEY_LEN];
    let mut p2 = [0u8; ELGAMAL_PUBKEY_LEN];
    let mut g = [0u8; 96];
    let mut r = [0u8; 32];
    unsafe {
        core::ptr::copy_nonoverlapping(first_pubkey, p1.as_mut_ptr(), ELGAMAL_PUBKEY_LEN);
        core::ptr::copy_nonoverlapping(second_pubkey, p2.as_mut_ptr(), ELGAMAL_PUBKEY_LEN);
        core::ptr::copy_nonoverlapping(grouped, g.as_mut_ptr(), 96);
        core::ptr::copy_nonoverlapping(opening, r.as_mut_ptr(), 32);
    }
    let seed = match read_seed(seed32) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match prove_grouped_validity_2(&p1, &p2, &g, amount, &r, &seed, CTX_GROUPED_VALIDITY_2) {
        Ok(proof) => {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    proof.as_ptr(),
                    out,
                    GROUPED_VALIDITY_2_PROOF_LEN,
                );
            }
            BU_SOLANA_ZK_OK
        }
        Err(e) => map_err(e),
    }
}

/// Verify 2-handle grouped validity. Returns OK, INVALID (1)
/// when well-formed but failed, or a negative error code.
#[no_mangle]
/// # Safety
/// Pointers must be non-null with the documented readable lengths.
pub unsafe extern "C" fn bu_solana_zk_verify_grouped_validity_2(
    first_pubkey: *const u8,
    second_pubkey: *const u8,
    grouped: *const u8,
    proof: *const u8,
) -> i32 {
    if first_pubkey.is_null()
        || second_pubkey.is_null()
        || grouped.is_null()
        || proof.is_null()
    {
        return BU_SOLANA_ZK_ERR_NULL;
    }
    let mut p1 = [0u8; ELGAMAL_PUBKEY_LEN];
    let mut p2 = [0u8; ELGAMAL_PUBKEY_LEN];
    let mut g = [0u8; 96];
    let mut pf = [0u8; GROUPED_VALIDITY_2_PROOF_LEN];
    unsafe {
        core::ptr::copy_nonoverlapping(first_pubkey, p1.as_mut_ptr(), ELGAMAL_PUBKEY_LEN);
        core::ptr::copy_nonoverlapping(second_pubkey, p2.as_mut_ptr(), ELGAMAL_PUBKEY_LEN);
        core::ptr::copy_nonoverlapping(grouped, g.as_mut_ptr(), 96);
        core::ptr::copy_nonoverlapping(
            proof,
            pf.as_mut_ptr(),
            GROUPED_VALIDITY_2_PROOF_LEN,
        );
    }
    match verify_grouped_validity_2(&p1, &p2, &g, &pf, CTX_GROUPED_VALIDITY_2) {
        Ok(()) => BU_SOLANA_ZK_OK,
        Err(crate::solana_zk::sigma_proofs::SigmaError::AlgebraicRelation) => 1,
        Err(crate::solana_zk::sigma_proofs::SigmaError::IdentityPoint) => 1,
        Err(crate::solana_zk::sigma_proofs::SigmaError::Deserialization) => {
            BU_SOLANA_ZK_ERR_PARSE
        }
    }
}

/// Prove 3-handle grouped validity into 192-byte `out`.
#[no_mangle]
/// # Safety
/// Pointers must be non-null with the documented readable lengths;
/// `out` addresses 192 writable bytes.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn bu_solana_zk_prove_grouped_validity_3(
    first_pubkey: *const u8,
    second_pubkey: *const u8,
    third_pubkey: *const u8,
    grouped: *const u8,
    amount: u64,
    opening: *const u8,
    seed32: *const u8,
    out: *mut u8,
) -> i32 {
    if first_pubkey.is_null()
        || second_pubkey.is_null()
        || third_pubkey.is_null()
        || grouped.is_null()
        || opening.is_null()
        || out.is_null()
    {
        return BU_SOLANA_ZK_ERR_NULL;
    }
    let mut p1 = [0u8; ELGAMAL_PUBKEY_LEN];
    let mut p2 = [0u8; ELGAMAL_PUBKEY_LEN];
    let mut p3 = [0u8; ELGAMAL_PUBKEY_LEN];
    let mut g = [0u8; 128];
    let mut r = [0u8; 32];
    unsafe {
        core::ptr::copy_nonoverlapping(first_pubkey, p1.as_mut_ptr(), ELGAMAL_PUBKEY_LEN);
        core::ptr::copy_nonoverlapping(second_pubkey, p2.as_mut_ptr(), ELGAMAL_PUBKEY_LEN);
        core::ptr::copy_nonoverlapping(third_pubkey, p3.as_mut_ptr(), ELGAMAL_PUBKEY_LEN);
        core::ptr::copy_nonoverlapping(grouped, g.as_mut_ptr(), 128);
        core::ptr::copy_nonoverlapping(opening, r.as_mut_ptr(), 32);
    }
    let seed = match read_seed(seed32) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match prove_grouped_validity_3(&p1, &p2, &p3, &g, amount, &r, &seed, CTX_GROUPED_VALIDITY_3) {
        Ok(proof) => {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    proof.as_ptr(),
                    out,
                    GROUPED_VALIDITY_3_PROOF_LEN,
                );
            }
            BU_SOLANA_ZK_OK
        }
        Err(e) => map_err(e),
    }
}

/// Verify 3-handle grouped validity. Returns OK, INVALID (1)
/// when well-formed but failed, or a negative error code.
#[no_mangle]
/// # Safety
/// Pointers must be non-null with the documented readable lengths.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn bu_solana_zk_verify_grouped_validity_3(
    first_pubkey: *const u8,
    second_pubkey: *const u8,
    third_pubkey: *const u8,
    grouped: *const u8,
    proof: *const u8,
) -> i32 {
    if first_pubkey.is_null()
        || second_pubkey.is_null()
        || third_pubkey.is_null()
        || grouped.is_null()
        || proof.is_null()
    {
        return BU_SOLANA_ZK_ERR_NULL;
    }
    let mut p1 = [0u8; ELGAMAL_PUBKEY_LEN];
    let mut p2 = [0u8; ELGAMAL_PUBKEY_LEN];
    let mut p3 = [0u8; ELGAMAL_PUBKEY_LEN];
    let mut g = [0u8; 128];
    let mut pf = [0u8; GROUPED_VALIDITY_3_PROOF_LEN];
    unsafe {
        core::ptr::copy_nonoverlapping(first_pubkey, p1.as_mut_ptr(), ELGAMAL_PUBKEY_LEN);
        core::ptr::copy_nonoverlapping(second_pubkey, p2.as_mut_ptr(), ELGAMAL_PUBKEY_LEN);
        core::ptr::copy_nonoverlapping(third_pubkey, p3.as_mut_ptr(), ELGAMAL_PUBKEY_LEN);
        core::ptr::copy_nonoverlapping(grouped, g.as_mut_ptr(), 128);
        core::ptr::copy_nonoverlapping(
            proof,
            pf.as_mut_ptr(),
            GROUPED_VALIDITY_3_PROOF_LEN,
        );
    }
    match verify_grouped_validity_3(&p1, &p2, &p3, &g, &pf, CTX_GROUPED_VALIDITY_3) {
        Ok(()) => BU_SOLANA_ZK_OK,
        Err(crate::solana_zk::sigma_proofs::SigmaError::AlgebraicRelation) => 1,
        Err(crate::solana_zk::sigma_proofs::SigmaError::IdentityPoint) => 1,
        Err(crate::solana_zk::sigma_proofs::SigmaError::Deserialization) => {
            BU_SOLANA_ZK_ERR_PARSE
        }
    }
}

/// Prove percentage-with-cap (256 bytes): three Pedersen
/// commitments (32 each) + openings (32 each) + amounts + max + seed + context.
#[no_mangle]
/// # Safety
/// Pointers must be non-null with the documented readable lengths;
/// `out` addresses 256 writable bytes.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn bu_solana_zk_prove_percentage_with_cap(
    percentage_commitment: *const u8,
    percentage_opening: *const u8,
    percentage_amount: u64,
    delta_commitment: *const u8,
    delta_opening: *const u8,
    delta_amount: u64,
    claimed_commitment: *const u8,
    claimed_opening: *const u8,
    max_value: u64,
    seed32: *const u8,
    out: *mut u8,
) -> i32 {
    if percentage_commitment.is_null()
        || percentage_opening.is_null()
        || delta_commitment.is_null()
        || delta_opening.is_null()
        || claimed_commitment.is_null()
        || claimed_opening.is_null()
        || out.is_null()
    {
        return BU_SOLANA_ZK_ERR_NULL;
    }
    let mut pc = [0u8; 32];
    let mut po = [0u8; 32];
    let mut dc = [0u8; 32];
    let mut dopen = [0u8; 32];
    let mut cc = [0u8; 32];
    let mut co = [0u8; 32];
    unsafe {
        core::ptr::copy_nonoverlapping(percentage_commitment, pc.as_mut_ptr(), 32);
        core::ptr::copy_nonoverlapping(percentage_opening, po.as_mut_ptr(), 32);
        core::ptr::copy_nonoverlapping(delta_commitment, dc.as_mut_ptr(), 32);
        core::ptr::copy_nonoverlapping(delta_opening, dopen.as_mut_ptr(), 32);
        core::ptr::copy_nonoverlapping(claimed_commitment, cc.as_mut_ptr(), 32);
        core::ptr::copy_nonoverlapping(claimed_opening, co.as_mut_ptr(), 32);
    }
    let seed = match read_seed(seed32) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match prove_percentage_with_cap(
        &pc, &po, percentage_amount, &dc, &dopen, delta_amount, &cc, &co,
        max_value, &seed, CTX_PERCENTAGE_WITH_CAP,
    ) {
        Ok(proof) => {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    proof.as_ptr(),
                    out,
                    PERCENTAGE_WITH_CAP_PROOF_LEN,
                );
            }
            BU_SOLANA_ZK_OK
        }
        Err(e) => map_err(e),
    }
}

/// Verify percentage-with-cap. Returns OK, INVALID (1) when
/// well-formed but failed, or a negative error code.
#[no_mangle]
/// # Safety
/// Pointers must be non-null with the documented readable lengths.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn bu_solana_zk_verify_percentage_with_cap(
    percentage_commitment: *const u8,
    delta_commitment: *const u8,
    claimed_commitment: *const u8,
    max_value: u64,
    proof: *const u8,
) -> i32 {
    if percentage_commitment.is_null()
        || delta_commitment.is_null()
        || claimed_commitment.is_null()
        || proof.is_null()
    {
        return BU_SOLANA_ZK_ERR_NULL;
    }
    let mut pc = [0u8; 32];
    let mut dc = [0u8; 32];
    let mut cc = [0u8; 32];
    let mut pf = [0u8; PERCENTAGE_WITH_CAP_PROOF_LEN];
    unsafe {
        core::ptr::copy_nonoverlapping(percentage_commitment, pc.as_mut_ptr(), 32);
        core::ptr::copy_nonoverlapping(delta_commitment, dc.as_mut_ptr(), 32);
        core::ptr::copy_nonoverlapping(claimed_commitment, cc.as_mut_ptr(), 32);
        core::ptr::copy_nonoverlapping(
            proof,
            pf.as_mut_ptr(),
            PERCENTAGE_WITH_CAP_PROOF_LEN,
        );
    }
    match verify_percentage_with_cap(&pc, &dc, &cc, max_value, &pf, CTX_PERCENTAGE_WITH_CAP) {
        Ok(()) => BU_SOLANA_ZK_OK,
        Err(crate::solana_zk::sigma_proofs::SigmaError::AlgebraicRelation) => 1,
        Err(crate::solana_zk::sigma_proofs::SigmaError::IdentityPoint) => 1,
        Err(crate::solana_zk::sigma_proofs::SigmaError::Deserialization) => {
            BU_SOLANA_ZK_ERR_PARSE
        }
    }
}

/// Prove batched 2-handle grouped validity into 160-byte `out`.
#[no_mangle]
/// # Safety
/// Pointers must be non-null with the documented readable lengths;
/// `out` addresses 160 writable bytes.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn bu_solana_zk_prove_batched_grouped_validity_2(
    first_pubkey: *const u8,
    second_pubkey: *const u8,
    grouped_lo: *const u8,
    grouped_hi: *const u8,
    amount_lo: u64,
    amount_hi: u64,
    opening_lo: *const u8,
    opening_hi: *const u8,
    seed32: *const u8,
    out: *mut u8,
) -> i32 {
    if first_pubkey.is_null()
        || second_pubkey.is_null()
        || grouped_lo.is_null()
        || grouped_hi.is_null()
        || opening_lo.is_null()
        || opening_hi.is_null()
        || out.is_null()
    {
        return BU_SOLANA_ZK_ERR_NULL;
    }
    let mut p1 = [0u8; ELGAMAL_PUBKEY_LEN];
    let mut p2 = [0u8; ELGAMAL_PUBKEY_LEN];
    let mut lo = [0u8; 96];
    let mut hi = [0u8; 96];
    let mut rol = [0u8; 32];
    let mut roh = [0u8; 32];
    unsafe {
        core::ptr::copy_nonoverlapping(first_pubkey, p1.as_mut_ptr(), ELGAMAL_PUBKEY_LEN);
        core::ptr::copy_nonoverlapping(second_pubkey, p2.as_mut_ptr(), ELGAMAL_PUBKEY_LEN);
        core::ptr::copy_nonoverlapping(grouped_lo, lo.as_mut_ptr(), 96);
        core::ptr::copy_nonoverlapping(grouped_hi, hi.as_mut_ptr(), 96);
        core::ptr::copy_nonoverlapping(opening_lo, rol.as_mut_ptr(), 32);
        core::ptr::copy_nonoverlapping(opening_hi, roh.as_mut_ptr(), 32);
    }
    let seed = match read_seed(seed32) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match prove_batched_grouped_validity_2(
        &p1, &p2, &lo, &hi, amount_lo, amount_hi, &rol, &roh, &seed, CTX_BATCHED_GROUPED_VALIDITY_2,
    ) {
        Ok(proof) => {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    proof.as_ptr(),
                    out,
                    BATCHED_GROUPED_VALIDITY_2_PROOF_LEN,
                );
            }
            BU_SOLANA_ZK_OK
        }
        Err(e) => map_err(e),
    }
}

/// Verify batched 2-handle grouped validity. Returns OK,
/// INVALID (1) when well-formed but failed, or a negative error code.
#[no_mangle]
/// # Safety
/// Pointers must be non-null with the documented readable lengths.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn bu_solana_zk_verify_batched_grouped_validity_2(
    first_pubkey: *const u8,
    second_pubkey: *const u8,
    grouped_lo: *const u8,
    grouped_hi: *const u8,
    proof: *const u8,
) -> i32 {
    if first_pubkey.is_null()
        || second_pubkey.is_null()
        || grouped_lo.is_null()
        || grouped_hi.is_null()
        || proof.is_null()
    {
        return BU_SOLANA_ZK_ERR_NULL;
    }
    let mut p1 = [0u8; ELGAMAL_PUBKEY_LEN];
    let mut p2 = [0u8; ELGAMAL_PUBKEY_LEN];
    let mut lo = [0u8; 96];
    let mut hi = [0u8; 96];
    let mut pf = [0u8; BATCHED_GROUPED_VALIDITY_2_PROOF_LEN];
    unsafe {
        core::ptr::copy_nonoverlapping(first_pubkey, p1.as_mut_ptr(), ELGAMAL_PUBKEY_LEN);
        core::ptr::copy_nonoverlapping(second_pubkey, p2.as_mut_ptr(), ELGAMAL_PUBKEY_LEN);
        core::ptr::copy_nonoverlapping(grouped_lo, lo.as_mut_ptr(), 96);
        core::ptr::copy_nonoverlapping(grouped_hi, hi.as_mut_ptr(), 96);
        core::ptr::copy_nonoverlapping(
            proof,
            pf.as_mut_ptr(),
            BATCHED_GROUPED_VALIDITY_2_PROOF_LEN,
        );
    }
    match verify_batched_grouped_validity_2(&p1, &p2, &lo, &hi, &pf, CTX_BATCHED_GROUPED_VALIDITY_2) {
        Ok(()) => BU_SOLANA_ZK_OK,
        Err(crate::solana_zk::sigma_proofs::SigmaError::AlgebraicRelation) => 1,
        Err(crate::solana_zk::sigma_proofs::SigmaError::IdentityPoint) => 1,
        Err(crate::solana_zk::sigma_proofs::SigmaError::Deserialization) => {
            BU_SOLANA_ZK_ERR_PARSE
        }
    }
}

/// Prove batched 3-handle grouped validity into 192-byte `out`.
#[no_mangle]
/// # Safety
/// Pointers must be non-null with the documented readable lengths;
/// `out` addresses 192 writable bytes.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn bu_solana_zk_prove_batched_grouped_validity_3(
    first_pubkey: *const u8,
    second_pubkey: *const u8,
    third_pubkey: *const u8,
    grouped_lo: *const u8,
    grouped_hi: *const u8,
    amount_lo: u64,
    amount_hi: u64,
    opening_lo: *const u8,
    opening_hi: *const u8,
    seed32: *const u8,
    out: *mut u8,
) -> i32 {
    if first_pubkey.is_null()
        || second_pubkey.is_null()
        || third_pubkey.is_null()
        || grouped_lo.is_null()
        || grouped_hi.is_null()
        || opening_lo.is_null()
        || opening_hi.is_null()
        || out.is_null()
    {
        return BU_SOLANA_ZK_ERR_NULL;
    }
    let mut p1 = [0u8; ELGAMAL_PUBKEY_LEN];
    let mut p2 = [0u8; ELGAMAL_PUBKEY_LEN];
    let mut p3 = [0u8; ELGAMAL_PUBKEY_LEN];
    let mut lo = [0u8; 128];
    let mut hi = [0u8; 128];
    let mut rol = [0u8; 32];
    let mut roh = [0u8; 32];
    unsafe {
        core::ptr::copy_nonoverlapping(first_pubkey, p1.as_mut_ptr(), ELGAMAL_PUBKEY_LEN);
        core::ptr::copy_nonoverlapping(second_pubkey, p2.as_mut_ptr(), ELGAMAL_PUBKEY_LEN);
        core::ptr::copy_nonoverlapping(third_pubkey, p3.as_mut_ptr(), ELGAMAL_PUBKEY_LEN);
        core::ptr::copy_nonoverlapping(grouped_lo, lo.as_mut_ptr(), 128);
        core::ptr::copy_nonoverlapping(grouped_hi, hi.as_mut_ptr(), 128);
        core::ptr::copy_nonoverlapping(opening_lo, rol.as_mut_ptr(), 32);
        core::ptr::copy_nonoverlapping(opening_hi, roh.as_mut_ptr(), 32);
    }
    let seed = match read_seed(seed32) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match prove_batched_grouped_validity_3(
        &p1, &p2, &p3, &lo, &hi, amount_lo, amount_hi, &rol, &roh, &seed, CTX_BATCHED_GROUPED_VALIDITY_3,
    ) {
        Ok(proof) => {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    proof.as_ptr(),
                    out,
                    BATCHED_GROUPED_VALIDITY_3_PROOF_LEN,
                );
            }
            BU_SOLANA_ZK_OK
        }
        Err(e) => map_err(e),
    }
}

/// Verify batched 3-handle grouped validity. Returns OK,
/// INVALID (1) when well-formed but failed, or a negative error code.
#[no_mangle]
/// # Safety
/// Pointers must be non-null with the documented readable lengths.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn bu_solana_zk_verify_batched_grouped_validity_3(
    first_pubkey: *const u8,
    second_pubkey: *const u8,
    third_pubkey: *const u8,
    grouped_lo: *const u8,
    grouped_hi: *const u8,
    proof: *const u8,
) -> i32 {
    if first_pubkey.is_null()
        || second_pubkey.is_null()
        || third_pubkey.is_null()
        || grouped_lo.is_null()
        || grouped_hi.is_null()
        || proof.is_null()
    {
        return BU_SOLANA_ZK_ERR_NULL;
    }
    let mut p1 = [0u8; ELGAMAL_PUBKEY_LEN];
    let mut p2 = [0u8; ELGAMAL_PUBKEY_LEN];
    let mut p3 = [0u8; ELGAMAL_PUBKEY_LEN];
    let mut lo = [0u8; 128];
    let mut hi = [0u8; 128];
    let mut pf = [0u8; BATCHED_GROUPED_VALIDITY_3_PROOF_LEN];
    unsafe {
        core::ptr::copy_nonoverlapping(first_pubkey, p1.as_mut_ptr(), ELGAMAL_PUBKEY_LEN);
        core::ptr::copy_nonoverlapping(second_pubkey, p2.as_mut_ptr(), ELGAMAL_PUBKEY_LEN);
        core::ptr::copy_nonoverlapping(third_pubkey, p3.as_mut_ptr(), ELGAMAL_PUBKEY_LEN);
        core::ptr::copy_nonoverlapping(grouped_lo, lo.as_mut_ptr(), 128);
        core::ptr::copy_nonoverlapping(grouped_hi, hi.as_mut_ptr(), 128);
        core::ptr::copy_nonoverlapping(
            proof,
            pf.as_mut_ptr(),
            BATCHED_GROUPED_VALIDITY_3_PROOF_LEN,
        );
    }
    match verify_batched_grouped_validity_3(&p1, &p2, &p3, &lo, &hi, &pf, CTX_BATCHED_GROUPED_VALIDITY_3) {
        Ok(()) => BU_SOLANA_ZK_OK,
        Err(crate::solana_zk::sigma_proofs::SigmaError::AlgebraicRelation) => 1,
        Err(crate::solana_zk::sigma_proofs::SigmaError::IdentityPoint) => 1,
        Err(crate::solana_zk::sigma_proofs::SigmaError::Deserialization) => {
            BU_SOLANA_ZK_ERR_PARSE
        }
    }
}

/// AES-GCM-SIV encrypt a u64 balance with a 16-byte key and
/// caller 12-byte nonce into 36-byte `out` (nonce || ct || tag).
/// # Safety
/// Pointers must be non-null with the documented readable lengths;
/// `out` addresses 36 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn bu_solana_zk_ae_encrypt(
    key16: *const u8,
    amount: u64,
    nonce12: *const u8,
    out: *mut u8,
) -> i32 {
    if key16.is_null() || nonce12.is_null() || out.is_null() {
        return BU_SOLANA_ZK_ERR_NULL;
    }
    let mut k = [0u8; 16];
    let mut n = [0u8; 12];
    unsafe {
        core::ptr::copy_nonoverlapping(key16, k.as_mut_ptr(), 16);
        core::ptr::copy_nonoverlapping(nonce12, n.as_mut_ptr(), 12);
    }
    match crate::solana_zk::aead_gcm_siv::ae_encrypt(&k, amount, &n) {
        Ok(ct) => {
            unsafe {
                core::ptr::copy_nonoverlapping(ct.as_ptr(), out, 36);
            }
            BU_SOLANA_ZK_OK
        }
        Err(e) => map_err(e),
    }
}

/// AES-GCM-SIV decrypt a 36-byte balance with a 16-byte key
/// into u64 `out_amount`. Returns INVALID (1) when authentication fails.
/// # Safety
/// Pointers must be non-null; `ae` addresses 36 readable bytes,
/// `out_amount` one writable u64.
#[no_mangle]
pub unsafe extern "C" fn bu_solana_zk_ae_decrypt(
    key16: *const u8,
    ae: *const u8,
    out_amount: *mut u64,
) -> i32 {
    if key16.is_null() || ae.is_null() || out_amount.is_null() {
        return BU_SOLANA_ZK_ERR_NULL;
    }
    let mut k = [0u8; 16];
    let mut c = [0u8; 36];
    unsafe {
        core::ptr::copy_nonoverlapping(key16, k.as_mut_ptr(), 16);
        core::ptr::copy_nonoverlapping(ae, c.as_mut_ptr(), 36);
    }
    match crate::solana_zk::aead_gcm_siv::ae_decrypt(&k, &c) {
        Ok(amount) => {
            unsafe {
                *out_amount = amount;
            }
            BU_SOLANA_ZK_OK
        }
        Err(crate::solana_zk::SolanaZkError::InvalidProof) => 1,
        Err(e) => map_err(e),
    }
}
