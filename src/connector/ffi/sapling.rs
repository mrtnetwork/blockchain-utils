//! Sapling Groth16 C ABI: params handles + prove / verify
//! (features `ffi` + `groth16-prover`).
//!
//! Four operations (+ handle free):
//! - `bu_sapling_set_spend_params` / `bu_sapling_set_output_params`:
//!   load ceremony `ZcashParameters` bytes into an opaque handle
//! - `bu_sapling_prove(handle, kind, witness, ...)`: prove under the handle
//! - `bu_sapling_verify(handle, kind, proof, inputs)`: verify under the handle
//!
//! `kind`: 0 = Spend, 1 = Output (else `BU_G16_ERR_INPUTS`).
//!
//! Packed witness blobs (little-endian):
//! ```text
//! spend (1288B): value_u64 | randomness[32] | ak[32] | nsk[32] | g_d[32]
//!   | commitment_randomness[32] | ar[32] | auth_path[32][32] | pos[32]
//!   (bytes 0/1) | anchor[32]
//! output (168B): value_u64 | randomness[32] | g_d[32] | pk_d[32]
//!   | commitment_randomness[32] | esk[32]
//! ```
//! Prove writes proof (192B) and public inputs (7/5×32B) to caller buffers
//! (length-query pattern: `*len` = capacity in, required size on LENGTH).
//! Verify takes proof (192B) + positional public inputs (7/5×32B LE limbs;
//! Spend order `rk_u,rk_v,cv_u,cv_v,anchor,nf_lo,nf_hi`, Output order
//! `cv_u,cv_v,epk_u,epk_v,cm_u`).
//!
//! Prove randomness comes from the crate global RNG (seed via `bu_rng_seed`).

#![cfg(all(
    feature = "ffi",
    any(feature = "zcash-sapling", feature = "groth16-prover")
))]

use crate::zk::groth16::ZcashParameters;
use crate::zk::sapling::load_parameters;
use crate::zk::{
    build_output_witness, build_spend_witness, prove_output_with_params, prove_spend_with_params,
    SaplingOutputBytes, SaplingSpendBytes, GROTH_PROOF_SIZE, KIND_OUTPUT, KIND_SPEND,
    MAX_AUTH_PATH, MAX_OUTPUT_VERIFY_INPUTS, MAX_SPEND_VERIFY_INPUTS, OUTPUT_WITNESS_PACKED_LEN,
    SPEND_WITNESS_PACKED_LEN,
};
use alloc::boxed::Box;
use alloc::vec::Vec;

pub const BU_SAPLING_OK: i32 = 0;
pub const BU_SAPLING_ERR_NULL: i32 = 1;
pub const BU_SAPLING_ERR_LENGTH: i32 = 2;
pub const BU_SAPLING_ERR_PARSE: i32 = 3;
pub const BU_SAPLING_ERR_PROVE: i32 = 4;
pub const BU_SAPLING_ERR_VERIFY: i32 = 5;
pub const BU_SAPLING_ERR_INTERNAL: i32 = 6;
pub const BU_SAPLING_ERR_KIND: i32 = 7;

/// Packed spend witness size.
pub const BU_SAPLING_SPEND_INPUT_LEN: usize = SPEND_WITNESS_PACKED_LEN;
/// Packed output witness size.
pub const BU_SAPLING_OUTPUT_INPUT_LEN: usize = OUTPUT_WITNESS_PACKED_LEN;

/// Opaque loaded-params handle (spend or output ceremony parameters).
pub struct BuSaplingParams {
    inner: ZcashParameters,
    is_spend: bool,
}

fn load_handle(bytes: &[u8], is_spend: bool, out: *mut *mut BuSaplingParams) -> i32 {
    if out.is_null() {
        return BU_SAPLING_ERR_NULL;
    }
    match load_parameters(bytes, false) {
        Ok(params) => {
            let boxed = Box::new(BuSaplingParams {
                inner: params,
                is_spend,
            });
            unsafe {
                *out = Box::into_raw(boxed);
            }
            BU_SAPLING_OK
        }
        Err(_) => BU_SAPLING_ERR_PARSE,
    }
}

/// Load Sapling Spend ceremony parameters (`sapling-spend.params` bytes).
/// Caller must `bu_sapling_params_free`.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_sapling_set_spend_params(
    params: *const u8,
    params_len: usize,
    out_handle: *mut *mut BuSaplingParams,
) -> i32 {
    if params.is_null() && params_len > 0 {
        return BU_SAPLING_ERR_NULL;
    }
    let bytes = core::slice::from_raw_parts(params, params_len);
    load_handle(bytes, true, out_handle)
}

/// Load Sapling Output ceremony parameters (`sapling-output.params` bytes).
/// Caller must `bu_sapling_params_free`.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_sapling_set_output_params(
    params: *const u8,
    params_len: usize,
    out_handle: *mut *mut BuSaplingParams,
) -> i32 {
    if params.is_null() && params_len > 0 {
        return BU_SAPLING_ERR_NULL;
    }
    let bytes = core::slice::from_raw_parts(params, params_len);
    load_handle(bytes, false, out_handle)
}

#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_sapling_params_free(handle: *mut BuSaplingParams) {
    if !handle.is_null() {
        drop(Box::from_raw(handle));
    }
}

fn take32(buf: &[u8], o: &mut usize) -> Option<[u8; 32]> {
    if *o + 32 > buf.len() {
        return None;
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&buf[*o..*o + 32]);
    *o += 32;
    Some(a)
}

fn parse_spend_witness(buf: &[u8]) -> Option<SaplingSpendBytes> {
    if buf.len() < BU_SAPLING_SPEND_INPUT_LEN {
        return None;
    }
    let mut o = 0usize;
    let mut v8 = [0u8; 8];
    v8.copy_from_slice(&buf[o..o + 8]);
    let value = u64::from_le_bytes(v8);
    o += 8;
    let randomness = take32(buf, &mut o)?;
    let ak = take32(buf, &mut o)?;
    let nsk = take32(buf, &mut o)?;
    let payment_address_diversify_hash = take32(buf, &mut o)?;
    let commitment_randomness = take32(buf, &mut o)?;
    let ar = take32(buf, &mut o)?;
    let mut auth_path = [[0u8; 32]; MAX_AUTH_PATH];
    for slot in auth_path.iter_mut().take(MAX_AUTH_PATH) {
        *slot = take32(buf, &mut o)?;
    }
    if o + MAX_AUTH_PATH > buf.len() {
        return None;
    }
    let mut auth_path_pos = [false; MAX_AUTH_PATH];
    for slot in auth_path_pos.iter_mut().take(MAX_AUTH_PATH) {
        match buf[o] {
            0 => *slot = false,
            1 => *slot = true,
            _ => return None,
        }
        o += 1;
    }
    let anchor = take32(buf, &mut o)?;
    Some(SaplingSpendBytes {
        value,
        randomness,
        ak,
        nsk,
        payment_address_diversify_hash,
        commitment_randomness,
        ar,
        auth_path,
        auth_path_pos,
        anchor,
    })
}

fn parse_output_witness(buf: &[u8]) -> Option<SaplingOutputBytes> {
    if buf.len() < BU_SAPLING_OUTPUT_INPUT_LEN {
        return None;
    }
    let mut o = 0usize;
    let mut v8 = [0u8; 8];
    v8.copy_from_slice(&buf[o..o + 8]);
    let value = u64::from_le_bytes(v8);
    o += 8;
    let randomness = take32(buf, &mut o)?;
    let recipient_address_diversify_hash = take32(buf, &mut o)?;
    let recipient_address_pk_d = take32(buf, &mut o)?;
    let commitment_randomness = take32(buf, &mut o)?;
    let esk = take32(buf, &mut o)?;
    Some(SaplingOutputBytes {
        value,
        randomness,
        recipient_address_diversify_hash,
        recipient_address_pk_d,
        commitment_randomness,
        esk,
    })
}

fn emit_bytes(out: *mut u8, out_len: *mut usize, data: &[u8]) -> i32 {
    if out_len.is_null() {
        return BU_SAPLING_ERR_NULL;
    }
    unsafe {
        if out.is_null() || *out_len < data.len() {
            *out_len = data.len();
            return BU_SAPLING_ERR_LENGTH;
        }
        core::ptr::copy_nonoverlapping(data.as_ptr(), out, data.len());
        *out_len = data.len();
    }
    BU_SAPLING_OK
}

/// Prove under a loaded params handle.
///
/// - `kind`: 0 = Spend (witness `BU_SAPLING_SPEND_INPUT_LEN` bytes),
///   1 = Output (witness `BU_SAPLING_OUTPUT_INPUT_LEN` bytes)
/// - Writes 192-byte proof to `out_proof` and positional public inputs
///   (7/5×32B) to `out_inputs` (length-query pattern on both).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_sapling_prove(
    handle: *const BuSaplingParams,
    kind: u32,
    witness: *const u8,
    witness_len: usize,
    out_proof: *mut u8,
    out_proof_len: *mut usize,
    out_inputs: *mut u8,
    out_inputs_len: *mut usize,
) -> i32 {
    if handle.is_null() || witness.is_null() {
        return BU_SAPLING_ERR_NULL;
    }
    let params = &(*handle).inner;
    let buf = core::slice::from_raw_parts(witness, witness_len);
    match kind {
        KIND_SPEND_U32 => {
            if !(*handle).is_spend {
                return BU_SAPLING_ERR_KIND;
            }
            let w = match parse_spend_witness(buf) {
                Some(w) => w,
                None => return BU_SAPLING_ERR_PARSE,
            };
            let full = match build_spend_witness(&w) {
                Ok(w) => w,
                Err(_) => return BU_SAPLING_ERR_PARSE,
            };
            let (out, _) = match prove_spend_with_params(params, &full) {
                Ok(r) => r,
                Err(_) => return BU_SAPLING_ERR_PROVE,
            };
            let mut flat = Vec::with_capacity(out.public_inputs.len() * 32);
            for s in &out.public_inputs {
                let mut b = [0u8; 32];
                s.to_bytes_le(&mut b);
                flat.extend_from_slice(&b);
            }
            let rc = emit_bytes(out_proof, out_proof_len, &out.proof);
            if rc != BU_SAPLING_OK {
                return rc;
            }
            emit_bytes(out_inputs, out_inputs_len, &flat)
        }
        KIND_OUTPUT_U32 => {
            if (*handle).is_spend {
                return BU_SAPLING_ERR_KIND;
            }
            let w = match parse_output_witness(buf) {
                Some(w) => w,
                None => return BU_SAPLING_ERR_PARSE,
            };
            let full = build_output_witness(&w);
            let (out, _) = match prove_output_with_params(params, &full) {
                Ok(r) => r,
                Err(_) => return BU_SAPLING_ERR_PROVE,
            };
            let mut flat = Vec::with_capacity(out.public_inputs.len() * 32);
            for s in &out.public_inputs {
                let mut b = [0u8; 32];
                s.to_bytes_le(&mut b);
                flat.extend_from_slice(&b);
            }
            let rc = emit_bytes(out_proof, out_proof_len, &out.proof);
            if rc != BU_SAPLING_OK {
                return rc;
            }
            emit_bytes(out_inputs, out_inputs_len, &flat)
        }
        _ => BU_SAPLING_ERR_KIND,
    }
}

/// Verify under a loaded params handle.
///
/// - `kind`: 0 = Spend (inputs 7×32B), 1 = Output (inputs 5×32B)
/// - `proof`: 192 bytes; `inputs`: positional LE limbs.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_sapling_verify(
    handle: *const BuSaplingParams,
    kind: u32,
    proof: *const u8,
    proof_len: usize,
    inputs: *const u8,
    inputs_len: usize,
) -> i32 {
    if handle.is_null() || proof.is_null() {
        return BU_SAPLING_ERR_NULL;
    }
    if proof_len != GROTH_PROOF_SIZE {
        return BU_SAPLING_ERR_LENGTH;
    }
    let proof_sl = core::slice::from_raw_parts(proof, proof_len);
    let mut proof_arr = [0u8; GROTH_PROOF_SIZE];
    proof_arr.copy_from_slice(proof_sl);
    let params = &(*handle).inner;
    match kind {
        KIND_SPEND_U32 => {
            if !(*handle).is_spend || inputs_len != MAX_SPEND_VERIFY_INPUTS * 32 {
                return if (*handle).is_spend {
                    BU_SAPLING_ERR_LENGTH
                } else {
                    BU_SAPLING_ERR_KIND
                };
            }
            if inputs.is_null() {
                return BU_SAPLING_ERR_NULL;
            }
            let ib = core::slice::from_raw_parts(inputs, inputs_len);
            let mut limbs = [[0u8; 32]; MAX_SPEND_VERIFY_INPUTS];
            for (i, limb) in limbs.iter_mut().enumerate() {
                limb.copy_from_slice(&ib[i * 32..(i + 1) * 32]);
            }
            match crate::zk::parse_input_scalars(&limbs) {
                Ok(scalars) => {
                    match crate::zk::verify_spend_with_params(params, &proof_arr, &scalars) {
                        Ok(()) => BU_SAPLING_OK,
                        Err(_) => BU_SAPLING_ERR_VERIFY,
                    }
                }
                Err(_) => BU_SAPLING_ERR_PARSE,
            }
        }
        KIND_OUTPUT_U32 => {
            if (*handle).is_spend || inputs_len != MAX_OUTPUT_VERIFY_INPUTS * 32 {
                return if (*handle).is_spend {
                    BU_SAPLING_ERR_KIND
                } else {
                    BU_SAPLING_ERR_LENGTH
                };
            }
            if inputs.is_null() {
                return BU_SAPLING_ERR_NULL;
            }
            let ib = core::slice::from_raw_parts(inputs, inputs_len);
            let mut limbs = [[0u8; 32]; MAX_OUTPUT_VERIFY_INPUTS];
            for (i, limb) in limbs.iter_mut().enumerate() {
                limb.copy_from_slice(&ib[i * 32..(i + 1) * 32]);
            }
            match crate::zk::parse_input_scalars(&limbs) {
                Ok(scalars) => {
                    match crate::zk::verify_output_with_params(params, &proof_arr, &scalars) {
                        Ok(()) => BU_SAPLING_OK,
                        Err(_) => BU_SAPLING_ERR_VERIFY,
                    }
                }
                Err(_) => BU_SAPLING_ERR_PARSE,
            }
        }
        _ => BU_SAPLING_ERR_KIND,
    }
}

const KIND_SPEND_U32: u32 = KIND_SPEND as u32;
const KIND_OUTPUT_U32: u32 = KIND_OUTPUT as u32;

/// Presence probe: 1 if `handle` is a live params handle, else 0.
/// (Legacy `has_spend_params`/`has_output_params` equivalent for handles.)
fn has_handle(handle: *const BuSaplingParams) -> i32 {
    if handle.is_null() {
        BU_SAPLING_ERR_NULL
    } else {
        // Touch the handle validity only (no deref of params needed).
        unsafe {
            let _ = (*handle).is_spend;
        }
        BU_SAPLING_OK
    }
}

/// Returns 1 in `out` when the spend params handle is live.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_sapling_has_spend_params(
    handle: *const BuSaplingParams,
    out_live: *mut u32,
) -> i32 {
    if out_live.is_null() {
        return BU_SAPLING_ERR_NULL;
    }
    let rc = has_handle(handle);
    if rc != BU_SAPLING_OK {
        return rc;
    }
    *out_live = u32::from((*handle).is_spend);
    BU_SAPLING_OK
}

/// Returns 1 in `out` when the output params handle is live.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_sapling_has_output_params(
    handle: *const BuSaplingParams,
    out_live: *mut u32,
) -> i32 {
    if out_live.is_null() {
        return BU_SAPLING_ERR_NULL;
    }
    let rc = has_handle(handle);
    if rc != BU_SAPLING_OK {
        return rc;
    }
    *out_live = u32::from(!(*handle).is_spend);
    BU_SAPLING_OK
}

/// Jubjub Pedersen hash over `bits_len` packed LSB-first bits.
/// `has_personalization`: 0 → NoteCommitment domain, else MerkleTree layer
/// `layer` (must be < 64). Output: 32-byte compressed point.
/// Matches legacy `PedersenHash` semantics.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_sapling_pedersen_hash(
    bits: *const u8,
    bits_len: usize,
    has_personalization: u32,
    layer: u8,
    out: *mut u8,
) -> i32 {
    use crate::hash::pedersen::{PedersenHash, Personalization};
    if bits.is_null() && bits_len > 0 {
        return BU_SAPLING_ERR_NULL;
    }
    if out.is_null() {
        return BU_SAPLING_ERR_NULL;
    }
    let bytes = core::slice::from_raw_parts(bits, bits_len);
    let pers = match has_personalization {
        0 => Personalization::NoteCommitment,
        _ => {
            if layer > 63 {
                return BU_SAPLING_ERR_PARSE;
            }
            Personalization::MerkleTree { layer }
        }
    };
    let mut bools = Vec::with_capacity(bits_len.saturating_mul(8));
    for b in bytes {
        for i in 0..8 {
            bools.push(((b >> i) & 1) == 1);
        }
    }
    let point = PedersenHash::hash_cached(pers, &bools);
    // Serialize via affine coordinates (matches zcash compressed form).
    let mut enc = [0u8; 32];
    let (u, v) = match point.affine_uv() {
        Ok(uv) => uv,
        Err(_) => return BU_SAPLING_ERR_INTERNAL,
    };
    let mut ube = [0u8; 32];
    let mut vbe = [0u8; 32];
    u.to_bytes_be(&mut ube);
    v.to_bytes_be(&mut vbe);
    // Compressed: v LE with u-sign in high bit of last byte.
    for i in 0..32 {
        enc[i] = vbe[31 - i];
    }
    if ube[31] & 1 == 1 {
        enc[31] |= 0x80;
    }
    core::ptr::copy_nonoverlapping(enc.as_ptr(), out, 32);
    BU_SAPLING_OK
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zk::{SaplingOutputBytes, SaplingSpendBytes};

    #[test]
    fn packed_lengths() {
        assert_eq!(BU_SAPLING_SPEND_INPUT_LEN, 8 + 32 * 6 + 32 * 32 + 32 + 32);
        assert_eq!(BU_SAPLING_OUTPUT_INPUT_LEN, 8 + 32 * 5);
        assert_eq!(GROTH_PROOF_SIZE, 192);
    }

    #[test]
    fn parse_rejects_short_and_bad_pos() {
        assert!(parse_spend_witness(&[0u8; 100]).is_none());
        assert!(parse_output_witness(&[0u8; 100]).is_none());
        let mut good = alloc::vec![0u8; BU_SAPLING_SPEND_INPUT_LEN];
        // pos byte 2 (invalid) at offset 8+192+1024 = 1224
        good[1224] = 2;
        assert!(parse_spend_witness(&good).is_none());
        for i in 0..MAX_AUTH_PATH {
            good[1224 + i] = 1;
        }
        let w = parse_spend_witness(&good).expect("parse");
        assert_eq!(w.value, 0);
        assert!(w.auth_path_pos.iter().all(|&b| b));
        let o =
            parse_output_witness(&alloc::vec![0u8; BU_SAPLING_OUTPUT_INPUT_LEN]).expect("parse");
        assert_eq!(o.value, 0);
        let _: SaplingOutputBytes = o;
        let _: SaplingSpendBytes = w;
    }

    #[test]
    fn kind_and_handle_validation() {
        unsafe {
            // Null handle.
            assert_eq!(
                bu_sapling_prove(
                    core::ptr::null(),
                    0,
                    core::ptr::null(),
                    0,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                ),
                BU_SAPLING_ERR_NULL
            );
            assert_eq!(
                bu_sapling_verify(
                    core::ptr::null(),
                    0,
                    core::ptr::null(),
                    0,
                    core::ptr::null(),
                    0,
                ),
                BU_SAPLING_ERR_NULL
            );
            // Bad params bytes.
            let mut h: *mut BuSaplingParams = core::ptr::null_mut();
            assert_eq!(
                bu_sapling_set_spend_params([0u8; 16].as_ptr(), 16, &mut h),
                BU_SAPLING_ERR_PARSE
            );
            assert!(h.is_null());
            bu_sapling_params_free(core::ptr::null_mut());
        }
    }
}
