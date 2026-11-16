//! Solana confidential-transfer ZK WASM exports (`BuWasm.solanaZk*`).
//!
//! /// Same semantics as the C ABI
//! (`connector::ffi::solana_zk`): validation is real; ElGamal, all Sigma
//! proofs, range proofs, bundles and AES-GCM-SIV are fully implemented.

#![cfg(feature = "wasm")]

use wasm_bindgen::prelude::*;

use crate::solana_zk::sigma_proofs::{
    prove_batched_grouped_validity_2, prove_batched_grouped_validity_3,
    prove_ciphertext_ciphertext_equality, prove_ciphertext_commitment_equality,
    prove_grouped_validity_2, prove_grouped_validity_3, prove_percentage_with_cap,
    prove_pubkey_validity, prove_zero_ciphertext,
    verify_batched_grouped_validity_2, verify_batched_grouped_validity_3,
    verify_ciphertext_ciphertext_equality, verify_ciphertext_commitment_equality,
    verify_grouped_validity_2, verify_grouped_validity_3,
    verify_percentage_with_cap, verify_pubkey_validity, verify_zero_ciphertext,
    CTX_BATCHED_GROUPED_VALIDITY_2, CTX_BATCHED_GROUPED_VALIDITY_3,
    CTX_CIPHERTEXT_CIPHERTEXT_EQUALITY, CTX_CIPHERTEXT_COMMITMENT_EQUALITY,
    CTX_GROUPED_VALIDITY_2, CTX_GROUPED_VALIDITY_3, CTX_PERCENTAGE_WITH_CAP,
    CTX_PUBKEY_VALIDITY, CTX_ZERO_CIPHERTEXT,
};
use crate::solana_zk::{
    elgamal_ciphertext_from_bytes, elgamal_decrypt_u32, elgamal_encrypt_with,
    elgamal_pubkey_from_bytes, elgamal_pubkey_from_secret, prove_batched_range,
    prove_transfer, prove_transfer_with_fee, prove_withdraw, MAX_BATCH,
};

/// Copy helper (keeps the monero WASM style).
fn u8_vec(a: &[u8]) -> Vec<u8> {
    a.to_vec()
}

/// Read an exact 32-byte seed.
fn read32(v: &[u8]) -> Result<[u8; 32], JsValue> {
    if v.len() != 32 {
        return Err(JsValue::from_str("need 32 bytes"));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(v);
    Ok(out)
}

/// Validate a 32-byte ElGamal pubkey. Returns true iff valid.
#[wasm_bindgen(js_name = solanaZkValidatePubkey)]
pub fn solana_zk_validate_pubkey(bytes: &[u8]) -> Result<bool, JsValue> {
    Ok(elgamal_pubkey_from_bytes(&u8_vec(bytes)).is_ok())
}

/// Validate a 64-byte ElGamal ciphertext. True iff valid.
#[wasm_bindgen(js_name = solanaZkValidateCiphertext)]
pub fn solana_zk_validate_ciphertext(bytes: &[u8]) -> Result<bool, JsValue> {
    Ok(elgamal_ciphertext_from_bytes(&u8_vec(bytes)).is_ok())
}

/// Validate a 36-byte AES decryptable balance (length gate + parse).
/// Mirrors FFI `bu_solana_zk_validate_ae`.
#[wasm_bindgen(js_name = solanaZkValidateAe)]
pub fn solana_zk_validate_ae(bytes: &[u8]) -> Result<bool, JsValue> {
    Ok(crate::solana_zk::ae_ciphertext_from_bytes(&u8_vec(bytes)).is_ok())
}

/// Derive `P = s^{-1} * H` from a 32-byte secret.
#[wasm_bindgen(js_name = solanaZkPubkeyFromSecret)]
pub fn solana_zk_pubkey_from_secret(secret: &[u8]) -> Result<Vec<u8>, JsValue> {
    let s = u8_vec(secret);
    if s.len() != 32 {
        return Err(JsValue::from_str("need 32 bytes"));
    }
    let mut fixed = [0u8; 32];
    fixed.copy_from_slice(&s);
    elgamal_pubkey_from_secret(&fixed)
        .map(|p| p.to_vec())
        .map_err(|_| JsValue::from_str("invalid secret"))
}

/// Deterministic encrypt-with-opening; returns 64 bytes.
#[wasm_bindgen(js_name = solanaZkEncryptWith)]
pub fn solana_zk_encrypt_with(
    pubkey: &[u8],
    amount: f64,
    opening: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let p = u8_vec(pubkey);
    let r = u8_vec(opening);
    if p.len() != 32 || r.len() != 32 {
        return Err(JsValue::from_str("need 32 bytes"));
    }
    let mut pf = [0u8; 32];
    let mut rf = [0u8; 32];
    pf.copy_from_slice(&p);
    rf.copy_from_slice(&r);
    let amount = amount as u64;
    elgamal_encrypt_with(&pf, amount, &rf)
        .map(|ct| ct.to_vec())
        .map_err(|_| JsValue::from_str("encrypt"))
}

/// Decrypt a 64-byte ciphertext; returns the u32-range amount.
#[wasm_bindgen(js_name = solanaZkDecryptU32)]
pub fn solana_zk_decrypt_u32(
    secret: &[u8],
    ciphertext: &[u8],
) -> Result<f64, JsValue> {
    let s = u8_vec(secret);
    let c = u8_vec(ciphertext);
    if s.len() != 32 || c.len() != 64 {
        return Err(JsValue::from_str("bad lengths"));
    }
    let mut sf = [0u8; 32];
    let mut cf = [0u8; 64];
    sf.copy_from_slice(&s);
    cf.copy_from_slice(&c);
    elgamal_decrypt_u32(&sf, &cf)
        .map(|v| v as f64)
        .map_err(|_| JsValue::from_str("decrypt"))
}

/// Prove batched range (`amounts` = n x 8 LE bytes,
/// `openings` = n x 32 bytes, `seed` = 32 bytes) under the on-chain
/// instruction transcript. Returns `proof || pod_commitments(256) ||
/// pod_bit_lengths(8)`; proof length is a pure function of `n`.
#[wasm_bindgen(js_name = solanaZkProveBatchedRange)]
pub fn solana_zk_prove_batched_range(
    amounts: &[u8],
    openings: &[u8],
    seed: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let a = u8_vec(amounts);
    let o = u8_vec(openings);
    if a.is_empty() || a.len() % 8 != 0 || a.len() / 8 > MAX_BATCH {
        return Err(JsValue::from_str("bad amounts"));
    }
    let n = a.len() / 8;
    if o.len() != n * 32 {
        return Err(JsValue::from_str("bad openings"));
    }
    let mut amounts_le = Vec::with_capacity(n);
    for c in a.chunks_exact(8) {
        let mut b = [0u8; 8];
        b.copy_from_slice(c);
        amounts_le.push(b);
    }
    let mut ops = Vec::with_capacity(n);
    for c in o.chunks_exact(32) {
        let mut b = [0u8; 32];
        b.copy_from_slice(c);
        ops.push(b);
    }
    prove_batched_range(&amounts_le, &ops, &read32(&u8_vec(seed))?)
        .map(|(blob, pod_c, pod_b)| {
            let mut flat = Vec::with_capacity(blob.len() + 264);
            flat.extend_from_slice(&blob);
            flat.extend_from_slice(&pod_c);
            flat.extend_from_slice(&pod_b);
            flat
        })
        .map_err(|_| JsValue::from_str("backend"))
}

/// Prove withdraw bundle (1256-byte fixed layout, see FFI docs).
#[wasm_bindgen(js_name = solanaZkProveWithdraw)]
#[allow(clippy::too_many_arguments)]
pub fn solana_zk_prove_withdraw(
    source_secret: &[u8],
    source_pubkey: &[u8],
    current_ciphertext: &[u8],
    current_balance: f64,
    withdraw_amount: f64,
    seed: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let ss = u8_vec(source_secret);
    let sp = u8_vec(source_pubkey);
    let cc = u8_vec(current_ciphertext);
    if ss.len() != 32 || sp.len() != 32 || cc.len() != 64 {
        return Err(JsValue::from_str("bad lengths"));
    }
    let mut ssf = [0u8; 32];
    let mut spf = [0u8; 32];
    let mut ccf = [0u8; 64];
    ssf.copy_from_slice(&ss);    let current_balance = current_balance as u64;
    let withdraw_amount = withdraw_amount as u64;

    spf.copy_from_slice(&sp);
    ccf.copy_from_slice(&cc);
    let b = prove_withdraw(
        &ssf, &spf, &ccf, current_balance, withdraw_amount,
        &read32(&u8_vec(seed))?,
    )
    .map_err(|_| JsValue::from_str("prove"))?;
    let mut flat = Vec::with_capacity(1256);
    flat.extend_from_slice(&b.equality_proof);
    flat.extend_from_slice(&b.range_proof);
    flat.extend_from_slice(&b.range_commitments);
    flat.extend_from_slice(&b.range_bit_lengths);
    flat.extend_from_slice(&b.remaining_commitment);
    flat.extend_from_slice(&b.remaining_opening);
    flat.extend_from_slice(&b.remaining_ciphertext);
    Ok(flat)
}

/// Prove transfer bundle (1896-byte fixed layout, see FFI docs).
#[wasm_bindgen(js_name = solanaZkProveTransfer)]
#[allow(clippy::too_many_arguments)]
pub fn solana_zk_prove_transfer(
    source_secret: &[u8],
    source_pubkey: &[u8],
    dest_pubkey: &[u8],
    auditor_pubkey: &[u8],
    current_ciphertext: &[u8],
    current_balance: f64,
    transfer_amount: f64,
    seed: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let vs: Vec<Vec<u8>> = [source_secret, source_pubkey, dest_pubkey, auditor_pubkey, current_ciphertext]
        .iter().map(|v| u8_vec(v)).collect();
    for (v, n) in vs.iter().zip([32, 32, 32, 32, 64].iter()) {
        if v.len() != *n {
            return Err(JsValue::from_str("bad lengths"));
        }
    }
    let cp32 = |v: &[u8]| {
        let mut o = [0u8; 32];
        o.copy_from_slice(&v[..32]);
        o
    };
    let mut cc = [0u8; 64];
    cc.copy_from_slice(&vs[4]);
    let current_balance = current_balance as u64;
    let transfer_amount = transfer_amount as u64;
    let b = prove_transfer(
        &cp32(&vs[0]), &cp32(&vs[1]), &cp32(&vs[2]), &cp32(&vs[3]), &cc,
        current_balance, transfer_amount, &read32(&u8_vec(seed))?,
    )
    .map_err(|_| JsValue::from_str("prove"))?;
    let mut flat = Vec::with_capacity(1896);
    flat.extend_from_slice(&b.equality_proof);
    flat.extend_from_slice(&b.validity_proof);
    flat.extend_from_slice(&b.range_proof);
    flat.extend_from_slice(&b.range_commitments);
    flat.extend_from_slice(&b.range_bit_lengths);
    flat.extend_from_slice(&b.grouped_lo);
    flat.extend_from_slice(&b.grouped_hi);
    flat.extend_from_slice(&b.remaining_commitment);
    flat.extend_from_slice(&b.remaining_opening);
    flat.extend_from_slice(&b.remaining_ciphertext);
    flat.extend_from_slice(&b.auditor_lo);
    flat.extend_from_slice(&b.auditor_hi);
    Ok(flat)
}

/// Prove transfer-with-fee bundle (2576-byte fixed layout).
#[wasm_bindgen(js_name = solanaZkProveTransferWithFee)]
#[allow(clippy::too_many_arguments)]
pub fn solana_zk_prove_transfer_with_fee(
    source_secret: &[u8],
    source_pubkey: &[u8],
    dest_pubkey: &[u8],
    auditor_pubkey: &[u8],
    authority_pubkey: &[u8],
    current_ciphertext: &[u8],
    current_balance: f64,
    transfer_amount: f64,
    fee_rate_basis_points: f64,
    maximum_fee: f64,
    seed: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let vs: Vec<Vec<u8>> = [source_secret, source_pubkey, dest_pubkey, auditor_pubkey, authority_pubkey, current_ciphertext]
        .iter().map(|v| u8_vec(v)).collect();
    for (v, n) in vs.iter().zip([32, 32, 32, 32, 32, 64].iter()) {
        if v.len() != *n {
            return Err(JsValue::from_str("bad lengths"));
        }
    }
    let cp32 = |v: &[u8]| {
        let mut o = [0u8; 32];
        o.copy_from_slice(&v[..32]);
        o
    };
    let mut cc = [0u8; 64];
    cc.copy_from_slice(&vs[5]);
    let current_balance = current_balance as u64;
    let transfer_amount = transfer_amount as u64;
    let fee_rate_basis_points = fee_rate_basis_points as u16;
    let maximum_fee = maximum_fee as u64;
    let b = prove_transfer_with_fee(
        &cp32(&vs[0]), &cp32(&vs[1]), &cp32(&vs[2]), &cp32(&vs[3]), &cp32(&vs[4]),
        &cc, current_balance, transfer_amount, fee_rate_basis_points, maximum_fee,
        &read32(&u8_vec(seed))?,
    )
    .map_err(|_| JsValue::from_str("prove"))?;
    let mut flat = Vec::with_capacity(2576);
    flat.extend_from_slice(&b.equality_proof);
    flat.extend_from_slice(&b.validity_proof);
    flat.extend_from_slice(&b.percentage_proof);
    flat.extend_from_slice(&b.fee_validity_proof);
    flat.extend_from_slice(&b.range_proof);
    flat.extend_from_slice(&b.range_commitments);
    flat.extend_from_slice(&b.range_bit_lengths);
    flat.extend_from_slice(&b.grouped_lo);
    flat.extend_from_slice(&b.grouped_hi);
    flat.extend_from_slice(&b.fee_grouped_lo);
    flat.extend_from_slice(&b.fee_grouped_hi);
    flat.extend_from_slice(&b.remaining_commitment);
    flat.extend_from_slice(&b.remaining_opening);
    flat.extend_from_slice(&b.remaining_ciphertext);
    flat.extend_from_slice(&b.fee_commitment);
    flat.extend_from_slice(&b.delta_commitment);
    flat.extend_from_slice(&b.claimed_commitment);
    flat.extend_from_slice(&b.net_commitment);
    flat.extend_from_slice(&b.max_fee.to_le_bytes());
    Ok(flat)
}

/// Prove pubkey-validity (64 bytes) for a 32-byte secret.
#[wasm_bindgen(js_name = solanaZkProvePubkeyValidity)]
pub fn solana_zk_prove_pubkey_validity(
    secret: &[u8],
    seed: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let s = u8_vec(secret);
    if s.len() != 32 {
        return Err(JsValue::from_str("need 32-byte secret"));
    }
    let mut sf = [0u8; 32];
    sf.copy_from_slice(&s);
    prove_pubkey_validity(&sf, &read32(&u8_vec(seed))?, CTX_PUBKEY_VALIDITY)
        .map(|p| p.to_vec())
        .map_err(|_| JsValue::from_str("prove"))
}

/// Verify a 64-byte pubkey-validity proof. True iff valid.
#[wasm_bindgen(js_name = solanaZkVerifyPubkeyValidity)]
pub fn solana_zk_verify_pubkey_validity(
    pubkey: &[u8],
    proof: &[u8],
) -> Result<bool, JsValue> {
    let p = u8_vec(pubkey);
    let pf = u8_vec(proof);
    if p.len() != 32 || pf.len() != 64 {
        return Err(JsValue::from_str("bad lengths"));
    }
    let mut pff = [0u8; 32];
    let mut prf = [0u8; 64];
    pff.copy_from_slice(&p);
    prf.copy_from_slice(&pf);
    Ok(verify_pubkey_validity(&pff, &prf, CTX_PUBKEY_VALIDITY).is_ok())
}

/// Prove zero-ciphertext (96 bytes).
#[wasm_bindgen(js_name = solanaZkProveZeroCiphertext)]
pub fn solana_zk_prove_zero_ciphertext(
    secret: &[u8],
    pubkey: &[u8],
    ciphertext: &[u8],
    seed: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let s = u8_vec(secret);
    let p = u8_vec(pubkey);
    let c = u8_vec(ciphertext);
    if s.len() != 32 || p.len() != 32 || c.len() != 64 {
        return Err(JsValue::from_str("bad lengths"));
    }
    let mut sf = [0u8; 32];
    let mut pf = [0u8; 32];
    let mut cf = [0u8; 64];
    sf.copy_from_slice(&s);
    pf.copy_from_slice(&p);
    cf.copy_from_slice(&c);
    prove_zero_ciphertext(&sf, &pf, &cf, &read32(&u8_vec(seed))?, CTX_ZERO_CIPHERTEXT)
        .map(|p| p.to_vec())
        .map_err(|_| JsValue::from_str("prove"))
}

/// Verify a 96-byte zero-ciphertext proof. True iff valid.
#[wasm_bindgen(js_name = solanaZkVerifyZeroCiphertext)]
pub fn solana_zk_verify_zero_ciphertext(
    pubkey: &[u8],
    ciphertext: &[u8],
    proof: &[u8],
) -> Result<bool, JsValue> {
    let p = u8_vec(pubkey);
    let c = u8_vec(ciphertext);
    let pf = u8_vec(proof);
    if p.len() != 32 || c.len() != 64 || pf.len() != 96 {
        return Err(JsValue::from_str("bad lengths"));
    }
    let mut pff = [0u8; 32];
    let mut cf = [0u8; 64];
    let mut prf = [0u8; 96];
    pff.copy_from_slice(&p);
    cf.copy_from_slice(&c);
    prf.copy_from_slice(&pf);
    Ok(verify_zero_ciphertext(&pff, &cf, &prf, CTX_ZERO_CIPHERTEXT).is_ok())
}

/// Prove ciphertext-commitment equality (192 bytes).
#[wasm_bindgen(js_name = solanaZkProveEquality)]
pub fn solana_zk_prove_equality(
    secret: &[u8],
    pubkey: &[u8],
    ciphertext: &[u8],
    commitment: &[u8],
    opening: &[u8],
    amount: f64,
    seed: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let s = u8_vec(secret);
    let p = u8_vec(pubkey);
    let c = u8_vec(ciphertext);
    let cm = u8_vec(commitment);
    let r = u8_vec(opening);
    if s.len() != 32 || p.len() != 32 || c.len() != 64 || cm.len() != 32 || r.len() != 32 {
        return Err(JsValue::from_str("bad lengths"));
    }
    let mut sf = [0u8; 32];
    let mut pf = [0u8; 32];
    let mut cf = [0u8; 64];
    let mut cmf = [0u8; 32];
    let mut rf = [0u8; 32];
    sf.copy_from_slice(&s);
    pf.copy_from_slice(&p);
    cf.copy_from_slice(&c);
    cmf.copy_from_slice(&cm);
    rf.copy_from_slice(&r);
    let amount = amount as u64;
    prove_ciphertext_commitment_equality(
        &sf, &pf, &cf, &cmf, &rf, amount, &read32(&u8_vec(seed))?, CTX_CIPHERTEXT_COMMITMENT_EQUALITY,
    )
    .map(|p| p.to_vec())
    .map_err(|_| JsValue::from_str("prove"))
}

/// Verify a 192-byte equality proof. True iff valid.
#[wasm_bindgen(js_name = solanaZkVerifyEquality)]
pub fn solana_zk_verify_equality(
    pubkey: &[u8],
    ciphertext: &[u8],
    commitment: &[u8],
    proof: &[u8],
) -> Result<bool, JsValue> {
    let p = u8_vec(pubkey);
    let c = u8_vec(ciphertext);
    let cm = u8_vec(commitment);
    let pf = u8_vec(proof);
    if p.len() != 32 || c.len() != 64 || cm.len() != 32 || pf.len() != 192 {
        return Err(JsValue::from_str("bad lengths"));
    }
    let mut pff = [0u8; 32];
    let mut cf = [0u8; 64];
    let mut cmf = [0u8; 32];
    let mut prf = [0u8; 192];
    pff.copy_from_slice(&p);
    cf.copy_from_slice(&c);
    cmf.copy_from_slice(&cm);
    prf.copy_from_slice(&pf);
    Ok(verify_ciphertext_commitment_equality(&pff, &cf, &cmf, &prf, CTX_CIPHERTEXT_COMMITMENT_EQUALITY).is_ok())
}

/// Prove ciphertext-ciphertext equality (224 bytes).
#[wasm_bindgen(js_name = solanaZkProveCiphertextEquality)]
#[allow(clippy::too_many_arguments)]
pub fn solana_zk_prove_ciphertext_equality(
    first_secret: &[u8],
    first_pubkey: &[u8],
    second_pubkey: &[u8],
    first_ciphertext: &[u8],
    second_ciphertext: &[u8],
    second_opening: &[u8],
    amount: f64,
    seed: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let fs = u8_vec(first_secret);
    let p1 = u8_vec(first_pubkey);
    let p2 = u8_vec(second_pubkey);
    let c1 = u8_vec(first_ciphertext);
    let c2 = u8_vec(second_ciphertext);
    let r = u8_vec(second_opening);
    if fs.len() != 32 || p1.len() != 32 || p2.len() != 32 || c1.len() != 64 || c2.len() != 64 || r.len() != 32 {
        return Err(JsValue::from_str("bad lengths"));
    }
    let mut fsf = [0u8; 32];
    let mut p1f = [0u8; 32];
    let mut p2f = [0u8; 32];
    let mut c1f = [0u8; 64];
    let mut c2f = [0u8; 64];
    let mut rf = [0u8; 32];
    fsf.copy_from_slice(&fs);
    p1f.copy_from_slice(&p1);
    p2f.copy_from_slice(&p2);
    c1f.copy_from_slice(&c1);
    c2f.copy_from_slice(&c2);
    rf.copy_from_slice(&r);
    let amount = amount as u64;
    prove_ciphertext_ciphertext_equality(
        &fsf, &p1f, &p2f, &c1f, &c2f, &rf, amount,
        &read32(&u8_vec(seed))?, CTX_CIPHERTEXT_CIPHERTEXT_EQUALITY,
    )
    .map(|p| p.to_vec())
    .map_err(|_| JsValue::from_str("prove"))
}

/// Verify a 224-byte ciphertext-ciphertext equality proof.
#[wasm_bindgen(js_name = solanaZkVerifyCiphertextEquality)]
#[allow(clippy::too_many_arguments)]
pub fn solana_zk_verify_ciphertext_equality(
    first_pubkey: &[u8],
    second_pubkey: &[u8],
    first_ciphertext: &[u8],
    second_ciphertext: &[u8],
    proof: &[u8],
) -> Result<bool, JsValue> {
    let p1 = u8_vec(first_pubkey);
    let p2 = u8_vec(second_pubkey);
    let c1 = u8_vec(first_ciphertext);
    let c2 = u8_vec(second_ciphertext);
    let pf = u8_vec(proof);
    if p1.len() != 32 || p2.len() != 32 || c1.len() != 64 || c2.len() != 64 || pf.len() != 224 {
        return Err(JsValue::from_str("bad lengths"));
    }
    let mut p1f = [0u8; 32];
    let mut p2f = [0u8; 32];
    let mut c1f = [0u8; 64];
    let mut c2f = [0u8; 64];
    let mut prf = [0u8; 224];
    p1f.copy_from_slice(&p1);
    p2f.copy_from_slice(&p2);
    c1f.copy_from_slice(&c1);
    c2f.copy_from_slice(&c2);
    prf.copy_from_slice(&pf);
    Ok(verify_ciphertext_ciphertext_equality(&p1f, &p2f, &c1f, &c2f, &prf, CTX_CIPHERTEXT_CIPHERTEXT_EQUALITY).is_ok())
}

/// Prove 2-handle grouped validity (160 bytes).
#[wasm_bindgen(js_name = solanaZkProveGroupedValidity2)]
#[allow(clippy::too_many_arguments)]
pub fn solana_zk_prove_grouped_validity_2(
    first_pubkey: &[u8],
    second_pubkey: &[u8],
    grouped: &[u8],
    amount: f64,
    opening: &[u8],
    seed: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let p1 = u8_vec(first_pubkey);
    let p2 = u8_vec(second_pubkey);
    let g = u8_vec(grouped);
    let r = u8_vec(opening);
    if p1.len() != 32 || p2.len() != 32 || g.len() != 96 || r.len() != 32 {
        return Err(JsValue::from_str("bad lengths"));
    }
    let mut p1f = [0u8; 32];
    let mut p2f = [0u8; 32];
    let mut gf = [0u8; 96];
    let mut rf = [0u8; 32];
    p1f.copy_from_slice(&p1);
    p2f.copy_from_slice(&p2);
    gf.copy_from_slice(&g);
    rf.copy_from_slice(&r);
    let amount = amount as u64;
    prove_grouped_validity_2(
        &p1f, &p2f, &gf, amount, &rf,
        &read32(&u8_vec(seed))?, CTX_GROUPED_VALIDITY_2,
    )
    .map(|p| p.to_vec())
    .map_err(|_| JsValue::from_str("prove"))
}

/// Verify a 160-byte 2-handle validity proof.
#[wasm_bindgen(js_name = solanaZkVerifyGroupedValidity2)]
pub fn solana_zk_verify_grouped_validity_2(
    first_pubkey: &[u8],
    second_pubkey: &[u8],
    grouped: &[u8],
    proof: &[u8],
) -> Result<bool, JsValue> {
    let p1 = u8_vec(first_pubkey);
    let p2 = u8_vec(second_pubkey);
    let g = u8_vec(grouped);
    let pf = u8_vec(proof);
    if p1.len() != 32 || p2.len() != 32 || g.len() != 96 || pf.len() != 160 {
        return Err(JsValue::from_str("bad lengths"));
    }
    let mut p1f = [0u8; 32];
    let mut p2f = [0u8; 32];
    let mut gf = [0u8; 96];
    let mut prf = [0u8; 160];
    p1f.copy_from_slice(&p1);
    p2f.copy_from_slice(&p2);
    gf.copy_from_slice(&g);
    prf.copy_from_slice(&pf);
    Ok(verify_grouped_validity_2(&p1f, &p2f, &gf, &prf, CTX_GROUPED_VALIDITY_2).is_ok())
}

/// Prove 3-handle grouped validity (192 bytes).
#[wasm_bindgen(js_name = solanaZkProveGroupedValidity3)]
#[allow(clippy::too_many_arguments)]
pub fn solana_zk_prove_grouped_validity_3(
    first_pubkey: &[u8],
    second_pubkey: &[u8],
    third_pubkey: &[u8],
    grouped: &[u8],
    amount: f64,
    opening: &[u8],
    seed: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let p1 = u8_vec(first_pubkey);
    let p2 = u8_vec(second_pubkey);
    let p3 = u8_vec(third_pubkey);
    let g = u8_vec(grouped);
    let r = u8_vec(opening);
    if p1.len() != 32 || p2.len() != 32 || p3.len() != 32 || g.len() != 128 || r.len() != 32 {
        return Err(JsValue::from_str("bad lengths"));
    }
    let mut p1f = [0u8; 32];
    let mut p2f = [0u8; 32];
    let mut p3f = [0u8; 32];
    let mut gf = [0u8; 128];
    let mut rf = [0u8; 32];
    p1f.copy_from_slice(&p1);
    p2f.copy_from_slice(&p2);
    p3f.copy_from_slice(&p3);
    gf.copy_from_slice(&g);
    rf.copy_from_slice(&r);
    let amount = amount as u64;
    prove_grouped_validity_3(
        &p1f, &p2f, &p3f, &gf, amount, &rf,
        &read32(&u8_vec(seed))?, CTX_GROUPED_VALIDITY_3,
    )
    .map(|p| p.to_vec())
    .map_err(|_| JsValue::from_str("prove"))
}

/// Verify a 192-byte 3-handle validity proof.
#[wasm_bindgen(js_name = solanaZkVerifyGroupedValidity3)]
#[allow(clippy::too_many_arguments)]
pub fn solana_zk_verify_grouped_validity_3(
    first_pubkey: &[u8],
    second_pubkey: &[u8],
    third_pubkey: &[u8],
    grouped: &[u8],
    proof: &[u8],
) -> Result<bool, JsValue> {
    let p1 = u8_vec(first_pubkey);
    let p2 = u8_vec(second_pubkey);
    let p3 = u8_vec(third_pubkey);
    let g = u8_vec(grouped);
    let pf = u8_vec(proof);
    if p1.len() != 32 || p2.len() != 32 || p3.len() != 32 || g.len() != 128 || pf.len() != 192 {
        return Err(JsValue::from_str("bad lengths"));
    }
    let mut p1f = [0u8; 32];
    let mut p2f = [0u8; 32];
    let mut p3f = [0u8; 32];
    let mut gf = [0u8; 128];
    let mut prf = [0u8; 192];
    p1f.copy_from_slice(&p1);
    p2f.copy_from_slice(&p2);
    p3f.copy_from_slice(&p3);
    gf.copy_from_slice(&g);
    prf.copy_from_slice(&pf);
    Ok(verify_grouped_validity_3(&p1f, &p2f, &p3f, &gf, &prf, CTX_GROUPED_VALIDITY_3).is_ok())
}

/// Prove percentage-with-cap (256 bytes).
#[wasm_bindgen(js_name = solanaZkProvePercentageWithCap)]
#[allow(clippy::too_many_arguments)]
pub fn solana_zk_prove_percentage_with_cap(
    percentage_commitment: &[u8],
    percentage_opening: &[u8],
    percentage_amount: f64,
    delta_commitment: &[u8],
    delta_opening: &[u8],
    delta_amount: f64,
    claimed_commitment: &[u8],
    claimed_opening: &[u8],
    max_value: f64,
    seed: &[u8],
) -> Result<Vec<u8>, JsValue> {
    for (v, n) in [
        (percentage_commitment, 32),
        (percentage_opening, 32),
        (delta_commitment, 32),
        (delta_opening, 32),
        (claimed_commitment, 32),
        (claimed_opening, 32),
    ] {
        if u8_vec(v).len() != n {
            return Err(JsValue::from_str("bad lengths"));
        }
    }
    let cp = |v: &[u8]| {
        let mut o = [0u8; 32];
        o.copy_from_slice(&u8_vec(v));
        o
    };
    prove_percentage_with_cap(
        &cp(percentage_commitment),
        &cp(percentage_opening),
        percentage_amount as u64,
        &cp(delta_commitment),
        &cp(delta_opening),
        delta_amount as u64,
        &cp(claimed_commitment),
        &cp(claimed_opening),
        max_value as u64,
        &read32(&u8_vec(seed))?,
        CTX_PERCENTAGE_WITH_CAP,
    )
    .map(|p| p.to_vec())
    .map_err(|_| JsValue::from_str("prove"))
}

/// Verify a 256-byte percentage-with-cap proof.
#[wasm_bindgen(js_name = solanaZkVerifyPercentageWithCap)]
pub fn solana_zk_verify_percentage_with_cap(
    percentage_commitment: &[u8],
    delta_commitment: &[u8],
    claimed_commitment: &[u8],
    max_value: f64,
    proof: &[u8],
) -> Result<bool, JsValue> {
    let pc = u8_vec(percentage_commitment);
    let dc = u8_vec(delta_commitment);
    let cc = u8_vec(claimed_commitment);
    let pf = u8_vec(proof);
    if pc.len() != 32 || dc.len() != 32 || cc.len() != 32 || pf.len() != 256 {
        return Err(JsValue::from_str("bad lengths"));
    }
    let mut pcf = [0u8; 32];
    let mut dcf = [0u8; 32];
    let mut ccf = [0u8; 32];
    let mut prf = [0u8; 256];
    pcf.copy_from_slice(&pc);
    dcf.copy_from_slice(&dc);
    ccf.copy_from_slice(&cc);
    prf.copy_from_slice(&pf);
    Ok(verify_percentage_with_cap(&pcf, &dcf, &ccf, max_value as u64, &prf, CTX_PERCENTAGE_WITH_CAP).is_ok())
}

/// Verify a batched range proof against `n` 32-byte
/// commitments (`commitments` = n*32 bytes). True iff valid.
#[wasm_bindgen(js_name = solanaZkVerifyBatchedRange)]
pub fn solana_zk_verify_batched_range(
    proof: &[u8],
    commitments: &[u8],
    n: usize,
) -> Result<bool, JsValue> {
    let c = u8_vec(commitments);
    if c.len() != n * 32 || n == 0 || n > 16 {
        return Err(JsValue::from_str("bad lengths"));
    }
    let mut pod_commitments = [0u8; 256];
    for (i, chunk) in c.chunks_exact(32).enumerate() {
        pod_commitments[i * 32..i * 32 + 32].copy_from_slice(chunk);
    }
    let mut pod_bit_lengths = [0u8; 8];
    for b in pod_bit_lengths.iter_mut().take(n) {
        *b = 64;
    }
    Ok(crate::solana_zk::verify_batched_range(
        &u8_vec(proof),
        &pod_commitments,
        &pod_bit_lengths,
    )
    .is_ok())
}

/// Prove batched 2-handle grouped validity (160 bytes).
#[wasm_bindgen(js_name = solanaZkProveBatchedGroupedValidity2)]
#[allow(clippy::too_many_arguments)]
pub fn solana_zk_prove_batched_grouped_validity_2(
    first_pubkey: &[u8],
    second_pubkey: &[u8],
    grouped_lo: &[u8],
    grouped_hi: &[u8],
    amount_lo: f64,
    amount_hi: f64,
    opening_lo: &[u8],
    opening_hi: &[u8],
    seed: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let p1 = u8_vec(first_pubkey);
    let p2 = u8_vec(second_pubkey);
    let lo = u8_vec(grouped_lo);
    let hi = u8_vec(grouped_hi);
    let rol = u8_vec(opening_lo);
    let roh = u8_vec(opening_hi);
    if p1.len() != 32 || p2.len() != 32 || lo.len() != 96 || hi.len() != 96 || rol.len() != 32 || roh.len() != 32 {
        return Err(JsValue::from_str("bad lengths"));
    }
    let cp = |v: &[u8], n: usize| {
        let mut o = vec![0u8; n];
        o.copy_from_slice(&v[..n]);
        o
    };
    let (p1f, p2f, lof, hif, rolf, rohf) =
        (cp(&p1, 32), cp(&p2, 32), cp(&lo, 96), cp(&hi, 96), cp(&rol, 32), cp(&roh, 32));
    let mut a1 = [0u8; 32];
    let mut a2 = [0u8; 32];
    let mut b1 = [0u8; 96];
    let mut b2 = [0u8; 96];
    let mut c1 = [0u8; 32];
    let mut c2 = [0u8; 32];
    a1.copy_from_slice(&p1f);
    a2.copy_from_slice(&p2f);
    b1.copy_from_slice(&lof);
    b2.copy_from_slice(&hif);
    c1.copy_from_slice(&rolf);
    c2.copy_from_slice(&rohf);
    prove_batched_grouped_validity_2(
        &a1, &a2, &b1, &b2, amount_lo as u64, amount_hi as u64, &c1, &c2,
        &read32(&u8_vec(seed))?, CTX_BATCHED_GROUPED_VALIDITY_2,
    )
    .map(|p| p.to_vec())
    .map_err(|_| JsValue::from_str("prove"))
}

/// Verify a 160-byte batched 2-handle validity proof.
#[wasm_bindgen(js_name = solanaZkVerifyBatchedGroupedValidity2)]
pub fn solana_zk_verify_batched_grouped_validity_2(
    first_pubkey: &[u8],
    second_pubkey: &[u8],
    grouped_lo: &[u8],
    grouped_hi: &[u8],
    proof: &[u8],
) -> Result<bool, JsValue> {
    let p1 = u8_vec(first_pubkey);
    let p2 = u8_vec(second_pubkey);
    let lo = u8_vec(grouped_lo);
    let hi = u8_vec(grouped_hi);
    let pf = u8_vec(proof);
    if p1.len() != 32 || p2.len() != 32 || lo.len() != 96 || hi.len() != 96 || pf.len() != 160 {
        return Err(JsValue::from_str("bad lengths"));
    }
    let mut a1 = [0u8; 32];
    let mut a2 = [0u8; 32];
    let mut b1 = [0u8; 96];
    let mut b2 = [0u8; 96];
    let mut prf = [0u8; 160];
    a1.copy_from_slice(&p1);
    a2.copy_from_slice(&p2);
    b1.copy_from_slice(&lo);
    b2.copy_from_slice(&hi);
    prf.copy_from_slice(&pf);
    Ok(verify_batched_grouped_validity_2(&a1, &a2, &b1, &b2, &prf, CTX_BATCHED_GROUPED_VALIDITY_2).is_ok())
}

/// Prove batched 3-handle grouped validity (192 bytes).
#[wasm_bindgen(js_name = solanaZkProveBatchedGroupedValidity3)]
#[allow(clippy::too_many_arguments)]
pub fn solana_zk_prove_batched_grouped_validity_3(
    first_pubkey: &[u8],
    second_pubkey: &[u8],
    third_pubkey: &[u8],
    grouped_lo: &[u8],
    grouped_hi: &[u8],
    amount_lo: f64,
    amount_hi: f64,
    opening_lo: &[u8],
    opening_hi: &[u8],
    seed: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let vs: Vec<Vec<u8>> = [first_pubkey, second_pubkey, third_pubkey, grouped_lo, grouped_hi, opening_lo, opening_hi]
        .iter().map(|v| u8_vec(v)).collect();
    let ns = [32, 32, 32, 128, 128, 32, 32];
    for (v, n) in vs.iter().zip(ns.iter()) {
        if v.len() != *n {
            return Err(JsValue::from_str("bad lengths"));
        }
    }
    let cp32 = |v: &[u8]| {
        let mut o = [0u8; 32];
        o.copy_from_slice(&v[..32]);
        o
    };
    let cp128 = |v: &[u8]| {
        let mut o = [0u8; 128];
        o.copy_from_slice(&v[..128]);
        o
    };
    prove_batched_grouped_validity_3(
        &cp32(&vs[0]), &cp32(&vs[1]), &cp32(&vs[2]), &cp128(&vs[3]), &cp128(&vs[4]),
        amount_lo as u64, amount_hi as u64, &cp32(&vs[5]), &cp32(&vs[6]),
        &read32(&u8_vec(seed))?, CTX_BATCHED_GROUPED_VALIDITY_3,
    )
    .map(|p| p.to_vec())
    .map_err(|_| JsValue::from_str("prove"))
}

/// Verify a 192-byte batched 3-handle validity proof.
#[wasm_bindgen(js_name = solanaZkVerifyBatchedGroupedValidity3)]
#[allow(clippy::too_many_arguments)]
pub fn solana_zk_verify_batched_grouped_validity_3(
    first_pubkey: &[u8],
    second_pubkey: &[u8],
    third_pubkey: &[u8],
    grouped_lo: &[u8],
    grouped_hi: &[u8],
    proof: &[u8],
) -> Result<bool, JsValue> {
    let vs: Vec<Vec<u8>> = [first_pubkey, second_pubkey, third_pubkey, grouped_lo, grouped_hi, proof]
        .iter().map(|v| u8_vec(v)).collect();
    let ns = [32, 32, 32, 128, 128, 192];
    for (v, n) in vs.iter().zip(ns.iter()) {
        if v.len() != *n {
            return Err(JsValue::from_str("bad lengths"));
        }
    }
    let cp32 = |v: &[u8]| {
        let mut o = [0u8; 32];
        o.copy_from_slice(&v[..32]);
        o
    };
    let cp128 = |v: &[u8]| {
        let mut o = [0u8; 128];
        o.copy_from_slice(&v[..128]);
        o
    };
    let mut prf = [0u8; 192];
    prf.copy_from_slice(&vs[5]);
    Ok(verify_batched_grouped_validity_3(
        &cp32(&vs[0]), &cp32(&vs[1]), &cp32(&vs[2]), &cp128(&vs[3]), &cp128(&vs[4]),
        &prf, CTX_BATCHED_GROUPED_VALIDITY_3,
    )
    .is_ok())
}

/// AES-GCM-SIV encrypt a u64 balance (36 bytes out).
#[wasm_bindgen(js_name = solanaZkAeEncrypt)]
pub fn solana_zk_ae_encrypt(
    key: &[u8],
    amount: f64,
    nonce: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let k = u8_vec(key);
    let n = u8_vec(nonce);
    if k.len() != 16 || n.len() != 12 {
        return Err(JsValue::from_str("bad lengths"));
    }
    let mut kf = [0u8; 16];
    let mut nf = [0u8; 12];
    kf.copy_from_slice(&k);
    nf.copy_from_slice(&n);
    crate::solana_zk::aead_gcm_siv::ae_encrypt(&kf, amount as u64, &nf)
        .map(|c| c.to_vec())
        .map_err(|_| JsValue::from_str("encrypt"))
}

/// AES-GCM-SIV decrypt a 36-byte balance to u64.
#[wasm_bindgen(js_name = solanaZkAeDecrypt)]
pub fn solana_zk_ae_decrypt(key: &[u8], ae: &[u8]) -> Result<f64, JsValue> {
    let k = u8_vec(key);
    let c = u8_vec(ae);
    if k.len() != 16 || c.len() != 36 {
        return Err(JsValue::from_str("bad lengths"));
    }
    let mut kf = [0u8; 16];
    let mut cf = [0u8; 36];
    kf.copy_from_slice(&k);
    cf.copy_from_slice(&c);
    crate::solana_zk::aead_gcm_siv::ae_decrypt(&kf, &cf)
        .map(|v| v as f64)
        .map_err(|_| JsValue::from_str("auth failed"))
}
