//! Confidential-transfer bundle provers (zero-dep port).
//!
//! /// Byte-compatible port of token-2022
//! `confidential/proof-generation` (`withdraw.rs`, `transfer.rs`,
//! `transfer_with_fee.rs`): each bundle produces the exact on-chain proof set
//! (withdraw = equality + U64 range; transfer = equality + batched validity-3
//! + U128 range; transfer-with-fee = equality + validity-3 +
//!   percentage-with-cap + batched fee-validity-2 + U256 range), every component
//!   under its on-chain instruction transcript label. Openings and masking
//!   randomness derive from the caller seed via SHA3-256 KDF sub-seeds, so a
//!   fresh seed per call keeps all secrets fresh. Amount splits, fee math and
//!   commitment arithmetic mirror the upstream generators exactly.

use super::range_proof;
use super::sigma_proofs::{
    self, CTX_BATCHED_GROUPED_VALIDITY_2, CTX_BATCHED_GROUPED_VALIDITY_3,
    CTX_CIPHERTEXT_COMMITMENT_EQUALITY,
    CTX_PERCENTAGE_WITH_CAP,
};
use super::{amount_scalar, h_point, SolanaZkError, SolanaZkResult};
use crate::curve::ed25519::Scalar;
use crate::curve::traits::CurvePoint;
use crate::curve::RistrettoPoint;


/// Transfer-amount split: low 16 bits, high 32 bits (amounts
/// must fit in 48 bits; mirrors `TRANSFER_AMOUNT_LO_BITS`).
pub const TRANSFER_LO_BITS: u32 = 16;
/// Fee-amount split widths (mirror `FEE_AMOUNT_LO/HI_BITS`).
pub const FEE_LO_BITS: u32 = 16;
/// Fee rate denominator (basis points).
pub const MAX_FEE_BASIS_POINTS: u64 = 10_000;

/// SHA3-256 KDF: sub-seed for one bundle component.
fn kdf(seed: &[u8; 32], tag: &[u8]) -> [u8; 32] {
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(seed);
    let tag_hash = crate::hash::keccak::sha3_256(tag).expect("sha3 kdf");
    for i in 0..32 {
        input[32 + i] = tag_hash[i] ^ (tag.len() as u8).wrapping_add(i as u8);
    }
    crate::hash::keccak::sha3_256(&input).expect("sha3 kdf")
}

/// KDF opening as canonical scalar bytes + scalar (uniform
/// 256-bit KDF output reduced mod L; retries with a counter on zero, which
/// never happens in practice but keeps the invariant strict).
fn kdf_opening(seed: &[u8; 32], tag: &[u8]) -> ([u8; 32], Scalar) {
    let mut ctr = 0u8;
    loop {
        let mut full_tag = [0u8; 64];
        let n = tag.len().min(63);
        full_tag[..n].copy_from_slice(&tag[..n]);
        full_tag[63] = ctr;
        let raw = kdf(seed, &full_tag);
        let s = Scalar::from_bytes_mod_order(&raw);
        if !s.is_zero() {
            let mut enc = [0u8; 32];
            s.to_bytes_le(&mut enc);
            return (enc, s);
        }
        ctr = ctr.wrapping_add(1);
    }
}

/// Scalar from u64 (always < L).
fn scalar_u64(v: u64) -> Scalar {
    amount_scalar(v)
}

/// Split a u64 into 16-bit lo and (up to 32-bit) hi parts.
fn split_u64(amount: u64) -> SolanaZkResult<(u64, u64)> {
    let lo = amount & 0xffff;
    let hi = amount >> TRANSFER_LO_BITS;
    if hi >= (1u64 << 32) {
        return Err(SolanaZkError::InvalidLength);
    }
    Ok((lo, hi))
}

/// Decoded ElGamal ciphertext (commitment, handle).
struct DecodedCt {
    /// Commitment point.
    c: RistrettoPoint,
    /// Handle point.
    d: RistrettoPoint,
}

impl DecodedCt {
    /// Decode 64 bytes.
    fn decode(bytes: &[u8; 64]) -> SolanaZkResult<Self> {
        Ok(Self {
            c: RistrettoPoint::from_bytes(&bytes[..32])
                .map_err(|_| SolanaZkError::InvalidPoint)?,
            d: RistrettoPoint::from_bytes(&bytes[32..])
                .map_err(|_| SolanaZkError::InvalidPoint)?,
        })
    }

    /// Encode to 64 bytes.
    fn encode(&self) -> SolanaZkResult<[u8; 64]> {
        let mut out = [0u8; 64];
        self.c
            .to_bytes_compressed(&mut out[..32])
            .map_err(|_| SolanaZkError::InvalidPoint)?;
        self.d
            .to_bytes_compressed(&mut out[32..])
            .map_err(|_| SolanaZkError::InvalidPoint)?;
        Ok(out)
    }

    /// Homomorphic subtract of a plaintext amount (`C - m*G`).
    fn sub_amount(&self, amount: u64) -> Self {
        let g = RistrettoPoint::generator();
        Self {
            c: self.c.add(&g.mul(&scalar_u64(amount)).neg()),
            d: self.d,
        }
    }

    /// Component-wise add.
    fn add_ct(&self, other: &Self) -> Self {
        Self {
            c: self.c.add(&other.c),
            d: self.d.add(&other.d),
        }
    }

    /// Component-wise scalar multiply.
    fn mul_scalar(&self, s: &Scalar) -> Self {
        Self {
            c: self.c.mul(s),
            d: self.d.mul(s),
        }
    }
}

/// Combine lo/hi ciphertexts (`C = C_lo + 2^16 * C_hi`).
fn combine_lo_hi(lo: &DecodedCt, hi: &DecodedCt) -> DecodedCt {
    let shift = scalar_u64(1u64 << TRANSFER_LO_BITS);
    lo.add_ct(&hi.mul_scalar(&shift))
}

/// Pedersen commitment point `m*G + r*H`.
fn pedersen_point(amount: u64, opening: &Scalar) -> SolanaZkResult<RistrettoPoint> {
    Ok(RistrettoPoint::generator()
        .mul(&scalar_u64(amount))
        .add(&h_point()?.mul(opening)))
}

/// Encode a point canonically.
fn enc_point(p: &RistrettoPoint) -> SolanaZkResult<[u8; 32]> {
    let mut out = [0u8; 32];
    p.to_bytes_compressed(&mut out)
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    Ok(out)
}

/// Grouped encryption of `amount` under `pubkeys` with one
/// opening: `(commitment, handle_0, ...)` encoded bytes.
fn grouped_encrypt(
    pubkeys: &[RistrettoPoint],
    amount: u64,
    opening: &Scalar,
) -> SolanaZkResult<(Vec<u8>, Vec<[u8; 32]>)> {
    let comm = pedersen_point(amount, opening)?;
    let mut grouped = enc_point(&comm)?.to_vec();
    let mut handles = Vec::with_capacity(pubkeys.len());
    for p in pubkeys {
        let h = enc_point(&p.mul(opening))?;
        grouped.extend_from_slice(&h);
        handles.push(h);
    }
    Ok((grouped, handles))
}

/// Masking-seed KDF tags per bundle component.
fn component_seed(seed: &[u8; 32], tag: &[u8]) -> [u8; 32] {
    kdf(seed, tag)
}

/// Withdraw bundle outputs (all values the instruction needs).
pub struct WithdrawBundle {
    /// Equality proof (192 bytes, instruction transcript).
    pub equality_proof: [u8; 192],
    /// U64 range proof bytes.
    pub range_proof: Vec<u8>,
    /// Range pod commitments (256 bytes).
    pub range_commitments: [u8; 256],
    /// Range pod bit lengths (8 bytes).
    pub range_bit_lengths: [u8; 8],
    /// Remaining-balance commitment (32 bytes).
    pub remaining_commitment: [u8; 32],
    /// Remaining-balance opening (persist for recovery).
    pub remaining_opening: [u8; 32],
    /// Remaining-balance ciphertext (64 bytes).
    pub remaining_ciphertext: [u8; 64],
}

/// Prove a withdraw bundle: equality + U64 range over the
/// remaining balance (mirrors `withdraw_proof_data`). Fails when
/// `withdraw_amount > current_balance`.
#[allow(clippy::too_many_arguments)]
pub fn prove_withdraw_bundle(
    source_secret: &[u8; 32],
    source_pubkey: &[u8; 32],
    current_ciphertext: &[u8; 64],
    current_balance: u64,
    withdraw_amount: u64,
    seed: &[u8; 32],
) -> SolanaZkResult<WithdrawBundle> {
    let remaining = current_balance
        .checked_sub(withdraw_amount)
        .ok_or(SolanaZkError::InvalidProof)?;
    let (opening_bytes, opening) = kdf_opening(seed, b"withdraw/remaining-opening");
    let comm_pt = pedersen_point(remaining, &opening)?;
    let remaining_commitment = enc_point(&comm_pt)?;
    let current = DecodedCt::decode(current_ciphertext)?;
    let remaining_ciphertext = current.sub_amount(withdraw_amount).encode()?;

    let eq_seed = component_seed(seed, b"withdraw/equality");
    let p = RistrettoPoint::from_bytes(source_pubkey)
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    let _ = p;
    let equality_proof = sigma_proofs::prove_ciphertext_commitment_equality(
        source_secret,
        source_pubkey,
        &remaining_ciphertext,
        &remaining_commitment,
        &opening_bytes,
        remaining,
        &eq_seed,
        CTX_CIPHERTEXT_COMMITMENT_EQUALITY,
    )?;

    let range_seed = component_seed(seed, b"withdraw/range");
    let (range_proof, range_commitments, range_bit_lengths) =
        range_proof::prove_range_instruction(
            &[remaining],
            &[64],
            &[opening_bytes],
            &range_seed,
        )
        .map_err(super::map_range_err)?;

    Ok(WithdrawBundle {
        equality_proof,
        range_proof,
        range_commitments,
        range_bit_lengths,
        remaining_commitment,
        remaining_opening: opening_bytes,
        remaining_ciphertext,
    })
}

/// Transfer bundle outputs.
pub struct TransferBundle {
    /// Equality proof (192 bytes).
    pub equality_proof: [u8; 192],
    /// Batched grouped-3 validity proof (192 bytes).
    pub validity_proof: [u8; 192],
    /// U128 range proof bytes (736 bytes).
    pub range_proof: Vec<u8>,
    /// Range pod commitments (256 bytes).
    pub range_commitments: [u8; 256],
    /// Range pod bit lengths (8 bytes).
    pub range_bit_lengths: [u8; 8],
    /// Lo grouped ciphertext (commitment + 3 handles, 128B).
    pub grouped_lo: Vec<u8>,
    /// Hi grouped ciphertext (128B).
    pub grouped_hi: Vec<u8>,
    /// Remaining-balance commitment (32 bytes).
    pub remaining_commitment: [u8; 32],
    /// Remaining-balance opening (32 bytes).
    pub remaining_opening: [u8; 32],
    /// Remaining-balance ciphertext (64 bytes).
    pub remaining_ciphertext: [u8; 64],
    /// Auditor lo/hi ciphertexts (64 bytes each).
    pub auditor_lo: [u8; 64],
    /// Auditor hi ciphertext.
    pub auditor_hi: [u8; 64],
}

/// Prove a transfer bundle (mirrors `transfer_split_proof_data`
/// with 16-bit lo / 32-bit hi splits and `[64, 16, 32, 16]` U128 range).
#[allow(clippy::too_many_arguments)]
pub fn prove_transfer_bundle(
    source_secret: &[u8; 32],
    source_pubkey: &[u8; 32],
    dest_pubkey: &[u8; 32],
    auditor_pubkey: &[u8; 32],
    current_ciphertext: &[u8; 64],
    current_balance: u64,
    transfer_amount: u64,
    seed: &[u8; 32],
) -> SolanaZkResult<TransferBundle> {
    let (amount_lo, amount_hi) = split_u64(transfer_amount)?;
    let remaining = current_balance
        .checked_sub(transfer_amount)
        .ok_or(SolanaZkError::InvalidProof)?;

    let (o_lo, r_lo) = kdf_opening(seed, b"transfer/opening-lo");
    let (o_hi, r_hi) = kdf_opening(seed, b"transfer/opening-hi");
    let (o_remaining, r_remaining) = kdf_opening(seed, b"transfer/opening-remaining");
    let (o_padding, r_padding) = kdf_opening(seed, b"transfer/opening-padding");

    let p_src = RistrettoPoint::from_bytes(source_pubkey)
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    let p_dst = RistrettoPoint::from_bytes(dest_pubkey)
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    let p_aud = RistrettoPoint::from_bytes(auditor_pubkey)
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    let pubs = [p_src, p_dst, p_aud];
    let (grouped_lo, _) = grouped_encrypt(&pubs, amount_lo, &r_lo)?;
    let (grouped_hi, _) = grouped_encrypt(&pubs, amount_hi, &r_hi)?;

    // Source ElGamal ciphertexts (handle index 0) for balance math.
    let src_lo_ct = DecodedCt {
        c: RistrettoPoint::from_bytes(&grouped_lo[..32])
            .map_err(|_| SolanaZkError::InvalidPoint)?,
        d: RistrettoPoint::from_bytes(&grouped_lo[32..64])
            .map_err(|_| SolanaZkError::InvalidPoint)?,
    };
    let src_hi_ct = DecodedCt {
        c: RistrettoPoint::from_bytes(&grouped_hi[..32])
            .map_err(|_| SolanaZkError::InvalidPoint)?,
        d: RistrettoPoint::from_bytes(&grouped_hi[32..64])
            .map_err(|_| SolanaZkError::InvalidPoint)?,
    };
    let current = DecodedCt::decode(current_ciphertext)?;
    let transfer_total = combine_lo_hi(&src_lo_ct, &src_hi_ct);
    let remaining_ciphertext = DecodedCt {
        c: current.c.add(&transfer_total.c.neg()),
        d: current.d.add(&transfer_total.d.neg()),
    }
    .encode()?;
    let comm_pt = pedersen_point(remaining, &r_remaining)?;
    let remaining_commitment = enc_point(&comm_pt)?;

    // Equality proof over the remaining balance.
    let equality_proof = sigma_proofs::prove_ciphertext_commitment_equality(
        source_secret,
        source_pubkey,
        &remaining_ciphertext,
        &remaining_commitment,
        &o_remaining,
        remaining,
        &component_seed(seed, b"transfer/equality"),
        CTX_CIPHERTEXT_COMMITMENT_EQUALITY,
    )?;

    // Batched grouped-3 validity over lo/hi.
    let mut glo = [0u8; 128];
    let mut ghi = [0u8; 128];
    glo.copy_from_slice(&grouped_lo);
    ghi.copy_from_slice(&grouped_hi);
    let validity_proof = sigma_proofs::prove_batched_grouped_validity_3(
        source_pubkey,
        dest_pubkey,
        auditor_pubkey,
        &glo,
        &ghi,
        amount_lo,
        amount_hi,
        &o_lo,
        &o_hi,
        &component_seed(seed, b"transfer/validity"),
        CTX_BATCHED_GROUPED_VALIDITY_3,
    )?;

    // U128 range: [remaining64, lo16, hi32, padding16].
    let pad_comm = enc_point(&pedersen_point(0, &r_padding)?)?;
    let (range_proof, range_commitments, range_bit_lengths) =
        range_proof::prove_range_instruction(
            &[remaining, amount_lo, amount_hi, 0],
            &[64, 16, 32, 16],
            &[o_remaining, o_lo, o_hi, o_padding],
            &component_seed(seed, b"transfer/range"),
        )
        .map_err(super::map_range_err)?;
    let _ = pad_comm;

    // Auditor ciphertexts (commitment + handle index 2).
    let mut auditor_lo = [0u8; 64];
    let mut auditor_hi = [0u8; 64];
    auditor_lo[..32].copy_from_slice(&grouped_lo[..32]);
    auditor_lo[32..].copy_from_slice(&grouped_lo[96..128]);
    auditor_hi[..32].copy_from_slice(&grouped_hi[..32]);
    auditor_hi[32..].copy_from_slice(&grouped_hi[96..128]);

    Ok(TransferBundle {
        equality_proof,
        validity_proof,
        range_proof,
        range_commitments,
        range_bit_lengths,
        grouped_lo,
        grouped_hi,
        remaining_commitment,
        remaining_opening: o_remaining,
        remaining_ciphertext,
        auditor_lo,
        auditor_hi,
    })
}

/// Fee math: `fee = ceil(amount * rate / 10000)`,
/// `delta = fee * 10000 - amount * rate` (mirrors `calculate_fee`).
pub fn calculate_fee(
    transfer_amount: u64,
    fee_rate_basis_points: u16,
) -> SolanaZkResult<(u64, u64)> {
    let numerator = (transfer_amount as u128)
        .checked_mul(fee_rate_basis_points as u128)
        .ok_or(SolanaZkError::InvalidLength)?;
    let fee = numerator
        .checked_add(9_999)
        .and_then(|v| v.checked_div(10_000))
        .ok_or(SolanaZkError::InvalidLength)?;
    let delta = fee
        .checked_mul(10_000)
        .and_then(|v| v.checked_sub(numerator))
        .ok_or(SolanaZkError::InvalidLength)?;
    Ok((fee as u64, delta as u64))
}

/// Transfer-with-fee bundle outputs.
pub struct TransferWithFeeBundle {
    /// Equality proof (192 bytes).
    pub equality_proof: [u8; 192],
    /// Batched grouped-3 validity proof (192 bytes).
    pub validity_proof: [u8; 192],
    /// Percentage-with-cap proof (256 bytes).
    pub percentage_proof: [u8; 256],
    /// Batched fee validity-2 proof (160 bytes).
    pub fee_validity_proof: [u8; 160],
    /// U256 range proof bytes (800 bytes).
    pub range_proof: Vec<u8>,
    /// Range pod commitments (256 bytes).
    pub range_commitments: [u8; 256],
    /// Range pod bit lengths (8 bytes).
    pub range_bit_lengths: [u8; 8],
    /// Transfer grouped lo/hi (128 bytes each).
    pub grouped_lo: Vec<u8>,
    /// Transfer grouped hi.
    pub grouped_hi: Vec<u8>,
    /// Fee grouped lo/hi (96 bytes each).
    pub fee_grouped_lo: Vec<u8>,
    /// Fee grouped hi.
    pub fee_grouped_hi: Vec<u8>,
    /// Remaining-balance commitment/ciphertext/opening.
    pub remaining_commitment: [u8; 32],
    /// Remaining opening.
    pub remaining_opening: [u8; 32],
    /// Remaining ciphertext.
    pub remaining_ciphertext: [u8; 64],
    /// Combined fee commitment (32 bytes).
    pub fee_commitment: [u8; 32],
    /// Delta commitment (32 bytes).
    pub delta_commitment: [u8; 32],
    /// Claimed commitment (32 bytes).
    pub claimed_commitment: [u8; 32],
    /// Net-transfer commitment (32 bytes).
    pub net_commitment: [u8; 32],
    /// Maximum fee (u64).
    pub max_fee: u64,
}

/// Prove a transfer-with-fee bundle (mirrors
/// `transfer_with_fee_split_proof_data`): equality + validity-3 +
/// percentage-with-cap + fee validity-2 + U256 range over
/// `[remaining64, lo16, hi32, claimed16, complement16, fee_lo16, fee_hi32,
/// net64]`.
#[allow(clippy::too_many_arguments)]
pub fn prove_transfer_with_fee_bundle(
    source_secret: &[u8; 32],
    source_pubkey: &[u8; 32],
    dest_pubkey: &[u8; 32],
    auditor_pubkey: &[u8; 32],
    authority_pubkey: &[u8; 32],
    current_ciphertext: &[u8; 64],
    current_balance: u64,
    transfer_amount: u64,
    fee_rate_basis_points: u16,
    maximum_fee: u64,
    seed: &[u8; 32],
) -> SolanaZkResult<TransferWithFeeBundle> {
    let (amount_lo, amount_hi) = split_u64(transfer_amount)?;
    let remaining = current_balance
        .checked_sub(transfer_amount)
        .ok_or(SolanaZkError::InvalidProof)?;

    // Openings (fresh KDF sub-seeds).
    let (o_lo, r_lo) = kdf_opening(seed, b"fee/opening-t-lo");
    let (o_hi, r_hi) = kdf_opening(seed, b"fee/opening-t-hi");
    let (o_remaining, r_remaining) = kdf_opening(seed, b"fee/opening-remaining");
    let (o_fee_lo, r_fee_lo) = kdf_opening(seed, b"fee/opening-f-lo");
    let (o_fee_hi, r_fee_hi) = kdf_opening(seed, b"fee/opening-f-hi");
    let (o_claimed, r_claimed) = kdf_opening(seed, b"fee/opening-claimed");

    let p_src = RistrettoPoint::from_bytes(source_pubkey)
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    let p_dst = RistrettoPoint::from_bytes(dest_pubkey)
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    let p_aud = RistrettoPoint::from_bytes(auditor_pubkey)
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    let p_auth = RistrettoPoint::from_bytes(authority_pubkey)
        .map_err(|_| SolanaZkError::InvalidPoint)?;

    // Transfer grouped ciphertexts (3 handles: src, dst, auditor).
    let (grouped_lo, _) = grouped_encrypt(&[p_src, p_dst, p_aud], amount_lo, &r_lo)?;
    let (grouped_hi, _) = grouped_encrypt(&[p_src, p_dst, p_aud], amount_hi, &r_hi)?;
    let src_lo_ct = DecodedCt {
        c: RistrettoPoint::from_bytes(&grouped_lo[..32])
            .map_err(|_| SolanaZkError::InvalidPoint)?,
        d: RistrettoPoint::from_bytes(&grouped_lo[32..64])
            .map_err(|_| SolanaZkError::InvalidPoint)?,
    };
    let src_hi_ct = DecodedCt {
        c: RistrettoPoint::from_bytes(&grouped_hi[..32])
            .map_err(|_| SolanaZkError::InvalidPoint)?,
        d: RistrettoPoint::from_bytes(&grouped_hi[32..64])
            .map_err(|_| SolanaZkError::InvalidPoint)?,
    };
    let current = DecodedCt::decode(current_ciphertext)?;
    let transfer_total = combine_lo_hi(&src_lo_ct, &src_hi_ct);
    let remaining_ciphertext = DecodedCt {
        c: current.c.add(&transfer_total.c.neg()),
        d: current.d.add(&transfer_total.d.neg()),
    }
    .encode()?;
    let remaining_commitment = enc_point(&pedersen_point(remaining, &r_remaining)?)?;

    let equality_proof = sigma_proofs::prove_ciphertext_commitment_equality(
        source_secret,
        source_pubkey,
        &remaining_ciphertext,
        &remaining_commitment,
        &o_remaining,
        remaining,
        &component_seed(seed, b"fee/equality"),
        CTX_CIPHERTEXT_COMMITMENT_EQUALITY,
    )?;

    let mut glo = [0u8; 128];
    let mut ghi = [0u8; 128];
    glo.copy_from_slice(&grouped_lo);
    ghi.copy_from_slice(&grouped_hi);
    let validity_proof = sigma_proofs::prove_batched_grouped_validity_3(
        source_pubkey,
        dest_pubkey,
        auditor_pubkey,
        &glo,
        &ghi,
        amount_lo,
        amount_hi,
        &o_lo,
        &o_hi,
        &component_seed(seed, b"fee/validity"),
        CTX_BATCHED_GROUPED_VALIDITY_3,
    )?;

    // Fee math.
    let (raw_fee, raw_delta) = calculate_fee(transfer_amount, fee_rate_basis_points)?;
    let (fee_amount, claimed_delta) = if maximum_fee < raw_fee {
        (maximum_fee, 0)
    } else {
        (raw_fee, raw_delta)
    };
    let net_transfer_amount = transfer_amount
        .checked_sub(fee_amount)
        .ok_or(SolanaZkError::InvalidProof)?;
    let (fee_lo, fee_hi) = split_u64(fee_amount)?;

    // Fee grouped ciphertexts (2 handles: dst, authority).
    let (fee_grouped_lo, _) = grouped_encrypt(&[p_dst, p_auth], fee_lo, &r_fee_lo)?;
    let (fee_grouped_hi, _) = grouped_encrypt(&[p_dst, p_auth], fee_hi, &r_fee_hi)?;

    // Combined commitments: C = C_lo + 2^16 * C_hi (openings likewise).
    let shift16 = scalar_u64(1u64 << TRANSFER_LO_BITS);
    let t_lo_c = RistrettoPoint::from_bytes(&grouped_lo[..32])
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    let t_hi_c = RistrettoPoint::from_bytes(&grouped_hi[..32])
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    let combined_t_comm = t_lo_c.add(&t_hi_c.mul(&shift16));
    let combined_t_open = r_lo.add(&r_hi.mul(&shift16));
    let f_lo_c = RistrettoPoint::from_bytes(&fee_grouped_lo[..32])
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    let f_hi_c = RistrettoPoint::from_bytes(&fee_grouped_hi[..32])
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    let combined_f_comm = f_lo_c.add(&f_hi_c.mul(&shift16));
    let combined_f_open = r_fee_lo.add(&r_fee_hi.mul(&shift16));

    // Net transfer commitment/opening.
    let net_comm = combined_t_comm.add(&combined_f_comm.neg());
    let net_open = combined_t_open.add(&combined_f_open.neg());

    // Delta commitment/opening: fee_comm * 10000 - transfer_comm * rate.
    let rate_s = scalar_u64(fee_rate_basis_points as u64);
    let base_s = scalar_u64(MAX_FEE_BASIS_POINTS);
    let delta_comm = combined_f_comm.mul(&base_s).add(&combined_t_comm.mul(&rate_s).neg());
    let delta_open = combined_f_open.mul(&base_s).add(&combined_t_open.mul(&rate_s).neg());

    // Claimed commitment (fresh Pedersen).
    let claimed_comm_pt = pedersen_point(claimed_delta, &r_claimed)?;
    let claimed_commitment = enc_point(&claimed_comm_pt)?;

    let percentage_proof = sigma_proofs::prove_percentage_with_cap(
        &enc_point(&combined_f_comm)?,
        &combined_f_open.to_bytes_le_checked()?,
        fee_amount,
        &enc_point(&delta_comm)?,
        &delta_open.to_bytes_le_checked()?,
        claimed_delta,
        &claimed_commitment,
        &o_claimed,
        maximum_fee,
        &component_seed(seed, b"fee/percentage"),
        CTX_PERCENTAGE_WITH_CAP,
    )?;

    // Fee ciphertext validity (batched 2-handle).
    let mut fglo = [0u8; 96];
    let mut fghi = [0u8; 96];
    fglo.copy_from_slice(&fee_grouped_lo);
    fghi.copy_from_slice(&fee_grouped_hi);
    let fee_validity_proof = sigma_proofs::prove_batched_grouped_validity_2(
        dest_pubkey,
        authority_pubkey,
        &fglo,
        &fghi,
        fee_lo,
        fee_hi,
        &o_fee_lo,
        &o_fee_hi,
        &component_seed(seed, b"fee/fee-validity"),
        CTX_BATCHED_GROUPED_VALIDITY_2,
    )?;

    // U256 range over 8 slots.
    let complement_amount = MAX_FEE_BASIS_POINTS_SUB_ONE
        .checked_sub(claimed_delta)
        .ok_or(SolanaZkError::InvalidProof)?;
    let base9999 = pedersen_point(MAX_FEE_BASIS_POINTS_SUB_ONE, &Scalar::zero())?;
    let _claimed_complement_comm = base9999.add(&claimed_comm_pt.neg());
    let claimed_complement_open = r_claimed.neg();
    let mut claimed_complement_opening = [0u8; 32];
    claimed_complement_open.to_bytes_le(&mut claimed_complement_opening);

    let mut combined_f_open_bytes = [0u8; 32];
    combined_f_open.to_bytes_le(&mut combined_f_open_bytes);
    let mut combined_t_open_bytes = [0u8; 32];
    combined_t_open.to_bytes_le(&mut combined_t_open_bytes);
    let mut net_open_bytes = [0u8; 32];
    net_open.to_bytes_le(&mut net_open_bytes);
    let mut delta_open_bytes = [0u8; 32];
    delta_open.to_bytes_le(&mut delta_open_bytes);

    let (range_proof, range_commitments, range_bit_lengths) =
        range_proof::prove_range_instruction(
            &[
                remaining,
                amount_lo,
                amount_hi,
                claimed_delta,
                complement_amount,
                fee_lo,
                fee_hi,
                net_transfer_amount,
            ],
            &[64, 16, 32, 16, 16, 16, 32, 64],
            &[
                o_remaining,
                o_lo,
                o_hi,
                o_claimed,
                claimed_complement_opening,
                o_fee_lo,
                o_fee_hi,
                net_open_bytes,
            ],
            &component_seed(seed, b"fee/range"),
        )
        .map_err(super::map_range_err)?;

    Ok(TransferWithFeeBundle {
        equality_proof,
        validity_proof,
        percentage_proof,
        fee_validity_proof,
        range_proof,
        range_commitments,
        range_bit_lengths,
        grouped_lo,
        grouped_hi,
        fee_grouped_lo,
        fee_grouped_hi,
        remaining_commitment,
        remaining_opening: o_remaining,
        remaining_ciphertext,
        fee_commitment: enc_point(&combined_f_comm)?,
        delta_commitment: enc_point(&delta_comm)?,
        claimed_commitment,
        net_commitment: enc_point(&net_comm)?,
        max_fee: maximum_fee,
    })
}

/// `MAX_FEE_BASIS_POINTS - 1` (complement range slot).
pub const MAX_FEE_BASIS_POINTS_SUB_ONE: u64 = MAX_FEE_BASIS_POINTS - 1;

/// Scalar little-endian encoding helper for openings reused as
/// commitment inputs across combined values.
trait ScalarLeExt {
    /// Encode, failing on internal error (infallible here).
    fn to_bytes_le_checked(&self) -> SolanaZkResult<[u8; 32]>;
}

impl ScalarLeExt for Scalar {
    fn to_bytes_le_checked(&self) -> SolanaZkResult<[u8; 32]> {
        let mut out = [0u8; 32];
        self.to_bytes_le(&mut out);
        Ok(out)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::solana_zk::sigma_proofs as sigma_proofs;

    /// Withdraw bundle roundtrip (both proofs verify under
    /// instruction transcripts).
    #[test]
    fn withdraw_bundle_roundtrip() {
        let secret = [2u8; 32];
        let pubkey = crate::solana_zk::elgamal_pubkey_from_secret(&secret).unwrap();
        let current_ct =
            crate::solana_zk::elgamal_encrypt_with(&pubkey, 100, &[3u8; 32]).unwrap();
        let b = prove_withdraw_bundle(
            &secret,
            &pubkey,
            &current_ct,
            100,
            45,
            &[9u8; 32],
        )
        .unwrap();
        assert_eq!(b.range_proof.len(), 672);
        assert_eq!(&b.range_bit_lengths[..1], &[64]);
        sigma_proofs::verify_ciphertext_commitment_equality(
            &pubkey,
            &b.remaining_ciphertext,
            &b.remaining_commitment,
            &b.equality_proof,
            sigma_proofs::CTX_CIPHERTEXT_COMMITMENT_EQUALITY,
        )
        .unwrap();
        range_proof::verify_range_instruction(
            &b.range_proof,
            &b.range_commitments,
            &b.range_bit_lengths,
        )
        .unwrap();
        // Overspend fails.
        assert!(prove_withdraw_bundle(
            &secret, &pubkey, &current_ct, 100, 101, &[9u8; 32],
        )
        .is_err());
    }

    /// Transfer bundle roundtrip (all three proofs verify).
    #[test]
    fn transfer_bundle_roundtrip() {
        let s = [2u8; 32];
        let d = [4u8; 32];
        let ps = crate::solana_zk::elgamal_pubkey_from_secret(&s).unwrap();
        let pd = crate::solana_zk::elgamal_pubkey_from_secret(&d).unwrap();
        let pa = [0u8; 32]; // identity auditor
        let current_ct =
            crate::solana_zk::elgamal_encrypt_with(&ps, 1000, &[3u8; 32]).unwrap();
        let b = prove_transfer_bundle(
            &s, &ps, &pd, &pa, &current_ct, 1000, 55, &[9u8; 32],
        )
        .unwrap();
        assert_eq!(b.range_proof.len(), 736);
        assert_eq!(b.grouped_lo.len(), 128);
        assert_eq!(b.grouped_hi.len(), 128);
        let mut glo = [0u8; 128];
        let mut ghi = [0u8; 128];
        glo.copy_from_slice(&b.grouped_lo);
        ghi.copy_from_slice(&b.grouped_hi);
        sigma_proofs::verify_batched_grouped_validity_3(
            &ps, &pd, &pa, &glo, &ghi, &b.validity_proof,
            sigma_proofs::CTX_BATCHED_GROUPED_VALIDITY_3,
        )
        .unwrap();
        sigma_proofs::verify_ciphertext_commitment_equality(
            &ps,
            &b.remaining_ciphertext,
            &b.remaining_commitment,
            &b.equality_proof,
            sigma_proofs::CTX_CIPHERTEXT_COMMITMENT_EQUALITY,
        )
        .unwrap();
        range_proof::verify_range_instruction(
            &b.range_proof,
            &b.range_commitments,
            &b.range_bit_lengths,
        )
        .unwrap();
    }

    /// Transfer-with-fee bundle roundtrip (all five verify).
    #[test]
    fn fee_bundle_roundtrip() {
        let s = [2u8; 32];
        let d = [4u8; 32];
        let a = [6u8; 32];
        let ps = crate::solana_zk::elgamal_pubkey_from_secret(&s).unwrap();
        let pd = crate::solana_zk::elgamal_pubkey_from_secret(&d).unwrap();
        let pa = crate::solana_zk::elgamal_pubkey_from_secret(&a).unwrap();
        let current_ct =
            crate::solana_zk::elgamal_encrypt_with(&ps, 10000, &[3u8; 32]).unwrap();
        let b = prove_transfer_with_fee_bundle(
            &s, &ps, &pd, &pa, &pa, &current_ct, 10000, 1000, 400, 50, &[9u8; 32],
        )
        .unwrap();
        assert_eq!(b.range_proof.len(), 800);
        assert_eq!(b.percentage_proof.len(), 256);
        assert_eq!(b.fee_validity_proof.len(), 160);
        assert_eq!(b.max_fee, 50);
        // fee = ceil(1000*400/10000) = 40 < 50 -> (40, delta=0)
        let mut glo = [0u8; 128];
        let mut ghi = [0u8; 128];
        glo.copy_from_slice(&b.grouped_lo);
        ghi.copy_from_slice(&b.grouped_hi);
        sigma_proofs::verify_batched_grouped_validity_3(
            &ps, &pd, &pa, &glo, &ghi, &b.validity_proof,
            sigma_proofs::CTX_BATCHED_GROUPED_VALIDITY_3,
        )
        .unwrap();
        let mut fglo = [0u8; 96];
        let mut fghi = [0u8; 96];
        fglo.copy_from_slice(&b.fee_grouped_lo);
        fghi.copy_from_slice(&b.fee_grouped_hi);
        sigma_proofs::verify_batched_grouped_validity_2(
            &pd, &pa, &fglo, &fghi, &b.fee_validity_proof,
            sigma_proofs::CTX_BATCHED_GROUPED_VALIDITY_2,
        )
        .unwrap();
        sigma_proofs::verify_percentage_with_cap(
            &b.fee_commitment,
            &b.delta_commitment,
            &b.claimed_commitment,
            b.max_fee,
            &b.percentage_proof,
            sigma_proofs::CTX_PERCENTAGE_WITH_CAP,
        )
        .unwrap();
        sigma_proofs::verify_ciphertext_commitment_equality(
            &ps,
            &b.remaining_ciphertext,
            &b.remaining_commitment,
            &b.equality_proof,
            sigma_proofs::CTX_CIPHERTEXT_COMMITMENT_EQUALITY,
        )
        .unwrap();
        range_proof::verify_range_instruction(
            &b.range_proof,
            &b.range_commitments,
            &b.range_bit_lengths,
        )
        .unwrap();
    }
}
