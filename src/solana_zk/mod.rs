//! Solana confidential-transfer ZK (dalek-compatible, no unsafe).
//!
//! /// Dalek Bulletproofs (classic 2018 range proofs) + Solana
//! Sigma protocols (equality, ciphertext-validity, fee-sigma, pubkey-validity,
//! zero-balance, withdraw/transfer bundles). This is NOT Monero
//! Bulletproofs+ (`crate::monero`) and NOT Groth16/Halo2 (`crate::zk`):
//! different transcripts, different layouts, not interchangeable.
//!
//! Current status: real length + Ristretto validation via
//! [`crate::curve::RistrettoPoint`]; provers are stubs returning
//! [`SolanaZkError::BackendNotLinked`]. Wire dalek `bulletproofs` +
//! Solana `zk-sdk` crates here, then the `connector::ffi` /
//! `connector::wasm` surface below forwards to these functions.

extern crate alloc;

/// Compiled-in baby steps, `no_std` builds only. `std`
/// builds decode against a lazily built affine runtime table instead, so
/// the ~2 MiB statics below never enter WASM / `.so` binaries.
#[cfg(not(feature = "std"))]
pub(crate) mod bsgs_table;
pub mod aead_gcm_siv;
pub mod bundles;
pub mod range_proof;
pub mod sigma_proofs;

use crate::curve::traits::CurvePoint;
use crate::curve::RistrettoPoint;
use alloc::vec::Vec;
#[cfg(feature = "std")]
use crate::curve::ed25519::Fe;
#[cfg(feature = "std")]
use std::sync::OnceLock;

/// ElGamal pubkey length (compressed Ristretto, 32 bytes).
pub const ELGAMAL_PUBKEY_LEN: usize = 32;

/// ElGamal ciphertext length (2 x compressed Ristretto).
pub const ELGAMAL_CIPHERTEXT_LEN: usize = 64;

/// AES decryptable-balance length: 12-byte nonce || 8-byte
/// ciphertext || 16-byte tag (matches `solana_zk_sdk_pod::AE_CIPHERTEXT_LEN`).
pub const AE_CIPHERTEXT_LEN: usize = 36;

/// Range proofs cover 64-bit amounts (split lo/hi 32-bit).
pub const RANGE_BITS: u32 = 64;

/// Maximum batched amounts per range proof (mirrors Monero 16).
pub const MAX_BATCH: usize = 16;

/// Errors for the Solana ZK module.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SolanaZkError {
    /// Input has the wrong length.
    InvalidLength,
    /// Ristretto point failed to decode.
    InvalidPoint,
    /// Proof blob is empty or has the wrong shape.
    InvalidProof,
    /// Backend-internal error (unreachable via public provers;
    /// kept for forward compatibility of the error code surface).
    BackendNotLinked,
}

/// Result alias for the Solana ZK module.
pub type SolanaZkResult<T> = core::result::Result<T, SolanaZkError>;

/// Length-checked ElGamal pubkey (32 bytes).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ElGamalPubkey(pub [u8; ELGAMAL_PUBKEY_LEN]);

/// Length-checked ElGamal ciphertext (64 bytes).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ElGamalCiphertext(pub Vec<u8>);

/// Length-checked AES decryptable balance (32 bytes).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AeCiphertext(pub [u8; AE_CIPHERTEXT_LEN]);

/// Decode one Ristretto point (RFC 9496 decompress).
fn decode_ristretto(bytes: &[u8]) -> SolanaZkResult<()> {
    if bytes.len() != 32 {
        return Err(SolanaZkError::InvalidLength);
    }
    let mut fixed = [0u8; 32];
    fixed.copy_from_slice(bytes);
    RistrettoPoint::decode(&fixed).map(|_| ()).map_err(|_| SolanaZkError::InvalidPoint)
}

/// Validate ElGamal pubkey (length + Ristretto decode).
pub fn elgamal_pubkey_from_bytes(bytes: &[u8]) -> SolanaZkResult<ElGamalPubkey> {
    if bytes.len() != ELGAMAL_PUBKEY_LEN {
        return Err(SolanaZkError::InvalidLength);
    }
    decode_ristretto(bytes)?;
    let mut out = [0u8; ELGAMAL_PUBKEY_LEN];
    out.copy_from_slice(bytes);
    Ok(ElGamalPubkey(out))
}

/// Validate ElGamal ciphertext (length + both halves decode).
pub fn elgamal_ciphertext_from_bytes(
    bytes: &[u8],
) -> SolanaZkResult<ElGamalCiphertext> {
    if bytes.len() != ELGAMAL_CIPHERTEXT_LEN {
        return Err(SolanaZkError::InvalidLength);
    }
    decode_ristretto(&bytes[..32])?;
    decode_ristretto(&bytes[32..])?;
    Ok(ElGamalCiphertext(bytes.to_vec()))
}

/// Validate AES decryptable-balance length (32 bytes).
pub fn ae_ciphertext_from_bytes(bytes: &[u8]) -> SolanaZkResult<AeCiphertext> {
    if bytes.len() != AE_CIPHERTEXT_LEN {
        return Err(SolanaZkError::InvalidLength);
    }
    let mut out = [0u8; AE_CIPHERTEXT_LEN];
    out.copy_from_slice(bytes);
    Ok(AeCiphertext(out))
}

/// Validate a raw 32-byte pubkey slice (FFI/WASM helper).
pub fn validate_pubkey(bytes: &[u8]) -> SolanaZkResult<()> {
    elgamal_pubkey_from_bytes(bytes).map(|_| ())
}

/// Validate a raw 64-byte ciphertext slice (FFI/WASM helper).
pub fn validate_ciphertext(bytes: &[u8]) -> SolanaZkResult<()> {
    elgamal_ciphertext_from_bytes(bytes).map(|_| ())
}

/// Shared prover-input gate (1..=MAX_BATCH amounts, 32-byte
/// openings, 32-byte seed). Real proving replaces the body with dalek +
/// zk-sdk calls; the gate stays.
fn check_range_inputs(
    amounts_le: &[[u8; 8]],
    openings: &[[u8; 32]],
    seed: &[u8; 32],
) -> SolanaZkResult<()> {
    let _ = seed;
    if amounts_le.is_empty()
        || amounts_le.len() > MAX_BATCH
        || openings.len() != amounts_le.len()
    {
        return Err(SolanaZkError::InvalidLength);
    }
    Ok(())
}

/// Pedersen `H` = hash-to-point of the basepoint (SHA3-512,
/// per zk-elgamal-proof `pedersen.rs`). Computed per call; no statics so
/// `no_std` stays clean.
pub(crate) fn h_point() -> SolanaZkResult<RistrettoPoint> {
    let mut g_enc = [0u8; 32];
    RistrettoPoint::generator()
        .to_bytes_compressed(&mut g_enc)
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    let wide = crate::hash::sha3_512(&g_enc).map_err(|_| SolanaZkError::InvalidPoint)?;
    Ok(RistrettoPoint::from_uniform_bytes(&wide))
}

/// Scalar from u64 amount (LE bytes, always < L).
pub(crate) fn amount_scalar(v: u64) -> crate::curve::ed25519::Scalar {
    let mut b = [0u8; 32];
    b[..8].copy_from_slice(&v.to_le_bytes());
    crate::curve::ed25519::Scalar::from_bytes_mod_order(&b)
}

/// Scalar from u64 amount (LE bytes, always < L).
fn scalar_from_u64(v: u64) -> crate::curve::ed25519::Scalar {
    amount_scalar(v)
}

/// Strict canonical scalar (rejects >= L); maps to InvalidScalar.
fn strict_scalar(
    bytes: &[u8; 32],
) -> SolanaZkResult<crate::curve::ed25519::Scalar> {
    crate::curve::ed25519::Scalar::from_bytes_le(bytes)
        .map_err(|_| SolanaZkError::InvalidPoint)
}

/// Fully implemented Twisted ElGamal pubkey derivation:
/// `P = s^{-1} * H` (zk-elgamal-proof `ElGamalPubkey::new`). Rejects zero /
/// non-canonical secrets.
pub fn elgamal_pubkey_from_secret(
    secret: &[u8; 32],
) -> SolanaZkResult<[u8; 32]> {
    let s = strict_scalar(secret)?;
    if s.is_zero() {
        return Err(SolanaZkError::InvalidPoint);
    }
    let s_inv = s.invert().map_err(|_| SolanaZkError::InvalidPoint)?;
    let p = h_point()?.mul(&s_inv);
    let mut out = [0u8; 32];
    p.to_bytes_compressed(&mut out)
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    Ok(out)
}

/// Fully implemented deterministic encrypt-with-opening:
/// `C = m*G + r*H`, `Dh = r*P` (zk-elgamal-proof `ElGamal::encrypt_with`).
/// Returns 64-byte `commitment || handle`.
pub fn elgamal_encrypt_with(
    pubkey: &[u8; 32],
    amount: u64,
    opening: &[u8; 32],
) -> SolanaZkResult<[u8; 64]> {
    let p = RistrettoPoint::from_bytes(pubkey).map_err(|_| SolanaZkError::InvalidPoint)?;
    let r = strict_scalar(opening)?;
    let m = scalar_from_u64(amount);
    let g = RistrettoPoint::generator();
    let h = h_point()?;
    let commitment = g.mul(&m).add(&h.mul(&r));
    let handle = p.mul(&r);
    let mut out = [0u8; 64];
    commitment
        .to_bytes_compressed(&mut out[..32])
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    handle
        .to_bytes_compressed(&mut out[32..])
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    Ok(out)
}

/// Fully implemented decrypt: recover `m*G = C - s*Dh`
/// (zk-elgamal-proof `ElGamal::decrypt`). Returns the 32-byte encoding of
/// `m*G` for discrete-log decoding.
pub fn elgamal_decrypt_point(
    secret: &[u8; 32],
    ciphertext: &[u8; 64],
) -> SolanaZkResult<[u8; 32]> {
    let s = strict_scalar(secret)?;
    let c = RistrettoPoint::from_bytes(&ciphertext[..32])
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    let dh = RistrettoPoint::from_bytes(&ciphertext[32..])
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    let m_g = c.add(&dh.mul(&s).neg());
    let mut out = [0u8; 32];
    m_g.to_bytes_compressed(&mut out)
        .map_err(|_| SolanaZkError::InvalidPoint)?;
    Ok(out)
}

/// Fully implemented u32 decrypt via baby-step giant-step
/// (2^16 babies x 2^16 giants, covers the full 0..2^32 range).
/// Returns `None` as `InvalidProof` when the point is not in range.
/// Backend is dual: `std` builds use a lazily built affine runtime table
/// (no static bytes in the binary); `no_std` builds use the compiled-in
/// [`bsgs_table`] statics. Builds the giant-step factor per call; for batch
/// wallet scans build one [`DiscreteLogTable`] and reuse it.
pub fn elgamal_decrypt_u32(
    secret: &[u8; 32],
    ciphertext: &[u8; 64],
) -> SolanaZkResult<u64> {
    let m_g_enc = elgamal_decrypt_point(secret, ciphertext)?;
    let table = DiscreteLogTable::build();
    table.decode(&m_g_enc).ok_or(SolanaZkError::InvalidProof)
}

/// Reusable BSGS decoder for discrete logs base `G` over
/// 0..2^32 (Monero-style `cached_exponet` pattern: build once, decode many).
/// Dual backend, same 2^16 x 2^16 split, same results:
/// * `std`: [`decode`] consults a lazily built affine runtime table
///   (`BABY_CACHE`), so WASM / `.so` binaries carry zero table bytes.
///   One-time ~0.5 s build (65536 adds + one Montgomery batch inversion +
///   sort) and ~4 MiB heap, amortized over the process.
/// * `no_std`: [`decode`] uses the `@generated` [`bsgs_table`] statics
///   (2^16 sorted encodings + parallel `u16` values).
///   The giant-step factor `-(2^16 * G)` is computed once at
///   [`DiscreteLogTable::build`] and reused by every [`DiscreteLogTable::decode`].
///   (Chunked giants sharing one Montgomery batch inversion over Ristretto
///   encodings were benchmarked and reverted: RFC 9496 encoding needs
///   `sqrt_ratio_m1` per point, so batching the Z-inversion saves nothing
///   measurable there. Batching IS used where it pays: building the affine
///   runtime table and normalizing affine giant steps.) Zero heap allocation
///   on the `no_std` path.
pub struct DiscreteLogTable {
    /// Hoisted giant-step factor `-(2^16 * G)` (`no_std`
    /// path; the `std` path uses the cached quotient-space factor).
    #[cfg(not(feature = "std"))]
    factor: RistrettoPoint,
}

/// Runtime BSGS context for `std` builds: sorted affine
/// `[8]P` keys plus the quotient-space giant factor. Keying on `[8]P`
/// (not raw affine coords) is load-bearing: this crate's Ristretto decode
/// forces `x = |…|`, so a decoded point generally sits on a different
/// Edwards representative than the add-chain builds for the same encoding.
/// `[8]` quotients out exactly that ambiguity (Ristretto = Edwards / E[8]),
/// and BSGS stays correct by linearity. Key uniqueness over all babies is
/// asserted at build: a duplicate would mean silent wrong amounts.
#[cfg(feature = "std")]
struct RuntimeCtx {
    table: Vec<([u8; 64], u16)>,
    factor8: RistrettoPoint,
}

/// Process-global BSGS context (`std` only).
#[cfg(feature = "std")]
static CTX_CACHE: OnceLock<RuntimeCtx> = OnceLock::new();

impl DiscreteLogTable {
    /// Babies per giant step (static and runtime tables).
    const BABY: usize = 1 << 16;
    /// Giant steps for the full 0..2^32 range (2^16 x 2^16).
    const GIANT: usize = 1 << 16;
    /// Giants per Montgomery batch on the `std` affine path
    /// (128 x (3 x 32 B) coords + 128 x 32 B scratch ~= 16 KiB of stack).
    #[cfg(feature = "std")]
    const CHUNK: usize = 128;

    /// One scalar mul up front on `no_std`; trivial on `std`
    /// (giant factor lives in the cached [`RuntimeCtx`]).
    pub fn build() -> Self {
        #[cfg(not(feature = "std"))]
        {
            Self { factor: Self::factor_neg() }
        }
        #[cfg(feature = "std")]
        {
            Self {}
        }
    }

    /// Giant-step factor `-(2^16 * G)` (one scalar mul).
    /// Used by the `no_std` decoder directly and mapped through `[8]` once
    /// for the cached `std` quotient-space factor.
    fn factor_neg() -> RistrettoPoint {
        let mut f_scalar_bytes = [0u8; 32];
        f_scalar_bytes[..4].copy_from_slice(&(1u32 << 16).to_le_bytes());
        let f_scalar =
            crate::curve::ed25519::Scalar::from_bytes_mod_order(&f_scalar_bytes);
        RistrettoPoint::generator().mul(&f_scalar).neg()
    }

    /// Decode `encode(m*G)` to `m` (`None` when out of range).
    pub fn decode(&self, target_enc: &[u8; 32]) -> Option<u64> {
        #[cfg(feature = "std")]
        {
            let _ = self;
            Self::decode_runtime(target_enc)
        }
        #[cfg(not(feature = "std"))]
        {
            Self::decode_static(&self.factor, target_enc)
        }
    }

    /// `no_std` decode against the compiled-in Ristretto
    /// statics (one sqrt-encode per giant step, binary search per step).
    #[cfg(not(feature = "std"))]
    fn decode_static(factor: &RistrettoPoint, target_enc: &[u8; 32]) -> Option<u64> {
        let target = RistrettoPoint::from_bytes(target_enc).ok()?;
        let mut giant = target;
        for i in 0..Self::GIANT {
            let mut enc = [0u8; 32];
            if giant.to_bytes_compressed(&mut enc).is_err() {
                return None;
            }
            if let Ok(pos) = bsgs_table::BSGS_BABY_ENC.binary_search(&enc) {
                return Some(
                    (i as u64) * (Self::BABY as u64)
                        + (bsgs_table::BSGS_BABY_VAL[pos] as u64),
                );
            }
            giant = giant.add(factor);
        }
        None
    }

    /// Cofactor map `[8]P` (three doublings, no sqrt): maps
    /// every Edwards representative of a Ristretto element to one canonical
    /// affine key input.
    #[cfg(feature = "std")]
    fn mul8(p: &RistrettoPoint) -> RistrettoPoint {
        use crate::curve::ed25519::Ed25519Point;
        let e = p.as_ed25519().as_extended();
        let e8 = e.double().double().double();
        RistrettoPoint::from_ed25519(Ed25519Point::from_extended(e8))
    }

    /// Build + sort the 2^16 quotient-space baby table: one
    /// Montgomery batch inversion for all points, canonical LE byte keys,
    /// duplicate-key assert (fail-closed: a duplicate would decode wrong
    /// amounts silently).
    #[cfg(feature = "std")]
    fn build_runtime_ctx() -> RuntimeCtx {
        const N: usize = 1 << 16;
        let g = RistrettoPoint::generator();
        let g8 = Self::mul8(&g);
        // Giant factor in quotient space, cached with the table.
        let factor8 = Self::mul8(&Self::factor_neg());
        let mut xs: Vec<Fe> = Vec::with_capacity(N);
        let mut ys: Vec<Fe> = Vec::with_capacity(N);
        let mut zs: Vec<Fe> = Vec::with_capacity(N);
        let mut cur = RistrettoPoint::identity();
        for _ in 0..N {
            let e = cur.as_ed25519().as_extended();
            xs.push(e.x);
            ys.push(e.y);
            zs.push(e.z);
            cur = cur.add(&g8);
        }
        // Single Montgomery batch inversion over all Z coordinates.
        let mut scratch = zs.clone();
        for k in 1..N {
            scratch[k] = scratch[k].mul(&scratch[k - 1]);
        }
        let mut inv = scratch[N - 1].invert().expect("baby Z nonzero");
        for k in (0..N).rev() {
            let prev = if k == 0 { Fe::one() } else { scratch[k - 1] };
            let zinv = inv.mul(&prev);
            inv = inv.mul(&zs[k]);
            scratch[k] = zinv;
        }
        let mut pairs: Vec<([u8; 64], u16)> = Vec::with_capacity(N);
        for k in 0..N {
            let x = xs[k].mul(&scratch[k]);
            let y = ys[k].mul(&scratch[k]);
            let mut key = [0u8; 64];
            let mut xb = [0u8; 32];
            let mut yb = [0u8; 32];
            x.to_bytes_le(&mut xb);
            y.to_bytes_le(&mut yb);
            key[..32].copy_from_slice(&xb);
            key[32..].copy_from_slice(&yb);
            pairs.push((key, k as u16));
        }
        pairs.sort_by_key(|a| a.0);
        assert!(
            pairs.windows(2).all(|w| w[0].0 != w[1].0),
            "duplicate [8]-baby key: quotient assumption broken"
        );
        RuntimeCtx { table: pairs, factor8 }
    }

    /// Montgomery batch inversion over a giant chunk
    /// (all Z nonzero for curve points). `false` is unreachable; the caller
    /// falls back to per-point `to_affine` if it ever triggers.
    #[cfg(feature = "std")]
    fn batch_invert_chunk(
        zs: &[Fe; Self::CHUNK],
        inv_out: &mut [Fe; Self::CHUNK],
    ) -> bool {
        inv_out.copy_from_slice(zs);
        for k in 1..Self::CHUNK {
            inv_out[k] = inv_out[k].mul(&inv_out[k - 1]);
        }
        let mut inv = match inv_out[Self::CHUNK - 1].invert() {
            Ok(v) => v,
            Err(_) => return false,
        };
        for k in (0..Self::CHUNK).rev() {
            let prev = if k == 0 { Fe::one() } else { inv_out[k - 1] };
            inv_out[k] = inv.mul(&prev);
            inv = inv.mul(&zs[k]);
        }
        true
    }

    /// `std` decode against the quotient-space runtime table:
    /// map the target once, then chunked giants share one batch inversion
    /// per chunk (affine compare needs no Ristretto sqrt-encode, so batching
    /// pays off here).
    #[cfg(feature = "std")]
    fn decode_runtime(target_enc: &[u8; 32]) -> Option<u64> {
        use crate::curve::ed25519::Extended;
        let ctx: &RuntimeCtx = CTX_CACHE.get_or_init(Self::build_runtime_ctx);
        let target = RistrettoPoint::from_bytes(target_enc).ok()?;
        let mut giant = Self::mul8(&target);
        let mut key = [0u8; 64];
        let mut i_base: u64 = 0;
        while (i_base as usize) < Self::GIANT {
            let mut xs = [Fe::zero(); Self::CHUNK];
            let mut ys = [Fe::zero(); Self::CHUNK];
            let mut zs = [Fe::zero(); Self::CHUNK];
            for k in 0..Self::CHUNK {
                let e = giant.as_ed25519().as_extended();
                xs[k] = e.x;
                ys[k] = e.y;
                zs[k] = e.z;
                giant = giant.add(&ctx.factor8);
            }
            let mut zinvs = [Fe::zero(); Self::CHUNK];
            let batched = Self::batch_invert_chunk(&zs, &mut zinvs);
            for k in 0..Self::CHUNK {
                let (x, y) = if batched {
                    (xs[k].mul(&zinvs[k]), ys[k].mul(&zinvs[k]))
                } else {
                    Extended { x: xs[k], y: ys[k], z: zs[k], t: Fe::zero() }
                        .to_affine()
                        .ok()?
                };
                let mut xb = [0u8; 32];
                let mut yb = [0u8; 32];
                x.to_bytes_le(&mut xb);
                y.to_bytes_le(&mut yb);
                key[..32].copy_from_slice(&xb);
                key[32..].copy_from_slice(&yb);
                if let Ok(pos) =
                    ctx.table.binary_search_by(|(k, _)| k.cmp(&key))
                {
                    return Some(
                        (i_base + k as u64) * (Self::BABY as u64)
                            + (ctx.table[pos].1 as u64),
                    );
                }
            }
            i_base += Self::CHUNK as u64;
        }
        None
    }
}



/// Map range-proof errors onto the backend error type.
fn map_range_err(e: range_proof::RangeError) -> SolanaZkError {
    use range_proof::RangeError as R;
    match e {
        R::AlgebraicRelation | R::InvalidProof | R::IdentityPoint
        | R::IdentityCommitment | R::InvalidPoint | R::InvalidScalar => {
            SolanaZkError::InvalidProof
        }
        R::Deserialization | R::VectorLengthMismatch | R::InnerProductLengthMismatch | R::InvalidBitSize => {
            SolanaZkError::InvalidLength
        }
        R::MaximumGeneratorLengthExceeded | R::Internal => {
            SolanaZkError::BackendNotLinked
        }
    }
}

/// Real aggregated range prover with the exact on-chain
/// instruction transcript (`batched-range-proof-instruction` + padded pod
/// context): each amount gets a 64-bit range (Token-2022 U64-batch shape),
/// aggregated into one proof via the zero-dep Bulletproofs port. Randomness
/// from the caller seed. Returns `(proof, pod_commitments, pod_bit_lengths)`
/// so callers can persist the exact instruction context alongside the proof.
pub fn prove_batched_range(
    amounts_le: &[[u8; 8]],
    openings: &[[u8; 32]],
    seed: &[u8; 32],
) -> SolanaZkResult<(Vec<u8>, [u8; 256], [u8; 8])> {
    check_range_inputs(amounts_le, openings, seed)?;
    let amounts: Vec<u64> =
        amounts_le.iter().map(|le| u64::from_le_bytes(*le)).collect();
    let bits = vec![64usize; amounts.len()];
    range_proof::prove_range_instruction(&amounts, &bits, openings, seed)
        .map_err(map_range_err)
}

/// Verify an aggregated 64-bit-per-amount range proof against
/// the on-chain instruction transcript (pod context required: 256-byte padded
/// commitments + 8-byte padded bit lengths, as emitted by
/// [`prove_batched_range`]).
pub fn verify_batched_range(
    proof: &[u8],
    pod_commitments: &[u8; 256],
    pod_bit_lengths: &[u8; 8],
) -> SolanaZkResult<()> {
    range_proof::verify_range_instruction(proof, pod_commitments, pod_bit_lengths)
        .map_err(map_range_err)
}

/// Withdraw bundle prover (equality + U64 range over the
/// remaining balance, all under on-chain instruction transcripts). See
/// [`bundles::prove_withdraw_bundle`].
pub fn prove_withdraw(
    source_secret: &[u8; 32],
    source_pubkey: &[u8; 32],
    current_ciphertext: &[u8; 64],
    current_balance: u64,
    withdraw_amount: u64,
    seed: &[u8; 32],
) -> SolanaZkResult<bundles::WithdrawBundle> {
    bundles::prove_withdraw_bundle(
        source_secret,
        source_pubkey,
        current_ciphertext,
        current_balance,
        withdraw_amount,
        seed,
    )
}

/// Transfer bundle prover (equality + batched validity-3 +
/// U128 range, all under on-chain instruction transcripts). Auditor pubkey
/// may be identity (no auditor). See [`bundles::prove_transfer_bundle`].
#[allow(clippy::too_many_arguments)]
pub fn prove_transfer(
    source_secret: &[u8; 32],
    source_pubkey: &[u8; 32],
    dest_pubkey: &[u8; 32],
    auditor_pubkey: &[u8; 32],
    current_ciphertext: &[u8; 64],
    current_balance: u64,
    transfer_amount: u64,
    seed: &[u8; 32],
) -> SolanaZkResult<bundles::TransferBundle> {
    bundles::prove_transfer_bundle(
        source_secret,
        source_pubkey,
        dest_pubkey,
        auditor_pubkey,
        current_ciphertext,
        current_balance,
        transfer_amount,
        seed,
    )
}

/// Transfer-with-fee bundle prover (equality + validity-3 +
/// percentage-with-cap + fee validity-2 + U256 range). See
/// [`bundles::prove_transfer_with_fee_bundle`].
#[allow(clippy::too_many_arguments)]
pub fn prove_transfer_with_fee(
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
) -> SolanaZkResult<bundles::TransferWithFeeBundle> {
    bundles::prove_transfer_with_fee_bundle(
        source_secret,
        source_pubkey,
        dest_pubkey,
        auditor_pubkey,
        authority_pubkey,
        current_ciphertext,
        current_balance,
        transfer_amount,
        fee_rate_basis_points,
        maximum_fee,
        seed,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Identity point (32 zero bytes) decodes; exact sizes pass.
    #[test]
    fn exact_lengths_pass() {
        assert!(elgamal_pubkey_from_bytes(&[0u8; 32]).is_ok());
        assert!(elgamal_ciphertext_from_bytes(&[0u8; 64]).is_ok());
        assert!(ae_ciphertext_from_bytes(&[0u8; 36]).is_ok());
    }

    /// Upstream AES compatibility vector (36 bytes:
    /// 12-byte nonce || 8-byte ciphertext || 16-byte tag) passes the gate.
    #[test]
    fn ae_compat_vector_passes() {
        let compat: [u8; 36] = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
            0x1b, 0x5a, 0x37, 0xbc, 0xf1, 0x4e, 0x84, 0x2c, 0x24, 0x03, 0x54,
            0x2b, 0x6b, 0x74, 0xe9, 0x8f, 0x1e, 0x17, 0x8a, 0x2a, 0xac, 0x29,
            0x21, 0x05, 0xe4,
        ];
        assert!(ae_ciphertext_from_bytes(&compat).is_ok());
    }

    /// Length gates reject off-by-one sizes.
    #[test]
    fn bad_lengths_fail() {
        assert_eq!(
            elgamal_pubkey_from_bytes(&[0u8; 31]).unwrap_err(),
            SolanaZkError::InvalidLength
        );
        assert_eq!(
            elgamal_ciphertext_from_bytes(&[0u8; 63]).unwrap_err(),
            SolanaZkError::InvalidLength
        );
        assert_eq!(
            ae_ciphertext_from_bytes(&[0u8; 35]).unwrap_err(),
            SolanaZkError::InvalidLength
        );
    }

    /// Non-canonical Ristretto encodings fail curve validation.
    #[test]
    fn bad_points_fail() {
        assert_eq!(
            elgamal_pubkey_from_bytes(&[0xffu8; 32]).unwrap_err(),
            SolanaZkError::InvalidPoint
        );
        let mut bad = [0u8; 64];
        bad[32..].copy_from_slice(&[0xffu8; 32]);
        assert_eq!(
            elgamal_ciphertext_from_bytes(&bad).unwrap_err(),
            SolanaZkError::InvalidPoint
        );
    }

    /// Empty batch rejected; real backend proves (amount 0 is
    /// in range) and verifies.
    #[test]
    fn backend_is_linked() {
        assert_eq!(
            prove_batched_range(&[], &[], &[0u8; 32]).unwrap_err(),
            SolanaZkError::InvalidLength
        );
        // Real backend: prove amount 0, verify via the pod context.
        // (Nonzero opening: amount 0 with opening 0 is the identity point,
        // which verifiers explicitly reject.)
        let amounts = [[0u8; 8]];
        let openings = [[2u8; 32]];
        let (proof, pod_commitments, pod_bit_lengths) =
            prove_batched_range(&amounts, &openings, &[1u8; 32]).unwrap();
        assert!(!proof.is_empty());
        assert_eq!(&pod_bit_lengths[..1], &[64]);
        assert_ne!(&pod_commitments[..32], &[0u8; 32]);
        verify_batched_range(&proof, &pod_commitments, &pod_bit_lengths).unwrap();
        // Tampered proof fails.
        let mut bad = proof.clone();
        bad[10] ^= 1;
        assert!(verify_batched_range(&bad, &pod_commitments, &pod_bit_lengths).is_err());
    }

    /// Fully worked ElGamal roundtrip at point level (fast, no
    /// discrete-log table): decrypt recovers exactly `m*G`.
    #[test]
    fn elgamal_roundtrip_point() {
        let secret = [7u8; 32];
        let pubkey = elgamal_pubkey_from_secret(&secret).unwrap();
        // Distinct secret -> distinct pubkey; zero secret rejected.
        let other = elgamal_pubkey_from_secret(&[9u8; 32]).unwrap();
        assert_ne!(pubkey, other);
        assert_eq!(
            elgamal_pubkey_from_secret(&[0u8; 32]).unwrap_err(),
            SolanaZkError::InvalidPoint
        );
        let g = RistrettoPoint::generator();
        for amount in [0u64, 1, 77, 123456] {
            let ct = elgamal_encrypt_with(&pubkey, amount, &[3u8; 32]).unwrap();
            assert_eq!(ct.len(), 64);
            let m_g_enc = elgamal_decrypt_point(&secret, &ct).unwrap();
            // Independently recompute m*G and compare encodings.
            let mut expected = [0u8; 32];
            g.mul(&scalar_from_u64(amount))
                .to_bytes_compressed(&mut expected)
                .unwrap();
            assert_eq!(m_g_enc, expected);
        }
    }

    /// BSGS table decodes small + cross-boundary amounts with
    /// one shared table build.
    #[test]
    fn elgamal_decrypt_u32_table() {
        let secret = [7u8; 32];
        let pubkey = elgamal_pubkey_from_secret(&secret).unwrap();
        let table = DiscreteLogTable::build();
        for amount in [0u64, 1, 77, 70000] {
            let ct = elgamal_encrypt_with(&pubkey, amount, &[3u8; 32]).unwrap();
            let m_g_enc = elgamal_decrypt_point(&secret, &ct).unwrap();
            assert_eq!(table.decode(&m_g_enc), Some(amount));
        }
        // Wrong secret lands on a different point (not the amount).
        let ct = elgamal_encrypt_with(&pubkey, 77, &[3u8; 32]).unwrap();
        let m_g_enc = elgamal_decrypt_point(&[9u8; 32], &ct).unwrap();
        assert_ne!(table.decode(&m_g_enc), Some(77));
    }

    /// Giant steps decode across small, boundary and deep
    /// giant indices (127 | 128 | 129, 511 | 512, and a 1000-deep scan).
    /// Baby values stay below 2^14 (static table size).
    #[test]
    fn elgamal_decrypt_u32_chunk_edges() {
        let secret = [7u8; 32];
        let pubkey = elgamal_pubkey_from_secret(&secret).unwrap();
        let table = DiscreteLogTable::build();
        // Giant indices at/around small boundaries and a deeper multi-step
        // scan (all < 2^16 giants; baby parts < 2^16).
        for (giant_i, baby_j) in
            [(127u64, 5u64), (128, 5), (129, 5), (511, 0), (512, 4000), (1000, 1234)]
        {
            let amount = giant_i * 65536 + baby_j;
            let ct =
                elgamal_encrypt_with(&pubkey, amount, &[3u8; 32]).unwrap();
            let m_g_enc = elgamal_decrypt_point(&secret, &ct).unwrap();
            assert_eq!(table.decode(&m_g_enc), Some(amount));
        }
    }

    /// Full-range decrypt (last giant, last baby).
    /// Exercises the whole scan on the active backend.
    #[test]
    fn elgamal_decrypt_u32_full_range() {
        let secret = [7u8; 32];
        let pubkey = elgamal_pubkey_from_secret(&secret).unwrap();
        let table = DiscreteLogTable::build();
        let amount = 0xFFFF_FFFFu64;
        let ct = elgamal_encrypt_with(&pubkey, amount, &[3u8; 32]).unwrap();
        let m_g_enc = elgamal_decrypt_point(&secret, &ct).unwrap();
        assert_eq!(table.decode(&m_g_enc), Some(amount));
    }
}
