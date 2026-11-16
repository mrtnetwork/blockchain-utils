//! FROST(Ed25519, SHA-512) — RFC 9591 Section 6.1.
//!
//! Byte-compatible with the RFC Appendix E.1 vectors (see tests below)
//! and with the reference prototype in `reference frost tests/`.
//!
//! Differences from the secp256k1 suite (`k1.rs`): little-endian
//! scalars, 32-byte elements, plain-SHA-512 hashes (`H2` has NO domain
//! separator, for Ed25519 compatibility), prime-order subgroup check on
//! deserialization, and cofactor-cleared verification (delegated to the
//! crate Ed25519 verifier, which enforces `[8]zB = [8]R + [8]cPK`).
//!
//! Same constant-time discipline as `k1.rs`; see its module docs.

use super::error::{FrostError, FrostResult};
use super::hash;
use crate::ct::ct_zeroize;
use crate::curve::ed25519::scalar::{Scalar, L_LE};
use crate::curve::ed25519::Ed25519Point;
use crate::curve::traits::{CurvePoint, Scalar as ScalarTrait};
use alloc::vec::Vec;

/// Ciphersuite context string (RFC 9591 Section 6.1).
pub const CONTEXT: &str = "FROST-ED25519-SHA512-v1";
/// Compressed element length (RFC 8032).
pub const ELEMENT_LEN: usize = 32;
/// Scalar length (little-endian).
pub const SCALAR_LEN: usize = 32;
/// Canonical signature length `R (32) || z (32)` (Appendix A).
pub const SIGNATURE_LEN: usize = 64;

/// One participant's public commitment entry (Section 4.3).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Commitment {
    /// Participant identifier (NonZeroScalar, typically `1..=MAX`).
    pub id: u32,
    /// `SerializeElement(hiding_nonce_commitment)`.
    pub hiding: [u8; ELEMENT_LEN],
    /// `SerializeElement(binding_nonce_commitment)`.
    pub binding: [u8; ELEMENT_LEN],
}

/// One participant's secret nonce pair plus public commitments (5.1).
#[derive(Clone, Debug)]
pub struct NoncePair {
    /// `SerializeScalar(hiding_nonce)` — SECRET.
    pub hiding: [u8; SCALAR_LEN],
    /// `SerializeScalar(binding_nonce)` — SECRET.
    pub binding: [u8; SCALAR_LEN],
    /// `SerializeElement(G*hiding)`.
    pub hiding_commitment: [u8; ELEMENT_LEN],
    /// `SerializeElement(G*binding)`.
    pub binding_commitment: [u8; ELEMENT_LEN],
}

impl NoncePair {
    /// Best-effort wipe of the secret nonce scalars (commitments kept).
    pub fn zeroize(&mut self) {
        ct_zeroize(&mut self.hiding);
        ct_zeroize(&mut self.binding);
    }

    /// Commitment entry for `id` referencing this pair's commitments.
    pub fn commitment(&self, id: u32) -> Commitment {
        Commitment {
            id,
            hiding: self.hiding_commitment,
            binding: self.binding_commitment,
        }
    }
}

/// One participant's Shamir share (Appendix C.1).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyShare {
    /// Participant identifier (NonZeroScalar).
    pub id: u32,
    /// `SerializeScalar(share)` — SECRET.
    pub share: [u8; SCALAR_LEN],
}

// ---------------------------------------------------------------------------
// Scalar / element codecs.
// ---------------------------------------------------------------------------

fn parse_scalar(bytes: &[u8; SCALAR_LEN]) -> FrostResult<Scalar> {
    Scalar::from_bytes(bytes).map_err(|_| FrostError::InvalidScalar)
}

fn scalar_bytes(s: &Scalar) -> [u8; SCALAR_LEN] {
    let mut out = [0u8; SCALAR_LEN];
    let _ = ScalarTrait::to_bytes(s, &mut out);
    out
}

/// Interpret a 32-byte secret input as a FROST scalar.
///
/// `is_scalar != 0` (`isScalar: true`): bytes are the canonical
/// little-endian scalar itself (validated, returned as-is).
/// `is_scalar == 0` (`isScalar: false`): bytes are an RFC 8032
/// Ed25519 seed; the scalar is `clamp(SHA-512(seed)[0:32]) mod L`,
/// matching `signature::ed25519::expand_secret(Variant::Ed25519)` and
/// `ED25519KeyUtils.derivePublicKey` (whose `reduceMultBase`
/// multiplies the clamped bytes, i.e. reduces mod `L`).
pub fn secret_to_scalar_bytes(input: &[u8; 32], is_scalar: u8) -> FrostResult<[u8; 32]> {
    if is_scalar != 0 {
        parse_scalar(input)?;
        return Ok(*input);
    }
    let digest = hash::sha512(input)?;
    let mut a = [0u8; 32];
    a.copy_from_slice(&digest[..32]);
    Scalar::clamp_ed25519(&mut a);
    // Clamped seeds have bit 254 set (`>= L`): reduce, don't parse.
    Ok(scalar_bytes(&Scalar::from_bytes_mod_order(&a)))
}

/// Lift a small identifier into a Scalar (infallible: `id < L`).
fn id_scalar(id: u32) -> Scalar {
    let mut b = [0u8; SCALAR_LEN];
    b[..4].copy_from_slice(&id.to_le_bytes());
    Scalar::from_bytes_mod_order(&b)
}

fn serialize_id(id: u32) -> [u8; SCALAR_LEN] {
    scalar_bytes(&id_scalar(id))
}

/// The group order `L` as a (non-reduced) Scalar for the subgroup check.
fn order_scalar() -> Scalar {
    let mut d = [0u32; 8];
    for (i, di) in d.iter_mut().enumerate() {
        let o = i * 4;
        *di = u32::from_le_bytes([L_LE[o], L_LE[o + 1], L_LE[o + 2], L_LE[o + 3]]);
    }
    Scalar { d }
}

/// Reduce a 64-byte little-endian digest mod `L` (H1/H2/H3 tail step).
fn scalar_from_digest_le(digest: &[u8; 64]) -> Scalar {
    let s256 = id_scalar(256);
    let mut acc = Scalar::zero();
    // Horner from the most significant byte down; CT scalar ops only.
    for byte in digest.iter().rev() {
        acc = acc.mul(&s256).add(&id_scalar(*byte as u32));
    }
    acc
}

fn parse_point(bytes: &[u8; ELEMENT_LEN]) -> FrostResult<Ed25519Point> {
    let p = Ed25519Point::from_bytes(bytes).map_err(|_| FrostError::InvalidKey)?;
    if p.ct_is_identity() == 1 {
        return Err(FrostError::InvalidKey);
    }
    // Prime-order subgroup check (Section 6.1): [L]P == I.
    if p.mul(&order_scalar()).ct_is_identity() != 1 {
        return Err(FrostError::InvalidKey);
    }
    Ok(p)
}

fn point_bytes(p: &Ed25519Point) -> FrostResult<[u8; ELEMENT_LEN]> {
    if p.ct_is_identity() == 1 {
        return Err(FrostError::InvalidKey);
    }
    let mut out = [0u8; ELEMENT_LEN];
    p.to_bytes_compressed(&mut out)
        .map_err(|_| FrostError::InvalidKey)?;
    Ok(out)
}

fn base_mul(s: &Scalar) -> FrostResult<[u8; ELEMENT_LEN]> {
    let p = Ed25519Point::generator().mul(s);
    point_bytes(&p)
}

// ---------------------------------------------------------------------------
// Hashes H1..H5 (Section 6.1).
// ---------------------------------------------------------------------------

fn ctx_body(label: &[u8], m: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(CONTEXT.len() + label.len() + m.len());
    v.extend_from_slice(CONTEXT.as_bytes());
    v.extend_from_slice(label);
    v.extend_from_slice(m);
    v
}

/// `H1(m) = H(ctx || "rho" || m)` as LE integer mod `L`.
pub fn h1(m: &[u8]) -> FrostResult<Scalar> {
    Ok(scalar_from_digest_le(&hash::sha512(&ctx_body(b"rho", m))?))
}

/// `H2(m) = H(m)` as LE integer mod `L` (no DST, Ed25519 compat).
pub fn h2(m: &[u8]) -> FrostResult<Scalar> {
    Ok(scalar_from_digest_le(&hash::sha512(m)?))
}

/// `H3(m) = H(ctx || "nonce" || m)` as LE integer mod `L`.
pub fn h3(m: &[u8]) -> FrostResult<Scalar> {
    Ok(scalar_from_digest_le(&hash::sha512(&ctx_body(b"nonce", m))?))
}

/// `H4(m) = H(ctx || "msg" || m)`, raw 64 bytes.
pub fn h4(m: &[u8]) -> FrostResult<[u8; 64]> {
    hash::sha512(&ctx_body(b"msg", m))
}

/// `H5(m) = H(ctx || "com" || m)`, raw 64 bytes.
pub fn h5(m: &[u8]) -> FrostResult<[u8; 64]> {
    hash::sha512(&ctx_body(b"com", m))
}

// ---------------------------------------------------------------------------
// Polynomials (Sections 4.2, C.1.1).
// ---------------------------------------------------------------------------

fn check_ids(ids: &[u32]) -> FrostResult<()> {
    if ids.is_empty() {
        return Err(FrostError::InvalidParticipant);
    }
    for i in 0..ids.len() {
        if ids[i] == 0 {
            return Err(FrostError::InvalidParticipant);
        }
        for j in (i + 1)..ids.len() {
            // Comparison on PUBLIC identifiers (no secret data).
            if ids[i] == ids[j] {
                return Err(FrostError::InvalidParticipant);
            }
        }
    }
    Ok(())
}

/// `derive_interpolating_value(L, x_i)` for `u32` identifiers.
pub fn derive_interpolating_value(ids: &[u32], xi: u32) -> FrostResult<Scalar> {
    check_ids(ids)?;
    if !ids.contains(&xi) {
        return Err(FrostError::InvalidParticipant);
    }
    let x = id_scalar(xi);
    let mut num = Scalar::one();
    let mut den = Scalar::one();
    for xj in ids {
        if *xj == xi {
            continue;
        }
        let xs = id_scalar(*xj);
        num = num.mul(&xs);
        den = den.mul(&xs.add(&x.neg()));
    }
    let inv = den.invert().map_err(|_| FrostError::InvalidParticipant)?;
    Ok(num.mul(&inv))
}

fn polynomial_evaluate(x: &Scalar, coeffs: &[Scalar]) -> Scalar {
    let mut v = Scalar::zero();
    for c in coeffs.iter().rev() {
        v = v.mul(x).add(c);
    }
    v
}

// ---------------------------------------------------------------------------
// Binding factors / commitments / challenge (Sections 4.3-4.6).
// ---------------------------------------------------------------------------

fn sorted_commitments(commitments: &[Commitment]) -> FrostResult<Vec<Commitment>> {
    if commitments.is_empty() {
        return Err(FrostError::InvalidCommitment);
    }
    let mut sorted = commitments.to_vec();
    sorted.sort_by_key(|c| c.id);
    let ids: Vec<u32> = sorted.iter().map(|c| c.id).collect();
    check_ids(&ids).map_err(|_| FrostError::InvalidCommitment)?;
    for c in &sorted {
        parse_point(&c.hiding).map_err(|_| FrostError::InvalidCommitment)?;
        parse_point(&c.binding).map_err(|_| FrostError::InvalidCommitment)?;
    }
    Ok(sorted)
}

fn encode_group_commitment_list(sorted: &[Commitment]) -> Vec<u8> {
    let mut out = Vec::with_capacity(sorted.len() * (SCALAR_LEN + 2 * ELEMENT_LEN));
    for c in sorted {
        out.extend_from_slice(&serialize_id(c.id));
        out.extend_from_slice(&c.hiding);
        out.extend_from_slice(&c.binding);
    }
    out
}

/// `compute_binding_factors` → `Vec<(id, rho_i)>` in ascending id order.
pub fn compute_binding_factors(
    group_pk: &[u8; ELEMENT_LEN],
    commitments: &[Commitment],
    msg: &[u8],
) -> FrostResult<Vec<(u32, [u8; SCALAR_LEN])>> {
    let sorted = sorted_commitments(commitments)?;
    parse_point(group_pk)?;
    let msg_hash = h4(msg)?;
    let enc_hash = h5(&encode_group_commitment_list(&sorted))?;
    let mut prefix = Vec::with_capacity(ELEMENT_LEN + 64 + 64);
    prefix.extend_from_slice(group_pk);
    prefix.extend_from_slice(&msg_hash);
    prefix.extend_from_slice(&enc_hash);
    let mut out = Vec::with_capacity(sorted.len());
    for c in &sorted {
        let mut input = Vec::with_capacity(prefix.len() + SCALAR_LEN);
        input.extend_from_slice(&prefix);
        input.extend_from_slice(&serialize_id(c.id));
        let rho = h1(&input)?;
        out.push((c.id, scalar_bytes(&rho)));
    }
    Ok(out)
}

fn factor_for(factors: &[(u32, [u8; SCALAR_LEN])], id: u32) -> FrostResult<Scalar> {
    for (i, f) in factors {
        if *i == id {
            return parse_scalar(f);
        }
    }
    Err(FrostError::InvalidParticipant)
}

/// `compute_group_commitment` → encoded `R`.
pub fn compute_group_commitment(
    commitments: &[Commitment],
    factors: &[(u32, [u8; SCALAR_LEN])],
) -> FrostResult<[u8; ELEMENT_LEN]> {
    let sorted = sorted_commitments(commitments)?;
    let mut acc = Ed25519Point::identity();
    for c in &sorted {
        let rho = factor_for(factors, c.id)?;
        let hiding = parse_point(&c.hiding).map_err(|_| FrostError::InvalidCommitment)?;
        let binding = parse_point(&c.binding).map_err(|_| FrostError::InvalidCommitment)?;
        acc = acc.add(&hiding).add(&binding.mul(&rho));
    }
    if acc.ct_is_identity() == 1 {
        return Err(FrostError::IdentityCommitment);
    }
    point_bytes(&acc)
}

/// `compute_challenge(R, PK, msg)` → encoded scalar.
pub fn compute_challenge(
    group_commitment: &[u8; ELEMENT_LEN],
    group_pk: &[u8; ELEMENT_LEN],
    msg: &[u8],
) -> FrostResult<[u8; SCALAR_LEN]> {
    parse_point(group_commitment)?;
    parse_point(group_pk)?;
    let mut input = Vec::with_capacity(2 * ELEMENT_LEN + msg.len());
    input.extend_from_slice(group_commitment);
    input.extend_from_slice(group_pk);
    input.extend_from_slice(msg);
    Ok(scalar_bytes(&h2(&input)?))
}

// ---------------------------------------------------------------------------
// Round 1: commit (Section 5.1, nonce_generate per Section 4.1).
// ---------------------------------------------------------------------------

/// Commit with caller-supplied 32-byte randomness (test vectors) or
/// CSPRNG output (production). `hiding = H3(rand_h || enc(secret))`.
pub fn commit_with_randomness(
    secret_share: &[u8; SCALAR_LEN],
    hiding_rand: &[u8; SCALAR_LEN],
    binding_rand: &[u8; SCALAR_LEN],
) -> FrostResult<NoncePair> {
    let sk = parse_scalar(secret_share)?;
    if sk.is_zero() {
        return Err(FrostError::InvalidScalar);
    }
    let sk_enc = scalar_bytes(&sk);
    let mut h_in = Vec::with_capacity(2 * SCALAR_LEN);
    h_in.extend_from_slice(hiding_rand);
    h_in.extend_from_slice(&sk_enc);
    let mut hiding = h3(&h_in)?;
    let mut b_in = Vec::with_capacity(2 * SCALAR_LEN);
    b_in.extend_from_slice(binding_rand);
    b_in.extend_from_slice(&sk_enc);
    let mut binding = h3(&b_in)?;
    if hiding.is_zero() || binding.is_zero() {
        hiding.zeroize();
        binding.zeroize();
        return Err(FrostError::InvalidNonce);
    }
    let pair = NoncePair {
        hiding: scalar_bytes(&hiding),
        binding: scalar_bytes(&binding),
        hiding_commitment: base_mul(&hiding)?,
        binding_commitment: base_mul(&binding)?,
    };
    hiding.zeroize();
    binding.zeroize();
    Ok(pair)
}

// ---------------------------------------------------------------------------
// Round 2: sign (Section 5.2).
// ---------------------------------------------------------------------------

/// `sign(id, sk_i, PK, nonce_i, msg, commitment_list)` → `sig_share`.
pub fn sign(
    id: u32,
    secret_share: &[u8; SCALAR_LEN],
    group_pk: &[u8; ELEMENT_LEN],
    nonces: &NoncePair,
    msg: &[u8],
    commitments: &[Commitment],
) -> FrostResult<[u8; SCALAR_LEN]> {
    if id == 0 {
        return Err(FrostError::InvalidParticipant);
    }
    let mut sk = parse_scalar(secret_share)?;
    let mut h = parse_scalar(&nonces.hiding)?;
    let mut b = parse_scalar(&nonces.binding)?;
    if h.is_zero() || b.is_zero() {
        return Err(FrostError::InvalidNonce);
    }
    let factors = compute_binding_factors(group_pk, commitments, msg)?;
    let rho = factor_for(&factors, id)?;
    let r_enc = compute_group_commitment(commitments, &factors)?;
    let sorted = sorted_commitments(commitments)?;
    let ids: Vec<u32> = sorted.iter().map(|c| c.id).collect();
    let lambda = derive_interpolating_value(&ids, id)?;
    let c_enc = compute_challenge(&r_enc, group_pk, msg)?;
    let c = parse_scalar(&c_enc)?;
    // z = h + b*rho + lambda*sk*c
    let z = h.add(&b.mul(&rho)).add(&lambda.mul(&sk).mul(&c));
    let out = scalar_bytes(&z);
    sk.zeroize();
    h.zeroize();
    b.zeroize();
    Ok(out)
}

// ---------------------------------------------------------------------------
// Aggregation + share verification (Section 5.3).
// ---------------------------------------------------------------------------

/// `aggregate(commitment_list, msg, PK, sig_shares)` → `(R, z)`.
///
/// Requires a full quorum: at least two shares and exactly one share
/// per commitment-list entry (`shares.len() == commitments.len()`),
/// mirroring frost-rust's identifier-mapped aggregation. Subset or
/// superset share sets are rejected instead of being silently summed
/// against an unrelated `R`.
pub fn aggregate(
    commitments: &[Commitment],
    msg: &[u8],
    group_pk: &[u8; ELEMENT_LEN],
    shares: &[[u8; SCALAR_LEN]],
) -> FrostResult<([u8; ELEMENT_LEN], [u8; SCALAR_LEN])> {
    if shares.len() < 2 {
        return Err(FrostError::TooFewShares);
    }
    if shares.len() != commitments.len() {
        return Err(FrostError::InvalidLength);
    }
    for s in shares {
        parse_scalar(s)?;
    }
    let factors = compute_binding_factors(group_pk, commitments, msg)?;
    let r = compute_group_commitment(commitments, &factors)?;
    let mut z = Scalar::zero();
    for s in shares {
        let si = parse_scalar(s)?;
        z = z.add(&si);
    }
    Ok((r, scalar_bytes(&z)))
}

/// `verify_signature_share` (Section 5.3). `Ok(false)` = bad share.
pub fn verify_share(
    id: u32,
    pk_share: &[u8; ELEMENT_LEN],
    comm: &Commitment,
    share: &[u8; SCALAR_LEN],
    commitments: &[Commitment],
    group_pk: &[u8; ELEMENT_LEN],
    msg: &[u8],
) -> FrostResult<bool> {
    if id == 0 || comm.id != id {
        return Err(FrostError::InvalidParticipant);
    }
    // The standalone commitment must match the list entry for `id`:
    // `rho`/`R`/`c` below are derived from the commitment list, so a
    // divergent `comm` would verify unrelated DLOG inputs meaninglessly.
    let sorted = sorted_commitments(commitments)?;
    let listed = sorted
        .iter()
        .find(|c| c.id == id)
        .ok_or(FrostError::InvalidParticipant)?;
    if listed.hiding != comm.hiding || listed.binding != comm.binding {
        return Err(FrostError::InvalidCommitment);
    }
    let pk = parse_point(pk_share)?;
    let z = parse_scalar(share)?;
    let factors = compute_binding_factors(group_pk, commitments, msg)?;
    let rho = factor_for(&factors, id)?;
    let r_enc = compute_group_commitment(commitments, &factors)?;
    let sorted = sorted_commitments(commitments)?;
    let ids: Vec<u32> = sorted.iter().map(|c| c.id).collect();
    let lambda = derive_interpolating_value(&ids, id)?;
    let c_enc = compute_challenge(&r_enc, group_pk, msg)?;
    let c = parse_scalar(&c_enc)?;
    let hiding = parse_point(&comm.hiding).map_err(|_| FrostError::InvalidCommitment)?;
    let binding = parse_point(&comm.binding).map_err(|_| FrostError::InvalidCommitment)?;
    // l = G*z ; r = (hiding + rho*binding) + (c*lambda)*PK_i
    let lhs = point_bytes(&Ed25519Point::generator().mul(&z))?;
    let comm_share = hiding.add(&binding.mul(&rho));
    let rhs = point_bytes(&comm_share.add(&pk.mul(&c.mul(&lambda))))?;
    Ok(lhs == rhs)
}

/// Section 6.1 verification (`[8]zB = [8]R + [8]cPK`, RFC 8032
/// compatible). Pure `false` on any malformed encoding.
pub fn verify_signature(
    group_commitment: &[u8; ELEMENT_LEN],
    z: &[u8; SCALAR_LEN],
    group_pk: &[u8; ELEMENT_LEN],
    msg: &[u8],
) -> bool {
    use crate::signature::ed25519::{PublicKey, Signature};
    let mut sig = [0u8; SIGNATURE_LEN];
    sig[..ELEMENT_LEN].copy_from_slice(group_commitment);
    sig[ELEMENT_LEN..].copy_from_slice(z);
    crate::signature::ed25519::verify(&PublicKey(*group_pk), msg, &Signature(sig)).is_ok()
}

/// Canonical encoding (Appendix A): `R (32) || z (32)`.
pub fn encode_signature(r: &[u8; ELEMENT_LEN], z: &[u8; SCALAR_LEN]) -> [u8; SIGNATURE_LEN] {
    let mut out = [0u8; SIGNATURE_LEN];
    out[..ELEMENT_LEN].copy_from_slice(r);
    out[ELEMENT_LEN..].copy_from_slice(z);
    out
}

/// Decode a canonical signature.
pub fn decode_signature(sig: &[u8]) -> FrostResult<([u8; ELEMENT_LEN], [u8; SCALAR_LEN])> {
    if sig.len() != SIGNATURE_LEN {
        return Err(FrostError::InvalidLength);
    }
    let mut r = [0u8; ELEMENT_LEN];
    let mut z = [0u8; SCALAR_LEN];
    r.copy_from_slice(&sig[..ELEMENT_LEN]);
    z.copy_from_slice(&sig[ELEMENT_LEN..]);
    parse_point(&r)?;
    parse_scalar(&z)?;
    Ok((r, z))
}

// ---------------------------------------------------------------------------
// Trusted dealer (Appendix C).
// ---------------------------------------------------------------------------

/// `secret_share_shard(s, coeffs, MAX)`: Shamir shares for ids `1..=MAX`.
/// Returns `(shares, full_poly)` with `full_poly[0] == s`.
///
/// The implied threshold `t = coeffs.len() + 1` must satisfy `t <= MAX`
/// (degree `< MAX`) with `MAX >= 2`; over-degree polynomials and
/// degenerate single-participant dealers are rejected.
///
/// `secret`/`coeffs` are canonical scalars here (validated as-is).
/// Seed holders must expand via [`secret_to_scalar_bytes`] with
/// `is_scalar == 0` before calling (the FFI/WASM sharding entry
/// points do this); never pass an unexpanded seed.
pub fn shard(
    secret: &[u8; SCALAR_LEN],
    coeffs: &[[u8; SCALAR_LEN]],
    max: u16,
) -> FrostResult<(Vec<KeyShare>, Vec<[u8; SCALAR_LEN]>)> {
    if max < 2 {
        return Err(FrostError::InvalidLength);
    }
    if coeffs.len() + 1 > max as usize {
        return Err(FrostError::InvalidLength);
    }
    let s = parse_scalar(secret)?;
    if s.is_zero() {
        return Err(FrostError::InvalidScalar);
    }
    let mut poly = Vec::with_capacity(1 + coeffs.len());
    poly.push(s);
    for c in coeffs {
        poly.push(parse_scalar(c)?);
    }
    let mut shares = Vec::with_capacity(max as usize);
    for i in 1..=max as u32 {
        let x = id_scalar(i);
        let y = polynomial_evaluate(&x, &poly);
        shares.push(KeyShare {
            id: i,
            share: scalar_bytes(&y),
        });
    }
    let full: Vec<[u8; SCALAR_LEN]> = poly.iter().map(scalar_bytes).collect();
    Ok((shares, full))
}

/// `secret_share_combine`: Lagrange interpolation at `x = 0`.
/// Requires a quorum of at least two shares; a single share is not a
/// valid quorum and is rejected with [`FrostError::TooFewShares`].
pub fn combine(shares: &[KeyShare]) -> FrostResult<[u8; SCALAR_LEN]> {
    if shares.len() < 2 {
        return Err(FrostError::TooFewShares);
    }
    let ids: Vec<u32> = shares.iter().map(|s| s.id).collect();
    check_ids(&ids)?;
    let mut acc = Scalar::zero();
    for s in shares {
        let y = parse_scalar(&s.share)?;
        let l = derive_interpolating_value(&ids, s.id)?;
        acc = acc.add(&y.mul(&l));
    }
    Ok(scalar_bytes(&acc))
}

/// Output of [`reshare`]: `(new_shares, new_pubs, group)`.
pub type ReshareOutput = (
    Vec<[u8; SCALAR_LEN]>,
    Vec<[u8; ELEMENT_LEN]>,
    [u8; ELEMENT_LEN],
);

/// Threshold reshare over independent secrets (RFC 9591 adaptation).
///
/// `secrets`/`coeffs` are canonical little-endian scalars, validated
/// as-is — exactly like [`crate::frost::k1::reshare`]. This keeps both
/// suites on the same preimage: raw scalars in, raw scalars out.
///
/// WARNING: this function never hashes. Callers holding RFC 8032 seeds
/// MUST expand them first via [`secret_to_scalar_bytes`] with
/// `is_scalar == 0`; passing a seed here directly uses it raw (it is
/// NOT expanded), and passing a canonical scalar to a seed-oriented
/// helper silently hashes it. The FFI/WASM `frost_ed_reshare` entry
/// points take seeds and expand them before calling this function.
///
/// Each secret `a_j` gets `f_j(x) = a_j + c_{j,1}x + ... + c_{j,t-1}x^{t-1}`
/// with the `j`-th chunk of `coeffs` (`n*(t-1)` entries total, row-major),
/// then `b_i = Σ_j f_j(id_i)`. Returns `(new_shares, new_pubs, group)`
/// with `pubs_i = G*b_i` and `group = Σ_j G*a_j`.
pub fn reshare(
    ids: &[u32],
    secrets: &[[u8; SCALAR_LEN]],
    coeffs: &[[u8; SCALAR_LEN]],
    threshold: u16,
) -> FrostResult<ReshareOutput> {
    let n = ids.len();
    if n < 2 {
        return Err(FrostError::InvalidLength);
    }
    let t = threshold as usize;
    if threshold < 2 || t > n {
        return Err(FrostError::InvalidLength);
    }
    if secrets.len() != n {
        return Err(FrostError::InvalidLength);
    }
    let k = t - 1;
    if coeffs.len() != n * k {
        return Err(FrostError::InvalidLength);
    }
    check_ids(ids)?;
    let mut a = Vec::with_capacity(n);
    for s in secrets {
        let v = parse_scalar(s)?;
        if v.is_zero() {
            return Err(FrostError::InvalidScalar);
        }
        a.push(v);
    }
    let mut c = Vec::with_capacity(coeffs.len());
    for x in coeffs {
        c.push(parse_scalar(x)?);
    }
    let mut polys: Vec<Vec<Scalar>> = Vec::with_capacity(n);
    for j in 0..n {
        let mut p = Vec::with_capacity(t);
        p.push(a[j]);
        p.extend_from_slice(&c[j * k..(j + 1) * k]);
        polys.push(p);
    }
    let mut orig_enc = Vec::with_capacity(n);
    for aj in &a {
        orig_enc.push(base_mul(aj)?);
    }
    let mut gacc = Ed25519Point::identity();
    for e in &orig_enc {
        gacc = gacc.add(&parse_point(e)?);
    }
    let group = point_bytes(&gacc)?;
    let mut shares = Vec::with_capacity(n);
    let mut pubs = Vec::with_capacity(n);
    for id in ids {
        let x = id_scalar(*id);
        let mut b = Scalar::zero();
        for p in &polys {
            b = b.add(&polynomial_evaluate(&x, p));
        }
        if b.is_zero() {
            return Err(FrostError::InvalidScalar);
        }
        shares.push(scalar_bytes(&b));
        pubs.push(base_mul(&b)?);
    }
    Ok((shares, pubs, group))
}

/// Validate a signing/group quorum shape: `n >= 2` shares, threshold
/// `0` (additive) or `2 <= t <= n`. Returns whether it is additive.
fn check_quorum(n: usize, threshold: u16) -> FrostResult<bool> {
    if n < 2 {
        return Err(FrostError::InvalidLength);
    }
    let t = threshold as usize;
    if t != 0 && (t < 2 || t > n) {
        return Err(FrostError::InvalidLength);
    }
    Ok(t == 0)
}

/// Expand seed inputs (when `is_scalar == 0`) and, for additive quorums,
/// pre-divide each share by its full-set Lagrange weight
/// (`w_i = s_i / λ_i`) so subset interpolation reconstructs the sum.
/// Shamir quorums pass shares through raw. Constant-time scalar backend;
/// no branching on secret data.
///
/// WARNING: `is_scalar == 0` hashes every input via
/// [`secret_to_scalar_bytes`] (`clamp(SHA-512(x))`). Pass
/// `is_scalar != 0` for canonical scalars — passing a canonical scalar
/// with `is_scalar == 0` silently hashes it instead of using it.
pub fn prepare_shares(
    ids: &[u32],
    shares: &[[u8; SCALAR_LEN]],
    threshold: u16,
    is_scalar: u8,
) -> FrostResult<Vec<[u8; SCALAR_LEN]>> {
    if ids.len() != shares.len() {
        return Err(FrostError::InvalidLength);
    }
    let additive = check_quorum(ids.len(), threshold)?;
    check_ids(ids)?;
    let mut secs = Vec::with_capacity(shares.len());
    for s in shares {
        let raw = secret_to_scalar_bytes(s, is_scalar)?;
        let v = parse_scalar(&raw).map_err(|_| FrostError::Internal)?;
        if v.is_zero() {
            return Err(FrostError::InvalidScalar);
        }
        secs.push(v);
    }
    if !additive {
        return Ok(secs.iter().map(scalar_bytes).collect());
    }
    let mut out = Vec::with_capacity(secs.len());
    for (i, id) in ids.iter().enumerate() {
        let lambda = derive_interpolating_value(ids, *id)?;
        let inv = lambda.invert().map_err(|_| FrostError::InvalidParticipant)?;
        out.push(scalar_bytes(&secs[i].mul(&inv)));
    }
    Ok(out)
}

/// Group key from member points: sum (`threshold == 0`, additive) or
/// Lagrange interpolation at zero over `(ids, pubs)`.
pub fn group_from_members(
    ids: &[u32],
    pubs: &[[u8; ELEMENT_LEN]],
    threshold: u16,
) -> FrostResult<[u8; ELEMENT_LEN]> {
    if ids.len() != pubs.len() {
        return Err(FrostError::InvalidLength);
    }
    let additive = check_quorum(ids.len(), threshold)?;
    check_ids(ids)?;
    let mut points = Vec::with_capacity(pubs.len());
    for p in pubs {
        points.push(parse_point(p)?);
    }
    let mut acc = Ed25519Point::identity();
    if additive {
        for p in &points {
            acc = acc.add(p);
        }
    } else {
        for (i, id) in ids.iter().enumerate() {
            let lambda = derive_interpolating_value(ids, *id)?;
            acc = acc.add(&points[i].mul(&lambda));
        }
    }
    point_bytes(&acc)
}

/// Feldman VSS commitment: `C_j = G * coeff_j`.
pub fn vss_commit(coeffs: &[[u8; SCALAR_LEN]]) -> FrostResult<Vec<[u8; ELEMENT_LEN]>> {
    if coeffs.is_empty() {
        return Err(FrostError::InvalidLength);
    }
    let mut out = Vec::with_capacity(coeffs.len());
    for c in coeffs {
        let s = parse_scalar(c)?;
        out.push(base_mul(&s)?);
    }
    Ok(out)
}

/// VSS verification: `G*share == Σ C_j * id^j`.
pub fn vss_verify(share: &KeyShare, commitment: &[[u8; ELEMENT_LEN]]) -> FrostResult<bool> {
    if share.id == 0 || commitment.is_empty() {
        return Err(FrostError::InvalidParticipant);
    }
    let y = parse_scalar(&share.share)?;
    let lhs = base_mul(&y)?;
    let x = id_scalar(share.id);
    let mut power = Scalar::one();
    let mut acc = Ed25519Point::identity();
    for c in commitment {
        let cp = parse_point(c)?;
        acc = acc.add(&cp.mul(&power));
        power = power.mul(&x);
    }
    Ok(point_bytes(&acc)? == lhs)
}

/// Group key (`C_0`) plus per-participant keys for ids `1..=max`.
pub fn group_info(
    max: u16,
    vss_commitment: &[[u8; ELEMENT_LEN]],
) -> FrostResult<([u8; ELEMENT_LEN], Vec<[u8; ELEMENT_LEN]>)> {
    if max == 0 || vss_commitment.is_empty() {
        return Err(FrostError::InvalidLength);
    }
    for c in vss_commitment {
        parse_point(c)?;
    }
    let group = vss_commitment[0];
    let mut pks = Vec::with_capacity(max as usize);
    for i in 1..=max as u32 {
        let x = id_scalar(i);
        let mut power = Scalar::one();
        let mut acc = Ed25519Point::identity();
        for c in vss_commitment {
            // Already validated above.
            let cp = parse_point(c).map_err(|_| FrostError::Internal)?;
            acc = acc.add(&cp.mul(&power));
            power = power.mul(&x);
        }
        pks.push(point_bytes(&acc)?);
    }
    Ok((group, pks))
}

// ---------------------------------------------------------------------------
// Tests: RFC 9591 Appendix E.1 vectors + negative/roundtrip checks.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        assert!(s.len().is_multiple_of(2));
        let mut out = Vec::with_capacity(s.len() / 2);
        let val = |c: u8| match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("bad hex"),
        };
        for i in (0..s.len()).step_by(2) {
            out.push(val(s[i]) << 4 | val(s[i + 1]));
        }
        out
    }

    fn b32(s: &str) -> [u8; 32] {
        let v = hex(s);
        assert_eq!(v.len(), 32);
        let mut o = [0u8; 32];
        o.copy_from_slice(&v);
        o
    }

    fn hx(b: &[u8]) -> Vec<u8> {
        b.to_vec()
    }

    const GROUP_SECRET: &str = "7b1c33d3f5291d85de664833beb1ad469f7fb6025a0ec78b3a790c6e13a98304";
    const GROUP_PK: &str = "15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673";
    const COEFF: &str = "178199860edd8c62f5212ee91eff1295d0d670ab4ed4506866bae57e7030b204";
    const MSG: &str = "74657374";
    const SHARE1: &str = "929dcc590407aae7d388761cddb0c0db6f5627aea8e217f4a033f2ec83d93509";
    const SHARE3: &str = "d3cb090a075eb154e82fdb4b3cb507f110040905468bb9c46da8bdea643a9a02";
    const P1_HRAND: &str = "0fd2e39e111cdc266f6c0f4d0fd45c947761f1f5d3cb583dfcb9bbaf8d4c9fec";
    const P1_BRAND: &str = "69cd85f631d5f7f2721ed5e40519b1366f340a87c2f6856363dbdcda348a7501";
    const P1_H: &str = "812d6104142944d5a55924de6d49940956206909f2acaeedecda2b726e630407";
    const P1_B: &str = "b1110165fc2334149750b28dd813a39244f315cff14d4e89e6142f262ed83301";
    const P1_HC: &str = "b5aa8ab305882a6fc69cbee9327e5a45e54c08af61ae77cb8207be3d2ce13de3";
    const P1_BC: &str = "67e98ab55aa310c3120418e5050c9cf76cf387cb20ac9e4b6fdb6f82a469f932";
    const P3_HRAND: &str = "86d64a260059e495d0fb4fcc17ea3da7452391baa494d4b00321098ed2a0062f";
    const P3_BRAND: &str = "13e6b25afb2eba51716a9a7d44130c0dbae0004a9ef8d7b5550c8a0e07c61775";
    const P3_H: &str = "c256de65476204095ebdc01bd11dc10e57b36bc96284595b8215222374f99c0e";
    const P3_B: &str = "243d71944d929063bc51205714ae3c2218bd3451d0214dfb5aeec2a90c35180d";
    const P3_HC: &str = "cfbdb165bd8aad6eb79deb8d287bcc0ab6658ae57fdcc98ed12c0669e90aec91";
    const P3_BC: &str = "7487bc41a6e712eea2f2af24681b58b1cf1da278ea11fe4e8b78398965f13552";
    const RHO1: &str = "f2cb9d7dd9beff688da6fcc83fa89046b3479417f47f55600b106760eb3b5603";
    const RHO3: &str = "b087686bf35a13f3dc78e780a34b0fe8a77fef1b9938c563f5573d71d8d7890f";
    const SIG1: &str = "001719ab5a53ee1a12095cd088fd149702c0720ce5fd2f29dbecf24b7281b603";
    const SIG3: &str = "bd86125de990acc5e1f13781d8e32c03a9bbd4c53539bbc106058bfd14326007";
    const SIG: &str = "36282629c383bb820a88b71cae937d41f2f2adfcc3d02e55507e2fb9e2dd3cbe bd9d2b0844e49ae0f3fa935161e1419aab7b47d21a37ebeae1f17d4987b3160b";

    fn e1_nonces() -> (NoncePair, NoncePair) {
        let n1 = commit_with_randomness(&b32(SHARE1), &b32(P1_HRAND), &b32(P1_BRAND)).unwrap();
        let n3 = commit_with_randomness(&b32(SHARE3), &b32(P3_HRAND), &b32(P3_BRAND)).unwrap();
        assert_eq!(hx(&n1.hiding), hex(P1_H));
        assert_eq!(hx(&n1.binding), hex(P1_B));
        assert_eq!(hx(&n1.hiding_commitment), hex(P1_HC));
        assert_eq!(hx(&n1.binding_commitment), hex(P1_BC));
        assert_eq!(hx(&n3.hiding), hex(P3_H));
        assert_eq!(hx(&n3.binding), hex(P3_B));
        assert_eq!(hx(&n3.hiding_commitment), hex(P3_HC));
        assert_eq!(hx(&n3.binding_commitment), hex(P3_BC));
        (n1, n3)
    }

    fn e1_commitments(n1: &NoncePair, n3: &NoncePair) -> Vec<Commitment> {
        alloc::vec![n1.commitment(1), n3.commitment(3)]
    }

    #[test]
    fn e1_dealer_shares() {
        let (shares, full) = shard(&b32(GROUP_SECRET), &[b32(COEFF)], 3).unwrap();
        assert_eq!(shares.len(), 3);
        assert_eq!(hx(&shares[0].share), hex(SHARE1));
        assert_eq!(hx(&shares[2].share), hex(SHARE3));
        assert_eq!(full[0], b32(GROUP_SECRET));
        let g = base_mul(&parse_scalar(&b32(GROUP_SECRET)).unwrap()).unwrap();
        assert_eq!(hx(&g), hex(GROUP_PK));
        let back = combine(&[
            KeyShare { id: 1, share: b32(SHARE1) },
            KeyShare { id: 3, share: b32(SHARE3) },
        ])
        .unwrap();
        assert_eq!(hx(&back), hex(GROUP_SECRET));
        let vss = vss_commit(&full).unwrap();
        for s in &shares {
            assert!(vss_verify(s, &vss).unwrap());
        }
        let (group, pks) = group_info(3, &vss).unwrap();
        assert_eq!(hx(&group), hex(GROUP_PK));
        let p1 = base_mul(&parse_scalar(&b32(SHARE1)).unwrap()).unwrap();
        assert_eq!(pks[0], p1);
    }

    #[test]
    fn e1_round1_and_binding_factors() {
        let (n1, n3) = e1_nonces();
        let list = e1_commitments(&n1, &n3);
        let factors = compute_binding_factors(&b32(GROUP_PK), &list, &hex(MSG)).unwrap();
        assert_eq!(factors.len(), 2);
        assert_eq!(factors[0].0, 1);
        assert_eq!(hx(&factors[0].1), hex(RHO1));
        assert_eq!(factors[1].0, 3);
        assert_eq!(hx(&factors[1].1), hex(RHO3));
    }

    #[test]
    fn e1_round2_and_aggregate() {
        let (n1, n3) = e1_nonces();
        let list = e1_commitments(&n1, &n3);
        let msg = hex(MSG);
        let pk = b32(GROUP_PK);
        let s1 = sign(1, &b32(SHARE1), &pk, &n1, &msg, &list).unwrap();
        let s3 = sign(3, &b32(SHARE3), &pk, &n3, &msg, &list).unwrap();
        assert_eq!(hx(&s1), hex(SIG1));
        assert_eq!(hx(&s3), hex(SIG3));
        let (r, z) = aggregate(&list, &msg, &pk, &[s1, s3]).unwrap();
        assert_eq!(hx(&encode_signature(&r, &z)), hex(SIG));
        assert!(verify_signature(&r, &z, &pk, &msg));
        // Cross-check with the crate RFC 8032 verifier.
        {
            use crate::signature::ed25519::{PublicKey, Signature};
            let sig = encode_signature(&r, &z);
            let mut raw = [0u8; 64];
            raw.copy_from_slice(&sig);
            assert!(crate::signature::ed25519::verify(&PublicKey(pk), &msg, &Signature(raw)).is_ok());
        }
        let (dr, dz) = decode_signature(&hex(SIG)).unwrap();
        assert_eq!((dr, dz), (r, z));
        // Wrong message must fail.
        assert!(!verify_signature(&r, &z, &pk, &[0x00]));
    }

    #[test]
    fn e1_share_verification_catches_tampering() {
        let (n1, n3) = e1_nonces();
        let list = e1_commitments(&n1, &n3);
        let msg = hex(MSG);
        let pk = b32(GROUP_PK);
        let s1 = sign(1, &b32(SHARE1), &pk, &n1, &msg, &list).unwrap();
        let pk1 = base_mul(&parse_scalar(&b32(SHARE1)).unwrap()).unwrap();
        assert!(verify_share(1, &pk1, &list[0], &s1, &list, &pk, &msg).unwrap());
        let mut bad = s1;
        bad[0] ^= 1;
        assert!(!verify_share(1, &pk1, &list[0], &bad, &list, &pk, &msg).unwrap());
    }

    #[test]
    fn rejects_bad_inputs() {
        assert_eq!(shard(&b32(GROUP_SECRET), &[b32(COEFF)], 0).unwrap_err(), FrostError::InvalidLength);
        assert_eq!(combine(&[]).unwrap_err(), FrostError::TooFewShares);
        let dup = alloc::vec![
            KeyShare { id: 1, share: b32(SHARE1) },
            KeyShare { id: 1, share: b32(SHARE3) },
        ];
        assert_eq!(combine(&dup).unwrap_err(), FrostError::InvalidParticipant);
        assert!(derive_interpolating_value(&[1, 3], 2).is_err());
        // Scalar ≥ L rejected (all 0xff LE is huge).
        assert_eq!(parse_scalar(&[0xffu8; 32]).unwrap_err(), FrostError::InvalidScalar);
        // Identity + low-order points rejected.
        assert!(parse_point(&[0u8; 32]).is_err());
        // 2^3*...: canonical encoding of a small-order point must fail
        // subgroup check (e.g. all-zero X with valid sign bit patterns
        // are not on the curve at all).
        assert!(parse_point(&b32("0000000000000000000000000000000000000000000000000000000000000080")).is_err());
        assert!(decode_signature(&[0u8; 63]).is_err());
        // Unsorted input still works (sorted internally).
        let (n1, n3) = e1_nonces();
        let rev = alloc::vec![n3.commitment(3), n1.commitment(1)];
        let fwd = e1_commitments(&n1, &n3);
        let a = compute_binding_factors(&b32(GROUP_PK), &rev, &hex(MSG)).unwrap();
        let b = compute_binding_factors(&b32(GROUP_PK), &fwd, &hex(MSG)).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn rejects_quorum_mismatch() {
        let (n1, n3) = e1_nonces();
        let list = e1_commitments(&n1, &n3);
        let msg = hex(MSG);
        let pk = b32(GROUP_PK);
        let s1 = sign(1, &b32(SHARE1), &pk, &n1, &msg, &list).unwrap();
        let pk1 = base_mul(&parse_scalar(&b32(SHARE1)).unwrap()).unwrap();
        // Single share is not a quorum, even against one commitment.
        assert_eq!(
            aggregate(&list[..1], &msg, &pk, &[s1]).unwrap_err(),
            FrostError::TooFewShares
        );
        // Share/commitment count mismatch (3 shares vs 2 commitments).
        assert_eq!(
            aggregate(&list, &msg, &pk, &[s1, s1, s1]).unwrap_err(),
            FrostError::InvalidLength
        );
        // Standalone commitment diverging from the list entry.
        let mut bad_comm = list[0].clone();
        bad_comm.binding = list[1].binding;
        assert_eq!(
            verify_share(1, &pk1, &bad_comm, &s1, &list, &pk, &msg).unwrap_err(),
            FrostError::InvalidCommitment
        );
        // Identifier absent from the commitment list.
        let unknown = Commitment { id: 2, ..list[0].clone() };
        assert_eq!(
            verify_share(2, &pk1, &unknown, &s1, &list, &pk, &msg).unwrap_err(),
            FrostError::InvalidParticipant
        );
        // Single share is not a combine quorum.
        assert_eq!(
            combine(&[KeyShare { id: 1, share: b32(SHARE1) }]).unwrap_err(),
            FrostError::TooFewShares
        );
        // Over-degree polynomial (t=5 > MAX=3) and tiny MAX.
        assert_eq!(
            shard(&b32(GROUP_SECRET), &[b32(COEFF), b32(COEFF), b32(COEFF), b32(COEFF)], 3)
                .unwrap_err(),
            FrostError::InvalidLength
        );
        assert_eq!(
            shard(&b32(GROUP_SECRET), &[b32(COEFF)], 1).unwrap_err(),
            FrostError::InvalidLength
        );
    }

    #[test]
    fn reshare_threshold_roundtrip() {
        use crate::curve::traits::CurvePoint;
        let seed = |v: u8| [v; 32];
        let ids = [1u32, 2, 3];
        // Seeds are expanded at the boundary; the core takes scalars only.
        let expand = |s: &[u8; 32]| secret_to_scalar_bytes(s, 0).unwrap();
        let secrets = [expand(&seed(0x11)), expand(&seed(0x22)), expand(&seed(0x33))];
        let coeffs = [expand(&seed(0x44)), expand(&seed(0x55)), expand(&seed(0x66))];
        let (shares, pubs, group) = reshare(&ids, &secrets, &coeffs, 2).unwrap();
        assert_eq!(shares.len(), 3);
        assert_eq!(pubs.len(), 3);
        // Expanded original scalars and their sum.
        let mut acc = Ed25519Point::identity();
        let mut sum = Scalar::zero();
        for sj in &secrets {
            let aj = parse_scalar(sj).unwrap();
            sum = sum.add(&aj);
            let enc = base_mul(&aj).unwrap();
            acc = acc.add(&parse_point(&enc).unwrap());
        }
        // group == sum of original pubs == G * S.
        assert_eq!(point_bytes(&acc).unwrap(), group);
        assert_eq!(base_mul(&sum).unwrap(), group);
        let expected = scalar_bytes(&sum);
        for pair in [[0usize, 1], [1, 2], [0, 2]] {
            let ks = alloc::vec![
                KeyShare { id: ids[pair[0]], share: shares[pair[0]] },
                KeyShare { id: ids[pair[1]], share: shares[pair[1]] },
            ];
            assert_eq!(combine(&ks).unwrap(), expected);
        }
        for (sh, pb) in shares.iter().zip(pubs.iter()) {
            assert_eq!(base_mul(&parse_scalar(sh).unwrap()).unwrap(), *pb);
        }
        assert_eq!(reshare(&ids, &secrets, &coeffs, 1).unwrap_err(), FrostError::InvalidLength);
        assert_eq!(reshare(&ids, &secrets, &coeffs, 0).unwrap_err(), FrostError::InvalidLength);
        assert_eq!(reshare(&ids, &secrets, &coeffs, 4).unwrap_err(), FrostError::InvalidLength);
        assert_eq!(reshare(&ids, &secrets, &coeffs[..2], 2).unwrap_err(), FrostError::InvalidLength);
        assert_eq!(reshare(&ids, &secrets[..2], &coeffs, 2).unwrap_err(), FrostError::InvalidLength);
        assert_eq!(reshare(&[1, 1, 2], &secrets, &coeffs, 2).unwrap_err(), FrostError::InvalidParticipant);
        assert_eq!(reshare(&[1], &secrets[..1], &[], 2).unwrap_err(), FrostError::InvalidLength);
    }
}
