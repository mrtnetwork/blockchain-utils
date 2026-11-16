//! FROST(secp256k1, SHA-256) — RFC 9591 Section 6.5.
//!
//! Byte-compatible with the RFC Appendix E.5 vectors (see tests below)
//! and with the reference prototype in `reference frost tests/`.
//!
//! ## Safety / constant-time notes
//!
//! - Secret scalars (`Scalar`) only flow through the constant-time
//!   field backend (`add`/`mul`/`neg`/fixed-window `mul_ct`) and
//!   `ct_select`-style helpers; there is no branching on secret data.
//! - `Scalar::invert` loops over the (public, constant) group order
//!   bits; Lagrange denominators only depend on public identifiers.
//! - Rejection of malformed encodings inspects public bytes only.
//! - Callers must wipe [`NoncePair`] (and share buffers) after use;
//!   [`NoncePair::zeroize`] does best-effort wiping via `ct_zeroize`.
//! - Nonces MUST never be reused across signing sessions (Section 7.3).

use super::error::{FrostError, FrostResult};
use super::hash;
use crate::ct::ct_zeroize;
use crate::curve::secp256k1::{Scalar, Secp256k1Point};
use crate::curve::traits::CurvePoint;
use alloc::vec::Vec;

/// Ciphersuite context string (RFC 9591 Section 6.5).
pub const CONTEXT: &str = "FROST-secp256k1-SHA256-v1";
/// Compressed element length (SEC1).
pub const ELEMENT_LEN: usize = 33;
/// Scalar length (SEC1 Field-Element-to-Octet-String).
pub const SCALAR_LEN: usize = 32;
/// Canonical signature length `R (33) || z (32)` (Appendix A).
pub const SIGNATURE_LEN: usize = 65;

/// Output of [`reshare`]: `(new_shares, new_pubs, group)`.
pub type ReshareOutput = (
    Vec<[u8; SCALAR_LEN]>,
    Vec<[u8; ELEMENT_LEN]>,
    [u8; ELEMENT_LEN],
);

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
    s.to_bytes_be(&mut out);
    out
}

/// Lift a small identifier into a Scalar (infallible: `id < n`).
fn id_scalar(id: u32) -> Scalar {
    let mut b = [0u8; SCALAR_LEN];
    b[28..32].copy_from_slice(&id.to_be_bytes());
    Scalar::from_bytes_mod_order(&b)
}

fn serialize_id(id: u32) -> [u8; SCALAR_LEN] {
    scalar_bytes(&id_scalar(id))
}

/// Reduce an arbitrary-length big-endian string mod `n` (RFC 9380
/// `hash_to_field` tail step). Fixed loop; CT scalar ops only.
fn scalar_from_uniform_be(uniform: &[u8]) -> Scalar {
    let s256 = id_scalar(256);
    let mut acc = Scalar::zero();
    for byte in uniform {
        acc = acc.mul(&s256).add(&id_scalar(*byte as u32));
    }
    acc
}

fn parse_point(bytes: &[u8; ELEMENT_LEN]) -> FrostResult<Secp256k1Point> {
    let p = Secp256k1Point::from_bytes(bytes).map_err(|_| FrostError::InvalidKey)?;
    if p.ct_is_identity() == 1 {
        return Err(FrostError::InvalidKey);
    }
    Ok(p)
}

fn point_bytes(p: &Secp256k1Point) -> FrostResult<[u8; ELEMENT_LEN]> {
    if p.ct_is_identity() == 1 {
        return Err(FrostError::InvalidKey);
    }
    let mut out = [0u8; ELEMENT_LEN];
    p.to_bytes_compressed(&mut out)
        .map_err(|_| FrostError::InvalidKey)?;
    Ok(out)
}

fn base_mul(s: &Scalar) -> FrostResult<[u8; ELEMENT_LEN]> {
    let p = Secp256k1Point::generator().mul(s);
    point_bytes(&p)
}

// ---------------------------------------------------------------------------
// Hashes H1..H5 (Section 6.5).
// ---------------------------------------------------------------------------

fn dst(label: &[u8]) -> Vec<u8> {
    let mut d = Vec::with_capacity(CONTEXT.len() + label.len());
    d.extend_from_slice(CONTEXT.as_bytes());
    d.extend_from_slice(label);
    d
}

/// `H1(m) = hash_to_field(m, 1)`, DST `context || "rho"`, SHA-256, L=48.
pub fn h1(m: &[u8]) -> FrostResult<Scalar> {
    let uniform = hash::expand_message_xmd_sha256(m, &dst(b"rho"), 48)?;
    Ok(scalar_from_uniform_be(&uniform))
}

/// `H2(m) = hash_to_field(m, 1)`, DST `context || "chal"`, SHA-256, L=48.
pub fn h2(m: &[u8]) -> FrostResult<Scalar> {
    let uniform = hash::expand_message_xmd_sha256(m, &dst(b"chal"), 48)?;
    Ok(scalar_from_uniform_be(&uniform))
}

/// `H3(m) = hash_to_field(m, 1)`, DST `context || "nonce"`, SHA-256, L=48.
pub fn h3(m: &[u8]) -> FrostResult<Scalar> {
    let uniform = hash::expand_message_xmd_sha256(m, &dst(b"nonce"), 48)?;
    Ok(scalar_from_uniform_be(&uniform))
}

/// `H4(m) = H(context || "msg" || m)`, raw 32 bytes.
pub fn h4(m: &[u8]) -> FrostResult<[u8; 32]> {
    let mut pre = Vec::with_capacity(CONTEXT.len() + 3 + m.len());
    pre.extend_from_slice(CONTEXT.as_bytes());
    pre.extend_from_slice(b"msg");
    pre.extend_from_slice(m);
    hash::sha256(&pre)
}

/// `H5(m) = H(context || "com" || m)`, raw 32 bytes.
pub fn h5(m: &[u8]) -> FrostResult<[u8; 32]> {
    let mut pre = Vec::with_capacity(CONTEXT.len() + 3 + m.len());
    pre.extend_from_slice(CONTEXT.as_bytes());
    pre.extend_from_slice(b"com");
    pre.extend_from_slice(m);
    hash::sha256(&pre)
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
            // Constant-time select on PUBLIC identifiers (no secret data).
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
        // den *= (x_j - x_i): sub via add(neg) (no Scalar::sub exists).
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
    // Validate point encodings eagerly (identity/off-curve rejected).
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
    let mut prefix = Vec::with_capacity(ELEMENT_LEN + 32 + 32);
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
    let mut acc = Secp256k1Point::identity();
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
        // Re-parse avoids keeping parsed copies alive longer than needed.
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
    let lhs = point_bytes(&Secp256k1Point::generator().mul(&z))?;
    let comm_share = hiding.add(&binding.mul(&rho));
    let rhs = point_bytes(&comm_share.add(&pk.mul(&c.mul(&lambda))))?;
    Ok(lhs == rhs)
}

/// Appendix-B verification: `z*G == R + c*PK`. Pure `false` on any
/// malformed encoding (attacker-controlled bytes are not errors).
pub fn verify_signature(
    group_commitment: &[u8; ELEMENT_LEN],
    z: &[u8; SCALAR_LEN],
    group_pk: &[u8; ELEMENT_LEN],
    msg: &[u8],
) -> bool {
    let r = match parse_point(group_commitment) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let zz = match parse_scalar(z) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let pk = match parse_point(group_pk) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let c_enc = match compute_challenge(group_commitment, group_pk, msg) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let c = match parse_scalar(&c_enc) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let lhs = Secp256k1Point::generator().mul(&zz);
    let rhs = r.add(&pk.mul(&c));
    match (point_bytes(&lhs), point_bytes(&rhs)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// Canonical encoding (Appendix A): `R (33) || z (32)`.
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

/// Threshold reshare over independent secrets (RFC 9591 adaptation).
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
    let mut gacc = Secp256k1Point::identity();
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

/// Additive-rescale signing shares: for additive quorums pre-divide each
/// share by its full-set Lagrange weight (`w_i = s_i / λ_i`) so subset
/// interpolation reconstructs the sum. Shamir quorums pass through raw.
/// k1 secrets are always canonical scalars; constant-time scalar backend.
pub fn prepare_shares(
    ids: &[u32],
    shares: &[[u8; SCALAR_LEN]],
    threshold: u16,
) -> FrostResult<Vec<[u8; SCALAR_LEN]>> {
    if ids.len() != shares.len() {
        return Err(FrostError::InvalidLength);
    }
    let additive = check_quorum(ids.len(), threshold)?;
    check_ids(ids)?;
    let mut secs = Vec::with_capacity(shares.len());
    for s in shares {
        let v = parse_scalar(s)?;
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
    let mut acc = Secp256k1Point::identity();
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
    let mut acc = Secp256k1Point::identity();
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
        let mut acc = Secp256k1Point::identity();
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
// Tests: RFC 9591 Appendix E.5 vectors + negative/roundtrip checks.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::traits::CurvePoint;

    fn hex(s: &str) -> Vec<u8> {
        let s: Vec<u8> = s
            .bytes()
            .filter(|b| !b.is_ascii_whitespace())
            .collect();
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

    fn b33(s: &str) -> [u8; 33] {
        let v = hex(s);
        assert_eq!(v.len(), 33);
        let mut o = [0u8; 33];
        o.copy_from_slice(&v);
        o
    }

    fn hx(b: &[u8]) -> Vec<u8> {
        b.to_vec()
    }

    const GROUP_SECRET: &str = "0d004150d27c3bf2a42f312683d35fac7394b1e9e318249c1bfe7f0795a83114";
    const GROUP_PK: &str = "02f37c34b66ced1fb51c34a90bdae006901f10625cc06c4f64663b0eae87d87b4f";
    const COEFF: &str = "fbf85eadae3058ea14f19148bb72b45e4399c0b16028acaf0395c9b03c823579";
    const MSG: &str = "74657374";
    const SHARE1: &str = "08f89ffe80ac94dcb920c26f3f46140bfc7f95b493f8310f5fc1ea2b01f4254c";
    const SHARE2: &str = "04f0feac2edcedc6ce1253b7fab8c86b856a797f44d83d82a385554e6e401984";
    const SHARE3: &str = "00e95d59dd0d46b0e303e500b62b7ccb0e555d49f5b849f5e748c071da8c0dbc";
    const P1_HRAND: &str = "7ea5ed09af19f6ff21040c07ec2d2adbd35b759da5a401d4c99dd26b82391cb2";
    const P1_BRAND: &str = "47acab018f116020c10cb9b9abdc7ac10aae1b48ca6e36dc15acb6ec9be5cdc5";
    const P1_H: &str = "841d3a6450d7580b4da83c8e618414d0f024391f2aeb511d7579224420aa81f0";
    const P1_B: &str = "8d2624f532af631377f33cf44b5ac5f849067cae2eacb88680a31e77c79b5a80";
    const P1_HC: &str = "03c699af97d26bb4d3f05232ec5e1938c12f1e6ae97643c8f8f11c9820303f1904";
    const P1_BC: &str = "02fa2aaccd51b948c9dc1a325d77226e98a5a3fe65fe9ba213761a60123040a45e";
    const P3_HRAND: &str = "e6cc56ccbd0502b3f6f831d91e2ebd01c4de0479e0191b66895a4ffd9b68d544";
    const P3_BRAND: &str = "7203d55eb82a5ca0d7d83674541ab55f6e76f1b85391d2c13706a89a064fd5b9";
    const P3_H: &str = "2b19b13f193f4ce83a399362a90cdc1e0ddcd83e57089a7af0bdca71d47869b2";
    const P3_B: &str = "7a443bde83dc63ef52dda354005225ba0e553243402a4705ce28ffaafe0f5b98";
    const P3_HC: &str = "03077507ba327fc074d2793955ef3410ee3f03b82b4cdc2370f71d865beb926ef6";
    const P3_BC: &str = "02ad53031ddfbbacfc5fbda3d3b0c2445c8e3e99cbc4ca2db2aa283fa68525b135";
    const RHO1: &str = "3e08fe561e075c653cbfd46908a10e7637c70c74f0a77d5fd45d1a750c739ec6";
    const RHO3: &str = "93f79041bb3fd266105be251adaeb5fd7f8b104fb554a4ba9a0becea48ddbfd7";
    const SIG1: &str = "c4fce1775a1e141fb579944166eab0d65eefe7b98d480a569bbbfcb14f91c197";
    const SIG3: &str = "0160fd0d388932f4826d2ebcd6b9eaba734f7c71cf25b4279a4ca2581e47b18d";
    const SIG: &str = "0205b6d04d3774c8929413e3c76024d54149c372d57aae62574ed74319b5ea14d0c65dde8492a7471437e6c2fe3da49b90d23f642b5c6dbe7e36089f096dd97324";

    fn e5_nonces() -> (NoncePair, NoncePair) {
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

    fn e5_commitments(n1: &NoncePair, n3: &NoncePair) -> Vec<Commitment> {
        alloc::vec![n1.commitment(1), n3.commitment(3)]
    }

    #[test]
    fn e5_dealer_shares() {
        let (shares, full) = shard(&b32(GROUP_SECRET), &[b32(COEFF)], 3).unwrap();
        assert_eq!(shares.len(), 3);
        assert_eq!(hx(&shares[0].share), hex(SHARE1));
        assert_eq!(hx(&shares[1].share), hex(SHARE2));
        assert_eq!(hx(&shares[2].share), hex(SHARE3));
        assert_eq!(full[0], b32(GROUP_SECRET));
        // Group key from secret.
        let g = base_mul(&parse_scalar(&b32(GROUP_SECRET)).unwrap()).unwrap();
        assert_eq!(hx(&g), hex(GROUP_PK));
        // Combine P1+P3 recovers the secret.
        let back = combine(&[
            KeyShare { id: 1, share: b32(SHARE1) },
            KeyShare { id: 3, share: b32(SHARE3) },
        ])
        .unwrap();
        assert_eq!(hx(&back), hex(GROUP_SECRET));
        // VSS round-trip.
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
    fn e5_round1_and_binding_factors() {
        let (n1, n3) = e5_nonces();
        let list = e5_commitments(&n1, &n3);
        let factors = compute_binding_factors(&b33(GROUP_PK), &list, &hex(MSG)).unwrap();
        assert_eq!(factors.len(), 2);
        assert_eq!(factors[0].0, 1);
        assert_eq!(hx(&factors[0].1), hex(RHO1));
        assert_eq!(factors[1].0, 3);
        assert_eq!(hx(&factors[1].1), hex(RHO3));
    }

    #[test]
    fn e5_round2_and_aggregate() {
        let (n1, n3) = e5_nonces();
        let list = e5_commitments(&n1, &n3);
        let msg = hex(MSG);
        let pk = b33(GROUP_PK);
        let s1 = sign(1, &b32(SHARE1), &pk, &n1, &msg, &list).unwrap();
        let s3 = sign(3, &b32(SHARE3), &pk, &n3, &msg, &list).unwrap();
        assert_eq!(hx(&s1), hex(SIG1));
        assert_eq!(hx(&s3), hex(SIG3));
        let (r, z) = aggregate(&list, &msg, &pk, &[s1, s3]).unwrap();
        assert_eq!(hx(&encode_signature(&r, &z)), hex(SIG));
        assert!(verify_signature(&r, &z, &pk, &msg));
        let (dr, dz) = decode_signature(&hex(SIG)).unwrap();
        assert_eq!((dr, dz), (r, z));
        // Correlate: generator mul sanity.
        let g = Secp256k1Point::generator();
        let mut enc = [0u8; 33];
        g.to_bytes_compressed(&mut enc).unwrap();
        assert_eq!(enc[0], 0x02);
    }

    #[test]
    fn e5_share_verification_catches_tampering() {
        let (n1, n3) = e5_nonces();
        let list = e5_commitments(&n1, &n3);
        let msg = hex(MSG);
        let pk = b33(GROUP_PK);
        let s1 = sign(1, &b32(SHARE1), &pk, &n1, &msg, &list).unwrap();
        let pk1 = base_mul(&parse_scalar(&b32(SHARE1)).unwrap()).unwrap();
        assert!(verify_share(1, &pk1, &list[0], &s1, &list, &pk, &msg).unwrap());
        let mut bad = s1;
        bad[31] = bad[31].wrapping_add(1);
        // Carry into range is still < n here (E.5 share ends 0x97).
        assert!(!verify_share(1, &pk1, &list[0], &bad, &list, &pk, &msg).unwrap());
        assert!(!verify_signature(&encode_signature(&list[0].hiding, &s1)[..33].try_into().unwrap(), &s1, &pk, &[0x00]));
    }

    #[test]
    fn rejects_bad_inputs() {
        assert_eq!(shard(&b32(GROUP_SECRET), &[b32(COEFF)], 0).unwrap_err(), FrostError::InvalidLength);
        assert_eq!(combine(&[]).unwrap_err(), FrostError::TooFewShares);
        // Duplicate ids.
        let dup = alloc::vec![
            KeyShare { id: 1, share: b32(SHARE1) },
            KeyShare { id: 1, share: b32(SHARE3) },
        ];
        assert_eq!(combine(&dup).unwrap_err(), FrostError::InvalidParticipant);
        // Zero id.
        assert!(derive_interpolating_value(&[1, 3], 0).is_err());
        assert!(derive_interpolating_value(&[1, 1], 1).is_err());
        // Bad encodings.
        assert_eq!(parse_scalar(&[0xffu8; 32]).unwrap_err(), FrostError::InvalidScalar);
        assert!(parse_point(&[0u8; 33]).is_err());
        assert!(decode_signature(&[0u8; 64]).is_err());
        // Unsorted input still works (sorted internally).
        let (n1, n3) = e5_nonces();
        let rev = alloc::vec![n3.commitment(3), n1.commitment(1)];
        let fwd = e5_commitments(&n1, &n3);
        let a = compute_binding_factors(&b33(GROUP_PK), &rev, &hex(MSG)).unwrap();
        let b = compute_binding_factors(&b33(GROUP_PK), &fwd, &hex(MSG)).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn rejects_quorum_mismatch() {
        let (n1, n3) = e5_nonces();
        let list = e5_commitments(&n1, &n3);
        let msg = hex(MSG);
        let pk = b33(GROUP_PK);
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
        fn s(v: u8) -> [u8; 32] {
            let mut b = [0u8; 32];
            b[31] = v;
            b
        }
        let ids = [1u32, 2, 3];
        let secrets = [s(1), s(2), s(3)];
        let coeffs = [s(4), s(5), s(6)];
        let (shares, pubs, group) = reshare(&ids, &secrets, &coeffs, 2).unwrap();
        assert_eq!(shares.len(), 3);
        assert_eq!(pubs.len(), 3);
        // group == sum of original pubs.
        let mut acc = Secp256k1Point::identity();
        let mut sum = Scalar::zero();
        for sj in &secrets {
            let aj = parse_scalar(sj).unwrap();
            sum = sum.add(&aj);
            let enc = base_mul(&aj).unwrap();
            acc = acc.add(&parse_point(&enc).unwrap());
        }
        assert_eq!(point_bytes(&acc).unwrap(), group);
        // group == G * S.
        assert_eq!(base_mul(&sum).unwrap(), group);
        let expected = scalar_bytes(&sum);
        // Any 2 new shares combine to S.
        for pair in [[0usize, 1], [1, 2], [0, 2]] {
            let ks = alloc::vec![
                KeyShare { id: ids[pair[0]], share: shares[pair[0]] },
                KeyShare { id: ids[pair[1]], share: shares[pair[1]] },
            ];
            assert_eq!(combine(&ks).unwrap(), expected);
        }
        // New pubs match base_mul of new shares.
        for (sh, pb) in shares.iter().zip(pubs.iter()) {
            assert_eq!(base_mul(&parse_scalar(sh).unwrap()).unwrap(), *pb);
        }
        // Rejections.
        assert_eq!(reshare(&ids, &secrets, &coeffs, 1).unwrap_err(), FrostError::InvalidLength);
        assert_eq!(reshare(&ids, &secrets, &coeffs, 0).unwrap_err(), FrostError::InvalidLength);
        assert_eq!(reshare(&ids, &secrets, &coeffs, 4).unwrap_err(), FrostError::InvalidLength);
        assert_eq!(reshare(&ids, &secrets, &coeffs[..2], 2).unwrap_err(), FrostError::InvalidLength);
        assert_eq!(reshare(&ids, &secrets[..2], &coeffs, 2).unwrap_err(), FrostError::InvalidLength);
        assert_eq!(reshare(&[1, 1, 2], &secrets, &coeffs, 2).unwrap_err(), FrostError::InvalidParticipant);
        assert_eq!(reshare(&[1], &secrets[..1], &[], 2).unwrap_err(), FrostError::InvalidLength);
    }
}
