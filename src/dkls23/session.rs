//! In-process session drivers (tests, FFI/WASM orchestration reference).
//!
//! Network transport lives outside this crate: production callers relay
//! the round messages. These drivers run all `n` parties in-process with
//! explicit seeds so KATs are deterministic and WASM-safe. Every secret
//! stays inside its party struct; only broadcasts cross the boundary.

use super::codec::{CompactSig, KeyShare};
use super::curve_id::{CurveId, DklsPoint, DklsScalar};
use super::dkg;
use super::error::{DklsError, DklsResult};
use super::schnorr;
use super::sign;
use crate::rng::ChaCha20Rng;
use alloc::vec::Vec;

/// Mix a caller seed with the session id into a session-bound RNG.
/// Same `(seed, sid)` always derives the same stream (deterministic
/// KATs); different `sid` values diverge (session binding).
fn session_rng(seed: &[u8; 32], sid: &[u8]) -> ChaCha20Rng {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(seed);
    let h = crate::hash::sha256::sha256(sid).unwrap_or([0u8; 32]);
    buf[32..].copy_from_slice(&h);
    let mixed = crate::hash::sha256::sha256(&buf).unwrap_or([0u8; 32]);
    ChaCha20Rng::from_seed(&mixed)
}

/// Run full DKG for `n` parties, threshold `t`, under `sid`.
///
/// Each party gets a deterministic seed `seed[i]`; aborts identify the
/// offender by index in the error path.
///
/// NOTE (OT BLOCKER, outstanding): the column proofs below are assembled
/// in-process from every dealer's unicast plus that column's dealer
/// nonce. A deployed network transport must instead run the paper's
/// pairwise OT-based multiplication so no single party ever holds the
/// full column secret; this driver is a KAT/FFI reference, not a
/// network protocol.
pub fn dkg_oneshot(
    curve: CurveId,
    sid: &[u8],
    n: usize,
    t: usize,
    seeds: &[[u8; 32]],
) -> DklsResult<Vec<KeyShare>> {
    if n == 0 || seeds.len() != n || t == 0 || t > n {
        return Err(DklsError::TooFew);
    }
    if sid.is_empty() {
        return Err(DklsError::InvalidLength);
    }
    // Round 1: dealers commit (openings kept in-process).
    let mut dealers = Vec::with_capacity(n);
    let mut r1s = Vec::with_capacity(n);
    let mut payloads: Vec<Vec<u8>> = Vec::with_capacity(n);
    let mut salts: Vec<Vec<u8>> = Vec::with_capacity(n);
    for (i, seed) in seeds.iter().enumerate().take(n) {
        let mut rng = session_rng(seed, sid);
        let (dealer, r1, salt) = dkg::dealer_round1_opening(&mut rng, i, curve, t, sid)?;
        // Use the round-1 opening verbatim: the commitment already
        // binds (sid, feldman, sch_commit, rid).
        payloads.push(dealer.payload.clone());
        salts.push(salt);
        dealers.push(dealer);
        r1s.push(r1);
    }
    // Unicast matrix.
    let mut sigmas: Vec<Vec<DklsScalar>> = Vec::with_capacity(n);
    for d in &dealers {
        let mut row = Vec::with_capacity(n);
        for i in 0..n {
            row.push(dkg::sigma_for(d, i));
        }
        sigmas.push(row);
    }
    // Schnorr proofs over column shares.
    let mut rid = alloc::vec![0u8; 32];
    for d in &dealers {
        for (k, b) in rid.iter_mut().enumerate() {
            *b ^= d.rid[k];
        }
    }
    let mut proofs = Vec::with_capacity(n);
    for (j, d) in dealers.iter().enumerate() {
        // Column public key y_j = Σ_k F_k(j+1).
        let mut y = DklsPoint::identity(curve);
        for q in &dealers {
            let fpts: Vec<DklsPoint> = q
                .coeffs
                .iter()
                .map(|c| DklsPoint::generator(curve).mul(c))
                .collect();
            y = y.add(&super::shares::eval_poly_points(
                &fpts,
                &super::shares::party_id(j, curve),
            ));
        }
        let y_enc = y.to_array_compressed().ok_or(DklsError::InvalidPoint)?;
        let mut sigma = DklsScalar::zero(curve);
        for row in &sigmas {
            sigma = sigma.add(&row[j]);
        }
        // Prove with the column secret, using this column dealer's
        // committed Schnorr nonce: the proof commitment then equals the
        // `sch_commit` bound in dealer j's round-2 payload, which is
        // exactly what `dkg_finish` checks.
        let mut ctx = Vec::with_capacity(sid.len() + 64);
        ctx.extend_from_slice(sid);
        ctx.extend_from_slice(&rid);
        ctx.extend_from_slice(&(j as u64).to_be_bytes());
        ctx.extend_from_slice(&y_enc);
        let a = d.sch_nonce.clone();
        let a_enc = DklsPoint::generator(curve)
            .mul(&a)
            .to_array_compressed()
            .ok_or(DklsError::InvalidPoint)?;
        let e_bytes = super::digest::tagged_hash(super::oracle::TAG_DLOG_PROOF, &[&ctx, &y_enc, &a_enc]);
        let e = DklsScalar::from_bytes_mod_order(curve, &e_bytes);
        let z = a.add(&e.mul(&sigma));
        proofs.push(schnorr::DlogProof { commitment: a_enc, response: z.to_array_be() });
    }
    let openings: Vec<(Vec<u8>, Vec<u8>)> =
        payloads.into_iter().zip(salts).collect();
    dkg::dkg_finish(curve, sid, n, t, &r1s, &openings, &sigmas, &proofs)
}

/// Run 2-party signing over `shares` on `msg_hash` (32 bytes).
///
/// Additive resharing is assumed (`x = Σ x_i`); threshold subsets must
/// be Lagrange-rescaled by the caller before invoking (the 2-of-2 path
/// needs no rescaling). Deterministic per-party seeds make KATs stable.
///
/// NOTE (OT BLOCKER, outstanding): the joint nonce `k = Σ k_i` is
/// reconstructed centrally here ONLY for the KAT/FFI reference driver —
/// production parties must never assemble `k` (paper Sec 4 / Abram
/// shares absent, `mul.rs` pads never exchanged over real OT). This
/// driver documents the honest transcript shape; it is not a network
/// protocol.
pub fn sign_oneshot(
    shares: &[KeyShare],
    sid: &[u8],
    msg_hash: &[u8; 32],
    seeds: &[[u8; 32]],
) -> DklsResult<CompactSig> {
    let n = shares.len();
    if n < 2 || seeds.len() != n {
        return Err(DklsError::TooFew);
    }
    if sid.is_empty() {
        return Err(DklsError::InvalidLength);
    }
    let curve = shares[0].curve;
    // Threshold rescale: DKG issues Shamir shares (σ_i = Σ_j f_j(i+1)),
    // so the signing subset must apply Lagrange weights for the secret
    // (`x = Σ λ_i·σ_i`) while fresh nonces stay purely additive.
    let ids: Vec<DklsScalar> = shares
        .iter()
        .map(|sh| super::shares::party_id(sh.party, curve))
        .collect();
    // Round 1: each signer commits; the openings stay in the signers.
    let mut signers = Vec::with_capacity(n);
    let mut r1s = Vec::with_capacity(n);
    let mut payloads: Vec<Vec<u8>> = Vec::with_capacity(n);
    for (sh, seed) in shares.iter().zip(seeds.iter()) {
        if sh.curve != curve {
            return Err(DklsError::InvalidParticipant);
        }
        let mut rng = session_rng(seed, sid);
        let (mut signer, r1) = sign::signer_round1(&mut rng, sh, sid)?;
        // Lagrange-rescale the key share into an additive share of x.
        let me_id = super::shares::party_id(sh.party, curve);
        let lambda = super::shares::lagrange_at_zero(&ids, &me_id)?;
        signer.x_i = lambda.mul(&signer.x_i);
        // Use the round-1 opening verbatim: the commitment already
        // binds (sid, curve, party, R_i).
        payloads.push(signer.payload.clone());
        signers.push(signer);
        r1s.push(r1);
    }
    // Round 2: reveals (same salts as round 1) + chi.
    let mut r2s = Vec::with_capacity(n);
    for s in &signers {
        let mut rng = ChaCha20Rng::from_seed(&[0u8; 32]);
        let (r2, _) = sign::signer_round2(&mut rng, s, sid, n)?;
        r2s.push(r2);
    }
    let (_, r_bytes) = sign::combine_nonce(curve, sid, &r1s, &r2s, &payloads)?;
    let r = DklsScalar::from_bytes_be(curve, &r_bytes).ok_or(DklsError::InvalidScalar)?;
    // Joint nonce k = Σ k_i (in-process reconstruction ONLY for the
    // KAT driver; production parties never assemble k).
    let mut k = DklsScalar::zero(curve);
    for s in &signers {
        k = k.add(&s.k_i);
    }
    if k.is_zero() {
        return Err(DklsError::ZeroSecret);
    }
    let k_inv = k.invert().ok_or(DklsError::ZeroSecret)?;
    // Split k_inv additively: party i uses k_inv/n.
    let n_scalar = {
        let mut b = [0u8; 32];
        b[24..32].copy_from_slice(&(n as u64).to_be_bytes());
        DklsScalar::from_bytes_mod_order(curve, &b)
    };
    let n_inv = n_scalar.invert().ok_or(DklsError::ZeroSecret)?;
    let k_part = k_inv.mul(&n_inv);
    let kr = k_inv.mul(&r);
    let e = DklsScalar::from_bytes_mod_order(curve, msg_hash);
    let mut parts = Vec::with_capacity(n);
    for s in &signers {
        parts.push(sign::signer_round3(s, &k_part, &kr, &e)?);
    }
    sign::combine_sig(curve, &r_bytes, &parts)
}

/// Import existing secrets as an additive n-of-n quorum (no DKG).
///
/// Each `secrets[i]` becomes party `i`'s additive share of the joint key
/// `x = Σ secrets[i]`, with group key `pk = Σ G·secrets[i]`. Because the
/// signing path always Lagrange-rescales over the signing subset, the
/// stored share is pre-divided (`w_i = x_i / λ_i` over the full set), so
/// the standard subset flow reconstructs exactly `x` when everybody
/// signs. Threshold is `Some(n)`; secrets must be canonical (`< q`) and
/// their sum nonzero. Deterministic — no RNG involved.
pub fn import_secrets(curve: CurveId, secrets: &[[u8; 32]]) -> DklsResult<Vec<KeyShare>> {
    let n = secrets.len();
    if n < 2 {
        return Err(DklsError::TooFew);
    }
    let mut xs = Vec::with_capacity(n);
    for s in secrets {
        xs.push(DklsScalar::from_bytes_be(curve, s).ok_or(DklsError::InvalidScalar)?);
    }
    let members: Vec<[u8; 33]> = xs
        .iter()
        .map(|x| {
            DklsPoint::generator(curve).mul(x).to_array_compressed().ok_or(DklsError::InvalidPoint)
        })
        .collect::<DklsResult<Vec<_>>>()?;
    let mut pk_pt = DklsPoint::identity(curve);
    for m in &members {
        pk_pt = pk_pt.add(&DklsPoint::from_bytes(curve, m).ok_or(DklsError::InvalidPoint)?);
    }
    if pk_pt.ct_is_identity() == 1 {
        return Err(DklsError::ZeroSecret);
    }
    let pk = pk_pt.to_array_compressed().ok_or(DklsError::InvalidPoint)?;
    let ids: Vec<DklsScalar> =
        (0..n).map(|i| super::shares::party_id(i, curve)).collect();
    let mut out = Vec::with_capacity(n);
    for (i, x) in xs.iter().enumerate() {
        let lambda = super::shares::lagrange_at_zero(&ids, &ids[i])?;
        let inv = lambda.invert().ok_or(DklsError::ZeroSecret)?;
        out.push(KeyShare {
            party: i,
            n,
            t: Some(n),
            curve,
            x: x.mul(&inv).to_array_be(),
            pk,
            shares: members.clone(),
        });
    }
    Ok(out)
}

/// Run verifiable key refresh over `shares` (public key unchanged).
///
/// Each party samples a zero-sum delta row from `seeds[i]` bound to
/// `sid`, broadcasts it, and all parties apply the column sums.
/// Deterministic under `(seeds, sid)`; WASM-safe.
pub fn refresh_oneshot(
    shares: &[KeyShare],
    sid: &[u8],
    seeds: &[[u8; 32]],
) -> DklsResult<Vec<KeyShare>> {
    let n = shares.len();
    if n == 0 || seeds.len() != n {
        return Err(DklsError::TooFew);
    }
    if sid.is_empty() {
        return Err(DklsError::InvalidLength);
    }
    let curve = shares[0].curve;
    for sh in shares {
        if sh.curve != curve {
            return Err(DklsError::InvalidParticipant);
        }
    }
    let mut msgs = Vec::with_capacity(n);
    let t = shares[0].t.unwrap_or(n);
    for (i, seed) in seeds.iter().enumerate() {
        let mut rng = session_rng(seed, sid);
        let (deltas, pts, feldman) = super::refresh::sample_deltas(&mut rng, curve, t, n)?;
        msgs.push(super::refresh::RefreshMsg {
            party: i,
            deltas: deltas.iter().map(|d| d.to_array_be()).collect(),
            delta_pts: pts
                .iter()
                .map(|p| p.to_array_compressed().ok_or(DklsError::InvalidPoint))
                .collect::<DklsResult<Vec<_>>>()?,
            feldman: feldman
                .iter()
                .map(|p| {
                    let mut enc = [0u8; 33];
                    // F[0] is the identity: K1/R1 backends encode it as
                    // the 33-zero slot, which `from_bytes` reopens.
                    if p.to_bytes_compressed(&mut enc) {
                        Ok(enc)
                    } else {
                        Err(DklsError::InvalidPoint)
                    }
                })
                .collect::<DklsResult<Vec<_>>>()?,
        });
    }
    super::refresh::refresh_apply(shares, &msgs, curve)
}
