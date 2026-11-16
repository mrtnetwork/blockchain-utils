//! Adversarial DKLs23 tests: every malicious deviation must abort with
//! the offender identified, never with a forged signature.
//!
//! Pattern per case: run the ceremony with one tampered message, assert
//! the expected error kind, then run the identification loop (the same
//! loop production callers use) and assert it names the exact tampered
//! party (and cell, where applicable).
//!
//! Plus larger committees: 3-of-5 DKG with every triple signing.

use blockchain_utils::dkls23::codec::KeyShare;
use blockchain_utils::dkls23::commit;
use blockchain_utils::dkls23::curve_id::{CurveId, DklsPoint, DklsScalar};
use blockchain_utils::dkls23::digest::tagged_hash;
use blockchain_utils::dkls23::dkg::{
    dealer_round1_opening, dkg_finish, parse_dkg_payload, sigma_for, Dealer, DkgR1,
};
use blockchain_utils::dkls23::error::{DklsError, DklsResult};
use blockchain_utils::dkls23::oracle::TAG_DLOG_PROOF;
use blockchain_utils::dkls23::schnorr::DlogProof;
use blockchain_utils::dkls23::session::{dkg_oneshot, refresh_oneshot, sign_oneshot};
use blockchain_utils::dkls23::shares::{eval_poly_points, party_id, verify_feldman_share};
use blockchain_utils::dkls23::sign as dsign;
use blockchain_utils::hash::sha256::sha256;
use blockchain_utils::rng::ChaCha20Rng;

// ---------------------------------------------------------------------------
// Local transcript driver (mirrors `session::dkg_oneshot` with hooks).
// ---------------------------------------------------------------------------

fn session_rng(seed: &[u8; 32], sid: &[u8]) -> ChaCha20Rng {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(seed);
    buf[32..].copy_from_slice(&sha256(sid).unwrap_or([0u8; 32]));
    ChaCha20Rng::from_seed(&sha256(&buf).unwrap_or([0u8; 32]))
}

fn seeds<const N: usize>(base: u8) -> [[u8; 32]; N] {
    let mut out = [[0u8; 32]; N];
    for (i, s) in out.iter_mut().enumerate() {
        for b in s.iter_mut() {
            *b = base.wrapping_add(i as u8);
        }
    }
    out
}

/// Full honest DKG transcript, reused across adversarial finish paths.
/// (`dealers` is retained for faithful transcript reconstruction even though
/// current checks only read the round artifacts below.)
#[allow(dead_code)]
struct Transcript {
    dealers: Vec<Dealer>,
    r1s: Vec<DkgR1>,
    payloads: Vec<Vec<u8>>,
    salts: Vec<Vec<u8>>,
    sigmas: Vec<Vec<DklsScalar>>,
    proofs: Vec<DlogProof>,
    y_cols: Vec<[u8; 33]>,
    rid: Vec<u8>,
}

fn honest_transcript(curve: CurveId, sid: &[u8], n: usize, t: usize, seeds: &[[u8; 32]]) -> Transcript {
    let mut dealers = Vec::with_capacity(n);
    let mut r1s = Vec::with_capacity(n);
    let mut payloads = Vec::with_capacity(n);
    let mut salts = Vec::with_capacity(n);
    for (i, seed) in seeds.iter().enumerate().take(n) {
        let mut rng = session_rng(seed, sid);
        // Use the round-1 opening verbatim (mirrors `session::dkg_oneshot`).
        let (dealer, r1, salt) = dealer_round1_opening(&mut rng, i, curve, t, sid).unwrap();
        payloads.push(dealer.payload.clone());
        salts.push(salt);
        dealers.push(dealer);
        r1s.push(r1);
    }
    let mut sigmas: Vec<Vec<DklsScalar>> = Vec::with_capacity(n);
    for d in &dealers {
        sigmas.push((0..n).map(|i| sigma_for(d, i)).collect());
    }
    let mut rid = vec![0u8; 32];
    for d in &dealers {
        for (k, b) in rid.iter_mut().enumerate() {
            *b ^= d.rid[k];
        }
    }
    let mut proofs = Vec::with_capacity(n);
    let mut y_cols = Vec::with_capacity(n);
    for j in 0..n {
        let mut y = DklsPoint::identity(curve);
        for q in &dealers {
            let fpts: Vec<DklsPoint> =
                q.coeffs.iter().map(|c| DklsPoint::generator(curve).mul(c)).collect();
            y = y.add(&eval_poly_points(&fpts, &party_id(j, curve)));
        }
        let y_enc = y.to_array_compressed().unwrap();
        y_cols.push(y_enc);
        let mut sigma = DklsScalar::zero(curve);
        for row in &sigmas {
            sigma = sigma.add(&row[j]);
        }
        // Prove with the column secret under this column dealer's
        // committed Schnorr nonce, so the proof commitment equals the
        // `sch_commit` bound in the payload (what `dkg_finish` checks).
        let mut ctx = Vec::new();
        ctx.extend_from_slice(sid);
        ctx.extend_from_slice(&rid);
        ctx.extend_from_slice(&(j as u64).to_be_bytes());
        ctx.extend_from_slice(&y_enc);
        let a = dealers[j].sch_nonce.clone();
        let a_enc = DklsPoint::generator(curve).mul(&a).to_array_compressed().unwrap();
        let e_bytes = tagged_hash(TAG_DLOG_PROOF, &[&ctx, &y_enc, &a_enc]);
        let e = DklsScalar::from_bytes_mod_order(curve, &e_bytes);
        proofs.push(DlogProof { commitment: a_enc, response: a.add(&e.mul(&sigma)).to_array_be() });
    }
    Transcript { dealers, r1s, payloads, salts, sigmas, proofs, y_cols, rid }
}

fn finish(tr: &Transcript, curve: CurveId, sid: &[u8], n: usize, t: usize) -> DklsResult<Vec<KeyShare>> {
    let openings: Vec<(Vec<u8>, Vec<u8>)> =
        tr.payloads.clone().into_iter().zip(tr.salts.clone()).collect();
    dkg_finish(curve, sid, n, t, &tr.r1s, &openings, &tr.sigmas, &tr.proofs)
}

/// Identification loop for commitment failures: first party whose
/// opening does not verify is the complainee.
fn find_bad_opener(tr: &Transcript) -> Option<usize> {
    tr.r1s.iter().enumerate().find_map(|(j, r1)| {
        commit::verify(&r1.commitment, &tr.payloads[j], &tr.salts[j]).err().map(|_| j)
    })
}

/// Identification loop for share failures: first (dealer, target) pair
/// failing the Feldman check.
fn find_bad_share(tr: &Transcript, curve: CurveId, t: usize) -> Option<(usize, usize)> {
    for j in 0..tr.r1s.len() {
        let (_, feldman, _, _) = parse_dkg_payload(&tr.payloads[j], t).unwrap();
        let mut pts = Vec::with_capacity(t);
        for enc in &feldman {
            pts.push(DklsPoint::from_bytes(curve, enc).unwrap());
        }
        for i in 0..tr.r1s.len() {
            if verify_feldman_share(&pts, i, &tr.sigmas[j][i]).is_err() {
                return Some((j, i));
            }
        }
    }
    None
}

fn expect_valid(curve: CurveId, pk: &[u8; 33], h: &[u8; 32], sig: &[u8; 64]) {
    match curve {
        CurveId::K1 => {
            let p = blockchain_utils::signature::ecdsa::PublicKey::from_bytes(pk).unwrap();
            let s = blockchain_utils::signature::ecdsa::Signature::from_compact(sig).unwrap();
            blockchain_utils::signature::ecdsa::verify(&p, h, &s).unwrap();
        }
        CurveId::R1 => {
            let p = blockchain_utils::signature::ecdsa_p256::PublicKey::from_bytes(pk).unwrap();
            let s = blockchain_utils::signature::ecdsa_p256::Signature::from_compact(sig).unwrap();
            blockchain_utils::signature::ecdsa_p256::verify(&p, h, &s).unwrap();
        }
    }
}

// ---------------------------------------------------------------------------
// Cases.
// ---------------------------------------------------------------------------

#[test]
fn liar_dealer_opening_identified() {
    for curve in [CurveId::K1, CurveId::R1] {
        let sid = b"adv-liar-opening";
        let s = seeds::<3>(0x11);
        let mut tr = honest_transcript(curve, sid, 3, 2, &s);
        // Dealer 1 reveals different Feldman bytes than committed.
        tr.payloads[1][0] ^= 0xFF;
        assert_eq!(finish(&tr, curve, sid, 3, 2).err(), Some(DklsError::BadCommitment));
        assert_eq!(find_bad_opener(&tr), Some(1));
        // Control: honest transcript finishes and identifies nobody.
        let good = honest_transcript(curve, sid, 3, 2, &s);
        assert!(finish(&good, curve, sid, 3, 2).is_ok());
        assert_eq!(find_bad_opener(&good), None);
    }
}

#[test]
fn forged_feldman_share_identified() {
    for curve in [CurveId::K1, CurveId::R1] {
        let sid = b"adv-forged-share";
        let s = seeds::<3>(0x22);
        let mut tr = honest_transcript(curve, sid, 3, 2, &s);
        // Dealer 1 sends party 0 a bogus unicast share.
        tr.sigmas[1][0] = DklsScalar::one(curve);
        assert_eq!(finish(&tr, curve, sid, 3, 2).err(), Some(DklsError::BadShare));
        assert_eq!(find_bad_share(&tr, curve, 2), Some((1, 0)));
        let good = honest_transcript(curve, sid, 3, 2, &s);
        assert_eq!(find_bad_share(&good, curve, 2), None);
    }
}

#[test]
fn forged_schnorr_proof_rejected() {
    for curve in [CurveId::K1, CurveId::R1] {
        let sid = b"adv-forged-proof";
        let s = seeds::<2>(0x33);
        let mut tr = honest_transcript(curve, sid, 2, 2, &s);
        tr.proofs[0].response[31] ^= 0x01;
        assert_eq!(finish(&tr, curve, sid, 2, 2).err(), Some(DklsError::BadProof));
        // Identify by re-verifying each proof against its column key.
        let mut culprit = None;
        for j in 0..2 {
            let y_pt = DklsPoint::from_bytes(curve, &tr.y_cols[j]).unwrap();
            let mut ctx = Vec::new();
            ctx.extend_from_slice(sid);
            ctx.extend_from_slice(&tr.rid);
            ctx.extend_from_slice(&(j as u64).to_be_bytes());
            ctx.extend_from_slice(&tr.y_cols[j]);
            if blockchain_utils::dkls23::schnorr::verify(curve, &y_pt, &tr.proofs[j], &ctx).is_err() {
                culprit = Some(j);
                break;
            }
        }
        assert_eq!(culprit, Some(0));
    }
}

#[test]
fn swapped_schnorr_commitment_rejected() {
    // D2/D3: the proof commitment must equal the Schnorr commitment the
    // dealer bound in its payload. Swapping in another valid point (even
    // one from a sibling proof) aborts with BadProof.
    for curve in [CurveId::K1, CurveId::R1] {
        let sid = b"adv-swapped-commitment";
        let s = seeds::<2>(0x34);
        let mut tr = honest_transcript(curve, sid, 2, 2, &s);
        // Control passes first.
        assert!(finish(&tr, curve, sid, 2, 2).is_ok());
        tr.proofs[0].commitment = tr.proofs[1].commitment;
        assert_eq!(finish(&tr, curve, sid, 2, 2).err(), Some(DklsError::BadProof));
    }
}

#[test]
fn empty_sid_rejected_everywhere() {
    for curve in [CurveId::K1, CurveId::R1] {
        assert_eq!(
            dkg_oneshot(curve, b"", 2, 2, &seeds::<2>(0x01)).err(),
            Some(DklsError::InvalidLength)
        );
        let shares = dkg_oneshot(curve, b"sid-ok", 2, 2, &seeds::<2>(0x01)).unwrap();
        let h = sha256(b"msg").unwrap();
        assert_eq!(
            sign_oneshot(&shares, b"", &h, &seeds::<2>(0x02)).err(),
            Some(DklsError::InvalidLength)
        );
        assert_eq!(
            refresh_oneshot(&shares, b"", &seeds::<2>(0x03)).err(),
            Some(DklsError::InvalidLength)
        );
    }
}

#[test]
fn sign_tampered_reveal_identified() {
    use blockchain_utils::dkls23::sign::parse_sign_payload;
    for curve in [CurveId::K1, CurveId::R1] {
        let sid = b"adv-sign-tamper";
        let shares = dkg_oneshot(curve, sid, 2, 2, &seeds::<2>(0x44)).unwrap();
        // Round 1 honestly, then tamper party 1's revealed nonce point.
        let mut signers = Vec::new();
        let mut r1s = Vec::new();
        let mut payloads = Vec::new();
        for (sh, seed) in shares.iter().zip(seeds::<2>(0x45).iter()) {
            let mut rng = session_rng(seed, sid);
            // Use the round-1 opening verbatim (mirrors the session driver).
            let (signer, r1) = dsign::signer_round1(&mut rng, sh, sid).unwrap();
            payloads.push(signer.payload.clone());
            signers.push(signer);
            r1s.push(r1);
        }
        let mut r2s = Vec::new();
        for x in &signers {
            let mut rng = ChaCha20Rng::from_seed(&[0u8; 32]);
            r2s.push(dsign::signer_round2(&mut rng, x, sid, 2).unwrap().0);
        }
        // Attacker swaps party 1's nonce point for the generator.
        r2s[1].nonce_pt = DklsPoint::generator(curve).to_array_compressed().unwrap();
        assert!(dsign::combine_nonce(curve, sid, &r1s, &r2s, &payloads).is_err());
        // Identify: first party whose reveal differs from its payload.
        let culprit = (0..2).find(|&j| {
            parse_sign_payload(&payloads[j]).map(|p| p.3).unwrap_or([0u8; 33])
                != r2s[j].nonce_pt
        });
        assert_eq!(culprit, Some(1));
    }
}

#[test]
fn refresh_tampered_cell_and_constant_rejected() {
    use blockchain_utils::dkls23::refresh::{refresh_apply, sample_deltas, RefreshMsg};
    for curve in [CurveId::K1, CurveId::R1] {
        let sid = b"adv-refresh";
        let shares = dkg_oneshot(curve, sid, 2, 2, &seeds::<2>(0x55)).unwrap();
        let t = 2;
        let mk_msgs = || {
            let mut msgs = Vec::new();
            for (i, seed) in seeds::<2>(0x56).iter().enumerate() {
                let mut rng = session_rng(seed, sid);
                let (deltas, pts, feldman) =
                    sample_deltas(&mut rng, curve, t, 2).unwrap();
                msgs.push(RefreshMsg {
                    party: i,
                    deltas: deltas.iter().map(|d| d.to_array_be()).collect(),
                    delta_pts: pts
                        .iter()
                        .map(|p| p.to_array_compressed().unwrap())
                        .collect(),
                    feldman: feldman
                        .iter()
                        .map(|p| {
                            let mut enc = [0u8; 33];
                            assert!(p.to_bytes_compressed(&mut enc));
                            enc
                        })
                        .collect(),
                });
            }
            msgs
        };
        // Control passes.
        assert!(refresh_apply(&shares, &mk_msgs(), curve).is_ok());
        // Tampered delta cell.
        let mut bad = mk_msgs();
        bad[0].deltas[1][0] ^= 0xFF;
        assert_eq!(
            refresh_apply(&shares, &bad, curve).err(),
            Some(DklsError::BadShare)
        );
        // Nonzero constant term (F[0] = generator, not identity).
        let mut bad0 = mk_msgs();
        bad0[1].feldman[0] =
            DklsPoint::generator(curve).to_array_compressed().unwrap();
        assert_eq!(
            refresh_apply(&shares, &bad0, curve).err(),
            Some(DklsError::BadShare)
        );
    }
}

#[test]
fn single_share_cannot_sign() {
    // Below-threshold: the session layer refuses to run signing with a
    // singleton outright (TooFew) — there is no code path that turns one
    // share into a group signature.
    for curve in [CurveId::K1, CurveId::R1] {
        let sid = b"adv-singleton";
        let shares = dkg_oneshot(curve, sid, 3, 2, &seeds::<3>(0x66)).unwrap();
        let h = sha256(b"singleton attempt").unwrap();
        let one = [shares[0].clone()];
        assert_eq!(
            sign_oneshot(&one, sid, &h, &seeds::<1>(0x67)).err(),
            Some(DklsError::TooFew)
        );
    }
}

// ---------------------------------------------------------------------------
// Larger committees.
// ---------------------------------------------------------------------------

fn triples(n: usize) -> Vec<[usize; 3]> {
    let mut out = Vec::new();
    for i in 0..n {
        for j in (i + 1)..n {
            for k in (j + 1)..n {
                out.push([i, j, k]);
            }
        }
    }
    out
}

#[test]
fn dkg_3of5_every_triple_signs_k1() {
    let curve = CurveId::K1;
    let sid = b"adv-3of5-k1";
    let shares = dkg_oneshot(curve, sid, 5, 3, &seeds::<5>(0x77)).expect("dkg 3-of-5");
    for w in &shares[1..] {
        assert_eq!(w.pk, shares[0].pk);
    }
    let h = sha256(b"3-of-5 k1").unwrap();
    let all_seeds = seeds::<5>(0x78);
    let mut count = 0;
    for triple in triples(5) {
        let subset =
            [shares[triple[0]].clone(), shares[triple[1]].clone(), shares[triple[2]].clone()];
        let sub_seeds = [all_seeds[triple[0]], all_seeds[triple[1]], all_seeds[triple[2]]];
        let sig = sign_oneshot(&subset, sid, &h, &sub_seeds).expect("triple signs");
        expect_valid(curve, &shares[0].pk, &h, &sig.to_bytes());
        count += 1;
    }
    assert_eq!(count, 10, "all C(5,3) triples must sign");
}

#[test]
fn dkg_3of5_spot_triples_sign_r1() {
    let curve = CurveId::R1;
    let sid = b"adv-3of5-r1";
    let shares = dkg_oneshot(curve, sid, 5, 3, &seeds::<5>(0x88)).expect("dkg 3-of-5");
    let h = sha256(b"3-of-5 r1").unwrap();
    let all_seeds = seeds::<5>(0x89);
    // Spot-check 3 of the 10 triples (debug R1 is slow; K1 covers all).
    for triple in [[0usize, 1, 2], [0, 2, 4], [1, 3, 4]] {
        let subset =
            [shares[triple[0]].clone(), shares[triple[1]].clone(), shares[triple[2]].clone()];
        let sub_seeds = [all_seeds[triple[0]], all_seeds[triple[1]], all_seeds[triple[2]]];
        let sig = sign_oneshot(&subset, sid, &h, &sub_seeds).expect("triple signs");
        expect_valid(curve, &shares[0].pk, &h, &sig.to_bytes());
    }
}

#[test]
fn dkg_5of5_signs_and_refreshes_k1() {
    use blockchain_utils::dkls23::session::refresh_oneshot;
    let curve = CurveId::K1;
    let sid = b"adv-5of5-k1";
    let shares = dkg_oneshot(curve, sid, 5, 5, &seeds::<5>(0x99)).expect("dkg 5-of-5");
    let h = sha256(b"5-of-5 k1").unwrap();
    let sig = sign_oneshot(&shares, sid, &h, &seeds::<5>(0x9A)).expect("all sign");
    expect_valid(curve, &shares[0].pk, &h, &sig.to_bytes());
    // Refresh the full committee, then re-sign with all five.
    let fresh = refresh_oneshot(&shares, b"adv-5of5-refresh", &seeds::<5>(0x9B)).expect("refresh");
    assert_eq!(fresh[0].pk, shares[0].pk);
    let h2 = sha256(b"5-of-5 post-refresh").unwrap();
    let sig2 = sign_oneshot(&fresh, sid, &h2, &seeds::<5>(0x9C)).expect("sign");
    expect_valid(curve, &shares[0].pk, &h2, &sig2.to_bytes());
}
