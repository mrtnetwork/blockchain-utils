//! DKLs23 known-answer tests: DKG → sign → standard-verify.
//!
//! Byte-identity contract: threshold signatures are standard ECDSA
//! `(r || s)` (64 bytes, low-S) and verify under the crate's existing
//! `signature::{ecdsa, ecdsa_p256}` verifiers — the same verifiers that
//! pass the RFC 6979 / BIP-340 / OpenSSL vectors. Oracle tags and the
//! tagged-hash encoding match the interoperable deployments so
//! transcripts cross-check byte-for-byte; all logic is this crate's own.

use blockchain_utils::dkls23::codec::CompactSig;
use blockchain_utils::dkls23::curve_id::CurveId;
use blockchain_utils::dkls23::session::{dkg_oneshot, refresh_oneshot, sign_oneshot};
use blockchain_utils::hash::sha256::sha256;

fn seeds<const N: usize>(base: u8) -> [[u8; 32]; N] {
    let mut out = [[0u8; 32]; N];
    for (i, s) in out.iter_mut().enumerate() {
        for b in s.iter_mut() {
            *b = base.wrapping_add(i as u8);
        }
    }
    out
}

fn e2e(curve: CurveId, dkg_base: u8, sign_base: u8, sid: &[u8], msg: &[u8]) {
    let dkg_seeds = seeds::<3>(dkg_base);
    let shares = dkg_oneshot(curve, sid, 2, 2, &dkg_seeds[..2]).expect("dkg 2-of-2");
    assert_eq!(shares.len(), 2);
    assert_eq!(shares[0].pk, shares[1].pk);
    // Public shares are distinct points; secret shares are distinct.
    assert_ne!(shares[0].x, shares[1].x);

    let h = sha256(msg).unwrap();
    let sign_seeds = seeds::<3>(sign_base);
    let sig: CompactSig =
        sign_oneshot(&shares, sid, &h, &sign_seeds[..2]).expect("sign 2-of-2");
    let compact = sig.to_bytes();
    assert_eq!(CompactSig::from_bytes(&compact).unwrap(), sig);

    match curve {
        CurveId::K1 => {
            let pk = blockchain_utils::signature::ecdsa::PublicKey::from_bytes(&shares[0].pk)
                .expect("group pk decodes");
            let s = blockchain_utils::signature::ecdsa::Signature::from_compact(&compact)
                .expect("compact parses");
            blockchain_utils::signature::ecdsa::verify(&pk, &h, &s).expect("k1 verifies");
            // Wrong message must fail.
            let bad = sha256(b"something else").unwrap();
            assert!(blockchain_utils::signature::ecdsa::verify(&pk, &bad, &s).is_err());
        }
        CurveId::R1 => {
            let pk =
                blockchain_utils::signature::ecdsa_p256::PublicKey::from_bytes(&shares[0].pk)
                    .expect("group pk decodes");
            let s = blockchain_utils::signature::ecdsa_p256::Signature::from_compact(&compact)
                .expect("compact parses");
            blockchain_utils::signature::ecdsa_p256::verify(&pk, &h, &s).expect("r1 verifies");
            let bad = sha256(b"something else").unwrap();
            assert!(blockchain_utils::signature::ecdsa_p256::verify(&pk, &bad, &s).is_err());
        }
    }
}

#[test]
fn dkls23_k1_2of2_sign_verifies() {
    e2e(CurveId::K1, 0x10, 0x40, b"dkls23-kat-k1-2of2", b"threshold ecdsa k1");
}

#[test]
fn dkls23_r1_2of2_sign_verifies() {
    e2e(CurveId::R1, 0x20, 0x50, b"dkls23-kat-r1-2of2", b"threshold ecdsa r1");
}

/// Verify a threshold signature against the group key for `curve`.
fn expect_valid(
    curve: CurveId,
    pk: &[u8; 33],
    msg_hash: &[u8; 32],
    sig: &CompactSig,
) {
    let compact = sig.to_bytes();
    match curve {
        CurveId::K1 => {
            let p = blockchain_utils::signature::ecdsa::PublicKey::from_bytes(pk)
                .expect("group pk decodes");
            let s = blockchain_utils::signature::ecdsa::Signature::from_compact(&compact)
                .expect("compact parses");
            blockchain_utils::signature::ecdsa::verify(&p, msg_hash, &s).expect("k1 verifies");
        }
        CurveId::R1 => {
            let p = blockchain_utils::signature::ecdsa_p256::PublicKey::from_bytes(pk)
                .expect("group pk decodes");
            let s = blockchain_utils::signature::ecdsa_p256::Signature::from_compact(&compact)
                .expect("compact parses");
            blockchain_utils::signature::ecdsa_p256::verify(&p, msg_hash, &s)
                .expect("r1 verifies");
        }
    }
}

#[test]
fn dkls23_k1_2of3_every_pair_signs() {
    // 2-of-3 DKG; every 2-party subset must produce a valid signature
    // under the same group key (Lagrange rescale per subset).
    let curve = CurveId::K1;
    let sid = b"dkls23-kat-k1-2of3";
    let shares = dkg_oneshot(curve, sid, 3, 2, &seeds::<3>(0x30)).expect("dkg");
    assert_eq!(shares[0].pk, shares[1].pk);
    assert_eq!(shares[1].pk, shares[2].pk);
    let h = sha256(b"subset signing k1").unwrap();
    for pair in [[0usize, 1usize], [0, 2], [1, 2]] {
        let subset =
            [shares[pair[0]].clone(), shares[pair[1]].clone()];
        // Seeds travel with the party index, not the subset position.
        let sub_seeds = [[0x40 + pair[0] as u8; 32], [0x40 + pair[1] as u8; 32]];
        let sig = sign_oneshot(&subset, sid, &h, &sub_seeds).expect("subset signs");
        expect_valid(curve, &shares[0].pk, &h, &sig);
    }
}

#[test]
fn dkls23_r1_2of3_every_pair_signs() {
    let curve = CurveId::R1;
    let sid = b"dkls23-kat-r1-2of3";
    let shares = dkg_oneshot(curve, sid, 3, 2, &seeds::<3>(0x31)).expect("dkg");
    assert_eq!(shares[0].pk, shares[1].pk);
    assert_eq!(shares[1].pk, shares[2].pk);
    let h = sha256(b"subset signing r1").unwrap();
    for pair in [[0usize, 1usize], [0, 2], [1, 2]] {
        let subset =
            [shares[pair[0]].clone(), shares[pair[1]].clone()];
        let sub_seeds = [[0x50 + pair[0] as u8; 32], [0x50 + pair[1] as u8; 32]];
        let sig = sign_oneshot(&subset, sid, &h, &sub_seeds).expect("subset signs");
        expect_valid(curve, &shares[0].pk, &h, &sig);
    }
}

#[test]
fn dkls23_k1_refresh_keeps_key_signs() {
    // DKG → refresh → sign: group key unchanged, new shares verify.
    let curve = CurveId::K1;
    let sid = b"dkls23-kat-k1-refresh";
    let shares = dkg_oneshot(curve, sid, 2, 2, &seeds::<3>(0x60)[..2]).expect("dkg");
    let fresh =
        refresh_oneshot(&shares, b"refresh-1", &seeds::<3>(0x61)[..2]).expect("refresh");
    assert_eq!(fresh.len(), 2);
    assert_eq!(fresh[0].pk, shares[0].pk);
    // Shares actually rotated.
    assert_ne!(fresh[0].x, shares[0].x);
    let h = sha256(b"post-refresh k1").unwrap();
    let sig = sign_oneshot(&fresh, sid, &h, &seeds::<3>(0x62)[..2]).expect("sign");
    expect_valid(curve, &shares[0].pk, &h, &sig);
    // Refresh is deterministic under (seeds, sid).
    let fresh2 =
        refresh_oneshot(&shares, b"refresh-1", &seeds::<3>(0x61)[..2]).expect("refresh");
    assert_eq!(fresh[0].x, fresh2[0].x);
}

#[test]
fn dkls23_r1_refresh_keeps_key_signs() {
    let curve = CurveId::R1;
    let sid = b"dkls23-kat-r1-refresh";
    let shares = dkg_oneshot(curve, sid, 2, 2, &seeds::<3>(0x70)[..2]).expect("dkg");
    let fresh =
        refresh_oneshot(&shares, b"refresh-1", &seeds::<3>(0x71)[..2]).expect("refresh");
    assert_eq!(fresh[0].pk, shares[0].pk);
    assert_ne!(fresh[0].x, shares[0].x);
    let h = sha256(b"post-refresh r1").unwrap();
    let sig = sign_oneshot(&fresh, sid, &h, &seeds::<3>(0x72)[..2]).expect("sign");
    expect_valid(curve, &shares[0].pk, &h, &sig);
}

#[test]
fn dkls23_dkg_is_deterministic() {
    let a = dkg_oneshot(CurveId::K1, b"det-sid", 2, 2, &seeds::<3>(0x77)[..2]).unwrap();
    let b = dkg_oneshot(CurveId::K1, b"det-sid", 2, 2, &seeds::<3>(0x77)[..2]).unwrap();
    assert_eq!(a[0].x, b[0].x);
    assert_eq!(a[0].pk, b[0].pk);
    let c = dkg_oneshot(CurveId::K1, b"other-sid", 2, 2, &seeds::<3>(0x77)[..2]).unwrap();
    assert_ne!(a[0].pk, c[0].pk);
}

#[test]
fn dkls23_tampered_commitment_aborts() {    use blockchain_utils::dkls23::commit::{commit, verify};
    let mut rng = blockchain_utils::rng::ChaCha20Rng::from_seed(&[1u8; 32]);
    let (com, open) = commit(&mut rng, b"payload");
    verify(&com, open.msg(), open.salt()).unwrap();
    assert!(verify(&com, b"tampered", open.salt()).is_err());
}

#[test]
fn dkls23_import_secrets_signs_both_curves() {
    use blockchain_utils::dkls23::session::import_secrets;
    for curve in [CurveId::K1, CurveId::R1] {
        // Two pre-existing secrets (e.g. established wallet keys).
        let mut s0 = [0u8; 32];
        let mut s1 = [0u8; 32];
        s0[31] = 0x11;
        s1[31] = 0x22;
        let shares = import_secrets(curve, &[s0, s1]).expect("import");
        assert_eq!(shares.len(), 2);
        assert_eq!(shares[0].t, Some(2));
        // Group key is the member-point sum (additive quorum).
        {
            use blockchain_utils::dkls23::curve_id::DklsPoint;
            let mut sum = DklsPoint::identity(curve);
            for sh in &shares[0].shares {
                sum = sum.add(&DklsPoint::from_bytes(curve, sh).unwrap());
            }
            let mut enc = [0u8; 33];
            assert!(sum.to_bytes_compressed(&mut enc));
            assert_eq!(&enc, &shares[0].pk);
        }
        let sid = b"dkls23-kat-import";
        let h = sha256(b"imported quorum message").unwrap();
        let sig = sign_oneshot(&shares, sid, &h, &seeds::<3>(0x90)[..2]).expect("sign");
        expect_valid(curve, &shares[0].pk, &h, &sig);
    }
}
