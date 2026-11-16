//! MuSig2 (BIP-327) integration tests.
//! Run: `cargo test --features alloc --test kats musig2_kat`

#![cfg(feature = "alloc")]

use blockchain_utils::curve::secp256k1::{Scalar, Secp256k1Point};
use blockchain_utils::curve::traits::CurvePoint;
use blockchain_utils::hash::sha256::sha256;
use blockchain_utils::musig2::{
    key_agg, nonce_agg, nonce_generate, partial_sig_agg, partial_sign, session_values, Session,
};
use blockchain_utils::signature::schnorr::{
    verify as bip340_verify, PublicKey as SchnorrPk, Signature as SchnorrSig,
};

fn sk_pk(seed: &[u8]) -> ([u8; 32], [u8; 33]) {
    let h = sha256(seed).unwrap();
    let d = Scalar::from_bytes(&h)
        .or_else(|_| Scalar::from_bytes_be(&h))
        .expect("scalar");
    let p = Secp256k1Point::generator().mul(&d);
    let mut pk = [0u8; 33];
    p.to_bytes_compressed(&mut pk).unwrap();
    let mut sk = [0u8; 32];
    d.to_bytes_be(&mut sk);
    (sk, pk)
}

#[test]
fn musig2_two_party_sign_aggregate_bip340_verify() {
    let (sk1, pk1) = sk_pk(b"musig2-party-1");
    let (sk2, pk2) = sk_pk(b"musig2-party-2");
    let keys = [pk1.as_slice(), pk2.as_slice()];
    let ctx = key_agg(&keys).expect("key_agg");
    let xonly = ctx.x_only().expect("xonly");

    let msg = b"musig2 bip327 two party";

    let n1 = nonce_generate(
        Some(&sk1),
        Some(&pk1),
        Some(&xonly),
        None,
        Some(msg),
        &[11u8; 32],
    )
    .expect("n1");
    let n2 = nonce_generate(
        Some(&sk2),
        Some(&pk2),
        Some(&xonly),
        None,
        Some(msg),
        &[22u8; 32],
    )
    .expect("n2");

    let aggnonce = nonce_agg(&[n1.pubnonce.as_slice(), n2.pubnonce.as_slice()]).expect("agg");

    let session = Session {
        public_keys: vec![pk1.to_vec(), pk2.to_vec()],
        tweaks: vec![],
        aggnonce: aggnonce.clone(),
        msg: msg.to_vec(),
    };

    let _vals = session_values(&session).expect("session");

    let s1 = partial_sign(&n1.secnonce, &sk1, &session).expect("s1");
    let s2 = partial_sign(&n2.secnonce, &sk2, &session).expect("s2");

    let sig64 = partial_sig_agg(&[s1, s2], &session).expect("agg sig");
    let mut rx = [0u8; 32];
    let mut ss = [0u8; 32];
    rx.copy_from_slice(&sig64[0..32]);
    ss.copy_from_slice(&sig64[32..64]);
    let sig = SchnorrSig { rx, s: ss };
    let pk = SchnorrPk(xonly);
    bip340_verify(&pk, msg, &sig).expect("BIP-340 verify of MuSig2 aggregate");
}

#[test]
fn musig2_key_agg_rejects_single_key() {
    let (_, pk1) = sk_pk(b"only-one");
    assert!(key_agg(&[pk1.as_slice()]).is_err());
}

#[test]
fn key_agg_list_tag_stable() {
    // Domain separation smoke: same keys always same Q (order-sensitive as BIP-327 without sort)
    let (sk1, pk1) = sk_pk(b"kat-a");
    let (sk2, pk2) = sk_pk(b"kat-b");
    let _ = (sk1, sk2);
    let a = key_agg(&[pk1.as_slice(), pk2.as_slice()]).unwrap();
    let b = key_agg(&[pk1.as_slice(), pk2.as_slice()]).unwrap();
    let mut ea = [0u8; 33];
    let mut eb = [0u8; 33];
    a.q.to_bytes_compressed(&mut ea).unwrap();
    b.q.to_bytes_compressed(&mut eb).unwrap();
    assert_eq!(ea, eb);
    // swapped order may differ (we do not sort by default)
    let c = key_agg(&[pk2.as_slice(), pk1.as_slice()]).unwrap();
    let mut ec = [0u8; 33];
    c.q.to_bytes_compressed(&mut ec).unwrap();
    // just ensure valid encoding
    assert!(ec[0] == 2 || ec[0] == 3);
}

#[test]
fn deterministic_sign_two_party_bip340() {
    use blockchain_utils::curve::secp256k1::{Scalar, Secp256k1Point};
    use blockchain_utils::curve::traits::CurvePoint;
    use blockchain_utils::hash::sha256::sha256;
    use blockchain_utils::musig2::{
        deterministic_sign, key_agg, nonce_agg, nonce_generate, partial_sig_agg, partial_sign,
        Session,
    };
    use blockchain_utils::signature::schnorr::{
        verify as bip340_verify, PublicKey as SchnorrPk, Signature as SchnorrSig,
    };

    fn sk_pk(seed: &[u8]) -> ([u8; 32], [u8; 33]) {
        let h = sha256(seed).unwrap();
        let d = Scalar::from_bytes_mod_order(&h);
        let p = Secp256k1Point::generator().mul(&d);
        let mut pk = [0u8; 33];
        p.to_bytes_compressed(&mut pk).unwrap();
        let mut sk = [0u8; 32];
        d.to_bytes_be(&mut sk);
        (sk, pk)
    }

    let (sk1, pk1) = sk_pk(b"det-party-1");
    let (sk2, pk2) = sk_pk(b"det-party-2");
    let keys = [pk1.as_slice(), pk2.as_slice()];
    let ctx = key_agg(&keys).unwrap();
    let xonly = ctx.x_only().unwrap();
    let msg = b"deterministic musig2";

    // Party1: normal nonce gen with fixed rand
    let n1 = nonce_generate(
        Some(&sk1),
        Some(&pk1),
        Some(&xonly),
        None,
        Some(msg),
        &[0xAAu8; 32],
    )
    .unwrap();

    // Party2: deterministic_sign using party1 pubnonce as aggother (single other)
    let det = deterministic_sign(
        &sk2,
        &n1.pubnonce,
        &[pk1.to_vec(), pk2.to_vec()],
        &[],
        msg,
        None, // fully deterministic
    )
    .expect("deterministic_sign");

    // Same det again → identical
    let det2 = deterministic_sign(
        &sk2,
        &n1.pubnonce,
        &[pk1.to_vec(), pk2.to_vec()],
        &[],
        msg,
        None,
    )
    .unwrap();
    assert_eq!(det.pubnonce, det2.pubnonce);
    assert_eq!(det.partial, det2.partial);

    let aggnonce = nonce_agg(&[n1.pubnonce.as_slice(), det.pubnonce.as_slice()]).unwrap();
    let session = Session {
        public_keys: vec![pk1.to_vec(), pk2.to_vec()],
        tweaks: vec![],
        aggnonce: aggnonce.clone(),
        msg: msg.to_vec(),
    };
    let s1 = partial_sign(&n1.secnonce, &sk1, &session).unwrap();
    let s2 = det.partial;
    let sig64 = partial_sig_agg(&[s1, s2], &session).unwrap();
    let mut rx = [0u8; 32];
    let mut ss = [0u8; 32];
    rx.copy_from_slice(&sig64[0..32]);
    ss.copy_from_slice(&sig64[32..64]);
    bip340_verify(&SchnorrPk(xonly), msg, &SchnorrSig { rx, s: ss }).expect("bip340");
}

#[test]
fn partial_sig_verify_and_verify_aggregate() {
    use blockchain_utils::curve::secp256k1::{Scalar, Secp256k1Point};
    use blockchain_utils::curve::traits::CurvePoint;
    use blockchain_utils::hash::sha256::sha256;
    use blockchain_utils::musig2::{
        key_agg, nonce_agg, nonce_generate, partial_sig_agg, partial_sig_verify, partial_sign,
        verify_aggregate, Session,
    };

    fn sk_pk(seed: &[u8]) -> ([u8; 32], [u8; 33]) {
        let h = sha256(seed).unwrap();
        let d = Scalar::from_bytes_mod_order(&h);
        let p = Secp256k1Point::generator().mul(&d);
        let mut pk = [0u8; 33];
        p.to_bytes_compressed(&mut pk).unwrap();
        let mut sk = [0u8; 32];
        d.to_bytes_be(&mut sk);
        (sk, pk)
    }

    // Several seeds to exercise odd-Y R / Q paths
    for label in [b"pv-a".as_slice(), b"pv-b", b"pv-c", b"pv-d", b"pv-e"] {
        let (sk1, pk1) = sk_pk(label);
        let (sk2, pk2) = sk_pk(&[label, b"-2"].concat());
        let keys = [pk1.as_slice(), pk2.as_slice()];
        let ctx = key_agg(&keys).unwrap();
        let xonly = ctx.x_only().unwrap();
        let msg = label;

        let n1 = nonce_generate(
            Some(&sk1),
            Some(&pk1),
            Some(&xonly),
            None,
            Some(msg),
            &[1u8; 32],
        )
        .unwrap();
        let n2 = nonce_generate(
            Some(&sk2),
            Some(&pk2),
            Some(&xonly),
            None,
            Some(msg),
            &[2u8; 32],
        )
        .unwrap();
        let aggnonce = nonce_agg(&[n1.pubnonce.as_slice(), n2.pubnonce.as_slice()]).unwrap();
        let session = Session {
            public_keys: vec![pk1.to_vec(), pk2.to_vec()],
            tweaks: vec![],
            aggnonce,
            msg: msg.to_vec(),
        };
        let s1 = partial_sign(&n1.secnonce, &sk1, &session).unwrap();
        let s2 = partial_sign(&n2.secnonce, &sk2, &session).unwrap();

        let mut pn1 = [0u8; 66];
        pn1.copy_from_slice(&n1.pubnonce);
        let mut pn2 = [0u8; 66];
        pn2.copy_from_slice(&n2.pubnonce);
        assert!(
            partial_sig_verify(&s1, &pn1, &pk1, &session).unwrap(),
            "partial verify p1 {:?}",
            std::str::from_utf8(label)
        );
        assert!(
            partial_sig_verify(&s2, &pn2, &pk2, &session).unwrap(),
            "partial verify p2 {:?}",
            std::str::from_utf8(label)
        );

        let sig = partial_sig_agg(&[s1, s2], &session).unwrap();
        assert!(
            verify_aggregate(msg, &sig, &xonly).unwrap(),
            "verify_aggregate {:?}",
            std::str::from_utf8(label)
        );
        // negative: bad message
        assert!(!verify_aggregate(b"nope", &sig, &xonly).unwrap());
    }
}
