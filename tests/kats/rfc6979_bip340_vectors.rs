//! Official / published test vectors for item 10 of the secp256k1 go-live checklist.
//!
//! - BIP-340: verification vectors from bitcoin/bips (test-vectors.csv)
//! - ECDSA secp256k1: well-known RFC 6979-style vectors (Bitcoin SE + community)
//!   exercised via `sign_with_nonce` with published k, and verify.
//!
//! Run: `cargo test --test kats rfc6979_bip340_vectors -- --nocapture`

#![cfg(feature = "alloc")]

use blockchain_utils::curve::secp256k1::Scalar;
use blockchain_utils::encoding::hex::decode;
use blockchain_utils::hash::sha256;
use blockchain_utils::signature::ecdsa::{
    sign_with_nonce, verify as ecdsa_verify, SecretKey as EcdsaSk,
};
use blockchain_utils::signature::schnorr::{
    verify as schnorr_verify, PublicKey as SchnorrPk, Signature as SchnorrSig,
};

fn unhex(s: &str) -> Vec<u8> {
    // Preserve prior leniency: ignore non-hex characters (e.g. separators),
    // then decode strictly via the crate implementation.
    let s: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    decode(&s).expect("hex")
}

fn unhex32(s: &str) -> [u8; 32] {
    let v = unhex(s);
    assert_eq!(v.len(), 32);
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    a
}

fn unhex64(s: &str) -> [u8; 64] {
    let v = unhex(s);
    assert_eq!(v.len(), 64);
    let mut a = [0u8; 64];
    a.copy_from_slice(&v);
    a
}

// ---------------------------------------------------------------------------
// BIP-340 verification vectors (official bitcoin/bips)
// ---------------------------------------------------------------------------

struct Bip340Vec {
    index: u32,
    pubkey: &'static str,
    message: &'static str,
    signature: &'static str,
    expect_ok: bool,
    comment: &'static str,
}

/// Subset of BIP-340 vectors: valid sigs must verify; invalid must fail.
const BIP340: &[Bip340Vec] = &[
    Bip340Vec {
        index: 0,
        pubkey: "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
        message: "0000000000000000000000000000000000000000000000000000000000000000",
        signature: "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
        expect_ok: true,
        comment: "vector 0",
    },
    Bip340Vec {
        index: 1,
        pubkey: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        signature: "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A",
        expect_ok: true,
        comment: "vector 1",
    },
    Bip340Vec {
        index: 2,
        pubkey: "DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
        message: "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C",
        signature: "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7",
        expect_ok: true,
        comment: "vector 2",
    },
    Bip340Vec {
        index: 3,
        pubkey: "25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517",
        message: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        signature: "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3",
        expect_ok: true,
        comment: "vector 3",
    },
    // Invalid public key (not on curve)
    Bip340Vec {
        index: 5,
        pubkey: "EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34",
        message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        signature: "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
        expect_ok: false,
        comment: "public key not on the curve",
    },
    // s = n (invalid)
    Bip340Vec {
        index: 13,
        pubkey: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        signature: "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        expect_ok: false,
        comment: "sig[32:64] equal to curve order",
    },
];

#[test]
fn bip340_official_verify_vectors() {
    for v in BIP340 {
        let pk_bytes = unhex32(v.pubkey);
        let msg = unhex(v.message);
        let sig_bytes = unhex64(v.signature);
        let mut rx = [0u8; 32];
        let mut s = [0u8; 32];
        rx.copy_from_slice(&sig_bytes[0..32]);
        s.copy_from_slice(&sig_bytes[32..64]);
        let pk = SchnorrPk(pk_bytes);
        let sig = SchnorrSig { rx, s };
        let result = schnorr_verify(&pk, &msg, &sig);
        if v.expect_ok {
            assert!(
                result.is_ok(),
                "BIP-340 #{} ({}) expected OK, got {:?}",
                v.index,
                v.comment,
                result
            );
            eprintln!("BIP-340 #{} OK ({})", v.index, v.comment);
        } else {
            assert!(
                result.is_err(),
                "BIP-340 #{} ({}) expected FAIL, got Ok",
                v.index,
                v.comment
            );
            eprintln!("BIP-340 #{} correctly rejected ({})", v.index, v.comment);
        }
    }
}

// ---------------------------------------------------------------------------
// ECDSA secp256k1 — published RFC 6979-style vectors
// Source: Bitcoin Stack Exchange / community (priv=1, msg="Satoshi Nakamoto")
// ---------------------------------------------------------------------------

#[test]
fn ecdsa_rfc6979_style_satoshi_vector() {
    // private key = 1
    let mut d = [0u8; 32];
    d[31] = 1;
    let sk = EcdsaSk::from_bytes(&d).unwrap();
    let pk = sk.public_key().unwrap();

    let msg = b"Satoshi Nakamoto";
    let hash = sha256(msg).unwrap();

    // Published k for RFC6979(secp256k1, SHA256) with d=1, msg="Satoshi Nakamoto"
    let k = Scalar::from_bytes_be(&unhex32(
        "8F8A276C19F4149656B280621E358CCE24F5F52542772691EE69063B74F15D15",
    ))
    .unwrap();

    let sig = sign_with_nonce(&sk, &hash, &k).unwrap();

    // Expected compact (r||s) from published vector (low-S form)
    let expected_r = unhex32("934B1EA10A4B3C1757E2B0C017D0B6143CE3C9A7E6A4A49860D7A6AB210EE3D8");
    let expected_s = unhex32("2442CE9D2B916064108014783E923EC36B49743E2FFA1C4496F01A512AAFD9E5");

    assert_eq!(sig.r, expected_r, "r mismatch");
    assert_eq!(sig.s, expected_s, "s mismatch");

    ecdsa_verify(&pk, &hash, &sig).expect("verify published Satoshi vector");
    eprintln!("ECDSA RFC6979-style Satoshi vector: OK");
}

#[test]
fn ecdsa_rfc6979_style_tears_in_rain() {
    let mut d = [0u8; 32];
    d[31] = 1;
    let sk = EcdsaSk::from_bytes(&d).unwrap();
    let pk = sk.public_key().unwrap();
    let msg = b"All those moments will be lost in time, like tears in rain. Time to die...";
    let hash = sha256(msg).unwrap();
    let k = Scalar::from_bytes_be(&unhex32(
        "38AA22D72376B4DBC472E06C3BA403EE0A394DA63FC58D88686C611ABA98D6B3",
    ))
    .unwrap();
    let sig = sign_with_nonce(&sk, &hash, &k).unwrap();
    let expected_r = unhex32("8600DBD41E348FE5C9465AB92D23E3DB8B98B873BEECD930736488696438CB6B");
    let expected_s = unhex32("547FE64427496DB33BF66019DACBF0039C04199ABB0122918601DB38A72CFC21");
    assert_eq!(sig.r, expected_r);
    assert_eq!(sig.s, expected_s);
    ecdsa_verify(&pk, &hash, &sig).expect("verify tears vector");
    eprintln!("ECDSA RFC6979-style tears-in-rain vector: OK");
}

#[test]
fn ecdsa_deterministic_sign_verify_stable() {
    // Our deterministic_k is RFC6979-lite; assert stability + verify roundtrip.
    let mut d = [0u8; 32];
    d[31] = 0x42;
    let sk = EcdsaSk::from_bytes(&d).unwrap();
    let pk = sk.public_key().unwrap();
    let hash = sha256(b"deterministic stability check").unwrap();
    let sig1 = blockchain_utils::signature::ecdsa::sign(&sk, &hash).unwrap();
    let sig2 = blockchain_utils::signature::ecdsa::sign(&sk, &hash).unwrap();
    assert_eq!(sig1.r, sig2.r);
    assert_eq!(sig1.s, sig2.s);
    ecdsa_verify(&pk, &hash, &sig1).unwrap();
    eprintln!("ECDSA deterministic stable roundtrip: OK");
}
