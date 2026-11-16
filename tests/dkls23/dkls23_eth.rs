//! DKLs23 → Ethereum flow: threshold-sign a transaction hash and build
//! the exact artifacts an Ethereum client expects.
//!
//! Ethereum signing = secp256k1 ECDSA over `keccak256(tx)` with:
//! - low-S `s` (Homestead EIP-2 rule),
//! - recovery id `v` (EIP-155: `v = rec_id + 35 + chain_id * 2`),
//! - sender address = last 20 bytes of `keccak256(uncompressed_pk[1..])`.
//!
//! This test proves our threshold signatures plug into that flow
//! byte-for-byte: recovery from `(hash, r, s, rec_id)` returns the DKG
//! group key, and the derived address matches the group key's address.

use blockchain_utils::curve::traits::CurvePoint;
use blockchain_utils::curve::Secp256k1Point;
use blockchain_utils::dkls23::curve_id::CurveId;
use blockchain_utils::dkls23::session::{dkg_oneshot, sign_oneshot};
use blockchain_utils::hash::keccak::keccak256;
use blockchain_utils::signature::ecdsa;

/// secp256k1 group order (for the low-S check).
const K1_N: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

/// Ethereum address of a 33-byte compressed group key.
fn eth_address(group_pk33: &[u8; 33]) -> [u8; 20] {
    let pt = Secp256k1Point::from_bytes(group_pk33).expect("group pk decodes");
    let mut uncomp = [0u8; 65];
    pt.to_bytes_uncompressed(&mut uncomp).expect("uncompressed");
    let digest = keccak256(&uncomp[1..]).expect("keccak");
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&digest[12..32]);
    addr
}

fn is_low_s(s: &[u8; 32]) -> bool {
    // s <= n/2: compute n/2 once (big-endian shift right).
    let mut half = K1_N;
    let mut carry = 0u8;
    for i in (0..32).rev() {
        let v = half[i];
        half[i] = (v >> 1) | (carry << 7);
        carry = v & 1;
    }
    // Lexicographic compare s <= half.
    for i in 0..32 {
        if s[i] < half[i] {
            return true;
        }
        if s[i] > half[i] {
            return false;
        }
    }
    true
}

#[test]
fn dkls23_threshold_ethereum_tx_flow() {
    // Fake legacy transaction bytes (RLP payload stands in for any
    // caller-supplied unsigned-tx encoding).
    let unsigned_tx = b"\xf8\x6a\x80\x85\x04\xa8\x17\xc0\x00\x82\x52\x08\x94\
        \x35\x33\x5e\x75\x36\xe7\xc7\xfd\xa5\xf6\x7b\x48\x3c\x9b\x37\x19\x96\x0d\
        \x87\x23\x86\xf8\xf2\x3f\xd8\xc0\x80\x80\x80";
    let tx_hash = keccak256(unsigned_tx).unwrap();

    // 2-of-2 DKG, then threshold-sign the transaction hash.
    let dkg_seeds = [[0x11u8; 32], [0x22u8; 32]];
    let sid = b"dkls23-eth-flow";
    let shares = dkg_oneshot(CurveId::K1, sid, 2, 2, &dkg_seeds).expect("dkg");
    let sign_seeds = [[0x33u8; 32], [0x44u8; 32]];
    let tsig = sign_oneshot(&shares, sid, &tx_hash, &sign_seeds).expect("sign");
    let compact = tsig.to_bytes();

    // 1. Standard verification under the group key.
    let group_pk = ecdsa::PublicKey::from_bytes(&shares[0].pk).unwrap();
    let sig = ecdsa::Signature::from_compact(&compact).unwrap();
    ecdsa::verify(&group_pk, &tx_hash, &sig).expect("threshold sig verifies");

    // 2. Low-S (Homestead relay rule).
    assert!(is_low_s(&tsig.s), "s must be low-S for Ethereum");

    // 3. Recovery id + recovery round-trip to the group key.
    let rec_id = ecdsa::recovery_id_for(&tx_hash, &sig, &group_pk).expect("recovery id");
    assert!(rec_id <= 1, "no overflow bit expected, got {rec_id}");
    let recovered = ecdsa::recover(&tx_hash, &sig, rec_id).expect("recover");
    let mut a = [0u8; 33];
    let mut b = [0u8; 33];
    group_pk.to_bytes_compressed(&mut a).unwrap();
    recovered.to_bytes_compressed(&mut b).unwrap();
    assert_eq!(a, b, "recovered key == DKG group key");

    // 4. EIP-155 `v` values for mainnet (chain 1) and a testnet (chain 5).
    let v_mainnet = rec_id as u64 + 35 + 2;
    let v_goerli = rec_id as u64 + 35 + 5 * 2;
    assert!(v_mainnet == 37 || v_mainnet == 38);
    assert!(v_goerli == 45 || v_goerli == 46);

    // 5. Sender address from the recovered key matches the group key's.
    assert_eq!(eth_address(&a), eth_address(&b));

    // 6. Full 65-byte Ethereum signature layout `r || s || v`.
    let mut eth65 = [0u8; 65];
    eth65[..64].copy_from_slice(&compact);
    eth65[64] = rec_id;
    assert_eq!(&eth65[..32], &tsig.r);
    assert_eq!(&eth65[32..64], &tsig.s);
}
