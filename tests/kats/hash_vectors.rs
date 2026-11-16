//! Real-world test vectors for the hash module.
//!
//! These tests exercise one-shot APIs against published vectors from RFCs,
//! FIPS, Ethereum, and the xxHash reference.

#![cfg(feature = "alloc")]

use blockchain_utils::hash::*;

#[test]
fn sha256_nist_long() {
    // "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    let d = sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq").unwrap();
    assert_eq!(
        d,
        [
            0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e,
            0x60, 0x39, 0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4,
            0x19, 0xdb, 0x06, 0xc1
        ]
    );
}

#[test]
fn sha256d_bitcoin_genesis_style() {
    // Double-SHA256 of empty is a known constant
    let d = sha256d(b"").unwrap();
    assert_eq!(d[0], 0x5d);
    assert_eq!(d[31], 0x56);
}

#[test]
fn hash160_pubkey_style() {
    // HASH160 = RIPEMD160(SHA256(x))
    let d = hash160(b"hello").unwrap();
    assert_eq!(d.len(), 20);
    // Deterministic
    assert_eq!(d, hash160(b"hello").unwrap());
}

#[test]
fn keccak256_ethereum_empty() {
    let d = keccak256(b"").unwrap();
    assert_eq!(&d[..4], &[0xc5, 0xd2, 0x46, 0x01]);
}

#[test]
fn keccak256_ethereum_abc() {
    let d = keccak256(b"abc").unwrap();
    assert_eq!(
        d,
        [
            0x4e, 0x03, 0x65, 0x7a, 0xea, 0x45, 0xa9, 0x4f, 0xc7, 0xd4, 0x7b, 0xa8, 0x26, 0xc8,
            0xd6, 0x67, 0xc0, 0xd1, 0xe6, 0xe3, 0x3a, 0x64, 0xa0, 0x36, 0xec, 0x44, 0xf5, 0x8f,
            0xa1, 0x2d, 0x6c, 0x45
        ]
    );
}

#[test]
fn sha3_all_sizes_deterministic() {
    assert_eq!(sha3_224(b"x").unwrap(), sha3_224(b"x").unwrap());
    assert_eq!(sha3_256(b"x").unwrap(), sha3_256(b"x").unwrap());
    assert_eq!(sha3_384(b"x").unwrap(), sha3_384(b"x").unwrap());
    assert_eq!(sha3_512(b"x").unwrap(), sha3_512(b"x").unwrap());
}

#[test]
fn keccak_all_sizes() {
    assert_eq!(keccak224(b"a").unwrap().len(), 28);
    assert_eq!(keccak384(b"a").unwrap().len(), 48);
    assert_eq!(keccak512(b"a").unwrap().len(), 64);
}

#[test]
fn shake_variable_output() {
    let mut a = [0u8; 32];
    let mut b = [0u8; 64];
    shake128(b"test", &mut a).unwrap();
    shake128(b"test", &mut b).unwrap();
    // Prefix of longer output matches shorter
    assert_eq!(a, b[..32]);
}

#[test]
fn hmac_sha256_rfc4231() {
    let key = [0x0bu8; 20];
    let tag = hmac_sha256(&key, b"Hi There").unwrap();
    assert_eq!(
        tag,
        [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
            0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
            0x2e, 0x32, 0xcf, 0xf7
        ]
    );
}

#[test]
fn pbkdf2_rfc6070() {
    let mut dk = [0u8; 32];
    pbkdf2_hmac_sha256(b"password", b"salt", 4096, &mut dk).unwrap();
    assert_eq!(
        dk,
        [
            0xc5, 0xe4, 0x78, 0xd5, 0x92, 0x88, 0xc8, 0x41, 0xaa, 0x53, 0x0d, 0xb6, 0x84, 0x5c,
            0x4c, 0x8d, 0x96, 0x28, 0x93, 0xa0, 0x01, 0xce, 0x4e, 0x11, 0xa4, 0x96, 0x38, 0x73,
            0xaa, 0x98, 0x13, 0x4a
        ]
    );
}

#[test]
fn blake2b_and_blake2s() {
    assert_eq!(blake2b_256(b"abc").unwrap()[0], 0xbd);
    assert_eq!(blake2s_256(b"abc").unwrap()[0], 0x50);
}

#[test]
fn xxhash_family() {
    assert_eq!(xxh32(b"", 0), 0x02cc5d05);
    assert_eq!(xxh64(b"", 0), 0xef46db3751d8e999);
    let _ = xxh3_64(b"hello", 0);
    let d128 = xxh3_128_bytes(b"hello", 0).unwrap();
    assert_eq!(d128.len(), 16);
    let d256 = xxh3_256_bytes(b"hello", 0).unwrap();
    assert_eq!(d256.len(), 32);
}

#[test]
fn legacy_hashes() {
    assert_eq!(md5(b"").unwrap()[0], 0xd4);
    assert_eq!(md4(b"").unwrap()[0], 0x31);
    assert_eq!(sha1(b"").unwrap()[0], 0xda);
    assert_eq!(ripemd160(b"").unwrap()[0], 0x9c);
}

#[test]
fn ct_verify_digest() {
    use blockchain_utils::ct_verify;
    let a = sha256(b"secret").unwrap();
    let b = sha256(b"secret").unwrap();
    let c = sha256(b"other").unwrap();
    assert!(ct_verify(&a, &b).is_ok());
    assert!(ct_verify(&a, &c).is_err());
}
