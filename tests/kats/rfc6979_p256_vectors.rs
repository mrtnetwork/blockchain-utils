//! RFC 6979 §A.2.5 — ECDSA P-256 (secp256r1) with SHA-256.
//!
//! Source: RFC 6979 Appendix A.2.5 (ECDSA, 256 Bits, Prime Field).
//! Run: `cargo test --test kats rfc6979_p256_vectors -- --nocapture`

#![cfg(feature = "alloc")]

use blockchain_utils::curve::secp256r1::Scalar;
use blockchain_utils::encoding::hex::decode;
use blockchain_utils::hash::sha256;
use blockchain_utils::signature::ecdsa_p256::{
    deterministic_k, sign, verify, SecretKey, Signature,
};

fn unhex(s: &str) -> Vec<u8> {
    // Preserve prior leniency: ignore non-hex characters (e.g. separators),
    // then decode strictly via the crate implementation.
    let s: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    decode(&s).expect("hex")
}

fn unhex32(s: &str) -> [u8; 32] {
    let v = unhex(s);
    assert_eq!(v.len(), 32, "{}", s);
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    a
}

// RFC 6979 A.2.5 key pair
const PRIV: &str = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";
const PUB_X: &str = "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6";
const PUB_Y: &str = "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299";

#[test]
fn rfc6979_a25_public_key() {
    let sk = SecretKey::from_bytes(&unhex32(PRIV)).unwrap();
    let pk = sk.public_key().unwrap();
    let mut enc = [0u8; 65];
    pk.to_bytes_uncompressed(&mut enc).unwrap();
    assert_eq!(enc[0], 0x04);
    assert_eq!(&enc[1..33], &unhex32(PUB_X));
    assert_eq!(&enc[33..65], &unhex32(PUB_Y));
    eprintln!("RFC6979 A.2.5 public key match: OK");
}

#[test]
fn rfc6979_a25_sha256_sample() {
    // With SHA-256, message = "sample"
    // k = A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60
    // r = EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716
    // s = F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8
    let sk = SecretKey::from_bytes(&unhex32(PRIV)).unwrap();
    let pk = sk.public_key().unwrap();
    let hash = sha256(b"sample").unwrap();

    let k_expected = unhex32("A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60");
    let k = deterministic_k(&sk, &hash);
    let mut kb = [0u8; 32];
    k.to_bytes_be(&mut kb);
    assert_eq!(kb, k_expected, "deterministic k mismatch for 'sample'");

    let sig = sign(&sk, &hash).unwrap();
    let r_exp = unhex32("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716");
    let s_exp = unhex32("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8");
    // Low-S may flip s to n-s; accept either form if verify passes and r matches
    assert_eq!(sig.r, r_exp, "r mismatch");
    if sig.s != s_exp {
        // check n - s
        let s = Scalar::from_bytes_be(&sig.s).unwrap();
        let mut ns = [0u8; 32];
        s.neg().to_bytes_be(&mut ns);
        assert_eq!(ns, s_exp, "s mismatch (neither s nor n-s)");
        eprintln!("note: signature used low-S form (n-s)");
    }
    verify(&pk, &hash, &sig).expect("verify sample");
    // Also verify published high-S form if different
    let published = Signature { r: r_exp, s: s_exp };
    verify(&pk, &hash, &published).expect("verify published sample");
    eprintln!("RFC6979 A.2.5 SHA-256 'sample': OK");
}

#[test]
fn rfc6979_a25_sha256_test() {
    // message = "test"
    // k = D16B6AE827F17175E040871A1C7EC3500192C4C92677336EC2537ACAEE0008E0
    // r = F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367
    // s = 019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083
    let sk = SecretKey::from_bytes(&unhex32(PRIV)).unwrap();
    let pk = sk.public_key().unwrap();
    let hash = sha256(b"test").unwrap();

    let k_expected = unhex32("D16B6AE827F17175E040871A1C7EC3500192C4C92677336EC2537ACAEE0008E0");
    let k = deterministic_k(&sk, &hash);
    let mut kb = [0u8; 32];
    k.to_bytes_be(&mut kb);
    assert_eq!(kb, k_expected, "deterministic k mismatch for 'test'");

    let r_exp = unhex32("F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367");
    let s_exp = unhex32("019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083");
    let sig = sign(&sk, &hash).unwrap();
    assert_eq!(sig.r, r_exp, "r mismatch");
    if sig.s != s_exp {
        let s = Scalar::from_bytes_be(&sig.s).unwrap();
        let mut ns = [0u8; 32];
        s.neg().to_bytes_be(&mut ns);
        assert_eq!(ns, s_exp, "s mismatch");
        eprintln!("note: low-S form for 'test'");
    }
    verify(&pk, &hash, &sig).unwrap();
    let published = Signature { r: r_exp, s: s_exp };
    verify(&pk, &hash, &published).expect("verify published test sig");
    eprintln!("RFC6979 A.2.5 SHA-256 'test': OK");
}

#[test]
fn p256_sign_verify_randomish() {
    let sk = SecretKey::from_bytes(&unhex32(PRIV)).unwrap();
    let pk = sk.public_key().unwrap();
    let h = sha256(b"hello p256 ecdsa").unwrap();
    let sig = sign(&sk, &h).unwrap();
    verify(&pk, &h, &sig).unwrap();
}
