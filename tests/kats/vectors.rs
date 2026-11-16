//! Large reference-library test vectors.
//!
//! Vectors live in `tests/vectors/*.json` (converted from the reference package).
//! Hex parsing uses our own `encoding::hex` implementation.

#![cfg(feature = "alloc")]

use blockchain_utils::aead::{chacha20_poly1305_decrypt, chacha20_poly1305_encrypt};
use blockchain_utils::cipher::{aes_ctr, stream_xor};
use blockchain_utils::encoding::hex::{decode, encode};
use blockchain_utils::hash::*;

/// Minimal JSON array-of-objects parser (no external deps).
/// Supports string and integer values only.
fn parse_json_array(s: &str) -> Vec<std::collections::BTreeMap<String, JsonVal>> {
    let mut items = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    // skip whitespace and [
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= bytes.len() || bytes[i] != b'[' {
        return items;
    }
    i += 1;
    loop {
        while i < bytes.len() && (bytes[i].is_ascii_whitespace() || bytes[i] == b',') {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] == b']' {
            break;
        }
        if bytes[i] != b'{' {
            break;
        }
        i += 1;
        let mut map = std::collections::BTreeMap::new();
        loop {
            while i < bytes.len() && (bytes[i].is_ascii_whitespace() || bytes[i] == b',') {
                i += 1;
            }
            if i >= bytes.len() || bytes[i] == b'}' {
                i += 1;
                break;
            }
            if bytes[i] != b'"' {
                break;
            }
            i += 1;
            let start = i;
            while i < bytes.len() && bytes[i] != b'"' {
                i += 1;
            }
            let key = std::str::from_utf8(&bytes[start..i]).unwrap().to_string();
            i += 1; // closing "
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < bytes.len() && bytes[i] == b':' {
                i += 1;
            }
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < bytes.len() && bytes[i] == b'"' {
                i += 1;
                let mut val = String::new();
                while i < bytes.len() && bytes[i] != b'"' {
                    if bytes[i] == b'\\' && i + 1 < bytes.len() {
                        val.push(bytes[i + 1] as char);
                        i += 2;
                    } else {
                        val.push(bytes[i] as char);
                        i += 1;
                    }
                }
                i += 1;
                map.insert(key, JsonVal::Str(val));
            } else {
                // number
                let start = i;
                if i < bytes.len() && bytes[i] == b'-' {
                    i += 1;
                }
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                let num: i64 = std::str::from_utf8(&bytes[start..i])
                    .unwrap()
                    .parse()
                    .unwrap_or(0);
                map.insert(key, JsonVal::Int(num));
            }
        }
        items.push(map);
    }
    items
}

#[derive(Clone, Debug)]
enum JsonVal {
    Str(String),
    Int(i64),
}

impl JsonVal {
    fn as_str(&self) -> &str {
        match self {
            JsonVal::Str(s) => s,
            _ => "",
        }
    }
    fn as_int(&self) -> i64 {
        match self {
            JsonVal::Int(n) => *n,
            _ => 0,
        }
    }
}

fn hex(s: &str) -> Vec<u8> {
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    decode(s).unwrap_or_else(|e| {
        panic!(
            "hex decode failed for '{}...': {:?}",
            &s[..s.len().min(16)],
            e
        )
    })
}

fn get<'a>(m: &'a std::collections::BTreeMap<String, JsonVal>, k: &str) -> &'a str {
    m.get(k).map(|v| v.as_str()).unwrap_or("")
}

macro_rules! vectors {
    ($file:expr) => {
        parse_json_array(include_str!(concat!("../vectors/", $file)))
    };
}

// ---------------------------------------------------------------------------
// Hash vectors
// ---------------------------------------------------------------------------

#[test]
fn reference_sha256() {
    for (idx, v) in vectors!("sha256.json").iter().enumerate() {
        let msg = hex(get(v, "message"));
        let expected = hex(get(v, "hash"));
        let got = sha256(&msg).unwrap();
        assert_eq!(got.as_slice(), expected.as_slice(), "sha256[{}]", idx);
    }
}

#[test]
fn reference_sha512() {
    for (idx, v) in vectors!("sha512.json").iter().enumerate() {
        let msg = hex(get(v, "message"));
        let expected = hex(get(v, "hash"));
        let got = sha512(&msg).unwrap();
        assert_eq!(got.as_slice(), expected.as_slice(), "sha512[{}]", idx);
    }
}

#[test]
fn reference_sha1() {
    for (idx, v) in vectors!("sha1.json").iter().enumerate() {
        let msg = hex(get(v, "message"));
        let expected = hex(get(v, "hash"));
        let got = sha1(&msg).unwrap();
        assert_eq!(got.as_slice(), expected.as_slice(), "sha1[{}]", idx);
    }
}

#[test]
fn reference_md4() {
    for (idx, v) in vectors!("md4.json").iter().enumerate() {
        let msg = hex(get(v, "message"));
        let expected = hex(get(v, "hash"));
        let got = md4(&msg).unwrap();
        assert_eq!(got.as_slice(), expected.as_slice(), "md4[{}]", idx);
    }
}

#[test]
fn reference_md5() {
    for (idx, v) in vectors!("md5.json").iter().enumerate() {
        let msg = hex(get(v, "message"));
        let expected = hex(get(v, "hash"));
        let got = md5(&msg).unwrap();
        assert_eq!(got.as_slice(), expected.as_slice(), "md5[{}]", idx);
    }
}

#[test]
fn reference_blake2b_512() {
    for (idx, v) in vectors!("blake2b.json").iter().enumerate() {
        // Skip keyed / salted vectors (need Blake2bConfig)
        if v.contains_key("key") || v.contains_key("salt") {
            continue;
        }
        let msg = hex(get(v, "message"));
        let expected = hex(get(v, "hash"));
        if expected.len() != 64 {
            continue;
        }
        let got = blake2b_512(&msg).unwrap();
        assert_eq!(got.as_slice(), expected.as_slice(), "blake2b[{}]", idx);
    }
}

#[test]
fn reference_keccak256() {
    for (idx, v) in vectors!("keccak.json").iter().enumerate() {
        let msg = hex(get(v, "message"));
        let expected = hex(get(v, "hash"));
        if expected.len() != 32 {
            continue;
        }
        let got = keccak256(&msg).unwrap();
        assert_eq!(got.as_slice(), expected.as_slice(), "keccak256[{}]", idx);
    }
}

#[test]
fn reference_keccak512() {
    for (idx, v) in vectors!("keccak.json").iter().enumerate() {
        let msg = hex(get(v, "message"));
        let expected = hex(get(v, "hash"));
        if expected.len() != 64 {
            continue;
        }
        let got = keccak512(&msg).unwrap();
        assert_eq!(got.as_slice(), expected.as_slice(), "keccak512[{}]", idx);
    }
}

#[test]
fn reference_sha3_256() {
    for (idx, v) in vectors!("sha3.json").iter().enumerate() {
        let msg = hex(get(v, "message"));
        let expected = hex(get(v, "hash"));
        if expected.len() != 32 {
            continue;
        }
        let got = sha3_256(&msg).unwrap();
        assert_eq!(got.as_slice(), expected.as_slice(), "sha3_256[{}]", idx);
    }
}

#[test]
fn reference_sha3_512() {
    for (idx, v) in vectors!("sha3.json").iter().enumerate() {
        let msg = hex(get(v, "message"));
        let expected = hex(get(v, "hash"));
        if expected.len() != 64 {
            continue;
        }
        let got = sha3_512(&msg).unwrap();
        assert_eq!(got.as_slice(), expected.as_slice(), "sha3_512[{}]", idx);
    }
}

#[test]
fn reference_ripemd160() {
    for (idx, v) in vectors!("ripemd160.json").iter().enumerate() {
        let msg = hex(get(v, "message"));
        let expected = hex(get(v, "hash"));
        if expected.len() != 20 {
            continue; // skip ripemd128/256/320
        }
        let got = ripemd160(&msg).unwrap();
        assert_eq!(got.as_slice(), expected.as_slice(), "ripemd160[{}]", idx);
    }
}

#[test]
fn reference_hmac() {
    let all = vectors!("hmac.json");
    // reference file order: hmach512TestVector (25), hmac256TestVector (25), sha3TestVector (rest)
    for (idx, v) in all.iter().enumerate() {
        let key = hex(get(v, "key"));
        let msg = hex(get(v, "message"));
        let expected = hex(get(v, "hash"));
        if idx < 25 {
            let got = hmac_sha512(&key, &msg).unwrap();
            assert_eq!(got.as_slice(), expected.as_slice(), "hmac_sha512[{}]", idx);
        } else if idx < 50 {
            let got = hmac_sha256(&key, &msg).unwrap();
            assert_eq!(got.as_slice(), expected.as_slice(), "hmac_sha256[{}]", idx);
        }
        // idx >= 50 → HMAC-SHA3, skip until SHA3-HMAC is exposed
    }
}

#[test]
fn reference_pbkdf2() {
    for (idx, v) in vectors!("pbkdf2.json").iter().enumerate() {
        let password = hex(get(v, "password"));
        let salt = hex(get(v, "salt"));
        let n = v.get("n").map(|x| x.as_int() as u32).unwrap_or(1);
        let expected = hex(get(v, "hash"));
        // reference PBKDF2 vectors always use HMAC-SHA512, output length from vector
        let mut out = vec![0u8; expected.len()];
        pbkdf2_hmac_sha512(&password, &salt, n, &mut out).unwrap();
        assert_eq!(out, expected, "pbkdf2[{}] n={}", idx, n);
    }
}

#[test]
fn reference_shake128() {
    for (idx, v) in vectors!("shake128.json").iter().enumerate() {
        let input = hex(get(v, "input"));
        let expected = hex(get(v, "out"));
        let mut out = vec![0u8; expected.len()];
        shake128(&input, &mut out).unwrap();
        assert_eq!(out, expected, "shake128[{}]", idx);
    }
}

#[test]
fn reference_shake256() {
    for (idx, v) in vectors!("shake256.json").iter().enumerate() {
        let input = hex(get(v, "input"));
        let expected = hex(get(v, "out"));
        let mut out = vec![0u8; expected.len()];
        shake256(&input, &mut out).unwrap();
        assert_eq!(out, expected, "shake256[{}]", idx);
    }
}

#[test]
fn reference_xxhash64() {
    // reference xxhash64 vectors use variable bitlength (XXH3-family / multi-size).
    // Only exercise classic XXH64 when bitlength == 64.
    let all = vectors!("xxhash64.json");
    // Optional file: an empty vector set exercises nothing and still passes.
    for (idx, v) in all.iter().enumerate() {
        let bitlength = v.get("bitlength").map(|x| x.as_int()).unwrap_or(0);
        if bitlength != 64 {
            continue;
        }
        let mut hash_hex = get(v, "hash").to_string();
        if hash_hex.starts_with("0x") || hash_hex.starts_with("0X") {
            hash_hex = hash_hex[2..].to_string();
        }
        let data_hex = get(v, "hex");
        let data = if data_hex.is_empty() {
            vec![]
        } else {
            hex(data_hex)
        };
        let expected = hex(&hash_hex);
        if expected.len() != 8 {
            continue;
        }
        let got = xxh64(&data, 0);
        assert_eq!(
            got.to_le_bytes().as_slice(),
            expected.as_slice(),
            "xxh64[{}]",
            idx
        );
    }
}

// ---------------------------------------------------------------------------
// AEAD / cipher vectors
// ---------------------------------------------------------------------------

#[test]
fn reference_chacha20_poly1305() {
    for (idx, v) in vectors!("chacha20_poly1305.json").iter().enumerate() {
        if !v.contains_key("tag") {
            continue;
        }
        let pt = hex(get(v, "plain_text"));
        let aad = hex(get(v, "assoc_data"));
        let key = hex(get(v, "key"));
        let nonce = hex(get(v, "nonce"));
        let tag = hex(get(v, "tag"));
        let ct = hex(get(v, "encrypt"));
        // Accept 8..=16 byte nonces (reference-compatible)
        if nonce.is_empty() || nonce.len() > 16 {
            continue;
        }

        let mut out = vec![0u8; pt.len() + 16];
        chacha20_poly1305_encrypt(&key, &nonce, &pt, &aad, &mut out).unwrap();
        assert_eq!(
            &out[..pt.len()],
            ct.as_slice(),
            "chacha_aead encrypt ct[{}]",
            idx
        );
        assert_eq!(
            &out[pt.len()..],
            tag.as_slice(),
            "chacha_aead encrypt tag[{}]",
            idx
        );

        let mut plain = vec![0u8; pt.len()];
        chacha20_poly1305_decrypt(&key, &nonce, &out, &aad, &mut plain).unwrap();
        assert_eq!(plain, pt, "chacha_aead decrypt[{}]", idx);
    }
}

#[test]
fn reference_chacha_seek_bytes() {
    for (idx, v) in vectors!("chacha20_poly1305.json").iter().enumerate() {
        if !v.contains_key("seek1") {
            continue;
        }
        let key = hex(get(v, "key"));
        let nonce = hex(get(v, "nonce"));
        let pt = hex(get(v, "plaintext"));
        let seek1 = v.get("seek1").map(|x| x.as_int() as usize).unwrap_or(0);
        let seek2 = v.get("seek2").map(|x| x.as_int() as usize).unwrap_or(0);
        let after1 = hex(get(v, "after_seek1"));
        let after2 = hex(get(v, "after_seek2"));

        let mut d = vec![0u8; pt.len()];
        stream_xor(&key, &nonce, &pt, &mut d, 0, seek1).unwrap();
        assert_eq!(d, after1, "chacha_seek1[{}]", idx);

        let mut d2 = vec![0u8; d.len()];
        stream_xor(&key, &nonce, &d, &mut d2, 0, seek2).unwrap();
        assert_eq!(d2, after2, "chacha_seek2[{}]", idx);
    }
}

#[test]
fn reference_aes_ctr() {
    // reference AES test_vector uses key/iv/plain_text/encrypt — CTR mode
    for (idx, v) in vectors!("aes.json").iter().enumerate() {
        let key = hex(get(v, "key"));
        let iv = hex(get(v, "iv"));
        let pt = hex(get(v, "plain_text"));
        let expected = hex(get(v, "encrypt"));
        if iv.len() != 16 {
            continue;
        }
        let mut iv_arr = [0u8; 16];
        iv_arr.copy_from_slice(&iv);
        let mut out = vec![0u8; pt.len()];
        aes_ctr(&key, &iv_arr, &pt, &mut out).unwrap();
        assert_eq!(out, expected, "aes_ctr[{}]", idx);
        // decrypt = encrypt
        let mut plain = vec![0u8; expected.len()];
        aes_ctr(&key, &iv_arr, &expected, &mut plain).unwrap();
        assert_eq!(plain, pt, "aes_ctr decrypt[{}]", idx);
    }
}

#[test]
fn hex_roundtrip_on_vectors() {
    // Sanity: our hex encoder matches decoded→encoded
    for v in vectors!("sha256.json").iter().take(5) {
        let msg = hex(get(v, "message"));
        assert_eq!(encode(&msg), get(v, "message").to_lowercase());
    }
}
