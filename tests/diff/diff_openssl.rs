//! P0 #2 — Cross-implementation differential tests (OpenSSL).
//!
//! Spawns `openssl` when available and checks that our secp256k1 / secp256r1
//! scalar-mul matches OpenSSL's public key for freshly generated private keys.
//!
//! Skips cleanly if `openssl` is not on PATH.
//!
//! Run: `cargo test --test diff diff_openssl -- --test-threads=1`
//! Or:  `bash scripts/ci_kats.sh`

#![cfg(feature = "alloc")]

use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use blockchain_utils::curve::{
    CurvePoint, Secp256k1Point, Secp256k1Scalar, Secp256r1Point, Secp256r1Scalar,
};
use blockchain_utils::encoding::hex::{decode, encode};

static COUNTER: AtomicU64 = AtomicU64::new(1);

fn openssl_available() -> bool {
    Command::new("openssl")
        .arg("version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn unhex(s: &str) -> Vec<u8> {
    // Preserve prior leniency: ignore non-hex characters (e.g. ':' separators
    // in `openssl -text` output), then decode strictly via the crate.
    let s: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    decode(&s).expect("hex")
}

fn tmp_pem_path(curve: &str) -> String {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    format!("/tmp/bu_ec_{}_{}_{}.pem", curve, std::process::id(), n)
}

/// Generate a random EC key with OpenSSL; return (priv_32, compressed_pub_33).
fn openssl_random_key_pair(curve_name: &str) -> Option<(Vec<u8>, Vec<u8>)> {
    let path = tmp_pem_path(curve_name);
    let gen = Command::new("openssl")
        .args([
            "ecparam", "-name", curve_name, "-genkey", "-noout", "-out", &path,
        ])
        .output()
        .ok()?;
    if !gen.status.success() {
        let _ = std::fs::remove_file(&path);
        return None;
    }

    let text = Command::new("openssl")
        .args(["ec", "-in", &path, "-text", "-noout"])
        .output()
        .ok();
    let text = match text {
        Some(t) if t.status.success() => t,
        _ => {
            let _ = std::fs::remove_file(&path);
            return None;
        }
    };
    let text_s = String::from_utf8_lossy(&text.stdout);
    let priv_bytes = parse_openssl_priv_hex(&text_s);

    let pub_der = Command::new("openssl")
        .args([
            "ec",
            "-in",
            &path,
            "-pubout",
            "-conv_form",
            "compressed",
            "-outform",
            "DER",
        ])
        .output()
        .ok();
    let _ = std::fs::remove_file(&path);

    let priv_bytes = priv_bytes.filter(|b| b.len() == 32)?;
    let pub_der = match pub_der {
        Some(p) if p.status.success() => p,
        _ => return None,
    };
    let compressed = extract_compressed_from_spki(&pub_der.stdout)?;
    Some((priv_bytes, compressed))
}

fn parse_openssl_priv_hex(text: &str) -> Option<Vec<u8>> {
    // priv:
    //     aa:bb:...
    //     ...
    // pub:
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        if !line.trim().starts_with("priv:") {
            continue;
        }
        let mut hex = String::new();
        for l in lines.by_ref() {
            let t = l.trim();
            if t.starts_with("pub:") {
                break;
            }
            if t.is_empty() {
                break;
            }
            if t.chars().all(|c| c.is_ascii_hexdigit() || c == ':') {
                hex.push_str(t);
            } else {
                break;
            }
        }
        let clean: String = hex.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        // OpenSSL may prefix a 00 byte when high bit set → 33 bytes; take last 32.
        if clean.len() >= 64 && clean.len().is_multiple_of(2) {
            let start = clean.len() - 64;
            return Some(unhex(&clean[start..]));
        }
        return None;
    }
    None
}

fn extract_compressed_from_spki(der: &[u8]) -> Option<Vec<u8>> {
    // BIT STRING: 03 22 00 || 33-byte compressed point
    let mut i = 0;
    while i + 36 <= der.len() {
        if der[i] == 0x03 && der[i + 1] == 0x22 && der[i + 2] == 0x00 {
            let pt = &der[i + 3..i + 36];
            if pt[0] == 0x02 || pt[0] == 0x03 {
                return Some(pt.to_vec());
            }
        }
        i += 1;
    }
    if der.len() >= 33 {
        let pt = &der[der.len() - 33..];
        if pt[0] == 0x02 || pt[0] == 0x03 {
            return Some(pt.to_vec());
        }
    }
    None
}

#[test]
fn diff_openssl_secp256k1_random_keys() {
    if !openssl_available() {
        eprintln!("skip: openssl not available");
        return;
    }
    const N: usize = 8;
    let mut matched = 0usize;
    for trial in 0..N {
        let Some((priv_b, openssl_pub)) = openssl_random_key_pair("secp256k1") else {
            eprintln!("trial {trial}: failed to parse openssl key");
            continue;
        };
        let sk = Secp256k1Scalar::from_bytes(&priv_b).expect("scalar");
        let pk = Secp256k1Point::generator().mul(&sk);
        let mut ours = [0u8; 33];
        pk.to_bytes_compressed(&mut ours).unwrap();
        assert_eq!(
            ours.as_slice(),
            openssl_pub.as_slice(),
            "secp256k1 trial {trial}: our [priv]G != OpenSSL\n priv={}\n ours={}\n ossl={}",
            encode(&priv_b),
            encode(&ours),
            encode(&openssl_pub)
        );
        matched += 1;
    }
    assert!(
        matched >= N / 2,
        "too few successful OpenSSL secp256k1 trials: {matched}/{N}"
    );
    eprintln!("diff_openssl secp256k1: {matched}/{N} matched");
}

#[test]
fn diff_openssl_secp256r1_random_keys() {
    if !openssl_available() {
        eprintln!("skip: openssl not available");
        return;
    }
    const N: usize = 8;
    let mut matched = 0usize;
    for trial in 0..N {
        let Some((priv_b, openssl_pub)) = openssl_random_key_pair("prime256v1") else {
            eprintln!("trial {trial}: failed to parse openssl P-256 key");
            continue;
        };
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&priv_b);
        let sk = Secp256r1Scalar::from_bytes_be(&arr).expect("scalar");
        let pk = Secp256r1Point::generator().mul(&sk);
        let mut ours = [0u8; 33];
        pk.to_bytes_compressed(&mut ours).unwrap();
        assert_eq!(
            ours.as_slice(),
            openssl_pub.as_slice(),
            "P-256 trial {trial}: our [priv]G != OpenSSL\n priv={}\n ours={}\n ossl={}",
            encode(&priv_b),
            encode(&ours),
            encode(&openssl_pub)
        );
        matched += 1;
    }
    assert!(
        matched >= N / 2,
        "too few successful OpenSSL P-256 trials: {matched}/{N}"
    );
    eprintln!("diff_openssl secp256r1: {matched}/{N} matched");
}

#[test]
fn diff_openssl_curve_names_known() {
    if !openssl_available() {
        return;
    }
    for name in ["secp256k1", "prime256v1"] {
        let out = Command::new("openssl")
            .args(["ecparam", "-name", name, "-text", "-noout"])
            .output()
            .expect("openssl");
        assert!(out.status.success(), "openssl ecparam -name {name}");
    }
}
