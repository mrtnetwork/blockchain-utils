//! ML-DSA KATs ported from reference `test/crypto/ml_dsa`.
#![cfg(feature = "std")]

use blockchain_utils::signature::ml_dsa::MlDsa;

fn unhex(s: &str) -> Vec<u8> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// minimal JSON: we only need string fields
fn get_str<'a>(obj: &'a str, key: &str) -> Option<&'a str> {
    let pat = format!("\"{}\":\"", key);
    let i = obj.find(&pat)? + pat.len();
    let j = obj[i..].find('"')? + i;
    Some(&obj[i..j])
}

fn objects(section: &str) -> Vec<&str> {
    // split on },{ roughly inside section
    let mut out = Vec::new();
    let mut depth = 0;
    let mut start = None;
    for (i, c) in section.char_indices() {
        match c {
            '{' => {
                if depth == 0 {
                    start = Some(i);
                }
                depth += 1;
            }
            '}' => {
                depth -= 1;
                if depth == 0 {
                    if let Some(s) = start {
                        out.push(&section[s..=i]);
                    }
                    start = None;
                }
            }
            _ => {}
        }
    }
    out
}

fn section<'a>(raw: &'a str, name: &str) -> &'a str {
    let key = format!("\"{}\":[", name);
    let i = raw.find(&key).expect(name) + key.len() - 1;
    let mut depth = 0;
    for (j, c) in raw[i..].char_indices() {
        match c {
            '[' => depth += 1,
            ']' => {
                depth -= 1;
                if depth == 0 {
                    return &raw[i..=i + j];
                }
            }
            _ => {}
        }
    }
    panic!("unclosed");
}

fn run_set(dsa: MlDsa, name: &str, external: bool) {
    let raw = include_str!("../vectors/mldsa_kat.json").replace([' ', '\n', '\t'], "");
    let sec = section(&raw, name);
    for obj in objects(sec) {
        let key_seed = unhex(get_str(obj, "key_seed").unwrap());
        let sign_seed = unhex(get_str(obj, "sign_seed").unwrap());
        let message = unhex(get_str(obj, "message").unwrap());
        let exp_pk = get_str(obj, "pk").unwrap();
        let exp_sk = get_str(obj, "sk").unwrap();
        let exp_sig = get_str(obj, "signature").unwrap();
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&key_seed);
        let (pk, sk) = dsa.keygen(&seed).expect("keygen");
        let pk2 = dsa.public_key_from_secret_key(&sk).unwrap();
        assert_eq!(pk, pk2, "pk_from_sk");
        assert_eq!(hex(&pk), exp_pk, "pk mismatch {name}");
        assert_eq!(hex(&sk), exp_sk, "sk mismatch {name}");
        let mut rnd = [0u8; 32];
        rnd.copy_from_slice(&sign_seed);
        let sig = if external {
            dsa.sign_external(&sk, &message, &rnd).expect("sign ext")
        } else {
            dsa.sign(&sk, &message, &rnd, &[]).expect("sign")
        };
        assert_eq!(hex(&sig), exp_sig, "sig mismatch {name}");
        let ok = if external {
            dsa.verify_external(&pk, &message, &sig)
        } else {
            dsa.verify(&pk, &message, &sig, &[])
        };
        assert!(ok, "verify {name}");
    }
}

#[test]
fn mldsa65_kat() {
    run_set(MlDsa::mldsa65(), "mlDsa65", false);
}

#[test]
fn mldsa65_external_kat() {
    run_set(MlDsa::mldsa65(), "mlDSA65External", true);
}

#[test]
fn mldsa44_kat() {
    run_set(MlDsa::mldsa44(), "mlDsa44", false);
}

#[test]
fn mldsa87_kat() {
    run_set(MlDsa::mldsa87(), "mlDsa87", false);
}
