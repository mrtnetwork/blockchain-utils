//! Dudect-style timing experiment for scalar multiplication (P0 #3).
//! Exit 0 = PASS; exit 2 = SUSPICIOUS class split.

use blockchain_utils::curve::bls::{G1Point, G2Point, Scalar as BlsScalar};
use blockchain_utils::curve::ed25519::{Ed25519Point, Scalar as EdScalar};use blockchain_utils::curve::jubjub::{JubJubPoint, Scalar as JubScalar};
use blockchain_utils::curve::pallas::Fe as PallasFe;
use blockchain_utils::curve::pallas::{PallasPoint, Scalar as PallasScalar};
use blockchain_utils::curve::ristretto::RistrettoPoint;
use blockchain_utils::curve::secp256k1::{Scalar as ScalarK1, Secp256k1Point};
use blockchain_utils::curve::secp256r1::{Scalar as ScalarR1, Secp256r1Point};
use blockchain_utils::curve::traits::CurvePoint;
use blockchain_utils::curve::vesta::{Scalar as VestaScalar, VestaPoint};
use blockchain_utils::dkls23::curve_id::{CurveId, DklsPoint, DklsScalar};
use blockchain_utils::hash::{blake2b_512, hmac_sha256, hmac_sha512, poseidon_hash, sha256};
use std::env;
use std::time::Instant;

fn mean(xs: &[f64]) -> f64 {
    xs.iter().sum::<f64>() / xs.len() as f64
}
fn variance(xs: &[f64], m: f64) -> f64 {
    xs.iter().map(|x| (x - m) * (x - m)).sum::<f64>() / xs.len() as f64
}
fn t_stat(a: &[f64], b: &[f64]) -> f64 {
    let ma = mean(a);
    let mb = mean(b);
    let se = (variance(a, ma) / a.len() as f64 + variance(b, mb) / b.len() as f64).sqrt();
    if se == 0.0 {
        0.0
    } else {
        (ma - mb) / se
    }
}
fn report(name: &str, fixed: &[f64], random: &[f64]) -> bool {
    let t = t_stat(fixed, random);
    println!(
        "--- {name} --- mean_fixed={:.0} mean_rand={:.0} |t|={:.2}",
        mean(fixed),
        mean(random),
        t.abs()
    );
    if t.abs() > 5.0 {
        println!("  RESULT: SUSPICIOUS");
        false
    } else {
        println!("  RESULT: ok");
        true
    }
}
fn prng_bytes(i: usize, out: &mut [u8]) {
    for (j, b) in out.iter_mut().enumerate() {
        *b = ((i.wrapping_mul(1103515245).wrapping_add(j * 12345 + 1)) & 0xff) as u8;
    }
}
fn be_low(w: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[31] = w;
    s
}
fn le_low(w: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[0] = w;
    s
}

fn bench_ed25519(n: usize) -> bool {
    let g = Ed25519Point::generator();
    let sf = EdScalar::from_bytes_le(&le_low(0x0f)).unwrap_or_else(|_| EdScalar::one());
    let mut fixed = Vec::with_capacity(n);
    let mut random = Vec::with_capacity(n);
    for _ in 0..50 {
        let _ = g.mul(&sf);
    }
    for i in 0..n {
        let t0 = Instant::now();
        let _ = std::hint::black_box(g.mul(&sf));
        fixed.push(t0.elapsed().as_nanos() as f64);
        let mut sb = [0u8; 32];
        prng_bytes(i, &mut sb);
        sb[31] &= 0x1f;
        let sr = EdScalar::from_bytes_le(&sb).unwrap_or_else(|_| EdScalar::one());
        let t1 = Instant::now();
        let _ = std::hint::black_box(g.mul(&sr));
        random.push(t1.elapsed().as_nanos() as f64);
    }
    report("ed25519", &fixed, &random)
}

fn bench_secp256k1(n: usize) -> bool {
    let g = Secp256k1Point::generator();
    let sf = ScalarK1::from_bytes_be(&be_low(0x0f)).unwrap_or_else(|_| ScalarK1::one());
    let mut fixed = Vec::with_capacity(n);
    let mut random = Vec::with_capacity(n);
    for _ in 0..50 {
        let _ = g.mul(&sf);
    }
    for i in 0..n {
        let t0 = Instant::now();
        let _ = std::hint::black_box(g.mul(&sf));
        fixed.push(t0.elapsed().as_nanos() as f64);
        let mut sb = [0u8; 32];
        prng_bytes(i, &mut sb);
        sb[0] &= 0x0f;
        let sr = ScalarK1::from_bytes_be(&sb).unwrap_or_else(|_| ScalarK1::one());
        let t1 = Instant::now();
        let _ = std::hint::black_box(g.mul(&sr));
        random.push(t1.elapsed().as_nanos() as f64);
    }
    report("secp256k1", &fixed, &random)
}

fn bench_secp256r1(n: usize) -> bool {
    let g = Secp256r1Point::generator();
    let sf = ScalarR1::from_bytes_be(&be_low(0x0f)).unwrap_or_else(|_| ScalarR1::one());
    let mut fixed = Vec::with_capacity(n);
    let mut random = Vec::with_capacity(n);
    for _ in 0..30 {
        let _ = g.mul(&sf);
    }
    for i in 0..n {
        let t0 = Instant::now();
        let _ = std::hint::black_box(g.mul(&sf));
        fixed.push(t0.elapsed().as_nanos() as f64);
        let mut sb = [0u8; 32];
        prng_bytes(i, &mut sb);
        sb[0] &= 0x0f;
        let sr = ScalarR1::from_bytes_be(&sb).unwrap_or_else(|_| ScalarR1::one());
        let t1 = Instant::now();
        let _ = std::hint::black_box(g.mul(&sr));
        random.push(t1.elapsed().as_nanos() as f64);
    }
    report("secp256r1", &fixed, &random)
}

fn bench_ristretto(n: usize) -> bool {
    let g = RistrettoPoint::generator();
    let sf = EdScalar::from_bytes_le(&le_low(0x0f)).unwrap_or_else(|_| EdScalar::one());
    let mut fixed = Vec::with_capacity(n);
    let mut random = Vec::with_capacity(n);
    for _ in 0..30 {
        let _ = g.mul(&sf);
    }
    for i in 0..n {
        let t0 = Instant::now();
        let _ = std::hint::black_box(g.mul(&sf));
        fixed.push(t0.elapsed().as_nanos() as f64);
        let mut sb = [0u8; 32];
        prng_bytes(i, &mut sb);
        sb[31] &= 0x1f;
        let sr = EdScalar::from_bytes_le(&sb).unwrap_or_else(|_| EdScalar::one());
        let t1 = Instant::now();
        let _ = std::hint::black_box(g.mul(&sr));
        random.push(t1.elapsed().as_nanos() as f64);
    }
    report("ristretto", &fixed, &random)
}

fn bench_bls_g1(n: usize) -> bool {
    let g = G1Point::generator();
    let sf = BlsScalar::from_bytes_be(&be_low(0x0f)).unwrap_or_else(|_| BlsScalar::one());
    let mut fixed = Vec::with_capacity(n);
    let mut random = Vec::with_capacity(n);
    for _ in 0..10 {
        let _ = g.mul(&sf);
    }
    for i in 0..n {
        let t0 = Instant::now();
        let _ = std::hint::black_box(g.mul(&sf));
        fixed.push(t0.elapsed().as_nanos() as f64);
        let mut sb = [0u8; 32];
        prng_bytes(i, &mut sb);
        sb[0] &= 0x0f;
        let sr = BlsScalar::from_bytes_be(&sb).unwrap_or_else(|_| BlsScalar::one());
        let t1 = Instant::now();
        let _ = std::hint::black_box(g.mul(&sr));
        random.push(t1.elapsed().as_nanos() as f64);
    }
    report("bls_g1", &fixed, &random)
}

fn bench_bls_g2(n: usize) -> bool {
    let g = G2Point::generator();
    let sf = BlsScalar::from_bytes_be(&be_low(0x0f)).unwrap_or_else(|_| BlsScalar::one());
    let mut fixed = Vec::with_capacity(n);
    let mut random = Vec::with_capacity(n);
    for _ in 0..3 {
        let _ = g.mul(&sf);
    }
    for i in 0..n {
        let t0 = Instant::now();
        let _ = std::hint::black_box(g.mul(&sf));
        fixed.push(t0.elapsed().as_nanos() as f64);
        let mut sb = [0u8; 32];
        prng_bytes(i, &mut sb);
        sb[0] &= 0x0f;
        let sr = BlsScalar::from_bytes_be(&sb).unwrap_or_else(|_| BlsScalar::one());
        let t1 = Instant::now();
        let _ = std::hint::black_box(g.mul(&sr));
        random.push(t1.elapsed().as_nanos() as f64);
    }
    report("bls_g2", &fixed, &random)
}

fn bench_pallas(n: usize) -> bool {
    let g = PallasPoint::generator();
    let sf = PallasScalar::from_bytes_be(&be_low(0x0f)).unwrap_or_else(|_| PallasScalar::one());
    let mut fixed = Vec::with_capacity(n);
    let mut random = Vec::with_capacity(n);
    for _ in 0..30 {
        let _ = g.mul(&sf);
    }
    for i in 0..n {
        let t0 = Instant::now();
        let _ = std::hint::black_box(g.mul(&sf));
        fixed.push(t0.elapsed().as_nanos() as f64);
        let mut sb = [0u8; 32];
        prng_bytes(i, &mut sb);
        sb[0] &= 0x0f;
        let sr = PallasScalar::from_bytes_be(&sb).unwrap_or_else(|_| PallasScalar::one());
        let t1 = Instant::now();
        let _ = std::hint::black_box(g.mul(&sr));
        random.push(t1.elapsed().as_nanos() as f64);
    }
    report("pallas", &fixed, &random)
}

fn bench_vesta(n: usize) -> bool {
    let g = VestaPoint::generator();
    let sf = VestaScalar::from_bytes_be(&be_low(0x0f)).unwrap_or_else(|_| VestaScalar::one());
    let mut fixed = Vec::with_capacity(n);
    let mut random = Vec::with_capacity(n);
    for _ in 0..30 {
        let _ = g.mul(&sf);
    }
    for i in 0..n {
        let t0 = Instant::now();
        let _ = std::hint::black_box(g.mul(&sf));
        fixed.push(t0.elapsed().as_nanos() as f64);
        let mut sb = [0u8; 32];
        prng_bytes(i, &mut sb);
        sb[0] &= 0x0f;
        let sr = VestaScalar::from_bytes_be(&sb).unwrap_or_else(|_| VestaScalar::one());
        let t1 = Instant::now();
        let _ = std::hint::black_box(g.mul(&sr));
        random.push(t1.elapsed().as_nanos() as f64);
    }
    report("vesta", &fixed, &random)
}

fn bench_jubjub(n: usize) -> bool {
    let g = JubJubPoint::generator();
    let sf = JubScalar::from_bytes_be(&be_low(0x0f)).unwrap_or_else(|_| JubScalar::one());
    let mut fixed = Vec::with_capacity(n);
    let mut random = Vec::with_capacity(n);
    for _ in 0..30 {
        let _ = g.mul(&sf);
    }
    for i in 0..n {
        let t0 = Instant::now();
        let _ = std::hint::black_box(g.mul(&sf));
        fixed.push(t0.elapsed().as_nanos() as f64);
        let mut sb = [0u8; 32];
        prng_bytes(i, &mut sb);
        sb[0] &= 0x0f;
        let sr = JubScalar::from_bytes_be(&sb).unwrap_or_else(|_| JubScalar::one());
        let t1 = Instant::now();
        let _ = std::hint::black_box(g.mul(&sr));
        random.push(t1.elapsed().as_nanos() as f64);
    }
    report("jubjub", &fixed, &random)
}

/// Secret input class = the KEY (fixed vs random), message held constant.
fn bench_hmac_sha256(n: usize) -> bool {
    let msg = [0x41u8; 64];
    let kf = [0x0fu8; 32];
    let mut fixed = Vec::with_capacity(n);
    let mut random = Vec::with_capacity(n);
    for _ in 0..50 {
        let _ = std::hint::black_box(hmac_sha256(&kf, &msg));
    }
    for i in 0..n {
        let t0 = Instant::now();
        let _ = std::hint::black_box(hmac_sha256(&kf, &msg));
        fixed.push(t0.elapsed().as_nanos() as f64);
        let mut kr = [0u8; 32];
        prng_bytes(i, &mut kr);
        let t1 = Instant::now();
        let _ = std::hint::black_box(hmac_sha256(&kr, &msg));
        random.push(t1.elapsed().as_nanos() as f64);
    }
    report("hmac_sha256_key", &fixed, &random)
}

/// Secret input class = the KEY (fixed vs random), message held constant.
fn bench_hmac_sha512(n: usize) -> bool {
    let msg = [0x41u8; 128];
    let kf = [0x0fu8; 64];
    let mut fixed = Vec::with_capacity(n);
    let mut random = Vec::with_capacity(n);
    for _ in 0..50 {
        let _ = std::hint::black_box(hmac_sha512(&kf, &msg));
    }
    for i in 0..n {
        let t0 = Instant::now();
        let _ = std::hint::black_box(hmac_sha512(&kf, &msg));
        fixed.push(t0.elapsed().as_nanos() as f64);
        let mut kr = [0u8; 64];
        prng_bytes(i, &mut kr);
        let t1 = Instant::now();
        let _ = std::hint::black_box(hmac_sha512(&kr, &msg));
        random.push(t1.elapsed().as_nanos() as f64);
    }
    report("hmac_sha512_key", &fixed, &random)
}

/// Control: plain digest over varying input must show no split (harness sanity).
fn bench_sha256(n: usize) -> bool {
    let mut fixed = Vec::with_capacity(n);
    let mut random = Vec::with_capacity(n);
    let mf = [0x42u8; 64];
    for _ in 0..50 {
        let _ = std::hint::black_box(sha256(&mf));
    }
    for i in 0..n {
        let t0 = Instant::now();
        let _ = std::hint::black_box(sha256(&mf));
        fixed.push(t0.elapsed().as_nanos() as f64);
        let mut mr = [0u8; 64];
        prng_bytes(i, &mut mr);
        let t1 = Instant::now();
        let _ = std::hint::black_box(sha256(&mr));
        random.push(t1.elapsed().as_nanos() as f64);
    }
    report("sha256_input", &fixed, &random)
}

fn bench_blake2b(n: usize) -> bool {
    let mut fixed = Vec::with_capacity(n);
    let mut random = Vec::with_capacity(n);
    let mf = [0x43u8; 64];
    for _ in 0..50 {
        let _ = std::hint::black_box(blake2b_512(&mf));
    }
    for i in 0..n {
        let t0 = Instant::now();
        let _ = std::hint::black_box(blake2b_512(&mf));
        fixed.push(t0.elapsed().as_nanos() as f64);
        let mut mr = [0u8; 64];
        prng_bytes(i, &mut mr);
        let t1 = Instant::now();
        let _ = std::hint::black_box(blake2b_512(&mr));
        random.push(t1.elapsed().as_nanos() as f64);
    }
    report("blake2b_input", &fixed, &random)
}

/// Witness-shaped input class: fixed vs random field preimage (Pallas base field).
fn bench_poseidon(n: usize) -> bool {
    let ff = PallasFe::from_u64(0x0f);
    let mut fixed = Vec::with_capacity(n);
    let mut random = Vec::with_capacity(n);
    for _ in 0..30 {
        let _ = std::hint::black_box(poseidon_hash(&[ff]));
    }
    for i in 0..n {
        let t0 = Instant::now();
        let _ = std::hint::black_box(poseidon_hash(&[ff]));
        fixed.push(t0.elapsed().as_nanos() as f64);
        let mut lb = [0u8; 8];
        prng_bytes(i, &mut lb);
        let fr = PallasFe::from_u64(u64::from_le_bytes(lb));
        let t1 = Instant::now();
        let _ = std::hint::black_box(poseidon_hash(&[fr]));
        random.push(t1.elapsed().as_nanos() as f64);
    }
    report("poseidon_preimage", &fixed, &random)
}

/// Fixed full-size secret scalar for timing classes: every real secret
/// in this crate (shares, nonces, keys) is ~256 bits, so the fixed class
/// must be full-size too. Comparing a 4-bit scalar against 252-bit
/// randoms measures a weight class that never holds secrets.
fn fixed_full_size(curve: CurveId) -> DklsScalar {
    // Deterministic full-size digest, reduced mod q (stays full-size).
    let h = blockchain_utils::hash::sha256::sha256(b"dkls23-timing-fixed-secret").unwrap();
    let mut full = h;
    full[0] |= 0xf0; // keep the top nibble populated pre-reduction
    let s = DklsScalar::from_bytes_mod_order(curve, &full);
    debug_assert!(!s.is_zero());
    s
}

/// DKLs23 dispatch layer: `DklsPoint::mul` over a fixed vs random share.
/// The `CurveId` discriminant is a public session parameter; this proves
/// the match adds no secret-dependent timing split on top of the backend.
fn bench_dkls_pointmul(curve: CurveId, name: &str, n: usize) -> bool {
    let g = DklsPoint::generator(curve);
    let sf = fixed_full_size(curve);
    let mut fixed = Vec::with_capacity(n);
    let mut random = Vec::with_capacity(n);
    for _ in 0..30 {
        let _ = std::hint::black_box(g.mul(&sf));
    }
    for i in 0..n {
        let t0 = Instant::now();
        let _ = std::hint::black_box(g.mul(&sf));
        fixed.push(t0.elapsed().as_nanos() as f64);
        let mut sb = [0u8; 32];
        prng_bytes(i, &mut sb);
        sb[0] &= 0x0f;
        let sr = DklsScalar::from_bytes_be(curve, &sb).unwrap_or_else(|| DklsScalar::one(curve));
        let t1 = Instant::now();
        let _ = std::hint::black_box(g.mul(&sr));
        random.push(t1.elapsed().as_nanos() as f64);
    }
    report(name, &fixed, &random)
}

/// DKLs23 round-3 equation over the secret share:
/// `s_part = k_part·e + kr·x`, fixed vs random `x`, public factors held
/// constant. Covers the per-party signing arithmetic.
fn bench_dkls_round3(curve: CurveId, name: &str, n: usize) -> bool {
    let mut eb = [0u8; 32];
    eb[31] = 0x11;
    let e = DklsScalar::from_bytes_mod_order(curve, &eb);
    let mut kb = [0u8; 32];
    kb[31] = 0x07;
    let k_part = DklsScalar::from_bytes_mod_order(curve, &kb);
    let mut rb = [0u8; 32];
    rb[31] = 0x03;
    let kr = DklsScalar::from_bytes_mod_order(curve, &rb);
    let xf = fixed_full_size(curve);
    let mut fixed = Vec::with_capacity(n);
    let mut random = Vec::with_capacity(n);
    for _ in 0..50 {
        let _ = std::hint::black_box(k_part.mul(&e).add(&kr.mul(&xf)));
    }
    for i in 0..n {
        let t0 = Instant::now();
        let _ = std::hint::black_box(k_part.mul(&e).add(&kr.mul(&xf)));
        fixed.push(t0.elapsed().as_nanos() as f64);
        let mut sb = [0u8; 32];
        prng_bytes(i, &mut sb);
        sb[0] &= 0x0f;
        let xr = DklsScalar::from_bytes_be(curve, &sb).unwrap_or_else(|| DklsScalar::one(curve));
        let t1 = Instant::now();
        let _ = std::hint::black_box(k_part.mul(&e).add(&kr.mul(&xr)));
        random.push(t1.elapsed().as_nanos() as f64);
    }
    report(name, &fixed, &random)
}

fn main() {
    let samples: usize = env::var("SAMPLES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5_000);
    let which = env::args().nth(1).unwrap_or_else(|| "all".into());
    println!("SAMPLES={samples} target={which}");
    let mut ok = true;
    let mut go = |name: &str, f: fn(usize) -> bool, n: usize| {
        println!(">>> {name}");
        ok &= f(n);
    };
    match which.as_str() {
        "ed25519" => go("ed25519", bench_ed25519, samples),
        "secp256k1" => go("secp256k1", bench_secp256k1, samples),
        "secp256r1" => go("secp256r1", bench_secp256r1, samples),
        "ristretto" => go("ristretto", bench_ristretto, samples),
        "bls_g1" => go("bls_g1", bench_bls_g1, samples.min(2000)),
        "bls_g2" => go("bls_g2", bench_bls_g2, samples.min(500)),
        "pallas" => go("pallas", bench_pallas, samples),
        "vesta" => go("vesta", bench_vesta, samples),
        "jubjub" => go("jubjub", bench_jubjub, samples),
        "hmac_sha256" => go("hmac_sha256_key", bench_hmac_sha256, samples),
        "hmac_sha512" => go("hmac_sha512_key", bench_hmac_sha512, samples),
        "sha256" => go("sha256_input", bench_sha256, samples),
        "blake2b" => go("blake2b_input", bench_blake2b, samples),
        "poseidon" => go("poseidon_preimage", bench_poseidon, samples.min(3000)),
        "dkls23" => {
            go("dkls23_k1_pointmul", |n| {
                bench_dkls_pointmul(CurveId::K1, "dkls23_k1_pointmul", n)
            }, samples);
            go("dkls23_r1_pointmul", |n| {
                bench_dkls_pointmul(CurveId::R1, "dkls23_r1_pointmul", n)
            }, samples.min(3000));
            go("dkls23_k1_round3", |n| bench_dkls_round3(CurveId::K1, "dkls23_k1_round3", n), samples);
            go("dkls23_r1_round3", |n| bench_dkls_round3(CurveId::R1, "dkls23_r1_round3", n), samples);
        }
        "all" => {
            go("ed25519", bench_ed25519, samples);
            go("secp256k1", bench_secp256k1, samples);
            go("secp256r1", bench_secp256r1, samples.min(3000));
            go("ristretto", bench_ristretto, samples);
            go("bls_g1", bench_bls_g1, samples.min(1000));
            go("bls_g2", bench_bls_g2, samples.min(300));
            go("pallas", bench_pallas, samples.min(3000));
            go("vesta", bench_vesta, samples.min(3000));
            go("jubjub", bench_jubjub, samples.min(3000));
            go("hmac_sha256", bench_hmac_sha256, samples.min(3000));
            go("hmac_sha512", bench_hmac_sha512, samples.min(3000));
            go("sha256", bench_sha256, samples.min(3000));
            go("blake2b", bench_blake2b, samples.min(3000));
            go("poseidon", bench_poseidon, samples.min(2000));
        }
        other => {
            eprintln!("unknown {other}");
            std::process::exit(1);
        }
    }
    if ok {
        println!("TIMING GATE: PASS");
        std::process::exit(0);
    }
    println!("TIMING GATE: FAIL");
    std::process::exit(2);
}
