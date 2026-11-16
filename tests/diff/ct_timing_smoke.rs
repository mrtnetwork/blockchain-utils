//! P0 timing smoke (item 6 of secp256k1 go-live checklist).
//!
//! Not a full dudect statistical test — runs fixed-work loops over Fe::add/mul
//! and mul_ct with two classes of inputs and checks that wall-time ratio stays
//! within a loose band. Catches gross early-exit regressions under debug builds.
//!
//! Run: `cargo test --test diff ct_timing_smoke -- --nocapture`

#![cfg(feature = "alloc")]

use blockchain_utils::curve::secp256k1::{Fe, Scalar, Secp256k1Point};
use blockchain_utils::curve::traits::CurvePoint;
use core::time::Duration;
use std::time::Instant;

fn time_iters<F: FnMut()>(iters: u32, mut f: F) -> Duration {
    let t0 = Instant::now();
    for _ in 0..iters {
        f();
    }
    t0.elapsed()
}

#[test]
fn fe_add_mul_timing_smoke() {
    // Class A: small values; Class B: near p
    let mut near_p = [0xffu8; 32];
    near_p[31] = 0x2e; // still < p
    let a = Fe::from_bytes_be(&[0u8; 32].map(|_| 3)).unwrap_or(Fe::one());
    let mut b_bytes = [0u8; 32];
    b_bytes[31] = 7;
    let b = Fe::from_bytes_be(&b_bytes).unwrap();
    let near = Fe::from_bytes_be(&near_p).unwrap_or(Fe::one());

    const ITERS: u32 = 50_000;
    let t_small = time_iters(ITERS, || {
        let _ = core::hint::black_box(a.add(&b).mul(&b));
    });
    let t_near = time_iters(ITERS, || {
        let _ = core::hint::black_box(near.add(&near).mul(&near));
    });

    let ratio = t_near.as_secs_f64() / t_small.as_secs_f64().max(1e-12);
    eprintln!("Fe add/mul smoke: small={t_small:?} near={t_near:?} ratio={ratio:.3}");
    // Loose band — only flags multi-x timing differences (early-exit style bugs).
    assert!(
        ratio > 0.25 && ratio < 4.0,
        "suspicious timing ratio {ratio} (expected ~1.0)"
    );
}

#[test]
fn mul_ct_timing_smoke() {
    let g = Secp256k1Point::generator();
    let mut s_lo = [0u8; 32];
    s_lo[31] = 3;
    let mut s_hi = [0xffu8; 32];
    s_hi[0] = 0x7f; // high but < n
    let k_lo = Scalar::from_bytes_be(&s_lo).unwrap();
    let k_hi = Scalar::from_bytes_be(&s_hi).unwrap_or(Scalar::one());

    const ITERS: u32 = 200;
    let t_lo = time_iters(ITERS, || {
        let _ = core::hint::black_box(g.mul(&k_lo));
    });
    let t_hi = time_iters(ITERS, || {
        let _ = core::hint::black_box(g.mul(&k_hi));
    });
    let ratio = t_hi.as_secs_f64() / t_lo.as_secs_f64().max(1e-12);
    eprintln!("mul_ct smoke: lo={t_lo:?} hi={t_hi:?} ratio={ratio:.3}");
    assert!(
        ratio > 0.25 && ratio < 4.0,
        "suspicious mul_ct timing ratio {ratio}"
    );
}

#[test]
fn secp256r1_fe_add_mul_timing_smoke() {
    use blockchain_utils::curve::secp256r1::Fe;
    let a = Fe::one();
    let b = Fe::one().add(&Fe::one());
    let _near = Fe::from_bytes_be(&[0xff; 32]).unwrap_or(Fe::one()); // may err if >=p
                                                                     // use small and mid values
    let mut mid = [0u8; 32];
    mid[0] = 0x7f;
    let near = Fe::from_bytes_be(&mid).unwrap_or(Fe::one());

    const ITERS: u32 = 50_000;
    let t_small = time_iters(ITERS, || {
        let _ = core::hint::black_box(a.add(&b).mul(&b));
    });
    let t_near = time_iters(ITERS, || {
        let _ = core::hint::black_box(near.add(&near).mul(&near));
    });
    let ratio = t_near.as_secs_f64() / t_small.as_secs_f64().max(1e-12);
    eprintln!("P-256 Fe add/mul smoke: small={t_small:?} near={t_near:?} ratio={ratio:.3}");
    assert!(ratio > 0.25 && ratio < 4.0, "suspicious ratio {ratio}");
}

#[test]
fn secp256r1_mul_ct_timing_smoke() {
    use blockchain_utils::curve::secp256r1::{Scalar, Secp256r1Point};
    use blockchain_utils::curve::traits::CurvePoint;
    let g = Secp256r1Point::generator();
    let mut s_lo = [0u8; 32];
    s_lo[31] = 3;
    let mut s_hi = [0u8; 32];
    s_hi[0] = 0x7f;
    let k_lo = Scalar::from_bytes_be(&s_lo).unwrap();
    let k_hi = Scalar::from_bytes_be(&s_hi).unwrap_or(Scalar::one());
    const ITERS: u32 = 200;
    let t_lo = time_iters(ITERS, || {
        let _ = core::hint::black_box(g.mul(&k_lo));
    });
    let t_hi = time_iters(ITERS, || {
        let _ = core::hint::black_box(g.mul(&k_hi));
    });
    let ratio = t_hi.as_secs_f64() / t_lo.as_secs_f64().max(1e-12);
    eprintln!("P-256 mul_ct smoke: lo={t_lo:?} hi={t_hi:?} ratio={ratio:.3}");
    assert!(ratio > 0.25 && ratio < 4.0, "suspicious ratio {ratio}");
}

#[test]
fn ed25519_scalar_add_mul_timing_smoke() {
    use blockchain_utils::curve::ed25519::Scalar;
    let a = Scalar::one();
    let mut b_bytes = [0u8; 32];
    b_bytes[0] = 3;
    let b = Scalar::from_bytes_mod_order(&b_bytes);
    let mut hi = [0u8; 32];
    hi[31] = 0x0f;
    let h = Scalar::from_bytes_mod_order(&hi);
    const ITERS: u32 = 5_000;
    let t_lo = time_iters(ITERS, || {
        let _ = core::hint::black_box(a.add(&b).mul(&b));
    });
    let t_hi = time_iters(ITERS, || {
        let _ = core::hint::black_box(h.add(&h).mul(&h));
    });
    let ratio = t_hi.as_secs_f64() / t_lo.as_secs_f64().max(1e-12);
    eprintln!("Ed25519 Scalar add/mul smoke: lo={t_lo:?} hi={t_hi:?} ratio={ratio:.3}");
    assert!(ratio > 0.25 && ratio < 4.0, "suspicious ratio {ratio}");
}
