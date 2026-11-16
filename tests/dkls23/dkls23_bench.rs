//! 2-of-3 threshold keygen + sign bench for DKLs23.
//!
//! Run optimized (timings are meaningless in debug):
//! ```sh
//! cargo test --release --test dkls23 dkls23_bench -- --nocapture --test-threads=1
//! ```
//!
//! Every case asserts functional correctness first (DKG public-key
//! agreement, signature verifies under the group key), then reports
//! wall-clock timing with one warmup iteration.

use blockchain_utils::dkls23::curve_id::CurveId;
use blockchain_utils::dkls23::session::{dkg_oneshot, sign_oneshot};
use blockchain_utils::hash::sha256::sha256;
use std::time::Instant;

fn seeds<const N: usize>(base: u8) -> [[u8; 32]; N] {
    let mut out = [[0u8; 32]; N];
    for (i, s) in out.iter_mut().enumerate() {
        for b in s.iter_mut() {
            *b = base.wrapping_add(i as u8);
        }
    }
    out
}

fn timely(name: &str, iters: u64, mut f: impl FnMut()) {
    // Warmup once (allocator, first-touch pages).
    f();
    let t0 = Instant::now();
    for _ in 0..iters {
        f();
    }
    let dt = t0.elapsed();
    let per = dt.as_nanos() as f64 / iters.max(1) as f64;
    println!("[bench] {name:<34} total={dt:>10?}  per-op={per:>14.1}ns/op  iters={iters}");
}

fn bench_curve(curve: CurveId, tag: &str, iters: u64) {
    let name = match curve {
        CurveId::K1 => "k1",
        CurveId::R1 => "r1",
    };
    let sid = format!("bench-2of3-{name}");
    let sid = sid.as_bytes();

    // --- correctness first -------------------------------------------------
    let dkg_seeds = seeds::<3>(0xA0);
    let shares = dkg_oneshot(curve, sid, 3, 2, &dkg_seeds).expect("dkg");
    assert_eq!(shares[0].pk, shares[1].pk);
    assert_eq!(shares[1].pk, shares[2].pk);
    let h = sha256(b"bench 2-of-3 message").unwrap();
    let sign_seeds = seeds::<3>(0xB0);
    let subset = [shares[0].clone(), shares[2].clone()];
    let sub_seeds = [sign_seeds[0], sign_seeds[2]];
    let sig = sign_oneshot(&subset, sid, &h, &sub_seeds).expect("sign");
    match curve {
        CurveId::K1 => {
            let pk = blockchain_utils::signature::ecdsa::PublicKey::from_bytes(&shares[0].pk)
                .unwrap();
            let s = blockchain_utils::signature::ecdsa::Signature::from_compact(&sig.to_bytes())
                .unwrap();
            blockchain_utils::signature::ecdsa::verify(&pk, &h, &s).unwrap();
        }
        CurveId::R1 => {
            let pk =
                blockchain_utils::signature::ecdsa_p256::PublicKey::from_bytes(&shares[0].pk)
                    .unwrap();
            let s = blockchain_utils::signature::ecdsa_p256::Signature::from_compact(
                &sig.to_bytes(),
            )
            .unwrap();
            blockchain_utils::signature::ecdsa_p256::verify(&pk, &h, &s).unwrap();
        }
    }

    // --- timed --------------------------------------------------------------
    timely(&format!("dkls23-2of3-dkg-{name}{tag}"), iters, || {
        let _ = dkg_oneshot(curve, sid, 3, 2, &dkg_seeds).expect("dkg");
    });
    timely(&format!("dkls23-2of3-sign-{name}{tag}"), iters, || {
        let _ = sign_oneshot(&subset, sid, &h, &sub_seeds).expect("sign");
    });
}

#[test]
fn bench_2of3_k1() {
    bench_curve(CurveId::K1, "", 10);
}

#[test]
fn bench_2of3_r1() {
    bench_curve(CurveId::R1, "", 10);
}
