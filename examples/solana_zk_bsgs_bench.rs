//! Release benchmark: BSGS baby-step table generation cost + Twisted ElGamal
//! encrypt/decrypt times (public API only, zero new dependencies).
//!
//! Run: `cargo run --release --example solana_zk_bsgs_bench`
//!
//! Times three things:
//!   1. building the 2^16 baby-step table at runtime (sequential adds +
//!      one compression per step — the cost a lazy table would pay once),
//!   2. `elgamal_encrypt_with` per-amount average,
//!   3. `elgamal_decrypt_u32` for a small amount (best case: giant `i = 0`)
//!      and for `0xFFFF_FFFF` (worst case: all 65536 giant steps).

use blockchain_utils::curve::traits::CurvePoint;
use blockchain_utils::curve::RistrettoPoint;
use blockchain_utils::solana_zk;
use std::time::Instant;

const TABLE: usize = 1 << 16;

fn main() {
    // 1. Runtime table generation (what a lazy table would build once). -----
    let g = RistrettoPoint::generator();
    let mut g_enc = [0u8; 32];
    g.to_bytes_compressed(&mut g_enc).expect("compress generator");
    // Warm up allocators/caches with a throwaway pass over fewer steps.
    {
        let mut cur = RistrettoPoint::identity();
        for _ in 0..1024 {
            cur = cur.add(&g);
        }
        let mut enc = [0u8; 32];
        cur.to_bytes_compressed(&mut enc).expect("compress");
        std::hint::black_box(enc);
    }
    let t0 = Instant::now();
    let mut table = Vec::with_capacity(TABLE);
    let mut cur = RistrettoPoint::identity();
    for _ in 0..TABLE {
        let mut enc = [0u8; 32];
        cur.to_bytes_compressed(&mut enc).expect("compress baby step");
        table.push(enc);
        cur = cur.add(&g);
    }
    let gen_time = t0.elapsed();
    assert_eq!(table.len(), TABLE);
    assert_eq!(table[1], g_enc, "baby step 1 must be the generator");
    println!("table gen 2^16 baby steps (adds + compress each): {gen_time:?}");

    // 2. Encrypt. -------------------------------------------------------------
    let secret = [7u8; 32];
    let pubkey = solana_zk::elgamal_pubkey_from_secret(&secret).expect("pubkey");
    let opening = [9u8; 32];
    let ct = solana_zk::elgamal_encrypt_with(&pubkey, 50_000, &opening).expect("encrypt");
    let n_enc = 200u32;
    let t0 = Instant::now();
    for _ in 0..n_enc {
        std::hint::black_box(
            solana_zk::elgamal_encrypt_with(&pubkey, 50_000, &opening).expect("encrypt"),
        );
    }
    println!("encrypt_with avg over {n_enc}: {:?}", t0.elapsed() / n_enc);

    // 3a. Decrypt a small amount (giant step i = 0, best case). ---------------
    let m = solana_zk::elgamal_decrypt_u32(&secret, &ct).expect("decrypt small");
    assert_eq!(m, 50_000);
    let n_dec = 50u32;
    let t0 = Instant::now();
    for _ in 0..n_dec {
        let m = solana_zk::elgamal_decrypt_u32(&secret, &ct).expect("decrypt small");
        std::hint::black_box(m);
    }
    println!("decrypt_u32 small (50000) avg over {n_dec}: {:?}", t0.elapsed() / n_dec);

    // 3b. Decrypt the max u32 (worst case: all 65536 giant steps). ------------
    let ct_max =
        solana_zk::elgamal_encrypt_with(&pubkey, 0xFFFF_FFFF, &opening).expect("encrypt max");
    let t0 = Instant::now();
    let m_max = solana_zk::elgamal_decrypt_u32(&secret, &ct_max).expect("decrypt max");
    let worst = t0.elapsed();
    assert_eq!(m_max, 0xFFFF_FFFF);
    println!("decrypt_u32 max (4294967295, 65536 giant steps): {worst:?}");
}
