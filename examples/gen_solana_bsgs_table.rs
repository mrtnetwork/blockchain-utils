//! Generator for `src/solana_zk/bsgs_table.rs` (`@generated` constants).
//!
//! Baby steps `encode(j*G)` for `j` in 0..65536 (2^16), sorted by encoding
//! for binary search (zero-dep discrete log, no runtime table build).
//! Giants cover 2^16 steps, so decode spans the full 0..2^32 range.
//! Values fit `u16` (`j <= 65535`), halving the parallel array.
//! Used only when `std` is off; `std` builds decode against a lazily built
//! affine runtime table instead (same 2^16 split, no static bytes).
//!
//! Run: `cargo run --profile fast --example gen_solana_bsgs_table`
//! and redirect stdout to `src/solana_zk/bsgs_table.rs`.

use blockchain_utils::curve::traits::CurvePoint;
use blockchain_utils::curve::RistrettoPoint;

fn main() {
    const TABLE: usize = 1 << 16;
    let g = RistrettoPoint::generator();
    let mut pairs: Vec<([u8; 32], u16)> = Vec::with_capacity(TABLE);
    let mut cur = RistrettoPoint::identity();
    for j in 0..TABLE {
        let mut enc = [0u8; 32];
        cur.to_bytes_compressed(&mut enc).expect("encode");
        pairs.push((enc, j as u16));
        cur = cur.add(&g);
    }
    pairs.sort_by_key(|a| a.0);
    println!("// @generated — BSGS baby steps encode(j*G), j in 0..65536,");
    println!("// sorted by encoding for binary search. Do not edit.");
    println!("/// Sorted baby-step encodings (`encode(j*G)`).");
    println!("pub static BSGS_BABY_ENC: [[u8; 32]; 65536] = [");
    for (enc, _) in &pairs {
        print!("    [");
        for (i, b) in enc.iter().enumerate() {
            if i > 0 {
                print!(", ");
            }
            print!("{b}");
        }
        println!("],");
    }
    println!("];");
    println!("/// Baby-step values parallel to [`BSGS_BABY_ENC`].");
    println!("pub static BSGS_BABY_VAL: [u16; 65536] = [");
    for (_, j) in &pairs {
        println!("    {j},");
    }
    println!("];");
}
