//! BLAKE2s R1CS gadget (Sapling personalizations `Zcashivk` / `Zcash_nf`).

use crate::zk::sapling::boolean::Boolean;
use crate::zk::sapling::cs::{Cs, MultiEq};
use crate::zk::sapling::uint32::UInt32;
use alloc::vec::Vec;

const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

fn mixing_g(
    meq: &mut MultiEq<'_>,
    v: &mut [UInt32; 16],
    idx: (usize, usize, usize, usize),
    x: &UInt32,
    y: &UInt32,
) {
    let (a, b, c, d) = idx;
    let va = v[a].clone();
    let vb = v[b].clone();
    v[a] = UInt32::add_many_eq(meq, &[&va, &vb, x]);
    let vd = v[d].clone();
    let va = v[a].clone();
    v[d] = UInt32::xor(meq.cs(), &vd, &va).rotr(16);
    let vc = v[c].clone();
    let vd = v[d].clone();
    v[c] = UInt32::add_many_eq(meq, &[&vc, &vd]);
    let vb = v[b].clone();
    let vc = v[c].clone();
    v[b] = UInt32::xor(meq.cs(), &vb, &vc).rotr(12);
    let va = v[a].clone();
    let vb = v[b].clone();
    v[a] = UInt32::add_many_eq(meq, &[&va, &vb, y]);
    let vd = v[d].clone();
    let va = v[a].clone();
    v[d] = UInt32::xor(meq.cs(), &vd, &va).rotr(8);
    let vc = v[c].clone();
    let vd = v[d].clone();
    v[c] = UInt32::add_many_eq(meq, &[&vc, &vd]);
    let vb = v[b].clone();
    let vc = v[c].clone();
    v[b] = UInt32::xor(meq.cs(), &vb, &vc).rotr(7);
}

fn compression(cs: &mut Cs, h: &mut [UInt32; 8], m: &[UInt32; 16], t: u64, f: bool) {
    let mut v: [UInt32; 16] = [
        h[0].clone(),
        h[1].clone(),
        h[2].clone(),
        h[3].clone(),
        h[4].clone(),
        h[5].clone(),
        h[6].clone(),
        h[7].clone(),
        UInt32::constant(cs, 0x6A09_E667),
        UInt32::constant(cs, 0xBB67_AE85),
        UInt32::constant(cs, 0x3C6E_F372),
        UInt32::constant(cs, 0xA54F_F53A),
        UInt32::constant(cs, 0x510E_527F),
        UInt32::constant(cs, 0x9B05_688C),
        UInt32::constant(cs, 0x1F83_D9AB),
        UInt32::constant(cs, 0x5BE0_CD19),
    ];
    let t_low = UInt32::constant(cs, t as u32);
    let t_high = UInt32::constant(cs, (t >> 32) as u32);
    let v12 = v[12].clone();
    v[12] = UInt32::xor(cs, &v12, &t_low);
    let v13 = v[13].clone();
    v[13] = UInt32::xor(cs, &v13, &t_high);
    if f {
        let all_ones = UInt32::constant(cs, 0xFFFF_FFFF);
        let v14 = v[14].clone();
        v[14] = UInt32::xor(cs, &v14, &all_ones);
    }
    {
        let mut meq = MultiEq::new(cs);
        for s in &SIGMA {
            mixing_g(&mut meq, &mut v, (0, 4, 8, 12), &m[s[0]], &m[s[1]]);
            mixing_g(&mut meq, &mut v, (1, 5, 9, 13), &m[s[2]], &m[s[3]]);
            mixing_g(&mut meq, &mut v, (2, 6, 10, 14), &m[s[4]], &m[s[5]]);
            mixing_g(&mut meq, &mut v, (3, 7, 11, 15), &m[s[6]], &m[s[7]]);
            mixing_g(&mut meq, &mut v, (0, 5, 10, 15), &m[s[8]], &m[s[9]]);
            mixing_g(&mut meq, &mut v, (1, 6, 11, 12), &m[s[10]], &m[s[11]]);
            mixing_g(&mut meq, &mut v, (2, 7, 8, 13), &m[s[12]], &m[s[13]]);
            mixing_g(&mut meq, &mut v, (3, 4, 9, 14), &m[s[14]], &m[s[15]]);
        }
    } // MultiEq drop flushes packed equalities
    for i in 0..8 {
        let hi = h[i].clone();
        let t1 = UInt32::xor(cs, &hi, &v[i]);
        h[i] = UInt32::xor(cs, &t1, &v[i + 8]);
    }
}

fn read_u32_le(personal: &[u8; 8], off: usize) -> u32 {
    u32::from_le_bytes([
        personal[off],
        personal[off + 1],
        personal[off + 2],
        personal[off + 3],
    ])
}

/// BLAKE2s-256 in-circuit. `input` length must be a multiple of 8 (bit length).
/// `personalization` is 8 bytes (e.g. `b"Zcashivk"` / `b"Zcash_nf"`).
/// Returns 256 output bits (LE within each word, words sequential).
pub fn blake2s_cs(cs: &mut Cs, input: &[Boolean], personalization: &[u8; 8]) -> Vec<Boolean> {
    assert_eq!(
        input.len() % 8,
        0,
        "blake2s input bit length must be multiple of 8"
    );
    let mut h = [
        UInt32::constant(cs, 0x6A09_E667 ^ 0x0101_0000 ^ 32),
        UInt32::constant(cs, 0xBB67_AE85),
        UInt32::constant(cs, 0x3C6E_F372),
        UInt32::constant(cs, 0xA54F_F53A),
        UInt32::constant(cs, 0x510E_527F),
        UInt32::constant(cs, 0x9B05_688C),
        UInt32::constant(cs, 0x1F83_D9AB ^ read_u32_le(personalization, 0)),
        UInt32::constant(cs, 0x5BE0_CD19 ^ read_u32_le(personalization, 4)),
    ];

    let mut blocks: Vec<[UInt32; 16]> = Vec::new();
    let mut i = 0;
    while i < input.len() {
        let end = core::cmp::min(i + 512, input.len());
        let block_bits = &input[i..end];
        let mut words = Vec::with_capacity(16);
        let mut j = 0;
        while j < block_bits.len() {
            let wend = core::cmp::min(j + 32, block_bits.len());
            words.push(UInt32::from_bits_pad(cs, &block_bits[j..wend]));
            j += 32;
        }
        while words.len() < 16 {
            words.push(UInt32::constant(cs, 0));
        }
        let mut arr = [
            words[0].clone(),
            words[1].clone(),
            words[2].clone(),
            words[3].clone(),
            words[4].clone(),
            words[5].clone(),
            words[6].clone(),
            words[7].clone(),
            words[8].clone(),
            words[9].clone(),
            words[10].clone(),
            words[11].clone(),
            words[12].clone(),
            words[13].clone(),
            words[14].clone(),
            words[15].clone(),
        ];
        // silence
        let _ = &mut arr;
        blocks.push([
            words[0].clone(),
            words[1].clone(),
            words[2].clone(),
            words[3].clone(),
            words[4].clone(),
            words[5].clone(),
            words[6].clone(),
            words[7].clone(),
            words[8].clone(),
            words[9].clone(),
            words[10].clone(),
            words[11].clone(),
            words[12].clone(),
            words[13].clone(),
            words[14].clone(),
            words[15].clone(),
        ]);
        i = end;
    }
    if blocks.is_empty() {
        blocks.push([
            UInt32::constant(cs, 0),
            UInt32::constant(cs, 0),
            UInt32::constant(cs, 0),
            UInt32::constant(cs, 0),
            UInt32::constant(cs, 0),
            UInt32::constant(cs, 0),
            UInt32::constant(cs, 0),
            UInt32::constant(cs, 0),
            UInt32::constant(cs, 0),
            UInt32::constant(cs, 0),
            UInt32::constant(cs, 0),
            UInt32::constant(cs, 0),
            UInt32::constant(cs, 0),
            UInt32::constant(cs, 0),
            UInt32::constant(cs, 0),
            UInt32::constant(cs, 0),
        ]);
    }

    let n = blocks.len();
    for (bi, block) in blocks.iter().enumerate().take(n.saturating_sub(1)) {
        compression(cs, &mut h, block, ((bi + 1) * 64) as u64, false);
    }
    let t_final = (input.len() / 8) as u64;
    compression(cs, &mut h, &blocks[n - 1], t_final, true);

    let mut out = Vec::with_capacity(256);
    for word in &h {
        out.extend(word.into_bits());
    }
    out
}

pub fn blake2s_zcash_ivk(cs: &mut Cs, input_512_bits: &[Boolean]) -> Vec<Boolean> {
    assert_eq!(input_512_bits.len(), 512);
    blake2s_cs(cs, input_512_bits, b"Zcashivk")
}

pub fn blake2s_zcash_nf(cs: &mut Cs, input_512_bits: &[Boolean]) -> Vec<Boolean> {
    assert_eq!(input_512_bits.len(), 512);
    blake2s_cs(cs, input_512_bits, b"Zcash_nf")
}

#[cfg(test)]
mod tests {
    #[cfg(all(feature = "std", feature = "groth16-prover"))]
    #[test]
    fn export_blake_dens() {
        use crate::zk::groth16::{a_density, b_density};
        use crate::zk::sapling::boolean::Boolean;
        use crate::zk::sapling::cs::Cs;
        let mut cs = Cs::new();
        let mut bits = Vec::new();
        for i in 0..512 {
            bits.push(Boolean::alloc(&mut cs, (i % 3) == 0));
        }
        let _ = super::blake2s_zcash_ivk(&mut cs, &bits);
        let (r1cs, _) = cs.into_r1cs();
        let da = a_density(&r1cs);
        let db = b_density(&r1cs);
        assert!(!da.is_empty(), "blake dens_a must be non-empty");
        assert!(!db.is_empty(), "blake dens_b must be non-empty");
        println!(
            "blake dens_a={} dens_b={} ncons={}",
            da.len(),
            db.len(),
            r1cs.constraints.len()
        );
    }

    #[cfg(all(feature = "std", feature = "groth16-prover"))]
    #[test]

    fn blake_b_side_stats() {
        use crate::zk::sapling::boolean::Boolean;
        use crate::zk::sapling::cs::Cs;
        let mut cs = Cs::new();
        let mut bits = Vec::new();
        for i in 0..512 {
            bits.push(Boolean::alloc(&mut cs, (i % 3) == 0));
        }
        let pre = cs.constraints.len();
        let _ = super::blake2s_zcash_ivk(&mut cs, &bits);
        let mut multi_b = 0usize;
        let mut max_b = 0usize;
        let mut empty_b = 0usize;
        for (_, b, _) in &cs.constraints[pre..] {
            let n = b.terms.len();
            if n == 0 {
                empty_b += 1;
            }
            if n > 1 {
                multi_b += 1;
            }
            max_b = max_b.max(n);
        }
        println!(
            "blake body constraints: multi_term_B={} empty_B={} max_B_terms={}",
            multi_b, empty_b, max_b
        );
    }

    #[cfg(all(feature = "std", feature = "groth16-prover"))]
    #[test]
    fn blake_enforce_time_dens() {
        use crate::zk::sapling::boolean::Boolean;
        use crate::zk::sapling::cs::Cs;
        let mut cs = Cs::new();
        let mut bits = Vec::new();
        for i in 0..512 {
            bits.push(Boolean::alloc(&mut cs, (i % 3) == 0));
        }
        let _ = super::blake2s_zcash_ivk(&mut cs, &bits);
        let _dens_a = 1 + cs.dens_a_aux.iter().filter(|&&x| x).count(); // +ONE always dens A for inputs dummy
        let dens_b_aux = cs.dens_b_aux.iter().filter(|&&x| x).count();
        // B dens also includes ONE if MultiEq/booleanity put it — count from constraints for ONE
        let dens_b = dens_b_aux + 1; // approximate ONE
        println!(
            "enforce-time dens_a_aux={} dens_b_aux={} dens_b≈{} naux={} ncons={}",
            cs.dens_a_aux.iter().filter(|&&x| x).count(),
            dens_b_aux,
            dens_b,
            cs.aux.len(),
            cs.constraints.len()
        );
    }

    #[cfg(all(feature = "std", feature = "groth16-prover"))]
    #[test]

    fn blake_dens_by_class() {
        use crate::curve::bls::Scalar;
        use crate::curve::traits::Scalar as ScalarTrait;
        use crate::zk::sapling::boolean::Boolean;
        use crate::zk::sapling::cs::{Cs, Var};
        let mut cs = Cs::new();
        let mut bits = Vec::new();
        for i in 0..512 {
            bits.push(Boolean::alloc(&mut cs, (i % 3) == 0));
        }
        let pre = cs.constraints.len();
        let pre_aux = cs.aux.len();
        let _ = super::blake2s_zcash_ivk(&mut cs, &bits);
        let _n_in = 1 + cs.num_public();
        // Classify each body constraint
        let mut dens_b_bool = std::collections::BTreeSet::new();
        let mut dens_b_xor = std::collections::BTreeSet::new();
        let mut dens_b_meq = std::collections::BTreeSet::new();
        let mut dens_b_other = std::collections::BTreeSet::new();
        let mut n_bool = 0usize;
        let mut n_xor = 0usize;
        let mut n_meq = 0usize;
        let mut n_other = 0usize;
        for (a, b, c) in &cs.constraints[pre..] {
            let b_vars: Vec<_> = b
                .terms
                .iter()
                .filter(|(_, c)| ScalarTrait::ct_eq(c, &Scalar::zero()) == 0)
                .map(|(v, _)| *v)
                .collect();
            let a_vars: Vec<_> = a
                .terms
                .iter()
                .filter(|(_, c)| ScalarTrait::ct_eq(c, &Scalar::zero()) == 0)
                .map(|(v, _)| *v)
                .collect();
            // booleanity: A has ONE + aux, B has same aux, C empty
            let is_bool = b_vars.len() == 1
                && matches!(b_vars[0], Var::Aux(_))
                && a_vars.iter().any(|v| matches!(v, Var::Input(0)))
                && c.terms.is_empty();
            // MultiEq: B = ONE only
            let is_meq = b_vars.len() == 1 && matches!(b_vars[0], Var::Input(0));
            // XOR: A has one aux twice (2a), B has one aux
            let is_xor = b_vars.len() == 1
                && matches!(b_vars[0], Var::Aux(_))
                && a_vars.len() == 1
                && matches!(a_vars[0], Var::Aux(_))
                && !c.terms.is_empty();
            let target = if is_bool {
                n_bool += 1;
                &mut dens_b_bool
            } else if is_meq {
                n_meq += 1;
                &mut dens_b_meq
            } else if is_xor {
                n_xor += 1;
                &mut dens_b_xor
            } else {
                n_other += 1;
                &mut dens_b_other
            };
            for v in &b_vars {
                if let Var::Aux(i) = v {
                    target.insert(*i);
                }
            }
        }
        println!(
            "class cons: bool={} xor={} meq={} other={}",
            n_bool, n_xor, n_meq, n_other
        );
        println!(
            "class dens_b unique aux: bool={} xor={} meq={} other={}",
            dens_b_bool.len(),
            dens_b_xor.len(),
            dens_b_meq.len(),
            dens_b_other.len()
        );
        // XOR dens_b that are NOT in booleanity dens_b (XOR results as second ops)
        let xor_only: Vec<_> = dens_b_xor.difference(&dens_b_bool).copied().collect();
        println!(
            "xor dens_b NOT in bool dens_b: {} (first {:?})",
            xor_only.len(),
            &xor_only[..xor_only.len().min(10)]
        );
        let body_aux = cs.aux.len() - pre_aux;
        println!(
            "body aux={} ncons body={}",
            body_aux,
            cs.constraints.len() - pre
        );
    }

    #[cfg(all(feature = "std", feature = "groth16-prover"))]
    #[test]
    fn blake_xor_new_b() {
        use crate::curve::bls::Scalar;
        use crate::curve::traits::Scalar as ScalarTrait;
        use crate::zk::sapling::boolean::Boolean;
        use crate::zk::sapling::cs::{Cs, Var};
        use std::collections::BTreeSet;
        let mut cs = Cs::new();
        let mut bits = Vec::new();
        for i in 0..512 {
            bits.push(Boolean::alloc(&mut cs, (i % 3) == 0));
        }
        let pre = cs.constraints.len();
        let _ = super::blake2s_zcash_ivk(&mut cs, &bits);
        let mut bool_b = BTreeSet::new();
        let mut xor_new = Vec::new();
        for (idx, (a, b, c)) in cs.constraints[pre..].iter().enumerate() {
            let b_vars: Vec<_> = b
                .terms
                .iter()
                .filter(|(_, c)| ScalarTrait::ct_eq(c, &Scalar::zero()) == 0)
                .map(|(v, _)| *v)
                .collect();
            let a_vars: Vec<_> = a
                .terms
                .iter()
                .filter(|(_, c)| ScalarTrait::ct_eq(c, &Scalar::zero()) == 0)
                .map(|(v, _)| *v)
                .collect();
            let c_empty = c
                .terms
                .iter()
                .all(|(_, c)| ScalarTrait::ct_eq(c, &Scalar::zero()) != 0);
            let is_bool = b_vars.len() == 1
                && matches!(b_vars[0], Var::Aux(_))
                && a_vars.iter().any(|v| matches!(v, Var::Input(0)))
                && c_empty
                && a_vars.iter().any(|v| *v == b_vars[0]);
            if is_bool {
                if let Var::Aux(i) = b_vars[0] {
                    bool_b.insert(i);
                }
            }
            let is_xor = b_vars.len() == 1
                && matches!(b_vars[0], Var::Aux(_))
                && a_vars.iter().all(|v| matches!(v, Var::Aux(_)))
                && !a_vars.is_empty()
                && !c_empty;
            if is_xor {
                if let (Var::Aux(ai), Var::Aux(bi)) = (a_vars[0], b_vars[0]) {
                    if !bool_b.contains(&bi) {
                        xor_new.push((idx, ai, bi));
                    }
                }
            }
        }
        let _unique: BTreeSet<_> = xor_new.iter().map(|(_, _, b)| *b).collect();
        // Filter final: still not in bool_b
        let final_new: Vec<_> = xor_new
            .into_iter()
            .filter(|(_, _, b)| !bool_b.contains(b))
            .collect();
        let u2: BTreeSet<_> = final_new.iter().map(|(_, _, b)| *b).collect();
        println!("OUR xor dens_b never-bool unique: {}", u2.len());
        for (i, a, b) in final_new.iter().take(20) {
            println!("  c{i}: A={a} B={b}");
        }
    }

    #[cfg(all(feature = "std", feature = "groth16-prover"))]
    #[test]
    fn blake2s_dens_probe() {
        use crate::zk::groth16::{a_density, b_density};
        use crate::zk::sapling::boolean::Boolean;
        use crate::zk::sapling::cs::Cs;
        let mut cs = Cs::new();
        let mut bits = Vec::new();
        for i in 0..512 {
            bits.push(Boolean::alloc(&mut cs, (i % 3) == 0));
        }
        let pre = cs.constraints.len();
        let _ = super::blake2s_zcash_ivk(&mut cs, &bits);
        let body = cs.constraints.len() - pre;
        let (r1cs, _) = cs.into_r1cs();
        let da = a_density(&r1cs);
        let db = b_density(&r1cs);
        println!(
            "blake2s+512bits: ncons={} body={} a_dens={} b_dens={} nvars={}",
            r1cs.constraints.len(),
            body,
            da.len(),
            db.len(),
            r1cs.num_variables
        );
    }

    use super::*;
    use crate::hash::blake2s::{Blake2s, Blake2sTreeParams};
    use crate::zk::sapling::cs::Cs;

    fn native_personal(personal: &[u8; 8], data: &[u8]) -> [u8; 32] {
        let tree = Blake2sTreeParams {
            fanout: 1,
            max_depth: 1,
            leaf_size: 0,
            node_offset: 0,
            node_depth: 0,
            inner_digest_length: 0,
            last_node: false,
            salt: None,
            personal: Some(*personal),
        };
        let mut h = Blake2s::new_with_tree(32, None, Some(&tree)).unwrap();
        h.update(data);
        h.finalize_256().unwrap()
    }

    fn bits_to_bytes(bits: &[Boolean]) -> Vec<u8> {
        let mut out = vec![0u8; bits.len().div_ceil(8)];
        for (i, b) in bits.iter().enumerate() {
            if b.value {
                out[i / 8] |= 1 << (i % 8);
            }
        }
        out
    }

    #[test]
    fn blake2s_empty_personal_ivk() {
        let mut cs = Cs::new();
        let input: Vec<Boolean> = Vec::new();
        let out = blake2s_cs(&mut cs, &input, b"Zcashivk");
        assert_eq!(out.len(), 256);
        let got = bits_to_bytes(&out);
        let expect = native_personal(b"Zcashivk", &[]);
        assert_eq!(&got[..], &expect[..]);
        let (r1cs, z) = cs.into_r1cs();
        assert!(r1cs.is_satisfied(&z), "ncons={}", r1cs.constraints.len());
    }

    #[test]
    fn blake2s_64_bytes_nf() {
        let mut cs = Cs::new();
        let data: Vec<u8> = (0..64).map(|i| i as u8).collect();
        let mut input = Vec::with_capacity(512);
        for &byte in &data {
            for i in 0..8 {
                input.push(Boolean::alloc(&mut cs, ((byte >> i) & 1) == 1));
            }
        }
        let out = blake2s_cs(&mut cs, &input, b"Zcash_nf");
        let got = bits_to_bytes(&out);
        let expect = native_personal(b"Zcash_nf", &data);
        assert_eq!(&got[..], &expect[..]);
        let (r1cs, z) = cs.into_r1cs();
        assert!(r1cs.is_satisfied(&z));
    }

    /// Protocol target ~21 006 constraints for BLAKE2s (excl. booleanize).
    #[test]
    fn blake2s_constraint_count_512() {
        let mut cs = Cs::new();
        let mut input = Vec::with_capacity(512);
        for i in 0..512 {
            input.push(Boolean::alloc(&mut cs, i % 3 == 0));
        }
        let after_bits = cs.constraints.len();
        let _ = blake2s_cs(&mut cs, &input, b"Zcashivk");
        let n = cs.constraints.len() - after_bits;
        println!("BLAKE2s 512-bit input constraints (excl. bit alloc): {n}");
        // Soft bound: should be near protocol 21006; allow headroom for IV/XOR shape
        assert!(n < 30_000, "BLAKE2s too heavy: {n}");
        assert!(n > 15_000, "BLAKE2s suspiciously light: {n}");
        let (r1cs, z) = cs.into_r1cs();
        assert!(r1cs.is_satisfied(&z));
    }
}
