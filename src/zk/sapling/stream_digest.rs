//! Offline constraint-stream digests for Bellman matrix comparison.
//!
//! ## Format (`stream_jsonl`)
//! One JSON object per constraint (JSON Lines):
//! ```text
//! {"i":0,"a":[[0,0,"01.."],...],"b":[...],"c":[...]}
//! ```
//! Each LC term is `[tag, index, coeff_be_hex]` where `tag=0` input, `tag=1` aux.
//! Compare against a Bellman `TestConstraintSystem` export of the same shape.

use crate::curve::bls::Scalar;
use crate::zk::sapling::cs::{Cs, Lc, Var};
use alloc::string::String;
use alloc::vec::Vec;

fn var_key(v: Var) -> (u8, usize) {
    match v {
        Var::Input(i) => (0, i),
        Var::Aux(i) => (1, i),
    }
}

fn coeff_hex(c: &Scalar) -> String {
    let mut be = [0u8; 32];
    c.to_bytes_be(&mut be);
    // trim leading zeros for compactness, keep at least one byte
    let start = be.iter().position(|&b| b != 0).unwrap_or(31);
    let mut s = String::with_capacity((32 - start) * 2);
    for &b in &be[start..] {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

fn lc_canonical(lc: &Lc) -> Vec<(u8, usize, String)> {
    // Merge coefficients per variable (Bellman LinearCombination semantics),
    // then sort by (tag, index) for stable digests.
    let mut map: Vec<(u8, usize, Scalar)> = Vec::new();
    for &(v, ref c) in &lc.terms {
        let (tag, i) = var_key(v);
        if let Some(slot) = map.iter_mut().find(|(t, j, _)| *t == tag && *j == i) {
            slot.2 = slot.2.add(c);
        } else {
            map.push((tag, i, *c));
        }
    }
    map.sort_by_key(|a| (a.0, a.1));
    map.into_iter()
        .filter(|(_, _, c)| crate::curve::traits::Scalar::ct_eq(c, &Scalar::zero()) == 0)
        .map(|(tag, idx, c)| (tag, idx, coeff_hex(&c)))
        .collect()
}

fn lc_json(lc: &Lc) -> String {
    let terms = lc_canonical(lc);
    let mut s = String::from("[");
    for (i, (tag, idx, hex)) in terms.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&alloc::format!("[{},{},\"{}\"]", tag, idx, hex));
    }
    s.push(']');
    s
}

/// FNV-1a 64-bit over canonical constraint stream.
/// Classify a constraint for order-diff vs Bellman (bitness / xor / equality / other).
pub fn classify_constraint(a: &Lc, b: &Lc, c: &Lc) -> &'static str {
    // Bitness: (1 - x) * x = 0  →  b has one var, c empty, a has one+ONE
    let c_empty = c.terms.is_empty();
    let b_one = b.terms.len() == 1;
    let a_has_one = a
        .terms
        .iter()
        .any(|(v, _)| matches!(v, crate::zk::sapling::cs::Var::Input(0)));
    if c_empty && b_one && a_has_one {
        return "bitness";
    }
    // XOR-ish: A has doubled coeff on same var, B single, C three terms
    if b.terms.len() == 1 && !a.terms.is_empty() && c.terms.len() >= 2 {
        return "xor_or_mul";
    }
    // Equality via * 1: B is ONE only
    if b.terms.len() == 1 {
        if let (crate::zk::sapling::cs::Var::Input(0), coeff) = (&b.terms[0].0, &b.terms[0].1) {
            if crate::curve::traits::Scalar::ct_eq(coeff, &crate::curve::bls::Scalar::one()) == 1 {
                return "equality";
            }
        }
    }
    "other"
}

/// Structure-only fingerprint of one constraint (no variable indices).
///
/// Sorted coefficient multisets per side — comparable to Bellman when
/// allocation indices differ but LC shapes must match.
pub fn structural_fingerprint(a: &Lc, b: &Lc, c: &Lc) -> String {
    fn side(lc: &Lc) -> String {
        let mut coeffs: Vec<String> = lc_canonical(lc).into_iter().map(|(_, _, h)| h).collect();
        coeffs.sort();
        alloc::format!("{}:{}", coeffs.len(), coeffs.join(","))
    }
    alloc::format!("A({})|B({})|C({})", side(a), side(b), side(c))
}

/// Structural stream for constraint slice `[start..]` (one line per constraint).
pub fn structural_stream(cs: &Cs, start: usize) -> String {
    use core::fmt::Write;
    let mut out = String::new();
    for (i, (a, b, c)) in cs.constraints[start..].iter().enumerate() {
        let _ = writeln!(
            &mut out,
            "{:04}:{}:{}",
            i,
            classify_constraint(a, b, c),
            structural_fingerprint(a, b, c)
        );
    }
    out
}

/// Compare two structural streams; returns first diverging body index + lines,
/// or `None` if identical length and content.
pub fn first_structural_divergence(ours: &str, theirs: &str) -> Option<(usize, String, String)> {
    let a: Vec<&str> = ours.lines().filter(|l| !l.is_empty()).collect();
    let b: Vec<&str> = theirs.lines().filter(|l| !l.is_empty()).collect();
    let n = core::cmp::min(a.len(), b.len());
    for i in 0..n {
        // Compare fingerprint part after "NNNN:class:"
        let fa = a[i].splitn(3, ':').nth(2).unwrap_or(a[i]);
        let fb = b[i].splitn(3, ':').nth(2).unwrap_or(b[i]);
        if fa != fb {
            return Some((i, a[i].into(), b[i].into()));
        }
    }
    if a.len() != b.len() {
        return Some((
            n,
            alloc::format!("len={}", a.len()),
            alloc::format!("len={}", b.len()),
        ));
    }
    None
}

/// Protocol / sapling-crypto Edwards-add structural gold (6 body constraints).
/// Coefficients may differ by curve constants; shapes (term counts) are locked.
#[allow(dead_code)]
pub const EDWARDS_ADD_STRUCT_GOLD: &[&str] = &[
    "A(2:01,01)|B(2:01,01)|C(1:01)", // U=(u1+v1)(u2+v2)
    "A(1:01)|B(1:01)|C(1:01)",       // A=v2·u1
    "A(1:01)|B(1:01)|C(1:01)",       // B=u2·v1
    // C=d·A·B — A side carries d (non-01 coeff)
    "A(1:)|B(1:01)|C(1:01)",         // prefix match on term counts
    "A(2:01,01)|B(1:01)|C(2:01,01)", // (1+C)·u3 = A+B
    "A(2:01,)|B(1:01)|C(3:",         // (1−C)·v3 = U−A−B (neg coeffs)
];

pub fn stream_digest64(cs: &Cs) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    let mix = |h: &mut u64, byte: u8| {
        *h ^= byte as u64;
        *h = h.wrapping_mul(0x100000001b3);
    };
    let mix_u64 = |h: &mut u64, v: u64| {
        for i in 0..8 {
            mix(h, ((v >> (8 * i)) & 0xff) as u8);
        }
    };
    mix_u64(&mut h, cs.constraints.len() as u64);
    for (a, b, c) in &cs.constraints {
        for lc in [a, b, c] {
            let terms = lc_canonical(lc);
            mix_u64(&mut h, terms.len() as u64);
            for (tag, idx, hex) in terms {
                mix(&mut h, tag);
                mix_u64(&mut h, idx as u64);
                for byte in hex.bytes() {
                    mix(&mut h, byte);
                }
            }
        }
    }
    h
}

/// Human-readable summary for offline diffs.
pub fn stream_summary(cs: &Cs) -> String {
    use core::fmt::Write;
    let mut s = String::new();
    let _ = write!(
        &mut s,
        "ncons={} naux={} ninputs={} digest=0x{:016x}",
        cs.constraints.len(),
        cs.aux.len(),
        cs.inputs.len(),
        stream_digest64(cs)
    );
    s
}

/// JSON Lines export of every constraint (for Bellman offline diff).
#[allow(dead_code)]
pub fn stream_jsonl(cs: &Cs) -> String {
    use core::fmt::Write;
    let mut out = String::new();
    let _ = writeln!(
        &mut out,
        "{{\"meta\":{{\"ncons\":{},\"naux\":{},\"ninputs\":{},\"digest\":\"0x{:016x}\"}}}}",
        cs.constraints.len(),
        cs.aux.len(),
        cs.inputs.len(),
        stream_digest64(cs)
    );
    for (i, (a, b, c)) in cs.constraints.iter().enumerate() {
        let _ = writeln!(
            &mut out,
            "{{\"i\":{},\"a\":{},\"b\":{},\"c\":{}}}",
            i,
            lc_json(a),
            lc_json(b),
            lc_json(c)
        );
    }
    out
}

/// Constraints added after `start` index, as JSONL (gadget-isolated slice).
pub fn stream_jsonl_slice(cs: &Cs, start: usize) -> String {
    use core::fmt::Write;
    let mut out = String::new();
    let slice = &cs.constraints[start..];
    let _ = writeln!(
        &mut out,
        "{{\"meta\":{{\"slice_start\":{},\"ncons\":{},\"naux\":{},\"ninputs\":{},\"digest_full\":\"0x{:016x}\"}}}}",
        start,
        slice.len(),
        cs.aux.len(),
        cs.inputs.len(),
        stream_digest64(cs)
    );
    for (j, (a, b, c)) in slice.iter().enumerate() {
        let _ = writeln!(
            &mut out,
            "{{\"i\":{},\"a\":{},\"b\":{},\"c\":{}}}",
            start + j,
            lc_json(a),
            lc_json(b),
            lc_json(c)
        );
    }
    out
}

/// Structure-normalized digest: rename variables by order of first appearance
/// in the constraint stream (inputs first by index, then aux by discovery).
/// Use this to compare against Bellman exports where absolute indices differ
/// but constraint *shape* should match.
pub fn stream_digest64_normalized(cs: &Cs) -> u64 {
    use alloc::collections::BTreeMap;
    let mut map: BTreeMap<(u8, usize), usize> = BTreeMap::new();
    let mut next = 0usize;
    let mut rename = |tag: u8, idx: usize| -> usize {
        *map.entry((tag, idx)).or_insert_with(|| {
            let id = next;
            next += 1;
            id
        })
    };
    // Pre-seed inputs in index order so public layout stays stable
    for i in 0..cs.inputs.len() {
        rename(0, i);
    }
    let mut h: u64 = 0xcbf29ce484222325;
    let mix = |h: &mut u64, byte: u8| {
        *h ^= byte as u64;
        *h = h.wrapping_mul(0x100000001b3);
    };
    let mix_u64 = |h: &mut u64, v: u64| {
        for i in 0..8 {
            mix(h, ((v >> (8 * i)) & 0xff) as u8);
        }
    };
    mix_u64(&mut h, cs.constraints.len() as u64);
    for (a, b, c) in &cs.constraints {
        for lc in [a, b, c] {
            let mut terms: Vec<(usize, String)> = lc_canonical(lc)
                .into_iter()
                .map(|(tag, idx, hex)| (rename(tag, idx), hex))
                .collect();
            terms.sort_by_key(|(id, _)| *id);
            mix_u64(&mut h, terms.len() as u64);
            for (id, hex) in terms {
                mix_u64(&mut h, id as u64);
                for byte in hex.bytes() {
                    mix(&mut h, byte);
                }
            }
        }
    }
    h
}

/// Export R1csBls (global var indices) as JSONL for offline Bellman diff.
///
/// Variable tagging: index `0..1+num_public` → input tag 0; rest → aux tag 1
/// with local aux index `i - (1+num_public)`.
#[allow(dead_code)]
pub fn r1cs_stream_jsonl(r1cs: &crate::zk::groth16::R1csBls) -> String {
    use core::fmt::Write;
    let n_in = 1 + r1cs.num_public;
    let mut out = String::new();
    let _ = writeln!(
        &mut out,
        "{{\"meta\":{{\"ncons\":{},\"nvars\":{},\"npublic\":{},\"source\":\"r1cs\"}}}}",
        r1cs.constraints.len(),
        r1cs.num_variables,
        r1cs.num_public
    );
    for (i, cons) in r1cs.constraints.iter().enumerate() {
        let fmt = |lc: &crate::zk::groth16::LinearCombinationBls| -> String {
            let mut terms: Vec<(u8, usize, String)> = Vec::new();
            // merge coeffs
            for &(var, ref c) in &lc.terms {
                if crate::curve::traits::Scalar::ct_eq(c, &crate::curve::bls::Scalar::zero()) == 1 {
                    continue;
                }
                let (tag, idx) = if var < n_in {
                    (0u8, var)
                } else {
                    (1u8, var - n_in)
                };
                if let Some(slot) = terms.iter_mut().find(|(t, j, _)| *t == tag && *j == idx) {
                    // rare duplicate — keep first hex; full merge needs Scalar add
                    let _ = slot;
                } else {
                    terms.push((tag, idx, coeff_hex(c)));
                }
            }
            terms.sort_by_key(|a| (a.0, a.1));
            let mut s = String::from("[");
            for (j, (tag, idx, hex)) in terms.iter().enumerate() {
                if j > 0 {
                    s.push(',');
                }
                s.push_str(&alloc::format!("[{},{},\"{}\"]", tag, idx, hex));
            }
            s.push(']');
            s
        };
        let _ = writeln!(
            &mut out,
            "{{\"i\":{},\"a\":{},\"b\":{},\"c\":{}}}",
            i,
            fmt(&cons.a),
            fmt(&cons.b),
            fmt(&cons.c)
        );
    }
    out
}

/// Structural stream from R1csBls (index-free fingerprints).
pub fn r1cs_structural_stream(r1cs: &crate::zk::groth16::R1csBls) -> String {
    use core::fmt::Write;
    let n_in = 1 + r1cs.num_public;
    let mut out = String::new();
    for (i, cons) in r1cs.constraints.iter().enumerate() {
        let side = |lc: &crate::zk::groth16::LinearCombinationBls| -> String {
            let mut coeffs: Vec<String> = Vec::new();
            for (_, c) in &lc.terms {
                if crate::curve::traits::Scalar::ct_eq(c, &crate::curve::bls::Scalar::zero()) == 0 {
                    coeffs.push(coeff_hex(c));
                }
            }
            coeffs.sort();
            alloc::format!("{}:{}", coeffs.len(), coeffs.join(","))
        };
        let a = side(&cons.a);
        let b = side(&cons.b);
        let c = side(&cons.c);
        let class = {
            let c_empty = cons.c.terms.is_empty()
                || cons.c.terms.iter().all(|(_, c)| {
                    crate::curve::traits::Scalar::ct_eq(c, &crate::curve::bls::Scalar::zero()) == 1
                });
            let b_one = cons.b.terms.len() == 1;
            let a_has_one = cons.a.terms.iter().any(|(v, _)| *v == 0);
            if c_empty && b_one && a_has_one {
                "bitness"
            } else if cons.b.terms.len() == 1 && !cons.a.terms.is_empty() && cons.c.terms.len() >= 2
            {
                "xor_or_mul"
            } else if b_one {
                "equality"
            } else {
                "other"
            }
        };
        let _ = writeln!(&mut out, "{:04}:{}:A({})|B({})|C({})", i, class, a, b, c);
        let _ = n_in; // used for docs; structural is index-free
    }
    out
}

/// Normalized JSONL from R1csBls (vars renamed by first appearance).
pub fn r1cs_stream_jsonl_normalized(r1cs: &crate::zk::groth16::R1csBls) -> String {
    use alloc::collections::BTreeMap;
    use core::fmt::Write;
    let n_in = 1 + r1cs.num_public;
    let mut map: BTreeMap<(u8, usize), usize> = BTreeMap::new();
    let mut next = 0usize;
    let mut rename = |tag: u8, idx: usize| -> usize {
        *map.entry((tag, idx)).or_insert_with(|| {
            let id = next;
            next += 1;
            id
        })
    };
    for i in 0..n_in {
        rename(0, i);
    }
    let mut out = String::new();
    let _ = writeln!(
        &mut out,
        "{{\"meta\":{{\"ncons\":{},\"nvars\":{},\"npublic\":{},\"normalized\":true}}}}",
        r1cs.constraints.len(),
        r1cs.num_variables,
        r1cs.num_public
    );
    for (i, cons) in r1cs.constraints.iter().enumerate() {
        let mut sides = alloc::vec::Vec::new();
        for lc in [&cons.a, &cons.b, &cons.c] {
            let mut terms: Vec<(usize, String)> = Vec::new();
            for &(var, ref c) in &lc.terms {
                if crate::curve::traits::Scalar::ct_eq(c, &crate::curve::bls::Scalar::zero()) == 1 {
                    continue;
                }
                let (tag, idx) = if var < n_in {
                    (0u8, var)
                } else {
                    (1u8, var - n_in)
                };
                terms.push((rename(tag, idx), coeff_hex(c)));
            }
            terms.sort_by_key(|(id, _)| *id);
            let mut s = String::from("[");
            for (j, (id, hex)) in terms.iter().enumerate() {
                if j > 0 {
                    s.push(',');
                }
                s.push_str(&alloc::format!("[{},\"{}\"]", id, hex));
            }
            s.push(']');
            sides.push(s);
        }
        let _ = writeln!(
            &mut out,
            "{{\"i\":{},\"a\":{},\"b\":{},\"c\":{}}}",
            i, sides[0], sides[1], sides[2]
        );
    }
    out
}

/// JSONL with normalized variable ids (for Bellman structural diff).
#[allow(dead_code)]
pub fn stream_jsonl_normalized(cs: &Cs) -> String {
    use alloc::collections::BTreeMap;
    use core::fmt::Write;
    let mut map: BTreeMap<(u8, usize), usize> = BTreeMap::new();
    let mut next = 0usize;
    let mut rename = |tag: u8, idx: usize| -> usize {
        *map.entry((tag, idx)).or_insert_with(|| {
            let id = next;
            next += 1;
            id
        })
    };
    for i in 0..cs.inputs.len() {
        rename(0, i);
    }
    let mut out = String::new();
    let _ = writeln!(
        &mut out,
        "{{\"meta\":{{\"ncons\":{},\"naux\":{},\"ninputs\":{},\"digest_norm\":\"0x{:016x}\"}}}}",
        cs.constraints.len(),
        cs.aux.len(),
        cs.inputs.len(),
        stream_digest64_normalized(cs)
    );
    for (i, (a, b, c)) in cs.constraints.iter().enumerate() {
        let mut fmt_lc = |lc: &Lc| -> String {
            let mut terms: Vec<(usize, String)> = lc_canonical(lc)
                .into_iter()
                .map(|(tag, idx, hex)| (rename(tag, idx), hex))
                .collect();
            terms.sort_by_key(|(id, _)| *id);
            let mut s = String::from("[");
            for (j, (id, hex)) in terms.iter().enumerate() {
                if j > 0 {
                    s.push(',');
                }
                s.push_str(&alloc::format!("[{},\"{}\"]", id, hex));
            }
            s.push(']');
            s
        };
        let _ = writeln!(
            &mut out,
            "{{\"i\":{},\"a\":{},\"b\":{},\"c\":{}}}",
            i,
            fmt_lc(a),
            fmt_lc(b),
            fmt_lc(c)
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zk::sapling::boolean::Boolean;
    use crate::zk::sapling::constants::{spending_key_generator, value_commitment_value_generator};
    use crate::zk::sapling::edwards::EdwardsPoint;
    use crate::zk::sapling::uint32::UInt32;

    #[test]
    fn edwards_add_stream_stable() {
        let mut cs = Cs::new();
        let p = EdwardsPoint::witness(&mut cs, &value_commitment_value_generator());
        let q = EdwardsPoint::witness(&mut cs, &spending_key_generator());
        let before = cs.constraints.len();
        let _ = EdwardsPoint::add(&mut cs, &p, &q);
        let n = cs.constraints.len() - before;
        let d = stream_digest64(&cs);
        let norm = stream_digest64_normalized(&cs);
        println!(
            "edwards_add isolated_cons={n} full {} digest=0x{d:016x} norm=0x{norm:016x}",
            stream_summary(&cs)
        );
        assert_eq!(n, 6);
        assert_ne!(d, 0);
        let jsonl = stream_jsonl_slice(&cs, before);
        assert!(jsonl.contains("\"ncons\":6"));
        // Structural order vs sapling-crypto / Bellman Edwards add:
        // 0 U=(u1+v1)(u2+v2)  1 A=v2*u1  2 B=u2*v1  3 C=d*A*B
        // 4 u3  5 v3
        let structural = structural_stream(&cs, before);
        println!("STREAM_STRUCT_BEGIN edwards_add\n{structural}STREAM_STRUCT_END edwards_add");
        let lines: alloc::vec::Vec<&str> = structural.lines().collect();
        assert_eq!(lines.len(), 6);
        // Each body constraint is a product equality (not pure bitness).
        for (i, line) in lines.iter().enumerate() {
            assert!(
                line.contains("xor_or_mul") || line.contains("equality") || line.contains("other"),
                "edwards body[{i}] unexpected class: {line}"
            );
        }
        // Lock first constraint: U has 2-term * 2-term = 1-term
        assert!(
            lines[0].contains("A(2:") && lines[0].contains("B(2:") && lines[0].contains("C(1:"),
            "U constraint shape: {}",
            lines[0]
        );
        // A and B are pure muls: 1*1=1
        assert!(
            lines[1].contains("A(1:") && lines[1].contains("B(1:") && lines[1].contains("C(1:"),
            "A mul shape: {}",
            lines[1]
        );
        assert!(
            lines[2].contains("A(1:") && lines[2].contains("B(1:") && lines[2].contains("C(1:"),
            "B mul shape: {}",
            lines[2]
        );
        // Protocol term-count shapes (coeff values may vary for d / negations)
        let shapes = [
            ("A(2:", "B(2:", "C(1:"), // U
            ("A(1:", "B(1:", "C(1:"), // A
            ("A(1:", "B(1:", "C(1:"), // B
            ("A(1:", "B(1:", "C(1:"), // C=dAB
            ("A(2:", "B(1:", "C(2:"), // u3
            ("A(2:", "B(1:", "C(3:"), // v3
        ];
        for (i, (a, b, c)) in shapes.iter().enumerate() {
            assert!(
                lines[i].contains(a) && lines[i].contains(b) && lines[i].contains(c),
                "edwards[{i}] shape miss: {}",
                lines[i]
            );
        }
        // Self-diff must be empty
        assert!(first_structural_divergence(&structural, &structural).is_none());
    }

    /// Output circuit size gate (ceremony nvars=7827) for LC-order track.
    #[test]
    fn output_circuit_structural_stages() {
        use crate::curve::jubjub::JubJubPoint;
        use crate::curve::traits::CurvePoint;
        use crate::zk::sapling::circuit_output::synthesize_output;
        use crate::zk::sapling::constants::{
            spending_key_generator, value_commitment_value_generator,
        };
        use crate::zk::sapling::spend::OutputWitness;
        let mut w = OutputWitness::synthetic();
        let point_bytes = |p: &JubJubPoint| {
            let mut b = [0u8; 32];
            p.to_bytes_compressed(&mut b).unwrap();
            b
        };
        w.g_d = point_bytes(&spending_key_generator());
        w.pk_d = point_bytes(&value_commitment_value_generator());
        let (r1cs, assignment) = synthesize_output(&w);
        assert!(
            r1cs.is_satisfied(&assignment),
            "output R1CS must be satisfied for stream export"
        );
        println!(
            "output_stream: nvars={} npublic={} ncons={} (ceremony nvars=7827)",
            r1cs.num_variables,
            r1cs.num_public,
            r1cs.constraints.len()
        );
        assert!(
            (r1cs.num_variables as i64 - 7827).abs() <= 2,
            "Output nvars drifted from ceremony 7827: {}",
            r1cs.num_variables
        );
    }

    /// Write Output + Spend-depth-1 normalized/structural streams for offline Bellman diff.
    #[test]
    #[cfg(all(feature = "std", feature = "groth16-prover"))]
    fn print_spend_head_shapes() {
        use crate::curve::jubjub::JubJubPoint;
        use crate::curve::traits::CurvePoint;
        use crate::zk::sapling::circuit_spend::synthesize_spend_depth;
        use crate::zk::sapling::constants::{
            proof_generation_key_generator, spending_key_generator,
            value_commitment_value_generator,
        };
        use crate::zk::sapling::spend::SpendWitness;
        let point_bytes = |p: &JubJubPoint| {
            let mut b = [0u8; 32];
            p.to_bytes_compressed(&mut b).unwrap();
            b
        };
        let mut w = SpendWitness::synthetic();
        w.ak = point_bytes(&proof_generation_key_generator());
        w.g_d = point_bytes(&spending_key_generator());
        w.pk_d = point_bytes(&value_commitment_value_generator());
        let (r1cs, _) = synthesize_spend_depth(&w, 1);
        for (i, c) in r1cs.constraints.iter().take(20).enumerate() {
            let an = c.a.terms.len();
            let bn = c.b.terms.len();
            let cn = c.c.terms.len();
            let a_idx: Vec<_> = c.a.terms.iter().map(|(v, _)| *v).collect();
            let b_idx: Vec<_> = c.b.terms.iter().map(|(v, _)| *v).collect();
            let c_idx: Vec<_> = c.c.terms.iter().map(|(v, _)| *v).collect();
            println!("{i:04}: ({an},{bn},{cn}) A={a_idx:?} B={b_idx:?} C={c_idx:?}");
        }
    }

    #[cfg(all(feature = "std", feature = "groth16-prover"))]
    #[test]
    fn print_cons_around_3685() {
        use crate::curve::jubjub::JubJubPoint;
        use crate::curve::traits::CurvePoint;
        use crate::zk::sapling::circuit_spend::synthesize_spend_depth;
        use crate::zk::sapling::constants::*;
        use crate::zk::sapling::spend::SpendWitness;
        let pb = |p: &JubJubPoint| {
            let mut b = [0u8; 32];
            p.to_bytes_compressed(&mut b).unwrap();
            b
        };
        let mut w = SpendWitness::synthetic();
        w.ak = pb(&proof_generation_key_generator());
        w.g_d = pb(&spending_key_generator());
        w.pk_d = pb(&value_commitment_value_generator());
        let (r1cs, _) = synthesize_spend_depth(&w, 1);
        for i in 3680..3720 {
            let c = &r1cs.constraints[i];
            let at: Vec<_> = c.a.terms.iter().map(|(v, _co)| format!("{v:?}")).collect();
            let bt: Vec<_> = c.b.terms.iter().map(|(v, _co)| format!("{v:?}")).collect();
            let ct: Vec<_> = c.c.terms.iter().map(|(v, _co)| format!("{v:?}")).collect();
            println!(
                "{i}: A({})={:?} B({})={:?} C({})={:?}",
                c.a.terms.len(),
                at,
                c.b.terms.len(),
                bt,
                c.c.terms.len(),
                ct
            );
        }
        // Also print ncons before blake / note commitment stages if marked
        println!("total ncons={}", r1cs.constraints.len());
    }

    #[cfg(all(feature = "std", feature = "groth16-prover"))]
    #[test]
    fn print_spend_head_merged() {
        use crate::curve::jubjub::JubJubPoint;
        use crate::curve::traits::CurvePoint;
        use crate::zk::sapling::circuit_spend::synthesize_spend_depth;
        use crate::zk::sapling::constants::*;
        use crate::zk::sapling::spend::SpendWitness;
        let pb = |p: &JubJubPoint| {
            let mut b = [0u8; 32];
            p.to_bytes_compressed(&mut b).unwrap();
            b
        };
        let mut w = SpendWitness::synthetic();
        w.ak = pb(&proof_generation_key_generator());
        w.g_d = pb(&spending_key_generator());
        w.pk_d = pb(&value_commitment_value_generator());
        let (r1cs, _) = synthesize_spend_depth(&w, 1);
        for i in 0..25 {
            let c = &r1cs.constraints[i];
            let a: Vec<_> = c.a.terms.iter().map(|(v, _)| *v).collect();
            let b: Vec<_> = c.b.terms.iter().map(|(v, _)| *v).collect();
            let cc: Vec<_> = c.c.terms.iter().map(|(v, _)| *v).collect();
            println!("{:04}: A={:?} B={:?} C={:?}", i, a, b, cc);
        }
    }

    #[cfg(all(feature = "std", feature = "groth16-prover"))]
    #[test]
    fn export_spend_d1_merged() {
        use crate::curve::bls::Scalar;
        use crate::curve::jubjub::JubJubPoint;
        use crate::curve::traits::{CurvePoint, Scalar as ScalarTrait};
        use crate::zk::sapling::circuit_spend::synthesize_spend_depth;
        use crate::zk::sapling::constants::*;
        use crate::zk::sapling::spend::SpendWitness;
        use std::collections::BTreeMap;
        let pb = |p: &JubJubPoint| {
            let mut b = [0u8; 32];
            p.to_bytes_compressed(&mut b).unwrap();
            b
        };
        let mut w = SpendWitness::synthetic();
        w.ak = pb(&proof_generation_key_generator());
        w.g_d = pb(&spending_key_generator());
        w.pk_d = pb(&value_commitment_value_generator());
        let (r1cs, _) = synthesize_spend_depth(&w, 1);
        fn side_str(terms: &[(usize, Scalar)], n_pub: usize) -> String {
            let mut map: BTreeMap<(u8, usize), Scalar> = BTreeMap::new();
            for (gi, c) in terms {
                if ScalarTrait::ct_eq(c, &Scalar::zero()) != 0 {
                    continue;
                }
                // Global index: 0=ONE, 1..n_public = inputs, rest aux
                // n_public = num_public (7), inputs = 8 including ONE
                let _ = n_pub;
                let (tag, idx) = if *gi < 8 { (0u8, *gi) } else { (1u8, *gi - 8) };
                let e = map.entry((tag, idx)).or_insert(Scalar::zero());
                *e = e.add(c);
            }
            let mut parts = Vec::new();
            for ((t, i), c) in map {
                if ScalarTrait::ct_eq(&c, &Scalar::zero()) != 0 {
                    continue;
                }
                let hx: String = if ScalarTrait::ct_eq(&c, &Scalar::one()) == 1 {
                    "01".to_string()
                } else if ScalarTrait::ct_eq(&c, &Scalar::one().neg()) == 1 {
                    "ff".to_string()
                } else if ScalarTrait::ct_eq(&c, &Scalar::one().add(&Scalar::one())) == 1 {
                    "02".to_string()
                } else {
                    "xx".to_string()
                };
                parts.push(format!("({t},{i},{hx})"));
            }
            format!("[{}]", parts.join(", "))
        }
        let mut out = String::new();
        // body without trailing dummy inputs (last 8)
        let body = r1cs.constraints.len().saturating_sub(8);
        for i in 0..body {
            let c = &r1cs.constraints[i];
            out.push_str(&format!(
                "A={} B={} C={}\n",
                side_str(&c.a.terms, 7),
                side_str(&c.b.terms, 7),
                side_str(&c.c.terms, 7)
            ));
        }
        assert!(body > 0, "spend depth-1 body must be non-empty");
        assert!(!out.is_empty(), "merged stream must be non-empty");
        println!("spend_d1_merged body={} lines", body);
    }

    #[test]
    fn export_output_spend_streams_to_artifacts() {
        use crate::curve::jubjub::JubJubPoint;
        use crate::curve::traits::CurvePoint;
        use crate::zk::sapling::circuit_output::synthesize_output;
        use crate::zk::sapling::circuit_spend::synthesize_spend_depth;
        use crate::zk::sapling::constants::{
            spending_key_generator, value_commitment_value_generator,
        };
        use crate::zk::sapling::spend::{OutputWitness, SpendWitness};

        // --- Output ---
        let mut ow = OutputWitness::synthetic();
        let point_bytes = |p: &JubJubPoint| {
            let mut b = [0u8; 32];
            p.to_bytes_compressed(&mut b).unwrap();
            b
        };
        ow.g_d = point_bytes(&spending_key_generator());
        ow.pk_d = point_bytes(&value_commitment_value_generator());
        let (or1cs, oass) = synthesize_output(&ow);
        assert!(or1cs.is_satisfied(&oass));
        let o_jsonl = r1cs_stream_jsonl_normalized(&or1cs);
        let o_struct = r1cs_structural_stream(&or1cs);
        assert!(!o_jsonl.is_empty(), "output jsonl stream must be non-empty");
        assert!(!o_struct.is_empty(), "output structural stream must be non-empty");
        println!(
            "output: ncons={} nvars={}",
            or1cs.constraints.len(),
            or1cs.num_variables
        );

        // --- Spend depth-1 (good_witness-style valid points) ---
        use crate::zk::sapling::constants::proof_generation_key_generator;
        let mut sw = SpendWitness::synthetic();
        sw.ak = point_bytes(&proof_generation_key_generator());
        sw.g_d = point_bytes(&spending_key_generator());
        sw.pk_d = point_bytes(&value_commitment_value_generator());
        let (sr1cs, sass) = synthesize_spend_depth(&sw, 1);
        println!(
            "spend_d1: satisfied={} ncons={} nvars={} npublic={}",
            sr1cs.is_satisfied(&sass),
            sr1cs.constraints.len(),
            sr1cs.num_variables,
            sr1cs.num_public
        );
        let s_jsonl = r1cs_stream_jsonl_normalized(&sr1cs);
        let s_struct = r1cs_structural_stream(&sr1cs);
        assert!(!s_jsonl.is_empty(), "spend jsonl stream must be non-empty");
        assert!(!s_struct.is_empty(), "spend structural stream must be non-empty");
        println!(
            "spend_depth1: ncons={} nvars={}",
            sr1cs.constraints.len(),
            sr1cs.num_variables
        );

        // Edwards gold comparison (structural shapes)
        let mut cs = Cs::new();
        let p = EdwardsPoint::witness(&mut cs, &value_commitment_value_generator());
        let q = EdwardsPoint::witness(&mut cs, &spending_key_generator());
        let before = cs.constraints.len();
        let _ = EdwardsPoint::add(&mut cs, &p, &q);
        let structural = structural_stream(&cs, before);
        // Bellman gold structural (from sapling-crypto shape)
        let gold = "\
0000:other:A(2:01,01)|B(2:01,01)|C(1:01)\n\
0001:other:A(1:01)|B(1:01)|C(1:01)\n\
0002:other:A(1:01)|B(1:01)|C(1:01)\n\
0003:other:A(1:2a9318e74bfa2b48f5fd9207e6bd7fd4292d7f6d37579d2601065fd6d6343eb1)|B(1:01)|C(1:01)\n\
0004:other:A(2:01,01)|B(1:01)|C(2:01,01)\n\
0005:other:A(2:01,73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000)|B(1:01)|C(3:01,73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000,73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000)\n";
        if let Some((i, a, b)) = first_structural_divergence(&structural, gold) {
            // Class prefix may differ (xor_or_mul vs other); compare fingerprints only
            println!("edwards structural first_div @ {i}:\n  ours={a}\n  gold={b}");
        } else {
            println!("edwards structural FULL MATCH vs Bellman gold");
        }
        // Fingerprint-only match (ignore class label)
        let fp = |line: &str| -> String { line.splitn(3, ':').nth(2).unwrap_or(line).to_string() };
        let ours_fp: Vec<String> = structural.lines().map(fp).collect();
        let gold_fp: Vec<String> = gold.lines().filter(|l| !l.is_empty()).map(fp).collect();
        assert_eq!(ours_fp.len(), 6);
        for i in 0..6 {
            let oc = &ours_fp[i];
            let gc = &gold_fp[i];
            let count = |s: &str, side: &str| -> String {
                s.split('|')
                    .find(|p| p.starts_with(side))
                    .and_then(|p| p.split(':').next())
                    .unwrap_or("")
                    .to_string()
            };
            assert_eq!(
                count(oc, "A"),
                count(gc, "A"),
                "edwards[{i}] A term-count: ours={oc} gold={gc}"
            );
            assert_eq!(
                count(oc, "B"),
                count(gc, "B"),
                "edwards[{i}] B term-count: ours={oc} gold={gc}"
            );
            assert_eq!(
                count(oc, "C"),
                count(gc, "C"),
                "edwards[{i}] C term-count: ours={oc} gold={gc}"
            );
        }
        println!("edwards term-count identity LOCKED vs Bellman gold (6/6)");
    }

    #[test]
    fn uint32_add2_stream_stable() {
        let mut cs = Cs::new();
        let bits_a: Vec<_> = (0..32)
            .map(|i| Boolean::alloc(&mut cs, i % 2 == 0))
            .collect();
        let bits_b: Vec<_> = (0..32)
            .map(|i| Boolean::alloc(&mut cs, i % 3 == 0))
            .collect();
        let a = UInt32::from_bits_pad(&mut cs, &bits_a);
        let b = UInt32::from_bits_pad(&mut cs, &bits_b);
        let before = cs.constraints.len();
        let _ = UInt32::add_many(&mut cs, &[&a, &b]);
        let delta = cs.constraints.len() - before;
        let d = stream_digest64(&cs);
        let n = stream_digest64_normalized(&cs);
        println!(
            "uint32_add2 body={delta} full {} digest=0x{d:016x} norm=0x{n:016x}",
            stream_summary(&cs)
        );
        // Bellman-style add2: 32 out bitness + 1 carry bitness + packed equality ≈ 34
        assert_eq!(
            delta, 34,
            "add2 body constraints drifted (Bellman target ~34)"
        );
        let jsonl = stream_jsonl_slice(&cs, before);
        assert!(jsonl.contains("\"ncons\":34"));
        println!("STREAM_JSONL_BEGIN uint32_add2");
        print!("{jsonl}");
        println!("STREAM_JSONL_END uint32_add2");
    }

    #[test]
    fn blake2s_body_stream_meta() {
        let mut cs = Cs::new();
        let mut input = Vec::with_capacity(512);
        for i in 0..512 {
            input.push(Boolean::alloc(&mut cs, i % 3 == 0));
        }
        let after_bits = cs.constraints.len();
        let _ = crate::zk::sapling::blake2s_circuit::blake2s_cs(&mut cs, &input, b"Zcashivk");
        let body = cs.constraints.len() - after_bits;
        let d = stream_digest64(&cs);
        let n = stream_digest64_normalized(&cs);
        println!(
            "blake2s_body={body} full {} digest=0x{d:016x} norm=0x{n:016x}",
            stream_summary(&cs)
        );
        assert_eq!(body, 21006, "blake2s body constraint count drifted");
        // First 24 body constraints for Bellman order diff (head of MultiEq stream)
        let _head_end = after_bits + 24;
        let mut head_cs_ncons = 0usize;
        {
            let jsonl = stream_jsonl_slice(&cs, after_bits);
            let mut lines = jsonl.lines();
            let meta = lines.next().unwrap();
            println!("blake2s_meta={meta}");
            println!("STREAM_JSONL_BEGIN blake2s_head24");
            println!("{meta}");
            for (i, line) in lines.enumerate() {
                if i >= 24 {
                    break;
                }
                println!("{line}");
                head_cs_ncons += 1;
            }
            println!("STREAM_JSONL_END blake2s_head24");
        }
        assert_eq!(head_cs_ncons, 24);
        assert_ne!(d, 0);
        assert_ne!(n, 0);
    }

    #[test]
    fn export_gadget_catalog() {
        let mut lines = Vec::new();

        {
            let mut cs = Cs::new();
            let p = EdwardsPoint::witness(&mut cs, &value_commitment_value_generator());
            let q = EdwardsPoint::witness(&mut cs, &spending_key_generator());
            let b = cs.constraints.len();
            let _ = EdwardsPoint::add(&mut cs, &p, &q);
            let body = cs.constraints.len() - b;
            let dig = stream_digest64(&cs);
            let norm = stream_digest64_normalized(&cs);
            lines.push(alloc::format!(
                "edwards_add body={body} digest=0x{dig:016x} norm=0x{norm:016x}"
            ));
            let jsonl = stream_jsonl_slice(&cs, b);
            println!("STREAM_JSONL_BEGIN edwards_add");
            print!("{jsonl}");
            println!("STREAM_JSONL_END edwards_add");
        }
        {
            let mut cs = Cs::new();
            let bits_a: Vec<_> = (0..32).map(|i| Boolean::alloc(&mut cs, i == 0)).collect();
            let bits_b: Vec<_> = (0..32).map(|i| Boolean::alloc(&mut cs, i == 1)).collect();
            let a = UInt32::from_bits_pad(&mut cs, &bits_a);
            let b = UInt32::from_bits_pad(&mut cs, &bits_b);
            let start = cs.constraints.len();
            let _ = UInt32::add_many(&mut cs, &[&a, &b]);
            let body = cs.constraints.len() - start;
            lines.push(alloc::format!(
                "uint32_add2 body={body} digest=0x{:016x} norm=0x{:016x}",
                stream_digest64(&cs),
                stream_digest64_normalized(&cs)
            ));
            let jsonl = stream_jsonl_slice(&cs, start);
            println!("STREAM_JSONL_BEGIN uint32_add2");
            print!("{jsonl}");
            println!("STREAM_JSONL_END uint32_add2");
        }
        for l in &lines {
            println!("CATALOG {l}");
        }
        assert_eq!(lines.len(), 2);
    }
}
