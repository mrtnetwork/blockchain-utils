//! Straus / Pippenger multiscalar multiplication over ed25519.
//!
//! Direct port of Monero reference implementation `Multiexp` (Monero C++ `multiexp.cc` logic):
//! batch-verification multiexps and the per-round `computeLR` folds.

#![cfg(feature = "monero")]

use super::{Ed25519Point, MoneroError, MoneroResult, S32};
use crate::curve::traits::CurvePoint;
use alloc::vec::Vec;

/// (scalar, point) pair for multiexp evaluation.
#[derive(Clone, Copy, Debug)]
pub struct MultiexpPair {
    /// 32-byte little-endian scalar.
    pub scalar: S32,
    /// Point to multiply.
    pub point: Ed25519Point,
}

impl MultiexpPair {
    /// New pair.
    pub fn new(scalar: S32, point: Ed25519Point) -> Self {
        Self { scalar, point }
    }
}

/// Straus window width (matches the reference implementation.strausC`).
pub const STRAUS_C: usize = 4;

/// Pippenger window for `n` points (matches the reference implementation.
pub fn pippenger_c(n: usize) -> usize {
    if n <= 13 {
        2
    } else if n <= 29 {
        3
    } else if n <= 83 {
        4
    } else if n <= 185 {
        5
    } else if n <= 465 {
        6
    } else if n <= 1180 {
        7
    } else if n <= 2295 {
        8
    } else {
        9
    }
}

fn is_lower_than(k0: &S32, k1: &S32) -> bool {
    for n in (0..32).rev() {
        if k0[n] < k1[n] {
            return true;
        }
        if k0[n] > k1[n] {
            return false;
        }
    }
    false
}

fn pow2(n: usize) -> MoneroResult<S32> {
    if n >= 256 {
        return Err(MoneroError::InvalidLength);
    }
    let mut res = [0u8; 32];
    res[n >> 3] |= 1 << (n & 7);
    Ok(res)
}

/// Precomputed odd multiples for Straus.
struct StrausTable {
    multiples: Vec<Vec<Ed25519Point>>,
}

impl StrausTable {
    fn build(data: &[MultiexpPair]) -> Self {
        let n = data.len();
        let width = (1usize << STRAUS_C) - 1;
        let mut multiples: Vec<Vec<Ed25519Point>> = Vec::with_capacity(n);
        for d in data.iter().take(n) {
            let mut row = Vec::with_capacity(width);
            row.push(d.point);
            for _ in 1..width {
                let next = row[row.len() - 1].add(&d.point);
                row.push(next);
            }
            multiples.push(row);
        }
        Self { multiples }
    }

    fn at(&self, point: usize, digit: u8) -> Ed25519Point {
        self.multiples[point][(digit - 1) as usize]
    }
}

/// Straus evaluation with band step (mirrors the reference implementation
pub fn straus(data: &[MultiexpPair], step: usize) -> MoneroResult<Ed25519Point> {
    if data.is_empty() {
        return Err(MoneroError::InvalidProof);
    }
    let step = if step == 0 { 192 } else { step };
    let table = StrausTable::build(data);
    // Nibble digits, little-endian (64 nibbles per scalar).
    let mut digits = Vec::with_capacity(64 * data.len());
    for d in data {
        for i in 0..64usize {
            let b = d.scalar[i / 2];
            if i % 2 == 0 {
                digits.push(b & 0xf);
            } else {
                digits.push(b >> 4);
            }
        }
    }
    let mut max_scalar = [0u8; 32];
    for d in data {
        if is_lower_than(&max_scalar, &d.scalar) {
            max_scalar = d.scalar;
        }
    }
    let mut start_i = 0usize;
    while start_i < 256 && !is_lower_than(&max_scalar, &pow2(start_i)?) {
        start_i += STRAUS_C;
    }
    let mut resp: Option<Ed25519Point> = None;
    let mut start_offset = 0usize;
    while start_offset < data.len() {
        let num_points = (data.len() - start_offset).min(step);
        let mut band: Option<Ed25519Point> = None;
        let mut i = start_i;
        if i >= STRAUS_C {
            i -= STRAUS_C;
            for j in start_offset..start_offset + num_points {
                let digit = digits[j * 64 + i / 4];
                if digit != 0 {
                    let p = table.at(j, digit);
                    band = Some(match band {
                        Some(b) => b.add(&p),
                        None => p,
                    });
                }
            }
        }
        while i >= STRAUS_C {
            let mut p1 = band.ok_or(MoneroError::InvalidProof)?;
            for _ in 0..STRAUS_C {
                p1 = p1.double();
            }
            band = Some(p1);
            i -= STRAUS_C;
            for j in start_offset..start_offset + num_points {
                let digit = digits[j * 64 + i / 4];
                if digit != 0 {
                    let p = table.at(j, digit);
                    band = Some(band.ok_or(MoneroError::InvalidProof)?.add(&p));
                }
            }
        }
        let band = band.ok_or(MoneroError::InvalidProof)?;
        resp = Some(match resp {
            Some(r) => r.add(&band),
            None => band,
        });
        start_offset += step;
    }
    resp.ok_or(MoneroError::InvalidProof)
}

fn is_bit_set(k: &S32, n: usize) -> bool {
    if n >= 256 {
        return false;
    }
    k[n >> 3] & (1 << (n & 7)) != 0
}

/// Pippenger evaluation (mirrors the reference implementation
pub fn pippenger(data: &[MultiexpPair], cache_size: usize, c: usize) -> MoneroResult<Ed25519Point> {
    // Cached and uncached point loads are currently identical; keep the
    // parameter for the C-mirrored API while silencing unused warnings.
    let _ = cache_size;
    if data.is_empty() {
        return Err(MoneroError::InvalidProof);
    }
    let c = if c == 0 { pippenger_c(data.len()) } else { c };
    let mut result = Ed25519Point::identity();
    let mut result_init = false;
    let n_buckets = 1usize << c;
    let mut buckets: Vec<Option<Ed25519Point>> = Vec::with_capacity(n_buckets);
    buckets.resize(n_buckets, None);
    let mut buckets_init = Vec::with_capacity(1usize << 9);
    buckets_init.resize(1usize << 9, false);

    let mut max_scalar = [0u8; 32];
    for d in data {
        if is_lower_than(&max_scalar, &d.scalar) {
            max_scalar = d.scalar;
        }
    }
    let mut groups = 0usize;
    while groups < 256 && !is_lower_than(&max_scalar, &pow2(groups)?) {
        groups += 1;
    }
    groups = groups.div_ceil(c);

    let mut k = groups;
    while k > 0 {
        k -= 1;
        if result_init {
            let mut p = result;
            for _ in 0..c {
                p = p.double();
            }
            result = p;
        }
        for b in buckets_init.iter_mut().take(n_buckets) {
            *b = false;
        }
        for d in data.iter() {
            let mut bucket = 0usize;
            for j in 0..c {
                if is_bit_set(&d.scalar, k * c + j) {
                    bucket |= 1 << j;
                }
            }
            if bucket == 0 {
                continue;
            }
            if bucket >= n_buckets {
                return Err(MoneroError::InvalidProof);
            }
            if buckets_init[bucket] {
                let p = d.point;
                buckets[bucket] = Some(match buckets[bucket] {
                    Some(b) => b.add(&p),
                    None => p,
                });
            } else {
                buckets[bucket] = Some(d.point);
                buckets_init[bucket] = true;
            }
        }
        let mut pail: Option<Ed25519Point> = None;
        for i in (1..n_buckets).rev() {
            if buckets_init[i] {
                pail = Some(match pail {
                    Some(p) => p.add(&buckets[i].ok_or(MoneroError::InvalidProof)?),
                    None => buckets[i].ok_or(MoneroError::InvalidProof)?,
                });
            }
            if let Some(p) = pail {
                if result_init {
                    result = result.add(&p);
                } else {
                    result = p;
                    result_init = true;
                }
            }
        }
    }
    if result_init {
        Ok(result)
    } else {
        Err(MoneroError::InvalidProof)
    }
}
