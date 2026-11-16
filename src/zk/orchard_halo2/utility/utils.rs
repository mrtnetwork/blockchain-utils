//! Implements utility/utils logic (field-only subset).
//! LE wire bytes throughout; debug via `format!`; Result style, no `assert!`.
//! Point-dependent routines (multiexp/window tables/FFT on points) stay TODO
//! until the curve vendor lands; field FFT/interp/invert are fully ported.

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

use crate::zk::orchard_halo2::curve::VestaScalar;
use crate::zk::orchard_halo2::error::{Halo2Error, Halo2Result};
use crate::zk::orchard_halo2::field::PallasFp;

pub const FIXED_BASE_WINDOW_SIZE: usize = 3;
pub const NUM_WINDOWS: usize = 85;
pub const H: usize = 1 << FIXED_BASE_WINDOW_SIZE;

pub fn log2_floor(num: usize) -> Halo2Result<u32> {
    if num == 0 {
        return Err(Halo2Error::operation_failed(
            "log2_floor",
            "non-positive input",
        ));
    }
    let mut pow: u32 = 0;
    while (1usize << (pow + 1)) <= num {
        pow += 1;
    }
    Ok(pow)
}

pub fn bit_reverse(mut n: usize, l: u32) -> usize {
    let mut r: usize = 0;
    for _ in 0..l {
        r = (r << 1) | (n & 1);
        n >>= 1;
    }
    r
}

pub fn compute_inner_product(a: &[PallasFp], b: &[PallasFp]) -> Halo2Result<PallasFp> {
    if a.len() != b.len() {
        return Err(Halo2Error::operation_failed(
            "compute_inner_product",
            "length mismatch",
        ));
    }
    let mut acc = PallasFp::zero();
    for (x, y) in a.iter().zip(b.iter()) {
        acc = acc.add_vartime(&x.mul_vartime(y));
    }
    Ok(acc)
}

pub fn kate_division(a: &[PallasFp], b: PallasFp) -> Halo2Result<Vec<PallasFp>> {
    let n = a.len();
    if n < 2 {
        return Err(Halo2Error::operation_failed(
            "kate_division",
            "polynomial too short",
        ));
    }
    let neg_b = b.neg();
    let mut q = Vec::with_capacity(n - 1);
    for _ in 0..n - 1 {
        q.push(PallasFp::zero());
    }
    let mut tmp = PallasFp::zero();
    let mut i = (n - 2) as isize;
    let mut j = (n - 1) as isize;
    while i >= 0 {
        let lead = a[j as usize].sub_vartime(&tmp);
        q[i as usize] = lead;
        tmp = lead.mul_vartime(&neg_b);
        i -= 1;
        j -= 1;
    }
    Ok(q)
}

pub fn eval_polynomial(poly: &[PallasFp], point: PallasFp) -> PallasFp {
    let mut acc = PallasFp::zero();
    for c in poly.iter().rev() {
        acc = acc.mul_vartime(&point).add_vartime(c);
    }
    acc
}

/// In-place batch invert (Montgomery trick). Zero entries stay zero.
pub fn batch_invert(values: &mut [PallasFp]) -> Halo2Result<PallasFp> {
    let mut acc = PallasFp::one();
    #[cfg(feature = "alloc")]
    let mut stack: Vec<(PallasFp, PallasFp)> = Vec::with_capacity(values.len());
    #[cfg(not(feature = "alloc"))]
    let mut stack: [Option<(PallasFp, PallasFp)>; 0] = [];
    for v in values.iter() {
        #[cfg(feature = "alloc")]
        stack.push((acc, *v));
        if !v.is_zero() {
            acc = acc.mul_vartime(v);
        }
    }
    let inv = acc.invert()?;
    let all_inv = inv;
    let mut acc_back = inv;
    #[cfg(feature = "alloc")]
    for (enumerate, item) in stack.into_iter().rev().enumerate() {
        let prev = item.0;
        let v = item.1;
        let idx = values.len() - 1 - enumerate;
        let skip = v.is_zero();
        let t = prev.mul_vartime(&acc_back);
        if !skip {
            acc_back = acc_back.mul_vartime(&v);
        }
        if !skip {
            values[idx] = t;
        }
    }
    Ok(all_inv)
}

pub fn lagrange_interpolate(points: &[PallasFp], evals: &[PallasFp]) -> Halo2Result<Vec<PallasFp>> {
    if points.len() != evals.len() {
        return Err(Halo2Error::operation_failed(
            "lagrange_interpolate",
            "length mismatch",
        ));
    }
    let n = points.len();
    if n == 0 {
        return Err(Halo2Error::operation_failed(
            "lagrange_interpolate",
            "empty input",
        ));
    }
    if n == 1 {
        return Ok(Vec::from([evals[0]]));
    }
    let mut denoms: Vec<Vec<PallasFp>> = Vec::with_capacity(n);
    for j in 0..n {
        let mut row: Vec<PallasFp> = Vec::new();
        for k in 0..n {
            if k != j {
                row.push(points[j].sub_vartime(&points[k]));
            }
        }
        batch_invert(&mut row)?;
        denoms.push(row);
    }
    let mut out: Vec<PallasFp> = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(PallasFp::zero());
    }
    for j in 0..n {
        let mut tmp: Vec<PallasFp> = Vec::from([PallasFp::one()]);
        let mut di = 0usize;
        for (k, &xk) in points.iter().enumerate() {
            if k == j {
                continue;
            }
            let denom = denoms[j][di];
            di += 1;
            let mut next: Vec<PallasFp> = Vec::with_capacity(tmp.len() + 1);
            for _ in 0..tmp.len() + 1 {
                next.push(PallasFp::zero());
            }
            for (i, t) in tmp.iter().enumerate() {
                let a = t.mul_vartime(&denom.neg().mul_vartime(&xk));
                next[i] = next[i].add_vartime(&a);
                let b = t.mul_vartime(&denom);
                next[i + 1] = next[i + 1].add_vartime(&b);
            }
            tmp = next;
        }
        if tmp.len() != n {
            return Err(Halo2Error::operation_failed(
                "lagrange_interpolate",
                "length mismatch",
            ));
        }
        for (i, t) in tmp.iter().enumerate() {
            out[i] = out[i].add_vartime(&t.mul_vartime(&evals[j]));
        }
    }
    Ok(out)
}

/// Field FFT (best_fft_field). Length must be a power of two; checked, no assert.
pub fn best_fft_field(a: &mut [PallasFp], omega: PallasFp, log_n: u32) -> Halo2Result<()> {
    let n = a.len();
    if n != (1usize << log_n) {
        return Err(Halo2Error::operation_failed(
            "best_fft_field",
            "length mismatch",
        ));
    }
    for k in 0..n {
        let rk = bit_reverse(k, log_n);
        if k < rk {
            a.swap(k, rk);
        }
    }
    let mut twiddles: Vec<PallasFp> = Vec::with_capacity(n / 2);
    let mut w = PallasFp::one();
    for _ in 0..n / 2 {
        twiddles.push(w);
        w = w.mul_vartime(&omega);
    }
    recursive_butterfly_field(a, 0, n, 1, &twiddles);
    Ok(())
}

fn recursive_butterfly_field(
    a: &mut [PallasFp],
    start: usize,
    n: usize,
    twiddle_chunk: usize,
    twiddles: &[PallasFp],
) {
    if n == 2 {
        let t = a[start + 1];
        a[start + 1] = a[start];
        a[start] = a[start].add_vartime(&t);
        a[start + 1] = a[start + 1].sub_vartime(&t);
    } else if n >= 1024 && crate::multicore::num_threads() > 1 {
        // Parallel halves (halo2 `join` shape); below the cutoff the
        // sequential recursion avoids thread-spawn overhead.
        let half = n / 2;
        let (left_all, right_all) = a.split_at_mut(start + half);
        let left = &mut left_all[start..];
        crate::multicore::scope(|s| {
            let h1 = s.spawn(move || {
                recursive_butterfly_field(left, 0, half, twiddle_chunk * 2, twiddles)
            });
            recursive_butterfly_field(right_all, 0, half, twiddle_chunk * 2, twiddles);
            crate::multicore::Scope::join(h1)
        });
        butterfly_combine(a, start, half, twiddle_chunk, twiddles);
    } else {
        let half = n / 2;
        recursive_butterfly_field(a, start, half, twiddle_chunk * 2, twiddles);
        recursive_butterfly_field(a, start + half, half, twiddle_chunk * 2, twiddles);
        butterfly_combine(a, start, half, twiddle_chunk, twiddles);
    }
}

/// Combine step shared by both butterfly schedules (twiddle multiply + add/sub).
fn butterfly_combine(
    a: &mut [PallasFp],
    start: usize,
    half: usize,
    twiddle_chunk: usize,
    twiddles: &[PallasFp],
) {
    {
        let t = a[start + half];
        a[start + half] = a[start];
        a[start] = a[start].add_vartime(&t);
        a[start + half] = a[start + half].sub_vartime(&t);
    }
    for i in 1..half {
        let ti = i * twiddle_chunk;
        if ti >= twiddles.len() {
            continue;
        }
        let t = a[start + half + i].mul_vartime(&twiddles[ti]);
        let av = a[start + i];
        a[start + i] = av.add_vartime(&t);
        a[start + half + i] = av.sub_vartime(&t);
    }
}

#[cfg(feature = "alloc")]
pub fn range_check_debug(word_debug: &str, range: usize) -> String {
    alloc::format!("range_check({}, {})", word_debug, range)
}

/// `Halo2Utils.boolCheck` / `rangeCheck` / `ternary` over expressions.
pub fn bool_check_expr(
    value: crate::zk::orchard_halo2::plonk::expression::Expression,
) -> Halo2Result<crate::zk::orchard_halo2::plonk::expression::Expression> {
    range_check_expr(value, 2)
}

pub fn range_check_expr(
    word: crate::zk::orchard_halo2::plonk::expression::Expression,
    range: usize,
) -> Halo2Result<crate::zk::orchard_halo2::plonk::expression::Expression> {
    use crate::zk::orchard_halo2::plonk::expression::Expression;
    let mut acc = word.clone();
    for i in 1..range {
        let term = Expression::constant(PallasFp::from_u64(i as u64)).try_sub(&word)?;
        acc = acc.try_mul_expr(&term)?;
    }
    Ok(acc)
}

pub fn ternary_expr(
    a: &crate::zk::orchard_halo2::plonk::expression::Expression,
    b: &crate::zk::orchard_halo2::plonk::expression::Expression,
    c: &crate::zk::orchard_halo2::plonk::expression::Expression,
) -> Halo2Result<crate::zk::orchard_halo2::plonk::expression::Expression> {
    use crate::zk::orchard_halo2::plonk::expression::Expression;
    let one_minus_a = Expression::constant(PallasFp::one()).try_sub(a)?;
    a.try_mul_expr(b)?.try_add(&one_minus_a.try_mul_expr(c)?)
}

/// Number of bits of the Pallas base field (`PallasFPConst.numBits`).
pub const PALLAS_NUM_BITS: usize = 255;
/// Field capacity bits (numBits - 1).
pub const PALLAS_CAPACITY_BITS: usize = 254;
/// Sinsemilla word size `K` (`HashDomainConst.K`).
pub const SINSEMILLA_K: usize = 10;
/// Short scalar window params (`lScalarShort`/`numWindowShort`).
pub const L_SCALAR_SHORT: usize = 64;
pub const NUM_WINDOW_SHORT: usize = 22;

/// `Halo2Utils.bitrangeSubset`: LE bits `[start..end)` accumulated
/// MSB-first. `end > 255` → Err.
pub fn bitrange_subset(elem: PallasFp, start: usize, end: usize) -> Halo2Result<PallasFp> {
    if end > PALLAS_NUM_BITS || start > end {
        return Err(Halo2Error::operation_failed(
            "bitrange_subset",
            "range overflow",
        ));
    }
    let mut bits = [false; 256];
    elem.to_bits_le(&mut bits);
    let mut acc = PallasFp::zero();
    let one = PallasFp::one();
    for i in (start..end).rev() {
        acc = acc.double();
        if bits[i] {
            acc = acc.add_vartime(&one);
        }
    }
    Ok(acc)
}

/// `Halo2Utils.decomposeWord`: LE bits → `window`-bit limbs.
/// `window > 8` → Err.
#[cfg(feature = "alloc")]
pub fn decompose_word(
    word: PallasFp,
    word_num_bits: usize,
    window_num_bits: usize,
) -> Halo2Result<Vec<u8>> {
    // `Vec` is prelude under `std`; import from `alloc` only for `no_std`.
    #[cfg(not(feature = "std"))]
    use alloc::vec::Vec;
    let mut bits = [false; 256];
    word.to_bits_le(&mut bits);
    decompose_bits(&bits, word_num_bits, window_num_bits)
}

/// Vesta-scalar variant (fixed-base windows).
#[cfg(feature = "alloc")]
pub fn decompose_word_vesta(
    word: crate::zk::orchard_halo2::field::VestaFq,
    word_num_bits: usize,
    window_num_bits: usize,
) -> Halo2Result<Vec<u8>> {
    // `Vec` is prelude under `std`; import from `alloc` only for `no_std`.
    #[cfg(not(feature = "std"))]
    use alloc::vec::Vec;
    let mut bits = [false; 256];
    word.to_bits_le(&mut bits);
    decompose_bits(&bits, word_num_bits, window_num_bits)
}

#[cfg(feature = "alloc")]
fn decompose_bits(
    bits: &[bool; 256],
    word_num_bits: usize,
    window_num_bits: usize,
) -> Halo2Result<Vec<u8>> {
    // `Vec` is prelude under `std`; import from `alloc` only for `no_std`.
    #[cfg(not(feature = "std"))]
    use alloc::vec::Vec;
    if window_num_bits > 8 || window_num_bits == 0 {
        return Err(Halo2Error::operation_failed("decompose_word", "bad window"));
    }
    let padding = (window_num_bits - (word_num_bits % window_num_bits)) % window_num_bits;
    let total = word_num_bits + padding;
    if total > 256 {
        return Err(Halo2Error::operation_failed(
            "decompose_word",
            "too many bits",
        ));
    }
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < total {
        let mut value: u8 = 0;
        for b in (0..window_num_bits).rev() {
            value = (value << 1) | (bits[i + b] as u8);
        }
        out.push(value);
        i += window_num_bits;
    }
    Ok(out)
}

/// FFT over Vesta projective points (`bestFft(List<VestaNativePoint>)`).
/// Twiddles are Pallas scalars; length must be `2^log_n`. No `assert!`.
pub fn best_fft_points(
    a: &mut [crate::zk::orchard_halo2::curve::VestaProjective],
    omega: PallasFp,
    log_n: u32,
) -> Halo2Result<()> {
    let n = a.len();
    if n != (1usize << log_n) {
        return Err(Halo2Error::operation_failed(
            "best_fft_points",
            "length mismatch",
        ));
    }
    for k in 0..n {
        let rk = bit_reverse(k, log_n);
        if k < rk {
            a.swap(k, rk);
        }
    }
    let mut twiddles: Vec<PallasFp> = Vec::with_capacity(n / 2);
    let mut w = PallasFp::one();
    for _ in 0..n / 2 {
        twiddles.push(w);
        w = w.mul_vartime(&omega);
    }
    let mut twiddle_scalars: Vec<VestaScalar> = Vec::with_capacity(twiddles.len());
    for t in twiddles.iter() {
        twiddle_scalars.push(VestaScalar::from_bytes_le(&t.to_le_bytes())?);
    }
    recursive_butterfly_points(a, 0, n, 1, &twiddle_scalars);
    Ok(())
}

fn recursive_butterfly_points(
    a: &mut [crate::zk::orchard_halo2::curve::VestaProjective],
    start: usize,
    n: usize,
    twiddle_chunk: usize,
    twiddles: &[VestaScalar],
) {
    if n == 2 {
        let t = a[start + 1];
        a[start + 1] = a[start].add_vartime(&t.neg());
        a[start] = a[start].add_vartime(&t);
    } else if n >= 512 && crate::multicore::num_threads() > 1 {
        // Parallel halves (halo2 `join` shape); sequential below the cutoff.
        let half = n / 2;
        let (left_all, right_all) = a.split_at_mut(start + half);
        let left = &mut left_all[start..];
        crate::multicore::scope(|s| {
            let h1 = s.spawn(move || {
                recursive_butterfly_points(left, 0, half, twiddle_chunk * 2, twiddles)
            });
            recursive_butterfly_points(right_all, 0, half, twiddle_chunk * 2, twiddles);
            crate::multicore::Scope::join(h1)
        });
        points_butterfly_combine(a, start, half, twiddle_chunk, twiddles);
    } else {
        let half = n / 2;
        recursive_butterfly_points(a, start, half, twiddle_chunk * 2, twiddles);
        recursive_butterfly_points(a, start + half, half, twiddle_chunk * 2, twiddles);
        points_butterfly_combine(a, start, half, twiddle_chunk, twiddles);
    }
}

/// Combine step for the points butterfly (twiddle mul + add/sub).
fn points_butterfly_combine(
    a: &mut [crate::zk::orchard_halo2::curve::VestaProjective],
    start: usize,
    half: usize,
    twiddle_chunk: usize,
    twiddles: &[VestaScalar],
) {
    {
        let t = a[start + half];
        a[start + half] = a[start].add_vartime(&t.neg());
        a[start] = a[start].add_vartime(&t);
    }
    for i in 1..half {
        let ti = i * twiddle_chunk;
        if ti >= twiddles.len() {
            continue;
        }
        let t = a[start + half + i].mul_vartime(&twiddles[ti]);
        let av = a[start + i];
        a[start + i] = av.add_vartime(&t);
        a[start + half + i] = av.add_vartime(&t.neg());
    }
}
