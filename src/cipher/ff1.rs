//! NIST SP 800-38G FF1 format-preserving encryption.
//!
//! Matches `lib/crypto/crypto/zcrypto/ff1` (FlexibleNumeralString digits
//! and BinaryNumeralString byte/bit packing for radix 2).
//!
//! Encrypt/decrypt return digit bytes (flexible) or packed bit-bytes (binary)
//! so callers can rebuild `FlexibleNumeralString` / `BinaryNumeralString`.

#![cfg(feature = "alloc")]

use super::aes::Aes;
use super::block::BlockCipher;
use super::error::CipherError;
use alloc::vec::Vec;
use alloc::vec;

const BLOCK: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ff1Error {
    InvalidKey,
    InvalidRadix,
    InvalidInput,
    InvalidLength,
    Cipher(CipherError),
}

impl From<CipherError> for Ff1Error {
    fn from(e: CipherError) -> Self {
        Ff1Error::Cipher(e)
    }
}

pub type Ff1Result<T> = Result<T, Ff1Error>;

/// CBC-MAC style PRF used by FF1 (IV = 0), matching the reference implementation.
struct Prf {
    key: Vec<u8>,
    prev: [u8; BLOCK],
    buf: [u8; BLOCK],
    offset: usize,
}

impl Prf {
    fn new(key: &[u8]) -> Ff1Result<Self> {
        // validate key
        let _ = Aes::new(key).map_err(Ff1Error::from)?;
        Ok(Self {
            key: key.to_vec(),
            prev: [0u8; BLOCK],
            buf: [0u8; BLOCK],
            offset: 0,
        })
    }

    fn aes(&self) -> Aes {
        Aes::new(&self.key).expect("key validated")
    }

    fn clone_state(&self) -> Self {
        Self {
            key: self.key.clone(),
            prev: self.prev,
            buf: self.buf,
            offset: self.offset,
        }
    }

    fn update(&mut self, data: &[u8]) {
        let mut pos = 0;
        while pos < data.len() {
            let to_copy = core::cmp::min(BLOCK - self.offset, data.len() - pos);
            self.buf[self.offset..self.offset + to_copy].copy_from_slice(&data[pos..pos + to_copy]);
            self.offset += to_copy;
            pos += to_copy;
            if self.offset == BLOCK {
                self.encrypt_buf();
                self.offset = 0;
            }
        }
    }

    fn encrypt_buf(&mut self) {
        let mut tmp = [0u8; BLOCK];
        for ((t, b), p) in tmp.iter_mut().zip(self.buf.iter()).zip(self.prev.iter()) {
            *t = b ^ p;
        }
        let aes = self.aes();
        let _ = aes.encrypt_block(&mut tmp);
        self.prev = tmp;
        self.buf = tmp;
    }

    fn output(&self) -> Ff1Result<[u8; BLOCK]> {
        if self.offset != 0 {
            return Err(Ff1Error::InvalidInput);
        }
        Ok(self.buf)
    }
}

// Aes needs clone of round keys — add helper via re-key from stored key, or store key.
// We store key bytes and re-create Aes on clone to avoid exposing internal keys.
struct Ff1Ctx {
    key: Vec<u8>,
}

impl Ff1Ctx {
    fn aes(&self) -> Ff1Result<Aes> {
        Aes::new(&self.key).map_err(Ff1Error::from)
    }

    fn prf(&self) -> Ff1Result<Prf> {
        Prf::new(&self.key)
    }
}

/// Minimum / maximum numeral string length for a radix (`FF1Radix`).
fn min_len(radix: u32) -> usize {
    // ceil(log_radix(100)) roughly — reference uses domain rules; NIST min is 2
    let _ = radix;
    2
}

fn max_len(_radix: u32) -> usize {
    // Practical upper bound
    4096
}

fn calculate_b(radix: u32, v: usize) -> usize {
    // b = ceil(v * log2(radix) / 8) via bit-length of (radix^v - 1)
    if radix <= 1 || v == 0 {
        return 0;
    }
    if radix.is_power_of_two() {
        let log_r = radix.trailing_zeros() as usize;
        return (v * log_r).div_ceil(8);
    }
    let mut x = vec![1u8];
    for _ in 0..v {
        mul_add_le(&mut x, radix, 0);
    }
    // x = radix^v; need bitlen(radix^v - 1)
    sub_le(&mut x, &[1]);
    while x.last() == Some(&0) && x.len() > 1 {
        x.pop();
    }
    let top = *x.last().unwrap_or(&0);
    let mut bits = x.len().saturating_sub(1) * 8;
    if top > 0 {
        bits += 8 - top.leading_zeros() as usize;
    } else {
        bits = 0;
    }
    bits.div_ceil(8)
}

fn be_u32(n: u32) -> [u8; 4] {
    n.to_be_bytes()
}

/// Big-endian integer from digits in given radix → BE byte string of length `b`.
fn digits_to_be_bytes(digits: &[u8], radix: u32, b: usize) -> Vec<u8> {
    // value = sum d[i] * radix^(n-1-i)
    let mut val = vec![0u8]; // LE little-endian growing
    for &d in digits {
        // val = val * radix + d
        mul_add_le(&mut val, radix, d as u32);
    }
    // convert LE to BE fixed length b
    while val.len() < b {
        val.push(0);
    }
    if val.len() > b {
        // take low b bytes (mod 2^(8b)) — should fit for valid FF1
        val.truncate(b);
    }
    val.reverse(); // LE -> BE
    val
}

fn mul_add_le(val: &mut Vec<u8>, mul: u32, add: u32) {
    let mut carry = add as u64;
    let m = mul as u64;
    for x in val.iter_mut() {
        let t = (*x as u64) * m + carry;
        *x = (t & 0xff) as u8;
        carry = t >> 8;
    }
    while carry != 0 {
        val.push((carry & 0xff) as u8);
        carry >>= 8;
    }
}

/// BE bytes → unsigned integer → digits of length m in radix (MSB first).
fn add_mod_exp(a_digits: &[u8], s_be: &[u8], radix: u32, m: usize) -> Vec<u8> {
    // (num(a) + int(s_be)) mod radix^m → digits
    let mut a_val = digits_to_le(a_digits, radix);
    let mut s_val = s_be.to_vec();
    s_val.reverse(); // BE -> LE
    let modulus = pow_radix_le(radix, m);
    mod_le(&mut s_val, &modulus);
    add_le(&mut a_val, &s_val);
    mod_le(&mut a_val, &modulus);
    le_to_digits(&a_val, radix, m)
}

fn sub_mod_exp(b_digits: &[u8], s_be: &[u8], radix: u32, m: usize) -> Vec<u8> {
    // (num(b) - int(s_be)) mod radix^m
    let mut b_val = digits_to_le(b_digits, radix);
    let mut s_val = s_be.to_vec();
    s_val.reverse(); // BE -> LE
                     // reduce s mod radix^m first (S is d bytes, may be larger than radix^m)
    let modulus = pow_radix_le(radix, m);
    mod_le(&mut s_val, &modulus);
    // b - s mod m: add modulus until b >= s
    for _ in 0..4 {
        if cmp_le(&b_val, &s_val) >= 0 {
            break;
        }
        add_le(&mut b_val, &modulus);
    }
    sub_le(&mut b_val, &s_val);
    mod_le(&mut b_val, &modulus);
    le_to_digits(&b_val, radix, m)
}

fn digits_to_le(digits: &[u8], radix: u32) -> Vec<u8> {
    let mut val = vec![0u8];
    for &d in digits {
        mul_add_le(&mut val, radix, d as u32);
    }
    val
}

fn le_to_digits(val: &[u8], radix: u32, m: usize) -> Vec<u8> {
    let mut v = val.to_vec();
    let mut digits = vec![0u8; m];
    let r = radix as u64;
    for i in 0..m {
        let mut rem = 0u64;
        for j in (0..v.len()).rev() {
            let cur = (rem << 8) | (v[j] as u64);
            v[j] = (cur / r) as u8;
            rem = cur % r;
        }
        digits[m - 1 - i] = rem as u8;
        while v.last() == Some(&0) && v.len() > 1 {
            v.pop();
        }
    }
    digits
}

fn pow_radix_le(radix: u32, m: usize) -> Vec<u8> {
    let mut v = vec![1u8];
    for _ in 0..m {
        mul_add_le(&mut v, radix, 0);
    }
    v
}

fn add_le(a: &mut Vec<u8>, b: &[u8]) {
    let mut carry = 0u16;
    let n = core::cmp::max(a.len(), b.len());
    a.resize(n, 0);
    for i in 0..n {
        let bb = if i < b.len() { b[i] as u16 } else { 0 };
        let t = a[i] as u16 + bb + carry;
        a[i] = (t & 0xff) as u8;
        carry = t >> 8;
    }
    if carry != 0 {
        a.push(carry as u8);
    }
}

fn sub_le(a: &mut Vec<u8>, b: &[u8]) {
    let mut borrow = 0i16;
    for i in 0..a.len() {
        let bb = if i < b.len() { b[i] as i16 } else { 0 };
        let mut t = a[i] as i16 - bb - borrow;
        if t < 0 {
            t += 256;
            borrow = 1;
        } else {
            borrow = 0;
        }
        a[i] = t as u8;
    }
    while a.last() == Some(&0) && a.len() > 1 {
        a.pop();
    }
}

fn cmp_le(a: &[u8], b: &[u8]) -> i8 {
    let n = core::cmp::max(a.len(), b.len());
    for i in (0..n).rev() {
        let aa = if i < a.len() { a[i] } else { 0 };
        let bb = if i < b.len() { b[i] } else { 0 };
        if aa < bb {
            return -1;
        }
        if aa > bb {
            return 1;
        }
    }
    0
}

fn mod_le(a: &mut Vec<u8>, m: &[u8]) {
    // a := a mod m using long division (LE limbs as base-256 digits)
    if m.is_empty() || (m.len() == 1 && m[0] == 0) {
        return;
    }
    // trim
    while a.last() == Some(&0) && a.len() > 1 {
        a.pop();
    }
    if cmp_le(a, m) < 0 {
        return;
    }
    // Division: process a from high to low producing remainder
    let mut rem = vec![0u8];
    for i in (0..a.len()).rev() {
        // rem = rem * 256 + a[i]
        mul_add_le(&mut rem, 256, a[i] as u32);
        // while rem >= m: rem -= m (at most a few times per step if we divide)
        // Better: estimate quotient digit
        while cmp_le(&rem, m) >= 0 {
            sub_le(&mut rem, m);
        }
    }
    *a = rem;
}

fn generate_s(aes: &Aes, r: &[u8; BLOCK], d: usize) -> Vec<u8> {
    let mut output = Vec::with_capacity(d + BLOCK);
    output.extend_from_slice(r);
    let blocks_needed = d.div_ceil(16);
    for j in 1..=blocks_needed {
        let mut block = *r;
        // XOR with BE encoding of j (16-byte)
        let mut j_bytes = [0u8; 16];
        let mut jj = j as u128;
        for k in 0..16 {
            j_bytes[15 - k] = (jj & 0xff) as u8;
            jj >>= 8;
        }
        for k in 0..16 {
            block[k] ^= j_bytes[k];
        }
        let mut enc = block;
        let _ = aes.encrypt_block(&mut enc);
        output.extend_from_slice(&enc);
    }
    output.truncate(d);
    output
}

/// FF1-encrypt a flexible numeral string (digit array, each digit in `0..radix`).
///
/// Returns ciphertext digits (same length as `pt`), suitable for
/// `FlexibleNumeralString(digits)`.
pub fn ff1_encrypt_flexible(key: &[u8], radix: u32, pt: &[u8], tweak: &[u8]) -> Ff1Result<Vec<u8>> {
    if !(2..=65536).contains(&radix) {
        return Err(Ff1Error::InvalidRadix);
    }
    let n = pt.len();
    if n < min_len(radix) || n > max_len(radix) {
        return Err(Ff1Error::InvalidLength);
    }
    if pt.iter().any(|&d| d as u32 >= radix) {
        return Err(Ff1Error::InvalidInput);
    }

    let ctx = Ff1Ctx { key: key.to_vec() };
    let aes = ctx.aes()?;

    let u = n / 2;
    let v = n - u;
    let mut x_a = pt[..u].to_vec();
    let mut x_b = pt[u..].to_vec();
    let b = calculate_b(radix, v);
    let d = 4 * b.div_ceil(4) + 4;

    // P = [1,2,1] || radix[1..4] BE || 10 || u8 || n BE || t BE
    let mut p = [0u8; 16];
    p[0] = 1;
    p[1] = 2;
    p[2] = 1;
    let rb = be_u32(radix);
    p[3..6].copy_from_slice(&rb[1..4]);
    p[6] = 10;
    p[7] = u as u8;
    let nb = be_u32(n as u32);
    p[8..12].copy_from_slice(&nb);
    let tb = be_u32(tweak.len() as u32);
    p[12..16].copy_from_slice(&tb);

    let mut prf = ctx.prf()?;
    prf.update(&p);
    prf.update(tweak);
    let padding = ((-(tweak.len() as isize + b as isize + 1)).rem_euclid(16)) as usize;
    if padding > 0 {
        prf.update(&vec![0u8; padding]);
    }

    for i in 0..10u8 {
        let mut round = prf.clone_state();
        round.update(&[i]);
        let xb_bytes = digits_to_be_bytes(&x_b, radix, b);
        round.update(&xb_bytes);
        let r = round.output()?;
        let s = generate_s(&aes, &r, d);
        let m = if i % 2 == 0 { u } else { v };
        let x_c = add_mod_exp(&x_a, &s, radix, m);
        x_a = x_b;
        x_b = x_c;
    }

    let mut out = x_a;
    out.extend_from_slice(&x_b);
    Ok(out)
}

/// FF1-decrypt flexible numeral string digits.
pub fn ff1_decrypt_flexible(key: &[u8], radix: u32, ct: &[u8], tweak: &[u8]) -> Ff1Result<Vec<u8>> {
    if !(2..=65536).contains(&radix) {
        return Err(Ff1Error::InvalidRadix);
    }
    let n = ct.len();
    if n < min_len(radix) || n > max_len(radix) {
        return Err(Ff1Error::InvalidLength);
    }
    if ct.iter().any(|&d| d as u32 >= radix) {
        return Err(Ff1Error::InvalidInput);
    }

    let ctx = Ff1Ctx { key: key.to_vec() };
    let aes = ctx.aes()?;

    let u = n / 2;
    let v = n - u;
    let mut x_a = ct[..u].to_vec();
    let mut x_b = ct[u..].to_vec();
    let b = calculate_b(radix, v);
    let d = 4 * b.div_ceil(4) + 4;

    let mut p = [0u8; 16];
    p[0] = 1;
    p[1] = 2;
    p[2] = 1;
    let rb = be_u32(radix);
    p[3..6].copy_from_slice(&rb[1..4]);
    p[6] = 10;
    p[7] = u as u8;
    let nb = be_u32(n as u32);
    p[8..12].copy_from_slice(&nb);
    let tb = be_u32(tweak.len() as u32);
    p[12..16].copy_from_slice(&tb);

    let mut prf = ctx.prf()?;
    prf.update(&p);
    prf.update(tweak);
    let padding = ((-(tweak.len() as isize + b as isize + 1)).rem_euclid(16)) as usize;
    if padding > 0 {
        prf.update(&vec![0u8; padding]);
    }

    for i in 0..10u8 {
        let e = 9 - i;
        let mut round = prf.clone_state();
        round.update(&[e]);
        let xa_bytes = digits_to_be_bytes(&x_a, radix, b);
        round.update(&xa_bytes);
        let r = round.output()?;
        let s = generate_s(&aes, &r, d);
        let m = if e % 2 == 0 { u } else { v };
        let x_c = sub_mod_exp(&x_b, &s, radix, m);
        x_b = x_a;
        x_a = x_c;
    }

    let mut out = x_a;
    out.extend_from_slice(&x_b);
    Ok(out)
}

// ---------------------------------------------------------------------------
// BinaryNumeralString (radix = 2) — matches the reference implementation
// ---------------------------------------------------------------------------

fn reverse_bits8(b: u8) -> u8 {
    let mut x = b;
    x = ((x & 0xF0) >> 4) | ((x & 0x0F) << 4);
    x = ((x & 0xCC) >> 2) | ((x & 0x33) << 2);
    x = ((x & 0xAA) >> 1) | ((x & 0x55) << 1);
    x
}

#[derive(Clone, Debug)]
struct BinaryNS {
    data: Vec<u8>,
    num_bits: usize,
}

impl BinaryNS {
    fn from_packed(data: &[u8]) -> Self {
        Self {
            data: data.to_vec(),
            num_bits: data.len() * 8,
        }
    }

    fn numeral_count(&self) -> usize {
        self.num_bits
    }

    /// `split()`.
    fn split(&self) -> (Self, Self) {
        let n = self.numeral_count();
        let u = n / 2;
        let v = n - u;
        let a_end = u.div_ceil(8);
        let b_start = u / 8;
        let a_slice = &self.data[..a_end.min(self.data.len())];
        let b_slice = if b_start < self.data.len() {
            &self.data[b_start..]
        } else {
            &[][..]
        };

        let (a_processed, b_processed): (Vec<u8>, Vec<u8>) = if u.is_multiple_of(8) {
            (
                a_slice.iter().map(|&b| reverse_bits8(b)).collect(),
                b_slice.iter().map(|&b| reverse_bits8(b)).collect(),
            )
        } else {
            let mut carried = 0u8;
            let mut a_p = Vec::with_capacity(a_slice.len());
            for &b in a_slice {
                let shifted = (b << 4) | (carried >> 4);
                carried = b;
                a_p.push(reverse_bits8(shifted));
            }
            let mut b_p = Vec::with_capacity(b_slice.len());
            for (i, &b) in b_slice.iter().enumerate() {
                let rb = reverse_bits8(b);
                b_p.push(if i == 0 { rb & 0x0f } else { rb });
            }
            (a_p, b_p)
        };

        let mut a_rev = a_processed;
        a_rev.reverse();
        let mut b_rev = b_processed;
        b_rev.reverse();
        (
            Self {
                data: a_rev,
                num_bits: u,
            },
            Self {
                data: b_rev,
                num_bits: v,
            },
        )
    }

    /// `concat(a, b)`.
    fn concat(a: &Self, b: &Self) -> Self {
        let out: Vec<u8> = if a.numeral_count().is_multiple_of(8) {
            let mut tmp: Vec<u8> = b
                .data
                .iter()
                .chain(a.data.iter())
                .copied()
                .map(reverse_bits8)
                .collect();
            tmp.reverse();
            tmp
        } else {
            let a_last = (a.data.first().copied().unwrap_or(0) & 0x0f) << 4;
            let mut carried = 0u8;
            let mut a_processed: Vec<u8> = Vec::new();
            for &next in &a.data {
                let shifted = (next << 4) | carried;
                carried = next >> 4;
                a_processed.push(reverse_bits8(shifted));
            }
            // skip(1)
            let a_processed: Vec<u8> = a_processed.into_iter().skip(1).collect();

            // b.data.reversed.indexed.toList().reversed.map
            // Ref: b.data.reversed.indexed.toList().reversed
            // = original order of b.data, but index from reversed view?
            // .reversed.indexed → (0, last), (1, second last), ...
            // .toList().reversed → (len-1, first), ..., (0, last) wait
            // Actually: b.data.reversed.indexed.toList().reversed
            //   step1: reverse b
            //   step2: index them 0..n-1
            //   step3: reverse the list of (index, value) pairs
            // So final first element is (n-1, b[0]? no)
            // b = [b0,b1,...,b_{n-1}]
            // reversed = [b_{n-1}, ..., b0]
            // indexed = [(0, b_{n-1}), (1, b_{n-2}), ..., (n-1, b0)]
            // reversed list = [(n-1, b0), (n-2, b1), ..., (0, b_{n-1})]
            // map: e.$1==0 ? aLast|e.$2 : e.$2  → only when index==0 i.e. last element of original order after reverse = b_{n-1}
            // So combined with aLast only for the last byte of b in the mapped output order...
            // Output of map in that order then [...bProcessed, ...aProcessed].reversed

            let _n = b.data.len();
            let mut pairs: Vec<(usize, u8)> = b
                .data
                .iter()
                .rev()
                .enumerate()
                .map(|(i, &v)| (i, v))
                .collect();
            pairs.reverse(); // now (n-1, b0), (n-2, b1), ..., (0, b_{n-1})
            let b_processed: Vec<u8> = pairs
                .into_iter()
                .map(|(idx, val)| {
                    let combined = if idx == 0 { a_last | val } else { val };
                    reverse_bits8(combined)
                })
                .collect();
            let mut tmp: Vec<u8> = b_processed.into_iter().chain(a_processed).collect();
            tmp.reverse();
            tmp
        };
        Self::from_packed(&out)
    }

    /// Integer value of bit-string (LE bytes of `data`).
    fn num_le(&self) -> Vec<u8> {
        // LE interpretation: data already is the LE byte array
        let mut v = self.data.clone();
        while v.last() == Some(&0) && v.len() > 1 {
            v.pop();
        }
        v
    }

    /// Write integer as LE into a buffer of same length as self.data.
    fn str_from_le(&self, le: &[u8]) -> Self {
        let mut data = vec![0u8; self.data.len()];
        let n = core::cmp::min(le.len(), data.len());
        data[..n].copy_from_slice(&le[..n]);
        Self {
            data,
            num_bits: self.num_bits,
        }
    }

    fn to_be_bytes(&self, b: usize) -> Vec<u8> {
        // num as LE → BE length b
        let mut le = self.num_le();
        while le.len() < b {
            le.push(0);
        }
        if le.len() > b {
            le.truncate(b);
        }
        le.reverse();
        le
    }

    fn add_mod_exp(&self, s_be: &[u8], m: usize) -> Self {
        debug_assert_eq!(self.num_bits, m);
        let mut a_val = self.num_le();
        let mut s_val = s_be.to_vec();
        s_val.reverse(); // BE → LE
                         // modulus = 2^m
        let modulus = pow2_le(m);
        mod_le(&mut s_val, &modulus);
        add_le(&mut a_val, &s_val);
        mod_le(&mut a_val, &modulus);
        self.str_from_le(&a_val)
    }

    fn sub_mod_exp(&self, s_be: &[u8], m: usize) -> Self {
        debug_assert_eq!(self.num_bits, m);
        let mut b_val = self.num_le();
        let mut s_val = s_be.to_vec();
        s_val.reverse();
        let modulus = pow2_le(m);
        mod_le(&mut s_val, &modulus);
        for _ in 0..4 {
            if cmp_le(&b_val, &s_val) >= 0 {
                break;
            }
            add_le(&mut b_val, &modulus);
        }
        sub_le(&mut b_val, &s_val);
        mod_le(&mut b_val, &modulus);
        self.str_from_le(&b_val)
    }
}

fn pow2_le(bits: usize) -> Vec<u8> {
    // 2^bits as LE bytes
    let nbytes = bits / 8 + 1;
    let mut v = vec![0u8; nbytes];
    let byte = bits / 8;
    let bit = bits % 8;
    if byte < v.len() {
        v[byte] = 1u8 << bit;
    }
    // trim
    while v.last() == Some(&0) && v.len() > 1 {
        v.pop();
    }
    v
}

/// FF1-encrypt packed binary data (radix 2). Returns ciphertext bytes
/// suitable for `BinaryNumeralString(data)`.
pub fn ff1_encrypt_binary(key: &[u8], pt: &[u8], tweak: &[u8]) -> Ff1Result<Vec<u8>> {
    let radix = 2u32;
    let x = BinaryNS::from_packed(pt);
    let n = x.numeral_count();
    if n < min_len(radix) || n > max_len(radix) {
        return Err(Ff1Error::InvalidLength);
    }
    let ctx = Ff1Ctx { key: key.to_vec() };
    let aes = ctx.aes()?;

    let (mut x_a, mut x_b) = x.split();
    let u = x_a.numeral_count();
    let v = x_b.numeral_count();
    let b = calculate_b(radix, v);
    let d = 4 * b.div_ceil(4) + 4;

    let mut p = [0u8; 16];
    p[0] = 1;
    p[1] = 2;
    p[2] = 1;
    let rb = be_u32(radix);
    p[3..6].copy_from_slice(&rb[1..4]);
    p[6] = 10;
    p[7] = u as u8;
    let nb = be_u32(n as u32);
    p[8..12].copy_from_slice(&nb);
    let tb = be_u32(tweak.len() as u32);
    p[12..16].copy_from_slice(&tb);

    let mut prf = ctx.prf()?;
    prf.update(&p);
    prf.update(tweak);
    let padding = ((-(tweak.len() as isize + b as isize + 1)).rem_euclid(16)) as usize;
    if padding > 0 {
        prf.update(&vec![0u8; padding]);
    }

    for i in 0..10u8 {
        let mut round = prf.clone_state();
        round.update(&[i]);
        let xb_bytes = x_b.to_be_bytes(b);
        round.update(&xb_bytes);
        let r = round.output()?;
        let s = generate_s(&aes, &r, d);
        let m = if i % 2 == 0 { u } else { v };
        let x_c = x_a.add_mod_exp(&s, m);
        x_a = x_b;
        x_b = x_c;
    }

    Ok(BinaryNS::concat(&x_a, &x_b).data)
}

/// FF1-decrypt packed binary data (radix 2).
pub fn ff1_decrypt_binary(key: &[u8], ct: &[u8], tweak: &[u8]) -> Ff1Result<Vec<u8>> {
    let radix = 2u32;
    let x = BinaryNS::from_packed(ct);
    let n = x.numeral_count();
    if n < min_len(radix) || n > max_len(radix) {
        return Err(Ff1Error::InvalidLength);
    }
    let ctx = Ff1Ctx { key: key.to_vec() };
    let aes = ctx.aes()?;

    let (mut x_a, mut x_b) = x.split();
    let u = x_a.numeral_count();
    let v = x_b.numeral_count();
    let b = calculate_b(radix, v);
    let d = 4 * b.div_ceil(4) + 4;

    let mut p = [0u8; 16];
    p[0] = 1;
    p[1] = 2;
    p[2] = 1;
    let rb = be_u32(radix);
    p[3..6].copy_from_slice(&rb[1..4]);
    p[6] = 10;
    p[7] = u as u8;
    let nb = be_u32(n as u32);
    p[8..12].copy_from_slice(&nb);
    let tb = be_u32(tweak.len() as u32);
    p[12..16].copy_from_slice(&tb);

    let mut prf = ctx.prf()?;
    prf.update(&p);
    prf.update(tweak);
    let padding = ((-(tweak.len() as isize + b as isize + 1)).rem_euclid(16)) as usize;
    if padding > 0 {
        prf.update(&vec![0u8; padding]);
    }

    for i in 0..10u8 {
        let e = 9 - i;
        let mut round = prf.clone_state();
        round.update(&[e]);
        let xa_bytes = x_a.to_be_bytes(b);
        round.update(&xa_bytes);
        let r = round.output()?;
        let s = generate_s(&aes, &r, d);
        let m = if e % 2 == 0 { u } else { v };
        let x_c = x_b.sub_mod_exp(&s, m);
        x_b = x_a;
        x_a = x_c;
    }

    Ok(BinaryNS::concat(&x_a, &x_b).data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hx(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn nist_sample1_radix10() {
        // key AES-128, radix 10, pt digits 0..9, empty tweak
        let key = hx("2b7e151628aed2a6abf7158809cf4f3c");
        let pt = hx("00010203040506070809");
        let expect = hx("02040303040707040804");
        let ct = ff1_encrypt_flexible(&key, 10, &pt, &[]).unwrap();
        assert_eq!(ct, expect, "encrypt");
        let dec = ff1_decrypt_flexible(&key, 10, &expect, &[]).unwrap();
        assert_eq!(dec, pt, "decrypt of NIST ct");
        let dec2 = ff1_decrypt_flexible(&key, 10, &ct, &[]).unwrap();
        assert_eq!(dec2, pt, "decrypt of our ct");
    }

    #[test]
    fn nist_sample2_radix10_tweak() {
        let key = hx("2b7e151628aed2a6abf7158809cf4f3c");
        let pt = hx("00010203040506070809");
        let tweak = hx("39383736353433323130");
        let expect = hx("06010204020000070703");
        let ct = ff1_encrypt_flexible(&key, 10, &pt, &tweak).unwrap();
        assert_eq!(ct, expect);
        let dec = ff1_decrypt_flexible(&key, 10, &ct, &tweak).unwrap();
        assert_eq!(dec, pt);
    }

    #[test]
    fn nist_binary_aes256() {
        // AES-256, radix 2 packed binary, empty tweak
        let key = hx("2b7e151628aed2a6abf7158809cf4f3cef4359d8d580aa4f7f036d6f04fc6a94");
        let pt = hx("90acee3f83cde7ae5622f3");
        let expect = hx("5b8bf120f39bab8527ea1b");
        let ct = ff1_encrypt_binary(&key, &pt, &[]).unwrap();
        assert_eq!(ct, expect, "binary encrypt");
        let dec = ff1_decrypt_binary(&key, &ct, &[]).unwrap();
        assert_eq!(dec, pt, "binary decrypt");
    }

    #[test]
    fn nist_binary_aes256_all_a() {
        let key = hx("2b7e151628aed2a6abf7158809cf4f3cef4359d8d580aa4f7f036d6f04fc6a94");
        let pt = hx("aaaaaaaaaaaaaaaaaaaaaa");
        let expect = hx("f082b7ee8f29c07691ce64");
        let ct = ff1_encrypt_binary(&key, &pt, &[]).unwrap();
        assert_eq!(ct, expect);
        let dec = ff1_decrypt_binary(&key, &ct, &[]).unwrap();
        assert_eq!(dec, pt);
    }

    #[test]
    fn nist_radix36() {
        let key = hx("2b7e151628aed2a6abf7158809cf4f3c");
        let pt = hx("000102030405060708090a0b0c0d0e0f101112");
        let tweak = hx("3737373770717273373737");
        let expect = hx("0a091d1f040016151509140d1e0500090e1e16");
        let ct = ff1_encrypt_flexible(&key, 36, &pt, &tweak).unwrap();
        assert_eq!(ct, expect);
        let dec = ff1_decrypt_flexible(&key, 36, &ct, &tweak).unwrap();
        assert_eq!(dec, pt);
    }
}
