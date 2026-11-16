//! RIPEMD-128, RIPEMD-256, RIPEMD-320 (ISO/IEC 10118-3).
//!
//! Pure `no_std`, zero-dependency. Complements [`super::ripemd160`].

use super::error::HashResult;

const BLOCK: usize = 64;

pub const RIPEMD128_LEN: usize = 16;
pub const RIPEMD256_LEN: usize = 32;
pub const RIPEMD320_LEN: usize = 40;

// Shared nonlinear functions (128-bit family uses 4 rounds × 16).
#[inline(always)]
fn f128(j: usize, x: u32, y: u32, z: u32) -> u32 {
    match j {
        0..=15 => x ^ y ^ z,
        16..=31 => (x & y) | (!x & z),
        32..=47 => (x | !y) ^ z,
        _ => (x & z) | (y & !z), // 48..=63
    }
}

#[inline(always)]
fn k128(j: usize) -> u32 {
    match j {
        0..=15 => 0x0000_0000,
        16..=31 => 0x5a82_7999,
        32..=47 => 0x6ed9_eba1,
        _ => 0x8f1b_bcdc,
    }
}

#[inline(always)]
fn kk128(j: usize) -> u32 {
    match j {
        0..=15 => 0x50a2_8be6,
        16..=31 => 0x5c4d_d124,
        32..=47 => 0x6d70_3ef3,
        _ => 0x0000_0000,
    }
}

// Selection/permutation tables for 128-bit family (64 steps).
const R128: [usize; 64] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5,
    2, 14, 11, 8, 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4,
    13, 3, 7, 15, 14, 5, 6, 2,
];
const RR128: [usize; 64] = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12,
    4, 9, 1, 2, 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5,
    12, 2, 13, 9, 7, 10, 14,
];
const S128: [u32; 64] = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15,
    9, 11, 7, 13, 12, 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14,
    15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
];
const SS128: [u32; 64] = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12,
    7, 6, 15, 13, 11, 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14,
    6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
];

// 160-family tables (80 steps) — same as ripemd160.
const R160: [usize; 80] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5,
    2, 14, 11, 8, 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4,
    13, 3, 7, 15, 14, 5, 6, 2, 4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
];
const RR160: [usize; 80] = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12,
    4, 9, 1, 2, 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5,
    12, 2, 13, 9, 7, 10, 14, 12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
];
const S160: [u32; 80] = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15,
    9, 11, 7, 13, 12, 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14,
    15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12, 9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
];
const SS160: [u32; 80] = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12,
    7, 6, 15, 13, 11, 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14,
    6, 14, 6, 9, 12, 9, 12, 5, 15, 8, 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
];

#[inline(always)]
fn f160(j: usize, x: u32, y: u32, z: u32) -> u32 {
    match j {
        0..=15 => x ^ y ^ z,
        16..=31 => (x & y) | (!x & z),
        32..=47 => (x | !y) ^ z,
        48..=63 => (x & z) | (y & !z),
        _ => x ^ (y | !z),
    }
}

#[inline(always)]
fn k160(j: usize) -> u32 {
    match j {
        0..=15 => 0x0000_0000,
        16..=31 => 0x5a82_7999,
        32..=47 => 0x6ed9_eba1,
        48..=63 => 0x8f1b_bcdc,
        _ => 0xa953_fd4e,
    }
}

#[inline(always)]
fn kk160(j: usize) -> u32 {
    match j {
        0..=15 => 0x50a2_8be6,
        16..=31 => 0x5c4d_d124,
        32..=47 => 0x6d70_3ef3,
        48..=63 => 0x7a6d_76e9,
        _ => 0x0000_0000,
    }
}

fn load_block(block: &[u8; BLOCK]) -> [u32; 16] {
    let mut x = [0u32; 16];
    for i in 0..16 {
        x[i] = u32::from_le_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }
    x
}

fn pad_and_finish<F>(
    buffer: &mut [u8; BLOCK],
    buffer_len: &mut usize,
    total_len: u64,
    mut process: F,
) where
    F: FnMut(&[u8; BLOCK]),
{
    let bit_len = total_len.wrapping_mul(8);
    buffer[*buffer_len] = 0x80;
    *buffer_len += 1;
    if *buffer_len > 56 {
        for b in &mut buffer[*buffer_len..BLOCK] {
            *b = 0;
        }
        process(buffer);
        *buffer_len = 0;
    }
    for b in &mut buffer[*buffer_len..56] {
        *b = 0;
    }
    buffer[56..64].copy_from_slice(&bit_len.to_le_bytes());
    process(buffer);
}

// ---- RIPEMD-128 ----

#[derive(Clone)]
pub struct Ripemd128 {
    state: [u32; 4],
    buffer: [u8; BLOCK],
    buffer_len: usize,
    total_len: u64,
    /// After clean(), further use is a no-op (reference parity).
    cleaned: bool,
}

impl Ripemd128 {
    pub const fn new() -> Self {
        Self {
            state: [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476],
            buffer: [0; BLOCK],
            buffer_len: 0,
            total_len: 0,
            cleaned: false,
        }
    }

    pub fn reset(&mut self) {
        if self.cleaned {
            return;
        }
        *self = Self::new();
    }

    pub fn update(&mut self, data: &[u8]) {
        if self.cleaned {
            return;
        }
        let mut offset = 0;
        if self.buffer_len > 0 {
            let need = BLOCK - self.buffer_len;
            let take = need.min(data.len());
            self.buffer[self.buffer_len..self.buffer_len + take].copy_from_slice(&data[..take]);
            self.buffer_len += take;
            offset += take;
            if self.buffer_len == BLOCK {
                let blk = self.buffer;
                self.process_block(&blk);
                self.buffer_len = 0;
            }
        }
        while offset + BLOCK <= data.len() {
            let mut blk = [0u8; BLOCK];
            blk.copy_from_slice(&data[offset..offset + BLOCK]);
            self.process_block(&blk);
            offset += BLOCK;
        }
        if offset < data.len() {
            let rest = &data[offset..];
            self.buffer[..rest.len()].copy_from_slice(rest);
            self.buffer_len = rest.len();
        }
        self.total_len = self.total_len.wrapping_add(data.len() as u64);
    }

    pub fn finalize_into(mut self, out: &mut [u8]) {
        assert!(out.len() >= RIPEMD128_LEN);
        let mut buf = self.buffer;
        let mut bl = self.buffer_len;
        pad_and_finish(&mut buf, &mut bl, self.total_len, |b| self.process_block(b));
        for i in 0..4 {
            out[i * 4..i * 4 + 4].copy_from_slice(&self.state[i].to_le_bytes());
        }
    }

    pub fn finalize(self) -> [u8; RIPEMD128_LEN] {
        let mut out = [0u8; RIPEMD128_LEN];
        self.finalize_into(&mut out);
        out
    }

    fn process_block(&mut self, block: &[u8; BLOCK]) {
        let x = load_block(block);
        let mut al = self.state[0];
        let mut bl = self.state[1];
        let mut cl = self.state[2];
        let mut dl = self.state[3];
        let mut ar = self.state[0];
        let mut br = self.state[1];
        let mut cr = self.state[2];
        let mut dr = self.state[3];

        for j in 0..64 {
            let t = al
                .wrapping_add(f128(j, bl, cl, dl))
                .wrapping_add(x[R128[j]])
                .wrapping_add(k128(j))
                .rotate_left(S128[j]);
            al = dl;
            dl = cl;
            cl = bl;
            bl = t;

            let t = ar
                .wrapping_add(f128(63 - j, br, cr, dr))
                .wrapping_add(x[RR128[j]])
                .wrapping_add(kk128(j))
                .rotate_left(SS128[j]);
            ar = dr;
            dr = cr;
            cr = br;
            br = t;
        }

        let t = self.state[1].wrapping_add(cl).wrapping_add(dr);
        self.state[1] = self.state[2].wrapping_add(dl).wrapping_add(ar);
        self.state[2] = self.state[3].wrapping_add(al).wrapping_add(br);
        self.state[3] = self.state[0].wrapping_add(bl).wrapping_add(cr);
        self.state[0] = t;
    }
}

impl Default for Ripemd128 {
    fn default() -> Self {
        Self::new()
    }
}

pub fn ripemd128(data: &[u8]) -> HashResult<[u8; RIPEMD128_LEN]> {
    let mut h = Ripemd128::new();
    h.update(data);
    Ok(h.finalize())
}

// ---- RIPEMD-256 ----

#[derive(Clone)]
pub struct Ripemd256 {
    state: [u32; 8],
    buffer: [u8; BLOCK],
    buffer_len: usize,
    total_len: u64,
    /// After clean(), further use is a no-op (reference parity).
    cleaned: bool,
}

impl Ripemd256 {
    pub const fn new() -> Self {
        Self {
            // Left chain = RIPEMD-128 IV; right chain = complementary
            state: [
                0x6745_2301,
                0xefcd_ab89,
                0x98ba_dcfe,
                0x1032_5476,
                0x7654_3210,
                0xfedc_ba98,
                0x89ab_cdef,
                0x0123_4567,
            ],
            buffer: [0; BLOCK],
            buffer_len: 0,
            total_len: 0,
            cleaned: false,
        }
    }

    pub fn reset(&mut self) {
        if self.cleaned {
            return;
        }
        *self = Self::new();
    }

    pub fn update(&mut self, data: &[u8]) {
        if self.cleaned {
            return;
        }
        let mut offset = 0;
        if self.buffer_len > 0 {
            let need = BLOCK - self.buffer_len;
            let take = need.min(data.len());
            self.buffer[self.buffer_len..self.buffer_len + take].copy_from_slice(&data[..take]);
            self.buffer_len += take;
            offset += take;
            if self.buffer_len == BLOCK {
                let blk = self.buffer;
                self.process_block(&blk);
                self.buffer_len = 0;
            }
        }
        while offset + BLOCK <= data.len() {
            let mut blk = [0u8; BLOCK];
            blk.copy_from_slice(&data[offset..offset + BLOCK]);
            self.process_block(&blk);
            offset += BLOCK;
        }
        if offset < data.len() {
            let rest = &data[offset..];
            self.buffer[..rest.len()].copy_from_slice(rest);
            self.buffer_len = rest.len();
        }
        self.total_len = self.total_len.wrapping_add(data.len() as u64);
    }

    pub fn finalize_into(mut self, out: &mut [u8]) {
        assert!(out.len() >= RIPEMD256_LEN);
        let mut buf = self.buffer;
        let mut bl = self.buffer_len;
        pad_and_finish(&mut buf, &mut bl, self.total_len, |b| self.process_block(b));
        for i in 0..8 {
            out[i * 4..i * 4 + 4].copy_from_slice(&self.state[i].to_le_bytes());
        }
    }

    pub fn finalize(self) -> [u8; RIPEMD256_LEN] {
        let mut out = [0u8; RIPEMD256_LEN];
        self.finalize_into(&mut out);
        out
    }

    fn process_block(&mut self, block: &[u8; BLOCK]) {
        let x = load_block(block);
        let mut al = self.state[0];
        let mut bl = self.state[1];
        let mut cl = self.state[2];
        let mut dl = self.state[3];
        let mut ar = self.state[4];
        let mut br = self.state[5];
        let mut cr = self.state[6];
        let mut dr = self.state[7];

        for j in 0..64 {
            let t = al
                .wrapping_add(f128(j, bl, cl, dl))
                .wrapping_add(x[R128[j]])
                .wrapping_add(k128(j))
                .rotate_left(S128[j]);
            al = dl;
            dl = cl;
            cl = bl;
            bl = t;

            let t = ar
                .wrapping_add(f128(63 - j, br, cr, dr))
                .wrapping_add(x[RR128[j]])
                .wrapping_add(kk128(j))
                .rotate_left(SS128[j]);
            ar = dr;
            dr = cr;
            cr = br;
            br = t;

            // Intermediate swaps after each 16-step round
            if j == 15 {
                core::mem::swap(&mut al, &mut ar);
            } else if j == 31 {
                core::mem::swap(&mut bl, &mut br);
            } else if j == 47 {
                core::mem::swap(&mut cl, &mut cr);
            } else if j == 63 {
                core::mem::swap(&mut dl, &mut dr);
            }
        }

        self.state[0] = self.state[0].wrapping_add(al);
        self.state[1] = self.state[1].wrapping_add(bl);
        self.state[2] = self.state[2].wrapping_add(cl);
        self.state[3] = self.state[3].wrapping_add(dl);
        self.state[4] = self.state[4].wrapping_add(ar);
        self.state[5] = self.state[5].wrapping_add(br);
        self.state[6] = self.state[6].wrapping_add(cr);
        self.state[7] = self.state[7].wrapping_add(dr);
    }
}

impl Default for Ripemd256 {
    fn default() -> Self {
        Self::new()
    }
}

pub fn ripemd256(data: &[u8]) -> HashResult<[u8; RIPEMD256_LEN]> {
    let mut h = Ripemd256::new();
    h.update(data);
    Ok(h.finalize())
}

// ---- RIPEMD-320 ----

#[derive(Clone)]
pub struct Ripemd320 {
    state: [u32; 10],
    buffer: [u8; BLOCK],
    buffer_len: usize,
    total_len: u64,
    /// After clean(), further use is a no-op (reference parity).
    cleaned: bool,
}

impl Ripemd320 {
    pub const fn new() -> Self {
        Self {
            state: [
                0x6745_2301,
                0xefcd_ab89,
                0x98ba_dcfe,
                0x1032_5476,
                0xc3d2_e1f0,
                0x7654_3210,
                0xfedc_ba98,
                0x89ab_cdef,
                0x0123_4567,
                0x3c2d_1e0f,
            ],
            buffer: [0; BLOCK],
            buffer_len: 0,
            total_len: 0,
            cleaned: false,
        }
    }

    pub fn reset(&mut self) {
        if self.cleaned {
            return;
        }
        *self = Self::new();
    }

    pub fn update(&mut self, data: &[u8]) {
        if self.cleaned {
            return;
        }
        let mut offset = 0;
        if self.buffer_len > 0 {
            let need = BLOCK - self.buffer_len;
            let take = need.min(data.len());
            self.buffer[self.buffer_len..self.buffer_len + take].copy_from_slice(&data[..take]);
            self.buffer_len += take;
            offset += take;
            if self.buffer_len == BLOCK {
                let blk = self.buffer;
                self.process_block(&blk);
                self.buffer_len = 0;
            }
        }
        while offset + BLOCK <= data.len() {
            let mut blk = [0u8; BLOCK];
            blk.copy_from_slice(&data[offset..offset + BLOCK]);
            self.process_block(&blk);
            offset += BLOCK;
        }
        if offset < data.len() {
            let rest = &data[offset..];
            self.buffer[..rest.len()].copy_from_slice(rest);
            self.buffer_len = rest.len();
        }
        self.total_len = self.total_len.wrapping_add(data.len() as u64);
    }

    pub fn finalize_into(mut self, out: &mut [u8]) {
        assert!(out.len() >= RIPEMD320_LEN);
        let mut buf = self.buffer;
        let mut bl = self.buffer_len;
        pad_and_finish(&mut buf, &mut bl, self.total_len, |b| self.process_block(b));
        for i in 0..10 {
            out[i * 4..i * 4 + 4].copy_from_slice(&self.state[i].to_le_bytes());
        }
    }

    pub fn finalize(self) -> [u8; RIPEMD320_LEN] {
        let mut out = [0u8; RIPEMD320_LEN];
        self.finalize_into(&mut out);
        out
    }

    fn process_block(&mut self, block: &[u8; BLOCK]) {
        let x = load_block(block);
        let mut al = self.state[0];
        let mut bl = self.state[1];
        let mut cl = self.state[2];
        let mut dl = self.state[3];
        let mut el = self.state[4];
        let mut ar = self.state[5];
        let mut br = self.state[6];
        let mut cr = self.state[7];
        let mut dr = self.state[8];
        let mut er = self.state[9];

        for j in 0..80 {
            let t = al
                .wrapping_add(f160(j, bl, cl, dl))
                .wrapping_add(x[R160[j]])
                .wrapping_add(k160(j))
                .rotate_left(S160[j])
                .wrapping_add(el);
            al = el;
            el = dl;
            dl = cl.rotate_left(10);
            cl = bl;
            bl = t;

            let t = ar
                .wrapping_add(f160(79 - j, br, cr, dr))
                .wrapping_add(x[RR160[j]])
                .wrapping_add(kk160(j))
                .rotate_left(SS160[j])
                .wrapping_add(er);
            ar = er;
            er = dr;
            dr = cr.rotate_left(10);
            cr = br;
            br = t;

            if j == 15 {
                core::mem::swap(&mut bl, &mut br);
            } else if j == 31 {
                core::mem::swap(&mut dl, &mut dr);
            } else if j == 47 {
                core::mem::swap(&mut al, &mut ar);
            } else if j == 63 {
                core::mem::swap(&mut cl, &mut cr);
            } else if j == 79 {
                core::mem::swap(&mut el, &mut er);
            }
        }

        self.state[0] = self.state[0].wrapping_add(al);
        self.state[1] = self.state[1].wrapping_add(bl);
        self.state[2] = self.state[2].wrapping_add(cl);
        self.state[3] = self.state[3].wrapping_add(dl);
        self.state[4] = self.state[4].wrapping_add(el);
        self.state[5] = self.state[5].wrapping_add(ar);
        self.state[6] = self.state[6].wrapping_add(br);
        self.state[7] = self.state[7].wrapping_add(cr);
        self.state[8] = self.state[8].wrapping_add(dr);
        self.state[9] = self.state[9].wrapping_add(er);
    }
}

impl Default for Ripemd320 {
    fn default() -> Self {
        Self::new()
    }
}

pub fn ripemd320(data: &[u8]) -> HashResult<[u8; RIPEMD320_LEN]> {
    let mut h = Ripemd320::new();
    h.update(data);
    Ok(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> alloc::vec::Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn ripemd128_kat() {
        // Bosselaers / ISO vectors
        assert_eq!(
            ripemd128(b"").unwrap().as_slice(),
            hex("cdf26213a150dc3ecb610f18f6b38b46").as_slice()
        );
        assert_eq!(
            ripemd128(b"abc").unwrap().as_slice(),
            hex("c14a12199c66e4ba84636b0f69144c77").as_slice()
        );
        assert_eq!(
            ripemd128(b"a").unwrap().as_slice(),
            hex("86be7afa339d0fc7cfc785e72f578d33").as_slice()
        );
    }

    #[test]
    fn ripemd256_kat() {
        assert_eq!(
            ripemd256(b"").unwrap().as_slice(),
            hex("02ba4c4e5f8ecd1877fc52d64d30e37a2d9774fb1e5d026380ae0168e3c5522d").as_slice()
        );
        assert_eq!(
            ripemd256(b"abc").unwrap().as_slice(),
            hex("afbd6e228b9d8cbbcef5ca2d03e6dba10ac0bc7dcbe4680e1e42d2e975459b65").as_slice()
        );
    }

    #[test]
    fn ripemd320_kat() {
        assert_eq!(
            ripemd320(b"").unwrap().as_slice(),
            hex("22d65d5661536cdc75c1fdf5c6de7b41b9f27325ebc61e8557177d705a0ec880151c3a32a00899b8")
                .as_slice()
        );
        assert_eq!(
            ripemd320(b"abc").unwrap().as_slice(),
            hex("de4c01b3054f8930a79d09ae738e92301e5a17085beffdc1b8d116713e74f82fa942d64cdbc4682d")
                .as_slice()
        );
    }
}
