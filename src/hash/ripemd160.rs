//! RIPEMD-160 implementation.
//!
//! Pure `no_std`, zero-dependency. Spec: ISO/IEC 10118-3 / original RIPEMD papers.

/// Digest length in bytes.
pub const RIPEMD160_LEN: usize = 20;
const BLOCK_SIZE: usize = 64;

#[inline(always)]
fn f(j: usize, x: u32, y: u32, z: u32) -> u32 {
    match j {
        0..=15 => x ^ y ^ z,
        16..=31 => (x & y) | (!x & z),
        32..=47 => (x | !y) ^ z,
        48..=63 => (x & z) | (y & !z),
        _ => x ^ (y | !z), // 64..=79
    }
}

#[inline(always)]
fn k(j: usize) -> u32 {
    match j {
        0..=15 => 0x00000000,
        16..=31 => 0x5a827999,
        32..=47 => 0x6ed9eba1,
        48..=63 => 0x8f1bbcdc,
        _ => 0xa953fd4e, // 64..=79
    }
}

#[inline(always)]
fn kk(j: usize) -> u32 {
    match j {
        0..=15 => 0x50a28be6,
        16..=31 => 0x5c4dd124,
        32..=47 => 0x6d703ef3,
        48..=63 => 0x7a6d76e9,
        _ => 0x00000000, // 64..=79
    }
}

const R: [usize; 80] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5,
    2, 14, 11, 8, 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4,
    13, 3, 7, 15, 14, 5, 6, 2, 4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
];

const RR: [usize; 80] = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12,
    4, 9, 1, 2, 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5,
    12, 2, 13, 9, 7, 10, 14, 12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
];

const S: [u32; 80] = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15,
    9, 11, 7, 13, 12, 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14,
    15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12, 9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
];

const SS: [u32; 80] = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12,
    7, 6, 15, 13, 11, 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14,
    6, 14, 6, 9, 12, 9, 12, 5, 15, 8, 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
];

/// RIPEMD-160 streaming hasher.
#[derive(Clone)]
pub struct Ripemd160 {
    state: [u32; 5],
    buffer: [u8; BLOCK_SIZE],
    buffer_len: usize,
    total_len: u64,
    /// After clean(), further use is a no-op (reference parity).
    cleaned: bool,
}

impl Ripemd160 {
    /// Create a new hasher.
    pub const fn new() -> Self {
        Self {
            state: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0],
            buffer: [0u8; BLOCK_SIZE],
            buffer_len: 0,
            total_len: 0,
            cleaned: false,
        }
    }

    /// Reset to initial state.
    pub fn reset(&mut self) {
        if self.cleaned {
            return;
        }
        *self = Self::new();
    }

    /// Absorb data.
    pub fn update(&mut self, data: &[u8]) {
        if self.cleaned {
            return;
        }
        self.total_len = self.total_len.wrapping_add(data.len() as u64);
        let mut offset = 0;

        if self.buffer_len > 0 {
            let need = BLOCK_SIZE - self.buffer_len;
            let take = core::cmp::min(need, data.len());
            self.buffer[self.buffer_len..self.buffer_len + take].copy_from_slice(&data[..take]);
            self.buffer_len += take;
            offset += take;
            if self.buffer_len == BLOCK_SIZE {
                let block = self.buffer;
                self.process_block(&block);
                self.buffer_len = 0;
            }
        }

        while offset + BLOCK_SIZE <= data.len() {
            let mut block = [0u8; BLOCK_SIZE];
            block.copy_from_slice(&data[offset..offset + BLOCK_SIZE]);
            self.process_block(&block);
            offset += BLOCK_SIZE;
        }

        if offset < data.len() {
            let remaining = data.len() - offset;
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buffer_len = remaining;
        }
    }

    /// Finalize into a 20-byte buffer.
    pub fn finalize_into(mut self, out: &mut [u8]) {
        assert!(out.len() >= RIPEMD160_LEN);
        let bit_len = self.total_len.wrapping_mul(8);

        let mut padding = [0u8; BLOCK_SIZE + 8];
        padding[0] = 0x80;
        let pad_len = if self.buffer_len < 56 {
            56 - self.buffer_len
        } else {
            56 + BLOCK_SIZE - self.buffer_len
        };
        self.update(&padding[..pad_len]);

        // Length is little-endian for RIPEMD-160.
        let mut len_bytes = [0u8; 8];
        len_bytes.copy_from_slice(&bit_len.to_le_bytes());
        self.update(&len_bytes);

        for i in 0..5 {
            let bytes = self.state[i].to_le_bytes();
            out[i * 4..i * 4 + 4].copy_from_slice(&bytes);
        }
    }

    /// Finalize and return a fixed array.
    pub fn finalize(self) -> [u8; RIPEMD160_LEN] {
        let mut out = [0u8; RIPEMD160_LEN];
        self.finalize_into(&mut out);
        out
    }

    fn process_block(&mut self, block: &[u8; BLOCK_SIZE]) {
        let mut x = [0u32; 16];
        for i in 0..16 {
            x[i] = u32::from_le_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }

        let mut al = self.state[0];
        let mut bl = self.state[1];
        let mut cl = self.state[2];
        let mut dl = self.state[3];
        let mut el = self.state[4];

        let mut ar = self.state[0];
        let mut br = self.state[1];
        let mut cr = self.state[2];
        let mut dr = self.state[3];
        let mut er = self.state[4];

        for j in 0..80 {
            let t = al
                .wrapping_add(f(j, bl, cl, dl))
                .wrapping_add(x[R[j]])
                .wrapping_add(k(j))
                .rotate_left(S[j])
                .wrapping_add(el);
            al = el;
            el = dl;
            dl = cl.rotate_left(10);
            cl = bl;
            bl = t;

            let t = ar
                .wrapping_add(f(79 - j, br, cr, dr))
                .wrapping_add(x[RR[j]])
                .wrapping_add(kk(j))
                .rotate_left(SS[j])
                .wrapping_add(er);
            ar = er;
            er = dr;
            dr = cr.rotate_left(10);
            cr = br;
            br = t;
        }

        let t = self.state[1].wrapping_add(cl).wrapping_add(dr);
        self.state[1] = self.state[2].wrapping_add(dl).wrapping_add(er);
        self.state[2] = self.state[3].wrapping_add(el).wrapping_add(ar);
        self.state[3] = self.state[4].wrapping_add(al).wrapping_add(br);
        self.state[4] = self.state[0].wrapping_add(bl).wrapping_add(cr);
        self.state[0] = t;
    }
}

impl Default for Ripemd160 {
    fn default() -> Self {
        Self::new()
    }
}

/// One-shot RIPEMD-160.
#[inline]
pub fn ripemd160(data: &[u8]) -> crate::hash::HashResult<[u8; RIPEMD160_LEN]> {
    let mut h = Ripemd160::new();
    h.update(data);
    Ok(h.finalize())
}

/// HASH160 = RIPEMD-160(SHA-256(data)) — common in Bitcoin.
#[inline]
pub fn hash160(data: &[u8]) -> crate::hash::HashResult<[u8; RIPEMD160_LEN]> {
    let sha = crate::hash::sha256::sha256(data)?;
    ripemd160(&sha)
}

impl crate::hash::digest::HashState for Ripemd160 {
    fn clean(&mut self) {
        *self = Self::new();
        self.cleaned = true;
    }
}

impl crate::hash::digest::SerializableHash for Ripemd160 {
    type State = Ripemd160;
    fn save_state(&self) -> Self::State {
        self.clone()
    }
    fn restore_state(&mut self, saved: &Self::State) {
        *self = saved.clone();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty() {
        let d = ripemd160(b"").unwrap();
        assert_eq!(
            d,
            [
                0x9c, 0x11, 0x85, 0xa5, 0xc5, 0xe9, 0xfc, 0x54, 0x61, 0x28, 0x08, 0x97, 0x7e, 0xe8,
                0xf5, 0x48, 0xb2, 0x25, 0x8d, 0x31
            ]
        );
    }

    #[test]
    fn abc() {
        let d = ripemd160(b"abc").unwrap();
        assert_eq!(
            d,
            [
                0x8e, 0xb2, 0x08, 0xf7, 0xe0, 0x5d, 0x98, 0x7a, 0x9b, 0x04, 0x4a, 0x8e, 0x98, 0xc6,
                0xb0, 0x87, 0xf1, 0x5a, 0x0b, 0xfc
            ]
        );
    }

    #[test]
    fn message_digest() {
        let d = ripemd160(b"message digest").unwrap();
        assert_eq!(
            d,
            [
                0x5d, 0x06, 0x89, 0xef, 0x49, 0xd2, 0xfa, 0xe5, 0x72, 0xb8, 0x81, 0xb1, 0x23, 0xa8,
                0x5f, 0xfa, 0x21, 0x59, 0x5f, 0x36
            ]
        );
    }
}
