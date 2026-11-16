//! MD5 hash (RFC 1321).
//!
//! Pure `no_std`, zero-dependency. MD5 is cryptographically broken for
//! collision resistance — provided for legacy compatibility only.

use super::error::{HashError, HashResult};

/// MD5 digest length.
pub const MD5_LEN: usize = 16;
const BLOCK_SIZE: usize = 64;

const T: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

/// MD5 streaming hasher.
#[derive(Clone)]
pub struct Md5 {
    state: [u32; 4],
    buffer: [u8; BLOCK_SIZE],
    buffer_len: usize,
    total_len: u64,
    /// After clean(), further use is a no-op (reference parity).
    cleaned: bool,
}

impl Md5 {
    /// Create a new MD5 hasher.
    pub const fn new() -> Self {
        Self {
            state: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476],
            buffer: [0u8; BLOCK_SIZE],
            buffer_len: 0,
            total_len: 0,
            cleaned: false,
        }
    }

    /// Reset.
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
            let rem = data.len() - offset;
            self.buffer[..rem].copy_from_slice(&data[offset..]);
            self.buffer_len = rem;
        }
    }

    /// Finalize into `out`.
    pub fn finalize_into(mut self, out: &mut [u8]) -> HashResult<()> {
        if out.len() < MD5_LEN {
            return Err(HashError::OutputTooSmall);
        }
        let bit_len = self.total_len.wrapping_mul(8);
        let mut padding = [0u8; 72];
        padding[0] = 0x80;
        let pad_len = if self.buffer_len < 56 {
            56 - self.buffer_len
        } else {
            56 + 64 - self.buffer_len
        };
        self.update(&padding[..pad_len]);
        let mut len_bytes = [0u8; 8];
        len_bytes.copy_from_slice(&bit_len.to_le_bytes());
        self.update(&len_bytes);
        for i in 0..4 {
            out[i * 4..i * 4 + 4].copy_from_slice(&self.state[i].to_le_bytes());
        }
        Ok(())
    }

    /// Finalize to array.
    pub fn finalize(self) -> HashResult<[u8; MD5_LEN]> {
        let mut out = [0u8; MD5_LEN];
        self.finalize_into(&mut out)?;
        Ok(out)
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
        let (mut a, mut b, mut c, mut d) =
            (self.state[0], self.state[1], self.state[2], self.state[3]);

        // Round 1
        for i in 0..16 {
            let f = (b & c) | (!b & d);
            let g = i;
            let tmp = d;
            d = c;
            c = b;
            b = b.wrapping_add(
                a.wrapping_add(f)
                    .wrapping_add(x[g])
                    .wrapping_add(T[i])
                    .rotate_left([7, 12, 17, 22][i % 4]),
            );
            a = tmp;
        }
        // Round 2
        for i in 0..16 {
            let f = (d & b) | (!d & c);
            let g = (5 * i + 1) % 16;
            let tmp = d;
            d = c;
            c = b;
            b = b.wrapping_add(
                a.wrapping_add(f)
                    .wrapping_add(x[g])
                    .wrapping_add(T[16 + i])
                    .rotate_left([5, 9, 14, 20][i % 4]),
            );
            a = tmp;
        }
        // Round 3
        for i in 0..16 {
            let f = b ^ c ^ d;
            let g = (3 * i + 5) % 16;
            let tmp = d;
            d = c;
            c = b;
            b = b.wrapping_add(
                a.wrapping_add(f)
                    .wrapping_add(x[g])
                    .wrapping_add(T[32 + i])
                    .rotate_left([4, 11, 16, 23][i % 4]),
            );
            a = tmp;
        }
        // Round 4
        for i in 0..16 {
            let f = c ^ (b | !d);
            let g = (7 * i) % 16;
            let tmp = d;
            d = c;
            c = b;
            b = b.wrapping_add(
                a.wrapping_add(f)
                    .wrapping_add(x[g])
                    .wrapping_add(T[48 + i])
                    .rotate_left([6, 10, 15, 21][i % 4]),
            );
            a = tmp;
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
    }
}

impl Default for Md5 {
    fn default() -> Self {
        Self::new()
    }
}

/// One-shot MD5.
#[inline]
pub fn md5(data: &[u8]) -> HashResult<[u8; MD5_LEN]> {
    let mut h = Md5::new();
    h.update(data);
    h.finalize()
}

impl crate::hash::digest::HashState for Md5 {
    fn clean(&mut self) {
        *self = Self::new();
        self.cleaned = true;
    }
}

impl crate::hash::digest::SerializableHash for Md5 {
    type State = Md5;
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
        assert_eq!(
            md5(b"").unwrap(),
            [
                0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8,
                0x42, 0x7e
            ]
        );
    }

    #[test]
    fn abc() {
        assert_eq!(
            md5(b"abc").unwrap(),
            [
                0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1,
                0x7f, 0x72
            ]
        );
    }
}
