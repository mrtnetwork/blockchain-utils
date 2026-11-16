//! MD4 hash (RFC 1320).
//!
//! Pure `no_std`, zero-dependency. Provided for legacy / blockchain compatibility
//! (e.g. some older protocols). MD4 is cryptographically broken — do not use
//! for security-sensitive purposes.

use super::error::{HashError, HashResult};

/// MD4 digest length.
pub const MD4_LEN: usize = 16;
const BLOCK_SIZE: usize = 64;

/// MD4 streaming hasher.
#[derive(Clone)]
pub struct Md4 {
    state: [u32; 4],
    buffer: [u8; BLOCK_SIZE],
    buffer_len: usize,
    total_len: u64,
    /// After clean(), further use is a no-op (reference parity).
    cleaned: bool,
}

impl Md4 {
    /// Create a new MD4 hasher.
    pub const fn new() -> Self {
        Self {
            state: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476],
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
            let rem = data.len() - offset;
            self.buffer[..rem].copy_from_slice(&data[offset..]);
            self.buffer_len = rem;
        }
    }

    /// Finalize into `out` (≥ 16 bytes).
    pub fn finalize_into(mut self, out: &mut [u8]) -> HashResult<()> {
        if out.len() < MD4_LEN {
            return Err(HashError::OutputTooSmall);
        }
        let bit_len = self.total_len.wrapping_mul(8);
        let mut padding = [0u8; 64 + 8];
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

    /// Finalize to fixed array.
    pub fn finalize(self) -> HashResult<[u8; MD4_LEN]> {
        let mut out = [0u8; MD4_LEN];
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

        macro_rules! f {
            ($x:expr, $y:expr, $z:expr) => {
                ($x & $y) | (!$x & $z)
            };
        }
        macro_rules! g {
            ($x:expr, $y:expr, $z:expr) => {
                ($x & $y) | ($x & $z) | ($y & $z)
            };
        }
        macro_rules! h {
            ($x:expr, $y:expr, $z:expr) => {
                $x ^ $y ^ $z
            };
        }
        macro_rules! round1 {
            ($a:ident, $b:ident, $c:ident, $d:ident, $k:expr, $s:expr) => {
                $a = $a
                    .wrapping_add(f!($b, $c, $d))
                    .wrapping_add(x[$k])
                    .rotate_left($s);
            };
        }
        macro_rules! round2 {
            ($a:ident, $b:ident, $c:ident, $d:ident, $k:expr, $s:expr) => {
                $a = $a
                    .wrapping_add(g!($b, $c, $d))
                    .wrapping_add(x[$k])
                    .wrapping_add(0x5a827999)
                    .rotate_left($s);
            };
        }
        macro_rules! round3 {
            ($a:ident, $b:ident, $c:ident, $d:ident, $k:expr, $s:expr) => {
                $a = $a
                    .wrapping_add(h!($b, $c, $d))
                    .wrapping_add(x[$k])
                    .wrapping_add(0x6ed9eba1)
                    .rotate_left($s);
            };
        }

        // Round 1
        round1!(a, b, c, d, 0, 3);
        round1!(d, a, b, c, 1, 7);
        round1!(c, d, a, b, 2, 11);
        round1!(b, c, d, a, 3, 19);
        round1!(a, b, c, d, 4, 3);
        round1!(d, a, b, c, 5, 7);
        round1!(c, d, a, b, 6, 11);
        round1!(b, c, d, a, 7, 19);
        round1!(a, b, c, d, 8, 3);
        round1!(d, a, b, c, 9, 7);
        round1!(c, d, a, b, 10, 11);
        round1!(b, c, d, a, 11, 19);
        round1!(a, b, c, d, 12, 3);
        round1!(d, a, b, c, 13, 7);
        round1!(c, d, a, b, 14, 11);
        round1!(b, c, d, a, 15, 19);
        // Round 2
        round2!(a, b, c, d, 0, 3);
        round2!(d, a, b, c, 4, 5);
        round2!(c, d, a, b, 8, 9);
        round2!(b, c, d, a, 12, 13);
        round2!(a, b, c, d, 1, 3);
        round2!(d, a, b, c, 5, 5);
        round2!(c, d, a, b, 9, 9);
        round2!(b, c, d, a, 13, 13);
        round2!(a, b, c, d, 2, 3);
        round2!(d, a, b, c, 6, 5);
        round2!(c, d, a, b, 10, 9);
        round2!(b, c, d, a, 14, 13);
        round2!(a, b, c, d, 3, 3);
        round2!(d, a, b, c, 7, 5);
        round2!(c, d, a, b, 11, 9);
        round2!(b, c, d, a, 15, 13);
        // Round 3
        round3!(a, b, c, d, 0, 3);
        round3!(d, a, b, c, 8, 9);
        round3!(c, d, a, b, 4, 11);
        round3!(b, c, d, a, 12, 15);
        round3!(a, b, c, d, 2, 3);
        round3!(d, a, b, c, 10, 9);
        round3!(c, d, a, b, 6, 11);
        round3!(b, c, d, a, 14, 15);
        round3!(a, b, c, d, 1, 3);
        round3!(d, a, b, c, 9, 9);
        round3!(c, d, a, b, 5, 11);
        round3!(b, c, d, a, 13, 15);
        round3!(a, b, c, d, 3, 3);
        round3!(d, a, b, c, 11, 9);
        round3!(c, d, a, b, 7, 11);
        round3!(b, c, d, a, 15, 15);

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
    }
}

impl Default for Md4 {
    fn default() -> Self {
        Self::new()
    }
}

/// One-shot MD4.
#[inline]
pub fn md4(data: &[u8]) -> HashResult<[u8; MD4_LEN]> {
    let mut h = Md4::new();
    h.update(data);
    h.finalize()
}

impl crate::hash::digest::HashState for Md4 {
    fn clean(&mut self) {
        *self = Self::new();
        self.cleaned = true;
    }
}

impl crate::hash::digest::SerializableHash for Md4 {
    type State = Md4;
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
            md4(b"").unwrap(),
            [
                0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31, 0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0,
                0x89, 0xc0
            ]
        );
    }

    #[test]
    fn abc() {
        assert_eq!(
            md4(b"abc").unwrap(),
            [
                0xa4, 0x48, 0x01, 0x7a, 0xaf, 0x21, 0xd8, 0x52, 0x5f, 0xc1, 0x0a, 0xe8, 0x7a, 0xa6,
                0x72, 0x9d
            ]
        );
    }

    #[test]
    fn message_digest() {
        assert_eq!(
            md4(b"message digest").unwrap(),
            [
                0xd9, 0x13, 0x0a, 0x81, 0x64, 0x54, 0x9f, 0xe8, 0x18, 0x87, 0x48, 0x06, 0xe1, 0xc7,
                0x01, 0x4b
            ]
        );
    }
}
