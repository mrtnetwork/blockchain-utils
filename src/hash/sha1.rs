//! SHA-1 (FIPS 180-4).
//!
//! Pure `no_std`, zero-dependency. SHA-1 is cryptographically broken for
//! collision resistance — provided for legacy / blockchain compatibility.

use super::error::{HashError, HashResult};

/// SHA-1 digest length.
pub const SHA1_LEN: usize = 20;
const BLOCK_SIZE: usize = 64;

/// SHA-1 streaming hasher.
#[derive(Clone)]
pub struct Sha1 {
    state: [u32; 5],
    buffer: [u8; BLOCK_SIZE],
    buffer_len: usize,
    total_len: u64,
    /// After clean(), further use is a no-op (reference parity).
    cleaned: bool,
}

impl Sha1 {
    /// Create a new SHA-1 hasher.
    pub const fn new() -> Self {
        Self {
            state: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0],
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
        if out.len() < SHA1_LEN {
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
        len_bytes.copy_from_slice(&bit_len.to_be_bytes());
        self.update(&len_bytes);
        for i in 0..5 {
            out[i * 4..i * 4 + 4].copy_from_slice(&self.state[i].to_be_bytes());
        }
        Ok(())
    }

    /// Finalize to array.
    pub fn finalize(self) -> HashResult<[u8; SHA1_LEN]> {
        let mut out = [0u8; SHA1_LEN];
        self.finalize_into(&mut out)?;
        Ok(out)
    }

    fn process_block(&mut self, block: &[u8; BLOCK_SIZE]) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let (mut a, mut b, mut c, mut d, mut e) = (
            self.state[0],
            self.state[1],
            self.state[2],
            self.state[3],
            self.state[4],
        );

        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5a827999u32),
                20..=39 => (b ^ c ^ d, 0x6ed9eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdc),
                _ => (b ^ c ^ d, 0xca62c1d6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
    }
}

impl Default for Sha1 {
    fn default() -> Self {
        Self::new()
    }
}

/// One-shot SHA-1.
#[inline]
pub fn sha1(data: &[u8]) -> HashResult<[u8; SHA1_LEN]> {
    let mut h = Sha1::new();
    h.update(data);
    h.finalize()
}

impl crate::hash::digest::HashState for Sha1 {
    fn clean(&mut self) {
        *self = Self::new();
        self.cleaned = true;
    }
}

impl crate::hash::digest::SerializableHash for Sha1 {
    type State = Sha1;
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
            sha1(b"").unwrap(),
            [
                0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60,
                0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09
            ]
        );
    }

    #[test]
    fn abc() {
        assert_eq!(
            sha1(b"abc").unwrap(),
            [
                0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
                0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d
            ]
        );
    }
}
