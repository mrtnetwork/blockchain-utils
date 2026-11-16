//! SHA-256 and SHA-224 implementations (FIPS 180-4).
//!
//! Pure `no_std`, zero-dependency, allocation-free.

/// SHA-256 digest length in bytes.
pub const SHA256_LEN: usize = 32;
/// SHA-224 digest length in bytes.
pub const SHA224_LEN: usize = 28;
/// Internal block size.
pub const BLOCK_SIZE: usize = 64;

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[inline(always)]
fn rotr(x: u32, n: u32) -> u32 {
    x.rotate_right(n)
}

#[inline(always)]
fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

#[inline(always)]
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

#[inline(always)]
fn big_sigma0(x: u32) -> u32 {
    rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
}

#[inline(always)]
fn big_sigma1(x: u32) -> u32 {
    rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
}

#[inline(always)]
fn small_sigma0(x: u32) -> u32 {
    rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)
}

#[inline(always)]
fn small_sigma1(x: u32) -> u32 {
    rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)
}

/// SHA-256 / SHA-224 streaming hasher.
#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; BLOCK_SIZE],
    buffer_len: usize,
    /// Total bytes processed (mod 2^64 is enough for practical use).
    total_len: u64,
    /// When true, produce a 224-bit digest.
    is_224: bool,
    /// After clean(), further use is a no-op (reference parity).
    cleaned: bool,
}

impl Sha256 {
    /// Create a new SHA-256 hasher.
    pub const fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buffer: [0u8; BLOCK_SIZE],
            buffer_len: 0,
            total_len: 0,
            is_224: false,
            cleaned: false,
        }
    }

    /// Create a new SHA-224 hasher.
    pub const fn new_224() -> Self {
        Self {
            state: [
                0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7,
                0xbefa4fa4,
            ],
            buffer: [0u8; BLOCK_SIZE],
            buffer_len: 0,
            total_len: 0,
            is_224: true,
            cleaned: false,
        }
    }

    /// Reset the hasher to its initial state.
    pub fn reset(&mut self) {
        if self.cleaned {
            return;
        }
        if self.is_224 {
            *self = Self::new_224();
        } else {
            *self = Self::new();
        }
    }

    /// Absorb more data.
    pub fn update(&mut self, data: &[u8]) {
        if self.cleaned {
            return;
        }
        let mut offset = 0;
        self.total_len = self.total_len.wrapping_add(data.len() as u64);

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

    /// Finalize and write the digest into `out`.
    ///
    /// `out` must be at least 32 bytes for SHA-256 or 28 bytes for SHA-224.
    pub fn finalize_into(mut self, out: &mut [u8]) {
        let bit_len = self.total_len.wrapping_mul(8);

        // Padding: 0x80 then zeros, then 64-bit length.
        let mut padding = [0u8; BLOCK_SIZE + 8];
        padding[0] = 0x80;
        let pad_len = if self.buffer_len < 56 {
            56 - self.buffer_len
        } else {
            56 + BLOCK_SIZE - self.buffer_len
        };

        self.update(&padding[..pad_len]);

        // Append length as big-endian u64.
        let mut len_bytes = [0u8; 8];
        len_bytes.copy_from_slice(&bit_len.to_be_bytes());
        self.update(&len_bytes);

        debug_assert_eq!(self.buffer_len, 0);

        let digest_len = if self.is_224 { SHA224_LEN } else { SHA256_LEN };
        assert!(out.len() >= digest_len);

        for i in 0..8 {
            if i * 4 >= digest_len {
                break;
            }
            let bytes = self.state[i].to_be_bytes();
            let start = i * 4;
            let end = core::cmp::min(start + 4, digest_len);
            out[start..end].copy_from_slice(&bytes[..end - start]);
        }
    }

    /// Finalize and return a fixed 32-byte array (SHA-256).
    /// Panics if this is a SHA-224 hasher.
    pub fn finalize(self) -> [u8; SHA256_LEN] {
        assert!(!self.is_224, "use finalize_into for SHA-224");
        let mut out = [0u8; SHA256_LEN];
        self.finalize_into(&mut out);
        out
    }

    /// Finalize and return a fixed 28-byte array (SHA-224).
    pub fn finalize_224(self) -> [u8; SHA224_LEN] {
        assert!(self.is_224, "use finalize for SHA-256");
        let mut out = [0u8; SHA224_LEN];
        self.finalize_into(&mut out);
        out
    }

    fn process_block(&mut self, block: &[u8; BLOCK_SIZE]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            w[i] = small_sigma1(w[i - 2])
                .wrapping_add(w[i - 7])
                .wrapping_add(small_sigma0(w[i - 15]))
                .wrapping_add(w[i - 16]);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        for i in 0..64 {
            let t1 = h
                .wrapping_add(big_sigma1(e))
                .wrapping_add(ch(e, f, g))
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

/// One-shot SHA-256. Returns `HashResult`.
#[inline]
pub fn sha256(data: &[u8]) -> crate::hash::HashResult<[u8; SHA256_LEN]> {
    let mut h = Sha256::new();
    h.update(data);
    Ok(h.finalize())
}

/// One-shot SHA-224. Returns `HashResult`.
#[inline]
pub fn sha224(data: &[u8]) -> crate::hash::HashResult<[u8; SHA224_LEN]> {
    let mut h = Sha256::new_224();
    h.update(data);
    Ok(h.finalize_224())
}

/// Double SHA-256 (common in Bitcoin). Returns `HashResult`.
#[inline]
pub fn sha256d(data: &[u8]) -> crate::hash::HashResult<[u8; SHA256_LEN]> {
    let first = sha256(data)?;
    sha256(&first)
}

// ---------------------------------------------------------------------------
// Digest trait implementation ( interface)
// ---------------------------------------------------------------------------

impl crate::hash::Digest for Sha256 {
    const OUTPUT_SIZE: usize = SHA256_LEN;
    const BLOCK_SIZE: usize = BLOCK_SIZE;
    const NAME: &'static str = "SHA-256";

    fn new() -> Self {
        // Call the inherent const constructor
        <Sha256 as core::default::Default>::default()
    }

    fn reset(&mut self) {
        *self = <Sha256 as core::default::Default>::default();
    }

    fn update(&mut self, data: &[u8]) {
        // Call inherent method via explicit path to avoid recursion
        Sha256::update(self, data);
    }

    fn finalize_into(self, out: &mut [u8]) -> crate::hash::HashResult<()> {
        if out.len() < SHA256_LEN {
            return Err(crate::hash::HashError::OutputTooSmall);
        }
        if self.is_224 {
            return Err(crate::hash::HashError::Unsupported);
        }
        let digest = Sha256::finalize(self);
        out[..SHA256_LEN].copy_from_slice(&digest);
        Ok(())
    }
}

impl crate::hash::HmacCapable for Sha256 {}

impl crate::hash::digest::HashState for Sha256 {
    fn clean(&mut self) {
        let was_224 = self.is_224;
        *self = if was_224 {
            Self::new_224()
        } else {
            Self::new()
        };
        self.cleaned = true;
    }
}

impl crate::hash::digest::SerializableHash for Sha256 {
    type State = Sha256;

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
    fn sha256_empty() {
        let digest = sha256(b"").unwrap();
        assert_eq!(
            digest,
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55
            ]
        );
    }

    #[test]
    fn sha256_abc() {
        let digest = sha256(b"abc").unwrap();
        assert_eq!(
            digest,
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad
            ]
        );
    }

    #[test]
    fn sha256_long() {
        let digest = sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq").unwrap();
        assert_eq!(
            digest,
            [
                0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e,
                0x60, 0x39, 0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4,
                0x19, 0xdb, 0x06, 0xc1
            ]
        );
    }

    #[test]
    fn sha224_abc() {
        let digest = sha224(b"abc").unwrap();
        assert_eq!(
            digest,
            [
                0x23, 0x09, 0x7d, 0x22, 0x34, 0x05, 0xd8, 0x22, 0x86, 0x42, 0xa4, 0x77, 0xbd, 0xa2,
                0x55, 0xb3, 0x2a, 0xad, 0xbc, 0xe4, 0xbd, 0xa0, 0xb3, 0xf7, 0xe3, 0x6c, 0x9d, 0xa7
            ]
        );
    }

    #[test]
    fn sha256d_empty() {
        let d = sha256d(b"").unwrap();
        // sha256(sha256(""))
        assert_eq!(
            d,
            [
                0x5d, 0xf6, 0xe0, 0xe2, 0x76, 0x13, 0x59, 0xd3, 0x0a, 0x82, 0x75, 0x05, 0x8e, 0x29,
                0x9f, 0xcc, 0x03, 0x81, 0x53, 0x45, 0x45, 0xf5, 0x5c, 0xf4, 0x3e, 0x41, 0x98, 0x3f,
                0x5d, 0x4c, 0x94, 0x56
            ]
        );
    }

    #[test]
    fn streaming_matches_oneshot() {
        let data = b"The quick brown fox jumps over the lazy dog";
        let one = sha256(data).unwrap();
        let mut h = Sha256::new();
        h.update(&data[..10]);
        h.update(&data[10..]);
        let stream = h.finalize();
        assert_eq!(one, stream);
    }
}
