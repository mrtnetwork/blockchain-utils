//! SHA-512, SHA-384 and SHA-512/256 implementations (FIPS 180-4).
//!
//! Pure `no_std`, zero-dependency, allocation-free.

/// SHA-512 digest length.
pub const SHA512_LEN: usize = 64;
/// SHA-384 digest length.
pub const SHA384_LEN: usize = 48;
/// SHA-512/256 digest length.
pub const SHA512_256_LEN: usize = 32;
/// Block size for the SHA-512 family.
pub const BLOCK_SIZE: usize = 128;

const K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

#[inline(always)]
fn rotr(x: u64, n: u32) -> u64 {
    x.rotate_right(n)
}

#[inline(always)]
fn ch(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (!x & z)
}

#[inline(always)]
fn maj(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (x & z) ^ (y & z)
}

#[inline(always)]
fn big_sigma0(x: u64) -> u64 {
    rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39)
}

#[inline(always)]
fn big_sigma1(x: u64) -> u64 {
    rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41)
}

#[inline(always)]
fn small_sigma0(x: u64) -> u64 {
    rotr(x, 1) ^ rotr(x, 8) ^ (x >> 7)
}

#[inline(always)]
fn small_sigma1(x: u64) -> u64 {
    rotr(x, 19) ^ rotr(x, 61) ^ (x >> 6)
}

/// Which SHA-512 variant is being computed.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Variant {
    Sha512,
    Sha384,
    Sha512_256,
}

/// SHA-512 family streaming hasher.
#[derive(Clone)]
pub struct Sha512 {
    state: [u64; 8],
    buffer: [u8; BLOCK_SIZE],
    buffer_len: usize,
    /// Total length in bytes (we keep 128-bit conceptually as two u64).
    total_len_low: u64,
    total_len_high: u64,
    variant: Variant,
    /// After clean(), further use is a no-op (reference parity).
    cleaned: bool,
}

impl Sha512 {
    /// New SHA-512 hasher.
    pub const fn new() -> Self {
        Self {
            state: [
                0x6a09e667f3bcc908,
                0xbb67ae8584caa73b,
                0x3c6ef372fe94f82b,
                0xa54ff53a5f1d36f1,
                0x510e527fade682d1,
                0x9b05688c2b3e6c1f,
                0x1f83d9abfb41bd6b,
                0x5be0cd19137e2179,
            ],
            buffer: [0u8; BLOCK_SIZE],
            buffer_len: 0,
            total_len_low: 0,
            total_len_high: 0,
            variant: Variant::Sha512,
            cleaned: false,
        }
    }

    /// New SHA-384 hasher.
    pub const fn new_384() -> Self {
        Self {
            state: [
                0xcbbb9d5dc1059ed8,
                0x629a292a367cd507,
                0x9159015a3070dd17,
                0x152fecd8f70e5939,
                0x67332667ffc00b31,
                0x8eb44a8768581511,
                0xdb0c2e0d64f98fa7,
                0x47b5481dbefa4fa4,
            ],
            buffer: [0u8; BLOCK_SIZE],
            buffer_len: 0,
            total_len_low: 0,
            total_len_high: 0,
            variant: Variant::Sha384,
            cleaned: false,
        }
    }

    /// New SHA-512/256 hasher.
    pub const fn new_512_256() -> Self {
        Self {
            state: [
                0x22312194fc2bf72c,
                0x9f555fa3c84c64c2,
                0x2393b86b6f53b151,
                0x963877195940eabd,
                0x96283ee2a88effe3,
                0xbe5e1e2553863992,
                0x2b0199fc2c85b8aa,
                0x0eb72ddc81c52ca2,
            ],
            buffer: [0u8; BLOCK_SIZE],
            buffer_len: 0,
            total_len_low: 0,
            total_len_high: 0,
            variant: Variant::Sha512_256,
            cleaned: false,
        }
    }

    /// Reset to initial state of the current variant.
    pub fn reset(&mut self) {
        if self.cleaned {
            return;
        }
        *self = match self.variant {
            Variant::Sha512 => Self::new(),
            Variant::Sha384 => Self::new_384(),
            Variant::Sha512_256 => Self::new_512_256(),
        };
    }

    /// Absorb data.
    pub fn update(&mut self, data: &[u8]) {
        if self.cleaned {
            return;
        }
        let len = data.len() as u64;
        let (new_low, carry) = self.total_len_low.overflowing_add(len);
        self.total_len_low = new_low;
        if carry {
            self.total_len_high = self.total_len_high.wrapping_add(1);
        }

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

    /// Finalize into the provided buffer.
    /// Required length depends on the variant (64 / 48 / 32).
    pub fn finalize_into(mut self, out: &mut [u8]) {
        let bit_len_low = self.total_len_low << 3;
        let bit_len_high = (self.total_len_high << 3) | (self.total_len_low >> 61);

        let mut padding = [0u8; BLOCK_SIZE + 16];
        padding[0] = 0x80;

        let pad_len = if self.buffer_len < 112 {
            112 - self.buffer_len
        } else {
            112 + BLOCK_SIZE - self.buffer_len
        };

        self.update(&padding[..pad_len]);

        let mut len_bytes = [0u8; 16];
        len_bytes[..8].copy_from_slice(&bit_len_high.to_be_bytes());
        len_bytes[8..].copy_from_slice(&bit_len_low.to_be_bytes());
        self.update(&len_bytes);

        debug_assert_eq!(self.buffer_len, 0);

        let digest_len = match self.variant {
            Variant::Sha512 => SHA512_LEN,
            Variant::Sha384 => SHA384_LEN,
            Variant::Sha512_256 => SHA512_256_LEN,
        };
        assert!(out.len() >= digest_len);

        for i in 0..8 {
            if i * 8 >= digest_len {
                break;
            }
            let bytes = self.state[i].to_be_bytes();
            let start = i * 8;
            let end = core::cmp::min(start + 8, digest_len);
            out[start..end].copy_from_slice(&bytes[..end - start]);
        }
    }

    /// Finalize as SHA-512 (64 bytes).
    pub fn finalize(self) -> [u8; SHA512_LEN] {
        assert!(self.variant == Variant::Sha512);
        let mut out = [0u8; SHA512_LEN];
        self.finalize_into(&mut out);
        out
    }

    /// Finalize as SHA-384 (48 bytes).
    pub fn finalize_384(self) -> [u8; SHA384_LEN] {
        assert!(self.variant == Variant::Sha384);
        let mut out = [0u8; SHA384_LEN];
        self.finalize_into(&mut out);
        out
    }

    /// Finalize as SHA-512/256 (32 bytes).
    pub fn finalize_512_256(self) -> [u8; SHA512_256_LEN] {
        assert!(self.variant == Variant::Sha512_256);
        let mut out = [0u8; SHA512_256_LEN];
        self.finalize_into(&mut out);
        out
    }

    fn process_block(&mut self, block: &[u8; BLOCK_SIZE]) {
        let mut w = [0u64; 80];
        for i in 0..16 {
            w[i] = u64::from_be_bytes([
                block[i * 8],
                block[i * 8 + 1],
                block[i * 8 + 2],
                block[i * 8 + 3],
                block[i * 8 + 4],
                block[i * 8 + 5],
                block[i * 8 + 6],
                block[i * 8 + 7],
            ]);
        }
        for i in 16..80 {
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

        for i in 0..80 {
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

impl Default for Sha512 {
    fn default() -> Self {
        Self::new()
    }
}

/// One-shot SHA-512.
#[inline]
pub fn sha512(data: &[u8]) -> crate::hash::HashResult<[u8; SHA512_LEN]> {
    let mut h = Sha512::new();
    h.update(data);
    Ok(h.finalize())
}

/// One-shot SHA-384.
#[inline]
pub fn sha384(data: &[u8]) -> crate::hash::HashResult<[u8; SHA384_LEN]> {
    let mut h = Sha512::new_384();
    h.update(data);
    Ok(h.finalize_384())
}

/// One-shot SHA-512/256.
#[inline]
pub fn sha512_256(data: &[u8]) -> crate::hash::HashResult<[u8; SHA512_256_LEN]> {
    let mut h = Sha512::new_512_256();
    h.update(data);
    Ok(h.finalize_512_256())
}

impl crate::hash::digest::HashState for Sha512 {
    fn clean(&mut self) {
        let v = self.variant;
        *self = match v {
            Variant::Sha512 => Self::new(),
            Variant::Sha384 => Self::new_384(),
            Variant::Sha512_256 => Self::new_512_256(),
        };
        self.cleaned = true;
    }
}

impl crate::hash::digest::SerializableHash for Sha512 {
    type State = Sha512;
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
    fn sha512_abc() {
        let d = sha512(b"abc").unwrap();
        assert_eq!(
            d,
            [
                0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20,
                0x41, 0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6,
                0x4b, 0x55, 0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba,
                0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
                0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f
            ]
        );
    }

    #[test]
    fn sha384_abc() {
        let d = sha384(b"abc").unwrap();
        assert_eq!(&d[..8], &[0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b]);
    }

    #[test]
    fn sha512_256_abc() {
        // Official FIPS 180-4 vector for SHA-512/256("abc")
        let d = sha512_256(b"abc").unwrap();
        assert_eq!(
            d,
            [
                0x53, 0x04, 0x8e, 0x26, 0x81, 0x94, 0x1e, 0xf9, 0x9b, 0x2e, 0x29, 0xb7, 0x6b, 0x4c,
                0x7d, 0xab, 0xe4, 0xc2, 0xd0, 0xc6, 0x34, 0xfc, 0x6d, 0x46, 0xe0, 0xe2, 0xf1, 0x31,
                0x07, 0xe7, 0xaf, 0x23
            ]
        );
    }

    #[test]
    fn sha512_empty() {
        let d = sha512(b"").unwrap();
        assert_eq!(&d[..8], &[0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd]);
    }
}
