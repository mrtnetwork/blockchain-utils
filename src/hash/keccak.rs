//! Keccak and SHA-3 family (variable digest sizes).
//!
//! Pure `no_std`, zero-dependency.
//!
//! Supports:
//! - Keccak-224 / 256 / 384 / 512 (Ethereum-style domain 0x01)
//! - SHA3-224 / 256 / 384 / 512 (NIST domain 0x06)
//! - SHAKE128 / SHAKE256 (XOF, domain 0x1f)

use super::error::{HashError, HashResult};

/// Keccak-256 / SHA3-256 digest length.
pub const KECCAK256_LEN: usize = 32;
/// Keccak-224 / SHA3-224.
pub const KECCAK224_LEN: usize = 28;
/// Keccak-384 / SHA3-384.
pub const KECCAK384_LEN: usize = 48;
/// Keccak-512 / SHA3-512.
pub const KECCAK512_LEN: usize = 64;

const ROUNDS: usize = 24;

const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

/// Generic Keccak sponge (rate determined by capacity = 2 * output_bits for fixed hashes).
#[derive(Clone)]
pub struct Keccak {
    state: [u64; 25],
    /// Rate in bytes.
    rate: usize,
    buffer: [u8; 200], // max rate for SHAKE128 is 168
    buffer_len: usize,
    /// Domain separation byte.
    domain: u8,
    /// Fixed output length (0 for XOF / SHAKE).
    out_len: usize,
    /// True until first pad (absorbing phase).
    absorbing: bool,
    /// Byte offset into current rate block while squeezing.
    squeeze_pos: usize,
    /// After clean(), further use is a no-op.
    cleaned: bool,
}

impl Keccak {
    fn new_with(rate: usize, domain: u8, out_len: usize) -> Self {
        assert!(rate <= 200);
        Self {
            state: [0u64; 25],
            rate,
            buffer: [0u8; 200],
            buffer_len: 0,
            domain,
            out_len,
            absorbing: true,
            squeeze_pos: 0,
            cleaned: false,
        }
    }

    // ---- Keccak (Ethereum) ----
    /// Keccak-224.
    pub fn keccak224() -> Self {
        Self::new_with(144, 0x01, 28)
    }
    /// Keccak-256.
    pub fn keccak256() -> Self {
        Self::new_with(136, 0x01, 32)
    }
    /// Keccak-384.
    pub fn keccak384() -> Self {
        Self::new_with(104, 0x01, 48)
    }
    /// Keccak-512.
    pub fn keccak512() -> Self {
        Self::new_with(72, 0x01, 64)
    }

    // ---- SHA-3 (NIST) ----
    /// SHA3-224.
    pub fn sha3_224() -> Self {
        Self::new_with(144, 0x06, 28)
    }
    /// SHA3-256.
    pub fn sha3_256() -> Self {
        Self::new_with(136, 0x06, 32)
    }
    /// SHA3-384.
    pub fn sha3_384() -> Self {
        Self::new_with(104, 0x06, 48)
    }
    /// SHA3-512.
    pub fn sha3_512() -> Self {
        Self::new_with(72, 0x06, 64)
    }

    // ---- SHAKE (XOF) ----
    /// SHAKE128 (variable output).
    pub fn shake128() -> Self {
        Self::new_with(168, 0x1f, 0)
    }
    /// SHAKE256 (variable output).
    pub fn shake256() -> Self {
        Self::new_with(136, 0x1f, 0)
    }

    /// Legacy constructor for Keccak-256 (Ethereum).
    pub const fn new() -> Self {
        // const-friendly path for keccak256
        Self {
            state: [0u64; 25],
            rate: 136,
            buffer: [0u8; 200],
            buffer_len: 0,
            domain: 0x01,
            out_len: 32,
            absorbing: true,
            squeeze_pos: 0,
            cleaned: false,
        }
    }

    /// Legacy constructor for SHA3-256.
    pub const fn new_sha3() -> Self {
        Self {
            state: [0u64; 25],
            rate: 136,
            buffer: [0u8; 200],
            buffer_len: 0,
            domain: 0x06,
            out_len: 32,
            absorbing: true,
            squeeze_pos: 0,
            cleaned: false,
        }
    }

    /// Absorb data.
    pub fn update(&mut self, data: &[u8]) {
        if self.cleaned || !self.absorbing {
            return;
        }
        let rate = self.rate;
        let mut offset = 0;
        if self.buffer_len > 0 {
            let need = rate - self.buffer_len;
            let take = core::cmp::min(need, data.len());
            self.buffer[self.buffer_len..self.buffer_len + take].copy_from_slice(&data[..take]);
            self.buffer_len += take;
            offset += take;
            if self.buffer_len == rate {
                self.absorb_block();
                self.buffer_len = 0;
            }
        }
        while offset + rate <= data.len() {
            for i in 0..(rate / 8) {
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&data[offset + i * 8..offset + i * 8 + 8]);
                self.state[i] ^= u64::from_le_bytes(bytes);
            }
            self.keccak_f();
            offset += rate;
        }
        if offset < data.len() {
            let rem = data.len() - offset;
            self.buffer[..rem].copy_from_slice(&data[offset..]);
            self.buffer_len = rem;
        }
    }

    /// Finalize fixed-length digest into `out`.
    pub fn finalize_into(mut self, out: &mut [u8]) -> HashResult<()> {
        let need = if self.out_len == 0 {
            out.len()
        } else {
            self.out_len
        };
        if out.len() < need && self.out_len != 0 {
            return Err(HashError::OutputTooSmall);
        }
        self.pad_and_absorb();
        self.squeeze(&mut out[..need]);
        Ok(())
    }

    /// Finalize as 32-byte array (only valid when out_len == 32).
    pub fn finalize(self) -> [u8; 32] {
        assert_eq!(self.out_len, 32);
        let mut out = [0u8; 32];
        let _ = self.finalize_into(&mut out);
        out
    }

    fn pad_and_absorb(&mut self) {
        let rate = self.rate;
        self.buffer[self.buffer_len] = self.domain;
        for i in self.buffer_len + 1..rate {
            self.buffer[i] = 0;
        }
        self.buffer[rate - 1] |= 0x80;
        self.absorb_block();
        self.buffer_len = 0;
    }

    fn absorb_block(&mut self) {
        let rate = self.rate;
        for i in 0..(rate / 8) {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&self.buffer[i * 8..i * 8 + 8]);
            self.state[i] ^= u64::from_le_bytes(bytes);
        }
        self.keccak_f();
    }

    /// Squeeze `out` bytes, advancing the XOF position (`_squeeze`).
    fn squeeze(&mut self, out: &mut [u8]) {
        let rate = self.rate;
        let mut offset = 0;
        while offset < out.len() {
            if self.squeeze_pos == rate {
                self.keccak_f();
                self.squeeze_pos = 0;
            }
            let take = core::cmp::min(rate - self.squeeze_pos, out.len() - offset);
            // copy from state[squeeze_pos..]
            let mut copied = 0;
            while copied < take {
                let lane = self.squeeze_pos / 8;
                let lane_off = self.squeeze_pos % 8;
                let bytes = self.state[lane].to_le_bytes();
                let n = core::cmp::min(8 - lane_off, take - copied);
                out[offset + copied..offset + copied + n]
                    .copy_from_slice(&bytes[lane_off..lane_off + n]);
                self.squeeze_pos += n;
                copied += n;
            }
            offset += take;
        }
    }

    /// Streaming finish (mutates self). SHAKE: each call continues the XOF.
    /// Fixed digests: first call pads; later calls continue squeezing (rarely useful).
    pub fn finish_into_mut(&mut self, out: &mut [u8]) -> HashResult<()> {
        if self.cleaned {
            return Err(HashError::Failure("cleaned or invalid keccak state"));
        }
        let need = if self.out_len == 0 {
            out.len()
        } else {
            self.out_len
        };
        if out.len() < need && self.out_len != 0 {
            return Err(HashError::OutputTooSmall);
        }
        if self.absorbing {
            self.pad_and_absorb();
            self.absorbing = false;
            self.squeeze_pos = 0;
        }
        let n = need.min(out.len());
        self.squeeze(&mut out[..n]);
        Ok(())
    }

    /// Reset to initial absorbing state (same rate/domain/out_len).
    pub fn reset(&mut self) {
        if self.cleaned {
            return;
        }
        let rate = self.rate;
        let domain = self.domain;
        let out_len = self.out_len;
        *self = Self::new_with(rate, domain, out_len);
    }

    /// Wipe and mark unusable.
    pub fn clean(&mut self) {
        self.state = [0u64; 25];
        self.buffer = [0u8; 200];
        self.buffer_len = 0;
        self.absorbing = true;
        self.squeeze_pos = 0;
        self.cleaned = true;
    }

    pub fn is_cleaned(&self) -> bool {
        self.cleaned
    }

    pub fn is_xof(&self) -> bool {
        self.out_len == 0
    }

    fn keccak_f(&mut self) {
        keccak_f_1600(&mut self.state);
    }
}

impl Default for Keccak {
    fn default() -> Self {
        Self::new()
    }
}

/// Keccak-f[1600] permutation on 25×u64 state (little-endian lanes).
/// Used by SHA-3/Keccak and by STROBE.
pub fn keccak_f_1600(st: &mut [u64; 25]) {
    const ROTC: [u32; 24] = [
        1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
    ];
    const PILN: [usize; 24] = [
        10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
    ];
    for rc in RC.iter().take(ROUNDS) {
        let mut bc = [0u64; 5];
        for i in 0..5 {
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        }
        for i in 0..5 {
            let t = bc[(i + 4) % 5] ^ bc[(i + 1) % 5].rotate_left(1);
            for j in 0..5 {
                st[j * 5 + i] ^= t;
            }
        }
        let mut t = st[1];
        for i in 0..24 {
            let j = PILN[i];
            let tmp = st[j];
            st[j] = t.rotate_left(ROTC[i]);
            t = tmp;
        }
        for j in 0..5 {
            let mut bc = [0u64; 5];
            for i in 0..5 {
                bc[i] = st[j * 5 + i];
            }
            for i in 0..5 {
                st[j * 5 + i] = bc[i] ^ ((!bc[(i + 1) % 5]) & bc[(i + 2) % 5]);
            }
        }
        st[0] ^= rc;
    }
}

// Type alias for backward compatibility
/// Alias for Keccak-256 hasher.
pub type Keccak256 = Keccak;

// ---- One-shot helpers ----

/// Keccak-256 (Ethereum).
pub fn keccak256(data: &[u8]) -> HashResult<[u8; 32]> {
    let mut h = Keccak::keccak256();
    h.update(data);
    let mut out = [0u8; 32];
    h.finalize_into(&mut out)?;
    Ok(out)
}

/// Keccak-224.
pub fn keccak224(data: &[u8]) -> HashResult<[u8; 28]> {
    let mut h = Keccak::keccak224();
    h.update(data);
    let mut out = [0u8; 28];
    h.finalize_into(&mut out)?;
    Ok(out)
}

/// Keccak-384.
pub fn keccak384(data: &[u8]) -> HashResult<[u8; 48]> {
    let mut h = Keccak::keccak384();
    h.update(data);
    let mut out = [0u8; 48];
    h.finalize_into(&mut out)?;
    Ok(out)
}

/// Keccak-512.
pub fn keccak512(data: &[u8]) -> HashResult<[u8; 64]> {
    let mut h = Keccak::keccak512();
    h.update(data);
    let mut out = [0u8; 64];
    h.finalize_into(&mut out)?;
    Ok(out)
}

/// SHA3-256.
pub fn sha3_256(data: &[u8]) -> HashResult<[u8; 32]> {
    let mut h = Keccak::sha3_256();
    h.update(data);
    let mut out = [0u8; 32];
    h.finalize_into(&mut out)?;
    Ok(out)
}

/// SHA3-224.
pub fn sha3_224(data: &[u8]) -> HashResult<[u8; 28]> {
    let mut h = Keccak::sha3_224();
    h.update(data);
    let mut out = [0u8; 28];
    h.finalize_into(&mut out)?;
    Ok(out)
}

/// SHA3-384.
pub fn sha3_384(data: &[u8]) -> HashResult<[u8; 48]> {
    let mut h = Keccak::sha3_384();
    h.update(data);
    let mut out = [0u8; 48];
    h.finalize_into(&mut out)?;
    Ok(out)
}

/// SHA3-512.
pub fn sha3_512(data: &[u8]) -> HashResult<[u8; 64]> {
    let mut h = Keccak::sha3_512();
    h.update(data);
    let mut out = [0u8; 64];
    h.finalize_into(&mut out)?;
    Ok(out)
}

/// SHAKE128 — variable-length output into `out`.
pub fn shake128(data: &[u8], out: &mut [u8]) -> HashResult<()> {
    let mut h = Keccak::shake128();
    h.update(data);
    h.finalize_into(out)
}

/// SHAKE256 — variable-length output into `out`.
pub fn shake256(data: &[u8], out: &mut [u8]) -> HashResult<()> {
    let mut h = Keccak::shake256();
    h.update(data);
    h.finalize_into(out)
}

impl crate::hash::digest::HashState for Keccak {
    fn clean(&mut self) {
        Keccak::clean(self);
    }
}

impl crate::hash::digest::SerializableHash for Keccak {
    type State = Keccak;

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
    fn keccak256_empty() {
        assert_eq!(
            keccak256(b"").unwrap(),
            [
                0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7,
                0x03, 0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04,
                0x5d, 0x85, 0xa4, 0x70
            ]
        );
    }

    #[test]
    fn keccak256_abc() {
        assert_eq!(
            keccak256(b"abc").unwrap(),
            [
                0x4e, 0x03, 0x65, 0x7a, 0xea, 0x45, 0xa9, 0x4f, 0xc7, 0xd4, 0x7b, 0xa8, 0x26, 0xc8,
                0xd6, 0x67, 0xc0, 0xd1, 0xe6, 0xe3, 0x3a, 0x64, 0xa0, 0x36, 0xec, 0x44, 0xf5, 0x8f,
                0xa1, 0x2d, 0x6c, 0x45
            ]
        );
    }

    #[test]
    fn sha3_256_empty() {
        assert_eq!(
            sha3_256(b"").unwrap(),
            [
                0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66, 0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61,
                0xd6, 0x62, 0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa, 0x82, 0xd8, 0x0a, 0x4b,
                0x80, 0xf8, 0x43, 0x4a
            ]
        );
    }

    #[test]
    fn sha3_256_abc() {
        assert_eq!(
            sha3_256(b"abc").unwrap(),
            [
                0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2, 0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3,
                0x90, 0xbd, 0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b, 0x46, 0xbf, 0xe2, 0x45,
                0x11, 0x43, 0x15, 0x32
            ]
        );
    }

    #[test]
    fn sha3_512_abc() {
        let d = sha3_512(b"abc").unwrap();
        assert_eq!(&d[..8], &[0xb7, 0x51, 0x85, 0x0b, 0x1a, 0x57, 0x16, 0x8a]);
    }

    #[test]
    fn shake128_abc() {
        let mut out = [0u8; 16];
        shake128(b"abc", &mut out).unwrap();
        // NIST SHAKE128("abc", 128 bits)
        assert_eq!(
            out,
            [
                0x58, 0x81, 0x09, 0x2d, 0xd8, 0x18, 0xbf, 0x5c, 0xf8, 0xa3, 0xdd, 0xb7, 0x93, 0xfb,
                0xcb, 0xa7
            ]
        );
    }
}
