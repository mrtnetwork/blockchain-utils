//! Poly1305 one-time MAC (RFC 8439).
//!
//! Uses u128 arithmetic for (h * r) mod (2^130 - 5). Pure `no_std`.

use super::error::{CipherError, CipherResult};

pub const KEY_LEN: usize = 32;
pub const TAG_LEN: usize = 16;

// Actually p = 2^130 - 5 doesn't fit in u128. We keep h as (hi: u32, lo: u128) where
// value = hi * 2^128 + lo, with hi in 0..4 after reduction.

/// Streaming Poly1305 authenticator (RFC 8439 §2.5).
///
/// Accepts arbitrarily long input with O(1) stack: full 16-byte blocks are
/// absorbed on the fly; only a partial tail block is buffered. Pure `no_std`.
pub struct Poly1305 {
    r: u128,
    s: u128,
    h_lo: u128,
    h_hi: u128,
    buf: [u8; 16],
    used: usize,
}

impl Poly1305 {
    /// Creates an authenticator for one-time key `key` (32 bytes).
    pub fn new(key: &[u8]) -> CipherResult<Self> {
        if key.len() != KEY_LEN {
            return Err(CipherError::InvalidKeyLength);
        }

        // Clamp r into a 128-bit integer (top 4 bits of 130-bit field already zero from clamp)
        let mut rb = [0u8; 16];
        rb.copy_from_slice(&key[0..16]);
        rb[3] &= 15;
        rb[7] &= 15;
        rb[11] &= 15;
        rb[15] &= 15;
        rb[4] &= 252;
        rb[8] &= 252;
        rb[12] &= 252;
        let r = u128::from_le_bytes(rb); // r < 2^124 after clamp

        let s = u128::from_le_bytes({
            let mut a = [0u8; 16];
            a.copy_from_slice(&key[16..32]);
            a
        });

        Ok(Self {
            r,
            s,
            h_lo: 0,
            h_hi: 0, // only low few bits used
            buf: [0u8; 16],
            used: 0,
        })
    }

    /// Absorbs more message bytes. No length limit.
    pub fn update(&mut self, mut data: &[u8]) {
        if self.used > 0 {
            let take = core::cmp::min(16 - self.used, data.len());
            self.buf[self.used..self.used + take].copy_from_slice(&data[..take]);
            self.used += take;
            data = &data[take..];
            if self.used == 16 {
                let block = self.buf;
                self.absorb_full(&block);
                self.used = 0;
            }
        }
        while data.len() >= 16 {
            let mut block = [0u8; 16];
            block.copy_from_slice(&data[..16]);
            self.absorb_full(&block);
            data = &data[16..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.used = data.len();
        }
    }

    /// Finishes: absorbs the padded tail block (if any) and returns the tag.
    /// Wipes the key and accumulator before returning.
    pub fn finalize(mut self) -> [u8; TAG_LEN] {
        if self.used > 0 {
            let mut block = [0u8; 17];
            block[..self.used].copy_from_slice(&self.buf[..self.used]);
            block[self.used] = 1;
            self.absorb_padded(&block);
            self.used = 0;
        }

        // Final full reduction: ensure h < p = 2^130 - 5
        // Fold remaining
        if self.h_hi > 3 {
            let high = self.h_hi >> 2;
            let top2 = self.h_hi & 3;
            let (a, c) = self.h_lo.overflowing_add(high.wrapping_mul(5));
            self.h_lo = a;
            self.h_hi = top2.wrapping_add(u128::from(c));
        }

        // if h >= p, subtract p
        // p = 2^130 - 5 = (top2=2, lo = 2^128 - 5)?  2^130 - 5 = 4 * 2^128 - 5
        // So p_hi=4, p_lo = 0 - 5 with borrow → p_hi=3, p_lo = 2^128 - 5
        // Easier: try h' = h + 5; if h' >= 2^130 then h >= p
        let (g_lo, c) = self.h_lo.overflowing_add(5);
        let g_hi = self.h_hi.wrapping_add(u128::from(c));
        if g_hi >= 4 {
            // h >= p; use g with bit 130 cleared
            self.h_lo = g_lo;
            let _h_hi = g_hi - 4; // should be 0
        }

        // tag = (h + s) mod 2^128  → just low 128 bits of h + s
        let tag = self.h_lo.wrapping_add(self.s).to_le_bytes();
        self.r = 0;
        self.s = 0;
        self.h_lo = 0;
        self.h_hi = 0;
        self.buf = [0u8; 16];
        tag
    }

    /// Absorbs one full 16-byte block (appends the RFC 8439 0x01 byte).
    #[inline]
    fn absorb_full(&mut self, block: &[u8; 16]) {
        let mut full = [0u8; 17];
        full[..16].copy_from_slice(block);
        full[16] = 1;
        self.absorb_padded(&full);
    }

    /// Core `h = ((h + n) * r) mod p` step for a 17-byte padded block
    /// (16 message bytes + trailing 0x01).
    fn absorb_padded(&mut self, block: &[u8; 17]) {
        let n_lo = u128::from_le_bytes({
            let mut a = [0u8; 16];
            a.copy_from_slice(&block[0..16]);
            a
        });
        let n_hi = block[16] as u128;

        // h += n
        let (sum_lo, carry) = self.h_lo.overflowing_add(n_lo);
        self.h_lo = sum_lo;
        self.h_hi = self.h_hi.wrapping_add(n_hi).wrapping_add(u128::from(carry));

        // h *= r
        // (h_hi * 2^128 + h_lo) * r = h_hi * r * 2^128 + h_lo * r
        // h_lo * r → up to ~252 bits → need wide mul
        let (p_lo, p_hi) = mul_u128(self.h_lo, self.r);
        // h_hi * r fits in u128 (h_hi small * r < 2^124 * 4)
        let hr = self.h_hi.wrapping_mul(self.r);
        // add hr * 2^128 to (p_hi, p_lo)
        let (new_hi, c) = p_hi.overflowing_add(hr);
        // c would be bit 256+; with small h_hi should be 0
        let _ = c;
        self.h_lo = p_lo;
        self.h_hi = new_hi;

        // Reduce mod 2^130 - 5
        // h = h_lo + h_hi * 2^128
        // 2^130 = 5 (mod p) ⇒ 2^128 = 5 * 2^{-2} is messy
        // Better: write h = (h mod 2^130) + (h >> 130) * 2^130
        //       ≡ (h mod 2^130) + (h >> 130) * 5  (mod p)
        // h mod 2^130 = low 130 bits = h_lo's all 128 bits + low 2 bits of h_hi
        // h >> 130 = h_hi >> 2
        // Represent 130-bit as (lo: u128, top2: u8)
        let top2 = (self.h_hi & 3) as u8;
        let high = self.h_hi >> 2;

        // new_h = (h_lo + top2*2^128) + high * 5
        let (a, c1) = self.h_lo.overflowing_add(high.wrapping_mul(5));
        self.h_lo = a;
        self.h_hi = u128::from(top2).wrapping_add(u128::from(c1));

        // one more fold if needed
        if self.h_hi > 3 {
            let high2 = self.h_hi >> 2;
            let top2b = self.h_hi & 3;
            let (a2, c2) = self.h_lo.overflowing_add(high2.wrapping_mul(5));
            self.h_lo = a2;
            self.h_hi = top2b.wrapping_add(u128::from(c2));
        }
    }
}

/// Poly1305 MAC (one-shot).
pub fn poly1305(key: &[u8], message: &[u8]) -> CipherResult<[u8; TAG_LEN]> {
    let mut mac = Poly1305::new(key)?;
    mac.update(message);
    Ok(mac.finalize())
}

/// Full 128×128 → 256-bit multiply.
#[inline]
fn mul_u128(a: u128, b: u128) -> (u128, u128) {
    let a0 = a as u64 as u128;
    let a1 = (a >> 64) as u64 as u128;
    let b0 = b as u64 as u128;
    let b1 = (b >> 64) as u64 as u128;

    let p00 = a0 * b0;
    let p01 = a0 * b1;
    let p10 = a1 * b0;
    let p11 = a1 * b1;

    let mid = (p00 >> 64) + (p01 & 0xffffffffffffffff) + (p10 & 0xffffffffffffffff);
    let lo = (p00 & 0xffffffffffffffff) | (mid << 64);
    let hi = p11 + (p01 >> 64) + (p10 >> 64) + (mid >> 64);
    (lo, hi)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc8439_poly1305() {
        let key = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5,
            0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf,
            0x41, 0x49, 0xf5, 0x1b,
        ];
        let msg = b"Cryptographic Forum Research Group";
        let tag = poly1305(&key, msg).unwrap();
        assert_eq!(
            tag,
            [
                0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01,
                0x27, 0xa9
            ]
        );
    }

    #[test]
    fn streaming_matches_oneshot() {
        let key = [0x42u8; 32];
        for len in [0usize, 1, 15, 16, 17, 31, 32, 100, 5000] {
            let msg: alloc::vec::Vec<u8> = (0..len).map(|i| (i & 0xff) as u8).collect();
            let expected = poly1305(&key, &msg).unwrap();
            // Feed in awkward chunk sizes to cross block boundaries.
            for chunk in [1usize, 7, 16, 31] {
                let mut mac = Poly1305::new(&key).unwrap();
                for piece in msg.chunks(chunk) {
                    mac.update(piece);
                }
                assert_eq!(mac.finalize(), expected, "len={len} chunk={chunk}");
            }
        }
    }
}
