//! STROBE protocol framework (Mike Hamburg).
//!
//! Independent `no_std` implementation of the STROBE duplex over Keccak-f[1600],
//! following the public STROBE specification:
//! <https://strobe.sourceforge.io/specs/>
//!
//! Merlin transcripts are built on STROBE128.

use crate::hash::keccak_f_1600;

/// 128-bit security (rate = 166 bytes).
pub const SEC_128: usize = 128;
/// 256-bit security (rate = 134 bytes).
pub const SEC_256: usize = 256;

const FLAG_I: u8 = 1;
const FLAG_A: u8 = 2;
const FLAG_C: u8 = 4;
const FLAG_T: u8 = 8;
const FLAG_M: u8 = 16;

/// STROBE duplex state.
#[derive(Clone)]
pub struct Strobe {
    /// 200-byte state (Keccak-f[1600] width).
    state: [u8; 200],
    rate: usize,
    /// `rate - 2` — room for trailing bytes before permute.
    strober: usize,
    pos: usize,
    pos_begin: usize,
    io: u8,
    initialized: bool,
}

impl Strobe {
    /// New STROBE instance: domain separation + protocol meta-AD.
    pub fn new(protocol: &[u8], security_bits: usize) -> Self {
        assert!(security_bits == 128 || security_bits == 256);
        let rate = (1600 / 8) - security_bits / 4;
        let mut s = Self {
            state: [0u8; 200],
            rate,
            strober: rate - 2,
            pos: 0,
            pos_begin: 0,
            io: 2,
            initialized: false,
        };
        // Domain: [1, R, 1, 0, 1, 96] || "STROBEv1.0.2"
        let mut domain = alloc::vec![1u8, rate as u8, 1, 0, 1, 12 * 8];
        domain.extend_from_slice(b"STROBEv1.0.2");
        s.duplex(&mut domain, false, false, true);
        s.initialized = true;
        s.operate(true, FLAG_A, protocol, 0);
        s
    }

    /// STROBE128 convenience constructor.
    pub fn new_128(protocol: &[u8]) -> Self {
        Self::new(protocol, SEC_128)
    }

    fn permute(&mut self) {
        let mut lanes = [0u64; 25];
        for (i, lane) in lanes.iter_mut().enumerate() {
            let o = i * 8;
            *lane = u64::from_le_bytes([
                self.state[o],
                self.state[o + 1],
                self.state[o + 2],
                self.state[o + 3],
                self.state[o + 4],
                self.state[o + 5],
                self.state[o + 6],
                self.state[o + 7],
            ]);
        }
        keccak_f_1600(&mut lanes);
        for (i, lane) in lanes.iter().enumerate() {
            let b = lane.to_le_bytes();
            let o = i * 8;
            self.state[o..o + 8].copy_from_slice(&b);
        }
    }

    fn run(&mut self) {
        if self.initialized {
            // Trailing: pos_begin, 0x04, zeros, final 0x80 at rate-1
            let mut block = [0u8; 200];
            block[..self.pos].copy_from_slice(&self.state[..self.pos]);
            // Actually buffer is separate in classic impl — we track pos in state absorb
            // Rebuild: bytes 0..pos already XORed into state; we need pad on a temp
            // Correct approach: maintain running XOR into state[0..rate].
            // Pad at current pos:
            self.state[self.pos] ^= self.pos_begin as u8;
            self.state[self.pos + 1] ^= 0x04;
            self.state[self.rate - 1] ^= 0x80;
            let _ = block;
        }
        self.permute();
        self.pos = 0;
        self.pos_begin = 0;
    }

    fn begin_op(&mut self, mut flags: u8) {
        if flags & FLAG_T != 0 {
            if self.io == 2 {
                self.io = flags & FLAG_I;
            }
            flags ^= self.io;
        }
        let old_begin = self.pos_begin as u8;
        self.pos_begin = (self.pos + 1) & 0xff;
        let force_f = (flags & (FLAG_C)) != 0;
        let mut marker = [old_begin, flags];
        self.duplex(&mut marker, false, false, force_f);
    }

    /// Duplex `data` (modified in place when `c_before` / `c_after`).
    fn duplex(&mut self, data: &mut [u8], c_before: bool, c_after: bool, force_f: bool) {
        let mut offset = 0;
        while offset < data.len() {
            let space = self.strober - self.pos;
            let take = core::cmp::min(space, data.len() - offset);
            let chunk = &mut data[offset..offset + take];

            if c_before {
                for (i, b) in chunk.iter_mut().enumerate() {
                    *b ^= self.state[self.pos + i];
                }
            }

            // Absorb into state
            for (i, &b) in chunk.iter().enumerate() {
                self.state[self.pos + i] ^= b;
            }

            if c_after {
                for (i, b) in chunk.iter_mut().enumerate() {
                    *b ^= self.state[self.pos + i];
                }
            }

            self.pos += take;
            offset += take;

            if self.pos == self.strober {
                self.run();
            }
        }
        if force_f && self.pos != 0 {
            self.run();
        }
    }

    /// Operate with optional meta flag. Returns PRF/output bytes when applicable.
    pub fn operate(
        &mut self,
        meta: bool,
        op_flags: u8,
        data_in: &[u8],
        out_len: usize,
    ) -> alloc::vec::Vec<u8> {
        let mut flags = op_flags;
        if meta {
            flags |= FLAG_M;
        }

        // PRF / RATCHET-style: produce `out_len` zeros then duplex with C before
        let is_prf_like = (flags & (FLAG_I | FLAG_A)) != FLAG_A
            && (flags & (FLAG_I | FLAG_T)) != (FLAG_I | FLAG_T);

        let mut data = if is_prf_like {
            assert!(out_len > 0);
            alloc::vec![0u8; out_len]
        } else {
            assert_eq!(out_len, 0);
            data_in.to_vec()
        };

        self.begin_op(flags);

        let c_after = (flags & (FLAG_C | FLAG_I | FLAG_T)) == (FLAG_C | FLAG_T);
        let c_before = (flags & FLAG_C) != 0 && !c_after;

        self.duplex(&mut data, c_before, c_after, false);

        if (flags & (FLAG_I | FLAG_A)) == (FLAG_I | FLAG_A) {
            return data; // PRF output
        }
        if (flags & (FLAG_I | FLAG_T)) == FLAG_T {
            return data;
        }
        alloc::vec::Vec::new()
    }

    /// Associated data (meta or not).
    pub fn ad(&mut self, meta: bool, data: &[u8]) {
        let _ = self.operate(meta, FLAG_A, data, 0);
    }

    /// Pseudo-random extraction.
    pub fn prf(&mut self, len: usize) -> alloc::vec::Vec<u8> {
        self.operate(false, FLAG_I | FLAG_A | FLAG_C, &[], len)
    }

    /// Inject key material.
    pub fn key(&mut self, data: &[u8]) {
        let _ = self.operate(false, FLAG_A | FLAG_C, data, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strobe_deterministic() {
        let mut a = Strobe::new_128(b"Merlin v1.0");
        a.ad(true, b"dom-sep");
        a.ad(false, b"test");
        let x = a.prf(32);

        let mut b = Strobe::new_128(b"Merlin v1.0");
        b.ad(true, b"dom-sep");
        b.ad(false, b"test");
        let y = b.prf(32);
        assert_eq!(x, y);
        assert_eq!(x.len(), 32);
    }
}
