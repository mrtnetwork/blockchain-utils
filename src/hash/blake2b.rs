//! BLAKE2b implementation (RFC 7693).
//!
//! Pure `no_std`, zero-dependency. Supports variable output length,
//! optional key, salt and personalization.

/// Maximum digest length.
pub const BLAKE2B_MAX_LEN: usize = 64;
const BLOCK_SIZE: usize = 128;

const IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

/// BLAKE2b streaming hasher.
#[derive(Clone)]
pub struct Blake2b {
    state: [u64; 8],
    buffer: [u8; BLOCK_SIZE],
    buffer_len: usize,
    /// Bytes compressed so far.
    t: [u64; 2],
    /// Desired output length (1..=64).
    out_len: usize,
    /// Last block flag.
    last_node: bool,
    /// Post-init snapshot for [`Self::reset`].
    init_state: [u64; 8],
    init_buffer: [u8; BLOCK_SIZE],
    init_buffer_len: usize,
    init_t: [u64; 2],
    cleaned: bool,
}

/// BLAKE2 tree (and sequential) parameter block fields (RFC 7693).
#[derive(Clone, Copy, Debug)]
pub struct Blake2TreeParams {
    pub fanout: u8,
    pub max_depth: u8,
    pub leaf_size: u32,
    pub node_offset: u64,
    pub node_depth: u8,
    pub inner_digest_length: u8,
    pub last_node: bool,
}

impl Default for Blake2TreeParams {
    fn default() -> Self {
        Self {
            fanout: 1,
            max_depth: 1,
            leaf_size: 0,
            node_offset: 0,
            node_depth: 0,
            inner_digest_length: 0,
            last_node: false,
        }
    }
}

impl Blake2b {
    /// Create a new hasher with output length 1..=64.
    pub fn new(
        out_len: usize,
        key: Option<&[u8]>,
        salt: Option<&[u8; 16]>,
        personal: Option<&[u8; 16]>,
    ) -> Self {
        Self::new_with_tree(out_len, key, salt, personal, None)
    }

    /// Full constructor including optional tree parameters.
    pub fn new_with_tree(
        out_len: usize,
        key: Option<&[u8]>,
        salt: Option<&[u8; 16]>,
        personal: Option<&[u8; 16]>,
        tree: Option<&Blake2TreeParams>,
    ) -> Self {
        assert!((1..=BLAKE2B_MAX_LEN).contains(&out_len));
        let key_len = key.map(|k| k.len()).unwrap_or(0);
        assert!(key_len <= 64);
        let tree = tree.copied().unwrap_or_default();

        let mut pblock = [0u8; 64];
        pblock[0] = out_len as u8;
        pblock[1] = key_len as u8;
        pblock[2] = tree.fanout;
        pblock[3] = tree.max_depth;
        pblock[4..8].copy_from_slice(&tree.leaf_size.to_le_bytes());
        pblock[8..16].copy_from_slice(&tree.node_offset.to_le_bytes());
        pblock[16] = tree.node_depth;
        pblock[17] = tree.inner_digest_length;
        if let Some(s) = salt {
            pblock[32..48].copy_from_slice(s);
        }
        if let Some(pers) = personal {
            pblock[48..64].copy_from_slice(pers);
        }

        let mut h = IV;
        for i in 0..8 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&pblock[i * 8..(i + 1) * 8]);
            h[i] ^= u64::from_le_bytes(b);
        }

        let mut hasher = Self {
            state: h,
            buffer: [0u8; BLOCK_SIZE],
            buffer_len: 0,
            t: [0, 0],
            out_len,
            last_node: tree.last_node,
            init_state: h,
            init_buffer: [0u8; BLOCK_SIZE],
            init_buffer_len: 0,
            init_t: [0, 0],
            cleaned: false,
        };
        if let Some(k) = key {
            let mut block = [0u8; BLOCK_SIZE];
            block[..k.len()].copy_from_slice(k);
            hasher.update(&block);
        }
        hasher.init_state = hasher.state;
        hasher.init_buffer = hasher.buffer;
        hasher.init_buffer_len = hasher.buffer_len;
        hasher.init_t = hasher.t;
        hasher
    }

    /// Restore post-construction state (key/salt/personal already applied).
    pub fn reset(&mut self) {
        if self.cleaned {
            return;
        }
        self.state = self.init_state;
        self.buffer = self.init_buffer;
        self.buffer_len = self.init_buffer_len;
        self.t = self.init_t;
    }

    /// Wipe and mark unusable.
    pub fn clean(&mut self) {
        self.state = [0; 8];
        self.buffer = [0u8; BLOCK_SIZE];
        self.buffer_len = 0;
        self.t = [0; 2];
        self.init_state = [0; 8];
        self.init_buffer = [0u8; BLOCK_SIZE];
        self.init_buffer_len = 0;
        self.init_t = [0; 2];
        self.out_len = 0;
        self.cleaned = true;
    }

    pub fn is_cleaned(&self) -> bool {
        self.cleaned
    }

    pub fn set_last_node(&mut self, last: bool) {
        self.last_node = last;
    }

    /// Convenience: unkeyed BLAKE2b-512.
    pub fn new_512() -> Self {
        Self::new(64, None, None, None)
    }

    /// Convenience: unkeyed BLAKE2b-256.
    pub fn new_256() -> Self {
        Self::new(32, None, None, None)
    }

    /// Absorb data.
    pub fn update(&mut self, data: &[u8]) {
        if self.cleaned {
            return;
        }
        // Same rule as BLAKE2s / ref: only compress a full buffer when more
        // input follows; leave a full block for finalize so f0 can be set.
        if data.is_empty() {
            return;
        }
        let mut in_data = data;
        if self.buffer_len > 0 {
            let fill = BLOCK_SIZE - self.buffer_len;
            if in_data.len() > fill {
                self.buffer[self.buffer_len..BLOCK_SIZE].copy_from_slice(&in_data[..fill]);
                self.increment_counter(BLOCK_SIZE as u64);
                let block = self.buffer;
                self.compress(&block, false);
                self.buffer_len = 0;
                in_data = &in_data[fill..];
            } else {
                self.buffer[self.buffer_len..self.buffer_len + in_data.len()]
                    .copy_from_slice(in_data);
                self.buffer_len += in_data.len();
                return;
            }
        }
        while in_data.len() > BLOCK_SIZE {
            self.increment_counter(BLOCK_SIZE as u64);
            let mut block = [0u8; BLOCK_SIZE];
            block.copy_from_slice(&in_data[..BLOCK_SIZE]);
            self.compress(&block, false);
            in_data = &in_data[BLOCK_SIZE..];
        }
        if !in_data.is_empty() {
            self.buffer[..in_data.len()].copy_from_slice(in_data);
            self.buffer_len = in_data.len();
        }
    }

    pub fn finalize_into(mut self, out: &mut [u8]) {
        assert!(out.len() >= self.out_len);
        self.increment_counter(self.buffer_len as u64);
        // Zero remaining buffer
        for i in self.buffer_len..BLOCK_SIZE {
            self.buffer[i] = 0;
        }
        let block = self.buffer;
        self.compress(&block, true);

        let mut full = [0u8; 64];
        for i in 0..8 {
            full[i * 8..i * 8 + 8].copy_from_slice(&self.state[i].to_le_bytes());
        }
        out[..self.out_len].copy_from_slice(&full[..self.out_len]);
    }

    /// Finalize as 64-byte array (only valid when out_len == 64).
    pub fn finalize(self) -> [u8; 64] {
        assert_eq!(self.out_len, 64);
        let mut out = [0u8; 64];
        self.finalize_into(&mut out);
        out
    }

    /// Finalize as 32-byte array (only valid when out_len == 32).
    pub fn finalize_256(self) -> [u8; 32] {
        assert_eq!(self.out_len, 32);
        let mut out = [0u8; 32];
        self.finalize_into(&mut out);
        out
    }

    fn increment_counter(&mut self, inc: u64) {
        self.t[0] = self.t[0].wrapping_add(inc);
        if self.t[0] < inc {
            self.t[1] = self.t[1].wrapping_add(1);
        }
    }

    fn compress(&mut self, block: &[u8; BLOCK_SIZE], last: bool) {
        let mut m = [0u64; 16];
        for i in 0..16 {
            m[i] = u64::from_le_bytes([
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

        let mut v = [0u64; 16];
        v[..8].copy_from_slice(&self.state);
        v[8..].copy_from_slice(&IV);
        v[12] ^= self.t[0];
        v[13] ^= self.t[1];
        // f[0] = last block; f[1] = last node — only on the final block.
        if last {
            v[14] = !v[14];
            if self.last_node {
                v[15] = !v[15];
            }
        }

        for s in &SIGMA {
            g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }

        for i in 0..8 {
            self.state[i] ^= v[i] ^ v[i + 8];
        }
    }
}

#[inline(always)]
fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

/// One-shot BLAKE2b-512.
#[inline]
pub fn blake2b_512(data: &[u8]) -> crate::hash::HashResult<[u8; 64]> {
    let mut h = Blake2b::new_512();
    h.update(data);
    Ok(h.finalize())
}

/// One-shot BLAKE2b-256.
#[inline]
pub fn blake2b_256(data: &[u8]) -> crate::hash::HashResult<[u8; 32]> {
    let mut h = Blake2b::new_256();
    h.update(data);
    Ok(h.finalize_256())
}

impl crate::hash::digest::HashState for Blake2b {
    fn clean(&mut self) {
        Blake2b::clean(self);
    }
}

impl crate::hash::digest::SerializableHash for Blake2b {
    type State = Blake2b;
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
    fn blake2b_512_empty() {
        let d = blake2b_512(b"").unwrap();
        assert_eq!(
            d,
            [
                0x78, 0x6a, 0x02, 0xf7, 0x42, 0x01, 0x59, 0x03, 0xc6, 0xc6, 0xfd, 0x85, 0x25, 0x52,
                0xd2, 0x72, 0x91, 0x2f, 0x47, 0x40, 0xe1, 0x58, 0x47, 0x61, 0x8a, 0x86, 0xe2, 0x17,
                0xf7, 0x1f, 0x54, 0x19, 0xd2, 0x5e, 0x10, 0x31, 0xaf, 0xee, 0x58, 0x53, 0x13, 0x89,
                0x64, 0x44, 0x93, 0x4e, 0xb0, 0x4b, 0x90, 0x3a, 0x68, 0x5b, 0x14, 0x48, 0xb7, 0x55,
                0xd5, 0x6f, 0x70, 0x1a, 0xfe, 0x9b, 0xe2, 0xce
            ]
        );
    }

    #[test]
    fn reset_preserves_key_salt() {
        let key = [7u8; 32];
        let salt = [1u8; 16];
        let pers = [2u8; 16];
        let mut h = Blake2b::new(32, Some(&key), Some(&salt), Some(&pers));
        h.update(b"xyz");
        let mut d1 = [0u8; 32];
        h.clone().finalize_into(&mut d1);
        h.reset();
        h.update(b"xyz");
        let mut d2 = [0u8; 32];
        h.finalize_into(&mut d2);
        assert_eq!(d1, d2);
    }

    #[test]
    fn blake2b_256_abc() {
        let d = blake2b_256(b"abc").unwrap();
        assert_eq!(
            d,
            [
                0xbd, 0xdd, 0x81, 0x3c, 0x63, 0x42, 0x39, 0x72, 0x31, 0x71, 0xef, 0x3f, 0xee, 0x98,
                0x57, 0x9b, 0x94, 0x96, 0x4e, 0x3b, 0xb1, 0xcb, 0x3e, 0x42, 0x72, 0x62, 0xc8, 0xc0,
                0x68, 0xd5, 0x23, 0x19
            ]
        );
    }
    /// RFC 7693 Appendix E blake2b self-test.
    #[test]
    fn rfc7693_selftest() {
        const RES: [u8; 32] = [
            0xC2, 0x3A, 0x78, 0x00, 0xD9, 0x81, 0x23, 0xBD, 0x10, 0xF5, 0x06, 0xC6, 0x1E, 0x29,
            0xDA, 0x56, 0x03, 0xD7, 0x63, 0xB8, 0xBB, 0xAD, 0x2E, 0x73, 0x7F, 0x5E, 0x76, 0x5A,
            0x7B, 0xCC, 0xD4, 0x75,
        ];
        const MD_LEN: [usize; 4] = [20, 32, 48, 64];
        const IN_LEN: [usize; 6] = [0, 3, 128, 129, 255, 1024];
        fn selftest_seq(out: &mut [u8], seed: u32) {
            let mut a: u32 = 0xDEAD4BADu32.wrapping_mul(seed);
            let mut b: u32 = 1;
            for p in out.iter_mut() {
                let t = a.wrapping_add(b);
                a = b;
                b = t;
                *p = (t >> 24) as u8;
            }
        }
        let mut ctx = Blake2b::new(32, None, None, None);
        for &outlen in &MD_LEN {
            for &inlen in &IN_LEN {
                let mut input = alloc::vec![0u8; inlen];
                selftest_seq(&mut input, inlen as u32);
                let mut md = alloc::vec![0u8; outlen];
                let mut h = Blake2b::new(outlen, None, None, None);
                h.update(&input);
                h.finalize_into(&mut md);
                ctx.update(&md);
                let mut key = alloc::vec![0u8; outlen];
                selftest_seq(&mut key, outlen as u32);
                let mut h = Blake2b::new(outlen, Some(&key), None, None);
                h.update(&input);
                h.finalize_into(&mut md);
                ctx.update(&md);
            }
        }
        let mut out = [0u8; 32];
        ctx.finalize_into(&mut out);
        assert_eq!(out, RES, "RFC 7693 blake2b self-test failed");
    }
}
