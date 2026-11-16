//! BLAKE2s (RFC 7693) — 32-bit variant.
//!
//! Pure `no_std`, zero-dependency. Max output 32 bytes.

use super::error::{HashError, HashResult};

/// Maximum BLAKE2s digest length.
pub const BLAKE2S_MAX_LEN: usize = 32;
const BLOCK_SIZE: usize = 64;

const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const SIGMA: [[usize; 16]; 10] = [
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
];

/// BLAKE2s streaming hasher.
#[derive(Clone)]
pub struct Blake2s {
    state: [u32; 8],
    buffer: [u8; BLOCK_SIZE],
    buffer_len: usize,
    t: [u32; 2],
    out_len: usize,
    last_node: bool,
    /// Post-init (after key absorb) snapshot for [`Self::reset`].
    init_state: [u32; 8],
    init_buffer: [u8; BLOCK_SIZE],
    init_buffer_len: usize,
    init_t: [u32; 2],
    cleaned: bool,
}

/// BLAKE2s tree parameters (RFC 7693, 32-byte parameter block).
#[derive(Clone, Copy, Debug)]
pub struct Blake2sTreeParams {
    pub fanout: u8,
    pub max_depth: u8,
    pub leaf_size: u32,
    /// Node offset (48-bit value stored in low 48 bits).
    pub node_offset: u64,
    pub node_depth: u8,
    pub inner_digest_length: u8,
    pub last_node: bool,
    pub salt: Option<[u8; 8]>,
    pub personal: Option<[u8; 8]>,
}

impl Default for Blake2sTreeParams {
    fn default() -> Self {
        Self {
            fanout: 1,
            max_depth: 1,
            leaf_size: 0,
            node_offset: 0,
            node_depth: 0,
            inner_digest_length: 0,
            last_node: false,
            salt: None,
            personal: None,
        }
    }
}

impl Blake2s {
    /// Create hasher with output length 1..=32, optional key (≤32 bytes).
    pub fn new(out_len: usize, key: Option<&[u8]>) -> HashResult<Self> {
        Self::new_with_tree(out_len, key, None)
    }

    /// Full constructor with optional tree / salt / personal.
    pub fn new_with_tree(
        out_len: usize,
        key: Option<&[u8]>,
        tree: Option<&Blake2sTreeParams>,
    ) -> HashResult<Self> {
        if !(1..=BLAKE2S_MAX_LEN).contains(&out_len) {
            return Err(HashError::InvalidLength);
        }
        let key_len = key.map(|k| k.len()).unwrap_or(0);
        if key_len > 32 {
            return Err(HashError::InvalidKeyLength);
        }

        let tree = tree.copied().unwrap_or_default();

        // 32-byte parameter block (RFC 7693 §2.5)
        let mut pblock = [0u8; 32];
        pblock[0] = out_len as u8;
        pblock[1] = key_len as u8;
        pblock[2] = tree.fanout;
        pblock[3] = tree.max_depth;
        pblock[4..8].copy_from_slice(&tree.leaf_size.to_le_bytes());
        // node offset: 48-bit little-endian at bytes 8..14
        let no = tree.node_offset.to_le_bytes();
        pblock[8..14].copy_from_slice(&no[..6]);
        pblock[14] = tree.node_depth;
        pblock[15] = tree.inner_digest_length;
        if let Some(s) = tree.salt {
            pblock[16..24].copy_from_slice(&s);
        }
        if let Some(p) = tree.personal {
            pblock[24..32].copy_from_slice(&p);
        }

        let mut h = IV;
        for i in 0..8 {
            let mut b = [0u8; 4];
            b.copy_from_slice(&pblock[i * 4..(i + 1) * 4]);
            h[i] ^= u32::from_le_bytes(b);
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
        // Snapshot after key absorb (matches the reference implementation
        hasher.init_state = hasher.state;
        hasher.init_buffer = hasher.buffer;
        hasher.init_buffer_len = hasher.buffer_len;
        hasher.init_t = hasher.t;
        Ok(hasher)
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

    /// Wipe and mark unusable (further update/finish should no-op).
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

    /// Unkeyed BLAKE2s-256.
    pub fn new_256() -> Self {
        Self::new(32, None).expect("valid")
    }

    /// Unkeyed BLAKE2s-128.
    pub fn new_128() -> Self {
        Self::new(16, None).expect("valid")
    }

    /// Absorb data.
    pub fn update(&mut self, data: &[u8]) {
        if self.cleaned {
            return;
        }
        // RFC 7693 / ref blake2s_update: only compress a full buffer when more
        // input follows in this call (`inlen > fill`). A buffer that is exactly
        // full is left for finalize (or a later update) so the last block can
        // set the finalization flag — critical for byte-at-a-time updates.
        if data.is_empty() {
            return;
        }
        let mut in_data = data;
        if self.buffer_len > 0 {
            let fill = BLOCK_SIZE - self.buffer_len;
            if in_data.len() > fill {
                self.buffer[self.buffer_len..BLOCK_SIZE].copy_from_slice(&in_data[..fill]);
                self.increment_counter(BLOCK_SIZE as u32);
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
            self.increment_counter(BLOCK_SIZE as u32);
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

    /// Finalize into `out`.
    pub fn finalize_into(mut self, out: &mut [u8]) -> HashResult<()> {
        if out.len() < self.out_len {
            return Err(HashError::OutputTooSmall);
        }
        self.increment_counter(self.buffer_len as u32);
        for i in self.buffer_len..BLOCK_SIZE {
            self.buffer[i] = 0;
        }
        let block = self.buffer;
        self.compress(&block, true);
        let mut full = [0u8; 32];
        for i in 0..8 {
            full[i * 4..i * 4 + 4].copy_from_slice(&self.state[i].to_le_bytes());
        }
        out[..self.out_len].copy_from_slice(&full[..self.out_len]);
        Ok(())
    }

    /// Finalize as 32-byte array.
    pub fn finalize_256(self) -> HashResult<[u8; 32]> {
        if self.out_len != 32 {
            return Err(HashError::Unsupported);
        }
        let mut out = [0u8; 32];
        self.finalize_into(&mut out)?;
        Ok(out)
    }

    fn increment_counter(&mut self, inc: u32) {
        self.t[0] = self.t[0].wrapping_add(inc);
        if self.t[0] < inc {
            self.t[1] = self.t[1].wrapping_add(1);
        }
    }

    fn compress(&mut self, block: &[u8; BLOCK_SIZE], last: bool) {
        let mut m = [0u32; 16];
        for i in 0..16 {
            m[i] = u32::from_le_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        let mut v = [0u32; 16];
        v[..8].copy_from_slice(&self.state);
        v[8..].copy_from_slice(&IV);
        v[12] ^= self.t[0];
        v[13] ^= self.t[1];
        // f[0] = last block; f[1] = last node — only together on the final block
        // (RFC 7693 / ref blake2s_set_lastblock).
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
fn g(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(12);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(8);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(7);
}

/// One-shot BLAKE2s-256.
#[inline]
pub fn blake2s_256(data: &[u8]) -> HashResult<[u8; 32]> {
    let mut h = Blake2s::new_256();
    h.update(data);
    h.finalize_256()
}

/// One-shot BLAKE2s-128.
#[inline]
pub fn blake2s_128(data: &[u8]) -> HashResult<[u8; 16]> {
    let mut h = Blake2s::new_128();
    h.update(data);
    let mut out = [0u8; 16];
    h.finalize_into(&mut out)?;
    Ok(out)
}

impl crate::hash::digest::HashState for Blake2s {
    fn clean(&mut self) {
        Blake2s::clean(self);
    }
}

impl crate::hash::digest::SerializableHash for Blake2s {
    type State = Blake2s;
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
    fn blake2s_256_empty() {
        // RFC 7693 appendix A
        let d = blake2s_256(b"").unwrap();
        assert_eq!(&d[..8], &[0x69, 0x21, 0x7a, 0x30, 0x79, 0x90, 0x80, 0x94]);
    }

    #[test]
    fn salt_personal_changes_digest() {
        let t = Blake2sTreeParams {
            salt: Some([1, 2, 3, 4, 5, 6, 7, 8]),
            personal: Some([9, 10, 11, 12, 13, 14, 15, 16]),
            ..Default::default()
        };
        let mut h1 = Blake2s::new_with_tree(32, None, None).unwrap();
        h1.update(b"abc");
        let mut d1 = [0u8; 32];
        h1.finalize_into(&mut d1).unwrap();
        let mut h2 = Blake2s::new_with_tree(32, None, Some(&t)).unwrap();
        h2.update(b"abc");
        let mut d2 = [0u8; 32];
        h2.finalize_into(&mut d2).unwrap();
        assert_ne!(d1, d2);
    }

    /// RFC 7693 Appendix E blake2s self-test (grand hash of hashes).
    #[test]

    fn short_salt_zero_pad_same_as_full() {
        let mut salt_short = [0u8; 8];
        salt_short[..4].copy_from_slice(&[1, 2, 3, 4]);
        let salt_full = [1u8, 2, 3, 4, 0, 0, 0, 0];
        let t1 = Blake2sTreeParams {
            salt: Some(salt_short),
            ..Default::default()
        };
        let t2 = Blake2sTreeParams {
            salt: Some(salt_full),
            ..Default::default()
        };
        let mut h1 = Blake2s::new_with_tree(32, None, Some(&t1)).unwrap();
        h1.update(b"abc");
        let mut o1 = [0u8; 32];
        h1.finalize_into(&mut o1).unwrap();
        let mut h2 = Blake2s::new_with_tree(32, None, Some(&t2)).unwrap();
        h2.update(b"abc");
        let mut o2 = [0u8; 32];
        h2.finalize_into(&mut o2).unwrap();
        assert_eq!(o1, o2);
    }

    #[test]
    fn official_keyed_kat_empty_and_00() {
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        // empty
        let h = Blake2s::new(32, Some(&key)).unwrap();
        let mut out = [0u8; 32];
        h.finalize_into(&mut out).unwrap();
        // Official BLAKE2s-kat.txt: empty in
        let exp = [
            0x48, 0xa8, 0x99, 0x7d, 0xa4, 0x07, 0x87, 0x6b, 0x3d, 0x79, 0xc0, 0xd9, 0x23, 0x25,
            0xad, 0x3b, 0x89, 0xcb, 0xb7, 0x54, 0xd8, 0x6a, 0xb7, 0x1a, 0xee, 0x04, 0x7a, 0xd3,
            0x45, 0xfd, 0x2c, 0x49,
        ];
        assert_eq!(out, exp);
        // in = 00
        let mut h = Blake2s::new(32, Some(&key)).unwrap();
        h.update(&[0x00]);
        h.finalize_into(&mut out).unwrap();
        let exp2 = [
            0x40, 0xd1, 0x5f, 0xee, 0x7c, 0x32, 0x88, 0x30, 0x16, 0x6a, 0xc3, 0xf9, 0x18, 0x65,
            0x0f, 0x80, 0x7e, 0x7e, 0x01, 0xe1, 0x77, 0x25, 0x8c, 0xdc, 0x0a, 0x39, 0xb1, 0x1f,
            0x59, 0x80, 0x66, 0xf1,
        ];
        assert_eq!(out, exp2);
    }

    #[test]
    fn rfc7693_selftest() {
        const RES: [u8; 32] = [
            0x6A, 0x41, 0x1F, 0x08, 0xCE, 0x25, 0xAD, 0xCD, 0xFB, 0x02, 0xAB, 0xA6, 0x41, 0x45,
            0x1C, 0xEC, 0x53, 0xC5, 0x98, 0xB2, 0x4F, 0x4F, 0xC7, 0x87, 0xFB, 0xDC, 0x88, 0x79,
            0x7F, 0x4C, 0x1D, 0xFE,
        ];
        const MD_LEN: [usize; 4] = [16, 20, 28, 32];
        const IN_LEN: [usize; 6] = [0, 3, 64, 65, 255, 1024];
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
        let mut ctx = Blake2s::new(32, None).unwrap();
        for &outlen in &MD_LEN {
            for &inlen in &IN_LEN {
                let mut input = alloc::vec![0u8; inlen];
                selftest_seq(&mut input, inlen as u32);
                // unkeyed
                let mut md = alloc::vec![0u8; outlen];
                let mut h = Blake2s::new(outlen, None).unwrap();
                h.update(&input);
                h.finalize_into(&mut md).unwrap();
                ctx.update(&md);
                // keyed (key length = outlen)
                let mut key = alloc::vec![0u8; outlen];
                selftest_seq(&mut key, outlen as u32);
                let mut h = Blake2s::new(outlen, Some(&key)).unwrap();
                h.update(&input);
                h.finalize_into(&mut md).unwrap();
                ctx.update(&md);
            }
        }
        let mut out = [0u8; 32];
        ctx.finalize_into(&mut out).unwrap();
        assert_eq!(out, RES, "RFC 7693 blake2s self-test failed");
    }

    #[test]
    fn tree_keyed_vector() {
        // digestSize: 20, input: 64EB, salt, person, key, full tree, lastNode
        fn dec(s: &str) -> alloc::vec::Vec<u8> {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect()
        }
        let input = dec("64EB");
        let salt = dec("F87AFAD4E3D4A722");
        let person = dec("47CE5CB661A2D82D");
        let key = dec("5702DFE9008383B6CCFC2A3F1498770C6DAB297DF613ACB95ADFA2DE12491ECC");
        let expected = dec("D67340BE4930567111ADF5F728E983A7FA59B4BE");
        let mut salt_a = [0u8; 8];
        salt_a.copy_from_slice(&salt);
        let mut pers_a = [0u8; 8];
        pers_a.copy_from_slice(&person);
        let tree = Blake2sTreeParams {
            fanout: 206,
            max_depth: 153,
            leaf_size: 3901562238,
            node_offset: 213725783482524,
            node_depth: 251,
            inner_digest_length: 31,
            last_node: true,
            salt: Some(salt_a),
            personal: Some(pers_a),
        };
        let mut h = Blake2s::new_with_tree(20, Some(&key), Some(&tree)).unwrap();
        h.update(&input);
        let mut out = [0u8; 20];
        h.finalize_into(&mut out).unwrap();
        assert_eq!(&out[..], &expected[..], "got {:02x?}", out);
    }

    #[test]
    fn byte_by_byte_vs_bulk_keyed_salt_personal() {
        let salt = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let personal = [9u8, 10, 11, 12, 13, 14, 15, 16];
        let key: [u8; 32] = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ];
        let tree = Blake2sTreeParams {
            salt: Some(salt),
            personal: Some(personal),
            ..Default::default()
        };
        let mut b = Blake2s::new_with_tree(32, Some(&key), Some(&tree)).unwrap();
        let buffer: alloc::vec::Vec<u8> = (0..256u32).map(|i| (i & 0xff) as u8).collect();
        for &i in &buffer {
            b.update(&[i]);
        }
        let mut hash = [0u8; 32];
        b.clone().finalize_into(&mut hash).unwrap();
        b.reset();
        b.update(&buffer);
        let mut hash2 = [0u8; 32];
        b.finalize_into(&mut hash2).unwrap();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn byte_by_byte_vs_bulk_no_reset() {
        let salt = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let personal = [9u8, 10, 11, 12, 13, 14, 15, 16];
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let tree = Blake2sTreeParams {
            salt: Some(salt),
            personal: Some(personal),
            ..Default::default()
        };
        let buffer: alloc::vec::Vec<u8> = (0..256u32).map(|i| (i & 0xff) as u8).collect();
        let mut b1 = Blake2s::new_with_tree(32, Some(&key), Some(&tree)).unwrap();
        for &i in &buffer {
            b1.update(&[i]);
        }
        let mut h1 = [0u8; 32];
        b1.finalize_into(&mut h1).unwrap();
        let mut b2 = Blake2s::new_with_tree(32, Some(&key), Some(&tree)).unwrap();
        b2.update(&buffer);
        let mut h2 = [0u8; 32];
        b2.finalize_into(&mut h2).unwrap();
        assert_eq!(h1, h2, "byte-by-byte must equal bulk");
    }

    #[test]
    fn bulk_reset_bulk() {
        let salt = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let personal = [9u8, 10, 11, 12, 13, 14, 15, 16];
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let tree = Blake2sTreeParams {
            salt: Some(salt),
            personal: Some(personal),
            ..Default::default()
        };
        let buffer: alloc::vec::Vec<u8> = (0..256u32).map(|i| (i & 0xff) as u8).collect();
        let mut b = Blake2s::new_with_tree(32, Some(&key), Some(&tree)).unwrap();
        b.update(&buffer);
        let mut h1 = [0u8; 32];
        b.clone().finalize_into(&mut h1).unwrap();
        b.reset();
        b.update(&buffer);
        let mut h2 = [0u8; 32];
        b.finalize_into(&mut h2).unwrap();
        assert_eq!(h1, h2, "reset then bulk must match");
    }
    #[test]
    fn blake2s_256_abc() {
        let d = blake2s_256(b"abc").unwrap();
        assert_eq!(
            d,
            [
                0x50, 0x8c, 0x5e, 0x8c, 0x32, 0x7c, 0x14, 0xe2, 0xe1, 0xa7, 0x2b, 0xa3, 0x4e, 0xeb,
                0x45, 0x2f, 0x37, 0x45, 0x8b, 0x20, 0x9e, 0xd6, 0x3a, 0x29, 0x4d, 0x99, 0x9b, 0x4c,
                0x86, 0x67, 0x59, 0x82
            ]
        );
    }

    #[test]
    fn reset_preserves_salt_personal_key() {
        let tree = Blake2sTreeParams {
            salt: Some([1, 2, 3, 4, 5, 6, 7, 8]),
            personal: Some([9, 10, 11, 12, 13, 14, 15, 16]),
            ..Default::default()
        };
        let key = [0u8; 16];
        let mut h = Blake2s::new_with_tree(28, Some(&key), Some(&tree)).unwrap();
        h.update(&[0, 0]);
        let mut d1 = [0u8; 28];
        h.clone().finalize_into(&mut d1).unwrap();
        h.reset();
        h.update(&[0, 0]);
        let mut d2 = [0u8; 28];
        h.finalize_into(&mut d2).unwrap();
        assert_eq!(d1, d2);
    }

    #[test]
    fn clean_blocks_further_use() {
        let mut h = Blake2s::new_256();
        h.update(b"abc");
        h.clean();
        assert!(h.is_cleaned());
        h.update(b"abc");
        h.reset();
        assert!(h.is_cleaned());
    }

    #[test]
    fn vector_salt_personal() {
        fn dec(s: &str) -> alloc::vec::Vec<u8> {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect()
        }
        let input = dec("ED49501A47C4F0AABDD51F6860C7FE40F9E49959AC209B589A534440917007E38DB979F5EA30B70E1582447D31C419514C197FE8FB8086E95E91AE61C9BB40");
        let salt_b = dec("18310EC945EF2790");
        let pers_b = dec("77E474D49E48EE60");
        let expected = dec("3F831E364AF44086927031D59AF93F87958BD7D43F9EB18409AA461FBA72F7DB");
        let mut salt = [0u8; 8];
        salt.copy_from_slice(&salt_b);
        let mut person = [0u8; 8];
        person.copy_from_slice(&pers_b);
        let tree = Blake2sTreeParams {
            salt: Some(salt),
            personal: Some(person),
            ..Default::default()
        };
        let mut h = Blake2s::new_with_tree(32, None, Some(&tree)).unwrap();
        h.update(&input);
        let mut out = [0u8; 32];
        h.finalize_into(&mut out).unwrap();
        assert_eq!(&out[..], &expected[..]);
    }
}
