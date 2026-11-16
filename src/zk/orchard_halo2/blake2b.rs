//! Minimal self-contained Blake2b-512 (RFC 7693).
//! LE message schedule; supports key (empty here), digest length 64,
//! salt/personal. Used by the Halo2 transcript (`Halo2-Transcript`
//! personalization). No `assert!`, Result style, `forbid(unsafe_code)`.

use crate::zk::orchard_halo2::error::{Halo2Error, Halo2Result};

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

#[inline]
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

fn compress(h: &mut [u64; 8], block: &[u8; 128], t: u128, last: bool) {
    let mut m = [0u64; 16];
    for (i, mi) in m.iter_mut().enumerate() {
        *mi = u64::from_le_bytes([
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
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&IV);
    v[12] ^= (t & 0xffff_ffff_ffff_ffff) as u64;
    v[13] ^= ((t >> 64) & 0xffff_ffff_ffff_ffff) as u64;
    if last {
        v[14] = !v[14];
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
        h[i] ^= v[i] ^ v[i + 8];
    }
}

/// Blake2b state with personalization. Cloneable (transcript clones per squeeze).
#[derive(Clone)]
pub struct Blake2b {
    h: [u64; 8],
    buf: [u8; 128],
    buf_len: usize,
    t: u128,
}

impl Blake2b {
    /// New state, digest length 64, optional 16-byte personalization.
    pub fn new(personalization: &[u8]) -> Halo2Result<Self> {
        if personalization.len() != 16 {
            return Err(Halo2Error::operation_failed(
                "blake2b::new",
                "personalization must be 16 bytes",
            ));
        }
        let mut param = [0u8; 64];
        param[0] = 64;
        param[1] = 0;
        param[2] = 1;
        param[3] = 1;
        param[48..64].copy_from_slice(personalization);
        let mut h = IV;
        for i in 0..8 {
            let p = u64::from_le_bytes([
                param[i * 8],
                param[i * 8 + 1],
                param[i * 8 + 2],
                param[i * 8 + 3],
                param[i * 8 + 4],
                param[i * 8 + 5],
                param[i * 8 + 6],
                param[i * 8 + 7],
            ]);
            h[i] ^= p;
        }
        Ok(Self {
            h,
            buf: [0u8; 128],
            buf_len: 0,
            t: 0,
        })
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut off = 0usize;
        while off < data.len() {
            // Flush a full buffer only when more data remains: the last
            // message block must reach `finalize` uncompressed so it is
            // processed with `last=true`. Eagerly flushing an exactly-full
            // buffer appends a spurious empty last block and corrupts the
            // digest whenever the total length is a nonzero multiple of 128.
            if self.buf_len == 128 {
                self.t += 128;
                let mut block = [0u8; 128];
                block.copy_from_slice(&self.buf);
                compress(&mut self.h, &block, self.t, false);
                self.buf_len = 0;
            }
            let room = 128 - self.buf_len;
            let take = core::cmp::min(room, data.len() - off);
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[off..off + take]);
            self.buf_len += take;
            off += take;
        }
    }

    /// Finalize into 64 LE-ordered bytes (standard Blake2b output).
    pub fn finalize(&self) -> [u8; 64] {
        let mut st = self.clone();
        st.t += st.buf_len as u128;
        let mut block = [0u8; 128];
        block[..st.buf_len].copy_from_slice(&st.buf[..st.buf_len]);
        compress(&mut st.h, &block, st.t, true);
        let mut out = [0u8; 64];
        for (i, hi) in st.h.iter().enumerate() {
            out[i * 8..i * 8 + 8].copy_from_slice(&hi.to_le_bytes());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(personalization: &[u8; 16], parts: &[&[u8]]) -> [u8; 64] {
        let mut h = Blake2b::new(personalization).unwrap();
        for p in parts {
            h.update(p);
        }
        h.finalize()
    }

    fn hex(s: &str) -> [u8; 64] {
        assert_eq!(s.len(), 128);
        let mut out = [0u8; 64];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    /// Reference vectors from an independent Blake2b (Python `hashlib`,
    /// personalization `b"Halo2-Transcript"`).
    #[test]
    fn known_answers() {
        let p = b"Halo2-Transcript";
        assert_eq!(hash(p, &[b""]), hex("a00b7d27460fda08f2843863fb81f89075b99584453a6bd8a8c1e84684ac5422391738d086dc7432f1ddeead5e4d4fb83d9bb83238961071175edf866675ddb2"));
        assert_eq!(hash(p, &[b"abc"]), hex("1a461cab63d8b3dbc9daab1574729f55d54e844b17b69ab1fce6dae8caecb9d24bb550cd9270aa53c8e9277d68008b3080da0b66fc6853231e15abec0b0159e5"));
        assert_eq!(hash(p, &[&[0u8; 129]]), hex("967b63698454ef509f5c92e1a82d736568915ddbfcde59ac711cbeea7da10ec636826b672914c06a77da8253bd43ca57f888657c24f80f5eaecded9f24f2a1b4"));
    }

    /// Exact multiples of the 128-byte block must hash as a final full
    /// block (`last=true`), not as an extra empty last block. A stale
    /// eager-flush bug corrupted exactly these digests (broke n=7 proofs:
    /// the transcript hit length 24192 = 189*128 at the xi squeeze).
    #[test]
    fn exact_block_multiples() {
        let p = b"Halo2-Transcript";
        assert_eq!(hash(p, &[&[0u8; 128]]), hex("66952edfce832af191ef074a27ef18c13899b3420e17d77fe2b55551a1fd5ed8d345ced7bb0c48c7bf4f5900ba84b7321e1698d698e3d24ea6f4e81328a25008"));
        assert_eq!(hash(p, &[&[0u8; 256]]), hex("2d681d944b1cc608a899c17d16afa17b9ac62622784ba1189122166f4b69b20326bb183f6ef691597066eda88db1199ee38cc6b365560ed0406584b734b6e405"));
        assert_eq!(hash(p, &[&[0u8; 384]]), hex("c48fde213f230860958ad89ffa41a7ea1def33321ed5aeb7206f1117c9a9b9c067039c43d6cee92063ec1695577557b235ad98aed7b57c15b1d17cff7b16cbfc"));
    }

    /// Chunked updates must equal single-shot updates, including splits
    /// that land exactly on block boundaries.
    #[test]
    fn chunking_is_invisible() {
        let p = b"Halo2-Transcript";
        let msg = [0x5au8; 300];
        let whole = hash(p, &[&msg]);
        for split in [0usize, 1, 64, 127, 128, 129, 200, 256, 299, 300] {
            let parted = hash(p, &[&msg[..split], &msg[split..]]);
            assert_eq!(whole, parted, "split at {split}");
        }
        // Byte-at-a-time must also agree (exercises boundary flushes).
        let mut h = Blake2b::new(p).unwrap();
        for b in msg.iter() {
            h.update(core::slice::from_ref(b));
        }
        assert_eq!(whole, h.finalize());
    }
}
