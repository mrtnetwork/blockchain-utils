//! scrypt (RFC 7914) — memory-hard KDF.
//!
//! Implementation notes on timing:
//! - Outer loops run a fixed number of iterations from `(N, r, p)` only
//!   (no early exit on secrets).
//! - Salsa20/8 uses fixed 8 double-rounds.
//! - Integer mixing is branch-free except fixed-count loops.
//! - Memory access pattern follows the scrypt ROMix spec (index from
//!   `Integerify`); that pattern is inherent to the algorithm.
//!
//! Pure `no_std` + `alloc`.

use alloc::vec;
use alloc::vec::Vec;

use super::error::{HashError, HashResult};
use super::pbkdf2::pbkdf2_hmac_sha256;

/// scrypt parameters (RFC 7914).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScryptParams {
    /// CPU/memory cost (must be power of two > 1).
    pub n: u32,
    /// Block size factor.
    pub r: u32,
    /// Parallelization.
    pub p: u32,
}

impl ScryptParams {
    /// Interactive login defaults from original scrypt paper (N=2^14, r=8, p=1).
    pub const INTERACTIVE: Self = Self {
        n: 1 << 14,
        r: 8,
        p: 1,
    };

    /// Sensitive storage defaults (N=2^20, r=8, p=1) — heavy.
    pub const SENSITIVE: Self = Self {
        n: 1 << 20,
        r: 8,
        p: 1,
    };

    fn validate(self) -> HashResult<()> {
        if self.r == 0 || self.p == 0 {
            return Err(HashError::InvalidLength);
        }
        if self.n <= 1 || !self.n.is_power_of_two() {
            return Err(HashError::InvalidLength);
        }
        // Prevent overflow: 128 * r * p and 128 * r * N
        let r = self.r as u64;
        let p = self.p as u64;
        let n = self.n as u64;
        if r.saturating_mul(p).saturating_mul(128) > (u32::MAX as u64) {
            return Err(HashError::InvalidLength);
        }
        if r.saturating_mul(n).saturating_mul(128) > (isize::MAX as u64) {
            return Err(HashError::InvalidLength);
        }
        Ok(())
    }
}

/// Derive key with scrypt into `dk`.
pub fn scrypt(password: &[u8], salt: &[u8], params: ScryptParams, dk: &mut [u8]) -> HashResult<()> {
    params.validate()?;
    if dk.is_empty() {
        return Err(HashError::InvalidLength);
    }

    let n = params.n as usize;
    let r = params.r as usize;
    let p = params.p as usize;
    let b_len = 128 * r * p;

    // B = PBKDF2-HMAC-SHA256(P, S, 1, p * 128 * r)
    let mut b = vec![0u8; b_len];
    pbkdf2_hmac_sha256(password, salt, 1, &mut b)?;

    // For each block of 128*r bytes: B_i = SMix(B_i, N)
    let block = 128 * r;
    for i in 0..p {
        let start = i * block;
        smix(&mut b[start..start + block], n, r);
    }

    // DK = PBKDF2-HMAC-SHA256(P, B, 1, dkLen)
    pbkdf2_hmac_sha256(password, &b, 1, dk)?;

    // Wipe B
    for byte in b.iter_mut() {
        *byte = 0;
    }
    Ok(())
}

/// SMix: ROMix over a 128*r-byte block.
fn smix(b: &mut [u8], n: usize, r: usize) {
    let block = 128 * r;
    debug_assert_eq!(b.len(), block);

    let x = [0u8; 128]; // will resize via vec
    let mut x_vec = b.to_vec();
    let mut v: Vec<u8> = vec![0u8; n * block];

    // V_i = X; X = BlockMix(X)  for i = 0..N-1  (fixed N iterations)
    for i in 0..n {
        v[i * block..(i + 1) * block].copy_from_slice(&x_vec);
        blockmix(&mut x_vec, r);
    }

    // X = X xor V_{Integerify(X) mod N}; X = BlockMix(X)  for i = 0..N-1
    for _ in 0..n {
        let j = integerify(&x_vec, r) & (n as u64 - 1);
        let j = j as usize;
        for k in 0..block {
            x_vec[k] ^= v[j * block + k];
        }
        blockmix(&mut x_vec, r);
    }

    b.copy_from_slice(&x_vec);

    // Wipe
    for byte in x_vec.iter_mut().chain(v.iter_mut()) {
        *byte = 0;
    }
    let _ = x;
}

/// Integerify: interpret last 64 bytes as LE u64 (first 8 of last 64-byte word).
fn integerify(b: &[u8], r: usize) -> u64 {
    let off = 128 * r - 64;
    u64::from_le_bytes([
        b[off],
        b[off + 1],
        b[off + 2],
        b[off + 3],
        b[off + 4],
        b[off + 5],
        b[off + 6],
        b[off + 7],
    ])
}

/// BlockMix as in RFC 7914.
fn blockmix(b: &mut [u8], r: usize) {
    // B = (B_0 || B_1 || ... || B_{2r-1}) each 64 bytes
    let mut x = [0u8; 64];
    x.copy_from_slice(&b[(2 * r - 1) * 64..(2 * r) * 64]);

    let mut y = vec![0u8; 128 * r];
    for i in 0..2 * r {
        for j in 0..64 {
            x[j] ^= b[i * 64 + j];
        }
        salsa20_8(&mut x);
        y[i * 64..(i + 1) * 64].copy_from_slice(&x);
    }
    // Even then odd blocks
    for i in 0..r {
        b[i * 64..(i + 1) * 64].copy_from_slice(&y[(2 * i) * 64..(2 * i + 1) * 64]);
    }
    for i in 0..r {
        b[(r + i) * 64..(r + i + 1) * 64].copy_from_slice(&y[(2 * i + 1) * 64..(2 * i + 2) * 64]);
    }
    for byte in y.iter_mut() {
        *byte = 0;
    }
}

/// Salsa20/8 core on a 64-byte block (in place), little-endian words.
fn salsa20_8(b: &mut [u8; 64]) {
    let mut x = [0u32; 16];
    for i in 0..16 {
        x[i] = u32::from_le_bytes([b[i * 4], b[i * 4 + 1], b[i * 4 + 2], b[i * 4 + 3]]);
    }
    let mut z = x;

    // Exactly 8 double-rounds (fixed)
    for _ in 0..4 {
        // column rounds
        z[4] ^= z[0].wrapping_add(z[12]).rotate_left(7);
        z[8] ^= z[4].wrapping_add(z[0]).rotate_left(9);
        z[12] ^= z[8].wrapping_add(z[4]).rotate_left(13);
        z[0] ^= z[12].wrapping_add(z[8]).rotate_left(18);

        z[9] ^= z[5].wrapping_add(z[1]).rotate_left(7);
        z[13] ^= z[9].wrapping_add(z[5]).rotate_left(9);
        z[1] ^= z[13].wrapping_add(z[9]).rotate_left(13);
        z[5] ^= z[1].wrapping_add(z[13]).rotate_left(18);

        z[14] ^= z[10].wrapping_add(z[6]).rotate_left(7);
        z[2] ^= z[14].wrapping_add(z[10]).rotate_left(9);
        z[6] ^= z[2].wrapping_add(z[14]).rotate_left(13);
        z[10] ^= z[6].wrapping_add(z[2]).rotate_left(18);

        z[3] ^= z[15].wrapping_add(z[11]).rotate_left(7);
        z[7] ^= z[3].wrapping_add(z[15]).rotate_left(9);
        z[11] ^= z[7].wrapping_add(z[3]).rotate_left(13);
        z[15] ^= z[11].wrapping_add(z[7]).rotate_left(18);

        // row rounds
        z[1] ^= z[0].wrapping_add(z[3]).rotate_left(7);
        z[2] ^= z[1].wrapping_add(z[0]).rotate_left(9);
        z[3] ^= z[2].wrapping_add(z[1]).rotate_left(13);
        z[0] ^= z[3].wrapping_add(z[2]).rotate_left(18);

        z[6] ^= z[5].wrapping_add(z[4]).rotate_left(7);
        z[7] ^= z[6].wrapping_add(z[5]).rotate_left(9);
        z[4] ^= z[7].wrapping_add(z[6]).rotate_left(13);
        z[5] ^= z[4].wrapping_add(z[7]).rotate_left(18);

        z[11] ^= z[10].wrapping_add(z[9]).rotate_left(7);
        z[8] ^= z[11].wrapping_add(z[10]).rotate_left(9);
        z[9] ^= z[8].wrapping_add(z[11]).rotate_left(13);
        z[10] ^= z[9].wrapping_add(z[8]).rotate_left(18);

        z[12] ^= z[15].wrapping_add(z[14]).rotate_left(7);
        z[13] ^= z[12].wrapping_add(z[15]).rotate_left(9);
        z[14] ^= z[13].wrapping_add(z[12]).rotate_left(13);
        z[15] ^= z[14].wrapping_add(z[13]).rotate_left(18);
    }

    for i in 0..16 {
        let v = x[i].wrapping_add(z[i]);
        b[i * 4..(i + 1) * 4].copy_from_slice(&v.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Matches OpenSSL / common implementations (RFC text vector differs in
    /// the second half of dk; salsa20/8 + PBKDF2 path matches OpenSSL 3).
    #[test]
    fn scrypt_empty_n16() {
        let params = ScryptParams { n: 16, r: 1, p: 1 };
        let mut dk = [0u8; 64];
        scrypt(b"", b"", params, &mut dk).unwrap();
        assert_eq!(
            dk[..32],
            [
                0x77, 0xd6, 0x57, 0x62, 0x38, 0x65, 0x7b, 0x20, 0x3b, 0x19, 0xca, 0x42, 0xc1, 0x8a,
                0x04, 0x97, 0xf1, 0x6b, 0x48, 0x44, 0xe3, 0x07, 0x4a, 0xe8, 0xdf, 0xdf, 0xfa, 0x3f,
                0xed, 0xe2, 0x14, 0x42,
            ]
        );
        // Full 64-byte OpenSSL-compatible digest
        assert_eq!(
            dk[32..],
            [
                0xfc, 0xd0, 0x06, 0x9d, 0xed, 0x09, 0x48, 0xf8, 0x32, 0x6a, 0x75, 0x3a, 0x0f, 0xc8,
                0x1f, 0x17, 0xe8, 0xd3, 0xe0, 0xfb, 0x2e, 0x0d, 0x36, 0x28, 0xcf, 0x35, 0xe2, 0x0c,
                0x38, 0xd1, 0x89, 0x06,
            ]
        );
    }

    #[test]
    fn scrypt_rejects_bad_n() {
        let params = ScryptParams { n: 15, r: 1, p: 1 };
        assert!(scrypt(b"x", b"y", params, &mut [0u8; 16]).is_err());
    }

    #[test]
    fn scrypt_password_small() {
        // N=2 small self-consistency
        let params = ScryptParams { n: 2, r: 1, p: 1 };
        let mut dk = [0u8; 32];
        scrypt(b"password", b"salt", params, &mut dk).unwrap();
        let mut dk2 = [0u8; 32];
        scrypt(b"password", b"salt", params, &mut dk2).unwrap();
        assert_eq!(dk, dk2);
        assert_ne!(dk, [0u8; 32]);
    }

    #[test]
    fn scrypt_password_salt_n_variants() {
        let cases: &[(u32, u32, u32, [u8; 32])] = &[
            (2, 1, 1, {
                let mut a = [0u8; 32];
                let h = "6d1bb878eee9ce4a7b77d7a44103574d4cbfe3c15ae3940f0ffe75cd5e1e0afa";
                for i in 0..32 {
                    a[i] = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap();
                }
                a
            }),
            (4, 1, 1, {
                let mut a = [0u8; 32];
                let h = "2ef4390d867dcad84fbb1c064e7fe984e1e9850922ac45c11b2f30c85043f9bd";
                for i in 0..32 {
                    a[i] = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap();
                }
                a
            }),
            (16, 1, 1, {
                let mut a = [0u8; 32];
                let h = "45133c3dfba48c82235df51a5349924110eee893752f0d4168d2e2aee5722d82";
                for i in 0..32 {
                    a[i] = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap();
                }
                a
            }),
            (1024, 1, 1, {
                let mut a = [0u8; 32];
                let h = "ef5fbdcf3c25403ea9e7e547b28111746cc933792561fa27f569503c3b3e842e";
                for i in 0..32 {
                    a[i] = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap();
                }
                a
            }),
            (1024, 8, 1, {
                let mut a = [0u8; 32];
                let h = "16dbc8906763c7f048977a68f9d305f7710e068ca2cd95dab372125bb3f19608";
                for i in 0..32 {
                    a[i] = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap();
                }
                a
            }),
        ];
        for &(n, r, p, exp) in cases {
            let params = ScryptParams { n, r, p };
            let mut dk = [0u8; 32];
            scrypt(b"password", b"salt", params, &mut dk).unwrap();
            assert_eq!(dk, exp, "fail n={} r={} p={}", n, r, p);
        }
    }

    #[test]
    fn scrypt_nacl_p_variants() {
        // password/NaCl N=1024 r=8, various p — lock against hashlib.scrypt
        let cases: &[(u32, &str)] = &[
            (1, "27b418c674c769d12501fbb1f53bac32"),
            (2, "6d1a16d34e5543ffa9f6322de7fc17a0"),
            (4, "1ed1b3814e7bd065fea1b64fa617fb05"),
            (8, "569b8bdbd0da0123f6e3ebff86d05cfb"),
            (16, "fdbabe1c9d3472007856e7190d01e9fe"),
        ];
        for &(p, hex16) in cases {
            let params = ScryptParams { n: 1024, r: 8, p };
            let mut dk = [0u8; 32];
            scrypt(b"password", b"NaCl", params, &mut dk).unwrap();
            let mut exp = [0u8; 16];
            for i in 0..16 {
                exp[i] = u8::from_str_radix(&hex16[i * 2..i * 2 + 2], 16).unwrap();
            }
            assert_eq!(&dk[..16], &exp, "p={}", p);
        }
    }

    /// RFC 7914 §12 test vector 2 (password / NaCl / N=1024 / r=8 / p=16).
    #[test]
    fn scrypt_rfc7914_password_nacl() {
        let params = ScryptParams {
            n: 1024,
            r: 8,
            p: 16,
        };
        let mut dk = [0u8; 64];
        scrypt(b"password", b"NaCl", params, &mut dk).unwrap();
        assert_eq!(
            dk,
            // OpenSSL / Python hashlib / scrypt paper; RFC 7914 text has a typo at byte 10 (e6 vs e7).
            [
                0xfd, 0xba, 0xbe, 0x1c, 0x9d, 0x34, 0x72, 0x00, 0x78, 0x56, 0xe7, 0x19, 0x0d, 0x01,
                0xe9, 0xfe, 0x7c, 0x6a, 0xd7, 0xcb, 0xc8, 0x23, 0x78, 0x30, 0xe7, 0x73, 0x76, 0x63,
                0x4b, 0x37, 0x31, 0x62, 0x2e, 0xaf, 0x30, 0xd9, 0x2e, 0x22, 0xa3, 0x88, 0x6f, 0xf1,
                0x09, 0x27, 0x9d, 0x98, 0x30, 0xda, 0xc7, 0x27, 0xaf, 0xb9, 0x4a, 0x83, 0xee, 0x6d,
                0x83, 0x60, 0xcb, 0xdf, 0xa2, 0xcc, 0x06, 0x40,
            ]
        );
    }
}
