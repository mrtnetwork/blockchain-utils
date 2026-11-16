//! ChaCha20 stream cipher (RFC 8439 / IETF + original 8-byte nonce variant).
//!
//! Pure `no_std`, zero-dependency.
//!
//! Supports:
//! - IETF: 32-byte key, 12-byte nonce, 32-bit counter
//! - Original: 32-byte key, 8-byte nonce, 64-bit counter
//! - `stream_xor` with `seek_bytes` (keystream offset) with keystream offset support

use super::error::{CipherError, CipherResult};
use crate::ct::ct_zeroize;

/// ChaCha20 key length.
pub const KEY_LEN: usize = 32;
/// IETF nonce length.
pub const NONCE_LEN: usize = 12;
/// Original ChaCha20 nonce length.
pub const NONCE_LEN_8: usize = 8;
/// Block size in bytes.
pub const BLOCK_LEN: usize = 64;

/// Generate one 64-byte ChaCha20 block (IETF: 12-byte nonce, 32-bit counter).
pub fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut state = [0u32; 16];
    init_constants(&mut state);
    load_key(&mut state, key);
    state[12] = counter;
    state[13] = u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);
    state[14] = u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]);
    state[15] = u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]);
    run_rounds(&state)
}

/// Generate one block from a full 16-byte nonce/counter block `nc`.
///
/// Layout of `nc` (little-endian words → state[12..16]):
/// bytes 0..4 → state[12], 4..8 → state[13], 8..12 → state[14], 12..16 → state[15].
pub fn chacha20_block_nc(key: &[u8; 32], nc: &[u8; 16]) -> [u8; 64] {
    let mut state = [0u32; 16];
    init_constants(&mut state);
    load_key(&mut state, key);
    for i in 0..4 {
        state[12 + i] =
            u32::from_le_bytes([nc[i * 4], nc[i * 4 + 1], nc[i * 4 + 2], nc[i * 4 + 3]]);
    }
    run_rounds(&state)
}

fn init_constants(state: &mut [u32; 16]) {
    // "expand 32-byte k"
    state[0] = 0x6170_7865;
    state[1] = 0x3320_646e;
    state[2] = 0x7962_2d32;
    state[3] = 0x6b20_6574;
}

fn load_key(state: &mut [u32; 16], key: &[u8; 32]) {
    for i in 0..8 {
        state[4 + i] =
            u32::from_le_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
    }
}

fn run_rounds(state: &[u32; 16]) -> [u8; 64] {
    let mut working = *state;
    for _ in 0..10 {
        quarter_round(&mut working, 0, 4, 8, 12);
        quarter_round(&mut working, 1, 5, 9, 13);
        quarter_round(&mut working, 2, 6, 10, 14);
        quarter_round(&mut working, 3, 7, 11, 15);
        quarter_round(&mut working, 0, 5, 10, 15);
        quarter_round(&mut working, 1, 6, 11, 12);
        quarter_round(&mut working, 2, 7, 8, 13);
        quarter_round(&mut working, 3, 4, 9, 14);
    }
    for i in 0..16 {
        working[i] = working[i].wrapping_add(state[i]);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        out[4 * i..4 * i + 4].copy_from_slice(&working[i].to_le_bytes());
    }
    out
}

#[inline(always)]
fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = s[d].rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = s[b].rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = s[d].rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = s[b].rotate_left(7);
}

/// Increment the first `counter_len` bytes of `nc` as a little-endian integer.
fn increment_counter(nc: &mut [u8; 16], counter_len: usize) {
    let mut carry = 1u16;
    for b in nc.iter_mut().take(counter_len) {
        let sum = *b as u16 + carry;
        *b = sum as u8;
        carry = sum >> 8;
        if carry == 0 {
            break;
        }
    }
}

/// XOR `src` with ChaCha20 keystream into `dst` (IETF 12-byte nonce).
///
/// Counter starts at `counter`. `dst.len()` must be ≥ `src.len()`; only
/// `src.len()` bytes are written.
pub fn chacha20_xor(
    key: &[u8],
    nonce: &[u8],
    mut counter: u32,
    data: &[u8],
    out: &mut [u8],
) -> CipherResult<()> {
    if key.len() != KEY_LEN {
        return Err(CipherError::InvalidKeyLength);
    }
    if nonce.len() != NONCE_LEN {
        return Err(CipherError::InvalidNonceLength);
    }
    if out.len() < data.len() {
        return Err(CipherError::InvalidLength);
    }
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(key);
    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(nonce);

    let mut offset = 0;
    while offset < data.len() {
        let block = chacha20_block(&key_arr, counter, &nonce_arr);
        let take = core::cmp::min(64, data.len() - offset);
        for i in 0..take {
            out[offset + i] = data[offset + i] ^ block[i];
        }
        offset += take;
        counter = counter.wrapping_add(1);
    }
    Ok(())
}

/// Stream XOR with optional keystream seek — API.
///
/// # Arguments
///
/// * `key` — 32-byte ChaCha20 key
/// * `nonce` — depending on `nonce_inplace_counter_length`:
///   - `0`: nonce is 8 or 12 bytes; a fresh 16-byte counter block is built
///     with the counter in the leading bytes and nonce at the end
///   - `> 0`: nonce must be 16 bytes; the first `nonce_inplace_counter_length`
///     bytes are treated as the counter and incremented in place (caller’s
///     buffer is **not** mutated; a copy is used)
/// * `src` — plaintext / ciphertext input
/// * `dst` — output buffer, must be ≥ `src.len()`
/// * `nonce_inplace_counter_length` — see above (0 = auto layout)
/// * `seek_bytes` — number of keystream bytes to skip before XORing
///
/// # Seek semantics
///
/// `seek_bytes = block_skip * 64 + byte_skip`:
/// 1. Advance the block counter by `block_skip` (no output)
/// 2. If `byte_skip > 0`, generate one block and XOR from offset `byte_skip`
/// 3. Continue with full blocks for the remainder of `src`
pub fn stream_xor(
    key: &[u8],
    nonce: &[u8],
    src: &[u8],
    dst: &mut [u8],
    nonce_inplace_counter_length: usize,
    seek_bytes: usize,
) -> CipherResult<()> {
    if key.len() != KEY_LEN {
        return Err(CipherError::InvalidKeyLength);
    }
    if dst.len() < src.len() {
        return Err(CipherError::InvalidLength);
    }

    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(key);

    // Build 16-byte nonce/counter block
    let (mut nc, counter_len) = if nonce_inplace_counter_length == 0 {
        if nonce.len() != 8 && nonce.len() != 12 {
            return Err(CipherError::InvalidNonceLength);
        }
        let counter_len = 16 - nonce.len();
        let mut nc = [0u8; 16];
        nc[counter_len..].copy_from_slice(nonce);
        (nc, counter_len)
    } else {
        if nonce.len() != 16 {
            return Err(CipherError::InvalidNonceLength);
        }
        if nonce_inplace_counter_length > 16 {
            return Err(CipherError::InvalidLength);
        }
        let mut nc = [0u8; 16];
        nc.copy_from_slice(nonce);
        (nc, nonce_inplace_counter_length)
    };

    // Clear destination prefix (match reference BinaryOps.zero(dst) for used range)
    for b in dst.iter_mut().take(src.len()) {
        *b = 0;
    }

    let block_skip = seek_bytes / 64;
    let byte_skip = seek_bytes % 64;

    // Advance counter by block_skip (no XOR)
    for _ in 0..block_skip {
        increment_counter(&mut nc, counter_len);
    }

    let mut src_offset = 0;
    let mut block = [0u8; 64];

    // Partial first block after byte seek
    if byte_skip != 0 {
        block = chacha20_block_nc(&key_arr, &nc);
        let mut j = byte_skip;
        while j < 64 && src_offset < src.len() {
            dst[src_offset] = src[src_offset] ^ block[j];
            j += 1;
            src_offset += 1;
        }
        increment_counter(&mut nc, counter_len);
    }

    // Full remaining blocks
    while src_offset < src.len() {
        block = chacha20_block_nc(&key_arr, &nc);
        let take = core::cmp::min(64, src.len() - src_offset);
        for j in 0..take {
            dst[src_offset + j] = src[src_offset + j] ^ block[j];
        }
        src_offset += take;
        increment_counter(&mut nc, counter_len);
    }

    ct_zeroize(&mut block);
    ct_zeroize(&mut nc);
    Ok(())
}

/// Convenience: `stream_xor` with IETF 12-byte nonce, counter starting at 0, no seek.
#[inline]
pub fn stream_xor_ietf(
    key: &[u8],
    nonce: &[u8; 12],
    src: &[u8],
    dst: &mut [u8],
) -> CipherResult<()> {
    stream_xor(key, nonce, src, dst, 0, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc8439_section_2_3_2() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        let block = chacha20_block(&key, 1, &nonce);
        assert_eq!(
            &block[..],
            &[
                0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20,
                0x71, 0xc4, 0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a,
                0xc3, 0xd4, 0x6c, 0x4e, 0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2,
                0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2, 0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
                0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e
            ]
        );
    }

    #[test]
    fn stream_xor_matches_chacha20_xor() {
        let key = [0x42u8; 32];
        let nonce = [0u8; 12];
        let data = b"Hello ChaCha20 stream XOR seek test!!";
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        chacha20_xor(&key, &nonce, 0, data, &mut a[..data.len()]).unwrap();
        stream_xor(&key, &nonce, data, &mut b, 0, 0).unwrap();
        assert_eq!(&a[..data.len()], &b[..data.len()]);
    }

    #[test]
    fn stream_xor_seek_bytes() {
        let key = [0x11u8; 32];
        let nonce = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        ];
        let data = [0xAAu8; 100];

        // Full keystream XOR from offset 0
        let mut full = [0u8; 100];
        stream_xor(&key, &nonce, &data, &mut full, 0, 0).unwrap();

        // Seek 10 bytes: should match full[10..] XOR when applied to data[0..]
        // i.e. dst[i] = data[i] ^ keystream[i + 10]
        let mut seeked = [0u8; 90];
        stream_xor(&key, &nonce, &data[..90], &mut seeked, 0, 10).unwrap();
        for i in 0..90 {
            assert_eq!(
                seeked[i],
                data[i] ^ (full[i + 10] ^ data[i + 10]),
                "i={}",
                i
            );
            // simpler: keystream[i+10] = full[i+10] ^ data[i+10]
            // seeked[i] = data[i] ^ keystream[i+10]
            assert_eq!(seeked[i], data[i] ^ full[i + 10] ^ data[i + 10]);
        }
    }

    #[test]
    fn stream_xor_seek_across_block() {
        let key = [0x7fu8; 32];
        let nonce = [0u8; 12];
        let data = [0x55u8; 80];

        let mut full = [0u8; 80];
        stream_xor(&key, &nonce, &data, &mut full, 0, 0).unwrap();

        // seek past first block (64) + 5
        let mut seeked = [0u8; 10];
        stream_xor(&key, &nonce, &data[..10], &mut seeked, 0, 69).unwrap();
        for i in 0..10 {
            assert_eq!(seeked[i], data[i] ^ full[i + 69] ^ data[i + 69]);
        }
    }

    #[test]
    fn stream_xor_8_byte_nonce() {
        let key = [0x33u8; 32];
        let nonce = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let data = b"short";
        let mut out = [0u8; 5];
        stream_xor(&key, &nonce, data, &mut out, 0, 0).unwrap();
        // Deterministic
        let mut out2 = [0u8; 5];
        stream_xor(&key, &nonce, data, &mut out2, 0, 0).unwrap();
        assert_eq!(out, out2);
        assert_ne!(out, *data); // actually encrypted
    }
}
