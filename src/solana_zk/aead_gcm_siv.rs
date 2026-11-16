//! AES-128-GCM-SIV (RFC 8452) decrypt/encrypt for Solana AES balances.
//!
//! /// Zero-dep port of the `aes-gcm-siv` usage in
//! `zk-sdk/src/encryption/auth_encryption.rs`: 12-byte nonce || 8-byte
//! ciphertext || 16-byte tag (36 bytes total, matches
//! `solana_zk_sdk_pod::AE_CIPHERTEXT_LEN`). POLYVAL is implemented over
//! GF(2^128) with schoolbook carryless multiplication (tiny inputs only).
//! Verified against RFC 8452 §7 field examples, §C.1 vectors, and the
//! zk-sdk AES compatibility vector.

use crate::solana_zk::{SolanaZkError, SolanaZkResult};

/// GCM-SIV nonce length (96 bits).
pub const GCM_SIV_NONCE_LEN: usize = 12;
/// Balance plaintext length (u64 LE).
pub const GCM_SIV_PLAINTEXT_LEN: usize = 8;
/// Authentication tag length.
pub const GCM_SIV_TAG_LEN: usize = 16;
/// Full AE ciphertext length (nonce || ct || tag).
pub const GCM_SIV_CIPHERTEXT_LEN: usize =
    GCM_SIV_NONCE_LEN + GCM_SIV_PLAINTEXT_LEN + GCM_SIV_TAG_LEN;

/// POLYVAL reduction constant `x^127+x^126+x^121+1`
/// (`f = x^128+x^127+x^126+x^121+1` without the `x^128` term).
const POLYVAL_R: u128 = (1u128 << 127) | (1u128 << 126) | (1u128 << 121) | 1;
/// `x^-128 = x^127+x^124+x^121+x^114+1` (RFC 8452 §3).
const POLYVAL_XINV128: u128 =
    (1u128 << 127) | (1u128 << 124) | (1u128 << 121) | (1u128 << 114) | 1;

/// Carryless multiply mod the POLYVAL field (LE convention:
/// bit `i` of the u128 is the `x^i` coefficient).
fn gfmul(mut a: u128, mut b: u128) -> u128 {
    let mut z = 0u128;
    for _ in 0..128 {
        if b & 1 == 1 {
            z ^= a;
        }
        let carry = (a >> 127) & 1;
        a <<= 1;
        if carry == 1 {
            a ^= POLYVAL_R;
        }
        b >>= 1;
    }
    z
}

/// `dot(a, b) = a * b * x^-128` (RFC 8452 §3).
/// Test-only: exercised by the RFC 8452 §7 field-arithmetic vector.
#[cfg(test)]
fn polyval_dot(a: u128, b: u128) -> u128 {
    gfmul(a, gfmul(b, POLYVAL_XINV128))
}

/// `POLYVAL(H, blocks)`: `S = dot(S ^ X_j, H)` from `S = 0`.
fn polyval(h: u128, blocks: &[u128]) -> u128 {
    let h_dot = gfmul(h, POLYVAL_XINV128);
    let mut s = 0u128;
    for x in blocks {
        s = gfmul(s ^ x, h_dot);
    }
    s
}

/// AES-128 encrypt one block with a 16-byte key.
fn aes128_block(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    use crate::cipher::block::BlockCipher;
    let aes = crate::cipher::aes::Aes::aes128(key);
    let mut out = *block;
    aes.encrypt_block(&mut out).expect("aes block");
    out
}

/// Derive per-nonce record keys (RFC 8452 §4): auth key from
/// counters 0..1, encryption key from counters 2..3 (first 8 bytes each).
fn derive_keys(key: &[u8; 16], nonce: &[u8; 12]) -> ([u8; 16], [u8; 16]) {
    let mut auth = [0u8; 16];
    let mut enc = [0u8; 16];
    for (i, out) in [&mut auth, &mut enc].into_iter().enumerate() {
        for half in 0..2 {
            let ctr = (i * 2 + half) as u32;
            let mut block = [0u8; 16];
            block[..4].copy_from_slice(&ctr.to_le_bytes());
            block[4..].copy_from_slice(nonce);
            let ct = aes128_block(key, &block);
            out[half * 8..half * 8 + 8].copy_from_slice(&ct[..8]);
        }
    }
    (auth, enc)
}

/// AES-CTR with LE32-wrapping counter on bytes 0..4.
fn aes_ctr(enc_key: &[u8; 16], mut counter: [u8; 16], input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut off = 0;
    while off < input.len() {
        let ks = aes128_block(enc_key, &counter);
        let n = (input.len() - off).min(16);
        for i in 0..n {
            out.push(ks[i] ^ input[off + i]);
        }
        let c = u32::from_le_bytes([counter[0], counter[1], counter[2], counter[3]])
            .wrapping_add(1);
        counter[..4].copy_from_slice(&c.to_le_bytes());
        off += n;
    }
    out
}

/// Compute the SIV tag over (empty AD, plaintext).
fn siv_tag(
    auth_key: &[u8; 16],
    enc_key: &[u8; 16],
    nonce: &[u8; 12],
    plaintext: &[u8],
) -> [u8; 16] {
    // X = padded plaintext ++ length block (ad_len = 0).
    let mut blocks = Vec::new();
    let mut padded = plaintext.to_vec();
    while !padded.len().is_multiple_of(16) {
        padded.push(0);
    }
    for c in padded.as_chunks::<16>().0 {
        let mut b = [0u8; 16];
        b.copy_from_slice(c);
        blocks.push(u128::from_le_bytes(b));
    }
    let mut len_block = [0u8; 16];
    len_block[8..].copy_from_slice(&((plaintext.len() as u64) * 8).to_le_bytes());
    blocks.push(u128::from_le_bytes(len_block));

    let h = u128::from_le_bytes(*auth_key);
    let mut s = polyval(h, &blocks).to_le_bytes();
    for i in 0..12 {
        s[i] ^= nonce[i];
    }
    s[15] &= 0x7f;
    aes128_block(enc_key, &s)
}

/// Decrypt a 36-byte AE ciphertext with a 16-byte key.
/// Returns the u64 balance, or `InvalidProof` when authentication fails.
pub fn ae_decrypt(key: &[u8; 16], bytes: &[u8; 36]) -> SolanaZkResult<u64> {
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&bytes[..12]);
    let (auth_key, enc_key) = derive_keys(key, &nonce);
    let tag: &[u8; 16] = bytes[20..36].try_into().map_err(|_| SolanaZkError::InvalidLength)?;
    let mut counter = *tag;
    counter[15] |= 0x80;
    let plaintext = aes_ctr(&enc_key, counter, &bytes[12..20]);
    let expected = siv_tag(&auth_key, &enc_key, &nonce, &plaintext);
    // Constant-time tag comparison.
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= expected[i] ^ tag[i];
    }
    if diff != 0 {
        return Err(SolanaZkError::InvalidProof);
    }
    let mut le = [0u8; 8];
    le.copy_from_slice(&plaintext);
    Ok(u64::from_le_bytes(le))
}

/// Encrypt a u64 balance with a 16-byte key and caller nonce.
/// Empty AD, exactly like upstream `AuthenticatedEncryption::encrypt`.
pub fn ae_encrypt(
    key: &[u8; 16],
    amount: u64,
    nonce: &[u8; 12],
) -> SolanaZkResult<[u8; 36]> {
    let (auth_key, enc_key) = derive_keys(key, nonce);
    let plaintext = amount.to_le_bytes();
    let tag = siv_tag(&auth_key, &enc_key, nonce, &plaintext);
    let mut counter = tag;
    counter[15] |= 0x80;
    let ct = aes_ctr(&enc_key, counter, &plaintext);
    let mut out = [0u8; 36];
    out[..12].copy_from_slice(nonce);
    out[12..20].copy_from_slice(&ct);
    out[20..].copy_from_slice(&tag);
    Ok(out)
}

/// AES decryptable-balance length (36 bytes).
pub const AE_LEN: usize = GCM_SIV_CIPHERTEXT_LEN;

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 8452 §7 field arithmetic examples.
    #[test]
    fn rfc_field_examples() {
        // RFC hex strings are display (byte) order; the field maps byte[0]
        // LSB to x^0, i.e. u128 little-endian.
        let ab = hex("66e94bd4ef8a2c3b884cfa59ca342b2e");
        let bb = hex("ff000000000000000000000000000000");
        let a = u128::from_le_bytes(ab.try_into().unwrap());
        let b = u128::from_le_bytes(bb.try_into().unwrap());
        // dot(a,b) == ebe563401e7e91ea3ad6426b8140c394.
        let d = polyval_dot(a, b);
        let got: String = d
            .to_le_bytes()
            .iter()
            .map(|x| format!("{:02x}", x))
            .collect();
        assert_eq!(got, "ebe563401e7e91ea3ad6426b8140c394");
    }

    /// RFC 8452 §C.1 8-byte vector (key 01.., nonce 03..).
    #[test]
    fn rfc_c1_vector() {
        let key = hex("01000000000000000000000000000000");
        let nonce = hex("030000000000000000000000");
        let pt = hex("0100000000000000");
        let want = hex("b5d839330ac7b786578782fff6013b815b287c22493a364c");
        let (auth, enc) = derive_keys(
            &key.try_into().unwrap(),
            &nonce.clone().try_into().unwrap(),
        );
        assert_eq!(
            auth.iter().map(|x| format!("{:02x}", x)).collect::<String>(),
            "d9b360279694941ac5dbc6987ada7377"
        );
        assert_eq!(
            enc.iter().map(|x| format!("{:02x}", x)).collect::<String>(),
            "4004a0dcd862f2a57360219d2d44ef6c"
        );
        let tag = siv_tag(
            &auth,
            &enc,
            &nonce.try_into().unwrap(),
            &pt,
        );
        let mut counter = tag;
        counter[15] |= 0x80;
        let ct = aes_ctr(&enc, counter, &pt);
        let mut got = ct;
        got.extend_from_slice(&tag);
        assert_eq!(got, want);
    }

    /// zk-sdk AES compatibility vector (decrypt path).
    #[test]
    fn zksdk_compat_vector_decrypts() {
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
            0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ];
        let ct: [u8; 36] = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
            0x1b, 0x5a, 0x37, 0xbc, 0xf1, 0x4e, 0x84, 0x2c, 0x24, 0x03, 0x54,
            0x2b, 0x6b, 0x74, 0xe9, 0x8f, 0x1e, 0x17, 0x8a, 0x2a, 0xac, 0x29,
            0x21, 0x05, 0xe4,
        ];
        assert_eq!(ae_decrypt(&key, &ct).unwrap(), 0x0102_0304_0506_0708);
        // Tampered tag fails.
        let mut bad = ct;
        bad[35] ^= 1;
        assert!(ae_decrypt(&key, &bad).is_err());
    }

    /// Encrypt/decrypt roundtrip.
    #[test]
    fn roundtrip() {
        let key = [9u8; 16];
        let nonce = [7u8; 12];
        let enc = ae_encrypt(&key, 123456789, &nonce).unwrap();
        assert_eq!(ae_decrypt(&key, &enc).unwrap(), 123456789);
        assert_eq!(&enc[..12], &nonce);
    }
}
