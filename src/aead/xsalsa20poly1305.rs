//! XSalsa20-Poly1305 (NaCl `crypto_secretbox`) and `crypto_box` (X25519).
//!
//! Construction: `subkey = HSalsa20(key, nonce[0:16])`, then Salsa20/20 with
//! `subkey` and `nonce[16:24]`. The first 32 keystream bytes are the
//! one-time Poly1305 key; the remainder encrypts the message.
//!
//! Framing (NaCl order): the 16-byte authenticator comes FIRST
//! (`TAG ‖ CIPHERTEXT`), exactly like `crypto_secretbox_easy` /
//! `crypto_box_easy` (tweetnacl, libsodium, PyNaCl). This deliberately
//! differs from [`super::chacha20poly1305`] / AES-GCM in this crate, which
//! append the tag (`CIPHERTEXT ‖ TAG`) per RFC 8439. The [`super::Aead`]
//! trait is therefore NOT implemented here: its contract promises
//! ciphertext-then-tag.
//!
//! Nonce handling: strictly 24 bytes (anything else is
//! [`CipherError::InvalidNonceLength`]); there is no padding, because
//! silent padding would break cross-implementation compatibility.
//! Secretbox authenticates the ciphertext only — any non-empty `aad` is
//! rejected with [`CipherError::Unsupported`] (use ChaCha20-Poly1305 or
//! AES-GCM for associated data).
//!
//! Pure `no_std` + `core` only, constant-time where it matters
//! (fixed 20-round Salsa core, [`ct_eq`] tag check, zeroized intermediates).

use crate::cipher::error::{CipherError, CipherResult};
use crate::cipher::poly1305::poly1305;
use crate::ct::{ct_eq, ct_zeroize};
use crate::curve::x25519;

/// XSalsa20 key length in bytes.
pub const XSALSA_KEY_LEN: usize = 32;
/// XSalsa20 nonce length in bytes (strict).
pub const XSALSA_NONCE_LEN: usize = 24;
/// Poly1305 tag length in bytes.
pub const XSALSA_TAG_LEN: usize = 16;

/// X25519 key length in bytes (secret key, public key, shared secret).
pub const SALSABOX_KEY_LEN: usize = 32;

const SIGMA: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

#[inline]
fn rotl(v: u32, n: u32) -> u32 {
    v.rotate_left(n)
}

/// Best-effort wipe of a word buffer (mirrors [`ct_zeroize`] for `u32`).
fn zeroize_words(x: &mut [u32]) {
    for w in x.iter_mut() {
        *w = 0;
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    core::hint::black_box(x.as_ptr());
}

/// One Salsa20 double round (column round + row round), in place.
fn double_round(x: &mut [u32; 16]) {
    // Column rounds.
    x[4] ^= rotl(x[0].wrapping_add(x[12]), 7);
    x[8] ^= rotl(x[4].wrapping_add(x[0]), 9);
    x[12] ^= rotl(x[8].wrapping_add(x[4]), 13);
    x[0] ^= rotl(x[12].wrapping_add(x[8]), 18);
    x[9] ^= rotl(x[5].wrapping_add(x[1]), 7);
    x[13] ^= rotl(x[9].wrapping_add(x[5]), 9);
    x[1] ^= rotl(x[13].wrapping_add(x[9]), 13);
    x[5] ^= rotl(x[1].wrapping_add(x[13]), 18);
    x[14] ^= rotl(x[10].wrapping_add(x[6]), 7);
    x[2] ^= rotl(x[14].wrapping_add(x[10]), 9);
    x[6] ^= rotl(x[2].wrapping_add(x[14]), 13);
    x[10] ^= rotl(x[6].wrapping_add(x[2]), 18);
    x[3] ^= rotl(x[15].wrapping_add(x[11]), 7);
    x[7] ^= rotl(x[3].wrapping_add(x[15]), 9);
    x[11] ^= rotl(x[7].wrapping_add(x[3]), 13);
    x[15] ^= rotl(x[11].wrapping_add(x[7]), 18);
    // Row rounds.
    x[1] ^= rotl(x[0].wrapping_add(x[3]), 7);
    x[2] ^= rotl(x[1].wrapping_add(x[0]), 9);
    x[3] ^= rotl(x[2].wrapping_add(x[1]), 13);
    x[0] ^= rotl(x[3].wrapping_add(x[2]), 18);
    x[6] ^= rotl(x[5].wrapping_add(x[4]), 7);
    x[7] ^= rotl(x[6].wrapping_add(x[5]), 9);
    x[4] ^= rotl(x[7].wrapping_add(x[6]), 13);
    x[5] ^= rotl(x[4].wrapping_add(x[7]), 18);
    x[11] ^= rotl(x[10].wrapping_add(x[9]), 7);
    x[8] ^= rotl(x[11].wrapping_add(x[10]), 9);
    x[9] ^= rotl(x[8].wrapping_add(x[11]), 13);
    x[10] ^= rotl(x[9].wrapping_add(x[8]), 18);
    x[12] ^= rotl(x[15].wrapping_add(x[14]), 7);
    x[13] ^= rotl(x[12].wrapping_add(x[15]), 9);
    x[14] ^= rotl(x[13].wrapping_add(x[12]), 13);
    x[15] ^= rotl(x[14].wrapping_add(x[13]), 18);
}

fn load_le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// One 64-byte Salsa20/20 block: `key` (32 bytes), 8-byte `nonce`,
/// 64-bit block `counter`.
fn salsa20_block(key: &[u8; 32], nonce8: &[u8; 8], counter: u64) -> [u8; 64] {
    let mut s = [0u32; 16];
    s[0] = SIGMA[0];
    s[1] = load_le(&key[0..4]);
    s[2] = load_le(&key[4..8]);
    s[3] = load_le(&key[8..12]);
    s[4] = load_le(&key[12..16]);
    s[5] = SIGMA[1];
    s[6] = load_le(&nonce8[0..4]);
    s[7] = load_le(&nonce8[4..8]);
    s[8] = counter as u32;
    s[9] = (counter >> 32) as u32;
    s[10] = SIGMA[2];
    s[11] = load_le(&key[16..20]);
    s[12] = load_le(&key[20..24]);
    s[13] = load_le(&key[24..28]);
    s[14] = load_le(&key[28..32]);
    s[15] = SIGMA[3];
    let mut x = s;
    for _ in 0..10 {
        double_round(&mut x);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        out[i * 4..i * 4 + 4]
            .copy_from_slice(&x[i].wrapping_add(s[i]).to_le_bytes());
    }
    zeroize_words(&mut s);
    zeroize_words(&mut x);
    out
}

/// HSalsa20: 32-byte subkey from `key` and a 16-byte nonce (no counter,
/// no feed-forward addition).
fn hsalsa20(key: &[u8; 32], nonce16: &[u8; 16]) -> [u8; 32] {
    let mut x = [0u32; 16];
    x[0] = SIGMA[0];
    x[1] = load_le(&key[0..4]);
    x[2] = load_le(&key[4..8]);
    x[3] = load_le(&key[8..12]);
    x[4] = load_le(&key[12..16]);
    x[5] = SIGMA[1];
    x[6] = load_le(&nonce16[0..4]);
    x[7] = load_le(&nonce16[4..8]);
    x[8] = load_le(&nonce16[8..12]);
    x[9] = load_le(&nonce16[12..16]);
    x[10] = SIGMA[2];
    x[11] = load_le(&key[16..20]);
    x[12] = load_le(&key[20..24]);
    x[13] = load_le(&key[24..28]);
    x[14] = load_le(&key[28..32]);
    x[15] = SIGMA[3];
    for _ in 0..10 {
        double_round(&mut x);
    }
    let mut out = [0u8; 32];
    for (i, w) in [x[0], x[5], x[10], x[15], x[6], x[7], x[8], x[9]]
        .iter()
        .enumerate()
    {
        out[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    zeroize_words(&mut x);
    out
}

fn check_key_nonce(key: &[u8], nonce: &[u8]) -> CipherResult<([u8; 32], [u8; 24])> {
    if key.len() != XSALSA_KEY_LEN {
        return Err(CipherError::InvalidKeyLength);
    }
    if nonce.len() != XSALSA_NONCE_LEN {
        return Err(CipherError::InvalidNonceLength);
    }
    let mut k = [0u8; 32];
    let mut n = [0u8; 24];
    k.copy_from_slice(key);
    n.copy_from_slice(nonce);
    Ok((k, n))
}

fn check_aad_empty(aad: &[u8]) -> CipherResult<()> {
    if !aad.is_empty() {
        return Err(CipherError::Unsupported);
    }
    Ok(())
}

/// XOR `data` with the XSalsa20 keystream for `key`/`nonce24`, skipping the
/// first 32 keystream bytes (the Poly1305 one-time key region).
fn xsalsa_xor_msg(key: &[u8; 32], nonce24: &[u8; 24], data: &[u8], out: &mut [u8]) {
    let mut n16 = [0u8; 16];
    let mut n8 = [0u8; 8];
    n16.copy_from_slice(&nonce24[..16]);
    n8.copy_from_slice(&nonce24[16..]);
    let mut subkey = hsalsa20(key, &n16);
    // Keystream offset 32 = block 0 second half onward.
    let mut counter: u64 = 0;
    let mut skip = 32usize;
    let mut offset = 0usize;
    while offset < data.len() {
        let mut block = salsa20_block(&subkey, &n8, counter);
        counter = counter.wrapping_add(1);
        let mut i = skip;
        while i < 64 && offset < data.len() {
            out[offset] = data[offset] ^ block[i];
            offset += 1;
            i += 1;
        }
        skip = 0;
        ct_zeroize(&mut block[..]);
    }
    ct_zeroize(&mut n16[..]);
    ct_zeroize(&mut n8[..]);
    ct_zeroize(&mut subkey[..]);
}

/// First 32 XSalsa20 keystream bytes = the Poly1305 one-time key.
fn xsalsa_otk(key: &[u8; 32], nonce24: &[u8; 24]) -> [u8; 32] {
    let mut n16 = [0u8; 16];
    let mut n8 = [0u8; 8];
    n16.copy_from_slice(&nonce24[..16]);
    n8.copy_from_slice(&nonce24[16..]);
    let mut subkey = hsalsa20(key, &n16);
    let mut block = salsa20_block(&subkey, &n8, 0);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&block[..32]);
    ct_zeroize(&mut n16[..]);
    ct_zeroize(&mut n8[..]);
    ct_zeroize(&mut subkey[..]);
    ct_zeroize(&mut block[..]);
    otk
}

/// Encrypt with XSalsa20-Poly1305 (NaCl `crypto_secretbox_easy`).
///
/// * `key` — 32 bytes; `nonce` — strictly 24 bytes.
/// * `out` — `plaintext.len() + 16`, layout `TAG ‖ CIPHERTEXT`.
/// * `aad` must be empty (secretbox has no associated data).
pub fn xsalsa20_poly1305_encrypt(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
    out: &mut [u8],
) -> CipherResult<()> {
    let (k, n) = check_key_nonce(key, nonce)?;
    check_aad_empty(aad)?;
    if out.len() != plaintext.len() + XSALSA_TAG_LEN {
        return Err(CipherError::InvalidLength);
    }
    let mut otk = xsalsa_otk(&k, &n);
    let (tag_out, ct_out) = out.split_at_mut(XSALSA_TAG_LEN);
    xsalsa_xor_msg(&k, &n, plaintext, ct_out);
    let mut tag = poly1305(&otk, ct_out)?;
    tag_out.copy_from_slice(&tag);
    ct_zeroize(&mut otk[..]);
    ct_zeroize(&mut tag[..]);
    Ok(())
}

/// Decrypt with XSalsa20-Poly1305.
///
/// * `tag_and_ct` — `TAG ‖ CIPHERTEXT`; `out` — plaintext (`len - 16`).
/// * On authentication failure returns [`CipherError::AuthenticationFailed`]
///   and zeroizes `out`.
pub fn xsalsa20_poly1305_decrypt(
    key: &[u8],
    nonce: &[u8],
    tag_and_ct: &[u8],
    aad: &[u8],
    out: &mut [u8],
) -> CipherResult<()> {
    let (k, n) = check_key_nonce(key, nonce)?;
    check_aad_empty(aad)?;
    if tag_and_ct.len() < XSALSA_TAG_LEN {
        return Err(CipherError::InvalidLength);
    }
    let ct_len = tag_and_ct.len() - XSALSA_TAG_LEN;
    if out.len() != ct_len {
        return Err(CipherError::InvalidLength);
    }
    let (tag, ct) = tag_and_ct.split_at(XSALSA_TAG_LEN);
    let mut otk = xsalsa_otk(&k, &n);
    let mut expected = poly1305(&otk, ct)?;
    ct_zeroize(&mut otk[..]);
    if ct_eq(&expected, tag) != 1 {
        ct_zeroize(out);
        ct_zeroize(&mut expected[..]);
        return Err(CipherError::AuthenticationFailed);
    }
    ct_zeroize(&mut expected[..]);
    xsalsa_xor_msg(&k, &n, ct, out);
    Ok(())
}

fn check_box_keys(peer: &[u8], sk: &[u8]) -> CipherResult<([u8; 32], [u8; 32])> {
    if peer.len() != SALSABOX_KEY_LEN || sk.len() != SALSABOX_KEY_LEN {
        return Err(CipherError::InvalidKeyLength);
    }
    let mut p = [0u8; 32];
    let mut s = [0u8; 32];
    p.copy_from_slice(peer);
    s.copy_from_slice(sk);
    Ok((p, s))
}

/// NaCl `crypto_box_beforenm`: X25519 DH, then HSalsa20 over the shared
/// secret with a zero nonce. Rejects a zero shared secret.
pub fn salsabox_beforenm(peer_public: &[u8], secret: &[u8]) -> CipherResult<[u8; 32]> {
    let (p, s) = check_box_keys(peer_public, secret)?;
    let mut shared = x25519::diffie_hellman(&s, &p)
        .map_err(|_| CipherError::Failure("zero x25519 shared secret"))?;
    let k = hsalsa20(&shared, &[0u8; 16]);
    ct_zeroize(&mut shared[..]);
    Ok(k)
}

/// NaCl `crypto_box_easy` detached encrypt (`TAG ‖ CIPHERTEXT`).
pub fn salsabox_encrypt(
    peer_public: &[u8],
    secret: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    out: &mut [u8],
) -> CipherResult<()> {
    let mut session = salsabox_beforenm(peer_public, secret)?;
    let r = xsalsa20_poly1305_encrypt(&session, nonce, plaintext, &[], out);
    ct_zeroize(&mut session[..]);
    r
}

/// NaCl `crypto_box_open_easy` detached decrypt.
pub fn salsabox_decrypt(
    peer_public: &[u8],
    secret: &[u8],
    nonce: &[u8],
    tag_and_ct: &[u8],
    out: &mut [u8],
) -> CipherResult<()> {
    let mut session = salsabox_beforenm(peer_public, secret)?;
    let r = xsalsa20_poly1305_decrypt(&session, nonce, tag_and_ct, &[], out);
    ct_zeroize(&mut session[..]);
    r
}

/// NaCl box, nonce-prefixed framing: `NONCE ‖ TAG ‖ CIPHERTEXT`.
pub fn salsabox_seal(
    peer_public: &[u8],
    secret: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    out: &mut [u8],
) -> CipherResult<()> {
    if nonce.len() != XSALSA_NONCE_LEN
        || out.len() != XSALSA_NONCE_LEN + plaintext.len() + XSALSA_TAG_LEN
    {
        return Err(CipherError::InvalidLength);
    }
    out[..XSALSA_NONCE_LEN].copy_from_slice(nonce);
    salsabox_encrypt(
        peer_public,
        secret,
        nonce,
        plaintext,
        &mut out[XSALSA_NONCE_LEN..],
    )
}

/// Open a `NONCE ‖ TAG ‖ CIPHERTEXT` blob.
pub fn salsabox_open(
    peer_public: &[u8],
    secret: &[u8],
    sealed: &[u8],
    out: &mut [u8],
) -> CipherResult<()> {
    if sealed.len() < XSALSA_NONCE_LEN + XSALSA_TAG_LEN
        || out.len() + XSALSA_NONCE_LEN + XSALSA_TAG_LEN != sealed.len()
    {
        return Err(CipherError::InvalidLength);
    }
    let (nonce, tag_ct) = sealed.split_at(XSALSA_NONCE_LEN);
    salsabox_decrypt(peer_public, secret, nonce, tag_ct, out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(2));
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn estream_salsa20_256_set1_vector0() {
        // eSTREAM verified.test-vectors, 256-bit Set 1 vector# 0
        // (key = 0x80…, IV = 0): stream[0..64] and stream[192..256].
        let mut key = [0u8; 32];
        key[0] = 0x80;
        let nonce = [0u8; 8];
        let mut stream = [0u8; 256];
        let mut counter: u64 = 0;
        let mut off = 0;
        while off < 256 {
            let b = salsa20_block(&key, &nonce, counter);
            counter += 1;
            stream[off..off + 64].copy_from_slice(&b);
            off += 64;
        }
        assert_eq!(
            hex("E3BE8FDD8BECA2E3EA8EF9475B29A6E7003951E1097A5C38D23B7A5FAD9F6844B22C97559E2723C7CBBD3FE4FC8D9A0744652A83E72A9C461876AF4D7EF1A117"),
            &stream[..64]
        );
        assert_eq!(
            hex("57BE81F47B17D9AE7C4FF15429A73E10ACF250ED3A90A93C711308A74C6216A9ED84CD126DA7F28E8ABF8BB63517E1CA98E712F4FB2E1A6AED9FDC73291FAA17"),
            &stream[192..256]
        );
    }

    #[test]
    fn xsalsa_go_vector() {
        // golang.org/x/crypto/salsa20 TestXSalsa20 (key/nonce ASCII).
        // Note: raw XSalsa20 starts at stream offset 0 (unlike secretbox,
        // which reserves the first 32 bytes for the Poly1305 key).
        let key = b"this is 32-byte key for xsalsa20";
        let mut k = [0u8; 32];
        k.copy_from_slice(&key[..]);
        let nonce = b"24-byte nonce for xsalsa";
        let mut n = [0u8; 24];
        n.copy_from_slice(&nonce[..]);
        let mut n16 = [0u8; 16];
        let mut n8 = [0u8; 8];
        n16.copy_from_slice(&n[..16]);
        n8.copy_from_slice(&n[16..]);
        let subkey = hsalsa20(&k, &n16);
        let hello = b"Hello world!";
        let mut out = [0u8; 12];
        let mut off = 0usize;
        let mut counter = 0u64;
        while off < hello.len() {
            let block = salsa20_block(&subkey, &n8, counter);
            counter += 1;
            for b in block.iter() {
                if off >= hello.len() {
                    break;
                }
                out[off] = hello[off] ^ b;
                off += 1;
            }
        }
        assert_eq!(out, [0x00, 0x2d, 0x45, 0x13, 0x84, 0x3f, 0xc2, 0x40, 0xc4, 0x01, 0xe5, 0x41]);
    }

    // TON Connect SessionCrypto goldens (ton-connect-core session.rs):
    // keys, nonce, pubs and both expected payloads.
    const ALICE_SK: &str =
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    const BOB_PK: &str =
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
    const ALICE_PK: &str =
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
    const BOB_SK: &str =
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
    const NONCE: &str = "69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37";
    const TWEETNACL_SEALED: &str = "69696ee955b62b73cd62bda875fc73d68219e0036b7a0b374f143feef2ba7f7dabdcb006973180de64d12a7a37868ec868e1378cba7808d0";

    #[test]
    fn tweetnacl_box_golden() {
        let sealed = hex(TWEETNACL_SEALED);
        let nonce = hex(NONCE);
        let mut out = vec![0u8; sealed.len() - XSALSA_NONCE_LEN - XSALSA_TAG_LEN];
        // Bob opens Alice's message.
        salsabox_open(&hex(ALICE_PK), &hex(BOB_SK), &sealed, &mut out).unwrap();
        assert_eq!(out, b"TON Connect core");
        // Alice re-seals byte-exact.
        let pt = b"TON Connect core";
        let mut re = vec![0u8; XSALSA_NONCE_LEN + pt.len() + XSALSA_TAG_LEN];
        salsabox_seal(&hex(BOB_PK), &hex(ALICE_SK), &nonce, pt, &mut re).unwrap();
        assert_eq!(re, sealed);
    }

    #[test]
    fn pytonconnect_box_golden() {
        // Generated by XaBbl4/pytonconnect SessionCrypto (libsodium):
        // NONCE ‖ TAG ‖ CT for "some protocol message: ...", fixed keys+nonce.
        let sealed = hex(concat!(
            "69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37",
            "0b94e8d664c2b89039df5e090e25f443",
            "43f1093f549992c979ed20c3b53717d069688aea3f157d0b2c64592a3dea33c9555209b2c612a7410c51f4e5800888356862925398da",
        ));
        let pt = b"some protocol message: { method_params: [1, 2, null] }";
        let mut open = vec![0u8; pt.len()];
        // Bob opens Alice's message.
        salsabox_open(&hex(ALICE_PK), &hex(BOB_SK), &sealed, &mut open).unwrap();
        assert_eq!(&open, pt);
        // Alice re-seals byte-exact.
        let mut re = vec![0u8; XSALSA_NONCE_LEN + pt.len() + XSALSA_TAG_LEN];
        salsabox_seal(&hex(BOB_PK), &hex(ALICE_SK), &hex(NONCE), pt, &mut re)
            .unwrap();
        assert_eq!(re, sealed);
    }

    #[test]
    fn secretbox_roundtrip_and_tamper() {
        let key = [0x42u8; 32];
        let nonce = [0x07u8; 24];
        let pt = b"xsalsa20-poly1305 roundtrip";
        let mut sealed = vec![0u8; pt.len() + XSALSA_TAG_LEN];
        xsalsa20_poly1305_encrypt(&key, &nonce, pt, &[], &mut sealed).unwrap();
        let mut open = vec![0u8; pt.len()];
        xsalsa20_poly1305_decrypt(&key, &nonce, &sealed, &[], &mut open).unwrap();
        assert_eq!(&open, pt);
        sealed[0] ^= 1;
        assert_eq!(
            xsalsa20_poly1305_decrypt(&key, &nonce, &sealed, &[], &mut open),
            Err(CipherError::AuthenticationFailed)
        );
    }

    #[test]
    fn strict_lengths_and_no_aad() {
        let key = [0u8; 32];
        let mut out = [0u8; 16];
        assert_eq!(
            xsalsa20_poly1305_encrypt(&key, &[0u8; 12], b"", &[], &mut out),
            Err(CipherError::InvalidNonceLength)
        );
        assert_eq!(
            xsalsa20_poly1305_encrypt(&key, &[0u8; 24], b"", b"ad", &mut out),
            Err(CipherError::Unsupported)
        );
        assert_eq!(
            salsabox_beforenm(&[0u8; 32], &[0u8; 32]).map(|_| ()),
            Err(CipherError::Failure("zero x25519 shared secret"))
        );
    }
}
