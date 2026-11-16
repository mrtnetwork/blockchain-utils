//! RFC 6979 deterministic nonce generation (HMAC-SHA256), matching
//! blockchain_utils `lib/crypto/crypto/ec/rfc6979 (RFC 6979)`.
//!
//! For secp256k1: order `n`, qlen = 256, rolen = 32.

use crate::curve::secp256k1::scalar::N_BE;
use crate::curve::secp256k1::Scalar;
use crate::hash::hmac_sha256;
use crate::signature::error::{SignatureError, SignatureResult};

/// bits2int (RFC 6979 §2.3.2): interpret `data` as big-endian integer,
/// keep only the top `qlen` bits (right-shift excess low bits). Never reduce mod n.
fn bits2int_qlen(data: &[u8], qlen: usize) -> [u8; 32] {
    // For secp256k1 qlen=256 and data is typically 32 bytes → identity.
    // If data longer than 32, take leftmost 32 bytes after shift; we only need 32-byte output.
    let l = data.len() * 8;
    if data.is_empty() {
        return [0u8; 32];
    }
    if l <= qlen {
        let mut out = [0u8; 32];
        let n = core::cmp::min(data.len(), 32);
        // left-pad to 32
        out[32 - n..].copy_from_slice(&data[..n]);
        return out;
    }
    // shift right by (l - qlen) bits
    let shift = l - qlen;
    let byte_shift = shift / 8;
    let bit_shift = shift % 8;
    let usable = data.len().saturating_sub(byte_shift);
    let mut tmp = [0u8; 64];
    let copy_len = core::cmp::min(usable, 64);
    tmp[..copy_len].copy_from_slice(&data[..copy_len]);
    if bit_shift == 0 {
        let mut out = [0u8; 32];
        let n = core::cmp::min(copy_len, 32);
        out[..n].copy_from_slice(&tmp[..n]);
        return out;
    }
    // shift right bit_shift within bytes
    let mut shifted = [0u8; 64];
    for i in 0..copy_len {
        let hi = tmp[i] >> bit_shift;
        let lo = if i + 1 < copy_len {
            tmp[i + 1] << (8 - bit_shift)
        } else {
            0
        };
        shifted[i] = hi | lo;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&shifted[..32]);
    out
}

/// Compare big-endian 32-byte integers: a >= b ? Branchless flag
/// accumulation (no early `return` on secret-derived bytes).
fn be32_gte(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut gt = 0u8;
    let mut eq = 1u8;
    for i in 0..32 {
        gt |= eq & u8::from(a[i] > b[i]);
        eq &= u8::from(a[i] == b[i]);
    }
    (gt | eq) == 1
}

/// a - b for big-endian 32-byte, assumes a >= b.
fn be32_sub(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow = 0i32;
    for i in (0..32).rev() {
        let t = a[i] as i32 - b[i] as i32 - borrow;
        if t < 0 {
            out[i] = (t + 256) as u8;
            borrow = 1;
        } else {
            out[i] = t as u8;
            borrow = 0;
        }
    }
    out
}

/// bits2octets: bits2int then if z >= n then z - n, then as 32 bytes.
fn bits2octets(data: &[u8]) -> [u8; 32] {
    let z1 = bits2int_qlen(data, 256);
    if be32_gte(&z1, &N_BE) {
        be32_sub(&z1, &N_BE)
    } else {
        z1
    }
}

fn hmac(key: &[u8], msg: &[u8]) -> [u8; 32] {
    hmac_sha256(key, msg).unwrap_or([0u8; 32])
}

/// Concatenate parts for HMAC input without alloc when possible.
fn hmac_concat(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    // Streaming HMAC
    use crate::hash::hmac::Hmac;
    use crate::hash::sha256::Sha256;
    let mut mac = Hmac::<Sha256>::new(key).expect("hmac");
    for p in parts {
        mac.update(p);
    }
    let mut out = [0u8; 32];
    let _ = mac.finalize_into(&mut out);
    out
}

/// RFC 6979 instantiate (steps b–g) + candidate loop (step h).
///
/// Returns a 32-byte k with 1 <= k < n (no overflow for Scalar::from_bytes_be).
/// Matches `RFC6979.generateSecp256k1KBytes` / `generateK`.
pub fn generate_k_secp256k1(
    secexp: &[u8; 32],
    hash32: &[u8; 32],
    extra_entropy: Option<&[u8]>,
    mut retry_gn: u32,
) -> SignatureResult<[u8; 32]> {
    let bx_h = bits2octets(hash32);
    let extra = extra_entropy.unwrap_or(&[]);

    // V = 0x01 * 32, K = 0x00 * 32
    let mut v = [0x01u8; 32];
    let mut k = [0x00u8; 32];

    // K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h) || extra)
    k = hmac_concat(&k, &[&v, &[0x00], secexp, &bx_h, extra]);
    // V = HMAC_K(V)
    v = hmac(&k, &v);
    // K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h) || extra)
    k = hmac_concat(&k, &[&v, &[0x01], secexp, &bx_h, extra]);
    // V = HMAC_K(V)
    v = hmac(&k, &v);

    // step h
    loop {
        // T = empty; while len(T) < 32: V = HMAC_K(V); T = T || V
        // rolen = 32, holen = 32 → one round
        v = hmac(&k, &v);
        let t = v;

        // Accept if T as integer is in [0, n) — matches ScalarSetB32 + !overflow
        // and reference generateSecp256k1KBytes. Also reject zero.
        if !be32_gte(&t, &N_BE) && t != [0u8; 32] {
            if retry_gn == 0 {
                return Ok(t);
            }
            retry_gn -= 1;
        }
        // K = HMAC_K(V || 0x00); V = HMAC_K(V)
        k = hmac_concat(&k, &[&v, &[0x00]]);
        v = hmac(&k, &v);
    }
}

/// Generate k as Scalar.
pub fn generate_k_scalar(
    secexp: &[u8; 32],
    hash32: &[u8; 32],
    extra_entropy: Option<&[u8]>,
) -> SignatureResult<Scalar> {
    let kb = generate_k_secp256k1(secexp, hash32, extra_entropy, 0)?;
    Scalar::from_bytes_be(&kb).map_err(|_| SignatureError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex32(s: &str) -> [u8; 32] {
        let mut a = [0u8; 32];
        for i in 0..32 {
            a[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        a
    }

    #[test]
    fn bits2octets_identity_when_below_n() {
        let h = unhex32("d34ff82ed41227bb0e8b3c0a466c699107f7c5658371779ffdb9bf69e65f1967");
        let o = bits2octets(&h);
        assert_eq!(o, h);
    }

    #[test]
    fn rfc6979_produces_nonzero_in_range() {
        let sk = unhex32("02cd0537757280e3480f433931dea6457aafa2db7642401522760ed2b3edf4cb");
        let h = unhex32("d34ff82ed41227bb0e8b3c0a466c699107f7c5658371779ffdb9bf69e65f1967");
        let entropy = unhex32("0000000000000000000000000000000000000000000000000000000000000070");
        let k = generate_k_secp256k1(&sk, &h, Some(&entropy), 0).unwrap();
        assert_ne!(k, [0u8; 32]);
        assert!(!be32_gte(&k, &N_BE));
    }
}
