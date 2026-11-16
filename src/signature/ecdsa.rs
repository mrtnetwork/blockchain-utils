//! ECDSA over secp256k1 (and shared interface for secp256r1).
//!
//! Supports verification and signing with an explicit nonce `k` (for test
//! vectors) plus a high-level sign that derives `k` from HMAC-DRBG style
//! deterministic RFC 6979-lite (HMAC-SHA256 of key||hash).

use crate::curve::secp256k1::scalar::N_BE;
use crate::curve::secp256k1::{Fe, Scalar, Secp256k1Point};
use crate::curve::traits::CurvePoint;

use crate::ct::ct_eq;
use crate::signature::error::{SignatureError, SignatureResult};

/// secp256k1 public key (compressed 33 or uncompressed 65).
#[derive(Clone, Copy, Debug)]
pub struct PublicKey {
    pub(crate) point: Secp256k1Point,
}

/// secp256k1 secret scalar.
#[derive(Clone, Copy, Debug)]
pub struct SecretKey {
    d: Scalar,
}

/// Compact signature (r || s), 64 bytes. Low-S normalized.
#[derive(Clone, Copy, Debug)]
pub struct Signature {
    pub r: [u8; 32],
    pub s: [u8; 32],
}

impl SecretKey {
    pub fn from_bytes(bytes: &[u8]) -> SignatureResult<Self> {
        if bytes.len() != 32 {
            return Err(SignatureError::InvalidLength);
        }
        let d = Scalar::from_bytes(bytes).map_err(|_| SignatureError::InvalidPrivateKey)?;
        if d.is_zero() {
            return Err(SignatureError::InvalidPrivateKey);
        }
        Ok(Self { d })
    }

    pub fn public_key(&self) -> SignatureResult<PublicKey> {
        let p = Secp256k1Point::generator().mul(&self.d);
        Ok(PublicKey { point: p })
    }

    pub fn to_bytes(&self, out: &mut [u8; 32]) {
        self.d.to_bytes_be(out);
    }
}

impl PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> SignatureResult<Self> {
        let point =
            Secp256k1Point::from_bytes(bytes).map_err(|_| SignatureError::InvalidPublicKey)?;
        Ok(Self { point })
    }

    pub fn to_bytes_compressed(&self, out: &mut [u8; 33]) -> SignatureResult<()> {
        self.point
            .to_bytes_compressed(out)
            .map_err(|_| SignatureError::InvalidPublicKey)
    }
}

impl Signature {
    pub fn from_compact(bytes: &[u8]) -> SignatureResult<Self> {
        if bytes.len() != 64 {
            return Err(SignatureError::InvalidLength);
        }
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&bytes[0..32]);
        s.copy_from_slice(&bytes[32..64]);
        Ok(Self { r, s })
    }

    pub fn to_compact(&self, out: &mut [u8; 64]) {
        out[0..32].copy_from_slice(&self.r);
        out[32..64].copy_from_slice(&self.s);
    }
}

/// Sign with explicit nonce `k` (for test vectors).
pub fn sign_with_nonce(
    sk: &SecretKey,
    hash32: &[u8; 32],
    k: &Scalar,
) -> SignatureResult<Signature> {
    if k.is_zero() {
        return Err(SignatureError::InvalidPrivateKey);
    }
    let kg = Secp256k1Point::generator().mul(k);
    let mut enc = [0u8; 33];
    kg.to_bytes_compressed(&mut enc)
        .map_err(|_| SignatureError::Failure("point"))?;
    let mut xb = [0u8; 32];
    xb.copy_from_slice(&enc[1..33]);
    let r = Scalar::from_bytes_be(&xb).map_err(|_| SignatureError::InvalidSignature)?;
    if r.is_zero() {
        return Err(SignatureError::InvalidSignature);
    }

    let e = Scalar::from_bytes_be(hash32).unwrap_or(Scalar::zero());
    let kinv = k.invert().map_err(|_| SignatureError::Failure("kinv"))?;
    // s = k^{-1} (e + r d) mod n
    let rd = r.mul(&sk.d);
    let e_rd = e.add(&rd);
    let mut s = kinv.mul(&e_rd);
    if s.is_zero() {
        return Err(SignatureError::InvalidSignature);
    }

    // low-S: if s > n/2, s = n - s
    s = normalize_low_s(s);

    let mut rb = [0u8; 32];
    let mut sb = [0u8; 32];
    r.to_bytes_be(&mut rb);
    s.to_bytes_be(&mut sb);
    Ok(Signature { r: rb, s: sb })
}

fn normalize_low_s(s: Scalar) -> Scalar {
    // n/2 ≈ 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0
    let half: [u8; 32] = [
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b,
        0x20, 0xa0,
    ];
    // Constant-time: if s > half then return -s, else s.
    let mut sb = [0u8; 32];
    s.to_bytes_be(&mut sb);
    let mut gt = 0u8;
    let mut eq = 1u8;
    for i in 0..32 {
        let a = sb[i];
        let b = half[i];
        let a_gt = u8::from(a > b);
        let a_eq = u8::from(a == b);
        gt |= eq & a_gt;
        eq &= a_eq;
    }
    // gt == 1 => s > half
    let neg_s = s.neg();
    // ct_select on scalar via limb mask — Scalar implements ct_select
    Scalar::ct_select(gt, &neg_s, &s)
}

/// Deterministic k from full RFC 6979 (HMAC-SHA256), .
pub fn deterministic_k(sk: &SecretKey, hash32: &[u8; 32]) -> Scalar {
    deterministic_k_ex(sk, hash32, None).unwrap_or(Scalar::one())
}

/// RFC 6979 k with optional extra entropy (RFC 6979 §3.6 / `extraEntropy`).
pub fn deterministic_k_ex(
    sk: &SecretKey,
    hash32: &[u8; 32],
    extra_entropy: Option<&[u8]>,
) -> SignatureResult<Scalar> {
    let mut x = [0u8; 32];
    sk.d.to_bytes_be(&mut x);
    crate::signature::rfc6979::generate_k_scalar(&x, hash32, extra_entropy)
}

/// Sign hash with deterministic nonce (no extra entropy).
pub fn sign(sk: &SecretKey, hash32: &[u8; 32]) -> SignatureResult<Signature> {
    sign_ex(sk, hash32, None)
}

/// Sign with optional RFC 6979 extra entropy (matches the reference implementation.
pub fn sign_ex(
    sk: &SecretKey,
    hash32: &[u8; 32],
    extra_entropy: Option<&[u8]>,
) -> SignatureResult<Signature> {
    let k = deterministic_k_ex(sk, hash32, extra_entropy)?;
    sign_with_nonce(sk, hash32, &k)
}

/// Verify ECDSA signature on a 32-byte message hash.
pub fn verify(pk: &PublicKey, hash32: &[u8; 32], sig: &Signature) -> SignatureResult<()> {
    let r = Scalar::from_bytes_be(&sig.r).map_err(|_| SignatureError::InvalidSignature)?;
    let s = Scalar::from_bytes_be(&sig.s).map_err(|_| SignatureError::InvalidSignature)?;
    if r.is_zero() || s.is_zero() {
        return Err(SignatureError::InvalidSignature);
    }
    let e = Scalar::from_bytes_be(hash32).unwrap_or(Scalar::zero());
    let w = s.invert().map_err(|_| SignatureError::InvalidSignature)?;
    let u1 = e.mul(&w);
    let u2 = r.mul(&w);
    let p1 = Secp256k1Point::generator().mul(&u1);
    let p2 = pk.point.mul(&u2);
    let r_point = p1.add(&p2);
    if r_point.is_identity() {
        return Err(SignatureError::VerificationFailed);
    }
    let mut enc = [0u8; 33];
    r_point
        .to_bytes_compressed(&mut enc)
        .map_err(|_| SignatureError::VerificationFailed)?;
    let mut xb = [0u8; 32];
    xb.copy_from_slice(&enc[1..33]);
    // compare x mod n with r
    let rx = match Scalar::from_bytes_be(&xb) {
        Ok(v) => v,
        Err(_) => return Err(SignatureError::VerificationFailed),
    };
    let mut rb = [0u8; 32];
    let mut rxb = [0u8; 32];
    r.to_bytes_be(&mut rb);
    rx.to_bytes_be(&mut rxb);
    if ct_eq(&rb, &rxb) == 1 {
        Ok(())
    } else {
        Err(SignatureError::VerificationFailed)
    }
}

/// Recover public key from compact signature + recovery id (0..3) and 32-byte message hash.
///
/// `rec_id`: bit0 = y-parity of R, bit1 = whether r was taken as r+n (overflow).
/// Returns compressed SEC1 public key (33 bytes).
pub fn recover(hash32: &[u8; 32], sig: &Signature, rec_id: u8) -> SignatureResult<PublicKey> {
    if rec_id > 3 {
        return Err(SignatureError::InvalidSignature);
    }
    let r = Scalar::from_bytes_be(&sig.r).map_err(|_| SignatureError::InvalidSignature)?;
    let s = Scalar::from_bytes_be(&sig.s).map_err(|_| SignatureError::InvalidSignature)?;
    if r.is_zero() || s.is_zero() {
        return Err(SignatureError::InvalidSignature);
    }
    let y_odd = (rec_id & 1) != 0;
    let x_overflow = (rec_id & 2) != 0;

    // x = r, or (r + n) mod p when overflow bit set (Bitcoin recovery id 2|3)
    let mut rb = [0u8; 32];
    r.to_bytes_be(&mut rb);
    let x_fe = if x_overflow {
        let rx = Fe::from_bytes_be(&rb).map_err(|_| SignatureError::InvalidSignature)?;
        let n_fe = Fe::from_bytes_be(&N_BE).map_err(|_| SignatureError::InvalidSignature)?;
        rx.add(&n_fe)
    } else {
        Fe::from_bytes_be(&rb).map_err(|_| SignatureError::InvalidSignature)?
    };
    let mut xb = [0u8; 32];
    x_fe.to_bytes_be(&mut xb);
    let mut comp = [0u8; 33];
    comp[0] = if y_odd { 0x03 } else { 0x02 };
    comp[1..].copy_from_slice(&xb);
    let r_point =
        Secp256k1Point::from_bytes(&comp).map_err(|_| SignatureError::InvalidSignature)?;

    // Q = r^{-1} (s·R - e·G)
    let e = Scalar::from_bytes_be(hash32).unwrap_or(Scalar::zero());
    let rinv = r.invert().map_err(|_| SignatureError::InvalidSignature)?;
    let sr = r_point.mul(&s);
    let eg = Secp256k1Point::generator().mul(&e);
    let q = sr.add(&eg.neg()).mul(&rinv);
    if q.is_identity() {
        return Err(SignatureError::VerificationFailed);
    }
    Ok(PublicKey { point: q })
}

/// Recovery id for a known public key (matches the reference implementation.recoverId`).
///
/// Tries ids 0 and 1 first (even/odd Y of R), then 2/3 (overflow). Returns the
/// id whose recovered pubkey matches `expected` compressed encoding.
pub fn recovery_id_for(
    hash32: &[u8; 32],
    sig: &Signature,
    expected: &PublicKey,
) -> SignatureResult<u8> {
    let mut exp = [0u8; 33];
    expected
        .to_bytes_compressed(&mut exp)
        .map_err(|_| SignatureError::InvalidPublicKey)?;
    for id in 0u8..4 {
        if let Ok(pk) = recover(hash32, sig, id) {
            let mut got = [0u8; 33];
            if pk.to_bytes_compressed(&mut got).is_ok() && got == exp {
                return Ok(id);
            }
        }
    }
    Err(SignatureError::VerificationFailed)
}

/// Prefer recovery id that matches the verifying pubkey; fall back to first verify.
pub fn recover_and_verify(hash32: &[u8; 32], sig: &Signature) -> SignatureResult<(PublicKey, u8)> {
    // Prefer ids 0,1 (no overflow) matching the reference implementation
    for id in 0u8..4 {
        if let Ok(pk) = recover(hash32, sig, id) {
            if verify(&pk, hash32, sig).is_ok() {
                return Ok((pk, id));
            }
        }
    }
    Err(SignatureError::VerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::hex;
    use crate::hash::sha256::sha256;

    fn unhex32(s: &str) -> [u8; 32] {
        let v = hex::decode(s).unwrap();
        let mut a = [0u8; 32];
        a.copy_from_slice(&v);
        a
    }

    #[test]
    fn ecdsa_sign_verify_roundtrip() {
        let d = unhex32("ebb2c082fd7727890a28ac82f6bdf97bad8de9f5d7c9028692de1a255cad3e0f");
        let sk = SecretKey::from_bytes(&d).unwrap();
        let pk = sk.public_key().unwrap();
        let h = unhex32("4b688df40bcedbe641ddb16ff0a1842d9c67ea1c3bf63f3e0471baa664531d1a");
        let k = Scalar::from_bytes_be(&unhex32(
            "49a0d7b786ec9cde0d0721d72804befd06571c974b191efb42ecf322ba9ddd9a",
        ))
        .unwrap();
        let sig = sign_with_nonce(&sk, &h, &k).unwrap();
        // known r
        let r_expected =
            unhex32("241097efbf8b63bf145c8961dbdf10c310efbb3b2676bbc0f8b08505c9e2f795");
        assert_eq!(sig.r, r_expected);
        verify(&pk, &h, &sig).unwrap();
    }

    #[test]
    fn ecdsa_deterministic_roundtrip() {
        let d = unhex32("0000000000000000000000000000000000000000000000000000000000000001");
        let sk = SecretKey::from_bytes(&d).unwrap();
        let pk = sk.public_key().unwrap();
        let h = sha256(b"test message").unwrap();
        let sig = sign(&sk, &h).unwrap();
        verify(&pk, &h, &sig).unwrap();
    }
    #[test]
    fn ecdsa_recover_roundtrip() {
        let d = unhex32("0000000000000000000000000000000000000000000000000000000000000001");
        let sk = SecretKey::from_bytes(&d).unwrap();
        let pk = sk.public_key().unwrap();
        let h = sha256(b"recover me").unwrap();
        let sig = sign(&sk, &h).unwrap();
        let id = recovery_id_for(&h, &sig, &pk).expect("recovery_id_for");
        let pk2 = recover(&h, &sig, id).expect("recover");
        let mut a = [0u8; 33];
        let mut b = [0u8; 33];
        pk.to_bytes_compressed(&mut a).unwrap();
        pk2.to_bytes_compressed(&mut b).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn recovery_id_matches_signer_sk1() {
        let d = unhex32("0000000000000000000000000000000000000000000000000000000000000001");
        let sk = SecretKey::from_bytes(&d).unwrap();
        let pk = sk.public_key().unwrap();
        let h = sha256(b"bitcoin ecdsa").unwrap();
        let sig = sign(&sk, &h).unwrap();
        let id = recovery_id_for(&h, &sig, &pk).expect("recovery id");
        // reference uses index into [even-y R, odd-y R]; must match recovered point
        let pk2 = recover(&h, &sig, id).unwrap();
        let mut a = [0u8; 33];
        let mut b = [0u8; 33];
        pk.to_bytes_compressed(&mut a).unwrap();
        pk2.to_bytes_compressed(&mut b).unwrap();
        assert_eq!(a, b);
        assert!(id == 0 || id == 1, "expected low recovery id, got {}", id);
    }

    #[test]
    fn recover_overflow_id_does_not_panic() {
        // rec_id with overflow bit: may fail point decompression, must not panic
        let d = unhex32("0000000000000000000000000000000000000000000000000000000000000001");
        let sk = SecretKey::from_bytes(&d).unwrap();
        let h = sha256(b"overflow path").unwrap();
        let sig = sign(&sk, &h).unwrap();
        let _ = recover(&h, &sig, 2);
        let _ = recover(&h, &sig, 3);
    }
}
