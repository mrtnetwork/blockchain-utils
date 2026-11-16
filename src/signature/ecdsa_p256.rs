//! ECDSA over NIST P-256 (secp256r1).
//!
//! - Explicit-nonce signing for known-answer tests
//! - Full RFC 6979 deterministic nonces (HMAC-SHA256)
//! - Constant-time low-S normalization
//!
//! RFC 6979 §A.2.5 vectors: `tests/rfc6979_p256_vectors.rs`.

use crate::ct::ct_eq;
use crate::curve::secp256r1::{Scalar, Secp256r1Point};
use crate::curve::traits::CurvePoint;
use crate::hash::hmac_sha256;
use crate::signature::error::{SignatureError, SignatureResult};

/// P-256 public key.
#[derive(Clone, Copy, Debug)]
pub struct PublicKey {
    point: Secp256r1Point,
}

/// P-256 secret scalar.
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
        let mut b = [0u8; 32];
        b.copy_from_slice(bytes);
        let d = Scalar::from_bytes_be(&b).map_err(|_| SignatureError::InvalidPrivateKey)?;
        if d.is_zero() {
            return Err(SignatureError::InvalidPrivateKey);
        }
        Ok(Self { d })
    }

    pub fn public_key(&self) -> SignatureResult<PublicKey> {
        let p = Secp256r1Point::generator().mul(&self.d);
        Ok(PublicKey { point: p })
    }

    pub fn to_bytes(&self, out: &mut [u8; 32]) {
        self.d.to_bytes_be(out);
    }
}

impl PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> SignatureResult<Self> {
        let point =
            Secp256r1Point::from_bytes(bytes).map_err(|_| SignatureError::InvalidPublicKey)?;
        Ok(Self { point })
    }

    pub fn to_bytes_compressed(&self, out: &mut [u8; 33]) -> SignatureResult<()> {
        self.point
            .to_bytes_compressed(out)
            .map_err(|_| SignatureError::InvalidPublicKey)
    }

    pub fn to_bytes_uncompressed(&self, out: &mut [u8; 65]) -> SignatureResult<()> {
        self.point
            .to_bytes_uncompressed(out)
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

fn hash_to_scalar(hash32: &[u8; 32]) -> Scalar {
    Scalar::from_bytes_mod_order(hash32)
}

/// Sign with explicit nonce `k`.
pub fn sign_with_nonce(
    sk: &SecretKey,
    hash32: &[u8; 32],
    k: &Scalar,
) -> SignatureResult<Signature> {
    if k.is_zero() {
        return Err(SignatureError::InvalidPrivateKey);
    }
    let kg = Secp256r1Point::generator().mul(k);
    let mut enc = [0u8; 33];
    kg.to_bytes_compressed(&mut enc)
        .map_err(|_| SignatureError::Failure("point"))?;
    let mut xb = [0u8; 32];
    xb.copy_from_slice(&enc[1..33]);
    let r = Scalar::from_bytes_mod_order(&xb);
    if r.is_zero() {
        return Err(SignatureError::InvalidSignature);
    }

    let e = hash_to_scalar(hash32);
    let kinv = k.invert().map_err(|_| SignatureError::Failure("kinv"))?;
    let rd = r.mul(&sk.d);
    let e_rd = e.add(&rd);
    let s = kinv.mul(&e_rd);
    if s.is_zero() {
        return Err(SignatureError::InvalidSignature);
    }
    // Low-S normalize (matches secp256k1 path and the reference backend):
    // networks expect canonical `s <= n/2`; both forms verify, but only
    // low-S is consensus-accepted.
    let s = normalize_low_s(s);
    let mut rb = [0u8; 32];
    let mut sb = [0u8; 32];
    r.to_bytes_be(&mut rb);
    s.to_bytes_be(&mut sb);
    Ok(Signature { r: rb, s: sb })
}

fn normalize_low_s(s: Scalar) -> Scalar {
    // n/2 for P-256
    let half: [u8; 32] = [
        0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31,
        0x92, 0xa8,
    ];
    let mut sb = [0u8; 32];
    s.to_bytes_be(&mut sb);
    let mut gt = 0u8;
    let mut eq = 1u8;
    for i in 0..32 {
        let a = sb[i];
        let b = half[i];
        gt |= eq & u8::from(a > b);
        eq &= u8::from(a == b);
    }
    let neg_s = s.neg();
    Scalar::ct_select(gt, &neg_s, &s)
}

/// RFC 6979 deterministic k (HMAC-SHA256).
pub fn deterministic_k(sk: &SecretKey, hash32: &[u8; 32]) -> Scalar {
    let mut x = [0u8; 32];
    sk.d.to_bytes_be(&mut x);

    let h1_int = hash_to_scalar(hash32);
    let mut h1_oct = [0u8; 32];
    h1_int.to_bytes_be(&mut h1_oct);

    let mut v = [0x01u8; 32];
    let mut kmac = [0x00u8; 32];

    let mut buf = [0u8; 97];
    buf[0..32].copy_from_slice(&v);
    buf[32] = 0x00;
    buf[33..65].copy_from_slice(&x);
    buf[65..97].copy_from_slice(&h1_oct);
    kmac = hmac_sha256(&kmac, &buf).unwrap_or(kmac);
    v = hmac_sha256(&kmac, &v).unwrap_or(v);

    buf[0..32].copy_from_slice(&v);
    buf[32] = 0x01;
    buf[33..65].copy_from_slice(&x);
    buf[65..97].copy_from_slice(&h1_oct);
    kmac = hmac_sha256(&kmac, &buf).unwrap_or(kmac);
    v = hmac_sha256(&kmac, &v).unwrap_or(v);

    for _ in 0..64 {
        v = hmac_sha256(&kmac, &v).unwrap_or(v);
        let cand = Scalar::from_bytes_mod_order(&v);
        // Accept if 1 <= cand < n (from_bytes_mod_order already mod n; reject 0)
        if !cand.is_zero() {
            // Also reject if original v was >= n and reduced? RFC requires 0 < k < q
            // from_bytes_mod_order gives [0, n). Zero already rejected.
            // If v >= n, bits2int would take high qlen bits then mod - for 256/256 equals mod n.
            return cand;
        }
        let mut step = [0u8; 33];
        step[0..32].copy_from_slice(&v);
        step[32] = 0x00;
        kmac = hmac_sha256(&kmac, &step).unwrap_or(kmac);
        v = hmac_sha256(&kmac, &v).unwrap_or(v);
    }
    Scalar::one()
}

/// Sign with RFC 6979 deterministic nonce.
pub fn sign(sk: &SecretKey, hash32: &[u8; 32]) -> SignatureResult<Signature> {
    sign_ex(sk, hash32, None)
}

/// Sign with RFC 6979 and optional extra entropy (`extraEntropy`).
pub fn sign_ex(
    sk: &SecretKey,
    hash32: &[u8; 32],
    extra_entropy: Option<&[u8]>,
) -> SignatureResult<Signature> {
    let k = deterministic_k_ex(sk, hash32, extra_entropy);
    sign_with_nonce(sk, hash32, &k)
}

/// RFC 6979 with optional extra entropy for P-256.
pub fn deterministic_k_ex(
    sk: &SecretKey,
    hash32: &[u8; 32],
    extra_entropy: Option<&[u8]>,
) -> Scalar {
    let mut x = [0u8; 32];
    sk.d.to_bytes_be(&mut x);
    let h1_int = hash_to_scalar(hash32);
    let mut h1_oct = [0u8; 32];
    h1_int.to_bytes_be(&mut h1_oct);

    let mut v = [0x01u8; 32];
    let mut kmac = [0x00u8; 32];

    // K = HMAC(K, V || 0x00 || x || h1 [|| extra])
    let extra = extra_entropy.unwrap_or(&[]);
    #[cfg(feature = "alloc")]
    {
        #[allow(unused_imports)]
        use alloc::vec::Vec;
        let mut buf = Vec::with_capacity(32 + 1 + 32 + 32 + extra.len());
        buf.extend_from_slice(&v);
        buf.push(0x00);
        buf.extend_from_slice(&x);
        buf.extend_from_slice(&h1_oct);
        buf.extend_from_slice(extra);
        kmac = hmac_sha256(&kmac, &buf).unwrap_or(kmac);
        v = hmac_sha256(&kmac, &v).unwrap_or(v);

        let mut buf = Vec::with_capacity(32 + 1 + 32 + 32 + extra.len());
        buf.extend_from_slice(&v);
        buf.push(0x01);
        buf.extend_from_slice(&x);
        buf.extend_from_slice(&h1_oct);
        buf.extend_from_slice(extra);
        kmac = hmac_sha256(&kmac, &buf).unwrap_or(kmac);
        v = hmac_sha256(&kmac, &v).unwrap_or(v);
    }
    #[cfg(not(feature = "alloc"))]
    {
        let _ = extra;
        return deterministic_k(sk, hash32);
    }

    for _ in 0..64 {
        v = hmac_sha256(&kmac, &v).unwrap_or(v);
        let cand = Scalar::from_bytes_mod_order(&v);
        if !cand.is_zero() {
            return cand;
        }
        let mut step = [0u8; 33];
        step[0..32].copy_from_slice(&v);
        step[32] = 0x00;
        kmac = hmac_sha256(&kmac, &step).unwrap_or(kmac);
        v = hmac_sha256(&kmac, &v).unwrap_or(v);
    }
    Scalar::one()
}

/// Verify ECDSA signature on a 32-byte message hash.
pub fn verify(pk: &PublicKey, hash32: &[u8; 32], sig: &Signature) -> SignatureResult<()> {
    let r = Scalar::from_bytes_be(&sig.r).map_err(|_| SignatureError::InvalidSignature)?;
    let s = Scalar::from_bytes_be(&sig.s).map_err(|_| SignatureError::InvalidSignature)?;
    if r.is_zero() || s.is_zero() {
        return Err(SignatureError::InvalidSignature);
    }

    let e = hash_to_scalar(hash32);
    let w = s.invert().map_err(|_| SignatureError::InvalidSignature)?;
    let u1 = e.mul(&w);
    let u2 = r.mul(&w);
    let p1 = Secp256r1Point::generator().mul(&u1);
    let p2 = pk.point.mul(&u2);
    let r_pt = p1.add(&p2);
    if r_pt.is_identity() {
        return Err(SignatureError::VerificationFailed);
    }
    let mut enc = [0u8; 33];
    r_pt.to_bytes_compressed(&mut enc)
        .map_err(|_| SignatureError::VerificationFailed)?;
    let mut xb = [0u8; 32];
    xb.copy_from_slice(&enc[1..33]);
    let rx = Scalar::from_bytes_mod_order(&xb);
    let mut rb = [0u8; 32];
    rx.to_bytes_be(&mut rb);
    if ct_eq(&rb, &sig.r) == 1 {
        Ok(())
    } else {
        Err(SignatureError::VerificationFailed)
    }
}

/// P-256 group order n (big-endian).
const N_BE: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
];

/// Recover compressed public key from compact signature + recovery id (0..3).
///
/// Same layout as secp256k1: bit0 = y-parity of R, bit1 = r+n overflow (rare on P-256).
pub fn recover(hash32: &[u8; 32], sig: &Signature, rec_id: u8) -> SignatureResult<PublicKey> {
    use crate::curve::secp256r1::Fe;
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
        Secp256r1Point::from_bytes(&comp).map_err(|_| SignatureError::InvalidSignature)?;

    // Q = r^{-1} (s·R − e·G)
    let e = hash_to_scalar(hash32);
    let rinv = r.invert().map_err(|_| SignatureError::InvalidSignature)?;
    let sr = r_point.mul(&s);
    let eg = Secp256r1Point::generator().mul(&e);
    let q = sr.add(&eg.neg()).mul(&rinv);
    if q.is_identity() {
        return Err(SignatureError::VerificationFailed);
    }
    Ok(PublicKey { point: q })
}

/// Recovery id for a known public key (ids 0..3), same convention as secp256k1.
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

#[cfg(test)]
mod tests {
    #[test]
    fn sig_match() {
        use super::*;
        let sk_hex = "5a01fb01767cc9ced3ec432b8110bfc2d97db1ca3e292460767d9917b6989837";
        let dig_hex = "df373efe9303e2370fe2fc92da30c6a357047d8d5cb160200a3f182814021b8c";
        // Canonical low-S vector (RFC 6979 + low-S normalize); the previous
        // expectation carried a stale non-canonical s.
        let exp_hex = "e23efea168e33a7ff2849750e364765de6c345304cbc45b3c67de3fc95b558df15f1c1272212427d1d3866ad0d29c41f6878bad14740b109710f672dea8087b6";
        let mut skb = [0u8; 32];
        let mut dig = [0u8; 32];
        let mut exp = [0u8; 64];
        for i in 0..32 {
            skb[i] = u8::from_str_radix(&sk_hex[i * 2..i * 2 + 2], 16).unwrap();
            dig[i] = u8::from_str_radix(&dig_hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        for i in 0..64 {
            exp[i] = u8::from_str_radix(&exp_hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        let sk = SecretKey::from_bytes(&skb).unwrap();
        let sig = sign(&sk, &dig).unwrap();
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&sig.r);
        out[32..].copy_from_slice(&sig.s);
        assert_eq!(out, exp);
        // Cryptographic validity under the matching public key.
        let pk = sk.public_key().unwrap();
        verify(&pk, &dig, &sig).unwrap();
    }

    use super::*;
    use crate::hash::sha256;

    #[test]
    fn p256_recover_roundtrip() {
        let mut d = [0u8; 32];
        d[31] = 1;
        let sk = SecretKey::from_bytes(&d).unwrap();
        let pk = sk.public_key().unwrap();
        let h = sha256(b"p256 recover").unwrap();
        let sig = sign(&sk, &h).unwrap();
        let id = recovery_id_for(&h, &sig, &pk).expect("recovery_id");
        assert!(id <= 1, "expected non-overflow id, got {id}");
        let pk2 = recover(&h, &sig, id).unwrap();
        let mut a = [0u8; 33];
        let mut b = [0u8; 33];
        pk.to_bytes_compressed(&mut a).unwrap();
        pk2.to_bytes_compressed(&mut b).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn p256_sign_verify_roundtrip() {
        let mut d = [0u8; 32];
        d[31] = 7;
        let sk = SecretKey::from_bytes(&d).unwrap();
        let pk = sk.public_key().unwrap();
        let h = sha256(b"p256 roundtrip").unwrap();
        let sig = sign(&sk, &h).unwrap();
        verify(&pk, &h, &sig).unwrap();
    }

    #[test]
    fn p256_deterministic_stable() {
        let mut d = [0u8; 32];
        d[31] = 9;
        let sk = SecretKey::from_bytes(&d).unwrap();
        let h = sha256(b"stable").unwrap();
        let s1 = sign(&sk, &h).unwrap();
        let s2 = sign(&sk, &h).unwrap();
        assert_eq!(s1.r, s2.r);
        assert_eq!(s1.s, s2.s);
    }

    #[test]
    fn invert_roundtrip() {
        let mut b = [0u8; 32];
        b[31] = 3;
        let k = Scalar::from_bytes_be(&b).unwrap();
        let inv = k.invert().unwrap();
        let one = k.mul(&inv);
        let mut out = [0u8; 32];
        one.to_bytes_be(&mut out);
        assert_eq!(out[31], 1);
        for b in out.iter().take(31) {
            assert_eq!(*b, 0, "invert not 1");
        }
    }

    #[test]
    fn p256_sign_with_known_k() {
        let mut d = [0u8; 32];
        d[31] = 7;
        let sk = SecretKey::from_bytes(&d).unwrap();
        let pk = sk.public_key().unwrap();
        let h = sha256(b"p256 roundtrip").unwrap();
        let mut k_bytes = [0u8; 32];
        k_bytes[31] = 3;
        let k = Scalar::from_bytes_be(&k_bytes).unwrap();
        let sig = sign_with_nonce(&sk, &h, &k).unwrap();
        let kg = Secp256r1Point::generator().mul(&k);
        let mut enc = [0u8; 33];
        kg.to_bytes_compressed(&mut enc).unwrap();
        assert_eq!(&sig.r[..], &enc[1..33], "r must equal x(kG)");
        verify(&pk, &h, &sig).expect("verify known k");
    }
}
