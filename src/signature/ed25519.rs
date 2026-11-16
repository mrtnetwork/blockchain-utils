//! Ed25519 (EdDSA) signatures — RFC 8032 + chain variants.
//!
//! Variants (`CryptoKeyType`):
//! - [`Variant::Ed25519`] — RFC 8032: `H = SHA-512`, seed 32 → expand
//! - [`Variant::Ed25519Blake2b`] — same expand with `H = Blake2b-512`
//! - [`Variant::Ed25519Kholaw`] — 64-byte key: `a || prefix` (no expand hash)
//! - [`Variant::Ed25519Monero`] — same as Kholaw (64-byte already expanded)
//!
//! Pure `no_std`, constant-time where secrets are involved.

use crate::ct::ct_eq;
use crate::curve::ed25519::{Ed25519Point, Scalar};
use crate::curve::traits::CurvePoint;
use crate::hash::blake2b::blake2b_512;
use crate::hash::sha512;
use crate::hash::{Blake2b, Sha512};
use crate::signature::error::{SignatureError, SignatureResult};

/// Signing / verification hash family for Ed25519 variants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Variant {
    /// RFC 8032 pure Ed25519 (SHA-512).
    Ed25519 = 0,
    /// Ed25519 with Blake2b-512 instead of SHA-512 (Cardano-style expand).
    Ed25519Blake2b = 1,
    /// Kholaw BIP32-Ed25519: 64-byte key `a || prefix`.
    Ed25519Kholaw = 2,
    /// Monero: 64-byte key `a || prefix` (same layout as Kholaw at sign time).
    Ed25519Monero = 3,
}

impl Variant {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Ed25519),
            1 => Some(Self::Ed25519Blake2b),
            2 => Some(Self::Ed25519Kholaw),
            3 => Some(Self::Ed25519Monero),
            _ => None,
        }
    }

    /// Expected secret material length: 32 (seed) or 64 (expanded).
    pub fn secret_len(self) -> usize {
        match self {
            Self::Ed25519 | Self::Ed25519Blake2b => 32,
            Self::Ed25519Kholaw | Self::Ed25519Monero => 64,
        }
    }
}

/// Ed25519 public key (32 bytes).
#[derive(Clone, Copy, Debug)]
pub struct PublicKey(pub [u8; 32]);

/// Ed25519 secret key seed (32 bytes) — RFC 8032 "private key".
#[derive(Clone, Copy, Debug)]
pub struct SecretKey(pub [u8; 32]);

/// Expanded signing material: scalar `a` (clamped/pruned) + 32-byte nonce prefix.
#[derive(Clone, Copy, Debug)]
pub struct ExpandedSecretKey {
    pub a: [u8; 32],
    pub prefix: [u8; 32],
}

/// Ed25519 signature (64 bytes = R || S).
#[derive(Clone, Copy, Debug)]
pub struct Signature(pub [u8; 64]);

impl SecretKey {
    pub fn from_bytes(bytes: &[u8]) -> SignatureResult<Self> {
        if bytes.len() != 32 {
            return Err(SignatureError::InvalidLength);
        }
        let mut b = [0u8; 32];
        b.copy_from_slice(bytes);
        Ok(Self(b))
    }

    /// Derive public key (RFC 8032 / SHA-512 expand).
    pub fn public_key(&self) -> SignatureResult<PublicKey> {
        public_key_variant(self.0.as_slice(), Variant::Ed25519)
    }
}

impl ExpandedSecretKey {
    pub fn public_key(&self) -> SignatureResult<PublicKey> {
        let a = Scalar::from_bytes_mod_order(&self.a);
        let a_point = Ed25519Point::generator().mul(&a);
        let mut out = [0u8; 32];
        a_point
            .to_bytes_compressed(&mut out)
            .map_err(|_| SignatureError::InvalidPublicKey)?;
        Ok(PublicKey(out))
    }
}

impl PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> SignatureResult<Self> {
        if bytes.len() != 32 {
            return Err(SignatureError::InvalidLength);
        }
        let mut b = [0u8; 32];
        b.copy_from_slice(bytes);
        Ed25519Point::from_bytes(&b).map_err(|_| SignatureError::InvalidPublicKey)?;
        Ok(Self(b))
    }
}

impl Signature {
    pub fn from_bytes(bytes: &[u8]) -> SignatureResult<Self> {
        if bytes.len() != 64 {
            return Err(SignatureError::InvalidLength);
        }
        let mut b = [0u8; 64];
        b.copy_from_slice(bytes);
        Ok(Self(b))
    }
}

/// Expand secret material per variant (`_extractKeys`).
///
/// | Variant | Input | Expand |
/// |---------|-------|--------|
/// | Ed25519 | 32-byte seed | SHA-512 → clamp left, prefix = right |
/// | Ed25519Blake2b | 32-byte seed | Blake2b-512 → clamp left, prefix = right |
/// | Kholaw / Monero | 64-byte key | left = `a` (no re-clamp), right = prefix |
pub fn expand_secret(secret: &[u8], variant: Variant) -> SignatureResult<ExpandedSecretKey> {
    match variant {
        Variant::Ed25519 => {
            if secret.len() != 32 {
                return Err(SignatureError::InvalidLength);
            }
            let h = sha512(secret).map_err(|_| SignatureError::Failure("sha512"))?;
            let mut a = [0u8; 32];
            let mut prefix = [0u8; 32];
            a.copy_from_slice(&h[0..32]);
            prefix.copy_from_slice(&h[32..64]);
            Scalar::clamp_ed25519(&mut a);
            Ok(ExpandedSecretKey { a, prefix })
        }
        Variant::Ed25519Blake2b => {
            if secret.len() != 32 {
                return Err(SignatureError::InvalidLength);
            }
            let h = blake2b_512(secret).map_err(|_| SignatureError::Failure("blake2b"))?;
            let mut a = [0u8; 32];
            let mut prefix = [0u8; 32];
            a.copy_from_slice(&h[0..32]);
            prefix.copy_from_slice(&h[32..64]);
            Scalar::clamp_ed25519(&mut a);
            Ok(ExpandedSecretKey { a, prefix })
        }
        Variant::Ed25519Kholaw | Variant::Ed25519Monero => {
            if secret.len() != 64 {
                return Err(SignatureError::InvalidLength);
            }
            let mut a = [0u8; 32];
            let mut prefix = [0u8; 32];
            a.copy_from_slice(&secret[0..32]);
            prefix.copy_from_slice(&secret[32..64]);
            // Ref: secret used as-is (already pruned by key gen)
            Ok(ExpandedSecretKey { a, prefix })
        }
    }
}

/// Public key from secret material + variant.
pub fn public_key_variant(secret: &[u8], variant: Variant) -> SignatureResult<PublicKey> {
    expand_secret(secret, variant)?.public_key()
}

fn hash_512(variant: Variant, parts: &[&[u8]]) -> SignatureResult<[u8; 64]> {
    match variant {
        Variant::Ed25519Blake2b => {
            let mut h = Blake2b::new_512();
            for p in parts {
                h.update(p);
            }
            let mut out = [0u8; 64];
            h.finalize_into(&mut out);
            Ok(out)
        }
        // Standard, Kholaw, Monero all use SHA-512 for domain hash in reference sign path
        Variant::Ed25519 | Variant::Ed25519Kholaw | Variant::Ed25519Monero => {
            let mut h = Sha512::new();
            for p in parts {
                h.update(p);
            }
            Ok(h.finalize())
        }
    }
}

/// Sign with expanded key and variant hash.
pub fn sign_expanded(
    exp: &ExpandedSecretKey,
    message: &[u8],
    variant: Variant,
) -> SignatureResult<Signature> {
    let a = Scalar::from_bytes_mod_order(&exp.a);
    let a_point = Ed25519Point::generator().mul(&a);
    let mut a_enc = [0u8; 32];
    a_point
        .to_bytes_compressed(&mut a_enc)
        .map_err(|_| SignatureError::InvalidPublicKey)?;

    // r = H(prefix || M) mod L
    let r_hash = hash_512(variant, &[&exp.prefix, message])?;
    let r = Scalar::from_bytes_wide(&r_hash);

    let r_point = Ed25519Point::generator().mul(&r);
    let mut r_enc = [0u8; 32];
    r_point
        .to_bytes_compressed(&mut r_enc)
        .map_err(|_| SignatureError::InvalidSignature)?;

    // k = H(R || A || M) mod L
    let k_hash = hash_512(variant, &[&r_enc, &a_enc, message])?;
    let k = Scalar::from_bytes_wide(&k_hash);

    // S = r + k*a mod L
    let s = r.add(&k.mul(&a));
    let mut s_enc = [0u8; 32];
    s.to_bytes_le(&mut s_enc);

    let mut sig = [0u8; 64];
    sig[0..32].copy_from_slice(&r_enc);
    sig[32..64].copy_from_slice(&s_enc);
    Ok(Signature(sig))
}

/// Sign with raw secret material and variant.
pub fn sign_variant(secret: &[u8], message: &[u8], variant: Variant) -> SignatureResult<Signature> {
    let exp = expand_secret(secret, variant)?;
    sign_expanded(&exp, message, variant)
}

/// Sign message with Ed25519 (RFC 8032 pure Ed25519).
pub fn sign(sk: &SecretKey, message: &[u8]) -> SignatureResult<Signature> {
    sign_variant(&sk.0, message, Variant::Ed25519)
}

/// Verify with the matching variant hash.
pub fn verify_variant(
    pk: &PublicKey,
    message: &[u8],
    sig: &Signature,
    variant: Variant,
) -> SignatureResult<()> {
    let mut r_bytes = [0u8; 32];
    let mut s_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&sig.0[0..32]);
    s_bytes.copy_from_slice(&sig.0[32..64]);

    // Reject S >= L
    let s = Scalar::from_bytes_le(&s_bytes).map_err(|_| SignatureError::InvalidSignature)?;
    let r_point =
        Ed25519Point::from_bytes(&r_bytes).map_err(|_| SignatureError::InvalidSignature)?;
    let a_point = Ed25519Point::from_bytes(&pk.0).map_err(|_| SignatureError::InvalidPublicKey)?;

    let k_hash = hash_512(variant, &[&r_bytes, &pk.0, message])?;
    let k = Scalar::from_bytes_wide(&k_hash);

    // [8][S]B = [8][R] + [8][k]A  (cofactor clear)
    let sb = Ed25519Point::generator().mul(&s);
    let ka = a_point.mul(&k);
    let rhs = r_point.add(&ka);

    // Cofactor clear: compare [8]S B vs [8](R + k A)
    let eight = {
        let mut e = [0u8; 32];
        e[0] = 8;
        Scalar::from_bytes_mod_order(&e)
    };
    let sb8 = sb.mul(&eight);
    let rhs8 = rhs.mul(&eight);
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    CurvePoint::to_bytes_compressed(&sb8, &mut a)
        .map_err(|_| SignatureError::VerificationFailed)?;
    CurvePoint::to_bytes_compressed(&rhs8, &mut b)
        .map_err(|_| SignatureError::VerificationFailed)?;
    if ct_eq(&a, &b) == 1 {
        Ok(())
    } else {
        Err(SignatureError::VerificationFailed)
    }
}

/// Verify Ed25519 signature (RFC 8032).
pub fn verify(pk: &PublicKey, message: &[u8], sig: &Signature) -> SignatureResult<()> {
    verify_variant(pk, message, sig, Variant::Ed25519)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> alloc::vec::Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn ed25519_rfc8032_empty() {
        // RFC 8032 test 1
        let sk = SecretKey::from_bytes(&unhex(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        ))
        .unwrap();
        let pk = sk.public_key().unwrap();
        let sig = sign(&sk, b"").unwrap();
        verify(&pk, b"", &sig).unwrap();
    }

    #[test]
    fn ed25519_blake2b_roundtrip() {
        let sk = [7u8; 32];
        let pk = public_key_variant(&sk, Variant::Ed25519Blake2b).unwrap();
        let sig = sign_variant(&sk, b"blake2b ed", Variant::Ed25519Blake2b).unwrap();
        verify_variant(&pk, b"blake2b ed", &sig, Variant::Ed25519Blake2b).unwrap();
        // wrong variant must fail
        assert!(verify_variant(&pk, b"blake2b ed", &sig, Variant::Ed25519).is_err());
    }

    #[test]
    fn ed25519_kholaw_64_byte_key() {
        // Synthetic 64-byte expanded key
        let mut key = [0u8; 64];
        key[0] = 1;
        key[31] = 2;
        key[32] = 3;
        key[63] = 4;
        let mut a_part = [0u8; 32];
        a_part.copy_from_slice(&key[0..32]);
        Scalar::clamp_ed25519(&mut a_part);
        key[0..32].copy_from_slice(&a_part);
        let pk = public_key_variant(&key, Variant::Ed25519Kholaw).unwrap();
        let sig = sign_variant(&key, b"kholaw", Variant::Ed25519Kholaw).unwrap();
        verify_variant(&pk, b"kholaw", &sig, Variant::Ed25519Kholaw).unwrap();
    }

    #[test]
    fn expand_ed25519_differs_from_blake2b() {
        let sk = [9u8; 32];
        let e1 = expand_secret(&sk, Variant::Ed25519).unwrap();
        let e2 = expand_secret(&sk, Variant::Ed25519Blake2b).unwrap();
        assert_ne!(e1.a, e2.a);
        assert_ne!(e1.prefix, e2.prefix);
    }
}
