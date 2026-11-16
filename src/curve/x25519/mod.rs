//! X25519 Diffie–Hellman (RFC 7748).
//!
//! Pure `no_std`, zero-dependency. Field arithmetic reuses the Curve25519
//! [`Fe`] from the Ed25519 module. Scalar multiplication uses the constant-time
//! Montgomery ladder on the u-line of Curve25519.
//!
//! # API
//!
//! - [`clamp_scalar`] — RFC 7748 private-key clamping
//! - [`public_key`] — `X25519(scalar, 9)` (base-point multiplication)
//! - [`diffie_hellman`] — `X25519(scalar, peer_u)` shared secret
//! - [`x25519`] — low-level ladder: `X25519(k, u)`
//!
//! All secret-dependent paths are constant-time (fixed 255 iterations, CT swap).

use crate::ct::{ct_eq, ct_zeroize};
use crate::curve::ed25519::Fe;
use crate::curve::error::{CurveError, CurveResult};

/// X25519 public / private / shared-secret length (bytes).
pub const X25519_LEN: usize = 32;

/// Base-point u-coordinate = 9 (RFC 7748).
const BASEPOINT_U: [u8; 32] = [
    9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// a24 = (A − 2) / 4 = 121665 for Curve25519 (A = 486662).
fn a24() -> Fe {
    // Little-endian encoding of 121665
    Fe::from_bytes_le(&[
        0x41, 0xdb, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ])
    .expect("a24")
}

/// Clamp a 32-byte scalar per RFC 7748 §5:
/// clear bits 0,1,2 of the first byte; clear bit 255; set bit 254.
#[inline]
pub fn clamp_scalar(bytes: &mut [u8; 32]) {
    bytes[0] &= 248;
    bytes[31] &= 127;
    bytes[31] |= 64;
}

/// Constant-time conditional swap of two field elements.
/// `swap` must be 0 or 1. When 1, `a` and `b` are exchanged.
#[inline]
fn cswap(swap: u8, a: &mut Fe, b: &mut Fe) {
    // choice=1 → exchange a and b; choice=0 → leave unchanged
    let choice = core::hint::black_box(swap) & 1;
    let new_a = Fe::ct_select(choice, b, a);
    let new_b = Fe::ct_select(choice, a, b);
    *a = new_a;
    *b = new_b;
}

/// RFC 7748 X25519 scalar multiplication: returns the u-coordinate of `[k]U`.
///
/// - `k` is interpreted as a little-endian integer (after the caller clamps).
/// - `u` is the little-endian u-coordinate of the peer/base point.
/// - Always runs a fixed 255-iteration Montgomery ladder (constant-time in `k`).
///
/// Bit 255 of `u` is ignored (RFC 7748).
pub fn x25519(k: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    // Clamp scalar (RFC 7748 §5 — part of the X25519 function definition)
    let mut scalar = *k;
    clamp_scalar(&mut scalar);

    // Decode u; clear high bit per RFC
    let mut u_bytes = *u;
    u_bytes[31] &= 0x7f;
    let x1 = Fe::from_bytes_le(&u_bytes).unwrap_or(Fe::zero());

    // Ladder state
    let mut x2 = Fe::one();
    let mut z2 = Fe::zero();
    let mut x3 = x1;
    let mut z3 = Fe::one();
    let mut swap = 0u8;

    // Process bits 254 down to 0 (bit 255 of clamped scalar is always 0)
    for t in (0..255).rev() {
        let byte = scalar[t / 8];
        let kt = (byte >> (t & 7)) & 1;
        swap ^= kt;
        cswap(swap, &mut x2, &mut x3);
        cswap(swap, &mut z2, &mut z3);
        swap = kt;

        // Montgomery ladder step
        let a = x2.add(&z2);
        let aa = a.square();
        let b = x2.sub(&z2);
        let bb = b.square();
        let e = aa.sub(&bb);
        let c = x3.add(&z3);
        let d = x3.sub(&z3);
        let da = d.mul(&a);
        let cb = c.mul(&b);
        x3 = da.add(&cb).square();
        z3 = x1.mul(&da.sub(&cb).square());
        x2 = aa.mul(&bb);
        // z2 = E * (AA + a24 * E)
        z2 = e.mul(&aa.add(&a24().mul(&e)));
    }

    cswap(swap, &mut x2, &mut x3);
    cswap(swap, &mut z2, &mut z3);

    // Affine: x = x2 / z2
    let z_inv = z2.invert().unwrap_or(Fe::zero());
    let x = x2.mul(&z_inv);
    let mut out = [0u8; 32];
    x.to_bytes_le(&mut out);
    ct_zeroize(&mut scalar);
    out
}

/// Derive the X25519 public key from a 32-byte private scalar.
///
/// Clamps a copy of `private_key`, multiplies by the base point u = 9, and
/// returns the 32-byte little-endian public u-coordinate. The input buffer is
/// not modified.
pub fn public_key(private_key: &[u8; 32]) -> [u8; 32] {
    x25519(private_key, &BASEPOINT_U)
}

/// Compute the X25519 shared secret.
///
/// Clamps a copy of `private_key`, then returns `X25519(private, peer_public)`.
/// The input private key buffer is not modified.
///
/// Returns [`CurveError::InvalidPoint`] if the result is all-zero (low-order
/// point / contributory behaviour failure). Callers that intentionally accept
/// non-contributory secrets can use [`diffie_hellman_raw`] instead.
pub fn diffie_hellman(private_key: &[u8; 32], peer_public: &[u8; 32]) -> CurveResult<[u8; 32]> {
    let shared = diffie_hellman_raw(private_key, peer_public);
    // Reject the all-zero shared secret (RFC 7748 implementation notes /
    // contributory behaviour).
    if ct_eq(&shared, &[0u8; 32]) == 1 {
        return Err(CurveError::InvalidPoint);
    }
    Ok(shared)
}

/// Like [`diffie_hellman`] but does not reject an all-zero shared secret.
pub fn diffie_hellman_raw(private_key: &[u8; 32], peer_public: &[u8; 32]) -> [u8; 32] {
    x25519(private_key, peer_public)
}

/// X25519 private key wrapper (zeroized on drop when `alloc`/`std` patterns apply
/// via explicit [`SecretKey::zeroize`]).
#[derive(Clone)]
pub struct SecretKey {
    bytes: [u8; 32],
}

impl SecretKey {
    /// Create from raw 32 bytes (not yet clamped; clamping happens on use).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Generate a public key for this secret.
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            bytes: public_key(&self.bytes),
        }
    }

    /// Diffie–Hellman with peer public key (rejects all-zero shared secret).
    pub fn diffie_hellman(&self, peer: &PublicKey) -> CurveResult<[u8; 32]> {
        diffie_hellman(&self.bytes, &peer.bytes)
    }

    /// Raw bytes (unclamped). Prefer not to expose in higher layers.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Best-effort wipe of the secret material.
    pub fn zeroize(&mut self) {
        ct_zeroize(&mut self.bytes);
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// X25519 public key (u-coordinate).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicKey {
    bytes: [u8; 32],
}

impl PublicKey {
    /// Parse a 32-byte public key (no on-curve check beyond length; X25519
    /// decodes any 32-byte string as a field element).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// 32-byte little-endian encoding.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Consume into raw bytes.
    pub fn to_bytes(self) -> [u8; 32] {
        self.bytes
    }
}

// ---------------------------------------------------------------------------
// Ed25519 ↔ X25519 conversion (libsodium-compatible)
// ---------------------------------------------------------------------------

/// Convert an Ed25519 public key to an X25519 public key.
///
/// Birational map on the y-coordinate: `u = (1 + y) / (1 - y)` (RFC 7748 / libsodium).
/// Input is the 32-byte RFC 8032 compressed Ed25519 public key.
pub fn ed25519_pk_to_x25519(ed_pk: &[u8; 32]) -> CurveResult<[u8; 32]> {
    // Clear sign bit to recover y
    let mut yb = *ed_pk;
    yb[31] &= 0x7f;
    let y = Fe::from_bytes_le(&yb)?;
    let one = Fe::one();
    let one_plus_y = one.add(&y);
    let one_minus_y = one.sub(&y);
    let inv = one_minus_y.invert().map_err(|_| CurveError::InvalidPoint)?;
    let u = one_plus_y.mul(&inv);
    let mut out = [0u8; 32];
    u.to_bytes_le(&mut out);
    Ok(out)
}

/// Convert a 32-byte Ed25519 seed to an X25519 private key.
///
/// Matches libsodium `crypto_sign_ed25519_sk_to_curve25519` for the seed half:
/// `clamp(SHA-512(seed)[0..32])`.
pub fn ed25519_seed_to_x25519(seed: &[u8; 32]) -> [u8; 32] {
    let mut h = crate::hash::Sha512::new();
    h.update(seed);
    let dig = h.finalize();
    let mut sk = [0u8; 32];
    sk.copy_from_slice(&dig[..32]);
    clamp_scalar(&mut sk);
    sk
}

/// Convert a 32-byte clamped (or unclamped) Ed25519 scalar to X25519 private key
/// by applying RFC 7748 clamp (idempotent if already clamped).
pub fn ed25519_scalar_to_x25519(scalar: &[u8; 32]) -> [u8; 32] {
    let mut sk = *scalar;
    clamp_scalar(&mut sk);
    sk
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_decode(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    /// RFC 7748 §5.2 — intermediate ladder test vector.
    #[test]
    fn rfc7748_intermediate() {
        let k = hex_decode("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let u = hex_decode("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        let expected =
            hex_decode("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
        let out = x25519(&k, &u);
        assert_eq!(out, expected);
    }

    #[test]
    fn rfc7748_intermediate_2() {
        let k = hex_decode("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
        let u = hex_decode("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
        let expected =
            hex_decode("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");
        assert_eq!(x25519(&k, &u), expected);
    }

    /// RFC 7748 §6.1 — Alice / Bob key agreement.
    #[test]
    fn rfc7748_alice_bob() {
        let alice_sk =
            hex_decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let alice_pk_expected =
            hex_decode("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        let bob_sk = hex_decode("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let bob_pk_expected =
            hex_decode("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let shared_expected =
            hex_decode("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

        let alice_pk = public_key(&alice_sk);
        assert_eq!(alice_pk, alice_pk_expected, "Alice public key");

        let bob_pk = public_key(&bob_sk);
        assert_eq!(bob_pk, bob_pk_expected, "Bob public key");

        let s1 = diffie_hellman(&alice_sk, &bob_pk).expect("alice shared");
        let s2 = diffie_hellman(&bob_sk, &alice_pk).expect("bob shared");
        assert_eq!(s1, shared_expected, "shared from Alice");
        assert_eq!(s2, shared_expected, "shared from Bob");
        assert_eq!(s1, s2);
    }

    /// RFC 7748 §5.2 — second iteration (iterated DH).
    #[test]
    fn rfc7748_iterated() {
        // Once: X25519(k, u) with the intermediate vector already tested.
        // Iterated: start with k=u=9, apply 1 / 1000 times (we do 1 and a few).
        let nine = BASEPOINT_U;
        // Self-consistency: public_key(nine) == x25519(nine, 9)
        let pk = public_key(&nine);
        assert_eq!(pk, x25519(&nine, &nine));

        // RFC stress pattern (10 iterations)
        let mut k = nine;
        let mut u = nine;
        for _ in 0..10 {
            let r = x25519(&k, &u);
            u = k;
            k = r;
        }
        assert_ne!(k, [0u8; 32]);
    }

    #[test]
    fn secret_public_wrappers() {
        let sk = SecretKey::from_bytes(hex_decode(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        ));
        let pk = sk.public_key();
        assert_eq!(
            pk.as_bytes(),
            &hex_decode("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        );
        let bob_pk = PublicKey::from_bytes(hex_decode(
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
        ));
        let shared = sk.diffie_hellman(&bob_pk).unwrap();
        assert_eq!(
            shared,
            hex_decode("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
        );
    }

    #[test]
    fn fe_invert_two() {
        let two = Fe::from_bytes_le(&[
            2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ])
        .unwrap();
        let inv = two.invert().unwrap();
        let one = two.mul(&inv);
        let mut out = [0u8; 32];
        one.to_bytes_le(&mut out);
        assert_eq!(out[0], 1);
        assert_eq!(&out[1..], &[0u8; 31]);
    }

    #[test]
    fn public_keys_only() {
        let alice_sk =
            hex_decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let alice_pk = public_key(&alice_sk);
        assert_eq!(
            alice_pk,
            hex_decode("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"),
            "Alice public"
        );
        let bob_sk = hex_decode("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let bob_pk = public_key(&bob_sk);
        assert_eq!(
            bob_pk,
            hex_decode("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"),
            "Bob public"
        );
    }

    #[test]
    fn ed_pk_to_x25519_generator() {
        // Ed25519 base point → Montgomery u = 9
        use crate::curve::ed25519::Ed25519Point;
        use crate::curve::traits::CurvePoint;
        let mut ed_pk = [0u8; 32];
        Ed25519Point::generator()
            .to_bytes_compressed(&mut ed_pk)
            .unwrap();
        let u = ed25519_pk_to_x25519(&ed_pk).unwrap();
        // Basepoint u-coordinate is 9
        let mut expected = [0u8; 32];
        expected[0] = 9;
        assert_eq!(u, expected);
    }

    #[test]
    fn ed_seed_to_x25519_deterministic() {
        let seed = [7u8; 32];
        let a = ed25519_seed_to_x25519(&seed);
        let b = ed25519_seed_to_x25519(&seed);
        assert_eq!(a, b);
        // Clamped bits
        assert_eq!(a[0] & 7, 0);
        assert_eq!(a[31] & 0x80, 0);
        assert_eq!(a[31] & 0x40, 0x40);
    }

    #[test]
    fn clamp_bits() {
        let mut b = [0xffu8; 32];
        clamp_scalar(&mut b);
        assert_eq!(b[0] & 0x07, 0);
        assert_eq!(b[31] & 0x80, 0);
        assert_eq!(b[31] & 0x40, 0x40);
    }

    #[test]
    fn zero_shared_rejected() {
        // Low-order public point (u=0) yields zero shared secret after clamp*0
        let sk = [1u8; 32];
        let peer = [0u8; 32];
        assert!(diffie_hellman(&sk, &peer).is_err());
        // Raw still returns zeros
        assert_eq!(diffie_hellman_raw(&sk, &peer), [0u8; 32]);
    }
}
