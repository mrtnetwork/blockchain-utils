//! Key aggregation (BIP-327 KeyAgg).

use super::error::{Musig2Error, Musig2Result};
use super::hash::tagged_hash;
use crate::curve::secp256k1::{Scalar, Secp256k1Point};
use crate::curve::traits::CurvePoint;
use alloc::vec::Vec;

/// Optional x-only or plain tweak applied after key aggregation.
#[derive(Clone, Debug)]
pub struct Tweak {
    pub tweak: [u8; 32],
    pub is_x_only: bool,
}

/// Aggregated key context: Q, running g_acc / t_acc for session math.
#[derive(Clone, Debug)]
pub struct KeyAggContext {
    pub q: Secp256k1Point,
    pub g_acc: Scalar,
    pub t_acc: Scalar,
}

fn parse_pk(bytes: &[u8]) -> Musig2Result<Secp256k1Point> {
    if bytes.len() != 33 {
        return Err(Musig2Error::InvalidLength);
    }
    Secp256k1Point::from_bytes(bytes).map_err(|_| Musig2Error::InvalidKey)
}

fn is_second_unique_key(keys: &[&[u8]], key: &[u8]) -> bool {
    if keys.is_empty() {
        return false;
    }
    let first = keys[0];
    for k in keys.iter().skip(1) {
        if *k != first {
            return *k == key;
        }
    }
    false
}

fn key_agg_coeff(keys: &[&[u8]], key: &[u8]) -> Scalar {
    if is_second_unique_key(keys, key) {
        return Scalar::one();
    }
    let mut list = Vec::new();
    for k in keys {
        list.extend_from_slice(k);
    }
    let hash_keys = tagged_hash(b"KeyAgg list", &list);
    let mut coeff_in = Vec::with_capacity(64);
    coeff_in.extend_from_slice(&hash_keys);
    coeff_in.extend_from_slice(key);
    let h = tagged_hash(b"KeyAgg coefficient", &coeff_in);
    Scalar::from_bytes_mod_order(&h)
}

/// Aggregate public keys → KeyAggContext (no tweaks).
pub fn key_agg(keys: &[&[u8]]) -> Musig2Result<KeyAggContext> {
    if keys.len() < 2 {
        return Err(Musig2Error::TooFewKeys);
    }
    for k in keys {
        if k.len() != 33 {
            return Err(Musig2Error::InvalidLength);
        }
    }
    let mut q = Secp256k1Point::identity();
    for k in keys {
        let pk = parse_pk(k)?;
        let a = key_agg_coeff(keys, k);
        q = q.add(&pk.mul(&a));
    }
    if q.ct_is_identity() == 1 {
        return Err(Musig2Error::InvalidKey);
    }
    Ok(KeyAggContext {
        q,
        g_acc: Scalar::one(),
        t_acc: Scalar::zero(),
    })
}

fn apply_tweak(ctx: &KeyAggContext, tweak: &Tweak) -> Musig2Result<KeyAggContext> {
    let t = Scalar::from_bytes_be(&tweak.tweak).map_err(|_| Musig2Error::InvalidScalar)?;
    if t.is_zero() {
        return Err(Musig2Error::InvalidScalar);
    }
    let mut g = Scalar::one();
    let ge = ctx.q.to_affine().map_err(|_| Musig2Error::InvalidKey)?;
    if tweak.is_x_only && ge.y.is_odd() == 1 {
        g = g.neg();
    }
    // Q' = g·Q + t·G
    let q2 = ctx.q.mul(&g).add(&Secp256k1Point::generator().mul(&t));
    if q2.ct_is_identity() == 1 {
        return Err(Musig2Error::InvalidKey);
    }
    let g_acc = g.mul(&ctx.g_acc);
    let t_acc = t.add(&g.mul(&ctx.t_acc));
    Ok(KeyAggContext {
        q: q2,
        g_acc,
        t_acc,
    })
}

/// KeyAgg then sequential tweaks (Taproot-style).
pub fn key_agg_and_tweak(keys: &[&[u8]], tweaks: &[Tweak]) -> Musig2Result<KeyAggContext> {
    let mut ctx = key_agg(keys)?;
    for tw in tweaks {
        ctx = apply_tweak(&ctx, tw)?;
    }
    Ok(ctx)
}

impl KeyAggContext {
    /// 32-byte x-only of Q (even-Y lift not forced; uses affine x).
    pub fn x_only(&self) -> Musig2Result<[u8; 32]> {
        let mut enc = [0u8; 33];
        self.q
            .to_bytes_compressed(&mut enc)
            .map_err(|_| Musig2Error::InvalidKey)?;
        let mut x = [0u8; 32];
        x.copy_from_slice(&enc[1..]);
        Ok(x)
    }

    pub fn is_odd_y(&self) -> Musig2Result<bool> {
        let ge = self.q.to_affine().map_err(|_| Musig2Error::InvalidKey)?;
        Ok(ge.y.is_odd() == 1)
    }
}

/// Coefficient a_i for a given compressed pk in the key list.
pub fn coeff_for_key(keys: &[&[u8]], key: &[u8]) -> Scalar {
    key_agg_coeff(keys, key)
}
