//! Session values (b, R, e) from aggnonce + KeyAgg + message.

use super::error::{Musig2Error, Musig2Result};
use super::hash::tagged_hash;
use super::key_agg::{key_agg_and_tweak, KeyAggContext, Tweak};
use crate::curve::secp256k1::{Scalar, Secp256k1Point};
use crate::curve::traits::CurvePoint;
use alloc::vec::Vec;

/// Caller-held session inputs.
#[derive(Clone, Debug)]
pub struct Session {
    pub public_keys: Vec<Vec<u8>>,
    pub tweaks: Vec<Tweak>,
    pub aggnonce: Vec<u8>,
    pub msg: Vec<u8>,
}

/// Derived session values used by partial_sign / verify.
#[derive(Clone, Debug)]
pub struct SessionValues {
    pub public_key: Secp256k1Point, // Q after tweaks
    pub g_acc: Scalar,
    pub t_acc: Scalar,
    pub b: Scalar,
    pub r: Secp256k1Point,
    pub e: Scalar,
}

fn parse_even_or_inf(bytes: &[u8]) -> Musig2Result<Secp256k1Point> {
    if bytes.len() != 33 {
        return Err(Musig2Error::InvalidLength);
    }
    if bytes.iter().all(|&b| b == 0) {
        return Ok(Secp256k1Point::identity());
    }
    // Strict BIP-327: reject non-0x02/0x03 prefixes (no coercion on error paths).
    if bytes[0] != 0x02 && bytes[0] != 0x03 {
        return Err(Musig2Error::InvalidNonce);
    }
    // Even-Y interpretation: lift x, negate iff odd prefix.
    let mut even = [0u8; 33];
    even[0] = 0x02;
    even[1..].copy_from_slice(&bytes[1..]);
    let p = Secp256k1Point::from_bytes(&even).map_err(|_| Musig2Error::InvalidNonce)?;
    if bytes[0] == 0x03 {
        return Ok(p.neg());
    }
    Ok(p)
}

pub fn session_values(session: &Session) -> Musig2Result<SessionValues> {
    if session.aggnonce.len() != 66 {
        return Err(Musig2Error::InvalidLength);
    }
    let key_refs: Vec<&[u8]> = session.public_keys.iter().map(|k| k.as_slice()).collect();
    let ctx: KeyAggContext = key_agg_and_tweak(&key_refs, &session.tweaks)?;
    let xonly = ctx.x_only()?;

    let mut coef_in = Vec::with_capacity(66 + 32 + session.msg.len());
    coef_in.extend_from_slice(&session.aggnonce);
    coef_in.extend_from_slice(&xonly);
    coef_in.extend_from_slice(&session.msg);
    let bh = tagged_hash(b"MuSig/noncecoef", &coef_in);
    let b = Scalar::from_bytes_mod_order(&bh);

    let r1 = parse_even_or_inf(&session.aggnonce[0..33])?;
    let r2 = parse_even_or_inf(&session.aggnonce[33..66])?;
    let mut r = r1.add(&r2.mul(&b));
    if r.ct_is_identity() == 1 {
        // BIP-327: fall back to G if R is infinity
        r = Secp256k1Point::generator();
    }

    let mut r_enc = [0u8; 33];
    r.to_bytes_compressed(&mut r_enc)
        .map_err(|_| Musig2Error::InvalidSession)?;
    let mut rx = [0u8; 32];
    rx.copy_from_slice(&r_enc[1..]);

    let mut chal = Vec::with_capacity(64 + session.msg.len());
    chal.extend_from_slice(&rx);
    chal.extend_from_slice(&xonly);
    chal.extend_from_slice(&session.msg);
    let eh = tagged_hash(b"BIP0340/challenge", &chal);
    let e = Scalar::from_bytes_mod_order(&eh);

    Ok(SessionValues {
        public_key: ctx.q,
        g_acc: ctx.g_acc,
        t_acc: ctx.t_acc,
        b,
        r,
        e,
    })
}
