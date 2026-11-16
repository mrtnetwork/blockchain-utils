//! Nonce generation and aggregation (BIP-327 layout).

use super::error::{Musig2Error, Musig2Result};
use super::hash::{tagged_hash, xor32};
use crate::curve::secp256k1::{Scalar, Secp256k1Point};
use crate::curve::traits::CurvePoint;
use alloc::vec;
use alloc::vec::Vec;

/// secnonce = k1(32) || k2(32) || pk(33); pubnonce = R1(33) || R2(33).
#[derive(Clone, Debug)]
pub struct NoncePair {
    pub secnonce: Vec<u8>,
    pub pubnonce: Vec<u8>,
}

/// BIP-327 `nonce_hash` buffer:
/// `rand || len(pk)||pk || len(aggpk)||aggpk || msg_prefixed || len4(extra)||extra || i`
fn nonce_hash(
    rand: &[u8; 32],
    pk: &[u8],
    aggpk: &[u8],
    i: u8,
    msg_prefixed: &[u8],
    extra_in: &[u8],
) -> [u8; 32] {
    let mut buf = Vec::with_capacity(
        32 + 1 + pk.len() + 1 + aggpk.len() + msg_prefixed.len() + 4 + extra_in.len() + 1,
    );
    buf.extend_from_slice(rand);
    buf.push(pk.len() as u8);
    buf.extend_from_slice(pk);
    buf.push(aggpk.len() as u8);
    buf.extend_from_slice(aggpk);
    buf.extend_from_slice(msg_prefixed);
    let elen = (extra_in.len() as u32).to_be_bytes();
    buf.extend_from_slice(&elen);
    buf.extend_from_slice(extra_in);
    buf.push(i);
    tagged_hash(b"MuSig/nonce", &buf)
}

/// Generate MuSig2 nonce (BIP-327).
///
/// - `sk`: optional secret key. If **present**, `rand = sk XOR hash_MuSig/aux(rand')`.
///   If **absent**, `rand = rand'` (no aux mix). BIP-327 optional argument.
/// - `pk`: 33-byte compressed (required if `sk` is `None`; otherwise derived from `sk`)
/// - `agg_pk`: optional 32-byte x-only aggregate
/// - `extra_in`: optional
/// - `msg`: optional message (`None` = absent → `0x00`; `Some(&[])` = empty present)
/// - `rand`: 32-byte randomness `rand'` (required, caller-provided CSPRNG output).
pub fn nonce_generate(
    sk: Option<&[u8; 32]>,
    pk: Option<&[u8]>,
    agg_pk: Option<&[u8]>,
    extra_in: Option<&[u8]>,
    msg: Option<&[u8]>,
    rand: &[u8; 32],
) -> Musig2Result<NoncePair> {
    let pk_bytes: Vec<u8> = if let Some(p) = pk {
        if p.len() != 33 {
            return Err(Musig2Error::InvalidLength);
        }
        p.to_vec()
    } else if let Some(skv) = sk {
        let d = Scalar::from_bytes(skv).map_err(|_| Musig2Error::InvalidScalar)?;
        let p = Secp256k1Point::generator().mul(&d);
        let mut pb = [0u8; 33];
        p.to_bytes_compressed(&mut pb)
            .map_err(|_| Musig2Error::InvalidKey)?;
        pb.to_vec()
    } else {
        return Err(Musig2Error::InvalidKey);
    };

    let rand_in: [u8; 32] = *rand;

    // BIP-327: only XOR with MuSig/aux when sk is present
    let rand_prime: [u8; 32] = if let Some(skv) = sk {
        let aux = tagged_hash(b"MuSig/aux", &rand_in);
        xor32(skv, &aux)
    } else {
        rand_in
    };

    let aggpk = agg_pk.unwrap_or(&[]);
    if !aggpk.is_empty() && aggpk.len() != 32 {
        return Err(Musig2Error::InvalidLength);
    }

    let msg_prefixed: Vec<u8> = match msg {
        None => vec![0x00],
        Some(m) => {
            let mut v = Vec::with_capacity(1 + 8 + m.len());
            v.push(0x01);
            v.extend_from_slice(&(m.len() as u64).to_be_bytes());
            v.extend_from_slice(m);
            v
        }
    };
    let extra = extra_in.unwrap_or(&[]);

    let k1h = nonce_hash(&rand_prime, &pk_bytes, aggpk, 0, &msg_prefixed, extra);
    let k2h = nonce_hash(&rand_prime, &pk_bytes, aggpk, 1, &msg_prefixed, extra);
    let k1 = Scalar::from_bytes_mod_order(&k1h);
    let k2 = Scalar::from_bytes_mod_order(&k2h);
    if k1.is_zero() || k2.is_zero() {
        return Err(Musig2Error::InvalidNonce);
    }
    let r1 = Secp256k1Point::generator().mul(&k1);
    let r2 = Secp256k1Point::generator().mul(&k2);
    let mut r1b = [0u8; 33];
    let mut r2b = [0u8; 33];
    r1.to_bytes_compressed(&mut r1b)
        .map_err(|_| Musig2Error::InvalidNonce)?;
    r2.to_bytes_compressed(&mut r2b)
        .map_err(|_| Musig2Error::InvalidNonce)?;

    let mut k1b = [0u8; 32];
    let mut k2b = [0u8; 32];
    k1.to_bytes_be(&mut k1b);
    k2.to_bytes_be(&mut k2b);

    let mut secnonce = Vec::with_capacity(97);
    secnonce.extend_from_slice(&k1b);
    secnonce.extend_from_slice(&k2b);
    secnonce.extend_from_slice(&pk_bytes);

    let mut pubnonce = Vec::with_capacity(66);
    pubnonce.extend_from_slice(&r1b);
    pubnonce.extend_from_slice(&r2b);
    Ok(NoncePair { secnonce, pubnonce })
}

/// Aggregate public nonces: sum R1_i, sum R2_i → 66 bytes.
pub fn nonce_agg(pubnonces: &[&[u8]]) -> Musig2Result<Vec<u8>> {
    if pubnonces.len() < 2 {
        return Err(Musig2Error::TooFewKeys);
    }
    let mut sum1 = Secp256k1Point::identity();
    let mut sum2 = Secp256k1Point::identity();
    for pn in pubnonces {
        if pn.len() != 66 {
            return Err(Musig2Error::InvalidLength);
        }
        let r1 = Secp256k1Point::from_bytes(&pn[0..33]).map_err(|_| Musig2Error::InvalidNonce)?;
        let r2 = Secp256k1Point::from_bytes(&pn[33..66]).map_err(|_| Musig2Error::InvalidNonce)?;
        sum1 = sum1.add(&r1);
        sum2 = sum2.add(&r2);
    }
    let mut out = alloc::vec![0u8; 66];
    if sum1.ct_is_identity() == 1 {
        out[0..33].fill(0);
    } else {
        sum1.to_bytes_compressed(&mut out[0..33])
            .map_err(|_| Musig2Error::InvalidNonce)?;
    }
    if sum2.ct_is_identity() == 1 {
        out[33..66].fill(0);
    } else {
        sum2.to_bytes_compressed(&mut out[33..66])
            .map_err(|_| Musig2Error::InvalidNonce)?;
    }
    Ok(out)
}
