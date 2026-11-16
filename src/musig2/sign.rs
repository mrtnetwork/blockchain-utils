//! Partial sign, verify, aggregate.

use super::error::{Musig2Error, Musig2Result};
use super::key_agg::coeff_for_key;
use super::session::{session_values, Session};
use crate::curve::secp256k1::{Scalar, Secp256k1Point};
use crate::curve::traits::CurvePoint;
use alloc::vec::Vec;

fn load_k(bytes: &[u8]) -> Musig2Result<Scalar> {
    if bytes.len() != 32 {
        return Err(Musig2Error::InvalidLength);
    }
    let mut b = [0u8; 32];
    b.copy_from_slice(bytes);
    let s = Scalar::from_bytes_be(&b).map_err(|_| Musig2Error::InvalidScalar)?;
    if s.is_zero() {
        return Err(Musig2Error::InvalidNonce);
    }
    Ok(s)
}

/// Partial signature: 32-byte scalar s.
pub fn partial_sign(secnonce: &[u8], sk: &[u8; 32], session: &Session) -> Musig2Result<[u8; 32]> {
    if secnonce.len() != 97 {
        return Err(Musig2Error::InvalidLength);
    }
    let vals = session_values(session)?;
    let mut k1 = load_k(&secnonce[0..32])?;
    let mut k2 = load_k(&secnonce[32..64])?;
    let pk_bytes = &secnonce[64..97];

    // If R is odd Y, negate both nonces
    let r_ge = vals
        .r
        .to_affine()
        .map_err(|_| Musig2Error::InvalidSession)?;
    if r_ge.y.is_odd() == 1 {
        k1 = k1.neg();
        k2 = k2.neg();
    }

    let d0 = Scalar::from_bytes(sk).map_err(|_| Musig2Error::InvalidScalar)?;
    if d0.is_zero() {
        return Err(Musig2Error::InvalidScalar);
    }
    let p = Secp256k1Point::generator().mul(&d0);
    let mut pb = [0u8; 33];
    p.to_bytes_compressed(&mut pb)
        .map_err(|_| Musig2Error::InvalidKey)?;
    if pb != pk_bytes {
        return Err(Musig2Error::InvalidKey);
    }

    let key_refs: Vec<&[u8]> = session.public_keys.iter().map(|k| k.as_slice()).collect();
    let a = coeff_for_key(&key_refs, &pb);

    let mut g = Scalar::one();
    let q_ge = vals
        .public_key
        .to_affine()
        .map_err(|_| Musig2Error::InvalidKey)?;
    if q_ge.y.is_odd() == 1 {
        g = g.neg();
    }
    // d' = g * g_acc * d
    let d = g.mul(&vals.g_acc).mul(&d0);

    // s = k1 + b*k2 + e*a*d
    let s = k1.add(&vals.b.mul(&k2)).add(&vals.e.mul(&a).mul(&d));
    let mut out = [0u8; 32];
    s.to_bytes_be(&mut out);
    Ok(out)
}

/// Verify a partial signature against pubnonce and pk for this session.
pub fn partial_sig_verify(
    signature: &[u8; 32],
    pubnonce: &[u8; 66],
    pk: &[u8],
    session: &Session,
) -> Musig2Result<bool> {
    if pk.len() != 33 {
        return Err(Musig2Error::InvalidLength);
    }
    let vals = session_values(session)?;
    // BIP-327: s must be strictly less than n (reject s >= n).
    let s = Scalar::from_bytes_be(signature).map_err(|_| Musig2Error::InvalidScalar)?;

    let r1 = Secp256k1Point::from_bytes(&pubnonce[0..33]).map_err(|_| Musig2Error::InvalidNonce)?;
    let r2 =
        Secp256k1Point::from_bytes(&pubnonce[33..66]).map_err(|_| Musig2Error::InvalidNonce)?;
    let mut re = r1.add(&r2.mul(&vals.b));
    // Negate individual effective nonce iff *session* R has odd Y (same as Sign)
    let r_sess = vals
        .r
        .to_affine()
        .map_err(|_| Musig2Error::InvalidSession)?;
    if r_sess.y.is_odd() == 1 {
        re = re.neg();
    }

    let p = Secp256k1Point::from_bytes(pk).map_err(|_| Musig2Error::InvalidKey)?;
    let key_refs: Vec<&[u8]> = session.public_keys.iter().map(|k| k.as_slice()).collect();
    let a = coeff_for_key(&key_refs, pk);

    let mut g = Scalar::one();
    let q_ge = vals
        .public_key
        .to_affine()
        .map_err(|_| Musig2Error::InvalidKey)?;
    if q_ge.y.is_odd() == 1 {
        g = g.neg();
    }
    // g' = g · g_acc ;  s·G == Re + e · a · g' · P
    let g_prime = g.mul(&vals.g_acc);
    let p_eff = p.mul(&a).mul(&g_prime);

    let sg = Secp256k1Point::generator().mul(&s);
    let rhs = re.add(&p_eff.mul(&vals.e));
    let mut aenc = [0u8; 33];
    let mut benc = [0u8; 33];
    if sg.to_bytes_compressed(&mut aenc).is_err() || rhs.to_bytes_compressed(&mut benc).is_err() {
        // both infinity or invalid — compare identity flags
        return Ok(sg.ct_is_identity() == 1 && rhs.ct_is_identity() == 1);
    }
    Ok(aenc == benc)
}

/// Aggregate partial signatures → final s; return BIP-340 (R.x || s).
pub fn partial_sig_agg(partials: &[[u8; 32]], session: &Session) -> Musig2Result<[u8; 64]> {
    if partials.is_empty() {
        return Err(Musig2Error::TooFewKeys);
    }
    let vals = session_values(session)?;
    let mut s = Scalar::zero();
    for p in partials {
        let si = Scalar::from_bytes_be(p).map_err(|_| Musig2Error::InvalidScalar)?;
        s = s.add(&si);
    }
    // s += e * t_acc  (tweak contribution)
    s = s.add(&vals.e.mul(&vals.t_acc));

    let mut r_enc = [0u8; 33];
    let mut r = vals.r;
    let r_ge = r.to_affine().map_err(|_| Musig2Error::InvalidSession)?;
    if r_ge.y.is_odd() == 1 {
        r = r.neg();
    }
    r.to_bytes_compressed(&mut r_enc)
        .map_err(|_| Musig2Error::InvalidSession)?;

    let mut out = [0u8; 64];
    out[0..32].copy_from_slice(&r_enc[1..]);
    let mut sb = [0u8; 32];
    s.to_bytes_be(&mut sb);
    out[32..64].copy_from_slice(&sb);
    Ok(out)
}

/// Verify a final MuSig2 / BIP-340 aggregate signature against the aggregate x-only key.
///
/// `signature` is 64 bytes (`R.x || s`), `agg_xonly` is 32 bytes.
pub fn verify_aggregate(message: &[u8], signature: &[u8], agg_xonly: &[u8]) -> Musig2Result<bool> {
    if signature.len() != 64 || agg_xonly.len() != 32 {
        return Err(Musig2Error::InvalidLength);
    }
    use crate::signature::schnorr::{
        verify as bip340_verify, PublicKey as SchnorrPk, Signature as SchnorrSig,
    };
    let mut rx = [0u8; 32];
    let mut s = [0u8; 32];
    rx.copy_from_slice(&signature[0..32]);
    s.copy_from_slice(&signature[32..64]);
    let mut x = [0u8; 32];
    x.copy_from_slice(agg_xonly);
    match bip340_verify(&SchnorrPk(x), message, &SchnorrSig { rx, s }) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[derive(Clone, Debug)]
pub struct DeterministicSignature {
    /// 66-byte public nonce of this signer.
    pub pubnonce: Vec<u8>,
    /// 32-byte partial signature.
    pub partial: [u8; 32],
}

/// BIP-327 `hash_MuSig/deterministic/nonce` input for index `i` (0 or 1).
fn det_nonce_hash(
    sk_prime: &[u8; 32],
    aggother_nonce: &[u8],
    aggpk_xonly: &[u8; 32],
    msg: &[u8],
    i: u8,
) -> [u8; 32] {
    use super::hash::tagged_hash;
    let mut buf = Vec::with_capacity(32 + 66 + 32 + 8 + msg.len() + 1);
    buf.extend_from_slice(sk_prime);
    buf.extend_from_slice(aggother_nonce);
    buf.extend_from_slice(aggpk_xonly);
    buf.extend_from_slice(&(msg.len() as u64).to_be_bytes());
    buf.extend_from_slice(msg);
    buf.push(i);
    tagged_hash(b"MuSig/deterministic/nonce", &buf)
}

/// BIP-327 **DeterministicSign**.
///
/// - `aggother_nonce`: 66-byte `NonceAgg` of **all other** signers' pubnonces
/// - `public_keys`: full participant list (33-byte compressed each)
/// - `tweaks`: optional key-agg tweaks
/// - `rand`: optional 32-byte aux; if set, `sk' = sk XOR hash_MuSig/aux(rand)`, else `sk' = sk`
///
/// Returns this signer's `pubnonce` and partial signature `s`.
pub fn deterministic_sign(
    sk: &[u8; 32],
    aggother_nonce: &[u8],
    public_keys: &[Vec<u8>],
    tweaks: &[super::key_agg::Tweak],
    msg: &[u8],
    rand: Option<&[u8; 32]>,
) -> Musig2Result<DeterministicSignature> {
    use super::hash::{tagged_hash, xor32};
    use super::key_agg::key_agg_and_tweak;
    use super::nonce::nonce_agg;

    if aggother_nonce.len() != 66 {
        return Err(Musig2Error::InvalidLength);
    }
    if public_keys.len() < 2 {
        return Err(Musig2Error::TooFewKeys);
    }
    for k in public_keys {
        if k.len() != 33 {
            return Err(Musig2Error::InvalidLength);
        }
    }

    // sk'
    let sk_prime: [u8; 32] = if let Some(r) = rand {
        let aux = tagged_hash(b"MuSig/aux", r);
        xor32(sk, &aux)
    } else {
        *sk
    };

    let key_refs: Vec<&[u8]> = public_keys.iter().map(|k| k.as_slice()).collect();
    let ctx = key_agg_and_tweak(&key_refs, tweaks)?;
    let aggpk = ctx.x_only()?;

    let k1h = det_nonce_hash(&sk_prime, aggother_nonce, &aggpk, msg, 0);
    let k2h = det_nonce_hash(&sk_prime, aggother_nonce, &aggpk, msg, 1);
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

    // Individual pk from sk (not sk')
    let d = Scalar::from_bytes(sk).map_err(|_| Musig2Error::InvalidScalar)?;
    if d.is_zero() {
        return Err(Musig2Error::InvalidScalar);
    }
    let p = Secp256k1Point::generator().mul(&d);
    let mut pk = [0u8; 33];
    p.to_bytes_compressed(&mut pk)
        .map_err(|_| Musig2Error::InvalidKey)?;

    let mut pubnonce = Vec::with_capacity(66);
    pubnonce.extend_from_slice(&r1b);
    pubnonce.extend_from_slice(&r2b);

    let mut secnonce = Vec::with_capacity(97);
    secnonce.extend_from_slice(&k1b);
    secnonce.extend_from_slice(&k2b);
    secnonce.extend_from_slice(&pk);

    // aggnonce = NonceAgg([our_pubnonce, aggother_nonce])
    let aggnonce = nonce_agg(&[pubnonce.as_slice(), aggother_nonce])?;

    let session = Session {
        public_keys: public_keys.to_vec(),
        tweaks: tweaks.to_vec(),
        aggnonce,
        msg: msg.to_vec(),
    };
    let partial = partial_sign(&secnonce, sk, &session)?;

    Ok(DeterministicSignature { pubnonce, partial })
}
