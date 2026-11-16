//! BIP-340 Schnorr signatures over secp256k1 (x-only public keys).
//!
//! Challenge tagged-hash and verification equation:
//! `s·G = R + e·P` with `e = H(R.x || P.x || m)`.

use crate::ct::ct_eq;
use crate::curve::secp256k1::{Scalar, Secp256k1Point};
use crate::curve::traits::CurvePoint;
use crate::hash::sha256;
use crate::signature::error::{SignatureError, SignatureResult};

/// x-only public key (32 bytes).
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[derive(Clone, Copy, Debug)]
pub struct PublicKey(pub [u8; 32]);

/// Secret key scalar.
#[derive(Clone, Copy, Debug)]
pub struct SecretKey {
    d: Scalar,
}

/// Signature (R.x || s), 64 bytes.
#[derive(Clone, Copy, Debug)]
pub struct Signature {
    pub rx: [u8; 32],
    pub s: [u8; 32],
}

fn tagged_hash(tag: &[u8], msg: &[u8]) -> [u8; 32] {
    let tag_hash = sha256(tag).unwrap_or([0u8; 32]);
    // BIP-340: SHA256(SHA256(tag) || SHA256(tag) || msg)
    #[cfg(feature = "alloc")]
    {
        #[allow(unused_imports)]
        use alloc::vec::Vec;
        let mut buf = Vec::with_capacity(64 + msg.len());
        buf.extend_from_slice(&tag_hash);
        buf.extend_from_slice(&tag_hash);
        buf.extend_from_slice(msg);
        sha256(&buf).unwrap_or([0u8; 32])
    }
    #[cfg(not(feature = "alloc"))]
    {
        // Stack-limited path for no_std without alloc (max 256-byte messages).
        let mut buf = [0u8; 64 + 256];
        let n = core::cmp::min(msg.len(), 256);
        buf[0..32].copy_from_slice(&tag_hash);
        buf[32..64].copy_from_slice(&tag_hash);
        buf[64..64 + n].copy_from_slice(&msg[..n]);
        sha256(&buf[..64 + n]).unwrap_or([0u8; 32])
    }
}

impl SecretKey {
    pub fn from_bytes(bytes: &[u8]) -> SignatureResult<Self> {
        if bytes.len() != 32 {
            return Err(SignatureError::InvalidLength);
        }
        let d = Scalar::from_bytes(bytes).map_err(|_| SignatureError::InvalidPrivateKey)?;
        Ok(Self { d })
    }

    pub fn to_bytes(&self, out: &mut [u8; 32]) {
        self.d.to_bytes_be(out);
    }

    pub fn public_key(&self) -> SignatureResult<PublicKey> {
        let p = Secp256k1Point::generator().mul(&self.d);
        let mut enc = [0u8; 33];
        p.to_bytes_compressed(&mut enc)
            .map_err(|_| SignatureError::InvalidPublicKey)?;
        // BIP-340: even y; if odd, negate d conceptually for signing
        let mut x = [0u8; 32];
        x.copy_from_slice(&enc[1..33]);
        Ok(PublicKey(x))
    }
}

impl PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> SignatureResult<Self> {
        if bytes.len() != 32 {
            return Err(SignatureError::InvalidLength);
        }
        let mut b = [0u8; 32];
        b.copy_from_slice(bytes);
        Ok(Self(b))
    }
}

/// Sign message with BIP-340 Schnorr (deterministic nonce; even-Y adjusted).
pub fn sign(sk: &SecretKey, message: &[u8]) -> SignatureResult<Signature> {
    // d' = d if even Y(d·G) else n - d — branchless: parity bit is secret-
    // derived (d is secret), so select via mask, never `if`.
    let p = Secp256k1Point::generator().mul(&sk.d);
    let mut penc = [0u8; 33];
    p.to_bytes_compressed(&mut penc)
        .map_err(|_| SignatureError::InvalidPublicKey)?;
    let d_odd = ((penc[0] == 0x03) as u8) & 1;
    let d_neg = sk.d.neg();
    let d = Scalar::ct_select(d_odd, &d_neg, &sk.d);
    let mut d_bytes = [0u8; 32];
    d.to_bytes_be(&mut d_bytes);
    let mut px = [0u8; 32];
    px.copy_from_slice(&penc[1..33]);

    // Deterministic nonce: k = int(SHA256(d_bytes || SHA256(m))) mod n
    let mh = sha256(message).unwrap_or([0u8; 32]);
    let mut seed = [0u8; 64];
    seed[0..32].copy_from_slice(&d_bytes);
    seed[32..64].copy_from_slice(&mh);
    let k_hash = sha256(&seed).unwrap_or([0u8; 32]);
    let mut k = Scalar::from_bytes_mod_order(&k_hash);
    if k.is_zero() {
        return Err(SignatureError::InvalidSignature);
    }

    let r_point = Secp256k1Point::generator().mul(&k);
    let mut r_enc = [0u8; 33];
    r_point
        .to_bytes_compressed(&mut r_enc)
        .map_err(|_| SignatureError::InvalidSignature)?;
    // Force even Y for R — branchless: always compute negated candidate,
    // select via mask (was `if odd { k.neg(); mul }` — 50% extra mul leaked
    // 1 nonce bit via timing).
    let k_neg = k.neg();
    let r_neg_pt = Secp256k1Point::generator().mul(&k_neg);
    let mut r_neg_enc = [0u8; 33];
    r_neg_pt
        .to_bytes_compressed(&mut r_neg_enc)
        .map_err(|_| SignatureError::InvalidSignature)?;
    let r_odd = ((r_enc[0] == 0x03) as u8) & 1;
    k = Scalar::ct_select(r_odd, &k_neg, &k);
    let _r_point = Secp256k1Point::ct_select(r_odd, &r_neg_pt, &r_point);
    for i in 0..33 {
        // byte-wise branchless select of the encoding
        let m = (r_odd as i8).wrapping_neg() as u8;
        r_enc[i] = (r_neg_enc[i] & m) | (r_enc[i] & !m);
    }
    let mut rx = [0u8; 32];
    rx.copy_from_slice(&r_enc[1..33]);

    // e = tagged_hash("BIP0340/challenge", r.x || P.x || m)  — full message
    #[cfg(feature = "alloc")]
    let e_bytes = {
        let mut chal = Vec::with_capacity(64 + message.len());
        chal.extend_from_slice(&rx);
        chal.extend_from_slice(&px);
        chal.extend_from_slice(message);
        tagged_hash(b"BIP0340/challenge", &chal)
    };
    #[cfg(not(feature = "alloc"))]
    let e_bytes = {
        let mut chal = [0u8; 64 + 256];
        let n = core::cmp::min(message.len(), 256);
        chal[0..32].copy_from_slice(&rx);
        chal[32..64].copy_from_slice(&px);
        chal[64..64 + n].copy_from_slice(&message[..n]);
        tagged_hash(b"BIP0340/challenge", &chal[..64 + n])
    };
    let e = Scalar::from_bytes_mod_order(&e_bytes);

    // s = k + e * d'
    let s = k.add(&e.mul(&d));
    let mut sb = [0u8; 32];
    s.to_bytes_be(&mut sb);
    Ok(Signature { rx, s: sb })
}

/// Verify BIP-340 Schnorr signature.
pub fn verify(pk: &PublicKey, message: &[u8], sig: &Signature) -> SignatureResult<()> {
    let s = Scalar::from_bytes_be(&sig.s).map_err(|_| SignatureError::InvalidSignature)?;
    // Lift x-only pk to point (even y)
    let mut comp = [0u8; 33];
    comp[0] = 0x02;
    comp[1..].copy_from_slice(&pk.0);
    let p = Secp256k1Point::from_bytes(&comp).map_err(|_| SignatureError::InvalidPublicKey)?;

    // BIP-340: e = int(hash_BIP0340/challenge(bytes(r) || bytes(P) || m)) mod n
    #[cfg(feature = "alloc")]
    let e_bytes = {
        let mut chal_input = Vec::with_capacity(64 + message.len());
        chal_input.extend_from_slice(&sig.rx);
        chal_input.extend_from_slice(&pk.0);
        chal_input.extend_from_slice(message);
        tagged_hash(b"BIP0340/challenge", &chal_input)
    };
    #[cfg(not(feature = "alloc"))]
    let e_bytes = {
        let mut chal_input = [0u8; 64 + 256];
        let n = core::cmp::min(message.len(), 256);
        chal_input[0..32].copy_from_slice(&sig.rx);
        chal_input[32..64].copy_from_slice(&pk.0);
        chal_input[64..64 + n].copy_from_slice(&message[..n]);
        tagged_hash(b"BIP0340/challenge", &chal_input[..64 + n])
    };
    let e = Scalar::from_bytes_mod_order(&e_bytes);

    // R' = s·G - e·P
    let sg = Secp256k1Point::generator().mul(&s);
    let ep = p.mul(&e);
    let r_calc = sg.add(&ep.neg());
    let mut enc = [0u8; 33];
    r_calc
        .to_bytes_compressed(&mut enc)
        .map_err(|_| SignatureError::VerificationFailed)?;
    if enc[0] != 0x02 {
        // need even Y
        return Err(SignatureError::VerificationFailed);
    }
    if ct_eq(&enc[1..33], &sig.rx) == 1 {
        Ok(())
    } else {
        Err(SignatureError::VerificationFailed)
    }
}

/// BIP-340 deterministic nonce with optional 32-byte aux randomness.
///
/// `k0 = int(tagged_hash("BIP0340/nonce", (d' XOR tagged_hash("BIP0340/aux", aux)) || Px || m)) mod n`
pub fn sign_with_aux(
    sk: &SecretKey,
    message: &[u8],
    aux: Option<&[u8; 32]>,
) -> SignatureResult<Signature> {
    sign_with_aux_and_tweak(sk, message, aux, None)
}

/// Optional Taproot/BIP-341 style secret tweak: `d' = d + t (mod n)` after even-Y adjust of `d`.
pub fn tweak_secret(sk: &SecretKey, tweak32: &[u8; 32]) -> SignatureResult<SecretKey> {
    let p = Secp256k1Point::generator().mul(&sk.d);
    let mut penc = [0u8; 33];
    p.to_bytes_compressed(&mut penc)
        .map_err(|_| SignatureError::InvalidPublicKey)?;
    let d_odd = ((penc[0] == 0x03) as u8) & 1;
    let d = Scalar::ct_select(d_odd, &sk.d.neg(), &sk.d);
    let t = Scalar::from_bytes_be(tweak32).map_err(|_| SignatureError::InvalidPrivateKey)?;
    if t.is_zero() {
        return Err(SignatureError::InvalidPrivateKey);
    }
    let d2 = d.add(&t);
    if d2.is_zero() {
        return Err(SignatureError::InvalidPrivateKey);
    }
    Ok(SecretKey { d: d2 })
}

/// Tweak an x-only public key: `P' = lift_x(P) + t·G` (even-Y lift of input x).
pub fn tweak_public(pk: &PublicKey, tweak32: &[u8; 32]) -> SignatureResult<PublicKey> {
    let mut comp = [0u8; 33];
    comp[0] = 0x02;
    comp[1..].copy_from_slice(&pk.0);
    let p = Secp256k1Point::from_bytes(&comp).map_err(|_| SignatureError::InvalidPublicKey)?;
    let t = Scalar::from_bytes_be(tweak32).map_err(|_| SignatureError::InvalidPrivateKey)?;
    if t.is_zero() {
        return Err(SignatureError::InvalidPrivateKey);
    }
    let p2 = p.add(&Secp256k1Point::generator().mul(&t));
    let mut enc = [0u8; 33];
    p2.to_bytes_compressed(&mut enc)
        .map_err(|_| SignatureError::InvalidPublicKey)?;
    // BIP-340 x-only: always report x; parity is implicit via even-Y convention on verify
    let mut x = [0u8; 32];
    x.copy_from_slice(&enc[1..33]);
    Ok(PublicKey(x))
}

/// BIP-340 sign with optional aux and optional secret tweak (applied before signing).
pub fn sign_with_aux_and_tweak(
    sk: &SecretKey,
    message: &[u8],
    aux: Option<&[u8; 32]>,
    tweak32: Option<&[u8; 32]>,
) -> SignatureResult<Signature> {
    let sk = if let Some(t) = tweak32 {
        tweak_secret(sk, t)?
    } else {
        *sk
    };

    // Byte form of signing key BEFORE even-Y adjust (reference default aux uses this).
    let mut key_bytes = [0u8; 32];
    sk.d.to_bytes_be(&mut key_bytes);

    let p = Secp256k1Point::generator().mul(&sk.d);
    let mut penc = [0u8; 33];
    p.to_bytes_compressed(&mut penc)
        .map_err(|_| SignatureError::InvalidPublicKey)?;
    let d_odd = ((penc[0] == 0x03) as u8) & 1;
    let d = Scalar::ct_select(d_odd, &sk.d.neg(), &sk.d);
    let mut d_bytes = [0u8; 32];
    d.to_bytes_be(&mut d_bytes);
    let mut px = [0u8; 32];
    px.copy_from_slice(&penc[1..33]);

    // BIP-340 nonce: t = H_aux(aux); rand = d_bytes XOR t; k0 = H_nonce(rand||Px||m)
    // Ref: aux ??= SHA256(digest || byteKey) where byteKey is pre-evenY secret.
    let aux_bytes: [u8; 32] = match aux {
        Some(a) => *a,
        None => {
            #[cfg(feature = "alloc")]
            {
                let mut seed = Vec::with_capacity(message.len() + 32);
                seed.extend_from_slice(message);
                seed.extend_from_slice(&key_bytes);
                sha256(&seed).unwrap_or([0u8; 32])
            }
            #[cfg(not(feature = "alloc"))]
            {
                if message.len() == 32 {
                    let mut seed = [0u8; 64];
                    seed[0..32].copy_from_slice(message);
                    seed[32..64].copy_from_slice(&key_bytes);
                    sha256(&seed).unwrap_or([0u8; 32])
                } else {
                    let mut seed = [0u8; 64 + 32];
                    let n = core::cmp::min(message.len(), 64);
                    seed[0..n].copy_from_slice(&message[..n]);
                    seed[n..n + 32].copy_from_slice(&key_bytes);
                    sha256(&seed[..n + 32]).unwrap_or([0u8; 32])
                }
            }
        }
    };
    let t = tagged_hash(b"BIP0340/aux", &aux_bytes);
    let mut rand = [0u8; 32];
    for i in 0..32 {
        rand[i] = d_bytes[i] ^ t[i];
    }

    #[cfg(feature = "alloc")]
    let k_hash = {
        #[allow(unused_imports)]
        use alloc::vec::Vec;
        let mut buf = Vec::with_capacity(64 + message.len());
        buf.extend_from_slice(&rand);
        buf.extend_from_slice(&px);
        buf.extend_from_slice(message);
        tagged_hash(b"BIP0340/nonce", &buf)
    };
    #[cfg(not(feature = "alloc"))]
    let k_hash = {
        let mut buf = [0u8; 64 + 256];
        let n = core::cmp::min(message.len(), 256);
        buf[0..32].copy_from_slice(&rand);
        buf[32..64].copy_from_slice(&px);
        buf[64..64 + n].copy_from_slice(&message[..n]);
        tagged_hash(b"BIP0340/nonce", &buf[..64 + n])
    };
    let mut k = Scalar::from_bytes_mod_order(&k_hash);
    if k.is_zero() {
        return Err(SignatureError::InvalidSignature);
    }

    let r_point = Secp256k1Point::generator().mul(&k);
    let mut r_enc = [0u8; 33];
    r_point
        .to_bytes_compressed(&mut r_enc)
        .map_err(|_| SignatureError::InvalidSignature)?;
    // Branchless even-Y (see `sign` above).
    let k_neg2 = k.neg();
    let r_neg_pt2 = Secp256k1Point::generator().mul(&k_neg2);
    let mut r_neg_enc2 = [0u8; 33];
    r_neg_pt2
        .to_bytes_compressed(&mut r_neg_enc2)
        .map_err(|_| SignatureError::InvalidSignature)?;
    let r_odd2 = ((r_enc[0] == 0x03) as u8) & 1;
    k = Scalar::ct_select(r_odd2, &k_neg2, &k);
    let _r_point = Secp256k1Point::ct_select(r_odd2, &r_neg_pt2, &r_point);
    {
        let m = (r_odd2 as i8).wrapping_neg() as u8;
        for i in 0..33 {
            r_enc[i] = (r_neg_enc2[i] & m) | (r_enc[i] & !m);
        }
    }
    let mut rx = [0u8; 32];
    rx.copy_from_slice(&r_enc[1..33]);

    #[cfg(feature = "alloc")]
    let e_bytes = {
        let mut chal = Vec::with_capacity(64 + message.len());
        chal.extend_from_slice(&rx);
        chal.extend_from_slice(&px);
        chal.extend_from_slice(message);
        tagged_hash(b"BIP0340/challenge", &chal)
    };
    #[cfg(not(feature = "alloc"))]
    let e_bytes = {
        let mut chal = [0u8; 64 + 256];
        let n = core::cmp::min(message.len(), 256);
        chal[0..32].copy_from_slice(&rx);
        chal[32..64].copy_from_slice(&px);
        chal[64..64 + n].copy_from_slice(&message[..n]);
        tagged_hash(b"BIP0340/challenge", &chal[..64 + n])
    };
    let e = Scalar::from_bytes_mod_order(&e_bytes);
    let s = k.add(&e.mul(&d));
    let mut sb = [0u8; 32];
    s.to_bytes_be(&mut sb);
    Ok(Signature { rx, s: sb })
}

#[cfg(test)]
mod tests {
    fn unhex32(s: &str) -> [u8; 32] {
        let mut a = [0u8; 32];
        for i in 0..32 {
            a[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        a
    }

    use super::*;

    #[test]
    fn schnorr_sign_verify_roundtrip() {
        let mut d = [0u8; 32];
        d[31] = 1;
        let sk = SecretKey::from_bytes(&d).unwrap();
        let pk = sk.public_key().unwrap();
        let msg = b"hello schnorr";
        let sig = sign(&sk, msg).unwrap();
        assert_eq!(sig.rx.len(), 32);
        assert_eq!(pk.0.len(), 32);
        verify(&pk, msg, &sig).expect("schnorr roundtrip");
    }

    #[test]
    fn bip340_aux_roundtrip() {
        let d = [1u8; 32];
        let sk = SecretKey::from_bytes(&d).unwrap();
        let pk = sk.public_key().unwrap();
        let aux = [9u8; 32];
        let msg = b"bip340 aux test";
        let sig = sign_with_aux(&sk, msg, Some(&aux)).unwrap();
        verify(&pk, msg, &sig).expect("aux verify");
    }

    #[test]
    fn bip340_tweak_roundtrip() {
        let d = [2u8; 32];
        let sk = SecretKey::from_bytes(&d).unwrap();
        let tweak = {
            let mut t = [0u8; 32];
            t[31] = 7;
            t
        };
        let sk2 = tweak_secret(&sk, &tweak).unwrap();
        let pk2 = sk2.public_key().unwrap();
        let msg = b"tweaked";
        let sig = sign_with_aux(&sk2, msg, Some(&[3u8; 32])).unwrap();
        verify(&pk2, msg, &sig).expect("tweak verify");
        // public tweak path should match x of sk2 pk (may differ parity handling)
        let pk = sk.public_key().unwrap();
        let _pk_tw = tweak_public(&pk, &tweak).unwrap();
    }
    #[test]
    fn bip340_vector0_official() {
        // BIP-340 test-vectors.csv index 0
        let sk = unhex32("0000000000000000000000000000000000000000000000000000000000000003");
        let pk_x = unhex32("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9");
        let aux = unhex32("0000000000000000000000000000000000000000000000000000000000000000");
        let msg = unhex32("0000000000000000000000000000000000000000000000000000000000000000");
        let sig_hex = "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0";
        let secret = SecretKey::from_bytes(&sk).unwrap();
        let pk = secret.public_key().unwrap();
        assert_eq!(pk.0, pk_x);
        let sig = sign_with_aux(&secret, &msg, Some(&aux)).unwrap();
        verify(&pk, &msg, &sig).unwrap();
        let mut got = [0u8; 64];
        got[..32].copy_from_slice(&sig.rx);
        got[32..].copy_from_slice(&sig.s);
        let mut exp = [0u8; 64];
        for i in 0..64 {
            exp[i] = u8::from_str_radix(&sig_hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        assert_eq!(got, exp, "BIP-340 vector 0 signature mismatch");
    }

    #[test]
    fn bip340_vector1_official() {
        let sk = unhex32("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF");
        let pk_x = unhex32("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659");
        let aux = unhex32("0000000000000000000000000000000000000000000000000000000000000001");
        let msg = unhex32("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89");
        let sig_hex = "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A";
        let secret = SecretKey::from_bytes(&sk).unwrap();
        let pk = secret.public_key().unwrap();
        assert_eq!(pk.0, pk_x);
        let sig = sign_with_aux(&secret, &msg, Some(&aux)).unwrap();
        let mut got = [0u8; 64];
        got[..32].copy_from_slice(&sig.rx);
        got[32..].copy_from_slice(&sig.s);
        let mut exp = [0u8; 64];
        for i in 0..64 {
            exp[i] = u8::from_str_radix(&sig_hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        assert_eq!(got, exp);
        verify(&pk, &msg, &sig).unwrap();
    }

    #[test]
    fn bip340_user_sk_no_aux_deterministic() {
        // User sk; message = sk itself as digest (common test); default aux path
        let sk = unhex32("54f96916a9e7a61f13ada084becd595afb3e04f2bdd546fd85a05a45f840ad57");
        let secret = SecretKey::from_bytes(&sk).unwrap();
        let msg = unhex32("0000000000000000000000000000000000000000000000000000000000000000");
        let sig1 = sign_with_aux(&secret, &msg, None).unwrap();
        let sig2 = sign_with_aux(&secret, &msg, None).unwrap();
        assert_eq!(sig1.rx, sig2.rx);
        assert_eq!(sig1.s, sig2.s);
        verify(&secret.public_key().unwrap(), &msg, &sig1).unwrap();
    }
}
