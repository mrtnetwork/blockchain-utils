//! BCH / “legacy” Schnorr over secp256k1 (not BIP-340).
//!
//! Matches `signSchnorr` / `signSchnorrConst`:
//! - RFC6979 k with default extra entropy ASCII `"Schnorr+SHA256  "`
//! - If `y(R)` is not a quadratic residue mod p, replace `k ← n − k`
//! - `e = SHA256(R.x ‖ compressed_pk ‖ digest)` interpreted as scalar
//! - `s = k + e·d (mod n)`
//! - Signature: `R.x ‖ s` (64 bytes)

use crate::curve::secp256k1::{Fe, Scalar, Secp256k1Point};
use crate::curve::traits::{CurvePoint, FieldElement};
use crate::hash::sha256::sha256;
use crate::signature::ecdsa::{PublicKey as EcdsaPk, SecretKey as EcdsaSk, Signature};
use crate::signature::error::{SignatureError, SignatureResult};
use crate::signature::rfc6979;

/// Default RFC6979 extra data used by Bitcoin Cash Schnorr (`bchSchnorrRfc6979ExtraData`).
pub const BCH_SCHNORR_EXTRA: &[u8] = b"Schnorr+SHA256  ";

/// Legendre symbol (a|p): a^((p-1)/2) mod p ∈ {0,1,p-1}.
fn is_quadratic_residue(y: &Fe) -> bool {
    // (p-1)/2 = 7fff...ffff7ffffe17
    let exp: [u8; 32] = [
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0xff,
        0xfe, 0x17,
    ];
    let base = *y;
    let mut result = Fe::one();
    for byte in exp.iter() {
        for bit in (0..8).rev() {
            result = result.square();
            let bit_set = (byte >> bit) & 1;
            let mulled = result.mul(&base);
            result = Fe::ct_select(bit_set, &mulled, &result);
        }
    }
    // QR iff result == 1
    let mut one = [0u8; 32];
    one[31] = 1;
    let one_fe = Fe::from_bytes_be(&one).unwrap_or(Fe::zero());
    result.ct_eq(&one_fe) == 1
}

fn point_affine_xy(p: &Secp256k1Point) -> SignatureResult<(Fe, Fe)> {
    let mut unc = [0u8; 65];
    CurvePoint::to_bytes_uncompressed(p, &mut unc).map_err(|_| SignatureError::InvalidSignature)?;
    let mut xb = [0u8; 32];
    let mut yb = [0u8; 32];
    xb.copy_from_slice(&unc[1..33]);
    yb.copy_from_slice(&unc[33..65]);
    let x = Fe::from_bytes_be(&xb).map_err(|_| SignatureError::InvalidSignature)?;
    let y = Fe::from_bytes_be(&yb).map_err(|_| SignatureError::InvalidSignature)?;
    Ok((x, y))
}

/// Sign 32-byte digest with BCH-style Schnorr.
///
/// `extra_entropy`: if `None`, uses [`BCH_SCHNORR_EXTRA`].
pub fn sign(
    sk: &EcdsaSk,
    digest32: &[u8; 32],
    extra_entropy: Option<&[u8]>,
) -> SignatureResult<Signature> {
    let mut d_bytes = [0u8; 32];
    sk.to_bytes(&mut d_bytes);
    let extra = extra_entropy.unwrap_or(BCH_SCHNORR_EXTRA);
    let mut k = rfc6979::generate_k_scalar(&d_bytes, digest32, Some(extra))?;

    let mut r_point = Secp256k1Point::generator().mul(&k);
    let (_x, y) = point_affine_xy(&r_point)?;
    // Branchless QR adjust: always compute negated candidate, select via mask
    // (was `if !is_qr { k.neg(); mul }` — 50% extra mul leaked QR/nonce bit).
    let k_neg = k.neg();
    let r_neg_pt = Secp256k1Point::generator().mul(&k_neg);
    let qr = (is_quadratic_residue(&y) as u8) & 1;
    // qr==1 → keep, qr==0 → take negated. ct_select(choice,a,b): 1→a.
    k = Scalar::ct_select(qr, &k, &k_neg);
    r_point = Secp256k1Point::ct_select(qr, &r_point, &r_neg_pt);

    let mut rx = [0u8; 32];
    let mut enc = [0u8; 33];
    CurvePoint::to_bytes_compressed(&r_point, &mut enc)
        .map_err(|_| SignatureError::InvalidSignature)?;
    rx.copy_from_slice(&enc[1..33]);

    let pk = sk.public_key()?;
    let mut pk_bytes = [0u8; 33];
    pk.to_bytes_compressed(&mut pk_bytes)
        .map_err(|_| SignatureError::InvalidPublicKey)?;

    // e = SHA256(R.x || compressed_pk || digest)
    let mut chal = [0u8; 32 + 33 + 32];
    chal[0..32].copy_from_slice(&rx);
    chal[32..65].copy_from_slice(&pk_bytes);
    chal[65..97].copy_from_slice(digest32);
    let e_hash = sha256(&chal).unwrap_or([0u8; 32]);
    // interpret as scalar: if >= n, Scalar::from_bytes_be fails — reduce via try or bits2int style
    let e = match Scalar::from_bytes_be(&e_hash) {
        Ok(s) => s,
        Err(_) => {
            // reduce mod n by subtraction once (e_hash < 2n almost always)
            use crate::curve::secp256k1::scalar::N_BE;
            let mut e2 = e_hash;
            // simple: use from_bytes that reduces if available — else error
            // Prefer: Scalar has no reduce_bytes; subtract N if needed
            if e2.iter().zip(N_BE.iter()).any(|(a, b)| a > b)
                || (e2 == N_BE)
                || e2.iter().zip(N_BE.iter()).fold(true, |eq, (_a, _b)| {
                    if !eq {
                        return false;
                    }
                    true
                })
            {
                // be sub
                let mut borrow = 0i32;
                for i in (0..32).rev() {
                    let t = e2[i] as i32 - N_BE[i] as i32 - borrow;
                    if t < 0 {
                        e2[i] = (t + 256) as u8;
                        borrow = 1;
                    } else {
                        e2[i] = t as u8;
                        borrow = 0;
                    }
                }
            }
            Scalar::from_bytes_be(&e2).unwrap_or(Scalar::zero())
        }
    };

    let d = {
        let mut db = [0u8; 32];
        sk.to_bytes(&mut db);
        Scalar::from_bytes_be(&db).map_err(|_| SignatureError::InvalidPrivateKey)?
    };
    let s = k.add(&e.mul(&d));
    let mut sb = [0u8; 32];
    s.to_bytes_be(&mut sb);
    Ok(Signature { r: rx, s: sb })
}

/// Verify BCH-style Schnorr: check `s·G = R + e·P` with R from r (lift with QR y).
pub fn verify(pk: &EcdsaPk, digest32: &[u8; 32], sig: &Signature) -> SignatureResult<()> {
    let s = Scalar::from_bytes_be(&sig.s).map_err(|_| SignatureError::InvalidSignature)?;
    if s.is_zero() {
        return Err(SignatureError::InvalidSignature);
    }
    // Reconstruct R from r (x) with quadratic residue y
    let mut comp_even = [0u8; 33];
    comp_even[0] = 0x02;
    comp_even[1..].copy_from_slice(&sig.r);
    let mut r_point = <Secp256k1Point as CurvePoint>::from_bytes(&comp_even)
        .map_err(|_| SignatureError::InvalidSignature)?;
    let (_x, y) = point_affine_xy(&r_point)?;
    if !is_quadratic_residue(&y) {
        // try odd y
        comp_even[0] = 0x03;
        r_point = <Secp256k1Point as CurvePoint>::from_bytes(&comp_even)
            .map_err(|_| SignatureError::InvalidSignature)?;
        let (_x2, y2) = point_affine_xy(&r_point)?;
        if !is_quadratic_residue(&y2) {
            return Err(SignatureError::VerificationFailed);
        }
    }

    let mut pk_bytes = [0u8; 33];
    pk.to_bytes_compressed(&mut pk_bytes)
        .map_err(|_| SignatureError::InvalidPublicKey)?;

    let mut chal = [0u8; 32 + 33 + 32];
    chal[0..32].copy_from_slice(&sig.r);
    chal[32..65].copy_from_slice(&pk_bytes);
    chal[65..97].copy_from_slice(digest32);
    let e_hash = sha256(&chal).unwrap_or([0u8; 32]);
    let e = Scalar::from_bytes_be(&e_hash).unwrap_or_else(|_| {
        use crate::curve::secp256k1::scalar::N_BE;
        let mut e2 = e_hash;
        let mut borrow = 0i32;
        for i in (0..32).rev() {
            let t = e2[i] as i32 - N_BE[i] as i32 - borrow;
            if t < 0 {
                e2[i] = (t + 256) as u8;
                borrow = 1;
            } else {
                e2[i] = t as u8;
                borrow = 0;
            }
        }
        Scalar::from_bytes_be(&e2).unwrap_or(Scalar::zero())
    });

    // s·G ?== R + e·P
    let sg = Secp256k1Point::generator().mul(&s);
    let ep = pk.point.mul(&e);
    let rhs = r_point.add(&ep);
    let mut a = [0u8; 33];
    let mut b = [0u8; 33];
    CurvePoint::to_bytes_compressed(&sg, &mut a).map_err(|_| SignatureError::VerificationFailed)?;
    CurvePoint::to_bytes_compressed(&rhs, &mut b)
        .map_err(|_| SignatureError::VerificationFailed)?;
    if a == b {
        Ok(())
    } else {
        Err(SignatureError::VerificationFailed)
    }
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
    fn bch_schnorr_vector1() {
        let sk = unhex32("e16bd99298dc05e07f0f0821947efe10e288c3cf426f465357bec6315328d03b");
        let digest = unhex32("819f570ca2b0d7569c01825b4588434bd728d24cc1cbe6658475d3884865ac88");
        let expected = {
            let mut s = [0u8; 64];
            let hex = "de00f0d9424152d5b0e4417d2b2843f7e5fed3b4e6d29d4189fafefb390ea7ca7a2c0e1d6bdbcff16f14e081d8e22162a46c494d04e32b6ab367f5823dacc320";
            for i in 0..64 {
                s[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
            }
            s
        };
        let secret = EcdsaSk::from_bytes(&sk).unwrap();
        let sig = sign(&secret, &digest, None).unwrap();
        let mut got = [0u8; 64];
        got[..32].copy_from_slice(&sig.r);
        got[32..].copy_from_slice(&sig.s);
        assert_eq!(got, expected);
        let pk = secret.public_key().unwrap();
        verify(&pk, &digest, &sig).unwrap();
    }

    #[test]
    fn bch_schnorr_vector2() {
        let sk = unhex32("e08d8207e60b7a145a38362cac13ff133854cecdfb49c33a48a1ec31ce7f3eff");
        let digest = unhex32("96df91ea13303feb1754f2b1e53a840e5897ea1a9a24756f1ee934eb8570a8d5");
        let expected = {
            let mut s = [0u8; 64];
            let hex = "db4ce4fb0f12a20cd8db1096c1dd6e3884b66250cd7bcc32410afa0a5fcaddbdcda886de225e567f55099606bffbe4d070302ec6ea20f65282ab632cc716c39e";
            for i in 0..64 {
                s[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
            }
            s
        };
        let secret = EcdsaSk::from_bytes(&sk).unwrap();
        let sig = sign(&secret, &digest, None).unwrap();
        let mut got = [0u8; 64];
        got[..32].copy_from_slice(&sig.r);
        got[32..].copy_from_slice(&sig.s);
        assert_eq!(got, expected);
        let pk = secret.public_key().unwrap();
        verify(&pk, &digest, &sig).unwrap();
    }
}
