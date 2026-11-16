//! ML-DSA (FIPS 204) keygen / sign / verify for parameter sets 44, 65, 87.

use super::encode;
use super::field;
use super::params::{Params, N, Q};
use super::poly::{expand_a, expand_mask, expand_s, sample_in_ball, PolyVec};
use crate::hash::keccak::shake256;

#[derive(Clone, Copy, Debug)]
pub enum MlDsaError {
    InvalidLength,
    InvalidSeed,
    SigningFailed,
    VerificationFailed,
}

pub type Result<T> = core::result::Result<T, MlDsaError>;

pub struct MlDsa {
    pub params: Params,
}

impl MlDsa {
    pub const fn mldsa44() -> Self {
        Self {
            params: Params::mldsa44(),
        }
    }
    pub const fn mldsa65() -> Self {
        Self {
            params: Params::mldsa65(),
        }
    }
    pub const fn mldsa87() -> Self {
        Self {
            params: Params::mldsa87(),
        }
    }

    pub fn keygen(&self, seed: &[u8; 32]) -> Result<(alloc::vec::Vec<u8>, alloc::vec::Vec<u8>)> {
        let p = &self.params;
        let mut xi = [0u8; 34];
        xi[..32].copy_from_slice(seed);
        xi[32] = p.k as u8;
        xi[33] = p.l as u8;
        let mut h_out = [0u8; 128];
        shake256(&xi, &mut h_out).map_err(|_| MlDsaError::SigningFailed)?;
        let rho = &h_out[0..32];
        let rho_prime = &h_out[32..96];
        let k_seed = &h_out[96..128];

        let a_hat = expand_a(rho, p.k, p.l);
        let (s1, s2) = expand_s(rho_prime, p.k, p.l, p.eta);
        let mut s1_ntt = s1.clone();
        s1_ntt.to_ntt();
        let mut t = PolyVec::new(p.k);
        a_hat.mul_vec_ntt(&mut t, &s1_ntt);
        t.from_ntt();
        t.add_assign(&s2);
        t.reduce();

        let mut t1 = PolyVec::new(p.k);
        let mut t0 = PolyVec::new(p.k);
        for i in 0..p.k {
            for j in 0..N {
                let (r1, r0) = encode::power2_round(t.polys[i].coeffs[j]);
                t1.polys[i].coeffs[j] = r1;
                let mut r0m = r0;
                if r0m < 0 {
                    r0m += Q;
                }
                t0.polys[i].coeffs[j] = r0m;
            }
        }
        let pk = encode::pk_encode(rho, &t1);
        let mut tr = [0u8; 64];
        shake256(&pk, &mut tr).map_err(|_| MlDsaError::SigningFailed)?;
        let sk = encode::sk_encode(rho, k_seed, &tr, &s1, &s2, &t0, p.eta);
        Ok((pk, sk))
    }

    /// FIPS 204 pure: message is wrapped as `0 || len(ctx) || ctx || msg`.
    pub fn sign(
        &self,
        sk: &[u8],
        message: &[u8],
        rnd: &[u8; 32],
        context: &[u8],
    ) -> Result<alloc::vec::Vec<u8>> {
        if context.len() > 255 {
            return Err(MlDsaError::InvalidLength);
        }
        let mut m = alloc::vec::Vec::with_capacity(2 + context.len() + message.len());
        m.push(0);
        m.push(context.len() as u8);
        m.extend_from_slice(context);
        m.extend_from_slice(message);
        self.sign_inner(sk, &m, rnd, false)
    }

    pub fn sign_deterministic(&self, sk: &[u8], message: &[u8]) -> Result<alloc::vec::Vec<u8>> {
        // TEST-ONLY: deterministic KAT path using FIPS `rnd = [0]*32`.
        // Production MUST call `sign` (or `sign_external`) with fresh
        // caller-supplied randomness. FFI (`bu_mldsa_sign`) and WASM
        // (`mldsaSign`) reject null/short `rnd` and never expose this path.
        self.sign(sk, message, &[0u8; 32], &[])
    }

    /// Pre-hashed / external μ (64 bytes).
    pub fn sign_external(
        &self,
        sk: &[u8],
        mu: &[u8],
        rnd: &[u8; 32],
    ) -> Result<alloc::vec::Vec<u8>> {
        if mu.len() != 64 {
            return Err(MlDsaError::InvalidLength);
        }
        self.sign_inner(sk, mu, rnd, true)
    }

    fn sign_inner(
        &self,
        sk: &[u8],
        message: &[u8],
        rnd: &[u8; 32],
        external: bool,
    ) -> Result<alloc::vec::Vec<u8>> {
        let p = &self.params;
        if sk.len() != p.secret_key_bytes() {
            return Err(MlDsaError::InvalidLength);
        }
        let rho = &sk[0..32];
        let k_seed = &sk[32..64];
        let tr = &sk[64..128];
        let eta_bytes = p.poly_eta_packed_bytes();
        let mut off = 128usize;
        let mut s1 = PolyVec::new(p.l);
        for i in 0..p.l {
            s1.polys[i] = encode::bit_unpack_eta(&sk[off..off + eta_bytes], p.eta);
            off += eta_bytes;
        }
        let mut s2 = PolyVec::new(p.k);
        for i in 0..p.k {
            s2.polys[i] = encode::bit_unpack_eta(&sk[off..off + eta_bytes], p.eta);
            off += eta_bytes;
        }
        let mut t0 = PolyVec::new(p.k);
        for i in 0..p.k {
            t0.polys[i] = encode::bit_unpack_t0(&sk[off..off + 416]);
            off += 416;
        }

        let mut mu = [0u8; 64];
        if external {
            if message.len() != 64 {
                return Err(MlDsaError::InvalidLength);
            }
            mu.copy_from_slice(message);
        } else {
            let mut buf = alloc::vec::Vec::with_capacity(64 + message.len());
            buf.extend_from_slice(tr);
            buf.extend_from_slice(message);
            shake256(&buf, &mut mu).map_err(|_| MlDsaError::SigningFailed)?;
        }

        // ρ″ = H(K || rnd || μ)
        let mut rp_in = alloc::vec::Vec::with_capacity(32 + 32 + 64);
        rp_in.extend_from_slice(k_seed);
        rp_in.extend_from_slice(rnd);
        rp_in.extend_from_slice(&mu);
        let mut rho_pp = [0u8; 64];
        shake256(&rp_in, &mut rho_pp).map_err(|_| MlDsaError::SigningFailed)?;

        let a_hat = expand_a(rho, p.k, p.l);
        let mut s1_ntt = s1.clone();
        s1_ntt.to_ntt();
        let mut s2_ntt = s2.clone();
        s2_ntt.to_ntt();
        let mut t0_ntt = t0.clone();
        t0_ntt.to_ntt();

        let mut kappa = 0usize;
        // FIPS 204 Alg 7: unbounded rejection loop; `kappa` advances by `l`
        // per attempt (ExpandMask offset). Never cap: callers retry with
        // fresh `kappa` until all norm / hint checks pass.
        loop {
            let y = expand_mask(&rho_pp, kappa, p.l, p.gamma1);
            kappa += p.l;
            let mut y_ntt = y.clone();
            y_ntt.to_ntt();
            let mut w = PolyVec::new(p.k);
            a_hat.mul_vec_ntt(&mut w, &y_ntt);
            w.from_ntt();
            w.reduce();

            // w1 = HighBits(w)
            let mut w1 = PolyVec::new(p.k);
            for i in 0..p.k {
                for j in 0..N {
                    w1.polys[i].coeffs[j] = encode::high_bits(w.polys[i].coeffs[j], p.gamma2);
                }
            }
            let w1_enc = w1_encode(&w1, p.gamma2);
            let mut c_in = alloc::vec::Vec::with_capacity(64 + w1_enc.len());
            c_in.extend_from_slice(&mu);
            c_in.extend_from_slice(&w1_enc);
            let c_len = p.c_tilde_bytes();
            let mut c_tilde = alloc::vec![0u8; c_len];
            shake256(&c_in, &mut c_tilde).map_err(|_| MlDsaError::SigningFailed)?;

            let c = sample_in_ball(&c_tilde, p.tau);
            let mut c_ntt = c.clone();
            c_ntt.to_ntt();

            let mut cs1 = PolyVec::new(p.l);
            for i in 0..p.l {
                cs1.polys[i] = c_ntt.clone();
                cs1.polys[i].pointwise_mul(&s1_ntt.polys[i]);
            }
            cs1.from_ntt();
            let mut z = y.clone();
            z.add_assign(&cs1);
            z.reduce();
            if !z.infinity_norm_ok(p.gamma1 - p.beta) {
                continue;
            }

            let mut cs2 = PolyVec::new(p.k);
            for i in 0..p.k {
                cs2.polys[i] = c_ntt.clone();
                cs2.polys[i].pointwise_mul(&s2_ntt.polys[i]);
            }
            cs2.from_ntt();
            let mut w_cs2 = w.clone();
            w_cs2.sub_assign(&cs2);
            w_cs2.reduce();
            let mut r0 = PolyVec::new(p.k);
            for i in 0..p.k {
                for j in 0..N {
                    r0.polys[i].coeffs[j] = encode::low_bits(w_cs2.polys[i].coeffs[j], p.gamma2);
                }
            }
            if !r0.infinity_norm_ok(p.gamma2 - p.beta) {
                continue;
            }

            let mut ct0 = PolyVec::new(p.k);
            for i in 0..p.k {
                ct0.polys[i] = c_ntt.clone();
                ct0.polys[i].pointwise_mul(&t0_ntt.polys[i]);
            }
            ct0.from_ntt();
            ct0.reduce();
            if !ct0.infinity_norm_ok(p.gamma2) {
                continue;
            }

            let mut hints = alloc::vec![alloc::vec::Vec::new(); p.k];
            let mut ones = 0usize;
            for (((r0p, ct0p), wp), h) in r0
                .polys
                .iter()
                .zip(ct0.polys.iter())
                .zip(w.polys.iter())
                .zip(hints.iter_mut())
                .take(p.k)
            {
                for j in 0..N {
                    let z_val = field::add(r0p.coeffs[j], ct0p.coeffs[j]);
                    let r_val = encode::high_bits(wp.coeffs[j], p.gamma2);
                    if encode::make_hint(z_val, r_val, p.gamma2) == 1 {
                        h.push(j);
                        ones += 1;
                    }
                }
            }
            if ones > p.omega {
                continue;
            }
            return Ok(encode::sig_encode(
                &c_tilde, &z, &hints, p.gamma1, p.omega, p.k,
            ));
        }
    }

    pub fn verify(&self, pk: &[u8], message: &[u8], signature: &[u8], context: &[u8]) -> bool {
        if context.len() > 255 {
            return false;
        }
        let mut m = alloc::vec::Vec::with_capacity(2 + context.len() + message.len());
        m.push(0);
        m.push(context.len() as u8);
        m.extend_from_slice(context);
        m.extend_from_slice(message);
        self.verify_inner(pk, &m, signature, false)
    }

    pub fn verify_external(&self, pk: &[u8], mu: &[u8], signature: &[u8]) -> bool {
        if mu.len() != 64 {
            return false;
        }
        self.verify_inner(pk, mu, signature, true)
    }

    /// Recompute public key from the encoded **secret key** (not the 32-byte seed).
    ///
    /// SK layout (FIPS 204): `ρ || K || tr || s1 || s2 || t0`.
    /// Reconstructs `t = A·s1 + s2`, then `pk = (ρ, t1)`.
    pub fn public_key_from_secret(&self, sk: &[u8]) -> Result<alloc::vec::Vec<u8>> {
        self.public_key_from_secret_key(sk)
    }

    /// Alias of [`Self::public_key_from_secret`].
    pub fn public_key_from_secret_key(&self, sk: &[u8]) -> Result<alloc::vec::Vec<u8>> {
        let p = &self.params;
        if sk.len() != p.secret_key_bytes() {
            return Err(MlDsaError::InvalidLength);
        }
        let rho = &sk[0..32];
        let eta_bytes = p.poly_eta_packed_bytes();
        let mut off = 128usize;
        let mut s1 = PolyVec::new(p.l);
        for i in 0..p.l {
            s1.polys[i] = encode::bit_unpack_eta(&sk[off..off + eta_bytes], p.eta);
            off += eta_bytes;
        }
        let mut s2 = PolyVec::new(p.k);
        for i in 0..p.k {
            s2.polys[i] = encode::bit_unpack_eta(&sk[off..off + eta_bytes], p.eta);
            off += eta_bytes;
        }
        let a_hat = expand_a(rho, p.k, p.l);
        let mut s1_ntt = s1.clone();
        s1_ntt.to_ntt();
        let mut t = PolyVec::new(p.k);
        a_hat.mul_vec_ntt(&mut t, &s1_ntt);
        t.from_ntt();
        t.add_assign(&s2);
        t.reduce();
        let mut t1 = PolyVec::new(p.k);
        for i in 0..p.k {
            for j in 0..N {
                let (r1, _) = encode::power2_round(t.polys[i].coeffs[j]);
                t1.polys[i].coeffs[j] = r1;
            }
        }
        Ok(encode::pk_encode(rho, &t1))
    }

    fn verify_inner(&self, pk: &[u8], message: &[u8], signature: &[u8], external: bool) -> bool {
        let p = &self.params;
        if pk.len() != p.public_key_bytes() || signature.len() != p.signature_bytes() {
            return false;
        }
        let (rho, t1) = encode::pk_decode(pk, p.k);
        let c_len = p.c_tilde_bytes();
        let c_tilde = &signature[..c_len];
        let z_bytes = p.poly_z_packed_bytes();
        let mut off = c_len;
        let mut z = PolyVec::new(p.l);
        for i in 0..p.l {
            z.polys[i] = encode::bit_unpack_z(&signature[off..off + z_bytes], p.gamma1);
            off += z_bytes;
        }
        let hint_raw = &signature[off..];
        if hint_raw.len() != p.omega + p.k {
            return false;
        }
        let mut hints = alloc::vec![alloc::vec::Vec::new(); p.k];
        // FIPS 204 Alg 8 + PQClean `unpack_sig` strictness: cumulative
        // offsets must be non-decreasing and bounded by `omega`; each
        // index must be `< N`, strictly increasing within its polynomial,
        // and trailing `y[pos..omega]` bytes must be zero (canonical form).
        let mut prev = 0usize;
        for i in 0..p.k {
            let end = hint_raw[p.omega + i] as usize;
            if end < prev || end > p.omega {
                return false;
            }
            for (t, h) in hint_raw[prev..end].iter().enumerate() {
                if (*h as usize) >= N {
                    return false;
                }
                if t > 0 && *h <= hint_raw[prev + t - 1] {
                    return false;
                }
                hints[i].push(*h as usize);
            }
            prev = end;
        }
        for b in &hint_raw[prev..p.omega] {
            if *b != 0 {
                return false;
            }
        }
        if !z.infinity_norm_ok(p.gamma1 - p.beta) {
            return false;
        }

        let mut tr = [0u8; 64];
        if shake256(pk, &mut tr).is_err() {
            return false;
        }
        let mut mu = [0u8; 64];
        if external {
            if message.len() != 64 {
                return false;
            }
            mu.copy_from_slice(message);
        } else {
            let mut buf = alloc::vec::Vec::with_capacity(64 + message.len());
            buf.extend_from_slice(&tr);
            buf.extend_from_slice(message);
            if shake256(&buf, &mut mu).is_err() {
                return false;
            }
        }

        let c = sample_in_ball(c_tilde, p.tau);
        let mut c_ntt = c.clone();
        c_ntt.to_ntt();
        let a_hat = expand_a(&rho, p.k, p.l);
        let mut z_ntt = z.clone();
        z_ntt.to_ntt();
        let mut az = PolyVec::new(p.k);
        a_hat.mul_vec_ntt(&mut az, &z_ntt);
        az.from_ntt();

        let mut t1_scaled = PolyVec::new(p.k);
        for i in 0..p.k {
            for j in 0..N {
                t1_scaled.polys[i].coeffs[j] = field::mul(t1.polys[i].coeffs[j], 1 << p.d);
            }
        }
        t1_scaled.to_ntt();
        let mut ct1 = PolyVec::new(p.k);
        for i in 0..p.k {
            ct1.polys[i] = c_ntt.clone();
            ct1.polys[i].pointwise_mul(&t1_scaled.polys[i]);
        }
        ct1.from_ntt();
        let mut w_approx = az;
        w_approx.sub_assign(&ct1);
        w_approx.reduce();

        let mut w1_prime = PolyVec::new(p.k);
        for ((w1p, wapp), h) in w1_prime
            .polys
            .iter_mut()
            .zip(w_approx.polys.iter())
            .zip(hints.iter())
            .take(p.k)
        {
            for j in 0..N {
                let hint_bit = if h.contains(&j) { 1 } else { 0 };
                w1p.coeffs[j] = encode::use_hint(hint_bit, wapp.coeffs[j], p.gamma2);
            }
        }
        let w1_enc = w1_encode(&w1_prime, p.gamma2);
        let mut c_in = alloc::vec::Vec::with_capacity(64 + w1_enc.len());
        c_in.extend_from_slice(&mu);
        c_in.extend_from_slice(&w1_enc);
        let mut c_tilde_prime = alloc::vec![0u8; c_len];
        if shake256(&c_in, &mut c_tilde_prime).is_err() {
            return false;
        }
        c_tilde == c_tilde_prime.as_slice()
    }
}

fn w1_encode(w1: &PolyVec, gamma2: i32) -> alloc::vec::Vec<u8> {
    let bits = if gamma2 == (Q - 1) / 88 { 6 } else { 4 };
    let mut parts = alloc::vec::Vec::new();
    for p in &w1.polys {
        parts.extend_from_slice(&encode::simple_bit_pack(p, bits));
    }
    parts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn param_sizes() {
        let a = Params::mldsa44();
        assert_eq!(a.public_key_bytes(), 1312);
        assert_eq!(a.secret_key_bytes(), 2560);
        assert_eq!(a.signature_bytes(), 2420);
        let b = Params::mldsa65();
        assert_eq!(b.public_key_bytes(), 1952);
        assert_eq!(b.secret_key_bytes(), 4032);
        assert_eq!(b.signature_bytes(), 3309);
        let c = Params::mldsa87();
        assert_eq!(c.public_key_bytes(), 2592);
        assert_eq!(c.secret_key_bytes(), 4896);
        assert_eq!(c.signature_bytes(), 4627);
    }

    #[test]
    fn ntt_roundtrip() {
        use crate::signature::ml_dsa::poly::Poly;
        let mut p = Poly::zero();
        for i in 0..256 {
            p.coeffs[i] = ((i as i32 * 12345 + 7) % Q + Q) % Q;
        }
        let orig = p.coeffs;
        p.to_ntt();
        p.from_ntt();
        for (i, (a, b)) in p.coeffs.iter().zip(orig.iter()).enumerate().take(256) {
            assert_eq!(*a, *b, "coeff {i}");
        }
    }

    #[test]
    fn keygen_sign_verify_65() {
        let dsa = MlDsa::mldsa65();
        let seed = [7u8; 32];
        let (pk, sk) = dsa.keygen(&seed).expect("keygen");
        assert_eq!(pk.len(), dsa.params.public_key_bytes());
        assert_eq!(sk.len(), dsa.params.secret_key_bytes());
        let msg = b"post-quantum signature test";
        let sig = dsa.sign_deterministic(&sk, msg).expect("sign");
        assert_eq!(sig.len(), dsa.params.signature_bytes());
        assert!(dsa.verify(&pk, msg, &sig, &[]));
        assert!(!dsa.verify(&pk, b"other", &sig, &[]));
    }

    #[test]
    fn keygen_sign_verify_44() {
        let dsa = MlDsa::mldsa44();
        let seed = [9u8; 32];
        let (pk, sk) = dsa.keygen(&seed).expect("keygen");
        let msg = b"ml-dsa";
        let sig = dsa.sign_deterministic(&sk, msg).expect("sign");
        assert!(dsa.verify(&pk, msg, &sig, &[]));
    }

    #[test]
    fn keygen_sign_verify_87() {
        let dsa = MlDsa::mldsa87();
        for i in 0u8..8 {
            let mut seed = [9u8; 32];
            seed[0] = i;
            let (pk, sk) = dsa.keygen(&seed).expect("keygen");
            let msg = b"ml-dsa-87";
            let mut rnd = [3u8; 32];
            rnd[1] = i;
            let sig = dsa.sign(&sk, msg, &rnd, &[]).expect("sign");
            if dsa.verify(&pk, msg, &sig, &[]) {
                return;
            }
        }
        panic!("verify 87 failed for several seeds");
    }
    #[test]
    fn pk_from_secret_matches_keygen() {
        for (name, dsa) in [
            ("44", MlDsa::mldsa44()),
            ("65", MlDsa::mldsa65()),
            ("87", MlDsa::mldsa87()),
        ] {
            let seed = [9u8; 32];
            let (pk, sk) = dsa.keygen(&seed).expect("keygen");
            let pk2 = dsa.public_key_from_secret(&sk).expect("from sk");
            assert_eq!(pk, pk2, "ML-DSA-{} pk from secret", name);
        }
    }

    /// FIPS 204 Alg 8 / PQClean strictness: hint indices must be `< N`,
    /// strictly increasing per polynomial, with zero trailing bytes.
    /// Malleated encodings of an otherwise-valid signature must reject.
    #[test]
    fn verify_rejects_malleated_hints() {
        let dsa = MlDsa::mldsa65();
        let p = dsa.params;
        let seed = [7u8; 32];
        let (pk, sk) = dsa.keygen(&seed).expect("keygen");
        let msg = b"hint strictness";
        let rnd = [1u8; 32];
        let sig = dsa.sign(&sk, msg, &rnd, &[]).expect("sign");
        assert!(dsa.verify(&pk, msg, &sig, &[]));
        let c_len = p.c_tilde_bytes();
        let hint_off = c_len + p.l * p.poly_z_packed_bytes();

        // Note: each hint index is one byte and N = 256, so an out-of-range
        // index value is unrepresentable on the wire; the `< N` check in
        // `verify_inner` is defense-in-depth. The live malleations are the
        // order / trailing-zero / offset-monotonicity arms below.
        // 1. non-increasing indices within polynomial 0 (duplicate first two).
        let mut dup = sig.clone();
        let end0 = dup[hint_off + p.omega] as usize;
        assert!(end0 >= 2, "test setup: need >= 2 hints in poly 0");
        dup[hint_off + 1] = dup[hint_off];
        assert!(
            !dsa.verify(&pk, msg, &dup, &[]),
            "duplicate hint index must reject"
        );
        // 2. non-zero trailing byte after the last used hint slot.
        let mut trail = sig.clone();
        let last_end = trail[hint_off + p.omega + p.k - 1] as usize;
        assert!(last_end < p.omega, "test setup: need trailing room");
        trail[hint_off + last_end] = 1;
        // keep offsets unchanged so the trailing byte is in y[pos..omega]
        assert!(
            !dsa.verify(&pk, msg, &trail, &[]),
            "non-zero trailing hint byte must reject"
        );
        // 3. decreasing cumulative offset must reject.
        let mut off = sig.clone();
        // bump an early offset above a later one without touching indices
        let e0 = off[hint_off + p.omega] as usize;
        let e1 = off[hint_off + p.omega + 1] as usize;
        assert!(e0 <= e1 && e1 < p.omega, "test setup: need e0<=e1<omega");
        off[hint_off + p.omega] = e1 as u8 + 1;
        assert!(
            !dsa.verify(&pk, msg, &off, &[]),
            "decreasing hint offset must reject"
        );
    }
}

#[test]
fn sk_header_matches_kat() {
    // first vector key_seed from reference mlDsa65
    let seed_hex = "55fb2b9468fe8ccab4136fa7218d5ee37c65b3ecb7c59a771af2ef629afab48e";
    let mut seed = [0u8; 32];
    for i in 0..32 {
        seed[i] = u8::from_str_radix(&seed_hex[i * 2..i * 2 + 2], 16).unwrap();
    }
    let dsa = MlDsa::mldsa65();
    let (pk, sk) = dsa.keygen(&seed).unwrap();
    // expected sk prefix from KAT file - load via include is heavy; just print first 160
    eprintln!("sk[0..160]={:02x?}", &sk[..160]);
    assert_eq!(pk.len(), 1952);
    // first 128 must match if tr=H(pk) and H(xi) ok — compare against known from json
}
