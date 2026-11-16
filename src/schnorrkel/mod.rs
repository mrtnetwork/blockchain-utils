//! Schnorrkel (sr25519): Schnorr signatures over Ristretto.
//!
//! Independent implementation of the Schnorrkel signing scheme used by
//! Substrate / Polkadot. Construction:
//! - Keys: 32-byte mini-secret → expand (Ed25519-style SHA-512 clamp) → Ristretto scalar
//! - Sign: Merlin transcript + nonce → R = r·B, c = H(transcript||R), s = r + c·k
//! - Verify: R ≟ s·B − c·P
//!
//! Transcript labels follow the public Schnorrkel / Substrate conventions
//! (`SigningContext`, `Schnorr-sig`, `sign:pk`, `sign:R`, `sign:c`).

use crate::curve::ed25519::Scalar;
use crate::curve::error::CurveResult;
use crate::curve::ristretto::RistrettoPoint;
use crate::curve::traits::CurvePoint;
use crate::hash::sha512;
use crate::merlin::Transcript;

/// Mini-secret: 32-byte seed (before expansion).
#[derive(Clone)]
pub struct MiniSecretKey {
    bytes: [u8; 32],
}

/// Expanded secret key: scalar + 32-byte nonce.
#[derive(Clone)]
pub struct SecretKey {
    key: Scalar,
    nonce: [u8; 32],
}

/// Ristretto public key (compressed encoding).
#[derive(Clone, Copy, Debug)]
pub struct PublicKey {
    point: RistrettoPoint,
}

/// Schnorrkel signature: R (32) || s (32).
#[derive(Clone, Copy, Debug)]
pub struct Signature {
    pub r: [u8; 32],
    pub s: [u8; 32],
}

impl MiniSecretKey {
    /// Construct from 32 raw seed bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self { bytes: *bytes }
    }

    /// Expand via SHA-512 + Ed25519 clamp + divide-by-cofactor (matches schnorrkel).
    pub fn expand_ed25519(&self) -> SecretKey {
        let h = sha512(&self.bytes).expect("sha512");
        let mut key_bytes = [0u8; 32];
        let mut nonce = [0u8; 32];
        key_bytes.copy_from_slice(&h[..32]);
        nonce.copy_from_slice(&h[32..]);
        // Ed25519 clamp
        key_bytes[0] &= 248;
        key_bytes[31] &= 63;
        key_bytes[31] |= 64;
        // Schnorrkel: divide clamped scalar by cofactor 8 (byte-wise >> 3 with carry).
        divide_scalar_bytes_by_cofactor(&mut key_bytes);
        let key = Scalar::from_bytes_mod_order(&key_bytes);
        SecretKey { key, nonce }
    }

    /// Expand via Merlin `"ExpandSecretKeys"` (uniform mode).
    pub fn expand_uniform(&self) -> SecretKey {
        let mut t = Transcript::new(b"ExpandSecretKeys");
        t.append_message(b"mini", &self.bytes);
        let mut wide = [0u8; 64];
        t.challenge_bytes(b"sk", &mut wide);
        let key = Scalar::from_bytes_wide(&wide);
        let mut nonce = [0u8; 32];
        t.challenge_bytes(b"no", &mut nonce);
        SecretKey { key, nonce }
    }

    /// Default: Ed25519 expansion.
    pub fn expand(&self) -> SecretKey {
        self.expand_ed25519()
    }
}

impl SecretKey {
    /// Public key P = k · B (Ristretto basepoint).
    pub fn public_key(&self) -> PublicKey {
        let g = RistrettoPoint::generator();
        PublicKey {
            point: g.mul(&self.key),
        }
    }

    /// Raw scalar (for advanced use).
    pub fn scalar(&self) -> &Scalar {
        &self.key
    }

    /// Sign a Merlin transcript.
    ///
    /// Transcript must already contain the application domain (e.g. SigningContext + message).
    ///
    /// `external_nonce` is 64 random bytes reduced mod L as the Schnorr nonce scalar `r`
    /// (matches the reference implementation. Official w3f schnorrkel instead
    /// mixes `self.nonce` via a `signing-nonce` transcript; that path is not used here so
    /// Substrate reference KATs match byte-for-byte.
    pub fn sign(&self, transcript: &mut Transcript, external_nonce: &[u8; 64]) -> Signature {
        let pk = self.public_key();
        let mut pk_bytes = [0u8; 32];
        pk.point.encode(&mut pk_bytes).expect("pk encode");

        transcript.append_message(b"proto-name", b"Schnorr-sig");
        transcript.append_message(b"sign:pk", &pk_bytes);

        // Ref: r = scalarReduceConst(nonce64) = from_bytes_wide
        let r_scalar = Scalar::from_bytes_wide(external_nonce);
        let r_point = RistrettoPoint::generator().mul(&r_scalar);
        let mut r_bytes = [0u8; 32];
        r_point.encode(&mut r_bytes).expect("R encode");

        transcript.append_message(b"sign:R", &r_bytes);
        let c = transcript.challenge_scalar(b"sign:c");

        // s = r + c·k  (reference mulAdd(sk, k, r) = sk·k + r)
        let ck = c.mul(&self.key);
        let s = r_scalar.add(&ck);
        let mut s_bytes = [0u8; 32];
        s.to_bytes_le(&mut s_bytes);

        Signature {
            r: r_bytes,
            s: s_bytes,
        }
    }

    /// Sign raw message under Substrate SigningContext domain `"substrate"`.
    pub fn sign_simple(&self, message: &[u8], external_nonce: &[u8; 64]) -> Signature {
        let mut t = Transcript::new(b"SigningContext");
        t.append_message(b"", b"substrate");
        t.append_message(b"sign-bytes", message);
        self.sign(&mut t, external_nonce)
    }
}

impl PublicKey {
    /// Decode compressed Ristretto public key.
    pub fn from_bytes(bytes: &[u8; 32]) -> CurveResult<Self> {
        let point = RistrettoPoint::decode(bytes)?;
        Ok(Self { point })
    }

    /// Encode compressed form.
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        self.point.encode(&mut out).expect("encode");
        out
    }

    /// Verify signature against transcript (must match signer domain).
    pub fn verify(&self, transcript: &mut Transcript, signature: &Signature) -> bool {
        let mut pk_bytes = [0u8; 32];
        self.point.encode(&mut pk_bytes).expect("pk");

        transcript.append_message(b"proto-name", b"Schnorr-sig");
        transcript.append_message(b"sign:pk", &pk_bytes);
        transcript.append_message(b"sign:R", &signature.r);
        let c = transcript.challenge_scalar(b"sign:c");

        let s = match Scalar::from_bytes_le(&signature.s) {
            Ok(s) => s,
            Err(_) => return false,
        };

        // R' = s·B - c·P = s·B + c·(-P)
        let sb = RistrettoPoint::generator().mul(&s);
        let cp = self.point.mul(&c);
        let r_check = sb.add(&cp.neg());
        let mut r_enc = [0u8; 32];
        if r_check.encode(&mut r_enc).is_err() {
            return false;
        }
        crate::ct::ct_eq(&r_enc, &signature.r) == 1
    }

    /// Verify simple Substrate message signature.
    pub fn verify_simple(&self, message: &[u8], signature: &Signature) -> bool {
        let mut t = Transcript::new(b"SigningContext");
        t.append_message(b"", b"substrate");
        t.append_message(b"sign-bytes", message);
        self.verify(&mut t, signature)
    }
}

impl Signature {
    /// Parse 64-byte signature (schnorrkel: high bit of `s` must be set).
    pub fn from_bytes(bytes: &[u8; 64]) -> Option<Self> {
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&bytes[..32]);
        s.copy_from_slice(&bytes[32..]);
        // Schnorrkel marks signatures by setting bit 255 of s.
        if s[31] & 0x80 == 0 {
            return None;
        }
        s[31] &= 0x7f;
        Some(Self { r, s })
    }

    /// Serialize to 64 bytes (sets high bit of `s` — schnorrkel convention).
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.r);
        out[32..].copy_from_slice(&self.s);
        out[63] |= 0x80;
        out
    }
}

// ---------------------------------------------------------------------------
// HDKD (SchnorrRistrettoHDKD) — Substrate soft/hard derivation
// ---------------------------------------------------------------------------

fn scalar_to_bytes(s: &Scalar) -> [u8; 32] {
    let mut b = [0u8; 32];
    s.to_bytes_le(&mut b);
    b
}

fn scalar_from_canonical(bytes: &[u8; 32]) -> Option<Scalar> {
    Scalar::from_bytes_le(bytes).ok()
}

/// Divide 32-byte little-endian scalar by cofactor 8 (schnorrkel).
fn divide_scalar_bytes_by_cofactor(s: &mut [u8; 32]) {
    let mut low = 0u8;
    for i in (0..32).rev() {
        let r = s[i] & 0x07;
        s[i] >>= 3;
        s[i] = s[i].wrapping_add(low);
        low = r << 5;
    }
}

/// Multiply scalar by cofactor 8 (Ed25519 / Ristretto).
fn mul_by_cofactor_scalar(s: &Scalar) -> Scalar {
    let mut eight = [0u8; 32];
    eight[0] = 8;
    let c = Scalar::from_bytes_mod_order(&eight);
    s.mul(&c)
}

impl SecretKey {
    /// 64-byte expanded secret: scalar ‖ nonce.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&scalar_to_bytes(&self.key));
        out[32..].copy_from_slice(&self.nonce);
        out
    }

    /// From expanded 64-byte secret (scalar ‖ nonce). Scalar must be < L.
    pub fn from_bytes(bytes: &[u8; 64]) -> Option<Self> {
        let mut key_b = [0u8; 32];
        let mut nonce = [0u8; 32];
        key_b.copy_from_slice(&bytes[..32]);
        nonce.copy_from_slice(&bytes[32..]);
        let key = scalar_from_canonical(&key_b)?;
        Some(Self { key, nonce })
    }

    /// Ed25519-compatible encoding: (8·sk) ‖ nonce (`toEd25519Bytes`).
    pub fn to_ed25519_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&scalar_to_bytes(&mul_by_cofactor_scalar(&self.key)));
        out[32..].copy_from_slice(&self.nonce);
        out
    }

    /// Hard derivation (SchnorrRistrettoHDKD / HDKD-hard).
    /// Returns (new expanded secret, new 32-byte chain code).
    pub fn hard_derive(
        &self,
        chain_code: &[u8],
        message: &[u8],
        ed25519_expand: bool,
    ) -> (SecretKey, [u8; 32]) {
        let sk = scalar_to_bytes(&self.key);
        let mut t = Transcript::new(b"SchnorrRistrettoHDKD");
        t.append_message(b"sign-bytes", message);
        t.append_message(b"chain-code", chain_code);
        t.append_message(b"secret-key", &sk);
        let mut new_mini = [0u8; 32];
        t.challenge_bytes(b"HDKD-hard", &mut new_mini);
        let mut new_cc = [0u8; 32];
        t.challenge_bytes(b"HDKD-chaincode", &mut new_cc);
        let mini = MiniSecretKey::from_bytes(&new_mini);
        let sk = if ed25519_expand {
            mini.expand_ed25519()
        } else {
            mini.expand_uniform()
        };
        (sk, new_cc)
    }

    /// Soft derivation: sk' = sk + HDKD-scalar(pk, chain, msg); new random nonce required.
    pub fn soft_derive(
        &self,
        chain_code: &[u8],
        message: &[u8],
        new_nonce: &[u8; 32],
    ) -> Option<(SecretKey, [u8; 32])> {
        let pk = self.public_key();
        let (delta, new_cc) = pk.derive_scalar_and_chaincode(chain_code, message)?;
        let new_key = self.key.add(&delta);
        Some((
            SecretKey {
                key: new_key,
                nonce: *new_nonce,
            },
            new_cc,
        ))
    }
}

impl PublicKey {
    /// True if compressed bytes decode to a non-identity Ristretto point.
    pub fn is_valid(bytes: &[u8; 32]) -> bool {
        match RistrettoPoint::decode(bytes) {
            Ok(p) => p.ct_is_identity() == 0,
            Err(_) => false,
        }
    }

    /// HDKD scalar + chain code from public key (soft-derive shared step).
    pub fn derive_scalar_and_chaincode(
        &self,
        chain_code: &[u8],
        message: &[u8],
    ) -> Option<(Scalar, [u8; 32])> {
        let mut t = Transcript::new(b"SchnorrRistrettoHDKD");
        t.append_message(b"sign-bytes", message);
        t.append_message(b"chain-code", chain_code);
        let pk = self.to_bytes();
        t.append_message(b"public-key", &pk);
        // Official schnorrkel + Ref: label "HDKD-scalar", 64-byte challenge → wide reduce.
        let delta = t.challenge_scalar(b"HDKD-scalar");
        let mut new_cc = [0u8; 32];
        t.challenge_bytes(b"HDKD-chaincode", &mut new_cc);
        Some((delta, new_cc))
    }

    /// Soft public derivation: `pk' = pk + [delta]·B` in the **Ristretto** group.
    ///
    /// Must use the Ristretto basepoint (not a raw Ed25519-only path). SR25519
    /// public keys are Ristretto encodings; soft-derive is Ristretto addition.
    /// (may compute the same via Edwards coords + `fromEdwardBytes` — that is
    /// an encoding detail; the group operation is still Ristretto/prime-order.)
    pub fn derive(&self, chain_code: &[u8], message: &[u8]) -> Option<(PublicKey, [u8; 32])> {
        let (delta, new_cc) = self.derive_scalar_and_chaincode(chain_code, message)?;
        // [delta]B with Ristretto generator B, then Ristretto add.
        let add = RistrettoPoint::generator().mul(&delta);
        let new_p = self.point.add(&add);
        Some((PublicKey { point: new_p }, new_cc))
    }
}

// ---------------------------------------------------------------------------
// VRF + DLEQ (Schnorrkel / Substrate)
// ---------------------------------------------------------------------------

/// VRF input/output pair (compressed Ristretto points).
#[derive(Clone, Copy, Debug)]
pub struct VrfInOut {
    pub input: [u8; 32],
    pub output: [u8; 32],
}

/// DLEQ proof: c (32) ‖ s (32).
#[derive(Clone, Copy, Debug)]
pub struct VrfProof {
    pub c: [u8; 32],
    pub s: [u8; 32],
}

impl VrfProof {
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut o = [0u8; 64];
        o[..32].copy_from_slice(&self.c);
        o[32..].copy_from_slice(&self.s);
        o
    }
    pub fn from_bytes(b: &[u8; 64]) -> Self {
        let mut c = [0u8; 32];
        let mut s = [0u8; 32];
        c.copy_from_slice(&b[..32]);
        s.copy_from_slice(&b[32..]);
        Self { c, s }
    }
}

/// Merlin prove transcript for VRF/DLEQ — matches the reference implementation.
///
/// ```text
/// MerlinTranscript("VRF");
/// if extra != null { additionalData([], extra); }
/// ```
pub fn vrf_script(extra: Option<&[u8]>) -> Transcript {
    let mut t = Transcript::new(b"VRF");
    if let Some(e) = extra {
        // Ref: additionalData([], extra) → empty label
        t.append_message(b"", e);
    }
    t
}

/// Hash transcript → Ristretto point (VRF input). Appends `vrf-nm-pk` with `pk`.
pub fn vrf_hash(transcript: &mut Transcript, pk_bytes: &[u8; 32]) -> RistrettoPoint {
    transcript.append_message(b"vrf-nm-pk", pk_bytes);
    let mut wide = [0u8; 64];
    transcript.challenge_bytes(b"VRFHash", &mut wide);
    RistrettoPoint::from_uniform_bytes(&wide)
}

impl SecretKey {
    /// VRFInOut = (H, [sk]H).
    pub fn vrf_in_out(&self, transcript: &mut Transcript) -> VrfInOut {
        let pk = self.public_key().to_bytes();
        let h = vrf_hash(transcript, &pk);
        let out_p = h.mul(&self.key);
        let mut input = [0u8; 32];
        let mut output = [0u8; 32];
        h.encode(&mut input).expect("enc");
        out_p.encode(&mut output).expect("enc");
        VrfInOut { input, output }
    }

    /// DLEQ prove: transcript must be forked for prove domain.
    /// `kusama_vrf`: if true, `vrf:pk` is appended after h^r; else before R.
    pub fn dleq_prove(
        &self,
        transcript: &mut Transcript,
        inout: &VrfInOut,
        nonce64: &[u8; 64],
        kusama_vrf: bool,
    ) -> Option<VrfProof> {
        let pk = self.public_key().to_bytes();
        transcript.append_message(b"proto-name", b"DLEQProof");
        transcript.append_message(b"vrf:h", &inout.input);
        if !kusama_vrf {
            transcript.append_message(b"vrf:pk", &pk);
        }
        let r_scalar = Scalar::from_bytes_wide(nonce64);
        let r_g = RistrettoPoint::generator().mul(&r_scalar);
        let mut r_g_b = [0u8; 32];
        r_g.encode(&mut r_g_b).ok()?;
        transcript.append_message(b"vrf:R=g^r", &r_g_b);

        let h = RistrettoPoint::decode(&inout.input).ok()?;
        let h_r = h.mul(&r_scalar);
        let mut h_r_b = [0u8; 32];
        h_r.encode(&mut h_r_b).ok()?;
        transcript.append_message(b"vrf:h^r", &h_r_b);
        if kusama_vrf {
            transcript.append_message(b"vrf:pk", &pk);
        }
        transcript.append_message(b"vrf:h^sk", &inout.output);
        let c = transcript.challenge_scalar(b"prove");
        // s = r - c*sk  (mulSub(c, sk, r) in reference)
        let s = r_scalar.add(&c.mul(&self.key).neg());
        Some(VrfProof {
            c: scalar_to_bytes(&c),
            s: scalar_to_bytes(&s),
        })
    }

    /// VRF sign: returns (inout, proof).
    pub fn vrf_sign(
        &self,
        transcript: &mut Transcript,
        prove_transcript: &mut Transcript,
        nonce64: &[u8; 64],
        kusama_vrf: bool,
    ) -> Option<(VrfInOut, VrfProof)> {
        let inout = self.vrf_in_out(transcript);
        let proof = self.dleq_prove(prove_transcript, &inout, nonce64, kusama_vrf)?;
        Some((inout, proof))
    }
}

impl PublicKey {
    /// DLEQ verify.
    pub fn dleq_verify(
        &self,
        transcript: &mut Transcript,
        inout: &VrfInOut,
        proof: &VrfProof,
        kusama_vrf: bool,
    ) -> bool {
        let pk = self.to_bytes();
        let c = match Scalar::from_bytes_le(&proof.c) {
            Ok(c) => c,
            Err(_) => return false,
        };
        let s = match Scalar::from_bytes_le(&proof.s) {
            Ok(s) => s,
            Err(_) => return false,
        };
        // R = [s]B + [c]P
        let r_g = RistrettoPoint::generator().mul(&s).add(&self.point.mul(&c));
        let h = match RistrettoPoint::decode(&inout.input) {
            Ok(h) => h,
            Err(_) => return false,
        };
        let h_sk = match RistrettoPoint::decode(&inout.output) {
            Ok(p) => p,
            Err(_) => return false,
        };
        // h^r = [s]H + [c](h^sk)
        let h_r = h.mul(&s).add(&h_sk.mul(&c));

        transcript.append_message(b"proto-name", b"DLEQProof");
        transcript.append_message(b"vrf:h", &inout.input);
        if !kusama_vrf {
            transcript.append_message(b"vrf:pk", &pk);
        }
        let mut r_g_b = [0u8; 32];
        if r_g.encode(&mut r_g_b).is_err() {
            return false;
        }
        transcript.append_message(b"vrf:R=g^r", &r_g_b);
        let mut h_r_b = [0u8; 32];
        if h_r.encode(&mut h_r_b).is_err() {
            return false;
        }
        transcript.append_message(b"vrf:h^r", &h_r_b);
        if kusama_vrf {
            transcript.append_message(b"vrf:pk", &pk);
        }
        transcript.append_message(b"vrf:h^sk", &inout.output);
        let c_check = transcript.challenge_scalar(b"prove");
        crate::ct::ct_eq(&scalar_to_bytes(&c_check), &proof.c) == 1
    }

    /// VRF verify: recompute H from transcript, check output matches and DLEQ.
    pub fn vrf_verify(
        &self,
        transcript: &mut Transcript,
        prove_transcript: &mut Transcript,
        inout: &VrfInOut,
        proof: &VrfProof,
        kusama_vrf: bool,
    ) -> bool {
        let pk = self.to_bytes();
        let h = vrf_hash(transcript, &pk);
        let mut h_b = [0u8; 32];
        if h.encode(&mut h_b).is_err() {
            return false;
        }
        if crate::ct::ct_eq(&h_b, &inout.input) != 1 {
            return false;
        }
        self.dleq_verify(prove_transcript, inout, proof, kusama_vrf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let seed = [7u8; 32];
        let mini = MiniSecretKey::from_bytes(&seed);
        let sk = mini.expand();
        let pk = sk.public_key();
        let msg = b"hello substrate";
        let nonce = [9u8; 64];
        let sig = sk.sign_simple(msg, &nonce);
        assert!(pk.verify_simple(msg, &sig));
        // wrong message fails
        assert!(!pk.verify_simple(b"other", &sig));
    }

    #[test]
    fn public_key_deterministic() {
        let mini = MiniSecretKey::from_bytes(&[1u8; 32]);
        let a = mini.expand().public_key().to_bytes();
        let b = mini.expand().public_key().to_bytes();
        assert_eq!(a, b);
    }

    #[test]
    fn soft_public_matches_secret() {
        let seed = [7u8; 32];
        let sk = MiniSecretKey::from_bytes(&seed).expand_ed25519();
        let pk = sk.public_key();
        let cc = [9u8; 32];
        let msg = b"0";
        let nonce = [3u8; 32];
        let (sk2, cc_sk) = sk.soft_derive(&cc, msg, &nonce).expect("soft sk");
        let (pk2, cc_pk) = pk.derive(&cc, msg).expect("soft pk");
        assert_eq!(cc_sk, cc_pk, "chain code");
        assert_eq!(
            sk2.public_key().to_bytes(),
            pk2.to_bytes(),
            "pk from sk soft vs public soft"
        );
    }

    fn hex32(s: &str) -> [u8; 32] {
        let b = hex_decode(s);
        let mut a = [0u8; 32];
        a.copy_from_slice(&b);
        a
    }
    fn hex64(s: &str) -> [u8; 64] {
        let b = hex_decode(s);
        let mut a = [0u8; 64];
        a.copy_from_slice(&b);
        a
    }
    fn hex_decode(s: &str) -> alloc::vec::Vec<u8> {
        let s = s.trim();
        assert!(s.len().is_multiple_of(2));
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn sign_debug_vec0() {
        let seed = hex32("f965e415f4ebbbe56dd70dfbb393187d951fa7435786bf424849d31747aaf592");
        let msg = hex_decode("8b2a80303ae6e497ff14335f53a5da9578556cb6eaf4a34fae8c03cd2727410dbd53e0edbd0463ada309a1ebd2dafdd1cdce300de26af132a40dfbeecd175bb1");
        let nonce = hex64("de7763ada5a6487401c987310aca7b8b78c147521b0cac94311c85801aaf3ae8991d28269e2dd725130d987875ef2d49a09afa866507429283b3cfb950c22fdf");
        let expect = hex64("de24737b9a7a968a8c6b574e02344b33ef92b4eff00aa08ab6dffc692b845d0d023833532ac75f97afd7305cff824788cea9cd08380b4f44638ad9e576ee078c");
        let sk = MiniSecretKey::from_bytes(&seed).expand_ed25519();
        let pk = sk.public_key().to_bytes();
        let sk_b = sk.to_bytes();
        println!("sk scalar {}", hex_encode(&sk_b[..32]));
        println!("pk {}", hex_encode(&pk));
        let sig = sk.sign_simple(&msg, &nonce);
        let got = sig.to_bytes();
        println!("R got  {}", hex_encode(&got[..32]));
        println!("R want {}", hex_encode(&expect[..32]));
        println!("S got  {}", hex_encode(&got[32..]));
        println!("S want {}", hex_encode(&expect[32..]));
        assert_eq!(&got[..32], &expect[..32], "R");
        assert_eq!(&got[32..], &expect[32..], "S");
    }

    /// Substrate sign KATs (SigningContext + ""/"substrate" + sign-bytes).
    #[test]
    fn sign_vectors() {
        let vectors: [(&str, &str, &str, &str); 4] = [
            (
                "f965e415f4ebbbe56dd70dfbb393187d951fa7435786bf424849d31747aaf592",
                "8b2a80303ae6e497ff14335f53a5da9578556cb6eaf4a34fae8c03cd2727410dbd53e0edbd0463ada309a1ebd2dafdd1cdce300de26af132a40dfbeecd175bb1",
                "de7763ada5a6487401c987310aca7b8b78c147521b0cac94311c85801aaf3ae8991d28269e2dd725130d987875ef2d49a09afa866507429283b3cfb950c22fdf",
                "de24737b9a7a968a8c6b574e02344b33ef92b4eff00aa08ab6dffc692b845d0d023833532ac75f97afd7305cff824788cea9cd08380b4f44638ad9e576ee078c",
            ),
            (
                "0f6a8381121cfec9c5824beefbb1acf92d26c6f80fb361aef781b07706d0b767",
                "fb0333ecf5e26c10ee261286770d4a123e6c7d2fbfc8352e293bbe9e4989aa0e887ad82180992f3cee92b74505bd0a8b819d12c6e908a42e020dacdbafe65c82",
                "332903ca2f5578821b9939d21b2744612dbe09d4cc7aba15c5eb4cf8b579f94c0ef739263d54fd76abc6f028d4aa8a567027c48eae4529afa710810c3cc13425",
                "f426e54dc15ae0b4d229e551e8ed6d89bf09b06e77a698b5dfccb70acabcbe2b4211529e2858f7e53297d38a2792f66ba17a42fc08077309399b05c8221b2087",
            ),
            (
                "0edbd15b78655b2a7bd057f440102301f653d697f43a73fa6eab9d3f6706770c",
                "a3d876f2bfb1b6094d479492abdb7292de70a78fb06d14202703978a08a866f1198dc6832e97481f194baabe085520bb2cd0a30f7fcb853b3f165aab8a71c84d",
                "a7f92b36a7e145c21f7d8c8487f1745d41fc0025ee26ed75668a8999eb54f5db5ed5cd9efe7967be8c16c5c69220b2fb9855fd137d3b0202cb18685afa2f3028",
                "7288ad04fac2bdbdc4c5cd92893a6052256e7001c10e37fea8117b27a38c6840e3e4ab5f7d807e88850d57804e2a461745a86ae42fff3cd0d7d5e37b04133386",
            ),
            (
                "240a57d092e47e589735713ab8b784f690d5e118d651115e6f506b27b0499ad6",
                "31b93a772771eac8fb1311ae247e69633bfcb7c2dd694c7bf1e4a321a0e83e73c0888f243860c93f8c1ca6a1db89c02bb8b44e148e1691ed8c2239ebe499bf2a",
                "f7fc272b97820d88f11d09b1546391de6ea163a123e84ccf56527519aab464c3708638f8465897c1533eea494baeec4ba003af7c8bda5748363c446b8420024b",
                "00a7bbdb1c64961c64520d17b2fb286f4c0a03b93cd17e4b5fa3380c0bffe1208e3f8a09eed267881cd34ec30ab3da543a050ed6f683975bd1310fa90ee29a80",
            ),
        ];
        for (i, (seed_h, msg_h, nonce_h, sig_h)) in vectors.iter().enumerate() {
            let seed = hex32(seed_h);
            let msg = hex_decode(msg_h);
            let nonce = hex64(nonce_h);
            let expect = hex64(sig_h);
            let sk = MiniSecretKey::from_bytes(&seed).expand_ed25519();
            let sig = sk.sign_simple(&msg, &nonce);
            let got = sig.to_bytes();
            assert_eq!(
                got.as_slice(),
                expect.as_slice(),
                "vector {i} mismatch\ngot  {}\nwant {}",
                hex_encode(&got),
                sig_h
            );
            let pk = sk.public_key();
            assert!(pk.verify_simple(&msg, &sig), "vector {i} verify");
        }
    }

    fn hex_encode(b: &[u8]) -> alloc::string::String {
        b.iter().map(|x| alloc::format!("{:02x}", x)).collect()
    }
}
