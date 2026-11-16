//! Noise_XX (`25519_ChaChaPoly_SHA256`) for BitBox02: pure `no_std` + `alloc`,
//! zero new crates. Reuses the crate's X25519, ChaCha20-Poly1305, SHA-256,
//! and HKDF — no crypto dependency was added for this module.
//!
//! BitBox02 speaks `Noise_XX_25519_ChaChaPoly_SHA256` over USB-HID before
//! any protobuf frames flow. The generic constructors below use the spec
//! empty prologue (byte-exact against the official vectors and `snow`); the
//! BitBox profile instead mixes the protocol name as prologue on BOTH sides
//! (firmware `bitbox-noise` passes the name, as does the Python host lib),
//! so BitBox paths must use `*_with_prologue(..., BITBOX_NOISE_PROLOGUE)`.
//! Handshake payloads stay empty, giving 32 / 96 / 64-byte messages. Both sides hold
//! long-term static keys (the host's lives in app config — a stored
//! pairing key); the handshake hash at [`NoiseTransport::handshake_hash`]
//! feeds the on-device pairing-code display. Wrap the finished transport
//! in [`NoiseTransportAdapter`] to use it as a [`Transport`].
//!
//! Strict spec implementation: prologue always mixes (even when empty),
//! every handshake message carries its payload step (even when empty).
//! Proven byte-exact against the official cacnoise vectors
//! (`tests/hw_noise_vector.rs`) and live against `snow`
//! (`tests/hw_noise_snow.rs`, dev-only).
//!
//! Randomness policy: this module never samples randomness. The caller
//! supplies the ephemeral private key (32 bytes from the platform RNG) to
//! the constructors — `no_std` has no clock or OS RNG, and explicit
//! parameters are deterministic under test.
//!
//! All secret state is wiped with volatile writes on drop.

use crate::aead::{chacha20_poly1305_decrypt, chacha20_poly1305_encrypt};
use crate::curve::x25519::{diffie_hellman, public_key};
use crate::error::{Error, Result};
use crate::hash::{hkdf_sha256, Sha256};
use crate::hw::transport::Transport;

use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::time::Duration;

/// Noise protocol name hashed into `h` at initialization.
const PROTOCOL_NAME: &[u8] = b"Noise_XX_25519_ChaChaPoly_SHA256";
/// The protocol name, reused as the Noise prologue by profiles that mix a
/// non-empty prologue (BitBox02: host and firmware both mix exactly this —
/// verified against `bitbox-noise` + the Python host lib, which pass the
/// name as prologue). Generic `new_initiator`/`new_responder` keep the spec
/// empty prologue (proven by official vectors + `snow` interop).
pub(crate) const BITBOX_NOISE_PROLOGUE: &[u8] = PROTOCOL_NAME;
/// Encrypted static key on the wire: 32 bytes + 16-byte Poly1305 tag.
pub const ENC_STATIC_LEN: usize = 48;
/// Handshake message TOKEN lengths (payload excluded): `-> e` (32),
/// `<- e,ee,s,es` (32 + 48), `-> s,se` (48). On the wire each message
/// appends its payload step: `+ payload.len()` cleartext for message 1,
/// `+ payload.len() + 16` encrypted for messages 2 and 3. BitBox passes
/// `b""` payloads, giving 32 / 96 / 64-byte messages.
pub const MSG1_LEN: usize = 32;
pub const MSG2_LEN: usize = 80;
pub const MSG3_LEN: usize = ENC_STATIC_LEN;

fn mix_hash(h: &mut [u8; 32], data: &[u8]) {
    let mut sh = Sha256::new();
    sh.update(h);
    sh.update(data);
    *h = sh.finalize();
}

fn mix_key(ck: &mut [u8; 32], temp_k: &mut [u8; 32], input: &[u8; 32]) -> Result<()> {
    let mut okm = [0u8; 64];
    hkdf_sha256(ck, input, b"", &mut okm)?;
    ck.copy_from_slice(&okm[..32]);
    temp_k.copy_from_slice(&okm[32..]);
    volatile_zero(&mut okm);
    Ok(())
}

/// Noise ChaChaPoly nonce: 4 zero bytes + little-endian `n`.
fn noise_nonce(n: u64) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[4..].copy_from_slice(&n.to_le_bytes());
    out
}

fn volatile_zero(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0) };
    }
}

/// XX handshake state. Drive with `write_message_*` / `read_message_*` in
/// order, then [`NoiseXX::split`] into transport keys. Wrong order or
/// truncated messages return `Err` — never panic on attacker bytes.
pub struct NoiseXX {
    h: [u8; 32],
    ck: [u8; 32],
    temp_k: [u8; 32],
    n: u64,
    e_priv: [u8; 32],
    e_pub: [u8; 32],
    re_pub: Option<[u8; 32]>,
    s_priv: [u8; 32],
    rs_pub: Option<[u8; 32]>,
    initiator: bool,
    step: u8,
}

impl NoiseXX {
    fn new(s_priv: [u8; 32], e_priv: [u8; 32], initiator: bool, prologue: &[u8]) -> Self {
        let e_pub = public_key(&e_priv);
        // Spec `Initialize`: h starts as the protocol name (exactly
        // 32 bytes, so no pre-hash padding branch), then MixHash(prologue)
        // — UNCONDITIONALLY, even for an empty prologue. Skipping the
        // empty mix forks `h` against every spec-faithful peer.
        debug_assert_eq!(PROTOCOL_NAME.len(), 32);
        let mut h = [0u8; 32];
        h.copy_from_slice(PROTOCOL_NAME);
        let ck = h; // pre-prologue: prologue mixes into `h` ONLY (spec).
        mix_hash(&mut h, prologue);
        Self {
            h,
            ck,
            temp_k: [0u8; 32],
            n: 0,
            e_priv,
            e_pub,
            re_pub: None,
            s_priv,
            rs_pub: None,
            initiator,
            step: 0,
        }
    }

    /// Generic initiator with the spec empty prologue (vectors/`snow`
    /// interop). BitBox paths must NOT use this; use
    /// `new_initiator_with_prologue(..., BITBOX_NOISE_PROLOGUE)`.
    pub fn new_initiator(s_priv: [u8; 32], e_priv: [u8; 32]) -> Self {
        Self::new(s_priv, e_priv, true, b"")
    }

    /// Generic responder with the spec empty prologue (test doubles for the
    /// generic profile only; BitBox doubles use the name prologue).
    pub fn new_responder(s_priv: [u8; 32], e_priv: [u8; 32]) -> Self {
        Self::new(s_priv, e_priv, false, b"")
    }

    /// Initiator with an explicit prologue (both sides must agree
    /// byte-for-byte, or the handshake fails at the first decrypt).
    pub fn new_initiator_with_prologue(
        s_priv: [u8; 32],
        e_priv: [u8; 32],
        prologue: &[u8],
    ) -> Self {
        Self::new(s_priv, e_priv, true, prologue)
    }

    /// Responder with an explicit prologue.
    pub fn new_responder_with_prologue(
        s_priv: [u8; 32],
        e_priv: [u8; 32],
        prologue: &[u8],
    ) -> Self {
        Self::new(s_priv, e_priv, false, prologue)
    }

    fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut out = alloc::vec![0u8; plaintext.len() + 16];
        chacha20_poly1305_encrypt(
            &self.temp_k,
            &noise_nonce(self.n),
            plaintext,
            &self.h,
            &mut out,
        )?;
        self.n += 1;
        mix_hash(&mut self.h, &out);
        Ok(out)
    }

    fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < 16 {
            return Err(Error::InvalidLength);
        }
        let mut out = alloc::vec![0u8; ciphertext.len() - 16];
        // `n` advances only on success: a garbled message must not
        // desynchronize the handshake state machine.
        chacha20_poly1305_decrypt(
            &self.temp_k,
            &noise_nonce(self.n),
            ciphertext,
            &self.h,
            &mut out,
        )?;
        self.n += 1;
        mix_hash(&mut self.h, ciphertext);
        Ok(out)
    }

    /// `-> e` + payload. No key has mixed yet, so the payload rides in
    /// the clear (but still hashed into `h`). Wire: [`MSG1_LEN`] + 32-bit
    /// `e` plus `payload.len()` cleartext bytes — 32 bytes when BitBox
    /// passes `b""`.
    pub fn write_message_1(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        if !self.initiator || self.step != 0 {
            return Err(Error::InvalidEncoding);
        }
        mix_hash(&mut self.h, &self.e_pub);
        mix_hash(&mut self.h, payload);
        self.step = 1;
        let mut out = Vec::with_capacity(MSG1_LEN + payload.len());
        out.extend_from_slice(&self.e_pub);
        out.extend_from_slice(payload);
        Ok(out)
    }

    /// `<- e` (responder ingests initiator's ephemeral). Returns the
    /// cleartext payload. Any length ≥ [`MSG1_LEN`] parses; the tail
    /// always mixes (even when empty — spec, and required for snow and
    /// BitBox interop alike).
    pub fn read_message_1(&mut self, msg: &[u8]) -> Result<Vec<u8>> {
        if self.initiator || self.step != 0 || msg.len() < MSG1_LEN {
            return Err(Error::InvalidLength);
        }
        let mut re = [0u8; 32];
        re.copy_from_slice(&msg[..MSG1_LEN]);
        // Reject low-order / all-zero contributions before they mix in.
        diffie_hellman(&self.e_priv, &re)?;
        mix_hash(&mut self.h, &re);
        mix_hash(&mut self.h, &msg[MSG1_LEN..]);
        self.re_pub = Some(re);
        self.step = 1;
        Ok(msg[MSG1_LEN..].to_vec())
    }

    /// `<- e, ee, s, es` + encrypted payload: responder's ephemeral (32),
    /// encrypted static (48), encrypted payload (`payload.len() + 16`).
    /// With BitBox's `b""` payload the wire message is exactly 96 bytes.
    pub fn write_message_2(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        if self.initiator || self.step != 1 {
            return Err(Error::InvalidEncoding);
        }
        let re = self.re_pub.ok_or(Error::InvalidEncoding)?;
        mix_hash(&mut self.h, &self.e_pub);
        let mut ee = diffie_hellman(&self.e_priv, &re)?;
        // Copy keys out before mixing (borrow discipline for mix_key).
        let mut ck = self.ck;
        let mut temp_k = self.temp_k;
        mix_key(&mut ck, &mut temp_k, &ee)?;
        volatile_zero(&mut ee);
        self.ck = ck;
        self.temp_k = temp_k;
        self.n = 0;
        let s_pub = public_key(&self.s_priv);
        let enc = self.encrypt_and_hash(&s_pub)?;
        // `es` per spec: responder mixes DH(own static, peer ephemeral) —
        // equal by commutativity to the initiator's DH(own ephemeral,
        // peer static). (Spec §WriteMessage: `es` = initiator-`e` ×
        // responder-`s`; both sides compute the same shared secret.)
        let mut es = diffie_hellman(&self.s_priv, &re)?;
        let mut ck = self.ck;
        let mut temp_k = self.temp_k;
        mix_key(&mut ck, &mut temp_k, &es)?;
        volatile_zero(&mut es);
        self.ck = ck;
        self.temp_k = temp_k;
        self.n = 0;
        let enc_payload = self.encrypt_and_hash(payload)?;
        let mut out = Vec::with_capacity(MSG2_LEN + enc_payload.len());
        out.extend_from_slice(&self.e_pub);
        out.extend_from_slice(&enc);
        out.extend_from_slice(&enc_payload);
        self.step = 2;
        Ok(out)
    }

    /// Initiator ingests message 2; recovers responder's static key and
    /// the payload. Strict spec form: `e(32) || enc_s(48) ||
    /// enc_payload(≥16)` — anything shorter is `InvalidLength`, and the
    /// trailing payload always decrypts (even when empty).
    pub fn read_message_2(&mut self, msg: &[u8]) -> Result<Vec<u8>> {
        if !self.initiator || self.step != 1 || msg.len() < MSG2_LEN + 16 {
            return Err(Error::InvalidLength);
        }
        let mut re = [0u8; 32];
        re.copy_from_slice(&msg[..32]);
        diffie_hellman(&self.e_priv, &re)?;
        mix_hash(&mut self.h, &re);
        let mut ee = diffie_hellman(&self.e_priv, &re)?;
        let mut ck = self.ck;
        let mut temp_k = self.temp_k;
        mix_key(&mut ck, &mut temp_k, &ee)?;
        volatile_zero(&mut ee);
        self.ck = ck;
        self.temp_k = temp_k;
        self.n = 0;
        let pt = self.decrypt_and_hash(&msg[MSG1_LEN..MSG2_LEN])?;
        if pt.len() != 32 {
            return Err(Error::InvalidEncoding);
        }
        let mut rs = [0u8; 32];
        rs.copy_from_slice(&pt);
        // `es`: our *ephemeral* × their static (responder's static just
        // arrived encrypted — this ordering is why XX keeps `s` secret).
        let mut es = diffie_hellman(&self.e_priv, &rs)?;
        let mut ck = self.ck;
        let mut temp_k = self.temp_k;
        mix_key(&mut ck, &mut temp_k, &es)?;
        volatile_zero(&mut es);
        self.ck = ck;
        self.temp_k = temp_k;
        self.n = 0;
        self.re_pub = Some(re);
        self.rs_pub = Some(rs);
        self.step = 2;
        self.decrypt_and_hash(&msg[MSG2_LEN..])
    }

    /// `-> s, se` + encrypted payload: encrypted static (48), encrypted
    /// payload (`payload.len() + 16`). With BitBox's `b""` payload the
    /// wire message is exactly 64 bytes.
    pub fn write_message_3(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        if !self.initiator || self.step != 2 {
            return Err(Error::InvalidEncoding);
        }
        // Step 2 implies message 2 was processed, so both re and rs are known.
        let re = self.re_pub.ok_or(Error::InvalidEncoding)?;
        let s_pub = public_key(&self.s_priv);
        let enc = self.encrypt_and_hash(&s_pub)?;
        // `se` per spec: initiator mixes DH(own static, peer *ephemeral*).
        // (Spec §WriteMessage: `se` = initiator-`s` × responder-`e`.)
        let mut se = diffie_hellman(&self.s_priv, &re)?;
        let mut ck = self.ck;
        let mut temp_k = self.temp_k;
        mix_key(&mut ck, &mut temp_k, &se)?;
        volatile_zero(&mut se);
        self.ck = ck;
        self.temp_k = temp_k;
        self.n = 0;
        let enc_payload = self.encrypt_and_hash(payload)?;
        let mut out = Vec::with_capacity(MSG3_LEN + enc_payload.len());
        out.extend_from_slice(&enc);
        out.extend_from_slice(&enc_payload);
        self.step = 3;
        Ok(out)
    }

    /// Responder ingests message 3; recovers initiator's static key and
    /// the payload. Strict spec form: `enc_s(48) || enc_payload(≥16)`.
    /// (`se` per spec: responder mixes DH(own ephemeral, peer static).)
    pub fn read_message_3(&mut self, msg: &[u8]) -> Result<Vec<u8>> {
        if self.initiator || self.step != 2 || msg.len() < MSG3_LEN + 16 {
            return Err(Error::InvalidLength);
        }
        let pt = self.decrypt_and_hash(&msg[..MSG3_LEN])?;
        if pt.len() != 32 {
            return Err(Error::InvalidEncoding);
        }
        let mut rs = [0u8; 32];
        rs.copy_from_slice(&pt);
        let mut se = diffie_hellman(&self.e_priv, &rs)?;
        let mut ck = self.ck;
        let mut temp_k = self.temp_k;
        mix_key(&mut ck, &mut temp_k, &se)?;
        volatile_zero(&mut se);
        self.ck = ck;
        self.temp_k = temp_k;
        self.n = 0;
        self.rs_pub = Some(rs);
        self.step = 3;
        self.decrypt_and_hash(&msg[MSG3_LEN..])
    }

    /// Peer's static public key (available after message 2 / 3). BitBox
    /// hosts compare this against the stored pairing key on reconnect.
    pub fn peer_static(&self) -> Option<[u8; 32]> {
        self.rs_pub
    }

    /// Finish: split `ck` into transport keys. Consumes the handshake
    /// state (ephemerals wiped on drop either way).
    pub fn split(self) -> Result<NoiseTransport> {
        if self.step != 3 {
            return Err(Error::InvalidEncoding);
        }
        let mut okm = [0u8; 64];
        hkdf_sha256(&self.ck, b"", b"", &mut okm)?;
        let mut k1 = [0u8; 32];
        let mut k2 = [0u8; 32];
        k1.copy_from_slice(&okm[..32]);
        k2.copy_from_slice(&okm[32..]);
        volatile_zero(&mut okm);
        let handshake_hash = self.h;
        let (k_send, k_recv) = if self.initiator { (k1, k2) } else { (k2, k1) };
        // self drops here → secrets wiped.
        Ok(NoiseTransport {
            k_send,
            k_recv,
            n_send: 0,
            n_recv: 0,
            handshake_hash,
        })
    }
}

impl Drop for NoiseXX {
    fn drop(&mut self) {
        volatile_zero(&mut self.e_priv);
        volatile_zero(&mut self.s_priv);
        volatile_zero(&mut self.temp_k);
        volatile_zero(&mut self.ck);
    }
}

/// Post-handshake transport: ChaChaPoly with empty AAD, 64-bit nonces.
/// Rekeying is the app's job (BitBox re-pairs long before 2^64 messages).
pub struct NoiseTransport {
    k_send: [u8; 32],
    k_recv: [u8; 32],
    n_send: u64,
    n_recv: u64,
    handshake_hash: [u8; 32],
}

impl NoiseTransport {
    /// Encrypt one post-handshake message (plaintext + 16-byte tag).
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut out = alloc::vec![0u8; plaintext.len() + 16];
        chacha20_poly1305_encrypt(
            &self.k_send,
            &noise_nonce(self.n_send),
            plaintext,
            b"",
            &mut out,
        )?;
        self.n_send = self.n_send.checked_add(1).ok_or(Error::InvalidEncoding)?;
        Ok(out)
    }

    /// Decrypt one post-handshake message. Wrong order, tampering, or
    /// replay all return `Err` — the nonce is implicit, never on the wire.
    /// The receive nonce advances only on success, so a garbled packet can
    /// be retried instead of killing the session.
    pub fn decrypt(&mut self, msg: &[u8]) -> Result<Vec<u8>> {
        if msg.len() < 16 {
            return Err(Error::InvalidLength);
        }
        let mut out = alloc::vec![0u8; msg.len() - 16];
        chacha20_poly1305_decrypt(&self.k_recv, &noise_nonce(self.n_recv), msg, b"", &mut out)?;
        self.n_recv += 1;
        Ok(out)
    }

    /// Handshake hash at split time — feeds the pairing-code display.
    pub fn handshake_hash(&self) -> [u8; 32] {
        self.handshake_hash
    }
}

impl Drop for NoiseTransport {
    fn drop(&mut self) {
        volatile_zero(&mut self.k_send);
        volatile_zero(&mut self.k_recv);
    }
}

/// Adapts a finished [`NoiseTransport`] to [`Transport`]: each `exchange`
/// encrypts the request, moves it through the inner transport, and decrypts
/// the reply. BitBox02 protobuf frames ride inside the encrypted payloads.
pub struct NoiseTransportAdapter<T: Transport> {
    inner: T,
    noise: NoiseTransport,
}

impl<T: Transport> NoiseTransportAdapter<T> {
    pub fn new(inner: T, noise: NoiseTransport) -> Self {
        Self { inner, noise }
    }

    /// Borrow the finished transport (e.g. for the pairing hash).
    pub fn noise(&self) -> &NoiseTransport {
        &self.noise
    }
}

impl<T: Transport> Transport for NoiseTransportAdapter<T> {
    fn exchange(&mut self, msg: &[u8]) -> Result<Vec<u8>> {
        let enc = self.noise.encrypt(msg)?;
        let reply = self.inner.exchange(&enc)?;
        self.noise.decrypt(&reply)
    }

    #[cfg(feature = "std")]
    fn exchange_timeout(&mut self, msg: &[u8], timeout: Duration) -> Result<Vec<u8>> {
        let enc = self.noise.encrypt(msg)?;
        let reply = self.inner.exchange_timeout(&enc, timeout)?;
        self.noise.decrypt(&reply)
    }
}
