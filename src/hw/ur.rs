//! Uniform Resources (UR2.0, BlockchainCommons BCR-2020-005) envelope.
//!
//! Used by all airgap devices: Foundation Passport, Keystone, Coldcard-QR,
//! Jade-QR. No transport needed — payloads travel as animated QR strings.
//!
//! Envelope handled here (fully spec-shaped):
//! `ur:<type>/<body>` (single) or `ur:<type>/<seq>-of-<total>/<body>`.
//!
//! Body alphabet: v1 uses lowercase RFC4648 base32 without padding
//! (`encode_body` / `decode_body`, isolated in one place). Swapping in the
//! BCR-2020-012 Bytewords 256-word table is a drop-in change of those two
//! functions; multipart sequencing, CBOR payloads and tests are unaffected.

use crate::error::{Error, Result};

use alloc::string::String;
use alloc::vec::Vec;

/// Parsed UR message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UrMessage {
    /// Lowercase type, e.g. `crypto-psbt`, `crypto-account`, `bytes`.
    pub ur_type: String,
    /// Raw CBOR payload bytes.
    pub payload: Vec<u8>,
    /// `None` = single-part, `Some((seq, total))` (1-based) otherwise.
    pub part: Option<(u32, u32)>,
}

impl UrMessage {
    pub fn single(ur_type: &str, payload: Vec<u8>) -> Self {
        Self {
            ur_type: ur_type_to_lower(ur_type),
            payload,
            part: None,
        }
    }
}

/// Lowercase ASCII (UR types are case-insensitive, canonical lowercase).
fn ur_type_to_lower(t: &str) -> String {
    let mut s = String::with_capacity(t.len());
    for b in t.bytes() {
        s.push((if b.is_ascii_uppercase() { b + 32 } else { b }) as char);
    }
    s
}

// ---------------------------------------------------------------------------
// body alphabet (isolated swap point for Bytewords)
// ---------------------------------------------------------------------------

const B32_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Encode bytes to lowercase base32, no padding.
pub fn encode_body(bytes: &[u8]) -> String {
    let mut s = String::new();
    let mut acc: u32 = 0;
    let mut bits = 0u8;
    for b in bytes {
        acc = (acc << 8) | *b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            s.push(B32_ALPHABET[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        s.push(B32_ALPHABET[((acc << (5 - bits)) & 31) as usize] as char);
    }
    s
}

/// Decode lowercase/uppercase base32, no padding (whitespace rejected).
pub fn decode_body(s: &str) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let mut acc: u32 = 0;
    let mut bits = 0u8;
    for b in s.bytes() {
        let v = match b {
            b'a'..=b'z' => b - b'a',
            b'A'..=b'Z' => b - b'A',
            b'2'..=b'7' => b - b'2' + 26,
            _ => return Err(Error::InvalidCharacter),
        } as u32;
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    // trailing bits must be zero padding
    if bits > 0 && acc != 0 {
        return Err(Error::InvalidEncoding);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// envelope
// ---------------------------------------------------------------------------

/// Encode single-part `ur:<type>/<body>`.
pub fn ur_encode_single(ur_type: &str, payload: &[u8]) -> String {
    let mut s = String::from("ur:");
    s.push_str(&ur_type_to_lower(ur_type));
    s.push('/');
    s.push_str(&encode_body(payload));
    s
}

/// Encode one multipart shard `ur:<type>/<seq>-of-<total>/<body>`.
pub fn ur_encode_part(ur_type: &str, seq: u32, total: u32, payload: &[u8]) -> Result<String> {
    if seq == 0 || total == 0 || seq > total || total > 10_000 {
        return Err(Error::InvalidLength);
    }
    let mut s = String::from("ur:");
    s.push_str(&ur_type_to_lower(ur_type));
    s.push('/');
    s.push_str(&u32_to_dec(seq));
    s.push_str("-of-");
    s.push_str(&u32_to_dec(total));
    s.push('/');
    s.push_str(&encode_body(payload));
    Ok(s)
}

fn u32_to_dec(mut v: u32) -> String {
    if v == 0 {
        return String::from("0");
    }
    let mut buf = [0u8; 10];
    let mut i = 10usize;
    while v > 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    String::from_utf8_lossy(&buf[i..]).into_owned()
}

/// Decode single- or multi-part UR string (no reassembly; see `UrAssembler`).
pub fn ur_decode_single(s: &str) -> Result<UrMessage> {
    let rest = s
        .strip_prefix("ur:")
        .or_else(|| s.strip_prefix("UR:"))
        .ok_or(Error::InvalidEncoding)?;
    let mut it = rest.split('/');
    let ur_type = it.next().ok_or(Error::InvalidEncoding)?;
    if ur_type.is_empty() {
        return Err(Error::InvalidEncoding);
    }
    let second = it.next().ok_or(Error::InvalidEncoding)?;
    let (part, body) = match it.next() {
        None => (None, second),
        Some(third) => {
            // `seq-of-total`
            let dash = second.find("-of-").ok_or(Error::InvalidEncoding)?;
            let seq = dec_to_u32(&second[..dash])?;
            let total = dec_to_u32(&second[dash + 4..])?;
            if seq == 0 || total == 0 || seq > total {
                return Err(Error::InvalidEncoding);
            }
            if it.next().is_some() {
                return Err(Error::InvalidEncoding);
            }
            (Some((seq, total)), third)
        }
    };
    Ok(UrMessage {
        ur_type: ur_type_to_lower(ur_type),
        payload: decode_body(body)?,
        part,
    })
}

fn dec_to_u32(s: &str) -> Result<u32> {
    if s.is_empty() || s.len() > 10 {
        return Err(Error::InvalidEncoding);
    }
    let mut v: u32 = 0;
    for b in s.bytes() {
        if !b.is_ascii_digit() {
            return Err(Error::InvalidEncoding);
        }
        v = v.saturating_mul(10).saturating_add((b - b'0') as u32);
    }
    Ok(v)
}

/// Reassemble multipart animated-QR shards. Feed shards in any order;
/// duplicates ignored; mixed types/totals rejected.
///
/// Sharding is uniform indexed (`seq-of-total`), NOT fountain-coded: the
/// scanner must collect all `total` distinct shards. Large payloads become
/// more frames for the app to cycle — see `tests/hw_ur_airgap.rs`.
#[derive(Clone, Debug)]
pub struct UrAssembler {
    ur_type: String,
    total: u32,
    parts: Vec<Option<Vec<u8>>>,
    got: u32,
}

impl UrAssembler {
    pub fn new() -> Self {
        Self {
            ur_type: String::new(),
            total: 0,
            parts: Vec::new(),
            got: 0,
        }
    }

    /// Feed one `ur:...` shard. Returns `Some(payload)` when complete.
    pub fn feed(&mut self, shard: &str) -> Result<Option<Vec<u8>>> {
        let msg = ur_decode_single(shard)?;
        let (seq, total) = msg.part.ok_or(Error::InvalidEncoding)?;
        if self.total == 0 {
            // `total` is attacker-controlled (up to u32::MAX): cap it like
            // `ur_encode_part` so a hostile first shard cannot force a
            // ~100 GB `parts` allocation (`ur:bytes/1-of-4294967295/…`).
            if total > 10_000 {
                return Err(Error::InvalidLength);
            }
            self.ur_type = msg.ur_type.clone();
            self.total = total;
            self.parts = alloc::vec![None; total as usize];
        } else {
            if self.ur_type != msg.ur_type || self.total != total {
                return Err(Error::InvalidEncoding);
            }
        }
        let slot = &mut self.parts[(seq - 1) as usize];
        if slot.is_none() {
            *slot = Some(msg.payload);
            self.got += 1;
        }
        if self.got == self.total {
            let mut out = Vec::new();
            for p in &self.parts {
                out.extend_from_slice(p.as_ref().ok_or(Error::InvalidLength)?);
            }
            Ok(Some(out))
        } else {
            Ok(None)
        }
    }

    pub fn is_empty(&self) -> bool {
        self.total == 0
    }
}

impl Default for UrAssembler {
    fn default() -> Self {
        Self::new()
    }
}
