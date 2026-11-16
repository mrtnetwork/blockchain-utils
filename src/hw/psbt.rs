//! Minimal BIP174 PSBT parser for airgap flows.
//!
//! The host builds unsigned tx bytes elsewhere; the PSBT envelope is what
//! Coldcard / Passport / Keystone / Jade pass around for signing. This parser
//! validates structure (`psbt\xff` magic, global + per-input/output TLV maps)
//! and exposes the unsigned-tx + map counts so callers can build/show
//! `ur:crypto-psbt` payloads. Full script-finalization is out of scope.

use crate::error::{Error, Result};

use alloc::vec::Vec;

/// PSBT magic: `psbt` + `0xff`.
pub const PSBT_MAGIC: [u8; 5] = [0x70, 0x73, 0x62, 0x74, 0xff];

/// Global map key types (BIP174 § global).
pub mod global {
    pub const UNSIGNED_TX: u8 = 0x00;
    pub const XPUB: u8 = 0x01;
    pub const TX_VERSION: u8 = 0x02;
    pub const FALLBACK_LOCKTIME: u8 = 0x03;
    pub const INPUT_COUNT: u8 = 0x04;
    pub const OUTPUT_COUNT: u8 = 0x05;
    pub const TX_MODIFIABLE: u8 = 0x06;
    pub const VERSION: u8 = 0xFB;
    pub const PROPRIETARY: u8 = 0xFC;
}

/// One TLV record `compactsize(len) compactsize(keytype) keydata... valuedata`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlvRecord {
    pub key_type: u64,
    pub key_data: Vec<u8>,
    pub value: Vec<u8>,
}

/// Parsed PSBT with raw map sections preserved.
#[derive(Clone, Debug)]
pub struct Psbt {
    pub global: Vec<TlvRecord>,
    pub inputs: Vec<Vec<TlvRecord>>,
    pub outputs: Vec<Vec<TlvRecord>>,
    /// Raw unsigned-tx bytes (global `0x00`), if present.
    pub unsigned_tx: Option<Vec<u8>>,
}

fn read_compactsize(buf: &[u8], pos: &mut usize) -> Result<u64> {
    if *pos >= buf.len() {
        return Err(Error::InvalidLength);
    }
    let b = buf[*pos];
    *pos += 1;
    Ok(match b {
        0x00..=0xFC => b as u64,
        0xFD => {
            if buf.len() < *pos + 2 {
                return Err(Error::InvalidLength);
            }
            let v = u16::from_le_bytes([buf[*pos], buf[*pos + 1]]) as u64;
            *pos += 2;
            v
        }
        0xFE => {
            if buf.len() < *pos + 4 {
                return Err(Error::InvalidLength);
            }
            let v =
                u32::from_le_bytes([buf[*pos], buf[*pos + 1], buf[*pos + 2], buf[*pos + 3]]) as u64;
            *pos += 4;
            v
        }
        0xFF => {
            if buf.len() < *pos + 8 {
                return Err(Error::InvalidLength);
            }
            let v = u64::from_le_bytes([
                buf[*pos],
                buf[*pos + 1],
                buf[*pos + 2],
                buf[*pos + 3],
                buf[*pos + 4],
                buf[*pos + 5],
                buf[*pos + 6],
                buf[*pos + 7],
            ]);
            *pos += 8;
            v
        }
    })
}

fn read_bytes<'a>(buf: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8]> {
    // `len` comes from a compactsize (up to u64::MAX): plain `*pos + len`
    // can wrap `usize`, pass the check, and panic in the slice below
    // (same class as the `fuzz_trezor` `proto_decode` crash).
    let end = pos.checked_add(len).ok_or(Error::InvalidLength)?;
    if buf.len() < end {
        return Err(Error::InvalidLength);
    }
    let s = &buf[*pos..end];
    *pos = end;
    Ok(s)
}

/// Parse one key-value map (terminated by a zero-length key).
fn parse_map(buf: &[u8], pos: &mut usize) -> Result<Vec<TlvRecord>> {
    let mut out = Vec::new();
    loop {
        let klen = read_compactsize(buf, pos)? as usize;
        if klen == 0 {
            break;
        }
        let kraw = read_bytes(buf, pos, klen)?;
        let mut kp = 0usize;
        // key itself is compactsize-prefixed inside? No: first byte(s) are key type varint.
        let ktype = {
            let b0 = kraw[0];
            if b0 <= 0xFC {
                kp = 1;
                b0 as u64
            } else {
                // rare long key-type encodings; decode varint manually
                let mut v: u64 = 0;
                let mut shift = 0u32;
                for (i, b) in kraw.iter().enumerate() {
                    // Bound like `trezor::varint_decode`: an unbounded
                    // continuation run would overflow the shift (debug
                    // panic) and only yield garbage.
                    if shift >= 64 || i >= 10 {
                        return Err(Error::InvalidEncoding);
                    }
                    v |= ((*b as u64) & 0x7F) << shift;
                    if b & 0x80 == 0 {
                        kp = i + 1;
                        break;
                    }
                    shift += 7;
                }
                v
            }
        };
        let vlen = read_compactsize(buf, pos)? as usize;
        let vraw = read_bytes(buf, pos, vlen)?;
        out.push(TlvRecord {
            key_type: ktype,
            key_data: kraw[kp..].to_vec(),
            value: vraw.to_vec(),
        });
        let _ = kp;
    }
    Ok(out)
}

impl Psbt {
    /// Parse + validate full PSBT bytes.
    pub fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() < 5 || raw[..5] != PSBT_MAGIC {
            return Err(Error::InvalidEncoding);
        }
        let mut pos = 5usize;
        let global = parse_map(raw, &mut pos)?;
        // input/output counts come from unsigned tx or explicit keys; the maps
        // themselves are simply repeated until input runs out. Heuristic: parse
        // maps greedily; caller splits via counts when known.
        let mut maps: Vec<Vec<TlvRecord>> = Vec::new();
        while pos < raw.len() {
            maps.push(parse_map(raw, &mut pos)?);
        }
        // Split inputs/outputs using global counts when available.
        let (mut n_in, mut n_out) = (0usize, 0usize);
        let mut unsigned_tx = None;
        for r in &global {
            match r.key_type as u8 {
                global::UNSIGNED_TX => unsigned_tx = Some(r.value.clone()),
                global::INPUT_COUNT if !r.value.is_empty() => {
                    n_in = r.value[0] as usize;
                }
                global::OUTPUT_COUNT if !r.value.is_empty() => {
                    n_out = r.value[0] as usize;
                }
                _ => {}
            }
        }
        // Fallback: derive counts from unsigned tx (2nd byte varint heuristic
        // is unreliable) — if unknown, treat all-but-last... instead require
        // explicit split: first `n_in` maps are inputs. When counts unknown and
        // unsigned_tx present, decode tx varints properly:
        if n_in == 0 && n_out == 0 {
            if let Some(tx) = &unsigned_tx {
                let (ni, no) = tx_in_out_counts(tx).unwrap_or((0, 0));
                n_in = ni;
                n_out = no;
            }
        }
        if maps.len() < n_in + n_out {
            return Err(Error::InvalidLength);
        }
        let inputs = maps.drain(..core::cmp::min(n_in, maps.len())).collect();
        let outputs = maps;
        // tolerate extra empty trailing map from some producers
        Ok(Self {
            global,
            inputs,
            outputs,
            unsigned_tx,
        })
    }

    pub fn input_count(&self) -> usize {
        self.inputs.len()
    }

    pub fn output_count(&self) -> usize {
        self.outputs.len()
    }
}

/// Decode legacy-tx input/output counts: `version(4) || vin compactsize ...
/// (each `36B + script compactsize + 4B`) || vout compactsize ...`.
fn tx_in_out_counts(tx: &[u8]) -> Result<(usize, usize)> {
    let mut pos = 0usize;
    if tx.len() < 4 {
        return Err(Error::InvalidLength);
    }
    pos += 4;
    let n_in = read_compactsize(tx, &mut pos)? as usize;
    for _ in 0..n_in {
        read_bytes(tx, &mut pos, 36)?;
        let sl = read_compactsize(tx, &mut pos)? as usize;
        read_bytes(tx, &mut pos, sl)?;
        read_bytes(tx, &mut pos, 4)?;
    }
    let n_out = read_compactsize(tx, &mut pos)? as usize;
    Ok((n_in, n_out))
}
