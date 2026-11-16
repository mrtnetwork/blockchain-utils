//! Ledger-style APDU framing: `CLA INS P1 P2 [Lc DATA] [Le]`.
//!
//! Covers all Ledger Nano S Plus / X / Flex / Stax (same BOLOS APDU).
//! Pure codec — chunking over HID USB is `hw::hid`.

use crate::error::{Error, Result};

use alloc::vec::Vec;

/// Success status word.
pub const SW_OK: u16 = 0x9000;
/// More data available (chain `GET RESPONSE`).
pub const SW_MORE: u16 = 0x61;
/// Wrong length.
pub const SW_WRONG_LENGTH: u16 = 0x6700;

/// APDU command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Apdu {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub data: Vec<u8>,
    /// Expected response length (`None` = absent, `Some(0)` = `Le=0` = 256).
    pub le: Option<u8>,
}

impl Apdu {
    pub fn new(cla: u8, ins: u8, p1: u8, p2: u8, data: Vec<u8>) -> Self {
        Self {
            cla,
            ins,
            p1,
            p2,
            data,
            le: None,
        }
    }

    /// Serialize to wire bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(5 + self.data.len() + 1);
        out.extend_from_slice(&[self.cla, self.ins, self.p1, self.p2]);
        if self.data.is_empty() && self.le.is_none() {
            return out; // case 1: header only
        }
        if self.data.len() > 255 {
            // extended length not used by Ledger apps in v1; keep simple.
            out.push(0);
            return out;
        }
        out.push(self.data.len() as u8);
        out.extend_from_slice(&self.data);
        if let Some(le) = self.le {
            out.push(le);
        }
        out
    }

    /// Parse wire bytes back (header + optional Lc/data [+Le]).
    pub fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() < 4 {
            return Err(Error::InvalidLength);
        }
        let (cla, ins, p1, p2) = (raw[0], raw[1], raw[2], raw[3]);
        if raw.len() == 4 {
            return Ok(Self {
                cla,
                ins,
                p1,
                p2,
                data: Vec::new(),
                le: None,
            });
        }
        let lc = raw[4] as usize;
        if raw.len() == 5 {
            // `... Le` with empty data.
            return Ok(Self {
                cla,
                ins,
                p1,
                p2,
                data: Vec::new(),
                le: Some(raw[4]),
            });
        }
        if raw.len() < 5 + lc {
            return Err(Error::InvalidLength);
        }
        let data = raw[5..5 + lc].to_vec();
        let le = if raw.len() > 5 + lc {
            if raw.len() != 5 + lc + 1 {
                return Err(Error::InvalidEncoding);
            }
            Some(raw[5 + lc])
        } else {
            None
        };
        Ok(Self {
            cla,
            ins,
            p1,
            p2,
            data,
            le,
        })
    }
}

/// APDU response: `DATA || SW1 SW2`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApduResponse {
    pub data: Vec<u8>,
    pub sw: u16,
}

impl ApduResponse {
    pub fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() < 2 {
            return Err(Error::InvalidLength);
        }
        let n = raw.len();
        Ok(Self {
            data: raw[..n - 2].to_vec(),
            sw: ((raw[n - 2] as u16) << 8) | raw[n - 1] as u16,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.data.clone();
        out.push((self.sw >> 8) as u8);
        out.push((self.sw & 0xFF) as u8);
        out
    }

    pub fn is_ok(&self) -> bool {
        self.sw == SW_OK
    }

    /// `Ok(data)` on `0x9000`, else `VerificationFailed` (wrong SW).
    pub fn into_data(self) -> Result<Vec<u8>> {
        if self.is_ok() {
            Ok(self.data)
        } else {
            Err(Error::VerificationFailed)
        }
    }
}

/// Encode a BIP32 path for Ledger apps: `len || be32(index)...`.
pub fn encode_bip32_path(path: &[u32]) -> Result<Vec<u8>> {
    if path.len() > 10 {
        return Err(Error::InvalidPath);
    }
    let mut out = Vec::with_capacity(1 + 4 * path.len());
    out.push(path.len() as u8);
    for i in path {
        out.extend_from_slice(&i.to_be_bytes());
    }
    Ok(out)
}
