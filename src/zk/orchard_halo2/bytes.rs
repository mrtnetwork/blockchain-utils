//! Byte utilities. Canonical wire order is **LE**.
//! Debug display is **BE hex with 0x** — i.e. `le_bytes.reversed → hex`.
//! Mirrors Ref: `BytesUtils.toHexString(b.toBytes().reversed.toList(), prefix: "0x")`.

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

use crate::zk::orchard_halo2::error::{Halo2Error, Halo2Result};

/// Encode bytes as lowercase hex with `0x` prefix into `out`.
/// Returns number of bytes written, or `Err` if `out` is too small.
/// No allocation, WASM/FFI safe.
pub fn to_hex_be_prefixed(le_bytes: &[u8], out: &mut [u8]) -> Halo2Result<usize> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let need =
        2usize
            .checked_add(le_bytes.len().checked_mul(2).ok_or_else(|| {
                Halo2Error::operation_failed("to_hex_be_prefixed", "length overflow")
            })?)
            .ok_or_else(|| Halo2Error::operation_failed("to_hex_be_prefixed", "length overflow"))?;
    if out.len() < need {
        return Err(Halo2Error::operation_failed(
            "to_hex_be_prefixed",
            "output too small",
        ));
    }
    out[0] = b'0';
    out[1] = b'x';
    let mut o = 2usize;
    for &b in le_bytes.iter().rev() {
        out[o] = HEX[(b >> 4) as usize];
        out[o + 1] = HEX[(b & 0xf) as usize];
        o += 2;
    }
    Ok(need)
}

#[cfg(feature = "alloc")]
pub fn to_hex_be_prefixed_alloc(le_bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(2 + le_bytes.len() * 2);
    s.push_str("0x");
    for &b in le_bytes.iter().rev() {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

/// Parse `0x`-prefixed (or bare) BE hex into LE bytes in `out_le`.
/// `hex` is BE display order; stored output is LE (reversed).
pub fn from_hex_be_to_le(hex: &[u8], out_le: &mut [u8]) -> Halo2Result<()> {
    let h = if hex.len() >= 2 && hex[0] == b'0' && (hex[1] == b'x' || hex[1] == b'X') {
        &hex[2..]
    } else {
        hex
    };
    if h.len() != out_le.len() * 2 {
        return Err(Halo2Error::operation_failed(
            "from_hex_be_to_le",
            "invalid hex length",
        ));
    }
    let val = |c: u8| -> Halo2Result<u8> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(Halo2Error::operation_failed(
                "from_hex_be_to_le",
                "invalid hex char",
            )),
        }
    };
    let n = out_le.len();
    for i in 0..n {
        let hi = val(h[i * 2])?;
        let lo = val(h[i * 2 + 1])?;
        out_le[n - 1 - i] = (hi << 4) | lo;
    }
    Ok(())
}

#[cfg(feature = "alloc")]
pub fn le_bytes_to_debug_hex(le_bytes: &[u8]) -> String {
    to_hex_be_prefixed_alloc(le_bytes)
}

/// Copy LE bytes with length check (no assert).
pub fn copy_le_bytes(dst: &mut [u8], src: &[u8]) -> Halo2Result<()> {
    if dst.len() != src.len() {
        return Err(Halo2Error::operation_failed(
            "copy_le_bytes",
            "length mismatch",
        ));
    }
    dst.copy_from_slice(src);
    Ok(())
}

#[cfg(feature = "alloc")]
pub fn to_vec_le(bytes: &[u8]) -> Vec<u8> {
    bytes.to_vec()
}
