//! BIP32 / SLIP10 path parsing + per-curve policy.
//!
//! Format: `m/44'/1729'/0'/0'` or without leading `m/` (`44'/0'/0'`).
//! Returns raw `u32` indexes with hardened bit `0x8000_0000` set.
//! Pure `no_std` + `alloc` for the string renderer; parser works on `&str`.

use crate::error::{Error, Result};
use crate::hw::coin::{CoinProfile, HwCurve};

#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// Hardened flag.
pub const HARDENED_BIT: u32 = 0x8000_0000;
/// Max index without hardened bit (2^31 - 1).
pub const MAX_UNHARDENED: u32 = 0x7FFF_FFFF;

/// True when `index` carries the hardened bit.
pub const fn is_hardened(index: u32) -> bool {
    index & HARDENED_BIT != 0
}

/// Parse `m/44'/1729'/0'/0'` (or `44'/1729'/0'/0'`) into raw indexes.
///
/// Errors: empty, bad number, index `>= 2^31`, trailing `/`, empty component.
pub fn parse_path(path: &str) -> Result<Vec<u32>> {
    #[cfg(feature = "alloc")]
    {
        let t = path.trim();
        // `m` alone is the master key.
        if t == "m" {
            return Ok(Vec::new());
        }
        let s = t.strip_prefix('m').unwrap_or(t);
        let s = s.strip_prefix('/').unwrap_or(s);
        if s.is_empty() {
            return Err(Error::InvalidPath);
        }
        let mut out = Vec::new();
        for comp in s.split('/') {
            if comp.is_empty() {
                return Err(Error::InvalidPath);
            }
            let (num, hardened) = match comp.strip_suffix('\'').or_else(|| comp.strip_suffix('h')) {
                Some(n) => (n, true),
                None => (comp, false),
            };
            if num.is_empty() {
                return Err(Error::InvalidPath);
            }
            if num.len() > 10 || !num.bytes().all(|b| b.is_ascii_digit()) {
                return Err(Error::InvalidPath);
            }
            let mut v: u32 = 0;
            for b in num.bytes() {
                v = v.saturating_mul(10).saturating_add((b - b'0') as u32);
                if v > MAX_UNHARDENED {
                    return Err(Error::InvalidPath);
                }
            }
            out.push(if hardened { v | HARDENED_BIT } else { v });
        }
        Ok(out)
    }
    #[cfg(not(feature = "alloc"))]
    {
        let _ = path;
        Err(Error::Unimplemented)
    }
}

/// Render raw indexes back to `m/44'/0'/0` form.
#[cfg(feature = "alloc")]
pub fn path_to_string(path: &[u32]) -> String {
    if path.is_empty() {
        return String::from("m");
    }
    let mut s = String::from("m");
    for i in path {
        s.push('/');
        let v = i & !HARDENED_BIT;
        // tiny u32 -> decimal without `format!` (keeps `no_std` clean).
        let mut buf = [0u8; 10];
        let mut n = v;
        let mut len = 0usize;
        if n == 0 {
            buf[9] = b'0';
            len = 1;
        } else {
            let mut end = 10usize;
            while n > 0 {
                end -= 1;
                buf[end] = b'0' + (n % 10) as u8;
                n /= 10;
                len += 1;
            }
            buf.copy_within(end..10, 10 - len);
        }
        for b in &buf[10 - len..10] {
            s.push(*b as char);
        }
        if is_hardened(*i) {
            s.push('\'');
        }
    }
    s
}

/// Validate `path` (already parsed) against a coin's curve policy:
/// - secp256k1/BIP32: anything goes (purpose'/coin'/account' shape checked by caller).
/// - SLIP10 ed25519 / nist / kholaw: every index MUST be hardened.
pub fn validate_for_curve(path: &[u32], curve: HwCurve) -> Result<()> {
    if curve.allows_unhardened_suffix() {
        return Ok(());
    }
    if path.iter().all(|i| is_hardened(*i)) {
        Ok(())
    } else {
        Err(Error::InvalidPath)
    }
}

/// Validate full `m/purpose'/slip44'/account'/suffix...` shape for `coin`.
pub fn validate_for_coin(path: &[u32], coin: &CoinProfile) -> Result<()> {
    if path.len() < 3 {
        return Err(Error::InvalidPath);
    }
    if path[0] != (coin.purpose | HARDENED_BIT) || path[1] != (coin.slip44 | HARDENED_BIT) {
        return Err(Error::InvalidPath);
    }
    validate_for_curve(path, coin.curve)
}
