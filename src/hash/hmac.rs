//! HMAC (RFC 2104) – works with any [`Digest`] that is [`HmacCapable`].
//!
//! Pure `no_std`, zero-dependency.

use super::digest::{Digest, HmacCapable};
use super::error::{HashError, HashResult};
use super::sha256::{Sha256, SHA256_LEN};
use super::sha512::{Sha512, BLOCK_SIZE as SHA512_BLOCK, SHA512_LEN};

/// Generic HMAC context.
///
/// ```ignore
/// let mut mac = Hmac::<Sha256>::new(b"key")?;
/// mac.update(b"message");
/// let tag = mac.finalize_array()?;
/// ```
pub struct Hmac<D: Digest + HmacCapable> {
    inner: D,
    opad: [u8; 128], // max block we support
    block_size: usize,
    output_size: usize,
}

impl<D: Digest + HmacCapable> Hmac<D> {
    /// Create a new HMAC context with the given key.
    pub fn new(key: &[u8]) -> HashResult<Self> {
        let block = D::BLOCK_SIZE;
        if block > 128 {
            return Err(HashError::Unsupported);
        }

        let mut k = [0u8; 128];
        if key.len() > block {
            // Hash long keys
            let mut tmp = [0u8; 64];
            if D::OUTPUT_SIZE > 64 {
                return Err(HashError::Unsupported);
            }
            D::hash_into(key, &mut tmp[..D::OUTPUT_SIZE])?;
            k[..D::OUTPUT_SIZE].copy_from_slice(&tmp[..D::OUTPUT_SIZE]);
        } else {
            k[..key.len()].copy_from_slice(key);
        }

        let mut ipad = [0x36u8; 128];
        let mut opad = [0x5cu8; 128];
        for i in 0..block {
            ipad[i] ^= k[i];
            opad[i] ^= k[i];
        }

        let mut inner = D::new();
        inner.update(&ipad[..block]);

        Ok(Self {
            inner,
            opad,
            block_size: block,
            output_size: D::OUTPUT_SIZE,
        })
    }

    /// Absorb message data.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalize into `out` (must be ≥ OUTPUT_SIZE).
    pub fn finalize_into(self, out: &mut [u8]) -> HashResult<()> {
        if out.len() < self.output_size {
            return Err(HashError::OutputTooSmall);
        }
        let mut inner_hash = [0u8; 64];
        self.inner
            .finalize_into(&mut inner_hash[..self.output_size])?;

        let mut outer = D::new();
        outer.update(&self.opad[..self.block_size]);
        outer.update(&inner_hash[..self.output_size]);
        outer.finalize_into(out)
    }

    /// Finalize and return a 64-byte buffer (leading OUTPUT_SIZE bytes are valid).
    pub fn finalize_array(self) -> HashResult<[u8; 64]> {
        let mut buf = [0u8; 64];
        let size = self.output_size;
        self.finalize_into(&mut buf[..size])?;
        Ok(buf)
    }
}

/// Generic one-shot HMAC.
pub fn hmac<D: Digest + HmacCapable>(key: &[u8], message: &[u8], out: &mut [u8]) -> HashResult<()> {
    let mut mac = Hmac::<D>::new(key)?;
    mac.update(message);
    mac.finalize_into(out)
}

/// HMAC-SHA256 one-shot. Returns fixed 32-byte array.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> HashResult<[u8; SHA256_LEN]> {
    let mut out = [0u8; SHA256_LEN];
    hmac::<Sha256>(key, message, &mut out)?;
    Ok(out)
}

/// HMAC-SHA512 one-shot. Returns fixed 64-byte array.
pub fn hmac_sha512(key: &[u8], message: &[u8]) -> HashResult<[u8; SHA512_LEN]> {
    // Sha512 must implement Digest + HmacCapable
    let mut out = [0u8; SHA512_LEN];
    // Temporary direct implementation until Sha512 implements the trait
    hmac_sha512_direct(key, message, &mut out)?;
    Ok(out)
}

fn hmac_sha512_direct(key: &[u8], message: &[u8], out: &mut [u8]) -> HashResult<()> {
    if out.len() < SHA512_LEN {
        return Err(HashError::OutputTooSmall);
    }
    let block = SHA512_BLOCK;
    let mut k = [0u8; SHA512_BLOCK];
    if key.len() > block {
        let h = super::sha512::sha512(key).map_err(|_| HashError::Failure("sha512"))?;
        k[..SHA512_LEN].copy_from_slice(&h);
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; SHA512_BLOCK];
    let mut opad = [0x5cu8; SHA512_BLOCK];
    for i in 0..block {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }

    let mut inner = Sha512::new();
    inner.update(&ipad);
    inner.update(message);
    let inner_hash = inner.finalize();

    let mut outer = Sha512::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    let result = outer.finalize();
    out[..SHA512_LEN].copy_from_slice(&result);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4231_case1_sha256() {
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let expected = [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
            0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
            0x2e, 0x32, 0xcf, 0xf7,
        ];
        let result = hmac_sha256(&key, data).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn rfc4231_case2_sha256() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected = [
            0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95,
            0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9,
            0x64, 0xec, 0x38, 0x43,
        ];
        let result = hmac_sha256(key, data).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn generic_hmac_sha256() {
        let mut out = [0u8; 32];
        hmac::<Sha256>(b"key", b"message", &mut out).unwrap();
        let expected = hmac_sha256(b"key", b"message").unwrap();
        assert_eq!(out, expected);
    }
}
