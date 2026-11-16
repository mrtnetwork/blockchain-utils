//! BIP-340 / BIP-327 tagged hashes.

use crate::hash::sha256::Sha256;

/// Tagged hash. Computed directly on the hasher (no `HashResult`) so there
/// is no silent-zero fallback path — a failure cannot yield a predictable
/// nonce. Callers needing `?` propagation (e.g. `nonce_generate` without
/// `rand`) handle `sha256()` errors at their own layer.
pub fn tagged_hash(tag: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut th = Sha256::new();
    th.update(tag);
    let tag_hash = th.finalize();
    let mut h = Sha256::new();
    h.update(&tag_hash);
    h.update(&tag_hash);
    h.update(msg);
    h.finalize()
}

pub fn xor32(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}
