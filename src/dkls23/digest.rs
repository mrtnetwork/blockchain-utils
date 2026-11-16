//! Tagged hash oracles: SHA-256 with length-delimited encoding.
//!
//! Encoding (shared with interoperable deployments so digests match
//! byte-for-byte):
//! `len(tag)||tag||len(c0)||c0||…`, each length an 8-byte big-endian
//! `u64`. Scalar derivation reduces the 32-byte digest mod the curve
//! order ([`DklsScalar::from_bytes_mod_order`]); point derivation is
//! intentionally *not* provided here (base OT derives its blinding point
//! from X25519 instead, keeping this crate free of hash-to-curve).

use super::curve_id::{CurveId, DklsScalar};
use super::error::{DklsError, DklsResult};

/// Length-delimited tagged SHA-256. Pure `no_std`, allocation-light.
pub fn tagged_hash(tag: &[u8], components: &[&[u8]]) -> [u8; 32] {
    let mut h = crate::hash::sha256::Sha256::new();
    h.update(&(tag.len() as u64).to_be_bytes());
    h.update(tag);
    for c in components {
        h.update(&(*c).len().to_be_bytes());
        h.update(c);
    }
    h.finalize()
}

/// Tagged hash reduced to a curve scalar (Fiat–Shamir challenges, DLog
/// proofs, zero-share fragments).
pub fn tagged_hash_scalar(curve: CurveId, tag: &[u8], components: &[&[u8]]) -> DklsScalar {
    DklsScalar::from_bytes_mod_order(curve, &tagged_hash(tag, components))
}

/// Expand a seed with a tag + 32-bit BE counter into `out` bytes
/// (MGF-style PRG for OT extension and zero shares).
pub fn tagged_expand(tag: &[u8], seed: &[u8], context: &[u8], out: &mut [u8]) {
    let mut counter = 0u32;
    let mut at = 0usize;
    while at < out.len() {
        let mut h = crate::hash::sha256::Sha256::new();
        h.update(&(tag.len() as u64).to_be_bytes());
        h.update(tag);
        h.update(&(seed.len() as u64).to_be_bytes());
        h.update(seed);
        h.update(&(context.len() as u64).to_be_bytes());
        h.update(context);
        h.update(&counter.to_be_bytes());
        let block = h.finalize();
        let take = core::cmp::min(block.len(), out.len() - at);
        out[at..at + take].copy_from_slice(&block[..take]);
        at += take;
        counter = counter.wrapping_add(1);
    }
}

/// Scalar lift of [`tagged_expand`] (reduces each 32-byte block and adds).
pub fn expand_to_scalar(
    curve: CurveId,
    tag: &[u8],
    seed: &[u8],
    context: &[u8],
    limbs: usize,
) -> DklsResult<DklsScalar> {
    if limbs == 0 {
        return Err(DklsError::InvalidLength);
    }
    let mut acc = DklsScalar::zero(curve);
    let mut buf = [0u8; 32];
    for i in 0..limbs {
        let mut ctx = alloc::vec::Vec::with_capacity(context.len() + 4);
        ctx.extend_from_slice(context);
        ctx.extend_from_slice(&(i as u32).to_be_bytes());
        tagged_expand(tag, seed, &ctx, &mut buf);
        acc = acc.add(&DklsScalar::from_bytes_mod_order(curve, &buf));
    }
    crate::bytes::zeroize(&mut buf);
    Ok(acc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn empty_tagged_hash_matches_manual_sha256() {
        let got = tagged_hash(b"t", &[b"a", b"bc"]);
        let mut raw = Vec::new();
        raw.extend_from_slice(&1u64.to_be_bytes());
        raw.extend_from_slice(b"t");
        raw.extend_from_slice(&1u64.to_be_bytes());
        raw.extend_from_slice(b"a");
        raw.extend_from_slice(&2u64.to_be_bytes());
        raw.extend_from_slice(b"bc");
        let expect = crate::hash::sha256::sha256(&raw).unwrap();
        assert_eq!(got, expect);
    }

    #[test]
    fn expand_is_deterministic_and_counter_chained() {
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        tagged_expand(b"x", b"seed", b"ctx", &mut a);
        tagged_expand(b"x", b"seed", b"ctx", &mut b);
        assert_eq!(a, b);
        let mut c = [0u8; 64];
        tagged_expand(b"x", b"seed", b"other", &mut c);
        assert_ne!(a, c);
    }

    /// Independently pinned with Python `hashlib` (the same encoding the
    /// interoperable deployments specify): `len||tag||len||c0||…` (u64 BE)
    /// under SHA-256. Guards transcript byte-identity across impls.
    #[test]
    fn pinned_vectors_match_independent_sha256() {
        fn hex(s: &str) -> [u8; 32] {
            let mut o = [0u8; 32];
            for i in 0..32 {
                o[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
            }
            o
        }
        let mut salt = [0u8; 64];
        for (i, b) in salt.iter_mut().enumerate() {
            *b = i as u8;
        }
        assert_eq!(
            tagged_hash(b"dkls23/commitment/v1", &[&salt, b"hello dkls23"]),
            hex("b67ec96818671b0d0dd4429eb4c64850486f447a2b2e0e4b83a861773df7e1f0")
        );
        assert_eq!(
            tagged_hash(b"dkls23/mul/gadget/v1", &[b"session-1"]),
            hex("4f158c1fc02367ad0d83ff8d8c7118ee4c7ddada4bb04e87acb018e7d92a65b2")
        );
    }

    #[test]
    fn scalar_reduce_never_zero_divides() {        // Zero digest still maps to the zero scalar without panicking.
        let s = DklsScalar::from_bytes_mod_order(CurveId::K1, &[0u8; 32]);
        assert!(s.is_zero());
        let t = tagged_hash_scalar(CurveId::R1, b"dkls23/commitment/v1", &[b"msg"]);
        let _ = t.to_array_be();
    }
}
