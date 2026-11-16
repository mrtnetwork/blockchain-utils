//! Streaming hash + HMAC FFI.
//!
//! Holds real hasher objects so `save_state` captures compression state
//! (including HMAC keyed ipad), matching the reference implementation.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ptr;
use core::slice;

use crate::curve::jubjub::JubJubPoint;
use crate::curve::pallas::{to_bytes_pasta, Fe as PallasFe, PallasPoint};
use crate::curve::traits::CurvePoint;
use crate::hash::blake2b::{Blake2TreeParams, Blake2b, BLAKE2B_MAX_LEN};
use crate::hash::blake2s::{Blake2s, Blake2sTreeParams, BLAKE2S_MAX_LEN};
use crate::hash::keccak::Keccak;
use crate::hash::md4::Md4;
use crate::hash::md5::Md5;
use crate::hash::pedersen::{PedersenHash, Personalization};
use crate::hash::poseidon::{poseidon_hash, poseidon_hash_two, Poseidon};
#[cfg(feature = "poseidon-bn254")]
use crate::hash::poseidon_bn254::hash_le;
use crate::hash::ripemd160::Ripemd160;
use crate::hash::ripemd_ext::{Ripemd128, Ripemd256, Ripemd320};
use crate::hash::sha1::Sha1;
use crate::hash::sha256::Sha256;
use crate::hash::sha512::Sha512;
use crate::hash::sinsemilla::{sinsemilla_commit, sinsemilla_short_commit, Sinsemilla};
use crate::hash::xxhash;

// ---- Algorithm IDs (stable ABI) ----
pub const BU_HASH_SHA256: u32 = 1;
pub const BU_HASH_SHA224: u32 = 2;
pub const BU_HASH_SHA512: u32 = 3;
pub const BU_HASH_SHA384: u32 = 4;
pub const BU_HASH_SHA512_256: u32 = 5;
pub const BU_HASH_SHA1: u32 = 6;
pub const BU_HASH_RIPEMD160: u32 = 7;
pub const BU_HASH_RIPEMD128: u32 = 35;
pub const BU_HASH_RIPEMD256: u32 = 36;
pub const BU_HASH_RIPEMD320: u32 = 37;
pub const BU_HASH_MD5: u32 = 8;
pub const BU_HASH_MD4: u32 = 9;
pub const BU_HASH_KECCAK256: u32 = 10;
pub const BU_HASH_KECCAK224: u32 = 11;
pub const BU_HASH_KECCAK384: u32 = 12;
pub const BU_HASH_KECCAK512: u32 = 13;
pub const BU_HASH_SHA3_256: u32 = 14;
pub const BU_HASH_SHA3_512: u32 = 15;
pub const BU_HASH_SHAKE128: u32 = 16;
pub const BU_HASH_SHAKE256: u32 = 17;
pub const BU_HASH_SHA3_224: u32 = 18;
pub const BU_HASH_SHA3_384: u32 = 19;
pub const BU_HASH_BLAKE2B: u32 = 20;
pub const BU_HASH_BLAKE2S: u32 = 21;
pub const BU_HASH_XXH32: u32 = 30;
pub const BU_HASH_XXH64: u32 = 31;
pub const BU_HASH_XXH3_64: u32 = 32;
pub const BU_HASH_XXH3_128: u32 = 33;
pub const BU_HASH_XXH3_256: u32 = 34;

pub const BU_HASH_FLAG_HMAC: u32 = 1;
pub const BU_HASH_MAX_DIGEST: usize = 64;
pub const BU_HASH_MAX_XOF: usize = 1024;

#[repr(C)]
pub struct BuHashConfig {
    pub algo: u32,
    pub digest_len: u32,
    pub flags: u32,
    pub key: *const u8,
    pub key_len: usize,
    pub salt: *const u8,
    pub salt_len: usize,
    pub personal: *const u8,
    pub personal_len: usize,
    pub seed: u64,
    pub fanout: u8,
    pub max_depth: u8,
    pub leaf_size: u32,
    pub node_offset: u64,
    pub node_depth: u8,
    pub inner_digest_length: u8,
    pub last_node: u8,
    pub _pad: [u8; 5],
}

/// Streaming engine — one concrete hasher.
#[derive(Clone)]
enum Engine {
    Sha256(Sha256),
    Sha512(Sha512),
    Sha1(Sha1),
    Md5(Md5),
    Md4(Md4),
    Ripemd160(Ripemd160),
    Ripemd128(Ripemd128),
    Ripemd256(Ripemd256),
    Ripemd320(Ripemd320),
    Keccak(Keccak),
    Blake2b(Blake2b),
    Blake2s(Blake2s),
    /// Algorithms without a long-lived streaming type: accumulate input.
    Accum {
        algo: u32,
        digest_len: usize,
        seed: u64,
        buf: Vec<u8>,
    },
}

impl Engine {
    fn update(&mut self, data: &[u8]) {
        match self {
            Engine::Sha256(h) => h.update(data),
            Engine::Sha512(h) => h.update(data),
            Engine::Sha1(h) => h.update(data),
            Engine::Md5(h) => h.update(data),
            Engine::Md4(h) => h.update(data),
            Engine::Ripemd160(h) => h.update(data),
            Engine::Ripemd128(h) => h.update(data),
            Engine::Ripemd256(h) => h.update(data),
            Engine::Ripemd320(h) => h.update(data),
            Engine::Keccak(h) => h.update(data),
            Engine::Blake2b(h) => h.update(data),
            Engine::Blake2s(h) => h.update(data),
            Engine::Accum { buf, .. } => buf.extend_from_slice(data),
        }
    }

    fn reset(&mut self, factory: &EngineFactory) {
        match self {
            Engine::Blake2b(h) => {
                h.reset();
                return;
            }
            Engine::Blake2s(h) => {
                h.reset();
                return;
            }
            _ => {}
        }
        *self = factory.make_plain();
    }

    /// Finish into `out`.
    /// Fixed digests: clone-then-finalize (idempotent).
    /// SHAKE/XOF (`out_len == 0`): advances the sponge (reference parity — 2nd digest differs).
    fn finish_into(&mut self, out: &mut [u8]) {
        match self {
            Engine::Sha256(h) => {
                let c = h.clone();
                c.finalize_into(out);
            }
            Engine::Sha512(h) => {
                let c = h.clone();
                c.finalize_into(out);
            }
            Engine::Sha1(h) => {
                let c = h.clone();
                let _ = c.finalize_into(out);
            }
            Engine::Md5(h) => {
                let c = h.clone();
                let _ = c.finalize_into(out);
            }
            Engine::Md4(h) => {
                let c = h.clone();
                let _ = c.finalize_into(out);
            }
            Engine::Ripemd160(h) => {
                let c = h.clone();
                c.finalize_into(out);
            }
            Engine::Ripemd128(h) => {
                let c = h.clone();
                c.finalize_into(out);
            }
            Engine::Ripemd256(h) => {
                let c = h.clone();
                c.finalize_into(out);
            }
            Engine::Ripemd320(h) => {
                let c = h.clone();
                c.finalize_into(out);
            }
            Engine::Keccak(h) => {
                if h.is_xof() {
                    let _ = h.finish_into_mut(out);
                } else {
                    // Fixed Keccak/SHA3: idempotent via clone (reference state tests).
                    let c = h.clone();
                    let _ = c.finalize_into(out);
                }
            }
            Engine::Blake2b(h) => {
                let c = h.clone();
                c.finalize_into(out);
            }
            Engine::Blake2s(h) => {
                let c = h.clone();
                let _ = c.finalize_into(out);
            }
            Engine::Accum {
                algo,
                digest_len,
                seed,
                buf,
            } => {
                finish_accum(*algo, *digest_len, *seed, buf, out);
            }
        }
    }

    fn clean(&mut self) {
        // Re-create empty equivalent via zeroing buffer paths where possible.
        match self {
            Engine::Accum { buf, .. } => {
                for b in buf.iter_mut() {
                    *b = 0;
                }
                buf.clear();
            }
            other => {
                // Clone-reset handled by replacing engine from factory at call sites.
                let _ = other;
            }
        }
    }
}

fn finish_accum(algo: u32, digest_len: usize, seed: u64, data: &[u8], out: &mut [u8]) {
    let n = digest_len.min(out.len());
    match algo {
        BU_HASH_XXH32 => {
            let d = xxhash::xxh32(data, seed as u32);
            if n >= 4 {
                out[..4].copy_from_slice(&d.to_le_bytes());
            }
        }
        BU_HASH_XXH64 => {
            // reference XXHash64: digestLength = (bitLength/64).ceil()*8 lanes,
            // each lane = XXH64(data, seed=lane_index) as little-endian u64.
            let rounds = n / 8;
            if rounds == 0 {
                // single partial? ignore
            } else if rounds == 1 {
                let d = xxhash::xxh64(data, seed);
                out[..8].copy_from_slice(&d.to_le_bytes());
            } else {
                for i in 0..rounds {
                    let d = xxhash::xxh64(data, i as u64);
                    out[i * 8..(i + 1) * 8].copy_from_slice(&d.to_le_bytes());
                }
            }
        }
        BU_HASH_XXH3_64 => {
            let d = xxhash::xxh3_64(data, seed);
            if n >= 8 {
                out[..8].copy_from_slice(&d.to_le_bytes());
            }
        }
        BU_HASH_XXH3_128 => {
            if let Ok(d) = xxhash::xxh3_128_bytes(data, seed) {
                out[..n.min(16)].copy_from_slice(&d[..n.min(16)]);
            }
        }
        BU_HASH_XXH3_256 => {
            if let Ok(d) = xxhash::xxh3_256_bytes(data, seed) {
                out[..n.min(32)].copy_from_slice(&d[..n.min(32)]);
            }
        }
        _ => {}
    }
}

/// How to construct a fresh engine for a given algo/config.
#[derive(Clone)]
struct EngineFactory {
    algo: u32,
    digest_len: usize,
    block_size: usize,
    key: Vec<u8>,
    salt: Option<[u8; 16]>,
    personal: Option<[u8; 16]>,
    seed: u64,
    tree_b: Blake2TreeParams,
    tree_s: Blake2sTreeParams,
}

impl EngineFactory {
    fn make_plain(&self) -> Engine {
        match self.algo {
            BU_HASH_SHA256 => Engine::Sha256(Sha256::new()),
            BU_HASH_SHA224 => Engine::Sha256(Sha256::new_224()),
            BU_HASH_SHA512 => Engine::Sha512(Sha512::new()),
            BU_HASH_SHA384 => Engine::Sha512(Sha512::new_384()),
            BU_HASH_SHA512_256 => Engine::Sha512(Sha512::new_512_256()),
            BU_HASH_SHA1 => Engine::Sha1(Sha1::new()),
            BU_HASH_MD5 => Engine::Md5(Md5::new()),
            BU_HASH_MD4 => Engine::Md4(Md4::new()),
            BU_HASH_RIPEMD160 => Engine::Ripemd160(Ripemd160::new()),
            BU_HASH_RIPEMD128 => Engine::Ripemd128(Ripemd128::new()),
            BU_HASH_RIPEMD256 => Engine::Ripemd256(Ripemd256::new()),
            BU_HASH_RIPEMD320 => Engine::Ripemd320(Ripemd320::new()),
            BU_HASH_KECCAK256 => Engine::Keccak(Keccak::keccak256()),
            BU_HASH_KECCAK224 => Engine::Keccak(Keccak::keccak224()),
            BU_HASH_KECCAK384 => Engine::Keccak(Keccak::keccak384()),
            BU_HASH_KECCAK512 => Engine::Keccak(Keccak::keccak512()),
            BU_HASH_SHA3_256 => Engine::Keccak(Keccak::sha3_256()),
            BU_HASH_SHA3_512 => Engine::Keccak(Keccak::sha3_512()),
            BU_HASH_SHA3_224 => Engine::Keccak(Keccak::sha3_224()),
            BU_HASH_SHA3_384 => Engine::Keccak(Keccak::sha3_384()),
            BU_HASH_SHAKE128 => {
                // Custom length XOF — sponge with out_len=0, finish uses out.len()
                let k = Keccak::shake128();
                // out_len stays 0 for XOF
                let _ = self.digest_len;
                Engine::Keccak(k)
            }
            BU_HASH_SHAKE256 => {
                let k = Keccak::shake256();
                Engine::Keccak(k)
            }
            BU_HASH_BLAKE2B => {
                let key = if self.key.is_empty() {
                    None
                } else {
                    Some(self.key.as_slice())
                };
                Engine::Blake2b(Blake2b::new_with_tree(
                    self.digest_len,
                    key,
                    self.salt.as_ref(),
                    self.personal.as_ref(),
                    Some(&self.tree_b),
                ))
            }
            BU_HASH_BLAKE2S => {
                let key = if self.key.is_empty() {
                    None
                } else {
                    Some(self.key.as_slice())
                };
                Engine::Blake2s(
                    Blake2s::new_with_tree(self.digest_len, key, Some(&self.tree_s))
                        .unwrap_or_else(|_| Blake2s::new_256()),
                )
            }
            BU_HASH_XXH32 | BU_HASH_XXH64 | BU_HASH_XXH3_64 | BU_HASH_XXH3_128
            | BU_HASH_XXH3_256 => Engine::Accum {
                algo: self.algo,
                digest_len: self.digest_len,
                seed: self.seed,
                buf: Vec::new(),
            },
            _ => Engine::Sha256(Sha256::new()),
        }
    }
}

/// HMAC: inner engine already keyed with ipad; outer template keyed with opad.
#[derive(Clone)]
struct HmacEngine {
    inner: Engine,
    /// Outer hasher after absorbing opad (ready for inner digest).
    outer_keyed: Engine,
    digest_len: usize,
}

impl HmacEngine {
    fn new(factory: &EngineFactory, key: &[u8]) -> Self {
        let bs = factory.block_size;
        let dl = factory.digest_len;

        // Normalize key
        let mut k = alloc::vec![0u8; bs];
        if key.len() > bs {
            let mut e = factory.make_plain();
            e.update(key);
            let mut hk = [0u8; 64];
            e.finish_into(&mut hk[..dl.min(64)]);
            k[..dl.min(bs)].copy_from_slice(&hk[..dl.min(bs)]);
        } else {
            k[..key.len()].copy_from_slice(key);
        }

        let mut ipad = alloc::vec![0x36u8; bs];
        let mut opad = alloc::vec![0x5cu8; bs];
        for i in 0..bs {
            ipad[i] ^= k[i];
            opad[i] ^= k[i];
        }

        let mut inner = factory.make_plain();
        inner.update(&ipad);

        let mut outer_keyed = factory.make_plain();
        outer_keyed.update(&opad);

        // wipe pads
        for b in ipad.iter_mut().chain(opad.iter_mut()).chain(k.iter_mut()) {
            *b = 0;
        }

        Self {
            inner,
            outer_keyed,
            digest_len: dl,
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finish_into(&self, out: &mut [u8]) {
        // Clone so HMAC finish stays non-consuming / idempotent for fixed digests.
        let mut idig = [0u8; 64];
        let mut inner = self.inner.clone();
        inner.finish_into(&mut idig[..self.digest_len.min(64)]);
        let mut outer = self.outer_keyed.clone();
        outer.update(&idig[..self.digest_len]);
        outer.finish_into(out);
        for b in idig.iter_mut() {
            *b = 0;
        }
    }
}

struct OwnedParams {
    factory: EngineFactory,
    hmac: bool,
    key: Vec<u8>,
}

pub struct BuHash {
    params: OwnedParams,
    plain: Option<Engine>,
    hmac: Option<HmacEngine>,
    /// After [`bu_hash_clean`], all ops no-op (reference clean behavior).
    cleaned: bool,
}

/// Opaque saved compression state.
pub struct BuHashState {
    plain: Option<Engine>,
    hmac: Option<HmacEngine>,
    algo: u32,
    digest_len: usize,
    is_hmac: bool,
}

fn default_digest_len(algo: u32) -> Option<usize> {
    Some(match algo {
        BU_HASH_SHA256 | BU_HASH_SHA512_256 | BU_HASH_KECCAK256 | BU_HASH_SHA3_256 => 32,
        BU_HASH_SHA224 | BU_HASH_KECCAK224 | BU_HASH_SHA3_224 => 28,
        BU_HASH_SHA512 | BU_HASH_KECCAK512 | BU_HASH_SHA3_512 => 64,
        BU_HASH_SHA384 | BU_HASH_KECCAK384 | BU_HASH_SHA3_384 => 48,
        BU_HASH_SHA1 | BU_HASH_RIPEMD160 => 20,
        BU_HASH_RIPEMD128 => 16,
        BU_HASH_RIPEMD256 => 32,
        BU_HASH_RIPEMD320 => 40,
        BU_HASH_MD5 | BU_HASH_MD4 => 16,
        BU_HASH_BLAKE2B => 64,
        BU_HASH_BLAKE2S => 32,
        BU_HASH_XXH32 => 4,
        BU_HASH_XXH64 | BU_HASH_XXH3_64 => 8,
        BU_HASH_XXH3_128 => 16,
        BU_HASH_XXH3_256 => 32,
        BU_HASH_SHAKE128 | BU_HASH_SHAKE256 => return None,
        _ => return None,
    })
}

fn block_size_for(algo: u32) -> Option<usize> {
    Some(match algo {
        BU_HASH_SHA256 | BU_HASH_SHA224 | BU_HASH_SHA1 | BU_HASH_RIPEMD160 | BU_HASH_MD5
        | BU_HASH_MD4 | BU_HASH_BLAKE2S | BU_HASH_RIPEMD128 | BU_HASH_RIPEMD256
        | BU_HASH_RIPEMD320 => 64,
        BU_HASH_SHA512 | BU_HASH_SHA384 | BU_HASH_SHA512_256 | BU_HASH_BLAKE2B => 128,
        BU_HASH_KECCAK256 | BU_HASH_SHA3_256 | BU_HASH_SHAKE256 => 136,
        BU_HASH_KECCAK224 | BU_HASH_SHA3_224 => 144,
        BU_HASH_KECCAK384 | BU_HASH_SHA3_384 => 104,
        BU_HASH_KECCAK512 | BU_HASH_SHA3_512 => 72,
        BU_HASH_SHAKE128 => 168,
        BU_HASH_XXH32 | BU_HASH_XXH64 | BU_HASH_XXH3_64 | BU_HASH_XXH3_128 | BU_HASH_XXH3_256 => 32,
        _ => return None,
    })
}

fn hmac_supported(algo: u32) -> bool {
    matches!(
        algo,
        BU_HASH_SHA256
            | BU_HASH_SHA224
            | BU_HASH_SHA512
            | BU_HASH_SHA384
            | BU_HASH_SHA512_256
            | BU_HASH_SHA1
            | BU_HASH_MD5
            | BU_HASH_MD4
            | BU_HASH_RIPEMD160
            | BU_HASH_RIPEMD128
            | BU_HASH_RIPEMD256
            | BU_HASH_RIPEMD320
            | BU_HASH_KECCAK256
            | BU_HASH_KECCAK512
            | BU_HASH_SHA3_256
            | BU_HASH_SHA3_512
            | BU_HASH_BLAKE2B
            | BU_HASH_BLAKE2S
    )
}

fn parse_config(cfg: &BuHashConfig) -> Option<OwnedParams> {
    let hmac = (cfg.flags & BU_HASH_FLAG_HMAC) != 0;
    if cfg.flags & !BU_HASH_FLAG_HMAC != 0 {
        return None;
    }
    let algo = cfg.algo;
    let block_size = block_size_for(algo)?;

    let digest_len = if matches!(algo, BU_HASH_SHAKE128 | BU_HASH_SHAKE256) {
        if cfg.digest_len == 0 {
            return None;
        }
        let d = cfg.digest_len as usize;
        if d == 0 || d > BU_HASH_MAX_XOF {
            return None;
        }
        d
    } else if cfg.digest_len == 0 {
        default_digest_len(algo)?
    } else {
        let d = cfg.digest_len as usize;
        if matches!(algo, BU_HASH_BLAKE2B) {
            if !(1..=BLAKE2B_MAX_LEN).contains(&d) {
                return None;
            }
        } else if matches!(algo, BU_HASH_BLAKE2S) {
            if !(1..=BLAKE2S_MAX_LEN).contains(&d) {
                return None;
            }
        } else if matches!(algo, BU_HASH_XXH64) {
            // reference multi-lane: 8..=64 bytes, multiple of 8
            if d == 0 || d > 64 || !d.is_multiple_of(8) {
                return None;
            }
        } else if matches!(algo, BU_HASH_XXH32) {
            if d != 4 {
                return None;
            }
        } else if let Some(def) = default_digest_len(algo) {
            if d != def {
                return None;
            }
        }
        d
    };

    if hmac && (!hmac_supported(algo) || cfg.key.is_null() || cfg.key_len == 0) {
        return None;
    }

    let key = if cfg.key_len == 0 || cfg.key.is_null() {
        Vec::new()
    } else {
        if !hmac && !matches!(algo, BU_HASH_BLAKE2B | BU_HASH_BLAKE2S) {
            // key only for HMAC or Blake2
            return None;
        }
        if !hmac {
            let max = if algo == BU_HASH_BLAKE2B { 64 } else { 32 };
            if cfg.key_len > max {
                return None;
            }
        }
        unsafe { slice::from_raw_parts(cfg.key, cfg.key_len).to_vec() }
    };

    // Blake2 salt/personal: reject if longer than RFC size; zero-pad if shorter (reference parity).
    let salt_b: Option<[u8; 16]> = if cfg.salt_len == 0 || cfg.salt.is_null() {
        None
    } else if algo == BU_HASH_BLAKE2B {
        if cfg.salt_len > 16 {
            return None;
        }
        let mut s = [0u8; 16];
        unsafe {
            s[..cfg.salt_len].copy_from_slice(slice::from_raw_parts(cfg.salt, cfg.salt_len));
        }
        Some(s)
    } else {
        None
    };

    let personal_b: Option<[u8; 16]> = if cfg.personal_len == 0 || cfg.personal.is_null() {
        None
    } else if algo == BU_HASH_BLAKE2B {
        if cfg.personal_len > 16 {
            return None;
        }
        let mut p = [0u8; 16];
        unsafe {
            p[..cfg.personal_len]
                .copy_from_slice(slice::from_raw_parts(cfg.personal, cfg.personal_len));
        }
        Some(p)
    } else {
        None
    };

    let salt_s: Option<[u8; 8]> = if cfg.salt_len == 0 || cfg.salt.is_null() {
        None
    } else if algo == BU_HASH_BLAKE2S {
        if cfg.salt_len > 8 {
            return None;
        }
        let mut s = [0u8; 8];
        unsafe {
            s[..cfg.salt_len].copy_from_slice(slice::from_raw_parts(cfg.salt, cfg.salt_len));
        }
        Some(s)
    } else {
        None
    };

    let personal_s: Option<[u8; 8]> = if cfg.personal_len == 0 || cfg.personal.is_null() {
        None
    } else if algo == BU_HASH_BLAKE2S {
        if cfg.personal_len > 8 {
            return None;
        }
        let mut p = [0u8; 8];
        unsafe {
            p[..cfg.personal_len]
                .copy_from_slice(slice::from_raw_parts(cfg.personal, cfg.personal_len));
        }
        Some(p)
    } else {
        None
    };

    // Reject salt/personal for non-Blake2 algos
    if !matches!(algo, BU_HASH_BLAKE2B | BU_HASH_BLAKE2S)
        && ((cfg.salt_len > 0 && !cfg.salt.is_null())
            || (cfg.personal_len > 0 && !cfg.personal.is_null()))
    {
        return None;
    }

    let tree_b = if cfg.fanout == 0 && cfg.max_depth == 0 && cfg.leaf_size == 0 {
        Blake2TreeParams::default()
    } else {
        Blake2TreeParams {
            fanout: if cfg.fanout == 0 { 1 } else { cfg.fanout },
            max_depth: if cfg.max_depth == 0 { 1 } else { cfg.max_depth },
            leaf_size: cfg.leaf_size,
            node_offset: cfg.node_offset,
            node_depth: cfg.node_depth,
            inner_digest_length: cfg.inner_digest_length,
            last_node: cfg.last_node != 0,
        }
    };
    let tree_s = Blake2sTreeParams {
        fanout: tree_b.fanout,
        max_depth: tree_b.max_depth,
        leaf_size: tree_b.leaf_size,
        node_offset: tree_b.node_offset,
        node_depth: tree_b.node_depth,
        inner_digest_length: tree_b.inner_digest_length,
        last_node: tree_b.last_node,
        salt: salt_s,
        personal: personal_s,
    };

    let factory = EngineFactory {
        algo,
        digest_len,
        block_size,
        key: if hmac { Vec::new() } else { key.clone() },
        salt: salt_b,
        personal: personal_b,
        seed: cfg.seed,
        tree_b,
        tree_s,
    };

    Some(OwnedParams { factory, hmac, key })
}

// ---- C ABI ----

/// One-shot HMAC for any supported PRF (used by HKDF).
pub(crate) fn hmac_oneshot(algo: u32, key: &[u8], data: &[u8], out: &mut [u8]) -> bool {
    if !hmac_supported(algo) || key.is_empty() {
        return false;
    }
    let digest_len = match default_digest_len(algo) {
        Some(d) => d,
        None => return false,
    };
    if out.len() < digest_len {
        return false;
    }
    let block_size = match block_size_for(algo) {
        Some(b) => b,
        None => return false,
    };
    let factory = EngineFactory {
        algo,
        digest_len,
        block_size,
        key: Vec::new(),
        salt: None,
        personal: None,
        seed: 0,
        tree_b: Blake2TreeParams::default(),
        tree_s: Blake2sTreeParams::default(),
    };
    let mut mac = HmacEngine::new(&factory, key);
    mac.update(data);
    mac.finish_into(out);
    true
}

pub(crate) fn algo_digest_len(algo: u32) -> Option<usize> {
    default_digest_len(algo)
}

pub(crate) fn algo_hmac_supported(algo: u32) -> bool {
    hmac_supported(algo)
}

/// Flat-arg constructor for WASM (avoids #[repr(C)] struct packing across wasm32).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hash_new_simple(
    algo: u32,
    digest_len: u32,
    flags: u32,
    key: *const u8,
    key_len: usize,
    salt: *const u8,
    salt_len: usize,
    personal: *const u8,
    personal_len: usize,
    seed: u64,
    fanout: u8,
    max_depth: u8,
    leaf_size: u32,
    node_offset: u64,
    node_depth: u8,
    inner_digest_length: u8,
    last_node: u8,
) -> *mut BuHash {
    let cfg = BuHashConfig {
        algo,
        digest_len,
        flags,
        key,
        key_len,
        salt,
        salt_len,
        personal,
        personal_len,
        seed,
        fanout,
        max_depth,
        leaf_size,
        node_offset,
        node_depth,
        inner_digest_length,
        last_node,
        _pad: [0; 5],
    };
    bu_hash_new(&cfg)
}

#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hash_new(cfg: *const BuHashConfig) -> *mut BuHash {
    if cfg.is_null() {
        return ptr::null_mut();
    }
    match parse_config(&*cfg) {
        Some(params) => {
            let hmac = if params.hmac {
                Some(HmacEngine::new(&params.factory, &params.key))
            } else {
                None
            };
            let plain = if params.hmac {
                None
            } else {
                Some(params.factory.make_plain())
            };
            Box::into_raw(Box::new(BuHash {
                params,
                plain,
                hmac,
                cleaned: false,
            }))
        }
        None => ptr::null_mut(),
    }
}

#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hash_update(ptr: *mut BuHash, data: *const u8, len: usize) {
    if ptr.is_null() || len == 0 || data.is_null() {
        return;
    }
    let h = &mut *ptr;
    if h.cleaned {
        return;
    }
    let bytes = slice::from_raw_parts(data, len);
    if let Some(ref mut mac) = h.hmac {
        mac.update(bytes);
    } else if let Some(ref mut eng) = h.plain {
        eng.update(bytes);
    }
}

#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hash_reset(ptr: *mut BuHash) {
    if ptr.is_null() {
        return;
    }
    let h = &mut *ptr;
    if h.cleaned {
        return;
    }
    if h.params.hmac {
        h.hmac = Some(HmacEngine::new(&h.params.factory, &h.params.key));
    } else if let Some(ref mut eng) = h.plain {
        eng.reset(&h.params.factory);
    } else {
        h.plain = Some(h.params.factory.make_plain());
    }
}

#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hash_finish(ptr: *mut BuHash, out: *mut u8) {
    if ptr.is_null() || out.is_null() {
        return;
    }
    let h = &*ptr;
    let len = h.params.factory.digest_len.min(BU_HASH_MAX_XOF);
    bu_hash_finish_n(ptr, out, len);
}

/// Finish into `out[0..out_len]` (SHAKE/XOF uses `out_len` as squeeze length).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hash_finish_n(ptr: *mut BuHash, out: *mut u8, out_len: usize) {
    if ptr.is_null() || out.is_null() || out_len == 0 {
        return;
    }
    let h = &mut *ptr;
    if h.cleaned {
        return;
    }
    let len = out_len.min(BU_HASH_MAX_XOF);
    let out = slice::from_raw_parts_mut(out, len);
    if let Some(ref mac) = h.hmac {
        mac.finish_into(out);
    } else if let Some(ref mut eng) = h.plain {
        eng.finish_into(out);
    }
}

/// Wipe hasher and mark unusable (`clean()`).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hash_clean(ptr: *mut BuHash) {
    if ptr.is_null() {
        return;
    }
    let h = &mut *ptr;
    if let Some(ref mut eng) = h.plain {
        eng.clean();
    }
    h.plain = None;
    h.hmac = None;
    h.cleaned = true;
}

#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hash_free(ptr: *mut BuHash) {
    if !ptr.is_null() {
        drop(Box::from_raw(ptr));
    }
}

#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hash_digest_len(ptr: *const BuHash) -> usize {
    if ptr.is_null() {
        return 0;
    }
    unsafe { (*ptr).params.factory.digest_len }
}

#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hash_block_size(ptr: *const BuHash) -> usize {
    if ptr.is_null() {
        return 0;
    }
    unsafe { (*ptr).params.factory.block_size }
}

#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hash_algo(ptr: *const BuHash) -> u32 {
    if ptr.is_null() {
        return 0;
    }
    unsafe { (*ptr).params.factory.algo }
}

/// Snapshot compression state → opaque handle (`saveState`).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hash_save_state(ptr: *const BuHash) -> *mut BuHashState {
    if ptr.is_null() {
        return ptr::null_mut();
    }
    let h = &*ptr;
    Box::into_raw(Box::new(BuHashState {
        plain: h.plain.clone(),
        hmac: h.hmac.clone(),
        algo: h.params.factory.algo,
        digest_len: h.params.factory.digest_len,
        is_hmac: h.params.hmac,
    }))
}

/// Restore compression state from opaque handle.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hash_restore_state(ptr: *mut BuHash, state: *const BuHashState) -> i32 {
    if ptr.is_null() || state.is_null() {
        return 1;
    }
    let h = &mut *ptr;
    let s = &*state;
    if s.algo != h.params.factory.algo
        || s.digest_len != h.params.factory.digest_len
        || s.is_hmac != h.params.hmac
    {
        return 2;
    }
    h.plain = s.plain.clone();
    h.hmac = s.hmac.clone();
    0
}

/// Free + wipe saved state handle.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hash_free_state(state: *mut BuHashState) {
    if state.is_null() {
        return;
    }
    let mut s = Box::from_raw(state);
    if let Some(ref mut e) = s.plain {
        e.clean();
    }
    if let Some(ref mut m) = s.hmac {
        m.inner.clean();
        m.outer_keyed.clean();
    }
    drop(s);
}

/// Legacy byte-blob save (length-prefixed buffer of algo metadata only + not full engine).
/// Prefer [`bu_hash_save_state`] opaque handles.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hash_state_len(ptr: *const BuHash) -> usize {
    if ptr.is_null() {
        return 0;
    }
    // Opaque handle path does not need length; return 0 to signal handle API.
    0
}

#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hash_save_state_bytes(
    _ptr: *const BuHash,
    _out: *mut u8,
    _out_len: usize,
) -> usize {
    0
}

#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hash_restore_state_bytes(
    _ptr: *mut BuHash,
    _state: *const u8,
    _state_len: usize,
) -> i32 {
    1
}

#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_hash_clean_saved_state(state: *mut u8, state_len: usize) {
    if state.is_null() || state_len == 0 {
        return;
    }
    let s = slice::from_raw_parts_mut(state, state_len);
    for b in s.iter_mut() {
        *b = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_sha256() -> BuHashConfig {
        BuHashConfig {
            algo: BU_HASH_SHA256,
            digest_len: 32,
            flags: 0,
            key: ptr::null(),
            key_len: 0,
            salt: ptr::null(),
            salt_len: 0,
            personal: ptr::null(),
            personal_len: 0,
            seed: 0,
            fanout: 0,
            max_depth: 0,
            leaf_size: 0,
            node_offset: 0,
            node_depth: 0,
            inner_digest_length: 0,
            last_node: 0,
            _pad: [0; 5],
        }
    }

    #[test]
    fn sha256_abc() {
        let cfg = cfg_sha256();
        unsafe {
            let h = bu_hash_new(&cfg);
            assert!(!h.is_null());
            let msg = b"abc";
            bu_hash_update(h, msg.as_ptr(), msg.len());
            let mut out = [0u8; 32];
            bu_hash_finish(h, out.as_mut_ptr());
            // ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
            assert_eq!(out[0], 0xba);
            assert_eq!(out[31], 0xad);
            bu_hash_free(h);
        }
    }

    #[test]
    fn save_restore_compression_state() {
        let cfg = cfg_sha256();
        unsafe {
            let h1 = bu_hash_new(&cfg);
            bu_hash_update(h1, b"hello".as_ptr(), 5);
            let st = bu_hash_save_state(h1);
            assert!(!st.is_null());

            let h2 = bu_hash_new(&cfg);
            assert_eq!(bu_hash_restore_state(h2, st), 0);

            // continue both with same suffix
            bu_hash_update(h1, b" world".as_ptr(), 6);
            bu_hash_update(h2, b" world".as_ptr(), 6);

            let mut d1 = [0u8; 32];
            let mut d2 = [0u8; 32];
            bu_hash_finish(h1, d1.as_mut_ptr());
            bu_hash_finish(h2, d2.as_mut_ptr());
            assert_eq!(d1, d2);

            bu_hash_free_state(st);
            bu_hash_free(h1);
            bu_hash_free(h2);
        }
    }

    #[test]
    fn hmac_sha256_vector() {
        // RFC 4231 test case 1
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let mut cfg = cfg_sha256();
        cfg.flags = BU_HASH_FLAG_HMAC;
        cfg.key = key.as_ptr();
        cfg.key_len = key.len();
        unsafe {
            let h = bu_hash_new(&cfg);
            assert!(!h.is_null());
            bu_hash_update(h, data.as_ptr(), data.len());
            let mut out = [0u8; 32];
            bu_hash_finish(h, out.as_mut_ptr());
            assert_eq!(
                out,
                [
                    0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf,
                    0x0b, 0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9,
                    0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7
                ]
            );
            bu_hash_free(h);
        }
    }

    #[test]
    fn hmac_save_restore_keyed_state() {
        let key = b"secret-key-material";
        let mut cfg = cfg_sha256();
        cfg.flags = BU_HASH_FLAG_HMAC;
        cfg.key = key.as_ptr();
        cfg.key_len = key.len();
        unsafe {
            let h1 = bu_hash_new(&cfg);
            bu_hash_update(h1, b"part1".as_ptr(), 5);
            let st = bu_hash_save_state(h1);

            let h2 = bu_hash_new(&cfg);
            assert_eq!(bu_hash_restore_state(h2, st), 0);

            bu_hash_update(h1, b"part2".as_ptr(), 5);
            bu_hash_update(h2, b"part2".as_ptr(), 5);

            let mut d1 = [0u8; 32];
            let mut d2 = [0u8; 32];
            bu_hash_finish(h1, d1.as_mut_ptr());
            bu_hash_finish(h2, d2.as_mut_ptr());
            assert_eq!(d1, d2);

            bu_hash_free_state(st);
            bu_hash_free(h1);
            bu_hash_free(h2);
        }
    }

    #[test]
    fn shake256_custom_len() {
        let mut cfg = cfg_sha256();
        cfg.algo = BU_HASH_SHAKE256;
        cfg.digest_len = 64;
        unsafe {
            let h = bu_hash_new(&cfg);
            assert!(!h.is_null());
            bu_hash_update(h, b"abc".as_ptr(), 3);
            let mut out = [0u8; 64];
            bu_hash_finish(h, out.as_mut_ptr());
            assert!(out.iter().any(|&b| b != 0));
            assert_eq!(bu_hash_digest_len(h), 64);
            bu_hash_free(h);
        }
    }

    #[test]
    fn shake_second_finish_differs() {
        let cfg = BuHashConfig {
            algo: BU_HASH_SHAKE256,
            digest_len: 32,
            flags: 0,
            key: core::ptr::null(),
            key_len: 0,
            salt: core::ptr::null(),
            salt_len: 0,
            personal: core::ptr::null(),
            personal_len: 0,
            seed: 0,
            fanout: 0,
            max_depth: 0,
            leaf_size: 0,
            node_offset: 0,
            node_depth: 0,
            inner_digest_length: 0,
            last_node: 0,
            _pad: [0; 5],
        };
        unsafe {
            let h = bu_hash_new(&cfg);
            assert!(!h.is_null());
            let msg = [0u8, 0u8];
            bu_hash_update(h, msg.as_ptr(), 2);
            let mut d1 = [0u8; 32];
            let mut d2 = [0u8; 32];
            bu_hash_finish_n(h, d1.as_mut_ptr(), 32);
            bu_hash_finish_n(h, d2.as_mut_ptr(), 32);
            assert_ne!(d1, d2);
            bu_hash_reset(h);
            bu_hash_update(h, msg.as_ptr(), 2);
            let mut d3 = [0u8; 32];
            bu_hash_finish_n(h, d3.as_mut_ptr(), 32);
            assert_eq!(d1, d3);
            bu_hash_clean(h);
            bu_hash_update(h, msg.as_ptr(), 2); // no-op
            bu_hash_free(h);
        }
    }

    #[test]
    fn blake2s_reset_keeps_salt() {
        let salt = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let pers = [9u8, 10, 11, 12, 13, 14, 15, 16];
        let cfg = BuHashConfig {
            algo: BU_HASH_BLAKE2S,
            digest_len: 28,
            flags: 0,
            key: core::ptr::null(),
            key_len: 0,
            salt: salt.as_ptr(),
            salt_len: 8,
            personal: pers.as_ptr(),
            personal_len: 8,
            seed: 0,
            fanout: 2,
            max_depth: 3,
            leaf_size: 1,
            node_offset: 1,
            node_depth: 4,
            inner_digest_length: 0,
            last_node: 0,
            _pad: [0; 5],
        };
        unsafe {
            let h = bu_hash_new(&cfg);
            assert!(!h.is_null());
            let msg = [0u8, 0u8];
            bu_hash_update(h, msg.as_ptr(), 2);
            let mut d1 = [0u8; 28];
            bu_hash_finish_n(h, d1.as_mut_ptr(), 28);
            bu_hash_reset(h);
            bu_hash_update(h, msg.as_ptr(), 2);
            let mut d2 = [0u8; 28];
            bu_hash_finish_n(h, d2.as_mut_ptr(), 28);
            assert_eq!(d1, d2);
            bu_hash_free(h);
        }
    }

    #[test]
    fn blake2b_custom_and_tree() {
        let mut cfg = cfg_sha256();
        cfg.algo = BU_HASH_BLAKE2B;
        cfg.digest_len = 32;
        cfg.fanout = 1;
        cfg.max_depth = 1;
        unsafe {
            let h = bu_hash_new(&cfg);
            assert!(!h.is_null());
            bu_hash_update(h, b"blake2".as_ptr(), 6);
            let mut out = [0u8; 32];
            bu_hash_finish(h, out.as_mut_ptr());
            assert!(out.iter().any(|&b| b != 0));
            bu_hash_free(h);
        }
    }
}

// ---------------------------------------------------------------------------
// Zcash hashes: Sinsemilla / Poseidon / Pedersen (moved from `ffi::zcash`;
// C symbol names unchanged).
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Error codes (shared style with curve FFI)
// ---------------------------------------------------------------------------

pub const BU_ZCASH_OK: i32 = 0;
pub const BU_ZCASH_ERR_NULL: i32 = 1;
pub const BU_ZCASH_ERR_BUFFER: i32 = 2;
pub const BU_ZCASH_ERR_INVALID_INPUT: i32 = 3;
pub const BU_ZCASH_ERR_DOMAIN: i32 = 4;
pub const BU_ZCASH_ERR_INTERNAL: i32 = 5;
/// Semantic null (`commit` returned null) — maps to BuErrorCode.invalidPoint (12).
pub const BU_ZCASH_ERR_NO_RESULT: i32 = 12;

/// Pedersen personalization: NoteCommitment (all-1s 6-bit prefix).
pub const BU_PEDERSEN_NOTE_COMMITMENT: u32 = 0;
/// Pedersen personalization: MerkleTree layer (layer in low 6 bits of `layer`).
pub const BU_PEDERSEN_MERKLE_TREE: u32 = 1;

const FE_LEN: usize = 32;
const POINT_LEN: usize = 32;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn check_out(out: *mut u8, out_len: usize, need: usize) -> Result<(), i32> {
    if out.is_null() {
        return Err(BU_ZCASH_ERR_NULL);
    }
    if out_len < need {
        return Err(BU_ZCASH_ERR_BUFFER);
    }
    Ok(())
}

fn fe_from_le(bytes: &[u8; 32]) -> Result<PallasFe, i32> {
    let mut be = [0u8; 32];
    for i in 0..32 {
        be[i] = bytes[31 - i];
    }
    PallasFe::from_bytes_be(&be).map_err(|_| BU_ZCASH_ERR_INVALID_INPUT)
}

fn fe_to_le(f: &PallasFe, out: &mut [u8; 32]) {
    let mut be = [0u8; 32];
    f.to_bytes_be(&mut be);
    for i in 0..32 {
        out[i] = be[31 - i];
    }
}

/// Expand packed bits (LSB-first within each byte) into bool vector.
fn bits_from_packed(data: &[u8], bit_len: usize) -> Result<alloc::vec::Vec<bool>, i32> {
    if bit_len > data.len().saturating_mul(8) {
        return Err(BU_ZCASH_ERR_INVALID_INPUT);
    }
    let mut bits = alloc::vec::Vec::with_capacity(bit_len);
    for i in 0..bit_len {
        let b = data[i / 8];
        bits.push(((b >> (i % 8)) & 1) == 1);
    }
    Ok(bits)
}

fn write_jubjub_compressed(p: &JubJubPoint, out: &mut [u8]) -> i32 {
    match p.to_bytes_compressed(out) {
        Ok(()) => BU_ZCASH_OK,
        Err(_) => BU_ZCASH_ERR_INTERNAL,
    }
}

// ---------------------------------------------------------------------------
// Sinsemilla
// ---------------------------------------------------------------------------

/// Hash a bit-string (`'0'`/`'1'` ASCII) under `domain` UTF-8.
///
/// Output: 32-byte Pasta compressed Pallas point.
///
/// # Safety
/// Pointers must be valid for the given lengths when non-null.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_sinsemilla_hash_bitstring(
    domain: *const u8,
    domain_len: usize,
    bits: *const u8,
    bits_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if let Err(e) = check_out(out, out_len, POINT_LEN) {
        return e;
    }
    if domain.is_null() && domain_len != 0 {
        return BU_ZCASH_ERR_NULL;
    }
    if bits.is_null() && bits_len != 0 {
        return BU_ZCASH_ERR_NULL;
    }
    let domain_bytes = if domain_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(domain, domain_len)
    };
    let bits_bytes = if bits_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(bits, bits_len)
    };
    let domain_str = match core::str::from_utf8(domain_bytes) {
        Ok(s) => s,
        Err(_) => return BU_ZCASH_ERR_DOMAIN,
    };
    let bit_str = match core::str::from_utf8(bits_bytes) {
        Ok(s) => s,
        Err(_) => return BU_ZCASH_ERR_INVALID_INPUT,
    };
    for c in bit_str.chars() {
        if c != '0' && c != '1' {
            return BU_ZCASH_ERR_INVALID_INPUT;
        }
    }
    let hasher = match Sinsemilla::from_domain(domain_str) {
        Ok(h) => h,
        Err(_) => return BU_ZCASH_ERR_DOMAIN,
    };
    let point = hasher.hash_bitstring(bit_str);
    let enc = to_bytes_pasta(&point);
    let out_slice = slice::from_raw_parts_mut(out, POINT_LEN);
    out_slice.copy_from_slice(&enc);
    BU_ZCASH_OK
}

/// Hash packed bits (LSB-first) under `domain` UTF-8.
///
/// `bit_len` is the number of significant bits in `bits`.
/// Output: 32-byte Pasta compressed Pallas point.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_sinsemilla_hash_bits(
    domain: *const u8,
    domain_len: usize,
    bits: *const u8,
    bits_byte_len: usize,
    bit_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if let Err(e) = check_out(out, out_len, POINT_LEN) {
        return e;
    }
    if domain.is_null() && domain_len != 0 {
        return BU_ZCASH_ERR_NULL;
    }
    if bits.is_null() && bits_byte_len != 0 {
        return BU_ZCASH_ERR_NULL;
    }
    let domain_bytes = if domain_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(domain, domain_len)
    };
    let packed = if bits_byte_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(bits, bits_byte_len)
    };
    let domain_str = match core::str::from_utf8(domain_bytes) {
        Ok(s) => s,
        Err(_) => return BU_ZCASH_ERR_DOMAIN,
    };
    let bools = match bits_from_packed(packed, bit_len) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let hasher = match Sinsemilla::from_domain(domain_str) {
        Ok(h) => h,
        Err(_) => return BU_ZCASH_ERR_DOMAIN,
    };
    let point = hasher.hash_bits(&bools);
    let enc = to_bytes_pasta(&point);
    let out_slice = slice::from_raw_parts_mut(out, POINT_LEN);
    out_slice.copy_from_slice(&enc);
    BU_ZCASH_OK
}

/// Sinsemilla commit: `HashToPoint(msg) + [r]R` for domain (`CommitDomainNative`).
///
/// Domain is the base string (e.g. `z.cash:Orchard-CommitIvk`); internally uses
/// `domain-M` / `domain-r` like the reference API.
/// `r_le`: 32-byte LE scalar. `out`: 32-byte Pasta compressed point.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_sinsemilla_commit(
    domain: *const u8,
    domain_len: usize,
    bits: *const u8,
    bits_byte_len: usize,
    bit_len: usize,
    r_le: *const u8,
    r_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if let Err(e) = check_out(out, out_len, POINT_LEN) {
        return e;
    }
    if r_le.is_null() || r_len != 32 {
        return BU_ZCASH_ERR_INVALID_INPUT;
    }
    if domain.is_null() && domain_len != 0 {
        return BU_ZCASH_ERR_NULL;
    }
    if bits.is_null() && bits_byte_len != 0 {
        return BU_ZCASH_ERR_NULL;
    }
    let domain_bytes = if domain_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(domain, domain_len)
    };
    let packed = if bits_byte_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(bits, bits_byte_len)
    };
    let domain_str = match core::str::from_utf8(domain_bytes) {
        Ok(s) => s,
        Err(_) => return BU_ZCASH_ERR_DOMAIN,
    };
    let bools = match bits_from_packed(packed, bit_len) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let mut r = [0u8; 32];
    r.copy_from_slice(slice::from_raw_parts(r_le, 32));
    let point = match sinsemilla_commit(domain_str, &bools, &r) {
        Ok(p) => p,
        Err(crate::hash::HashError::Failure("sinsemilla_null")) => return BU_ZCASH_ERR_NO_RESULT,
        Err(_) => return BU_ZCASH_ERR_INVALID_INPUT,
    };
    let enc = to_bytes_pasta(&point);
    slice::from_raw_parts_mut(out, POINT_LEN).copy_from_slice(&enc);
    BU_ZCASH_OK
}

/// Sinsemilla shortCommit: LE 32-byte affine *x* of commit.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_sinsemilla_short_commit(
    domain: *const u8,
    domain_len: usize,
    bits: *const u8,
    bits_byte_len: usize,
    bit_len: usize,
    r_le: *const u8,
    r_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if let Err(e) = check_out(out, out_len, POINT_LEN) {
        return e;
    }
    if r_le.is_null() || r_len != 32 {
        return BU_ZCASH_ERR_INVALID_INPUT;
    }
    if domain.is_null() && domain_len != 0 {
        return BU_ZCASH_ERR_NULL;
    }
    if bits.is_null() && bits_byte_len != 0 {
        return BU_ZCASH_ERR_NULL;
    }
    let domain_bytes = if domain_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(domain, domain_len)
    };
    let packed = if bits_byte_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(bits, bits_byte_len)
    };
    let domain_str = match core::str::from_utf8(domain_bytes) {
        Ok(s) => s,
        Err(_) => return BU_ZCASH_ERR_DOMAIN,
    };
    let bools = match bits_from_packed(packed, bit_len) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let mut r = [0u8; 32];
    r.copy_from_slice(slice::from_raw_parts(r_le, 32));
    let x = match sinsemilla_short_commit(domain_str, &bools, &r) {
        Ok(x) => x,
        Err(crate::hash::HashError::Failure("sinsemilla_null")) => return BU_ZCASH_ERR_NO_RESULT,
        Err(_) => return BU_ZCASH_ERR_INVALID_INPUT,
    };
    slice::from_raw_parts_mut(out, POINT_LEN).copy_from_slice(&x);
    BU_ZCASH_OK
}

// ---------------------------------------------------------------------------
// Poseidon (Pallas Fe, width-3 P128Pow5T3)
// ---------------------------------------------------------------------------

/// Poseidon hash of two field elements (LE 32-byte each).
///
/// `a`, `b`: 32-byte LE field elements. `out`: 32-byte LE field element.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_poseidon_hash_two(
    a: *const u8,
    a_len: usize,
    b: *const u8,
    b_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if a.is_null() || b.is_null() {
        return BU_ZCASH_ERR_NULL;
    }
    if a_len < FE_LEN || b_len < FE_LEN {
        return BU_ZCASH_ERR_BUFFER;
    }
    if let Err(e) = check_out(out, out_len, FE_LEN) {
        return e;
    }
    let a_bytes: &[u8; 32] = match slice::from_raw_parts(a, FE_LEN).try_into() {
        Ok(x) => x,
        Err(_) => return BU_ZCASH_ERR_BUFFER,
    };
    let b_bytes: &[u8; 32] = match slice::from_raw_parts(b, FE_LEN).try_into() {
        Ok(x) => x,
        Err(_) => return BU_ZCASH_ERR_BUFFER,
    };
    let fa = match fe_from_le(a_bytes) {
        Ok(f) => f,
        Err(e) => return e,
    };
    let fb = match fe_from_le(b_bytes) {
        Ok(f) => f,
        Err(e) => return e,
    };
    let r = poseidon_hash_two(&fa, &fb);
    let mut le = [0u8; 32];
    fe_to_le(&r, &mut le);
    slice::from_raw_parts_mut(out, FE_LEN).copy_from_slice(&le);
    BU_ZCASH_OK
}

/// Poseidon sponge over `n` consecutive LE field elements (`inputs` length `n * 32`).
///
/// Output: 32-byte LE field element (state[0] after absorb).
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_poseidon_hash(
    inputs: *const u8,
    inputs_len: usize,
    n: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if let Err(e) = check_out(out, out_len, FE_LEN) {
        return e;
    }
    if n == 0 {
        // Empty absorb still runs one permute in our sponge.
        if inputs.is_null() {
            // allow null when n==0
        } else if inputs_len > 0 {
            // ignore extra
        }
        let r = poseidon_hash(&[]);
        let mut le = [0u8; 32];
        fe_to_le(&r, &mut le);
        slice::from_raw_parts_mut(out, FE_LEN).copy_from_slice(&le);
        return BU_ZCASH_OK;
    }
    if inputs.is_null() {
        return BU_ZCASH_ERR_NULL;
    }
    if inputs_len < n.saturating_mul(FE_LEN) {
        return BU_ZCASH_ERR_BUFFER;
    }
    let raw = slice::from_raw_parts(inputs, n * FE_LEN);
    let mut fes = alloc::vec::Vec::with_capacity(n);
    for i in 0..n {
        let mut chunk = [0u8; 32];
        chunk.copy_from_slice(&raw[i * FE_LEN..(i + 1) * FE_LEN]);
        match fe_from_le(&chunk) {
            Ok(f) => fes.push(f),
            Err(e) => return e,
        }
    }
    let r = poseidon_hash(&fes);
    let mut le = [0u8; 32];
    fe_to_le(&r, &mut le);
    slice::from_raw_parts_mut(out, FE_LEN).copy_from_slice(&le);
    BU_ZCASH_OK
}

/// In-place Poseidon permutation on a width-3 state (3 × 32-byte LE field elements).
///
/// `state` must point to 96 bytes; result is written back LE.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_poseidon_permute(state: *mut u8, state_len: usize) -> i32 {
    if state.is_null() {
        return BU_ZCASH_ERR_NULL;
    }
    if state_len < 3 * FE_LEN {
        return BU_ZCASH_ERR_BUFFER;
    }
    let buf = slice::from_raw_parts_mut(state, 3 * FE_LEN);
    let mut s = [PallasFe::zero(); 3];
    for i in 0..3 {
        let mut chunk = [0u8; 32];
        chunk.copy_from_slice(&buf[i * FE_LEN..(i + 1) * FE_LEN]);
        match fe_from_le(&chunk) {
            Ok(f) => s[i] = f,
            Err(e) => return e,
        }
    }
    Poseidon::permute_state(&mut s);
    for i in 0..3 {
        let mut le = [0u8; 32];
        fe_to_le(&s[i], &mut le);
        buf[i * FE_LEN..(i + 1) * FE_LEN].copy_from_slice(&le);
    }
    BU_ZCASH_OK
}

// ---------------------------------------------------------------------------
// Poseidon BN254 (circomlib / Sui zkLogin / Aptos keyless).
// Only compiled with the `poseidon-bn254` feature (tables ~404 KB).
// ---------------------------------------------------------------------------

/// circomlib-compatible Poseidon over BN254 Fr.
///
/// `inputs`: `n` 32-byte LE field elements (1..=64, each `< r`).
/// Output: 32-byte LE digest.
#[cfg(feature = "poseidon-bn254")]
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_poseidon_bn254_hash(
    inputs: *const u8,
    inputs_len: usize,
    n: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if let Err(e) = check_out(out, out_len, FE_LEN) {
        return e;
    }
    if n == 0 || n > 64 {
        return BU_ZCASH_ERR_INVALID_INPUT;
    }
    if inputs.is_null() {
        return BU_ZCASH_ERR_NULL;
    }
    if inputs_len < n.saturating_mul(FE_LEN) {
        return BU_ZCASH_ERR_BUFFER;
    }
    let raw = slice::from_raw_parts(inputs, n * FE_LEN);
    let mut fes = alloc::vec::Vec::with_capacity(n);
    for i in 0..n {
        let mut chunk = [0u8; 32];
        chunk.copy_from_slice(&raw[i * FE_LEN..(i + 1) * FE_LEN]);
        fes.push(chunk);
    }
    let le = match hash_le(&fes) {
        Ok(x) => x,
        Err(_) => return BU_ZCASH_ERR_INVALID_INPUT,
    };
    slice::from_raw_parts_mut(out, FE_LEN).copy_from_slice(&le);
    BU_ZCASH_OK
}

// ---------------------------------------------------------------------------
// Pedersen (Sapling / Jubjub)
// ---------------------------------------------------------------------------

/// Pedersen hash over packed bits (LSB-first).
///
/// `personal`: `BU_PEDERSEN_NOTE_COMMITMENT` or `BU_PEDERSEN_MERKLE_TREE`.
/// `layer`: used only for MerkleTree (0..63).
/// Output: 32-byte compressed Jubjub point.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_pedersen_hash(
    personal: u32,
    layer: u8,
    bits: *const u8,
    bits_byte_len: usize,
    bit_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if let Err(e) = check_out(out, out_len, POINT_LEN) {
        return e;
    }
    if bits.is_null() && bits_byte_len != 0 {
        return BU_ZCASH_ERR_NULL;
    }
    let packed = if bits_byte_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(bits, bits_byte_len)
    };
    let bools = match bits_from_packed(packed, bit_len) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let pers = match personal {
        BU_PEDERSEN_NOTE_COMMITMENT => Personalization::NoteCommitment,
        BU_PEDERSEN_MERKLE_TREE => {
            if layer > 63 {
                return BU_ZCASH_ERR_INVALID_INPUT;
            }
            Personalization::MerkleTree { layer }
        }
        _ => return BU_ZCASH_ERR_INVALID_INPUT,
    };
    // Mont-table path: tables already hold Montgomery limbs, so there is
    // no per-call generator rebuild and no limb re-encoding. Bit-identical
    // to the reference `PedersenHash::hash` (see `pedersen_cached_matches_reference`).
    let point = PedersenHash::hash_cached(pers, &bools);
    let out_slice = slice::from_raw_parts_mut(out, POINT_LEN);
    write_jubjub_compressed(&point, out_slice)
}

/// Pedersen hash of a `0`/`1` ASCII bit-string ().
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_pedersen_hash_bitstring(
    personal: u32,
    layer: u8,
    bits: *const u8,
    bits_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if let Err(e) = check_out(out, out_len, POINT_LEN) {
        return e;
    }
    if bits.is_null() && bits_len != 0 {
        return BU_ZCASH_ERR_NULL;
    }
    let bits_bytes = if bits_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(bits, bits_len)
    };
    let bit_str = match core::str::from_utf8(bits_bytes) {
        Ok(s) => s,
        Err(_) => return BU_ZCASH_ERR_INVALID_INPUT,
    };
    for c in bit_str.chars() {
        if c != '0' && c != '1' {
            return BU_ZCASH_ERR_INVALID_INPUT;
        }
    }
    let pers = match personal {
        BU_PEDERSEN_NOTE_COMMITMENT => Personalization::NoteCommitment,
        BU_PEDERSEN_MERKLE_TREE => {
            if layer > 63 {
                return BU_ZCASH_ERR_INVALID_INPUT;
            }
            Personalization::MerkleTree { layer }
        }
        _ => return BU_ZCASH_ERR_INVALID_INPUT,
    };
    let bools: Vec<bool> = bit_str.bytes().map(|c| c == b'1').collect();
    let point = PedersenHash::hash_cached(pers, &bools);
    let out_slice = slice::from_raw_parts_mut(out, POINT_LEN);
    write_jubjub_compressed(&point, out_slice)
}

// Silence unused import warning if CurvePoint only used via trait methods in some builds.
#[allow(dead_code)]
fn _assert_point_trait() {
    let _: fn(&PallasPoint) -> u8 = |p| p.ct_is_identity();
    let _ = ptr::null::<u8>();
}

#[cfg(test)]
mod sinsemilla_tests {
    use super::*;
    use crate::hash::sinsemilla::sinsemilla_hash;

    #[test]
    fn sinsemilla_ffi_matches_rust() {
        let domain = b"z.cash:test-Sinsemilla";
        let bits = b"10110";
        let mut out = [0u8; 32];
        let rc = unsafe {
            bu_sinsemilla_hash_bitstring(
                domain.as_ptr(),
                domain.len(),
                bits.as_ptr(),
                bits.len(),
                out.as_mut_ptr(),
                out.len(),
            )
        };
        assert_eq!(rc, BU_ZCASH_OK);
        let expected = sinsemilla_hash(
            core::str::from_utf8(domain).unwrap(),
            core::str::from_utf8(bits).unwrap(),
        )
        .unwrap();
        assert_eq!(out, to_bytes_pasta(&expected));
    }

    #[test]
    fn poseidon_hash_two_roundtrip() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        a[0] = 1; // LE one
        b[0] = 2; // LE two
        let mut out = [0u8; 32];
        let rc = unsafe {
            bu_poseidon_hash_two(
                a.as_ptr(),
                a.len(),
                b.as_ptr(),
                b.len(),
                out.as_mut_ptr(),
                out.len(),
            )
        };
        assert_eq!(rc, BU_ZCASH_OK);
        // Deterministic: second call matches
        let mut out2 = [0u8; 32];
        let rc2 = unsafe {
            bu_poseidon_hash_two(
                a.as_ptr(),
                a.len(),
                b.as_ptr(),
                b.len(),
                out2.as_mut_ptr(),
                out2.len(),
            )
        };
        assert_eq!(rc2, BU_ZCASH_OK);
        assert_eq!(out, out2);
    }

    #[cfg(feature = "poseidon-bn254")]
    #[test]
    fn poseidon_bn254_hash_known_answer() {
        // reference ZkLoginPoseidon.hash([1, 2]): BE
        // 115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a
        let mut inputs = [0u8; 64];
        inputs[0] = 1; // LE one
        inputs[32] = 2; // LE two
        let mut out = [0u8; 32];
        let rc = unsafe {
            bu_poseidon_bn254_hash(
                inputs.as_ptr(),
                inputs.len(),
                2,
                out.as_mut_ptr(),
                out.len(),
            )
        };
        assert_eq!(rc, BU_ZCASH_OK);
        let expect: [u8; 32] = [
            0x9a, 0x18, 0x17, 0x44, 0x7a, 0x60, 0x19, 0x9e, 0x51, 0x45, 0x32,
            0x74, 0xf2, 0x17, 0x36, 0x2a, 0xcf, 0xe9, 0x62, 0x96, 0x6b, 0x4c,
            0xf6, 0x3d, 0x41, 0x90, 0xd6, 0xe7, 0xf5, 0xc0, 0x5c, 0x11,
        ];
        assert_eq!(out, expect);
        // Empty input is rejected (unlike the legacy Pallas sponge).
        let rc = unsafe {
            bu_poseidon_bn254_hash(
                inputs.as_ptr(),
                inputs.len(),
                0,
                out.as_mut_ptr(),
                out.len(),
            )
        };
        assert_eq!(rc, BU_ZCASH_ERR_INVALID_INPUT);
    }

    #[test]
    fn pedersen_empty_note_commitment() {
        let mut out = [0u8; 32];
        let rc = unsafe {
            bu_pedersen_hash(
                BU_PEDERSEN_NOTE_COMMITMENT,
                0,
                ptr::null(),
                0,
                0,
                out.as_mut_ptr(),
                out.len(),
            )
        };
        assert_eq!(rc, BU_ZCASH_OK);
        // Non-identity for empty note-commitment hash with gens
        assert_ne!(out, [0u8; 32]);
    }
}
