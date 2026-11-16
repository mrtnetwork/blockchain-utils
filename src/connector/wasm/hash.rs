//! Hash streaming WASM exports (`BuWasm.hash*`).

use std::cell::RefCell;
use std::collections::HashMap;

use wasm_bindgen::prelude::*;

use crate::hash::blake2b::{Blake2TreeParams, Blake2b};
use crate::hash::blake2s::{Blake2s, Blake2sTreeParams};
use crate::hash::keccak::Keccak;
use crate::hash::md4::Md4;
use crate::hash::md5::Md5;
use crate::hash::ripemd160::Ripemd160;
use crate::hash::ripemd_ext::{Ripemd128, Ripemd256, Ripemd320};
use crate::hash::sha1::Sha1;
use crate::hash::sha256::Sha256;
use crate::hash::sha512::Sha512;
use crate::hash::xxhash;

use super::handles::alloc_id;
use crate::curve::pallas::{to_bytes_pasta, Fe as PallasFe};
use crate::curve::traits::CurvePoint;
use crate::hash::pedersen::{PedersenHash, Personalization};
use crate::hash::poseidon::{poseidon_hash, poseidon_hash_two, Poseidon};
#[cfg(feature = "poseidon-bn254")]
use crate::hash::poseidon_bn254::hash_le;
use crate::hash::sinsemilla::{sinsemilla_commit, sinsemilla_short_commit, Sinsemilla};

const A_SHA256: u32 = 1;
const A_SHA224: u32 = 2;
const A_SHA512: u32 = 3;
const A_SHA384: u32 = 4;
const A_SHA512_256: u32 = 5;
const A_SHA1: u32 = 6;
const A_RIPEMD160: u32 = 7;
const A_MD5: u32 = 8;
const A_MD4: u32 = 9;
const A_KECCAK256: u32 = 10;
const A_KECCAK224: u32 = 11;
const A_KECCAK384: u32 = 12;
const A_KECCAK512: u32 = 13;
const A_SHA3_256: u32 = 14;
const A_SHA3_512: u32 = 15;
const A_SHAKE128: u32 = 16;
const A_SHAKE256: u32 = 17;
const A_SHA3_224: u32 = 18;
const A_SHA3_384: u32 = 19;
const A_BLAKE2B: u32 = 20;
const A_BLAKE2S: u32 = 21;
const A_XXH32: u32 = 30;
const A_XXH64: u32 = 31;
const A_XXH3_64: u32 = 32;
const A_XXH3_128: u32 = 33;
const A_XXH3_256: u32 = 34;
const A_RIPEMD128: u32 = 35;
const A_RIPEMD256: u32 = 36;
const A_RIPEMD320: u32 = 37;

#[derive(Clone)]
enum Engine {
    Sha256(Sha256),
    Sha224(Sha256),
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
    Accum { algo: u32, seed: u64, buf: Vec<u8> },
}

/// HMAC (RFC 2104) over a plain engine: inner absorbs ipad‖message,
/// outer absorbs opad‖inner-digest. Mirrors `ffi::hash::HmacEngine`.
#[derive(Clone)]
struct HmacEngine {
    algo: u32,
    inner: Engine,
    outer_keyed: Engine,
    digest_len: usize,
}

impl HmacEngine {
    fn new(
        algo: u32,
        digest_len: usize,
        key: Option<&[u8]>,
        salt: Option<&[u8]>,
        personal: Option<&[u8]>,
        seed: u64,
        fanout: u8,
        max_depth: u8,
        leaf_size: u32,
        node_offset: u64,
        node_depth: u8,
        inner_len: u8,
        last_node: bool,
        raw_key: &[u8],
    ) -> Option<Self> {
        let bs = block_size(algo);
        if bs == 0 || bs > 128 {
            return None;
        }
        // Normalize key (hash long keys with a fresh plain engine).
        let mut k = vec![0u8; bs];
        if raw_key.len() > bs {
            let mut e = make_engine(
                algo,
                digest_len,
                None,
                salt,
                personal,
                seed,
                fanout,
                max_depth,
                leaf_size,
                node_offset,
                node_depth,
                inner_len,
                last_node,
            )?;
            update(&mut e, raw_key);
            let hk = finish(&mut e, algo, digest_len.min(64))?;
            k[..hk.len().min(bs)].copy_from_slice(&hk[..hk.len().min(bs)]);
        } else {
            k[..raw_key.len()].copy_from_slice(raw_key);
        }
        let mut ipad = vec![0x36u8; bs];
        let mut opad = vec![0x5cu8; bs];
        for i in 0..bs {
            ipad[i] ^= k[i];
            opad[i] ^= k[i];
        }
        let mut inner = make_engine(
            algo,
            digest_len,
            key,
            salt,
            personal,
            seed,
            fanout,
            max_depth,
            leaf_size,
            node_offset,
            node_depth,
            inner_len,
            last_node,
        )?;
        update(&mut inner, &ipad);
        let mut outer_keyed = make_engine(
            algo,
            digest_len,
            key,
            salt,
            personal,
            seed,
            fanout,
            max_depth,
            leaf_size,
            node_offset,
            node_depth,
            inner_len,
            last_node,
        )?;
        update(&mut outer_keyed, &opad);
        for b in ipad.iter_mut().chain(opad.iter_mut()).chain(k.iter_mut()) {
            *b = 0;
        }
        Some(Self {
            algo,
            inner,
            outer_keyed,
            digest_len,
        })
    }

    fn update(&mut self, data: &[u8]) {
        update(&mut self.inner, data);
    }

    fn finish_into(&self, out: &mut [u8]) {
        let mut idig = vec![0u8; self.digest_len.min(64)];
        let mut inner = self.inner.clone();
        if let Some(d) = finish(&mut inner, self.algo, self.digest_len) {
            let n = d.len().min(idig.len());
            idig[..n].copy_from_slice(&d[..n]);
        }
        let mut outer = self.outer_keyed.clone();
        update(&mut outer, &idig[..self.digest_len.min(idig.len())]);
        if let Some(d) = finish(&mut outer, self.algo, out.len()) {
            out.copy_from_slice(&d[..out.len().min(d.len())]);
        }
        for b in idig.iter_mut() {
            *b = 0;
        }
    }
}

#[derive(Clone)]
struct Entry {
    algo: u32,
    digest_len: usize,
    block_size: usize,
    engine: Engine,
    hmac: Option<HmacEngine>,
    /// Params needed to rebuild initial state on reset (Blake2 key/salt/tree).
    key: Option<Vec<u8>>,
    salt: Option<Vec<u8>>,
    personal: Option<Vec<u8>>,
    seed: u64,
    fanout: u8,
    max_depth: u8,
    leaf_size: u32,
    node_offset: u64,
    node_depth: u8,
    inner: u8,
    last_node: bool,
    cleaned: bool,
}

thread_local! {
    static HASHES: RefCell<HashMap<u32, Entry>> = RefCell::new(HashMap::new());
    static STATES: RefCell<HashMap<u32, Entry>> = RefCell::new(HashMap::new());
}

fn default_digest(algo: u32, req: u32) -> usize {
    if req > 0 {
        return req as usize;
    }
    match algo {
        A_SHA256 | A_KECCAK256 | A_SHA3_256 | A_BLAKE2S | A_SHA512_256 | A_RIPEMD256 => 32,
        A_SHA224 | A_KECCAK224 | A_SHA3_224 => 28,
        A_SHA512 | A_KECCAK512 | A_SHA3_512 | A_BLAKE2B => 64,
        A_SHA384 | A_KECCAK384 | A_SHA3_384 => 48,
        A_SHA1 | A_RIPEMD160 => 20,
        A_MD5 | A_MD4 | A_RIPEMD128 => 16,
        A_RIPEMD320 => 40,
        A_SHAKE128 => 32,
        A_SHAKE256 => 64,
        A_XXH32 => 4,
        A_XXH64 | A_XXH3_64 => 8,
        A_XXH3_128 => 16,
        A_XXH3_256 => 32,
        _ => 32,
    }
}

fn block_size(algo: u32) -> usize {
    match algo {
        A_SHA512 | A_SHA384 | A_SHA512_256 | A_BLAKE2B => 128,
        A_KECCAK256 | A_SHA3_256 | A_SHAKE128 => 136,
        A_KECCAK512 | A_SHA3_512 | A_SHAKE256 => 72,
        A_KECCAK384 | A_SHA3_384 => 104,
        A_KECCAK224 | A_SHA3_224 => 144,
        _ => 64,
    }
}

fn make_engine(
    algo: u32,
    digest_len: usize,
    key: Option<&[u8]>,
    salt: Option<&[u8]>,
    personal: Option<&[u8]>,
    seed: u64,
    fanout: u8,
    max_depth: u8,
    leaf_size: u32,
    node_offset: u64,
    node_depth: u8,
    inner: u8,
    last_node: bool,
) -> Option<Engine> {
    match algo {
        A_SHA256 => Some(Engine::Sha256(Sha256::new())),
        A_SHA224 => Some(Engine::Sha224(Sha256::new_224())),
        A_SHA512 => Some(Engine::Sha512(Sha512::new())),
        A_SHA384 => Some(Engine::Sha512(Sha512::new_384())),
        A_SHA512_256 => Some(Engine::Sha512(Sha512::new_512_256())),
        A_SHA1 => Some(Engine::Sha1(Sha1::new())),
        A_MD5 => Some(Engine::Md5(Md5::new())),
        A_MD4 => Some(Engine::Md4(Md4::new())),
        A_RIPEMD160 => Some(Engine::Ripemd160(Ripemd160::new())),
        A_RIPEMD128 => Some(Engine::Ripemd128(Ripemd128::new())),
        A_RIPEMD256 => Some(Engine::Ripemd256(Ripemd256::new())),
        A_RIPEMD320 => Some(Engine::Ripemd320(Ripemd320::new())),
        A_KECCAK256 => Some(Engine::Keccak(Keccak::keccak256())),
        A_KECCAK224 => Some(Engine::Keccak(Keccak::keccak224())),
        A_KECCAK384 => Some(Engine::Keccak(Keccak::keccak384())),
        A_KECCAK512 => Some(Engine::Keccak(Keccak::keccak512())),
        A_SHA3_256 => Some(Engine::Keccak(Keccak::sha3_256())),
        A_SHA3_224 => Some(Engine::Keccak(Keccak::sha3_224())),
        A_SHA3_384 => Some(Engine::Keccak(Keccak::sha3_384())),
        A_SHA3_512 => Some(Engine::Keccak(Keccak::sha3_512())),
        A_SHAKE128 => Some(Engine::Keccak(Keccak::shake128())),
        A_SHAKE256 => Some(Engine::Keccak(Keccak::shake256())),
        A_BLAKE2B => {
            let tree = Blake2TreeParams {
                fanout: if fanout == 0 { 1 } else { fanout },
                max_depth: if max_depth == 0 { 1 } else { max_depth },
                leaf_size,
                node_offset,
                node_depth,
                inner_digest_length: inner,
                last_node,
            };
            let salt16 = salt.filter(|s| s.len() == 16).map(|s| {
                let mut a = [0u8; 16];
                a.copy_from_slice(s);
                a
            });
            let pers16 = personal.filter(|s| s.len() == 16).map(|s| {
                let mut a = [0u8; 16];
                a.copy_from_slice(s);
                a
            });
            Some(Engine::Blake2b(Blake2b::new_with_tree(
                digest_len,
                key,
                salt16.as_ref(),
                pers16.as_ref(),
                Some(&tree),
            )))
        }
        A_BLAKE2S => {
            let salt8 = salt.filter(|s| s.len() == 8).map(|s| {
                let mut a = [0u8; 8];
                a.copy_from_slice(s);
                a
            });
            let pers8 = personal.filter(|s| s.len() == 8).map(|s| {
                let mut a = [0u8; 8];
                a.copy_from_slice(s);
                a
            });
            let tree = Blake2sTreeParams {
                fanout: if fanout == 0 { 1 } else { fanout },
                max_depth: if max_depth == 0 { 1 } else { max_depth },
                leaf_size,
                node_offset,
                node_depth,
                inner_digest_length: inner,
                last_node,
                salt: salt8,
                personal: pers8,
            };
            Blake2s::new_with_tree(digest_len, key, Some(&tree))
                .ok()
                .map(Engine::Blake2s)
        }
        A_XXH32 | A_XXH64 | A_XXH3_64 | A_XXH3_128 | A_XXH3_256 => Some(Engine::Accum {
            algo,
            seed,
            buf: Vec::new(),
        }),
        _ => None,
    }
}

fn update(e: &mut Engine, data: &[u8]) {
    match e {
        Engine::Sha256(h) | Engine::Sha224(h) => h.update(data),
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

fn finish(e: &mut Engine, algo: u32, digest_len: usize) -> Option<Vec<u8>> {
    let mut out = vec![0u8; digest_len];
    match e {
        Engine::Sha256(h) => {
            let d = h.clone().finalize();
            out[..d.len().min(digest_len)].copy_from_slice(&d[..d.len().min(digest_len)]);
        }
        Engine::Sha224(h) => {
            let d = h.clone().finalize_224();
            out[..d.len().min(digest_len)].copy_from_slice(&d[..d.len().min(digest_len)]);
        }
        Engine::Sha512(h) => {
            // Variant-aware finalize: plain finalize() asserts Sha512 and
            // would trap (poisoning later calls) on 384 / 512_256 engines.
            let full: Vec<u8> = match algo {
                A_SHA384 => h.clone().finalize_384().to_vec(),
                A_SHA512_256 => h.clone().finalize_512_256().to_vec(),
                _ => h.clone().finalize().to_vec(),
            };
            out[..full.len().min(digest_len)].copy_from_slice(&full[..full.len().min(digest_len)]);
        }
        Engine::Sha1(h) => {
            let d = h.clone().finalize().ok()?;
            out[..d.len().min(digest_len)].copy_from_slice(&d[..d.len().min(digest_len)]);
        }
        Engine::Md5(h) => {
            let d = h.clone().finalize().ok()?;
            out[..d.len().min(digest_len)].copy_from_slice(&d[..d.len().min(digest_len)]);
        }
        Engine::Md4(h) => {
            let d = h.clone().finalize().ok()?;
            out[..d.len().min(digest_len)].copy_from_slice(&d[..d.len().min(digest_len)]);
        }
        Engine::Ripemd160(h) => {
            let d = h.clone().finalize();
            out[..d.len().min(digest_len)].copy_from_slice(&d[..d.len().min(digest_len)]);
        }
        Engine::Ripemd128(h) => {
            let mut tmp = [0u8; 16];
            h.clone().finalize_into(&mut tmp);
            out[..digest_len.min(16)].copy_from_slice(&tmp[..digest_len.min(16)]);
        }
        Engine::Ripemd256(h) => {
            let mut tmp = [0u8; 32];
            h.clone().finalize_into(&mut tmp);
            out[..digest_len.min(32)].copy_from_slice(&tmp[..digest_len.min(32)]);
        }
        Engine::Ripemd320(h) => {
            let mut tmp = [0u8; 40];
            h.clone().finalize_into(&mut tmp);
            out[..digest_len.min(40)].copy_from_slice(&tmp[..digest_len.min(40)]);
        }
        Engine::Keccak(h) => {
            let mut tmp = vec![0u8; digest_len];
            if h.is_xof() {
                let _ = h.finish_into_mut(&mut tmp);
            } else {
                let _ = h.clone().finalize_into(&mut tmp);
            }
            out.copy_from_slice(&tmp);
        }
        Engine::Blake2b(h) => {
            let _ = h.clone().finalize_into(&mut out);
        }
        Engine::Blake2s(h) => {
            let _ = h.clone().finalize_into(&mut out);
        }
        Engine::Accum { algo, seed, buf } => match *algo {
            A_XXH32 => {
                let d = xxhash::xxh32_bytes(buf, *seed as u32).ok()?;
                out[..4].copy_from_slice(&d);
            }
            A_XXH64 => {
                let rounds = digest_len / 8;
                if rounds <= 1 {
                    let d = xxhash::xxh64_bytes(buf, *seed).ok()?;
                    out[..8.min(digest_len)].copy_from_slice(&d[..8.min(digest_len)]);
                } else {
                    for i in 0..rounds {
                        let d = xxhash::xxh64(buf, i as u64);
                        out[i * 8..(i + 1) * 8].copy_from_slice(&d.to_le_bytes());
                    }
                }
            }
            A_XXH3_64 => {
                let d = xxhash::xxh3_64_bytes(buf, *seed).ok()?;
                out[..8].copy_from_slice(&d);
            }
            A_XXH3_128 => {
                let d = xxhash::xxh3_128_bytes(buf, *seed).ok()?;
                out[..16].copy_from_slice(&d);
            }
            A_XXH3_256 => {
                let d = xxhash::xxh3_256_bytes(buf, *seed).ok()?;
                out[..32].copy_from_slice(&d);
            }
            _ => return None,
        },
    }
    Some(out)
}

/// `BuWasm.hashNew(...)` — explicit positional config (no JS objects, no
/// js-sys); returns integer handle. `digest_length` 0 = default, absent
/// byte arrays are empty, `seed`/`node_offset` cross as f64 (exact for all
/// in-range values).
#[wasm_bindgen(js_name = hashNew)]
pub fn hash_new(
    algo: u32,
    digest_length: u32,
    key: Option<Vec<u8>>,
    salt: Option<Vec<u8>>,
    personal: Option<Vec<u8>>,
    seed: f64,
    fanout: u32,
    max_depth: u32,
    leaf_size: u32,
    node_offset: f64,
    node_depth: u32,
    inner_digest_length: u32,
    last_node: bool,
    hmac_flag: bool,
) -> u32 {
    let digest_len = default_digest(algo, digest_length);
    let seed = seed as u64;
    let fanout = fanout as u8;
    let max_depth = max_depth as u8;
    let node_offset = node_offset as u64;
    let node_depth = node_depth as u8;
    let inner = inner_digest_length as u8;

    let engine = match make_engine(
        algo,
        digest_len,
        key.as_deref(),
        salt.as_deref(),
        personal.as_deref(),
        seed,
        fanout,
        max_depth,
        leaf_size,
        node_offset,
        node_depth,
        inner,
        last_node,
    ) {
        Some(e) => e,
        None => return 0,
    };

    // HMAC wraps the plain engine (RFC 2104 ipad/opad); mirrors ffi::hash.
    let hmac = if hmac_flag {
        HmacEngine::new(
            algo,
            digest_len,
            key.as_deref(),
            salt.as_deref(),
            personal.as_deref(),
            seed,
            fanout,
            max_depth,
            leaf_size,
            node_offset,
            node_depth,
            inner,
            last_node,
            key.as_deref().unwrap_or(&[]),
        )
    } else {
        None
    };

    let id = alloc_id();
    HASHES.with(|h| {
        h.borrow_mut().insert(
            id,
            Entry {
                algo,
                digest_len,
                block_size: block_size(algo),
                engine,
                hmac,
                key,
                salt,
                personal,
                seed,
                fanout,
                max_depth,
                leaf_size,
                node_offset,
                node_depth,
                inner,
                last_node,
                cleaned: false,
            },
        );
    });
    id
}

/// Absorb `data` into `handle` (no-op if unknown/cleaned).
#[wasm_bindgen(js_name = hashUpdate)]
pub fn hash_update(handle: u32, data: &[u8]) {
    let mut buf = vec![0u8; data.len() as usize];
    buf.copy_from_slice(data);
    HASHES.with(|h| {
        if let Some(e) = h.borrow_mut().get_mut(&handle) {
            if e.cleaned {
                return;
            }
            if let Some(hm) = e.hmac.as_mut() {
                hm.update(&buf);
            } else {
                update(&mut e.engine, &buf);
            }
        }
    });
}

/// Reset `handle` to initial cfg (preserves key/salt; no-op if cleaned).
#[wasm_bindgen(js_name = hashReset)]
pub fn hash_reset(handle: u32) {
    HASHES.with(|h| {
        let mut map = h.borrow_mut();
        if let Some(e) = map.get_mut(&handle) {
            if e.cleaned {
                return;
            }
            // HMAC entries rebuild both engines (ipad/opad re-applied).
            if e.hmac.is_some() {
                let raw_key = e.key.clone().unwrap_or_default();
                if let Some(eng) = make_engine(
                    e.algo,
                    e.digest_len,
                    e.key.as_deref(),
                    e.salt.as_deref(),
                    e.personal.as_deref(),
                    e.seed,
                    e.fanout,
                    e.max_depth,
                    e.leaf_size,
                    e.node_offset,
                    e.node_depth,
                    e.inner,
                    e.last_node,
                ) {
                    e.engine = eng;
                }
                e.hmac = HmacEngine::new(
                    e.algo,
                    e.digest_len,
                    e.key.as_deref(),
                    e.salt.as_deref(),
                    e.personal.as_deref(),
                    e.seed,
                    e.fanout,
                    e.max_depth,
                    e.leaf_size,
                    e.node_offset,
                    e.node_depth,
                    e.inner,
                    e.last_node,
                    &raw_key,
                );
                return;
            }
            // Prefer in-engine reset (Blake2/Keccak preserve key/salt/XOF init)
            match &mut e.engine {
                Engine::Blake2b(h) => {
                    h.reset();
                    return;
                }
                Engine::Blake2s(h) => {
                    h.reset();
                    return;
                }
                Engine::Keccak(h) => {
                    h.reset();
                    return;
                }
                _ => {}
            }
            if let Some(eng) = make_engine(
                e.algo,
                e.digest_len,
                e.key.as_deref(),
                e.salt.as_deref(),
                e.personal.as_deref(),
                e.seed,
                e.fanout,
                e.max_depth,
                e.leaf_size,
                e.node_offset,
                e.node_depth,
                e.inner,
                e.last_node,
            ) {
                e.engine = eng;
            }
        }
    });
}

/// Finalize `handle` (non-consuming) into digest bytes.
#[wasm_bindgen(js_name = hashFinish)]
pub fn hash_finish(handle: u32) -> Vec<u8> {
    hash_finish_n(handle, 0)
}

/// Finish with explicit output length (0 = use configured digestLength). SHAKE uses this for XOF.
#[wasm_bindgen(js_name = hashFinishN)]
pub fn hash_finish_n(handle: u32, out_len: u32) -> Vec<u8> {
    let out = HASHES.with(|h| {
        let mut map = h.borrow_mut();
        let e = map.get_mut(&handle)?;
        if e.cleaned {
            return None;
        }
        let len = if out_len == 0 {
            e.digest_len
        } else {
            out_len as usize
        };
        if let Some(hm) = e.hmac.as_ref() {
            let mut out = vec![0u8; len];
            hm.finish_into(&mut out);
            Some(out)
        } else {
            finish(&mut e.engine, e.algo, len)
        }
    });
    match out {
        Some(v) => v,
        None => Vec::new(),
    }
}

/// Wipe `handle` and mark unusable (later ops no-op).
#[wasm_bindgen(js_name = hashClean)]
pub fn hash_clean(handle: u32) {
    HASHES.with(|h| {
        if let Some(e) = h.borrow_mut().get_mut(&handle) {
            match &mut e.engine {
                Engine::Blake2b(x) => x.clean(),
                Engine::Blake2s(x) => x.clean(),
                Engine::Keccak(x) => x.clean(),
                _ => {}
            }
            e.cleaned = true;
        }
    });
}

/// Drop `handle` from the table.
#[wasm_bindgen(js_name = hashFree)]
pub fn hash_free(handle: u32) {
    HASHES.with(|h| {
        h.borrow_mut().remove(&handle);
    });
}

/// Configured digest length for `handle` (0 = unknown).
#[wasm_bindgen(js_name = hashDigestLen)]
pub fn hash_digest_len(handle: u32) -> u32 {
    HASHES.with(|h| {
        h.borrow()
            .get(&handle)
            .map(|e| e.digest_len as u32)
            .unwrap_or(0)
    })
}

/// Block size for `handle` (0 = unknown).
#[wasm_bindgen(js_name = hashBlockSize)]
pub fn hash_block_size(handle: u32) -> u32 {
    HASHES.with(|h| {
        h.borrow()
            .get(&handle)
            .map(|e| e.block_size as u32)
            .unwrap_or(0)
    })
}

/// Algorithm id for `handle` (0 = unknown).
#[wasm_bindgen(js_name = hashAlgo)]
pub fn hash_algo(handle: u32) -> u32 {
    HASHES.with(|h| h.borrow().get(&handle).map(|e| e.algo).unwrap_or(0))
}

/// Snapshot `handle` compression state; returns state id (0 = unknown).
#[wasm_bindgen(js_name = hashSaveState)]
pub fn hash_save_state(handle: u32) -> u32 {
    let snapshot = HASHES.with(|h| h.borrow().get(&handle).cloned());
    match snapshot {
        Some(e) => {
            let id = alloc_id();
            STATES.with(|s| s.borrow_mut().insert(id, e));
            id
        }
        None => 0,
    }
}

/// Restore `state` into `handle`; returns 1 on success, 0 if unknown.
#[wasm_bindgen(js_name = hashRestoreState)]
pub fn hash_restore_state(handle: u32, state: u32) -> Result<u32, JsValue> {
    let snap = STATES.with(|s| s.borrow().get(&state).cloned());
    let e = snap.ok_or_else(|| JsValue::from_str("unknown state"))?;
    HASHES.with(|h| {
        let mut map = h.borrow_mut();
        let cur = map
            .get(&handle)
            .ok_or_else(|| JsValue::from_str("unknown handle"))?;
        // Mirror bu_hash_restore_state: algo + digest length + hmac-ness
        // must match (e.g. sha3 state into keccak is rejected).
        if cur.algo != e.algo
            || cur.digest_len != e.digest_len
            || cur.hmac.is_some() != e.hmac.is_some()
        {
            return Err(JsValue::from_str("state/algo mismatch"));
        }
        map.insert(handle, e);
        Ok(1)
    })
}

/// Drop saved state `state`.
#[wasm_bindgen(js_name = hashFreeState)]
pub fn hash_free_state(state: u32) {
    STATES.with(|s| {
        s.borrow_mut().remove(&state);
    });
}

/// Keccak-f1600 permutation glue (200-byte state copy-through, permuted
/// in place like FFI `bu_keccak_f1600`).
#[wasm_bindgen(js_name = keccakF1600)]
pub fn keccak_f1600(state200: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; state200.len()];
    buf.copy_from_slice(state200);
    if buf.len() == 200 {
        let mut st = [0u64; 25];
        for i in 0..25 {
            let mut w = [0u8; 8];
            w.copy_from_slice(&buf[i * 8..(i + 1) * 8]);
            st[i] = u64::from_le_bytes(w);
        }
        crate::hash::keccak::keccak_f_1600(&mut st);
        for i in 0..25 {
            buf[i * 8..(i + 1) * 8].copy_from_slice(&st[i].to_le_bytes());
        }
    }
    buf
}

// ---------------------------------------------------------------------------
// Zcash hashes: Sinsemilla / Poseidon / Pedersen (moved from `wasm::zcash`;
// JS names unchanged).
// ---------------------------------------------------------------------------

fn u8_vec(a: &[u8]) -> Vec<u8> {
    let mut v = vec![0u8; a.len() as usize];
    v.copy_from_slice(a);
    v
}
fn to_u8(v: &[u8]) -> Vec<u8> {
    v.to_vec()
}

fn fe_from_le(bytes: &[u8; 32]) -> Result<PallasFe, JsValue> {
    let mut be = [0u8; 32];
    for i in 0..32 {
        be[i] = bytes[31 - i];
    }
    PallasFe::from_bytes_be(&be).map_err(|_| JsValue::from_str("fe"))
}
fn fe_to_le(f: &PallasFe, out: &mut [u8; 32]) {
    let mut be = [0u8; 32];
    f.to_bytes_be(&mut be);
    for i in 0..32 {
        out[i] = be[31 - i];
    }
}

fn bits_from_packed(data: &[u8], bit_len: usize) -> Result<Vec<bool>, JsValue> {
    if bit_len > data.len().saturating_mul(8) {
        return Err(JsValue::from_str("bit_len"));
    }
    let mut bits = Vec::with_capacity(bit_len);
    for i in 0..bit_len {
        let b = data[i / 8];
        bits.push(((b >> (i % 8)) & 1) == 1);
    }
    Ok(bits)
}

/// Poseidon hash of two LE field elements; Err "fe32"/"fe" on bad input.
#[wasm_bindgen(js_name = poseidonHashTwo)]
pub fn poseidon_hash_two_js(a: &[u8], b: &[u8]) -> Result<Vec<u8>, JsValue> {
    if a.len() != 32 || b.len() != 32 {
        return Err(JsValue::from_str("fe32"));
    }
    let mut aa = [0u8; 32];
    let mut bb = [0u8; 32];
    aa.copy_from_slice(a);
    bb.copy_from_slice(b);
    let r = poseidon_hash_two(&fe_from_le(&aa)?, &fe_from_le(&bb)?);
    let mut out = [0u8; 32];
    fe_to_le(&r, &mut out);
    Ok(to_u8(&out))
}

/// Poseidon sponge over n*32 LE bytes; Err on bad length/field.
#[wasm_bindgen(js_name = poseidonHash)]
pub fn poseidon_hash_js(inputs: &[u8]) -> Result<Vec<u8>, JsValue> {
    let raw = u8_vec(inputs);
    if raw.len() % 32 != 0 {
        return Err(JsValue::from_str("inputs must be n*32"));
    }
    let n = raw.len() / 32;
    let mut fes = Vec::with_capacity(n);
    for i in 0..n {
        let mut b = [0u8; 32];
        b.copy_from_slice(&raw[i * 32..(i + 1) * 32]);
        fes.push(fe_from_le(&b)?);
    }
    let r = poseidon_hash(&fes);
    let mut out = [0u8; 32];
    fe_to_le(&r, &mut out);
    Ok(to_u8(&out))
}

/// circomlib-compatible Poseidon over BN254 Fr (Sui zkLogin / Aptos keyless).
/// `inputs`: 1..=64 elements of 32 LE bytes each. Only available with the
/// `poseidon-bn254` feature; Err on bad length/field.
#[cfg(feature = "poseidon-bn254")]
#[wasm_bindgen(js_name = poseidonBn254Hash)]
pub fn poseidon_bn254_hash_js(inputs: &[u8]) -> Result<Vec<u8>, JsValue> {
    let raw = u8_vec(inputs);
    if raw.is_empty() || raw.len() % 32 != 0 || raw.len() > 64 * 32 {
        return Err(JsValue::from_str("inputs must be 1..64 x 32 bytes"));
    }
    let n = raw.len() / 32;
    let mut fes = Vec::with_capacity(n);
    for i in 0..n {
        let mut b = [0u8; 32];
        b.copy_from_slice(&raw[i * 32..(i + 1) * 32]);
        fes.push(b);
    }
    let le = hash_le(&fes).map_err(|_| JsValue::from_str("fe"))?;
    Ok(to_u8(&le))
}

/// Sinsemilla hash of packed bits under `domain`; Err "domain"/"bit_len".
#[wasm_bindgen(js_name = sinsemillaHashBits)]
pub fn sinsemilla_hash_bits_js(
    domain: &[u8],
    packed_bits: &[u8],
    bit_len: u32,
) -> Result<Vec<u8>, JsValue> {
    let dom = u8_vec(domain);
    let domain_str = core::str::from_utf8(&dom).map_err(|_| JsValue::from_str("domain"))?;
    let packed = u8_vec(packed_bits);
    let bools = bits_from_packed(&packed, bit_len as usize)?;
    let hasher = Sinsemilla::from_domain(domain_str).map_err(|_| JsValue::from_str("domain"))?;
    let point = hasher.hash_bits(&bools);
    Ok(to_u8(&to_bytes_pasta(&point)))
}

/// Sinsemilla commit with randomness `r32`; Err "domain"/"r32"/"commit".
#[wasm_bindgen(js_name = sinsemillaCommit)]
pub fn sinsemilla_commit_js(
    domain: &[u8],
    packed_bits: &[u8],
    bit_len: u32,
    r32: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let dom = u8_vec(domain);
    let domain_str = core::str::from_utf8(&dom).map_err(|_| JsValue::from_str("domain"))?;
    let packed = u8_vec(packed_bits);
    let bools = bits_from_packed(&packed, bit_len as usize)?;
    let mut r = [0u8; 32];
    if r32.len() != 32 {
        return Err(JsValue::from_str("r32"));
    }
    r.copy_from_slice(r32);
    let p = sinsemilla_commit(domain_str, &bools, &r).map_err(|_| JsValue::from_str("commit"))?;
    Ok(to_u8(&to_bytes_pasta(&p)))
}

/// Sinsemilla short commit (LE x) with `r32`; Err "domain"/"r32".
#[wasm_bindgen(js_name = sinsemillaShortCommit)]
pub fn sinsemilla_short_commit_js(
    domain: &[u8],
    packed_bits: &[u8],
    bit_len: u32,
    r32: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let dom = u8_vec(domain);
    let domain_str = core::str::from_utf8(&dom).map_err(|_| JsValue::from_str("domain"))?;
    let packed = u8_vec(packed_bits);
    let bools = bits_from_packed(&packed, bit_len as usize)?;
    let mut r = [0u8; 32];
    if r32.len() != 32 {
        return Err(JsValue::from_str("r32"));
    }
    r.copy_from_slice(r32);
    let fe = sinsemilla_short_commit(domain_str, &bools, &r)
        .map_err(|_| JsValue::from_str("shortCommit"))?;
    Ok(to_u8(&fe))
}

/// Poseidon width-3 permute over 96 LE bytes; Err "state96"/"fe".
#[wasm_bindgen(js_name = poseidonPermute)]
pub fn poseidon_permute_js(state: &[u8]) -> Result<Vec<u8>, JsValue> {
    let raw = u8_vec(state);
    if raw.len() < 96 {
        return Err(JsValue::from_str("state96"));
    }
    let mut s = [PallasFe::zero(); 3];
    for i in 0..3 {
        let mut b = [0u8; 32];
        b.copy_from_slice(&raw[i * 32..(i + 1) * 32]);
        let mut be = [0u8; 32];
        for j in 0..32 {
            be[j] = b[31 - j];
        }
        s[i] = PallasFe::from_bytes_be(&be).map_err(|_| JsValue::from_str("fe"))?;
    }
    Poseidon::permute_state(&mut s);
    let mut out = [0u8; 96];
    for i in 0..3 {
        let mut be = [0u8; 32];
        s[i].to_bytes_be(&mut be);
        for j in 0..32 {
            out[i * 32 + j] = be[31 - j];
        }
    }
    Ok(to_u8(&out))
}

/// Sinsemilla hash of '0'/'1' string under `domain`; Err "domain"/"bits".
#[wasm_bindgen(js_name = sinsemillaHashBitstring)]
pub fn sinsemilla_hash_bitstring_js(domain: &[u8], bits: &[u8]) -> Result<Vec<u8>, JsValue> {
    let dom = u8_vec(domain);
    let domain_str = core::str::from_utf8(&dom).map_err(|_| JsValue::from_str("domain"))?;
    let raw = u8_vec(bits);
    let bit_str = core::str::from_utf8(&raw).map_err(|_| JsValue::from_str("bits"))?;
    for c in bit_str.chars() {
        if c != '0' && c != '1' {
            return Err(JsValue::from_str("bits"));
        }
    }
    let hasher = Sinsemilla::from_domain(domain_str).map_err(|_| JsValue::from_str("domain"))?;
    let point = hasher.hash_bitstring(bit_str);
    Ok(to_u8(&to_bytes_pasta(&point)))
}

fn pedersen_pers(personal: u32, layer: u8) -> Result<Personalization, JsValue> {
    match personal {
        0 => Ok(Personalization::NoteCommitment),
        1 => {
            if layer > 63 {
                return Err(JsValue::from_str("layer"));
            }
            Ok(Personalization::MerkleTree { layer })
        }
        _ => Err(JsValue::from_str("personal")),
    }
}

/// Pedersen hash of packed bits; Err "personal"/"layer"/"bit_len"/"internal".
#[wasm_bindgen(js_name = pedersenHash)]
pub fn pedersen_hash_js(
    personal: u32,
    layer: u8,
    packed_bits: &[u8],
    bit_len: u32,
) -> Result<Vec<u8>, JsValue> {
    let pers = pedersen_pers(personal, layer)?;
    let packed = u8_vec(packed_bits);
    let bools = bits_from_packed(&packed, bit_len as usize)?;
    let point = PedersenHash::hash_cached(pers, &bools);
    let mut out = [0u8; 32];
    point
        .to_bytes_compressed(&mut out)
        .map_err(|_| JsValue::from_str("internal"))?;
    Ok(to_u8(&out))
}

/// Pedersen hash of '0'/'1' string; Err "personal"/"layer"/"bits"/"internal".
#[wasm_bindgen(js_name = pedersenHashBitstring)]
pub fn pedersen_hash_bitstring_js(
    personal: u32,
    layer: u8,
    bits: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let pers = pedersen_pers(personal, layer)?;
    let raw = u8_vec(bits);
    let bit_str = core::str::from_utf8(&raw).map_err(|_| JsValue::from_str("bits"))?;
    for c in bit_str.chars() {
        if c != '0' && c != '1' {
            return Err(JsValue::from_str("bits"));
        }
    }
    let bools: Vec<bool> = bit_str.bytes().map(|c| c == b'1').collect();
    let point = PedersenHash::hash_cached(pers, &bools);
    let mut out = [0u8; 32];
    point
        .to_bytes_compressed(&mut out)
        .map_err(|_| JsValue::from_str("internal"))?;
    Ok(to_u8(&out))
}
