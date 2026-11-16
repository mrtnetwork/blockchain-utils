//! Cryptographic hash functions, HMAC, HKDF and PBKDF2.
//!
//! Pure `no_std`, zero-dependency. Written from the relevant standards.
//!
//! ## Constant-time posture 
//!
//! Compression cores (SHA-256/512, Keccak-f, BLAKE2b/s) are fixed-round
//! straight-line code: no branches on message content. Residual timing
//! depends only on *public* framing (message length, key length, flags),
//! which is standard-accepted. Verified by `scripts/timing_harness`
//! (`hmac_sha256_key`, `hmac_sha512_key`, `sha256_input`, `blake2b_input`,
//! `poseidon_preimage`; Welch |t| < 5 to pass).
//!
//! | Primitive | Secret-absorbing uses | Verdict |
//! |---|---|---|
//! | SHA-256 | RFC6979 nonces, BIP-340/Schnorr seeds, MuSig2 tags, Noise HKDF input, HMAC key | CT-OK (content) |
//! | SHA-512 | Ed25519/SR25519 secret hashing, HMAC key | CT-OK (content) |
//! | HMAC-SHA256/512 | RFC6979, HKDF, PBKDF2, Noise chaining keys | CT-OK (key): key-XOR loops fixed-length; length branch is public |
//! | HKDF / PBKDF2 | Noise keys, password KDF | CT-OK: fixed iteration counts |
//! | scrypt | password KDF | CT-OK except ROMix `V[Integerify mod N]` secret-indexed reads — inherent cache-timing property of scrypt, accepted |
//! | BLAKE2s | Sapling ivk/nk (secret keys), note commitments | CT-OK (content) |
//! | BLAKE2b | RedDSA H (secret nonce), Ed25519 contexts | CT-OK (content) |
//! | Keccak/SHAKE | Monero `hash_to_scalar`, ML-DSA XOF | CT-OK (content) |
//! | Poseidon / Sinsemilla | Orchard witnesses (secret) | arithmetic is straight-line field ops; full CT rides on Pallas `Fe`/`mul` |
//! | Pedersen | Sapling note bits (secret) | curve op; CT rides on Jubjub scalar-mul; `find_group_hash` inputs are public constants |
//! | SHA-1 / MD4 / MD5 / RIPEMD / XXH | legacy / non-crypto, public inputs only | public-only; not hardened |
//!
//! All digest/MAC comparisons on secret-derived values use `ct::ct_eq`
//! (signatures, AEAD tags); no `==` on secrets remains.

pub mod blake2b;
pub mod blake2s;
pub mod digest;
pub mod error;
pub mod hkdf;
pub mod hmac;
pub mod keccak;
pub mod md4;
pub mod md5;
pub mod pbkdf2;
pub mod ripemd160;
pub mod ripemd_ext;
pub mod scrypt;
pub mod sha1;
pub mod sha256;
pub mod sha512;
pub mod xxhash;

// Zcash hashes: Pedersen (Sapling), Poseidon & Sinsemilla (Orchard).
// Pure `no_std`, zero-dependency; moved from the former `crate::zcash`.
pub mod pedersen;
pub(crate) mod pedersen_tables;
pub mod poseidon;
pub mod sinsemilla;
pub(crate) mod sinsemilla_s_table;

// circomlib-compatible Poseidon over BN254 Fr (Sui zkLogin). Opt-in:
// the tables are ~404 KB, so this stays out of `default` and costs
// nothing when disabled.
#[cfg(feature = "poseidon-bn254")]
pub(crate) mod poseidon_bn254_tables;
#[cfg(feature = "poseidon-bn254")]
pub mod poseidon_bn254;

#[cfg(test)]
mod compat_tests;

pub use digest::{Digest, HashState, HmacCapable, SerializableHash};
pub use error::{HashError, HashResult};

// SHA family
pub use sha1::{sha1, Sha1, SHA1_LEN};
pub use sha256::{sha224, sha256, sha256d, Sha256, SHA224_LEN, SHA256_LEN};
pub use sha512::{sha384, sha512, sha512_256, Sha512, SHA384_LEN, SHA512_256_LEN, SHA512_LEN};

// Legacy
pub use md4::{md4, Md4, MD4_LEN};
pub use md5::{md5, Md5, MD5_LEN};
pub use ripemd160::{hash160, ripemd160, Ripemd160, RIPEMD160_LEN};
pub use ripemd_ext::{
    ripemd128, ripemd256, ripemd320, Ripemd128, Ripemd256, Ripemd320, RIPEMD128_LEN, RIPEMD256_LEN,
    RIPEMD320_LEN,
};

// Keccak / SHA-3 / SHAKE
pub use keccak::{
    keccak224, keccak256, keccak384, keccak512, keccak_f_1600, sha3_224, sha3_256, sha3_384,
    sha3_512, shake128, shake256, Keccak, Keccak256, KECCAK224_LEN, KECCAK256_LEN, KECCAK384_LEN,
    KECCAK512_LEN,
};

// BLAKE2
pub use blake2b::{blake2b_256, blake2b_512, Blake2TreeParams, Blake2b, BLAKE2B_MAX_LEN};
pub use blake2s::{blake2s_128, blake2s_256, Blake2s, Blake2sTreeParams, BLAKE2S_MAX_LEN};

// XXHash / XXH3
pub use xxhash::{
    xxh32, xxh32_bytes, xxh3_128, xxh3_128_bytes, xxh3_256_bytes, xxh3_64, xxh3_64_bytes, xxh64,
    xxh64_bytes, XXH128_LEN, XXH256_LEN, XXH32_LEN, XXH64_LEN,
};

// MAC / KDF
pub use hkdf::{
    hkdf_expand_sha256, hkdf_expand_sha512, hkdf_extract_sha256, hkdf_extract_sha512, hkdf_sha256,
    hkdf_sha512,
};
pub use hmac::{hmac, hmac_sha256, hmac_sha512, Hmac};
pub use pbkdf2::{pbkdf2_hmac_sha256, pbkdf2_hmac_sha512};
pub use scrypt::{scrypt, ScryptParams};

// Zcash hashes (see above).
pub use pedersen::{find_group_hash, pedersen_hash, PedersenHash, Personalization};
pub use poseidon::{poseidon_hash, poseidon_hash_two, Poseidon};
pub use sinsemilla::{sinsemilla_hash, Sinsemilla};
