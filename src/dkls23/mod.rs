//! DKLs23 threshold ECDSA (clean-room implementation).
//!
//! Doerner–Kondi–Lee–shelat 2023 ("Threshold ECDSA in Three Rounds",
//! `eprint 2023/765`): threshold ECDSA with malicious security against a
//! dishonest majority, built from an ideal commitment functionality plus
//! two-party (OT-based) multiplication. No Paillier, no class groups, no
//! range proofs in the signing path — which is why it replaces CGGMP21
//! here: the whole stack is symmetric crypto + curve arithmetic, both of
//! which this crate already does `no_std` + zero-dependency.
//!
//! ## Scope of this module
//!
//! - Curve-generic over secp256k1 (`K1`) and secp256r1/P-256 (`R1`) via
//!   [`curve_id`]: the same 33-byte compressed points / 32-byte scalars
//!   on the wire, arithmetic dispatched to the existing CT backends.
//! - Hash commitments ([`commit`]), Schnorr DLog proofs ([`schnorr`]),
//!   base OT over X25519 + OT extension over ChaCha/SHA-256 ([`ot`]),
//!   vector multiplication with consistency check ([`mul`]).
//! - DKG = commit → release → complain (no proofs of knowledge, per the
//!   paper §3); signing = 3 rounds over the Abram et al. intermediate
//!   representation; refresh / repair in [`refresh`].
//! - Wire codec ([`codec`]) is LE-framed (`[len:u32 LE] ++ bytes`), WASM
//!   safe (no threads, no OS RNG, no `std`), deterministic under an
//!   explicit 32-byte seed ([`crate::rng::ChaCha20Rng]).
//!
//! ## Safety posture
//!
//! - Long-lived secrets use zeroizing wrappers and are never logged.
//! - Secret scalar multiplication reuses the CT curve backends; abort is
//!   identifiable (the offender's message fails verification).
//! - Prime search / Paillier do not exist here by design.
//!
//! Protocol domain-separation strings ([`oracle`]) match the well-known
//! interoperable deployments so transcripts cross-check byte-for-byte;
//! all logic around them is written fresh for this crate.

#![cfg(feature = "alloc")]

pub mod codec;
pub mod commit;
pub mod curve_id;
pub mod dkg;
pub mod digest;
pub mod error;
pub mod keys;
pub mod mul;
pub mod oracle;
pub mod ot;
pub mod refresh;
pub mod schnorr;
pub mod session;
pub mod shares;
pub mod sign;

pub use curve_id::{CurveId, DklsPoint, DklsScalar};
pub use error::{DklsError, DklsResult};
