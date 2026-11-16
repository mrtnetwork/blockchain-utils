//! Elliptic-curve groups and shared traits.
//!
//! One interface ([`FieldElement`], [`Scalar`], [`CurvePoint`]); limbs private
//! per curve. Constant-time secret scalar multiplication where implemented.
//!
//! ## Constant-time posture 
//!
//! Secret-scalar paths use complete addition formulas with masked selects
//! (no exceptional-case branches) and fixed-window table scans. Field
//! arithmetic is branchless (conditional subtracts via masks, not `if`s).
//! Inversions are Fermat exponentiations with *public* exponents, hence
//! secret-independent; the zero-input early reject is standard-accepted.
//! Verified by `scripts/timing_harness` (fixed-vs-random secret classes,
//! Welch |t| < 5 to pass).
//!
//! 
//! - BLS12-381 G1 `add`: removed mixed-addition fast path that branched on
//!   the CT-selected table entry (`other.z == 1`).
//! - BLS12-381 G2 `double`: removed identity early-return (leading-zero
//!   windows were measurably faster).
//! - BLS `Fe`/`Scalar` add/neg: branchless conditional subtracts.
//! - Vesta `Fe` add/neg: branchless (mirrors Pallas).
//! - Jubjub `Fe`: converted to Montgomery form (fixed-loop CIOS); the old
//!   schoolbook + secret-dependent Horner reduction leaked. `Fe`/`Scalar`
//!   add/neg and the bit-serial reduction loops are now select-based.
//!   Side benefit: Jubjub point mul is ~4x faster.
//!
//! Deliberately vartime (matches every production prover / upstream crate):
//! - Pippenger MSM (secret-indexed buckets + zero skips) — prover-side;
//!   threat model excludes local timing on the prover.
//! - Sinsemilla native hash (secret-indexed table + incomplete adds) —
//!   matches the reference `sinsemilla` crate; prover/wallet-side.
//! - Bulletproofs+ `*_var` Straus (prover-side, matches Monero).
//! - BLS/BN254 pairing + Miller loop (verify-only, public inputs).
//! - `mul_vartime*` entry points: public scalars only (name says so).

pub mod bls;
pub mod bn254;
pub mod ed25519;
pub mod error;
pub mod jubjub;
pub mod pallas;
pub mod ristretto;
pub mod secp256k1;
pub mod secp256r1;
pub mod traits;
pub mod vesta;
pub mod x25519;

pub use bls::{hash_to_g1, hash_to_g2, G1Point as BlsG1Point, G2Point as BlsG2Point};
pub use bn254::{G1Point as Bn254G1Point, Scalar as Bn254Scalar};
pub use ed25519::{Ed25519Point, Fe as Ed25519Fe, Scalar as Ed25519Scalar};
pub use error::{CurveError, CurveResult};
pub use jubjub::JubJubPoint;
pub use pallas::PallasPoint;
pub use ristretto::RistrettoPoint;
pub use secp256k1::{
    Fe as Secp256k1Fe, Scalar as Secp256k1Scalar, Secp256k1Point,
    SecretScalar as Secp256k1SecretScalar,
};
pub use secp256r1::{Fe as Secp256r1Fe, Scalar as Secp256r1Scalar, Secp256r1Point};
pub use traits::{CurvePoint, FieldElement, Scalar};
pub use vesta::VestaPoint;
pub use x25519::{
    clamp_scalar, diffie_hellman, diffie_hellman_raw, ed25519_pk_to_x25519,
    ed25519_scalar_to_x25519, ed25519_seed_to_x25519, public_key, x25519,
    PublicKey as X25519PublicKey, SecretKey as X25519SecretKey, X25519_LEN,
};
