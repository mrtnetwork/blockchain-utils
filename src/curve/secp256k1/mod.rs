//! Constant-time secp256k1 field, scalar, and points.
//!
//! Limb layout and algorithms are informed by bitcoin-core/secp256k1; this is
//! an independent `no_std` implementation (not a copy of that codebase).

pub mod fe;
pub mod point;
pub mod scalar;

pub use fe::Fe;
pub use point::{Affine, Jacobian, Secp256k1Point};
pub use scalar::{Scalar, SecretScalar};
