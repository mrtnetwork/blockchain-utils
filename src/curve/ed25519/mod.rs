//! Ed25519 / Curve25519 twisted Edwards group (constant-time).
//!
//! Field and point limbs are private. Public API goes through
//! [`crate::curve::traits::CurvePoint`] and [`Ed25519Point`].
//!
//! Encoding follows RFC 8032 (little-endian, y + sign bit of x).
//! Monero helpers live in [`monero`].

pub mod fe;
pub mod monero;
pub mod point;
pub mod scalar;

pub use fe::Fe;
pub use monero::{
    check_key, check_key_vartime, from_fe_bytes, from_fe_bytes_clear_cofactor,
    from_fe_bytes_clear_cofactor_vartime, from_fe_bytes_vartime,
    ge_double_scalar_mult_base_point_var, ge_double_scalar_mult_precomp_point_var,
    ge_dsm_precomp_var, ge_triple_scalar_mult_base_point_var,
    ge_triple_scalar_mult_precomp_point_var, hash_to_ec, mul_by_cofactor, scalarmult8,
    scalarmult_key_image, scalarmult_key_image_secret, slide,
};
pub use point::{Ed25519Point, Extended};
pub use scalar::{Scalar, SecretScalar};
