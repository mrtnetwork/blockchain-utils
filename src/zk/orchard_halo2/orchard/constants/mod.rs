//! orchard constants: compile-time LE bytes (no hex, no BigInt.parse).

#[allow(clippy::module_inception)] // Module layout mirrors the upstream halo2 crate structure; renaming would break module paths.
pub mod constants;
pub mod fixed_bases;
