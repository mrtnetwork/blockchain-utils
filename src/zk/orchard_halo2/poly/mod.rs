//! poly.

pub mod commitment;
pub mod domain;
pub mod evaluator;
pub mod multiopen;
pub mod params;
#[allow(clippy::module_inception)] // Module layout mirrors the upstream halo2 crate structure; renaming would break module paths.
pub mod poly;
