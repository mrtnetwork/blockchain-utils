//! poseidon: chip + compile-time spec (no per-call regeneration).

#[allow(clippy::module_inception)] // Module layout mirrors the upstream halo2 crate structure; renaming would break module paths.
pub mod poseidon;
pub mod spec_const;
