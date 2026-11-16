//! sinsemilla.

pub mod merkle;
pub mod message;
#[allow(clippy::module_inception)] // Module layout mirrors the upstream halo2 crate structure; renaming would break module paths.
pub mod sinsemilla;
pub mod table;
