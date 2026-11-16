//! Implements orchard/verifier logic.
//! The verifier lives in `super::prover` (`DefaultOrchardVerifier`); this
//! module re-exports it so `orchard::verifier` matches the reference layout.

pub use super::prover::{DefaultOrchardVerifier, OrchardBatchVerifyProofInputs};
