//! Encoding and decoding utilities.
//!
//! | Module | Spec / use |
//! |--------|------------|
//! | [`hex`]  | Hex encode/decode |

pub mod hex;

pub use hex::{decode_to_slice, decoded_len, encode_to_slice};

#[cfg(feature = "alloc")]
pub use hex::{decode, encode, encode_upper};
