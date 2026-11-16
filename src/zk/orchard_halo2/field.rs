//! Shared Pasta fields for orchard_halo2.
//!
//! No local field arithmetic is generated here: `PallasFp`/`VestaFq` are the
//! existing `crate::curve::{pallas,vesta}::Fe` types (4-limb Montgomery).
//! Only plain byte-level helpers (NOT field arithmetic) live in this module.

pub use crate::curve::pallas::Fe as PallasFp;
pub use crate::curve::vesta::Fe as VestaFq;

/// `tQ` (scalar-mul decomposition offset), plain U256 LE bytes (NOT mod p).
pub const T_Q_LE: [u8; 32] = [
    1, 0, 0, 0, 33, 235, 70, 140, 221, 168, 148, 9, 252, 152, 70, 34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0,
];
/// `tP` (canonicity offset), plain U256 LE bytes (NOT mod p).
pub const T_P_LE: [u8; 32] = [
    1, 0, 0, 0, 237, 48, 45, 153, 27, 249, 76, 9, 252, 152, 70, 34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0,
];

/// Plain 256-bit LE addition (for `scalar + tQ`), returns 32 bytes.
pub fn u256_add_le(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut carry: u16 = 0;
    for i in 0..32 {
        let s = a[i] as u16 + b[i] as u16 + carry;
        out[i] = s as u8;
        carry = s >> 8;
    }
    out
}
