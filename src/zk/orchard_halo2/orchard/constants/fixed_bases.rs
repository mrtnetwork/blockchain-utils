//! Implements orchard/constants/fixed_bases logic.
//! Clean API over compile-time LE byte tables (`constants.rs`):
//! no hex strings, no runtime `BigInt.parse`. Generators decode LE bytes
//! via `PallasFp::from_le_array` (Result style). Debug via `format!`.

#[cfg(feature = "alloc")]
use alloc::string::String;
// `Vec` is prelude under `std`; import from `alloc` only for `no_std`.
#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::vec::Vec;

use crate::zk::orchard_halo2::error::{Halo2Error, Halo2Result};
use crate::zk::orchard_halo2::field::PallasFp;
use crate::zk::orchard_halo2::orchard::constants::constants as C;
use crate::zk::orchard_halo2::tables as T;

/// A fixed base with LE-encoded generator, `z` shifts and `u` table.
pub trait FixedBase {
    fn num_windows(&self) -> usize;
    fn generator_le(&self) -> ([u8; 32], [u8; 32]);
    /// Generator as Montgomery limbs (unchecked, no conversion).
    fn generator_mont(&self) -> [[u64; 4]; 2];
    fn z(&self) -> &'static [u32];
    fn u_le(&self, window: usize) -> Halo2Result<[[u8; 32]; 8]>;
    /// Precomputed Lagrange x-coefficients [windows][8] LE (bit-exact).
    fn lagrange_le(&self) -> &'static [[[u8; 32]; 8]];

    fn generator_fp(&self) -> Halo2Result<(PallasFp, PallasFp)> {
        let (x, y) = self.generator_le();
        Ok((PallasFp::from_le_array(&x)?, PallasFp::from_le_array(&y)?))
    }

    fn u_fp(&self, window: usize) -> Halo2Result<[PallasFp; 8]> {
        let row = self.u_le(window)?;
        let mut out = [PallasFp::zero(); 8];
        for (i, b) in row.iter().enumerate() {
            out[i] = PallasFp::from_le_array(b)?;
        }
        Ok(out)
    }

    #[cfg(feature = "alloc")]
    fn to_debug_string(&self) -> String;
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum FullBase {
    CommitIvkR,
    NoteCommitR,
    ValueCommitR,
    SpendAuthG,
}

impl FixedBase for FullBase {
    fn num_windows(&self) -> usize {
        85
    }

    fn generator_le(&self) -> ([u8; 32], [u8; 32]) {
        match self {
            Self::SpendAuthG => (C::ORCHARDSPENDAUTHG_BASE_X, C::ORCHARDSPENDAUTHG_BASE_Y),
            Self::NoteCommitR => (C::ORCHARDNOTECOMMIT_BASE_X, C::ORCHARDNOTECOMMIT_BASE_Y),
            Self::ValueCommitR => (C::ORCHARDVALUECOMMITR_BASE_X, C::ORCHARDVALUECOMMITR_BASE_Y),
            Self::CommitIvkR => (C::ORCHARDCOMMITIVK_BASE_X, C::ORCHARDCOMMITIVK_BASE_Y),
        }
    }
    fn generator_mont(&self) -> [[u64; 4]; 2] {
        match self {
            Self::SpendAuthG => ORCHARDSPENDAUTHG_BASE_MONT,
            Self::NoteCommitR => ORCHARDNOTECOMMIT_BASE_MONT,
            Self::ValueCommitR => ORCHARDVALUECOMMITR_BASE_MONT,
            Self::CommitIvkR => ORCHARDCOMMITIVK_BASE_MONT,
        }
    }

    fn z(&self) -> &'static [u32] {
        match self {
            Self::SpendAuthG => &C::ORCHARDSPENDAUTHG_Z,
            Self::NoteCommitR => &C::ORCHARDNOTECOMMIT_Z,
            Self::ValueCommitR => &C::ORCHARDVALUECOMMITR_Z,
            Self::CommitIvkR => &C::ORCHARDCOMMITIVK_Z,
        }
    }

    fn u_le(&self, window: usize) -> Halo2Result<[[u8; 32]; 8]> {
        let table: &[[[u8; 32]; 8]] = match self {
            Self::SpendAuthG => &C::ORCHARDSPENDAUTHG_U,
            Self::NoteCommitR => &C::ORCHARDNOTECOMMIT_U,
            Self::ValueCommitR => &C::ORCHARDVALUECOMMITR_U,
            Self::CommitIvkR => &C::ORCHARDCOMMITIVK_U,
        };
        table
            .get(window)
            .copied()
            .ok_or_else(|| Halo2Error::operation_failed("fixed_base::u", "window out of range"))
    }

    fn lagrange_le(&self) -> &'static [[[u8; 32]; 8]] {
        match self {
            Self::SpendAuthG => &T::SPENDAUTHG_LAGRANGE,
            Self::NoteCommitR => &T::NOTECOMMITR_LAGRANGE,
            Self::ValueCommitR => &T::VALUECOMMITR_LAGRANGE,
            Self::CommitIvkR => &T::COMMITIVKR_LAGRANGE,
        }
    }

    #[cfg(feature = "alloc")]
    fn to_debug_string(&self) -> String {
        let name = match self {
            Self::CommitIvkR => "commitIvkR",
            Self::NoteCommitR => "noteCommitR",
            Self::ValueCommitR => "valueCommitR",
            Self::SpendAuthG => "spendAuthG",
        };
        let (x, y) = self.generator_le();
        alloc::format!(
            "FixedBaseFull({}, x: {}, y: {}, windows: {})",
            name,
            crate::zk::orchard_halo2::bytes::to_hex_be_prefixed_alloc(&x),
            crate::zk::orchard_halo2::bytes::to_hex_be_prefixed_alloc(&y),
            self.num_windows()
        )
    }
}

pub struct NullifierK;

impl FixedBase for NullifierK {
    fn num_windows(&self) -> usize {
        85
    }

    fn generator_le(&self) -> ([u8; 32], [u8; 32]) {
        (C::ORCHARDNULLIFIERK_BASE_X, C::ORCHARDNULLIFIERK_BASE_Y)
    }
    fn generator_mont(&self) -> [[u64; 4]; 2] {
        ORCHARDNULLIFIERK_BASE_MONT
    }

    fn z(&self) -> &'static [u32] {
        &C::ORCHARDNULLIFIERK_Z
    }

    fn u_le(&self, window: usize) -> Halo2Result<[[u8; 32]; 8]> {
        C::ORCHARDNULLIFIERK_U
            .get(window)
            .copied()
            .ok_or_else(|| Halo2Error::operation_failed("fixed_base::u", "window out of range"))
    }

    fn lagrange_le(&self) -> &'static [[[u8; 32]; 8]] {
        &T::NULLIFIERK_LAGRANGE
    }

    #[cfg(feature = "alloc")]
    fn to_debug_string(&self) -> String {
        alloc::string::String::from("FixedBase(nullifierK, windows: 85)")
    }
}

pub struct ValueCommitV;

impl FixedBase for ValueCommitV {
    fn num_windows(&self) -> usize {
        22
    }

    fn generator_le(&self) -> ([u8; 32], [u8; 32]) {
        (C::ORCHARDVALUECOMMITV_BASE_X, C::ORCHARDVALUECOMMITV_BASE_Y)
    }
    fn generator_mont(&self) -> [[u64; 4]; 2] {
        ORCHARDVALUECOMMITV_BASE_MONT
    }

    fn z(&self) -> &'static [u32] {
        &C::ORCHARDVALUECOMMITV_Z
    }

    fn u_le(&self, window: usize) -> Halo2Result<[[u8; 32]; 8]> {
        C::ORCHARDVALUECOMMITV_U
            .get(window)
            .copied()
            .ok_or_else(|| Halo2Error::operation_failed("fixed_base::u", "window out of range"))
    }

    fn lagrange_le(&self) -> &'static [[[u8; 32]; 8]] {
        &T::VALUECOMMITV_LAGRANGE
    }

    #[cfg(feature = "alloc")]
    fn to_debug_string(&self) -> String {
        alloc::string::String::from("FixedBase(valueCommitV, windows: 22)")
    }
}
// Fixed-base generators as Montgomery limbs (unchecked).
// Generated from `constants.rs` LE bytes; load with `from_affine_mont_limbs`.

pub const ORCHARDSPENDAUTHG_BASE_MONT: [[u64; 4]; 2] = [
    [
        5264466673313547928,
        10333203565794581066,
        9965125688782365053,
        1191378874554977547,
    ],
    [
        16613790901992704663,
        2660772978433416708,
        8778179246636635677,
        935550387939465227,
    ],
];
pub const ORCHARDNOTECOMMIT_BASE_MONT: [[u64; 4]; 2] = [
    [
        8733257103008891519,
        13102218297985517998,
        10585865075856119621,
        3251806556531842579,
    ],
    [
        13296719146072255912,
        3285228197737509799,
        7310949420390645216,
        2250581666821098065,
    ],
];
pub const ORCHARDVALUECOMMITR_BASE_MONT: [[u64; 4]; 2] = [
    [
        2845817119958416836,
        9164760055157252168,
        17374653478061863198,
        1858716823038486356,
    ],
    [
        5358554816547260529,
        12651796841123479157,
        5360682003649880277,
        3717404296076135847,
    ],
];
pub const ORCHARDCOMMITIVK_BASE_MONT: [[u64; 4]; 2] = [
    [
        798294910756764276,
        11184908281550712938,
        13763444790617342549,
        2562141719027363819,
    ],
    [
        14704726316066658977,
        2135579965058735105,
        4040393330797142932,
        1092896874057398600,
    ],
];
pub const ORCHARDNULLIFIERK_BASE_MONT: [[u64; 4]; 2] = [
    [
        6462649102716222376,
        3236211048384560624,
        10080215765758817635,
        1819896793334342575,
    ],
    [
        11570266481667401216,
        10250616822194834319,
        7375833611117897183,
        3565054432703740043,
    ],
];
pub const ORCHARDVALUECOMMITV_BASE_MONT: [[u64; 4]; 2] = [
    [
        9736663461290671665,
        14894112383296529695,
        12212730830462686952,
        1327727298026885211,
    ],
    [
        6090618634769829689,
        17048142026232542733,
        155522756301207405,
        3089927062619958092,
    ],
];
