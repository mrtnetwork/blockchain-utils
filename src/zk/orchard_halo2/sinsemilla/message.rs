//! Implements sinsemilla/message logic.

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

use crate::zk::orchard_halo2::error::{Halo2Error, Halo2Result};
use crate::zk::orchard_halo2::field::PallasFp;
use crate::zk::orchard_halo2::sinsemilla::merkle::SinsemillaConfig;
use crate::zk::orchard_halo2::utility::layouter::{AssignedCell, Layouter};
use crate::zk::orchard_halo2::utility::range_constrained::RangeConstrained;
use crate::zk::orchard_halo2::utility::utils::SINSEMILLA_K;

#[derive(Clone)]
pub struct SinsemillaMessagePiece {
    pub cell_value: AssignedCell<PallasFp>,
    pub num_words: usize,
}

impl SinsemillaMessagePiece {
    pub fn from_field_elem<L: Layouter + ?Sized>(
        chip: &SinsemillaConfig,
        layouter: &mut L,
        field_elem: Option<PallasFp>,
        num_words: usize,
    ) -> Halo2Result<Self> {
        chip.witness_message_piece(layouter, field_elem, num_words)
    }

    pub fn from_subpieces<L: Layouter + ?Sized>(
        chip: &SinsemillaConfig,
        layouter: &mut L,
        subpieces: Vec<RangeConstrained<Option<PallasFp>>>,
    ) -> Halo2Result<Self> {
        let mut field_elem = PallasFp::zero();
        let mut total_bits = 0usize;
        for sub in subpieces.iter() {
            if total_bits >= 64 {
                return Err(Halo2Error::operation_failed(
                    "message::from_subpieces",
                    "too many bits",
                ));
            }
            if let Some(f) = sub.inner {
                let shift = PallasFp::from_u64(2)
                    .pow_u64(total_bits as u64)
                    .mul_vartime(&f);
                field_elem = field_elem.add_vartime(&shift);
            }
            total_bits += sub.num_bits;
        }
        if !total_bits.is_multiple_of(SINSEMILLA_K) {
            return Err(Halo2Error::operation_failed(
                "message::from_subpieces",
                "bit length not divisible by K",
            ));
        }
        let num_words = total_bits / SINSEMILLA_K;
        Self::from_field_elem(chip, layouter, Some(field_elem), num_words)
    }

    #[cfg(feature = "alloc")]
    pub fn to_debug_string(&self) -> String {
        alloc::format!("SinsemillaMessagePiece(words: {})", self.num_words)
    }
}

#[derive(Clone)]
pub struct SinsemillaMessage {
    pub messages: Vec<SinsemillaMessagePiece>,
}
