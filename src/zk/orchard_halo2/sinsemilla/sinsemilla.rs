//! Implements sinsemilla/sinsemilla logic (hash/commit domains).

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

use crate::zk::orchard_halo2::chip::ecc::{
    EccConfig, EccPoint, EccPointWithConfig, EccScalarFixed,
};
use crate::zk::orchard_halo2::curve::PallasAffine;
use crate::zk::orchard_halo2::error::Halo2Result;
use crate::zk::orchard_halo2::field::PallasFp;
use crate::zk::orchard_halo2::orchard::constants::fixed_bases::FullBase;
use crate::zk::orchard_halo2::sinsemilla::merkle::SinsemillaConfig;
use crate::zk::orchard_halo2::sinsemilla::message::SinsemillaMessage;
use crate::zk::orchard_halo2::utility::layouter::{AssignedCell, Layouter};

// Sinsemilla hash output: x-coordinate cell plus per-piece running sums.
type SinsemillaHashCells = (AssignedCell<PallasFp>, Vec<Vec<AssignedCell<PallasFp>>>);

#[derive(Clone, Copy)]
pub struct HaloHashDomain<'a> {
    pub chip: &'a SinsemillaConfig,
    pub ecc_chip: EccConfig,
    pub q: PallasAffine,
}

impl<'a> HaloHashDomain<'a> {
    pub fn hash_to_point<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        message: &SinsemillaMessage,
    ) -> Halo2Result<(EccPointWithConfig, Vec<Vec<AssignedCell<PallasFp>>>)> {
        let (p, r) = self.chip.hash_to_point(layouter, &self.q, message)?;
        Ok((
            EccPointWithConfig {
                chip: self.ecc_chip,
                inner: p,
            },
            r,
        ))
    }

    pub fn hash_to_point_with_private_init<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        q: &EccPoint,
        message: &SinsemillaMessage,
    ) -> Halo2Result<(EccPoint, Vec<Vec<AssignedCell<PallasFp>>>)> {
        self.chip
            .hash_to_point_with_private_init(layouter, q, message)
    }

    pub fn hash<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        message: &SinsemillaMessage,
    ) -> Halo2Result<SinsemillaHashCells> {
        let (point, zs) = self.chip.hash_to_point(layouter, &self.q, message)?;
        Ok((point.get_x(), zs))
    }

    #[cfg(feature = "alloc")]
    pub fn to_debug_string(&self) -> String {
        alloc::string::String::from("HaloHashDomain")
    }
}

#[derive(Clone, Copy)]
pub struct HaloCommitDomains<'a> {
    pub m: HaloHashDomain<'a>,
    pub r: FullBase,
}

impl<'a> HaloCommitDomains<'a> {
    pub fn init(
        chip: EccConfig,
        sinsemilla_chip: &'a SinsemillaConfig,
        q: PallasAffine,
        r: FullBase,
    ) -> Self {
        Self {
            m: HaloHashDomain {
                chip: sinsemilla_chip,
                ecc_chip: chip,
                q,
            },
            r,
        }
    }

    pub fn commit<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        message: &SinsemillaMessage,
        r: EccScalarFixed,
    ) -> Halo2Result<(EccPointWithConfig, Vec<Vec<AssignedCell<PallasFp>>>)> {
        let (blind_point, _) = self.m.ecc_chip.mul_fixed(layouter, r, self.r)?;
        let blind = EccPointWithConfig {
            chip: self.m.ecc_chip,
            inner: blind_point,
        };
        let (p, zs) = self.m.hash_to_point(layouter, message)?;
        Ok((p.add(layouter, &blind)?, zs))
    }

    pub fn short_commit<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        message: &SinsemillaMessage,
        r: EccScalarFixed,
    ) -> Halo2Result<SinsemillaHashCells> {
        let (p, z) = self.commit(layouter, message, r)?;
        Ok((p.extract_p(), z))
    }
}
