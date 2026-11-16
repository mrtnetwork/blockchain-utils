//! Pasta curve points for orchard_halo2.
//!
//! No local point arithmetic is generated here: affine and projective point
//! types are the existing `crate::curve::{pallas,vesta}` points
//! (`PallasPoint`/`VestaPoint`, Jacobian/var-time/Pippenger inside).
//! Wire encodings and debug strings match `toBytes`/`fromBytes`.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::curve::pallas::pippenger_msm as pallas_pippenger;
use crate::curve::vesta::pippenger_msm as vesta_pippenger;
use crate::zk::orchard_halo2::error::{Halo2Error, Halo2Result};
use crate::zk::orchard_halo2::field::{PallasFp, VestaFq};

pub use crate::curve::pallas::PallasPoint as PallasAffine;
pub use crate::curve::pallas::PallasPoint as PallasProjective;
pub use crate::curve::pallas::Scalar as PallasScalar;
pub use crate::curve::vesta::Scalar as VestaScalar;
pub use crate::curve::vesta::VestaPoint as VestaAffine;
pub use crate::curve::vesta::VestaPoint as VestaProjective;

fn scalar_le_bytes(fe_to_le: &[u8; 32]) -> [u8; 32] {
    let mut b = [0u8; 32];
    b.copy_from_slice(fe_to_le);
    b
}

/// Serial MSM over Pallas: sum(scalar_i * base_i), Pippenger buckets.
/// Scalars live mod q (`VestaFq`); converted once to `pallas::Scalar`.
pub fn msm_pallas(scalars: &[VestaFq], bases: &[PallasAffine]) -> Halo2Result<PallasProjective> {
    if scalars.len() != bases.len() {
        return Err(Halo2Error::operation_failed(
            "msm_pallas",
            "length mismatch",
        ));
    }
    if scalars.is_empty() {
        return Ok(PallasAffine::identity());
    }
    let mut sc: Vec<PallasScalar> = Vec::with_capacity(scalars.len());
    for s in scalars.iter() {
        sc.push(PallasScalar::from_bytes_le(&scalar_le_bytes(
            &s.to_le_bytes(),
        ))?);
    }
    Ok(pallas_pippenger(bases, &sc))
}

/// Serial MSM over Vesta: sum(scalar_i * base_i), Pippenger buckets.
/// Scalars live mod p (`PallasFp`); converted once to `vesta::Scalar`.
pub fn msm_vesta(scalars: &[PallasFp], bases: &[VestaAffine]) -> Halo2Result<VestaProjective> {
    if scalars.len() != bases.len() {
        return Err(Halo2Error::operation_failed("msm_vesta", "length mismatch"));
    }
    if scalars.is_empty() {
        return Ok(VestaAffine::identity());
    }
    let mut sc: Vec<VestaScalar> = Vec::with_capacity(scalars.len());
    for s in scalars.iter() {
        sc.push(VestaScalar::from_bytes_le(&scalar_le_bytes(
            &s.to_le_bytes(),
        ))?);
    }
    Ok(vesta_pippenger(bases, &sc))
}
