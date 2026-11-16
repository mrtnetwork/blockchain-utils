//! Implements sinsemilla/table logic (`GeneratorTableConfig`).
//! Lookup tuples built with `try_*` operators; fixed-base init point comes
//! from the precomputed S2 LE table (no runtime hashing).

#[cfg(feature = "alloc")]
use alloc::string::String;
// `Vec` is prelude under `std`; import from `alloc` only for `no_std`.
#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::vec::Vec;

use crate::zk::orchard_halo2::curve::PallasAffine;
use crate::zk::orchard_halo2::error::{Halo2Error, Halo2Result};
use crate::zk::orchard_halo2::field::PallasFp;
use crate::zk::orchard_halo2::plonk::column::TableColumn;
use crate::zk::orchard_halo2::plonk::constraint::ConstraintSystem;
use crate::zk::orchard_halo2::poly::poly::Rotation;
use crate::zk::orchard_halo2::sinsemilla::merkle::SinsemillaConfig;
use crate::zk::orchard_halo2::utility::layouter::Layouter;

#[derive(Clone, Copy)]
pub struct GeneratorTableConfig {
    pub table_idx: TableColumn,
    pub table_x: TableColumn,
    pub table_y: TableColumn,
}

impl GeneratorTableConfig {
    pub fn configure(meta: &mut ConstraintSystem, config: &SinsemillaConfig) -> Halo2Result<()> {
        meta.lookup(
            &mut |meta: &mut crate::zk::orchard_halo2::plonk::constraint::VirtualCells<'_>| {
                let q_s1 = meta.query_selector(config.q_sinsemilla1);
                let q_s2 = meta.query_fixed(config.q_sinsemilla2);
                let q_s3 = config.q_s3(meta)?;
                let q_run = q_s2.try_sub(&q_s3)?;

                let z_cur = meta.query_advice(config.bits, Rotation::cur());
                let z_next = meta.query_advice(config.bits, Rotation::next());
                let word = z_cur.try_sub(
                    &q_run
                        .try_mul_expr(&z_next)?
                        .scale(PallasFp::from_u64(1u64 << 10)),
                )?;

                let x_p_cur = meta.query_advice(config.double_and_add.x_p, Rotation::cur());
                let lambda1 = meta.query_advice(config.double_and_add.lambda1, Rotation::cur());
                let x_a = meta.query_advice(config.double_and_add.x_a, Rotation::cur());
                let y_a_full = config.double_and_add.y_a(meta, Rotation::cur())?;
                let y_p = y_a_full
                    .scale(PallasFp::two_inv())
                    .try_sub(&lambda1.try_mul_expr(&x_a.try_sub(&x_p_cur)?)?)?;

                let s0 = config.sinsemilla_s.first().ok_or_else(|| {
                    Halo2Error::operation_failed("table::configure", "empty S table")
                })?;
                let (sxb, syb, _) = s0.to_affine_le()?;
                let init_x = PallasFp::from_le_array(&sxb)?;
                let init_y = PallasFp::from_le_array(&syb)?;
                let not_qs1 = crate::zk::orchard_halo2::plonk::expression::Expression::constant(
                    PallasFp::one(),
                )
                .try_sub(&q_s1)?;

                let m = q_s1.try_mul_expr(&word)?;
                let x_p = q_s1
                    .try_mul_expr(&x_p_cur)?
                    .try_add(&not_qs1.scale(init_x))?;
                let y_p_final = q_s1.try_mul_expr(&y_p)?.try_add(&not_qs1.scale(init_y))?;
                Ok(vec![
                    (m, config.generator_table.table_idx),
                    (x_p, config.generator_table.table_x),
                    (y_p_final, config.generator_table.table_y),
                ])
            },
        )?;
        Ok(())
    }

    pub fn load<L: Layouter + ?Sized>(
        &self,
        lookup_config: &crate::zk::orchard_halo2::chip::lookup::LookupRangeCheckConfig,
        layouter: &mut L,
        sinsemilla_s: &[PallasAffine],
    ) -> Halo2Result<()> {
        lookup_config.load_table(self, layouter, sinsemilla_s)
    }

    #[cfg(feature = "alloc")]
    pub fn to_debug_string(&self) -> String {
        alloc::string::String::from("GeneratorTableConfig")
    }
}
