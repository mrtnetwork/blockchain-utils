//! Implements orchard/gadget logic (`OrchardGadget`).
//! Value commit, nullifier, CommitIvk and NoteCommit gadgets over the
//! previously ported chips. Length `assert!`s become `Err`.

#[cfg(feature = "alloc")]
use alloc::string::String;
// `Vec` is prelude under `std`; import from `alloc` only for `no_std`.
#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::vec::Vec;

use crate::zk::orchard_halo2::chip::ecc::{
    EccConfig, EccPoint, EccPointWithConfig, EccScalarFixed,
};
use crate::zk::orchard_halo2::chip::lookup::LookupRangeCheckConfig;
use crate::zk::orchard_halo2::crypto_context::CryptoContext;
use crate::zk::orchard_halo2::error::{Halo2Error, Halo2Result};
use crate::zk::orchard_halo2::field::{PallasFp, T_P_LE};
use crate::zk::orchard_halo2::orchard::configs::add::OrchardAddConfig;
use crate::zk::orchard_halo2::orchard::configs::commit_ivk::{CommitIvkConfig, GateCells};
use crate::zk::orchard_halo2::orchard::configs::note_commit::NoteCommitConfig;
use crate::zk::orchard_halo2::orchard::constants::fixed_bases::FullBase;
use crate::zk::orchard_halo2::poseidon::poseidon::{HaloPoseidonHash, Pow5Config};
use crate::zk::orchard_halo2::sinsemilla::merkle::SinsemillaConfig;
use crate::zk::orchard_halo2::sinsemilla::message::SinsemillaMessagePiece;
use crate::zk::orchard_halo2::sinsemilla::sinsemilla::HaloCommitDomains;
use crate::zk::orchard_halo2::utility::layouter::{AssignedCell, Layouter};
use crate::zk::orchard_halo2::utility::range_constrained::RangeConstrained;

pub struct OrchardGadget;

impl OrchardGadget {
    pub fn value_commit_orchard<L: Layouter + ?Sized>(
        layouter: &mut L,
        chip: &EccConfig,
        v: crate::zk::orchard_halo2::chip::ecc::EccScalarFixedShort,
        rcv: EccScalarFixed,
    ) -> Halo2Result<EccPointWithConfig> {
        let (p, _) = chip.mul_fixed_short(
            layouter,
            v,
            crate::zk::orchard_halo2::orchard::constants::fixed_bases::ValueCommitV,
        )?;
        let commitment = EccPointWithConfig {
            chip: *chip,
            inner: p,
        };
        let (blind_point, _) = chip.mul_fixed(layouter, rcv, FullBase::ValueCommitR)?;
        let blind = EccPointWithConfig {
            chip: *chip,
            inner: blind_point,
        };
        commitment.add(layouter, &blind)
    }

    #[allow(clippy::too_many_arguments)] // Gate API mirrors upstream halo2 circuit signatures; regrouping args would churn call sites.
    pub fn derive_nullifier<L: Layouter + ?Sized>(
        layouter: &mut L,
        poseidon_chip: &Pow5Config,
        add_chip: &OrchardAddConfig,
        chip: &EccConfig,
        rho: &AssignedCell<PallasFp>,
        psi: &AssignedCell<PallasFp>,
        cm: &EccPointWithConfig,
        nk: &AssignedCell<PallasFp>,
    ) -> Halo2Result<AssignedCell<PallasFp>> {
        let mut hasher = HaloPoseidonHash::init(layouter, poseidon_chip)?;
        let hash = hasher.hash(layouter, vec![*nk, *rho])?;
        let scalar = add_chip.add(layouter, &hash, psi)?;
        let mul = chip.mul_fixed_base_field_elem(
            layouter,
            &scalar,
            crate::zk::orchard_halo2::orchard::constants::fixed_bases::NullifierK,
        )?;
        Ok(cm
            .add(
                layouter,
                &EccPointWithConfig {
                    chip: *chip,
                    inner: mul,
                },
            )?
            .extract_p())
    }

    #[allow(clippy::too_many_arguments)] // Gate API mirrors upstream halo2 circuit signatures; regrouping args would churn call sites.
    pub fn commit_ivk<L: Layouter + ?Sized>(
        sinsemilla_chip: &SinsemillaConfig,
        ecc_chip: &EccConfig,
        commit_ivk_chip: &CommitIvkConfig,
        layouter: &mut L,
        ak: &AssignedCell<PallasFp>,
        nk: &AssignedCell<PallasFp>,
        rivk: EccScalarFixed,
        context: &dyn CryptoContext,
    ) -> Halo2Result<AssignedCell<PallasFp>> {
        let a = SinsemillaMessagePiece::from_subpieces(
            sinsemilla_chip,
            layouter,
            vec![RangeConstrained::bitrange_of(ak.value, 0, 250)],
        )?;
        let b0 = sinsemilla_chip
            .lookup_config
            .witness_short(layouter, ak.value, 250, 254)?;
        let b1 = RangeConstrained::bitrange_of(ak.value, 254, 255);
        let b2 = sinsemilla_chip
            .lookup_config
            .witness_short(layouter, nk.value, 0, 5)?;
        let b = SinsemillaMessagePiece::from_subpieces(
            sinsemilla_chip,
            layouter,
            vec![b0.value(), b1.clone(), b2.value()],
        )?;
        let c = SinsemillaMessagePiece::from_subpieces(
            sinsemilla_chip,
            layouter,
            vec![RangeConstrained::bitrange_of(nk.value, 5, 245)],
        )?;
        let d0 = sinsemilla_chip
            .lookup_config
            .witness_short(layouter, nk.value, 245, 254)?;
        let d1 = RangeConstrained::bitrange_of(nk.value, 254, 255);
        let d = SinsemillaMessagePiece::from_subpieces(
            sinsemilla_chip,
            layouter,
            vec![d0.value(), d1.clone()],
        )?;
        let message = crate::zk::orchard_halo2::sinsemilla::message::SinsemillaMessage {
            messages: vec![a.clone(), b.clone(), c.clone(), d.clone()],
        };
        let q = context.get_domain_point_affine(b"z.cash:Orchard-CommitIvk-M")?;
        let domain = HaloCommitDomains::init(*ecc_chip, sinsemilla_chip, q, FullBase::CommitIvkR);
        let (ivk, zs) = domain.short_commit(layouter, &message, rivk)?;
        let z13_a = zs[0]
            .get(13)
            .copied()
            .ok_or_else(|| Halo2Error::operation_failed("gadget::commit_ivk", "missing z13a"))?;
        let z13_c = zs[2]
            .get(13)
            .copied()
            .ok_or_else(|| Halo2Error::operation_failed("gadget::commit_ivk", "missing z13c"))?;
        let (a_prime, z13_a_prime) =
            Self::ak_canonicity(&sinsemilla_chip.lookup_config, layouter, &a.cell_value)?;
        let (b2_c_prime, z14) =
            Self::nk_canonicity(&sinsemilla_chip.lookup_config, layouter, &b2, &c.cell_value)?;
        let cells = GateCells {
            a: a.cell_value,
            b: b.cell_value,
            c: c.cell_value,
            d: d.cell_value,
            ak: *ak,
            nk: *nk,
            b0,
            b1,
            b2,
            d0,
            d1,
            z13_a,
            a_prime,
            z13_a_prime,
            z13_c,
            b2_c_prime,
            z14_b2_c_prime: z14,
        };
        commit_ivk_chip.assign_gate(layouter, &cells)?;
        Ok(ivk)
    }

    pub fn nk_canonicity<L: Layouter + ?Sized>(
        lookup_config: &LookupRangeCheckConfig,
        layouter: &mut L,
        b2: &RangeConstrained<AssignedCell<PallasFp>>,
        c: &AssignedCell<PallasFp>,
    ) -> Halo2Result<(AssignedCell<PallasFp>, AssignedCell<PallasFp>)> {
        let mut prime_val: Option<PallasFp> = None;
        if let (Some(b), Some(cv)) = (b2.inner.value, c.value) {
            prime_val = Some(
                b.add_vartime(&cv.mul_vartime(&PallasFp::from_u64(32)))
                    .add_vartime(&PallasFp::from_u64(2).pow_u64(140))
                    .sub_vartime(&PallasFp::from_le_array(&T_P_LE)?),
            );
        }
        let zs = lookup_config.witness_check(layouter, prime_val, 14, false)?;
        if zs.len() != 15 {
            return Err(Halo2Error::operation_failed("gadget::nk_canon", "bad zs"));
        }
        Ok((zs[0], zs[14]))
    }

    pub fn ak_canonicity<L: Layouter + ?Sized>(
        lookup_config: &LookupRangeCheckConfig,
        layouter: &mut L,
        a: &AssignedCell<PallasFp>,
    ) -> Halo2Result<(AssignedCell<PallasFp>, AssignedCell<PallasFp>)> {
        let mut prime_val: Option<PallasFp> = None;
        if let Some(v) = a.value {
            prime_val = Some(
                v.add_vartime(&PallasFp::from_u64(2).pow_u64(130))
                    .sub_vartime(&PallasFp::from_le_array(&T_P_LE)?),
            );
        }
        let zs = lookup_config.witness_check(layouter, prime_val, 13, false)?;
        if zs.len() != 14 {
            return Err(Halo2Error::operation_failed("gadget::ak_canon", "bad zs"));
        }
        Ok((zs[0], zs[13]))
    }

    #[allow(clippy::too_many_arguments)] // Gate API mirrors upstream halo2 circuit signatures; regrouping args would churn call sites.
    pub fn note_commit<L: Layouter + ?Sized>(
        layouter: &mut L,
        chip: &SinsemillaConfig,
        ecc_chip: &EccConfig,
        note_commit_chip: &NoteCommitConfig,
        g_d: &EccPoint,
        pk_d: &EccPoint,
        value: &AssignedCell<PallasFp>,
        rho: &AssignedCell<PallasFp>,
        psi: &AssignedCell<PallasFp>,
        rcm: EccScalarFixed,
        context: &dyn CryptoContext,
    ) -> Halo2Result<EccPointWithConfig> {
        let lookup = &chip.lookup_config;
        let a = SinsemillaMessagePiece::from_subpieces(
            chip,
            layouter,
            vec![RangeConstrained::bitrange_of(g_d.get_x().value, 0, 250)],
        )?;
        let (b, b0, b1, b2, b3) = note_commit_chip
            .b
            .decompose(lookup, chip, layouter, g_d, pk_d)?;
        let c = SinsemillaMessagePiece::from_subpieces(
            chip,
            layouter,
            vec![RangeConstrained::bitrange_of(pk_d.get_x().value, 4, 254)],
        )?;
        let (d, d0, d1, d2) = note_commit_chip
            .d
            .decompose(lookup, chip, layouter, pk_d, value)?;
        let (e, e0, e1) = note_commit_chip
            .e
            .decompose(lookup, chip, layouter, value, rho)?;
        let f = SinsemillaMessagePiece::from_subpieces(
            chip,
            layouter,
            vec![RangeConstrained::bitrange_of(rho.value, 4, 254)],
        )?;
        let (g, g0, g1) = note_commit_chip
            .g
            .decompose(lookup, chip, layouter, rho, psi)?;
        let (h, h0, h1) = note_commit_chip.h.decompose(lookup, chip, layouter, psi)?;
        let b2_checked = Self::y_canonicity(
            lookup,
            &note_commit_chip.y_canon,
            layouter,
            &g_d.get_y(),
            b2,
        )?;
        let d1_checked = Self::y_canonicity(
            lookup,
            &note_commit_chip.y_canon,
            layouter,
            &pk_d.get_y(),
            d1,
        )?;

        let message = crate::zk::orchard_halo2::sinsemilla::message::SinsemillaMessage {
            messages: vec![
                a.clone(),
                b.clone(),
                c.clone(),
                d.clone(),
                e.clone(),
                f.clone(),
                g.clone(),
                h.clone(),
            ],
        };
        let q = context.get_domain_point_affine(b"z.cash:Orchard-NoteCommit-M")?;
        let domain = HaloCommitDomains::init(*ecc_chip, chip, q, FullBase::NoteCommitR);
        let (cm, zs) = domain.commit(layouter, &message, rcm)?;

        let get = |a: usize, b: usize| -> Halo2Result<AssignedCell<PallasFp>> {
            zs.get(a)
                .and_then(|r| r.get(b))
                .copied()
                .ok_or_else(|| Halo2Error::operation_failed("gadget::note_commit", "missing zs"))
        };
        let (z13_a, z13_c, z1_d, z13_f, z1_g, z13_g) = (
            get(0, 13)?,
            get(2, 13)?,
            get(3, 1)?,
            get(5, 13)?,
            get(6, 1)?,
            get(6, 13)?,
        );
        let g2 = z1_g;
        let (canon_a_prime, canon_a_z13) =
            Self::canon_bitshift130(lookup, layouter, &a.cell_value)?;
        let (canon_pk_prime, canon_pk_z14) =
            Self::pkd_x_canonicity(lookup, layouter, &b3, &c.cell_value)?;
        let (canon_rho_prime, canon_rho_z14) =
            Self::rho_canonicity(lookup, layouter, &e1, &f.cell_value)?;
        let (canon_psi_prime, canon_psi_z13) = Self::psi_canonicity(lookup, layouter, &g1, &g2)?;

        let b1_assigned = note_commit_chip
            .b
            .assign(layouter, &b, &b0, &b1, &b2_checked, &b3)?;
        let d0_assigned = note_commit_chip
            .d
            .assign(layouter, &d, &d0, &d1_checked, &d2, &z1_d)?;
        note_commit_chip.e.assign(layouter, &e, &e0, &e1)?;
        let g0_assigned = note_commit_chip.g.assign(layouter, &g, &g0, &g1, &z1_g)?;
        let h1_assigned = note_commit_chip.h.assign(layouter, &h, &h0, &h1)?;
        note_commit_chip.g_d.assign(
            layouter,
            g_d,
            &a,
            &b0,
            &b1_assigned,
            &canon_a_prime,
            &z13_a,
            &canon_a_z13,
        )?;
        note_commit_chip.pk_d.assign(
            layouter,
            pk_d,
            &b3,
            &c,
            &d0_assigned,
            &canon_pk_prime,
            &z13_c,
            &canon_pk_z14,
        )?;
        note_commit_chip
            .value
            .assign(layouter, value, &d2, &z1_d, &e0)?;
        note_commit_chip.rho.assign(
            layouter,
            rho,
            &e1,
            &f,
            &g0_assigned,
            &canon_rho_prime,
            &z13_f,
            &canon_rho_z14,
        )?;
        note_commit_chip.psi.assign(
            layouter,
            psi,
            &g1,
            &z1_g,
            &h0,
            &h1_assigned,
            &canon_psi_prime,
            &z13_g,
            &canon_psi_z13,
        )?;
        Ok(cm)
    }

    pub fn canon_bitshift130<L: Layouter + ?Sized>(
        lookup_config: &LookupRangeCheckConfig,
        layouter: &mut L,
        a: &AssignedCell<PallasFp>,
    ) -> Halo2Result<(AssignedCell<PallasFp>, AssignedCell<PallasFp>)> {
        let mut prime: Option<PallasFp> = None;
        if let Some(v) = a.value {
            prime = Some(
                v.add_vartime(&PallasFp::from_u64(2).pow_u64(130))
                    .sub_vartime(&PallasFp::from_le_array(&T_P_LE)?),
            );
        }
        let zs = lookup_config.witness_check(layouter, prime, 13, false)?;
        if zs.len() != 14 {
            return Err(Halo2Error::operation_failed("gadget::canon130", "bad zs"));
        }
        Ok((zs[0], zs[13]))
    }

    pub fn y_canonicity<L: Layouter + ?Sized>(
        lookup_config: &LookupRangeCheckConfig,
        y_canon: &crate::zk::orchard_halo2::orchard::configs::note_commit::YCanonicity,
        layouter: &mut L,
        y: &AssignedCell<PallasFp>,
        lsb: RangeConstrained<Option<PallasFp>>,
    ) -> Halo2Result<RangeConstrained<AssignedCell<PallasFp>>> {
        let k0 = lookup_config.witness_short(layouter, y.value, 1, 10)?;
        let k1 = RangeConstrained::bitrange_of(y.value, 10, 250);
        let k2 = lookup_config.witness_short(layouter, y.value, 250, 254)?;
        let k3 = RangeConstrained::bitrange_of(y.value, 254, 255);
        let mut j_value: Option<PallasFp> = None;
        if let (Some(l), Some(k0v), Some(k1v)) = (lsb.inner, k0.inner.value, k1.inner) {
            j_value = Some(
                l.add_vartime(&PallasFp::from_u64(2).mul_vartime(&k0v))
                    .add_vartime(&PallasFp::from_u64(1024).mul_vartime(&k1v)),
            );
        }
        let zs = lookup_config.witness_check(layouter, j_value, 25, true)?;
        if zs.len() != 26 {
            return Err(Halo2Error::operation_failed("gadget::y_canon", "bad zs"));
        }
        let (j, z1_j, z13_j) = (zs[0], zs[1], zs[13]);
        let (j_prime, z13_j_prime) = Self::canon_bitshift130(lookup_config, layouter, &j)?;
        y_canon.assign(
            layouter,
            y,
            &lsb,
            &k0,
            &k2,
            &k3,
            &j,
            &z1_j,
            &z13_j,
            &j_prime,
            &z13_j_prime,
        )
    }

    pub fn pkd_x_canonicity<L: Layouter + ?Sized>(
        lookup_config: &LookupRangeCheckConfig,
        layouter: &mut L,
        b3: &RangeConstrained<AssignedCell<PallasFp>>,
        c: &AssignedCell<PallasFp>,
    ) -> Halo2Result<(AssignedCell<PallasFp>, AssignedCell<PallasFp>)> {
        let mut prime: Option<PallasFp> = None;
        if let (Some(b), Some(cv)) = (b3.inner.value, c.value) {
            prime = Some(
                b.add_vartime(&PallasFp::from_u64(16).mul_vartime(&cv))
                    .add_vartime(&PallasFp::from_u64(2).pow_u64(140))
                    .sub_vartime(&PallasFp::from_le_array(&T_P_LE)?),
            );
        }
        let zs = lookup_config.witness_check(layouter, prime, 14, false)?;
        if zs.len() != 15 {
            return Err(Halo2Error::operation_failed("gadget::pkd_canon", "bad zs"));
        }
        Ok((zs[0], zs[14]))
    }

    pub fn rho_canonicity<L: Layouter + ?Sized>(
        lookup_config: &LookupRangeCheckConfig,
        layouter: &mut L,
        e1: &RangeConstrained<AssignedCell<PallasFp>>,
        f: &AssignedCell<PallasFp>,
    ) -> Halo2Result<(AssignedCell<PallasFp>, AssignedCell<PallasFp>)> {
        let mut prime: Option<PallasFp> = None;
        if let (Some(e), Some(fv)) = (e1.inner.value, f.value) {
            prime = Some(
                e.add_vartime(&PallasFp::from_u64(16).mul_vartime(&fv))
                    .add_vartime(&PallasFp::from_u64(2).pow_u64(140))
                    .sub_vartime(&PallasFp::from_le_array(&T_P_LE)?),
            );
        }
        let zs = lookup_config.witness_check(layouter, prime, 14, false)?;
        if zs.len() != 15 {
            return Err(Halo2Error::operation_failed("gadget::rho_canon", "bad zs"));
        }
        Ok((zs[0], zs[14]))
    }

    pub fn psi_canonicity<L: Layouter + ?Sized>(
        lookup_config: &LookupRangeCheckConfig,
        layouter: &mut L,
        g1: &RangeConstrained<AssignedCell<PallasFp>>,
        g2: &AssignedCell<PallasFp>,
    ) -> Halo2Result<(AssignedCell<PallasFp>, AssignedCell<PallasFp>)> {
        let mut prime: Option<PallasFp> = None;
        if let (Some(g), Some(gv)) = (g1.inner.value, g2.value) {
            prime = Some(
                g.add_vartime(&PallasFp::from_u64(512).mul_vartime(&gv))
                    .add_vartime(&PallasFp::from_u64(2).pow_u64(130))
                    .sub_vartime(&PallasFp::from_le_array(&T_P_LE)?),
            );
        }
        let zs = lookup_config.witness_check(layouter, prime, 13, false)?;
        if zs.len() != 14 {
            return Err(Halo2Error::operation_failed("gadget::psi_canon", "bad zs"));
        }
        Ok((zs[0], zs[13]))
    }

    #[cfg(feature = "alloc")]
    pub fn to_debug_string() -> String {
        alloc::string::String::from("OrchardGadget")
    }
}
