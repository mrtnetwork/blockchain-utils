//! Implements orchard/circuit logic (`OrchardCircuitConfig`, `OrchardCircuit`).
//! Wallet-level key types from Zcash reference types are represented as their raw
//! field/point material (LE); no wallet dependency. The `path` length check
//! (`assert`) becomes `Err`.

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

use crate::zk::orchard_halo2::chip::ecc::{EccConfig, EccPointWithConfig};
use crate::zk::orchard_halo2::chip::lookup::LookupRangeCheckConfig;
use crate::zk::orchard_halo2::crypto_context::{CryptoContext, DefaultCryptoContext};
use crate::zk::orchard_halo2::curve::PallasAffine;
use crate::zk::orchard_halo2::error::{Halo2Error, Halo2Result};
use crate::zk::orchard_halo2::field::{PallasFp, VestaFq};
use crate::zk::orchard_halo2::orchard::configs::add::OrchardAddConfig;
use crate::zk::orchard_halo2::orchard::configs::commit_ivk::CommitIvkConfig;
use crate::zk::orchard_halo2::orchard::configs::note_commit::NoteCommitConfig;
use crate::zk::orchard_halo2::orchard::gadget::OrchardGadget;
use crate::zk::orchard_halo2::plonk::column::{AssignmentColumn, Selector};
use crate::zk::orchard_halo2::plonk::constraint::{ConstraintSystem, Constraints, VirtualCells};
use crate::zk::orchard_halo2::plonk::expression::Expression;
use crate::zk::orchard_halo2::poly::poly::Rotation;
use crate::zk::orchard_halo2::poseidon::poseidon::Pow5Config;
use crate::zk::orchard_halo2::sinsemilla::merkle::{
    HalOrchardMerklePath, MerkleConfig, SinsemillaConfig,
};
use crate::zk::orchard_halo2::utility::layouter::{AssignedCell, Layouter, Region};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OrchardProtocolVersion {
    InsecureV1 = 0,
    V2 = 1,
    V3 = 2,
}

#[derive(Clone)]
pub struct OrchardCircuitConfig {
    pub primary: AssignmentColumn,
    pub q_orchard: Selector,
    pub advices: Vec<AssignmentColumn>,
    pub add_config: OrchardAddConfig,
    pub ecc_config: EccConfig,
    pub poseidon_config: Pow5Config,
    pub merkle_config1: MerkleConfig,
    pub merkle_config2: MerkleConfig,
    pub sinsemilla_config1: SinsemillaConfig,
    pub sinsemilla_config2: SinsemillaConfig,
    pub commit_ivk_config: CommitIvkConfig,
    pub old_note_commit_config: NoteCommitConfig,
    pub new_note_commit_config: NoteCommitConfig,
    pub context: DefaultCryptoContext,
}

impl OrchardCircuitConfig {
    pub fn configure(
        meta: &mut ConstraintSystem,
        context: &DefaultCryptoContext,
    ) -> Halo2Result<Self> {
        let mut advices = Vec::with_capacity(10);
        for _ in 0..10 {
            advices.push(meta.advice_column());
        }
        let q_orchard = meta.selector();
        meta.create_gate(&mut |meta: &mut VirtualCells<'_>| {
            let q = meta.query_selector(q_orchard);
            let v_old = meta.query_advice(advices[0], Rotation::cur());
            let v_new = meta.query_advice(advices[1], Rotation::cur());
            let magnitude = meta.query_advice(advices[2], Rotation::cur());
            let sign = meta.query_advice(advices[3], Rotation::cur());
            let root = meta.query_advice(advices[4], Rotation::cur());
            let anchor = meta.query_advice(advices[5], Rotation::cur());
            let enable_spends = meta.query_advice(advices[6], Rotation::cur());
            let enable_outputs = meta.query_advice(advices[7], Rotation::cur());
            let one = Expression::constant(PallasFp::one());
            Ok(Constraints {
                selector: Some(q),
                constraints: vec![
                    v_old
                        .try_sub(&v_new)?
                        .try_sub(&magnitude.try_mul_expr(&sign)?)?,
                    v_old.try_mul_expr(&root.try_sub(&anchor)?)?,
                    v_old.try_mul_expr(&one.try_sub(&enable_spends)?)?,
                    v_new.try_mul_expr(&one.try_sub(&enable_outputs)?)?,
                ],
            })
        })?;

        let add_config = OrchardAddConfig::configure(advices[7], advices[8], advices[6], meta)?;

        let table_idx = meta.lookup_table_column();
        let lookup = (
            table_idx,
            meta.lookup_table_column(),
            meta.lookup_table_column(),
        );
        let primary = meta.instance_column();
        meta.enable_equality(primary);
        for col in advices.iter() {
            meta.enable_equality(*col);
        }
        let mut lagrange_coeffs = [advices[0]; 8];
        for slot in lagrange_coeffs.iter_mut() {
            *slot = meta.fixed_column();
        }
        let rc_a = [lagrange_coeffs[2], lagrange_coeffs[3], lagrange_coeffs[4]];
        let rc_b = [lagrange_coeffs[5], lagrange_coeffs[6], lagrange_coeffs[7]];
        meta.enable_constant(lagrange_coeffs[0]);

        let range_check = LookupRangeCheckConfig::configure(meta, advices[9], table_idx, 10)?;
        let ecc_config =
            EccConfig::configure(meta, advices_array(&advices)?, lagrange_coeffs, range_check)?;
        let poseidon_config = Pow5Config::configure(
            meta,
            vec![advices[6], advices[7], advices[8]],
            advices[5],
            rc_a.to_vec(),
            rc_b.to_vec(),
        )?;
        let sinsemilla_config1 = SinsemillaConfig::configure(
            meta,
            advices_array5(&advices, 0)?,
            advices[6],
            lagrange_coeffs[0],
            lookup,
            range_check,
            false,
            context,
        )?;
        let merkle_config1 = MerkleConfig::configure(meta, &sinsemilla_config1)?;
        let sinsemilla_config2 = SinsemillaConfig::configure(
            meta,
            advices_array5(&advices, 5)?,
            advices[7],
            lagrange_coeffs[1],
            lookup,
            range_check,
            false,
            context,
        )?;
        let merkle_config2 = MerkleConfig::configure(meta, &sinsemilla_config2)?;
        let commit_ivk_config = CommitIvkConfig::configure(meta, advices_array9(&advices)?)?;
        let old_note_commit_config =
            NoteCommitConfig::configure(meta, advices.clone(), &sinsemilla_config1)?;
        let new_note_commit_config =
            NoteCommitConfig::configure(meta, advices.clone(), &sinsemilla_config2)?;
        Ok(Self {
            primary,
            q_orchard,
            advices,
            add_config,
            ecc_config,
            poseidon_config,
            merkle_config1,
            merkle_config2,
            sinsemilla_config1,
            sinsemilla_config2,
            commit_ivk_config,
            old_note_commit_config,
            new_note_commit_config,
            context: DefaultCryptoContext,
        })
    }
}

fn advices_array(v: &[AssignmentColumn]) -> Halo2Result<[AssignmentColumn; 10]> {
    if v.len() < 10 {
        return Err(Halo2Error::operation_failed(
            "circuit::configure",
            "short advices",
        ));
    }
    Ok([v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], v[9]])
}

fn advices_array5(v: &[AssignmentColumn], at: usize) -> Halo2Result<[AssignmentColumn; 5]> {
    if v.len() < at + 5 {
        return Err(Halo2Error::operation_failed(
            "circuit::configure",
            "short advices",
        ));
    }
    Ok([v[at], v[at + 1], v[at + 2], v[at + 3], v[at + 4]])
}

fn advices_array9(v: &[AssignmentColumn]) -> Halo2Result<[AssignmentColumn; 9]> {
    if v.len() < 9 {
        return Err(Halo2Error::operation_failed(
            "circuit::configure",
            "short advices",
        ));
    }
    Ok([v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8]])
}

#[derive(Clone)]
pub struct OrchardCircuit {
    pub path: Option<Vec<PallasFp>>,
    pub pos: Option<usize>,
    pub gd_old: Option<PallasAffine>,
    pub pkd_old: Option<PallasAffine>,
    pub v_old: Option<u64>,
    pub rho_old: Option<PallasFp>,
    pub psi_old: Option<PallasFp>,
    pub rcm_old: Option<VestaFq>,
    pub cm_old: Option<PallasAffine>,
    pub alpha: Option<VestaFq>,
    pub ak: Option<PallasAffine>,
    pub nk: Option<PallasFp>,
    pub rivk: Option<VestaFq>,
    pub gd_new: Option<PallasAffine>,
    pub pkd_new: Option<PallasAffine>,
    pub v_new: Option<u64>,
    pub psi_new: Option<PallasFp>,
    pub rcm_new: Option<VestaFq>,
    pub rcv: Option<VestaFq>,
    pub version: OrchardProtocolVersion,
}

impl OrchardCircuit {
    pub fn default_config(version: OrchardProtocolVersion) -> Self {
        Self {
            path: None,
            pos: None,
            gd_old: None,
            pkd_old: None,
            v_old: None,
            rho_old: None,
            psi_old: None,
            rcm_old: None,
            cm_old: None,
            alpha: None,
            ak: None,
            nk: None,
            rivk: None,
            gd_new: None,
            pkd_new: None,
            v_new: None,
            psi_new: None,
            rcm_new: None,
            rcv: None,
            version,
        }
    }

    pub fn assign_free_advice<
        L: Layouter + ?Sized,
        F: Clone + crate::zk::orchard_halo2::utility::layouter::IntoAssigned,
    >(
        &self,
        layouter: &mut L,
        column: AssignmentColumn,
        value: Option<F>,
    ) -> Halo2Result<AssignedCell<F>> {
        let _ = self;
        layouter.assign_region(&mut |region: &mut Region<'_>| {
            region.assign_advice(column, 0, &mut || value.clone())
        })
    }

    pub fn synthesize_base<L: Layouter + ?Sized>(
        &self,
        config: &OrchardCircuitConfig,
        layouter: &mut L,
    ) -> Halo2Result<AddressPoint> {
        config.sinsemilla_config1.load(layouter)?;
        let chip = config.ecc_config;

        let psi_old = self.assign_free_advice(layouter, config.advices[0], self.psi_old)?;
        let rho_old = self.assign_free_advice(layouter, config.advices[0], self.rho_old)?;
        let cm_old = EccPointWithConfig {
            chip,
            inner: chip.witness_point(layouter, self.cm_old)?,
        };
        let gd_old = EccPointWithConfig {
            chip,
            inner: chip.witness_point_non_id(layouter, self.gd_old)?,
        };
        let ak_p = EccPointWithConfig {
            chip,
            inner: chip.witness_point_non_id(layouter, self.ak)?,
        };
        let nk: AssignedCell<PallasFp> =
            self.assign_free_advice(layouter, config.advices[0], self.nk)?;
        let v_old: AssignedCell<PallasFp> = self.assign_free_advice(
            layouter,
            config.advices[0],
            self.v_old.map(PallasFp::from_u64),
        )?;
        let v_new: AssignedCell<PallasFp> = self.assign_free_advice(
            layouter,
            config.advices[0],
            self.v_new.map(PallasFp::from_u64),
        )?;

        if let Some(p) = &self.path {
            if p.len() != 32 {
                return Err(Halo2Error::operation_failed("circuit::merkle", "bad path"));
            }
        }
        let merkle_path = HalOrchardMerklePath::with_length(
            vec![&config.merkle_config1, &config.merkle_config2],
            config
                .context
                .get_domain_point_affine(b"z.cash:Orchard-MerkleCRH")?,
            self.pos,
            self.path.clone(),
        );
        let leaf = cm_old.extract_p();
        let root = merkle_path.calculate_root(layouter, &leaf)?;

        let v_net: Option<i128> = match (self.v_old, self.v_new) {
            (Some(a), Some(b)) => Some(a as i128 - b as i128),
            _ => None,
        };
        let (magnitude_v, sign_v): (Option<PallasFp>, Option<PallasFp>) = match v_net {
            Some(n) => {
                let (mag, neg) = if n < 0 {
                    (-n as u64, true)
                } else {
                    (n as u64, false)
                };
                (
                    Some(PallasFp::from_u64(mag)),
                    Some(if neg {
                        PallasFp::one().neg()
                    } else {
                        PallasFp::one()
                    }),
                )
            }
            None => (None, None),
        };
        let magnitude: AssignedCell<PallasFp> =
            self.assign_free_advice(layouter, config.advices[9], magnitude_v)?;
        let sign: AssignedCell<PallasFp> =
            self.assign_free_advice(layouter, config.advices[9], sign_v)?;
        let v_net_scalar = crate::zk::orchard_halo2::chip::ecc::EccScalarFixedShort::new(
            magnitude,
            sign,
        );
        let rcv = chip.witness_scalar_fixed(self.rcv);
        let cv_net = OrchardGadget::value_commit_orchard(layouter, &chip, v_net_scalar, rcv)?;
        layouter.constrain_instance(cv_net.inner.get_x().cell, config.primary, 1)?;
        layouter.constrain_instance(cv_net.inner.get_y().cell, config.primary, 2)?;

        let nf_old = OrchardGadget::derive_nullifier(
            layouter,
            &config.poseidon_config,
            &config.add_config,
            &chip,
            &rho_old,
            &psi_old,
            &cm_old,
            &nk,
        )?;
        layouter.constrain_instance(nf_old.cell, config.primary, 3)?;

        let alpha = chip.witness_scalar_fixed(self.alpha);
        let (alpha_commitment, _) = chip.mul_fixed(
            layouter,
            alpha,
            crate::zk::orchard_halo2::orchard::constants::fixed_bases::FullBase::SpendAuthG,
        )?;
        let alpha_commitment = EccPointWithConfig {
            chip,
            inner: alpha_commitment,
        };
        let rk = alpha_commitment.add(layouter, &ak_p)?;
        layouter.constrain_instance(rk.inner.get_x().cell, config.primary, 4)?;
        layouter.constrain_instance(rk.inner.get_y().cell, config.primary, 5)?;

        let rivk = chip.witness_scalar_fixed(self.rivk);
        let ivk_ = OrchardGadget::commit_ivk(
            &config.sinsemilla_config1,
            &chip,
            &config.commit_ivk_config,
            layouter,
            &ak_p.extract_p(),
            &nk,
            rivk,
            &config.context,
        )?;
        let ivk = chip.scalar_var_from_base(ivk_);
        let ivk_cell = match &ivk {
            crate::zk::orchard_halo2::chip::ecc::ScalarVar::BaseFieldElem(s) => s.cell,
            _ => {
                return Err(Halo2Error::operation_failed("circuit::ivk", "bad scalar"));
            }
        };
        // Fixed circuits (v2/v3) anchor the incomplete-addition base.
        let anchored = self.version != OrchardProtocolVersion::InsecureV1;
        let (derived_pkd_old, _) = chip.mul(layouter, &ivk_cell, &gd_old.inner, anchored)?;
        let derived_pkd_old = EccPointWithConfig {
            chip,
            inner: derived_pkd_old,
        };
        let pkd_old = EccPointWithConfig {
            chip,
            inner: chip.witness_point_non_id(layouter, self.pkd_old)?,
        };
        derived_pkd_old.constrain_equal(layouter, &pkd_old)?;

        let rcm_old = chip.witness_scalar_fixed(self.rcm_old);
        let derived_cm_old = OrchardGadget::note_commit(
            layouter,
            &config.sinsemilla_config1,
            &chip,
            &config.old_note_commit_config,
            &gd_old.inner,
            &pkd_old.inner,
            &v_old,
            &rho_old,
            &psi_old,
            rcm_old,
            &config.context,
        )?;
        derived_cm_old.constrain_equal(layouter, &cm_old)?;

        let gd_new = EccPointWithConfig {
            chip,
            inner: chip.witness_point_non_id(layouter, self.gd_new)?,
        };
        let pkd_new = EccPointWithConfig {
            chip,
            inner: chip.witness_point_non_id(layouter, self.pkd_new)?,
        };
        let rho_new = nf_old;
        let psi_new: AssignedCell<PallasFp> =
            self.assign_free_advice(layouter, config.advices[0], self.psi_new)?;
        let rcm_new = chip.witness_scalar_fixed(self.rcm_new);
        let cm_new = OrchardGadget::note_commit(
            layouter,
            &config.sinsemilla_config2,
            &chip,
            &config.new_note_commit_config,
            &gd_new.inner,
            &pkd_new.inner,
            &v_new,
            &rho_new,
            &psi_new,
            rcm_new,
            &config.context,
        )?;
        let cmx = cm_new.extract_p();
        layouter.constrain_instance(cmx.cell, config.primary, 6)?;

        layouter.assign_region(&mut |region: &mut Region<'_>| {
            v_old.copy_advice(region, config.advices[0], 0)?;
            v_new.copy_advice(region, config.advices[1], 0)?;
            magnitude.copy_advice(region, config.advices[2], 0)?;
            sign.copy_advice(region, config.advices[3], 0)?;
            root.copy_advice(region, config.advices[4], 0)?;
            region.assign_advice_from_instance(config.primary, 0, config.advices[5], 0)?;
            region.assign_advice_from_instance(config.primary, 7, config.advices[6], 0)?;
            region.assign_advice_from_instance(config.primary, 8, config.advices[7], 0)?;
            config.q_orchard.enable(region, 0)
        })?;
        Ok(AddressPoint {
            gd_old,
            pkd_old,
            gd_new,
            pkd_new,
        })
    }

    pub fn synthesize_cross_address_checks<L: Layouter + ?Sized>(
        &self,
        config: &OrchardCircuitConfig,
        layouter: &mut L,
        addrs: &AddressPoint,
    ) -> Halo2Result<()> {
        const DISABLE_INSTANCE: usize = 9;
        layouter.assign_region(&mut |region: &mut Region<'_>| {
            let pairs = [
                (&addrs.gd_old.inner.x, &addrs.gd_new.inner.x),
                (&addrs.gd_old.inner.y, &addrs.gd_new.inner.y),
                (&addrs.pkd_old.inner.x, &addrs.pkd_new.inner.x),
                (&addrs.pkd_old.inner.y, &addrs.pkd_new.inner.y),
            ];
            for (offset, (old_c, new_c)) in pairs.into_iter().enumerate() {
                let disabled = region.assign_advice_from_instance(
                    config.primary,
                    DISABLE_INSTANCE,
                    config.advices[0],
                    offset,
                )?;
                region.assign_advice_from_constant(config.advices[1], offset, PallasFp::zero())?;
                disabled.copy_advice(region, config.advices[2], offset)?;
                region.assign_advice_from_constant(config.advices[3], offset, PallasFp::one())?;
                old_c.copy_advice(region, config.advices[4], offset)?;
                new_c.copy_advice(region, config.advices[5], offset)?;
                region.assign_advice_from_constant(config.advices[6], offset, PallasFp::one())?;
                region.assign_advice_from_constant(config.advices[7], offset, PallasFp::one())?;
                disabled.copy_advice(region, config.advices[8], offset)?;
                disabled.copy_advice(region, config.advices[9], offset)?;
                config.q_orchard.enable(region, offset)?;
            }
            Ok(())
        })
    }

    pub fn synthesize<L: Layouter + ?Sized>(
        &self,
        config: &OrchardCircuitConfig,
        layouter: &mut L,
    ) -> Halo2Result<()> {
        let addrs = self.synthesize_base(config, layouter)?;
        if self.version == OrchardProtocolVersion::V3 {
            self.synthesize_cross_address_checks(config, layouter, &addrs)?;
        }
        Ok(())
    }

    #[cfg(feature = "alloc")]
    pub fn to_debug_string(&self) -> String {
        alloc::string::String::from("OrchardCircuit")
    }
}

#[derive(Clone)]
pub struct AddressPoint {
    pub gd_old: EccPointWithConfig,
    pub pkd_old: EccPointWithConfig,
    pub gd_new: EccPointWithConfig,
    pub pkd_new: EccPointWithConfig,
}
