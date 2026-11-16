//! Implements sinsemilla/merkle logic (`SinsemillaConfig`, `MerkleConfig`,
//! `CondSwapConfig`, `HalOrchardMerklePath`).
//! Debug-only native-hash cross-checks (`assert(checkHashResult(...))`,
//! `assert(test())`) are intentionally not ported: they are test hooks, and
//! the task defers all tests. The S2 table itself is bit-exact (precomputed
//! from the same reference implementation). All other logic is faithful;
//! bounds/throws become `Halo2Result`.

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

use crate::zk::orchard_halo2::chip::ecc::EccPoint;
use crate::zk::orchard_halo2::chip::lookup::LookupRangeCheckConfig;
use crate::zk::orchard_halo2::chip::mul::DoubleAndAdd;
use crate::zk::orchard_halo2::crypto_context::CryptoContext;
use crate::zk::orchard_halo2::curve::PallasAffine;
use crate::zk::orchard_halo2::error::{Halo2Error, Halo2Result};
use crate::zk::orchard_halo2::field::PallasFp;
use crate::zk::orchard_halo2::plonk::assigned::Assigned;
use crate::zk::orchard_halo2::plonk::column::{AssignmentColumn, Selector, TableColumn};
use crate::zk::orchard_halo2::plonk::constraint::{ConstraintSystem, Constraints, VirtualCells};
use crate::zk::orchard_halo2::plonk::expression::Expression;
use crate::zk::orchard_halo2::poly::poly::Rotation;
use crate::zk::orchard_halo2::sinsemilla::message::{SinsemillaMessage, SinsemillaMessagePiece};
use crate::zk::orchard_halo2::sinsemilla::table::GeneratorTableConfig;
use crate::zk::orchard_halo2::utility::layouter::{AssignedCell, Layouter, Region};
use crate::zk::orchard_halo2::utility::range_constrained::RangeConstrained;
use crate::zk::orchard_halo2::utility::utils::{bool_check_expr, PALLAS_NUM_BITS, SINSEMILLA_K};

// Message-piece hash state: (x, y) accumulators plus running-sum cells.
type HashPieceCells = (
    AssignedCell<Assigned>,
    Option<Assigned>,
    Vec<AssignedCell<PallasFp>>,
);

// Full-piece hash state: (x, y) accumulators plus per-row running sums.
type HashAllPiecesCells = (
    AssignedCell<Assigned>,
    AssignedCell<Assigned>,
    Vec<Vec<AssignedCell<PallasFp>>>,
);

#[derive(Clone)]
pub struct SinsemillaConfig {
    pub q_sinsemilla1: Selector,
    pub q_sinsemilla2: AssignmentColumn,
    pub q_sinsemilla4: Selector,
    pub fixed_y_q: AssignmentColumn,
    pub double_and_add: DoubleAndAdd,
    pub bits: AssignmentColumn,
    pub witness_pieces: AssignmentColumn,
    pub generator_table: GeneratorTableConfig,
    pub lookup_config: LookupRangeCheckConfig,
    pub allow_init: bool,
    pub sinsemilla_s: Vec<PallasAffine>,
}

impl SinsemillaConfig {
    #[allow(clippy::too_many_arguments)] // Gate API mirrors upstream halo2 circuit signatures; regrouping args would churn call sites.
    pub fn configure(
        meta: &mut ConstraintSystem,
        advices: [AssignmentColumn; 5],
        witness_pieces: AssignmentColumn,
        fixed_y_q: AssignmentColumn,
        lookup: (TableColumn, TableColumn, TableColumn),
        range_check: LookupRangeCheckConfig,
        allow_init: bool,
        context: &dyn CryptoContext,
    ) -> Halo2Result<Self> {
        for a in advices.iter() {
            meta.enable_equality(*a);
        }
        let config = Self {
            q_sinsemilla1: meta.complex_selector(),
            q_sinsemilla2: meta.fixed_column(),
            q_sinsemilla4: meta.selector(),
            sinsemilla_s: Vec::new(),
            fixed_y_q,
            double_and_add: DoubleAndAdd {
                x_a: advices[0],
                x_p: advices[1],
                lambda1: advices[3],
                lambda2: advices[4],
            },
            bits: advices[2],
            witness_pieces,
            generator_table: GeneratorTableConfig {
                table_idx: lookup.0,
                table_x: lookup.1,
                table_y: lookup.2,
            },
            lookup_config: range_check,
            allow_init,
        };
        let mut config = config;
        config.sinsemilla_s = context.sinsemilla_s2()?;
        GeneratorTableConfig::configure(meta, &config)?;
        let two = PallasFp::from_u64(2);
        // Initial y_Q gate.
        meta.create_gate(&mut |meta: &mut VirtualCells<'_>| {
            let q_s4 = meta.query_selector(config.q_sinsemilla4);
            let y_q = if allow_init {
                meta.query_advice(config.double_and_add.x_p, Rotation { location: -1 })
            } else {
                meta.query_fixed(config.fixed_y_q)
            };
            let y_a_cur = config.double_and_add.y_a(meta, Rotation::cur())?;
            let check = y_q.scale(two).try_sub(&y_a_cur)?;
            Ok(Constraints {
                selector: Some(q_s4),
                constraints: vec![check],
            })
        })?;
        // Main gate.
        meta.create_gate(&mut |meta: &mut VirtualCells<'_>| {
            let q_s1 = meta.query_selector(config.q_sinsemilla1);
            let q_s3 = config.q_s3(meta)?;
            let lambda1_next = meta.query_advice(config.double_and_add.lambda1, Rotation::next());
            let lambda2_cur = meta.query_advice(config.double_and_add.lambda2, Rotation::cur());
            let x_a_cur = meta.query_advice(config.double_and_add.x_a, Rotation::cur());
            let x_a_next = meta.query_advice(config.double_and_add.x_a, Rotation::next());
            let x_r_cur = config.double_and_add.x_r(meta, Rotation::cur())?;
            let y_a_cur = config.double_and_add.y_a(meta, Rotation::cur())?;
            let y_a_next = config.double_and_add.y_a(meta, Rotation::next())?;
            let secant = lambda2_cur
                .square()?
                .try_sub(&x_a_next.try_add(&x_r_cur)?.try_add(&x_a_cur)?)?;
            let lhs = lambda2_cur
                .scale(PallasFp::from_u64(4))
                .try_mul_expr(&x_a_cur.try_sub(&x_a_next)?)?;
            let rhs = y_a_cur
                .scale(two)
                .try_add(
                    &Expression::constant(PallasFp::from_u64(2))
                        .try_sub(&q_s3)?
                        .try_mul_expr(&y_a_next)?,
                )?
                .try_add(&q_s3.scale(two).try_mul_expr(&lambda1_next)?)?;
            let y_check = lhs.try_sub(&rhs)?;
            Ok(Constraints {
                selector: Some(q_s1),
                constraints: vec![secant, y_check],
            })
        })?;
        Ok(config)
    }

    pub fn q_s3(&self, meta: &mut VirtualCells<'_>) -> Halo2Result<Expression> {
        let one = Expression::constant(PallasFp::one());
        let q_s2 = meta.query_fixed(self.q_sinsemilla2);
        q_s2.try_mul_expr(&q_s2.try_sub(&one)?)
    }

    pub fn advices(&self) -> Vec<AssignmentColumn> {
        vec![
            self.double_and_add.x_a,
            self.double_and_add.x_p,
            self.bits,
            self.double_and_add.lambda1,
            self.double_and_add.lambda2,
        ]
    }

    pub fn load<L: Layouter + ?Sized>(&self, layouter: &mut L) -> Halo2Result<()> {
        self.generator_table
            .load(&self.lookup_config, layouter, &self.sinsemilla_s)
    }

    fn private_q_init(
        &self,
        region: &mut Region<'_>,
        q: &EccPoint,
    ) -> Halo2Result<(usize, AssignedCell<Assigned>, Option<Assigned>)> {
        if !self.allow_init {
            return Err(Halo2Error::operation_failed(
                "sinsemilla::private_q",
                "not allowed",
            ));
        }
        self.q_sinsemilla4.enable(region, 1)?;
        let qy = q.get_y();
        let qy_assigned = AssignedCell {
            value: qy.value.map(Assigned::Trivial),
            cell: qy.cell,
        };
        let y_assigned = qy_assigned.copy_advice(region, self.double_and_add.x_p, 0)?;
        let qx = q.get_x();
        let qx_assigned = AssignedCell {
            value: qx.value.map(Assigned::Trivial),
            cell: qx.cell,
        };
        let x_assigned = qx_assigned.copy_advice(region, self.double_and_add.x_a, 1)?;
        Ok((1, x_assigned, y_assigned.value))
    }

    pub fn hash_message_with_private_init(
        &self,
        region: &mut Region<'_>,
        q: &EccPoint,
        message: &SinsemillaMessage,
    ) -> Halo2Result<(EccPoint, Vec<Vec<AssignedCell<PallasFp>>>)> {
        if !self.allow_init {
            return Err(Halo2Error::operation_failed(
                "sinsemilla::private",
                "not allowed",
            ));
        }
        let (offset, x_a0, y_a0) = self.private_q_init(region, q)?;
        let (x_a, y_a, zs) = self.hash_all_pieces(region, offset, message, &x_a0, y_a0)?;
        if let (Some(x), Some(y)) = (x_a.value, y_a.value) {
            if x.evaluate().is_zero() || y.evaluate().is_zero() {
                return Err(Halo2Error::operation_failed(
                    "sinsemilla::private",
                    "identity",
                ));
            }
        }
        Ok((EccPoint { x: x_a, y: y_a }, zs))
    }

    pub fn witness_message_piece<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        field_elem: Option<PallasFp>,
        num_words: usize,
    ) -> Halo2Result<SinsemillaMessagePiece> {
        let cell = layouter.assign_region(&mut |region: &mut Region<'_>| {
            region.assign_advice(self.witness_pieces, 0, &mut || field_elem)
        })?;
        Ok(SinsemillaMessagePiece {
            cell_value: cell,
            num_words,
        })
    }

    pub fn hash_to_point<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        q: &PallasAffine,
        message: &SinsemillaMessage,
    ) -> Halo2Result<(EccPoint, Vec<Vec<AssignedCell<PallasFp>>>)> {
        layouter.assign_region(&mut |region: &mut Region<'_>| {
            let (p, zs) = self.hash_message(region, q, message)?;
            Ok((p, zs))
        })
    }

    pub fn hash_to_point_with_private_init<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        q: &EccPoint,
        message: &SinsemillaMessage,
    ) -> Halo2Result<(EccPoint, Vec<Vec<AssignedCell<PallasFp>>>)> {
        layouter.assign_region(&mut |region: &mut Region<'_>| {
            self.hash_message_with_private_init(region, q, message)
        })
    }

    pub fn hash_message(
        &self,
        region: &mut Region<'_>,
        q: &PallasAffine,
        message: &SinsemillaMessage,
    ) -> Halo2Result<(EccPoint, Vec<Vec<AssignedCell<PallasFp>>>)> {
        let (offset, x_a, y_a) = self.public_q_init(region, q)?;
        let (x, y, zs) = self.hash_all_pieces(region, offset, message, &x_a, y_a)?;
        if let (Some(a), Some(b)) = (x.value, y.value) {
            if a.evaluate().is_zero() || b.evaluate().is_zero() {
                return Err(Halo2Error::operation_failed("sinsemilla::hash", "identity"));
            }
        }
        Ok((EccPoint { x, y }, zs))
    }

    fn public_q_init(
        &self,
        region: &mut Region<'_>,
        q: &PallasAffine,
    ) -> Halo2Result<(usize, AssignedCell<Assigned>, Option<Assigned>)> {
        let (xqb, yqb, _) = q.to_affine_le()?;
        let x_q = PallasFp::from_le_array(&xqb)?;
        let y_q = PallasFp::from_le_array(&yqb)?;
        let mut offset = 0usize;
        let y_a: Option<Assigned> = if self.allow_init {
            self.q_sinsemilla4.enable(region, offset + 1)?;
            let cell = region.assign_advice_from_constant(
                self.double_and_add.x_p,
                offset,
                Assigned::Trivial(y_q),
            )?;
            offset += 1;
            cell.value
        } else {
            self.q_sinsemilla4.enable(region, offset)?;
            region.assign_fixed(self.fixed_y_q, offset, &mut || Some(y_q))?;
            Some(Assigned::Trivial(y_q))
        };
        let x_a = region.assign_advice_from_constant(
            self.double_and_add.x_a,
            offset,
            Assigned::Trivial(x_q),
        )?;
        Ok((offset, x_a, y_a))
    }

    pub fn hash_piece(
        &self,
        region: &mut Region<'_>,
        offset: usize,
        piece: &SinsemillaMessagePiece,
        x_a: &AssignedCell<Assigned>,
        y_a: Option<Assigned>,
        final_piece: bool,
    ) -> Halo2Result<HashPieceCells> {
        for row in 0..piece.num_words {
            self.q_sinsemilla1.enable(region, offset + row)?;
        }
        for row in 0..piece.num_words.saturating_sub(1) {
            region.assign_fixed(self.q_sinsemilla2, offset + row, &mut || {
                Some(PallasFp::one())
            })?;
        }
        region.assign_fixed(
            self.q_sinsemilla2,
            offset + piece.num_words.saturating_sub(1),
            &mut || {
                Some(if final_piece {
                    PallasFp::from_u64(2)
                } else {
                    PallasFp::zero()
                })
            },
        )?;

        let mut bitstring: Option<Vec<bool>> = None;
        if let Some(v) = piece.cell_value.value {
            let mut bits = [false; 256];
            v.to_bits_le(&mut bits);
            bitstring = Some(bits[..SINSEMILLA_K * piece.num_words].to_vec());
        }
        let mut words: Vec<Option<u16>> = vec![None; piece.num_words];
        let mut generators: Vec<Option<(PallasFp, PallasFp)>> = vec![None; piece.num_words];
        if let Some(bs) = bitstring {
            for (i, chunk) in bs.chunks(SINSEMILLA_K).enumerate() {
                let mut word: u16 = 0;
                for (j, b) in chunk.iter().enumerate() {
                    if *b {
                        word |= 1 << j;
                    }
                }
                words[i] = Some(word);
                let s = self.sinsemilla_s.get(word as usize).ok_or_else(|| {
                    Halo2Error::operation_failed("sinsemilla::piece", "table overflow")
                })?;
                let (sxb, syb, _) = s.to_affine_le()?;
                generators[i] = Some((
                    PallasFp::from_le_array(&sxb)?,
                    PallasFp::from_le_array(&syb)?,
                ));
            }
        }

        let mut zs: Vec<AssignedCell<PallasFp>> =
            vec![piece.cell_value.copy_advice(region, self.bits, offset)?];
        let mut z = piece.cell_value.value;
        let inv_two_pow_k = PallasFp::from_u64(1u64 << SINSEMILLA_K).invert()?;
        for (i, word) in words.iter().enumerate().take(words.len().saturating_sub(1)) {
            z = match (z, *word) {
                (Some(zv), Some(w)) => Some(
                    zv.sub_vartime(&PallasFp::from_u64(w as u64))
                        .mul_vartime(&inv_two_pow_k),
                ),
                _ => None,
            };
            zs.push(region.assign_advice(self.bits, offset + i + 1, &mut || z)?);
        }

        let mut x_a_cur = *x_a;
        let mut y_a_cur = y_a;
        for (row, gen) in generators.into_iter().enumerate() {
            let (xp, yp): (Option<Assigned>, Option<Assigned>) = match gen {
                Some((gx, gy)) => (Some(Assigned::Trivial(gx)), Some(Assigned::Trivial(gy))),
                None => (None, None),
            };
            region.assign_advice(self.double_and_add.x_p, offset + row, &mut || xp)?;
            let lambda1: Option<Assigned> = match (y_a_cur, yp, x_a_cur.value, xp) {
                (Some(a), Some(b), Some(xa), Some(xp)) => {
                    Some(a.try_sub(&b).try_mul(&xa.try_sub(&xp).invert()))
                }
                _ => None,
            };
            region.assign_advice(self.double_and_add.lambda1, offset + row, &mut || lambda1)?;
            let x_r: Option<Assigned> = match (lambda1, xp) {
                (Some(l), Some(xp)) => x_a_cur.value.map(|xa| l.square().try_sub(&xa).try_sub(&xp)),
                _ => None,
            };
            let lambda2: Option<Assigned> = match (y_a_cur, x_r, lambda1) {
                (Some(a), Some(xr), Some(l)) => x_a_cur.value.map(|xa| {
                    a.try_mul(&Assigned::Trivial(PallasFp::from_u64(2)))
                        .try_mul(&xa.try_sub(&xr).invert())
                        .try_sub(&l)
                }),
                _ => None,
            };
            region.assign_advice(self.double_and_add.lambda2, offset + row, &mut || lambda2)?;
            let x_a_next_val: Option<Assigned> = match (lambda2, x_r) {
                (Some(l), Some(xr)) => x_a_cur.value.map(|xa| l.square().try_sub(&xa).try_sub(&xr)),
                _ => None,
            };
            let x_a_next =
                region.assign_advice(self.double_and_add.x_a, offset + row + 1, &mut || {
                    x_a_next_val
                })?;
            let y_a_next: Option<Assigned> = match (lambda2, y_a_cur) {
                (Some(l), Some(a)) => match x_a_next.value {
                    Some(xn) => x_a_cur.value.map(|xa| l.try_mul(&xa.try_sub(&xn)).try_sub(&a)),
                    None => None,
                },
                _ => None,
            };
            x_a_cur = x_a_next;
            y_a_cur = y_a_next;
        }
        Ok((x_a_cur, y_a_cur, zs))
    }

    pub fn hash_all_pieces(
        &self,
        region: &mut Region<'_>,
        mut offset: usize,
        message: &SinsemillaMessage,
        x_a: &AssignedCell<Assigned>,
        y_a: Option<Assigned>,
    ) -> Halo2Result<HashAllPiecesCells> {
        let mut zs_sum: Vec<Vec<AssignedCell<PallasFp>>> = Vec::new();
        let mut xa = *x_a;
        let mut ya = y_a;
        for (idx, piece) in message.messages.iter().enumerate() {
            let final_piece = idx + 1 == message.messages.len();
            let (x, y, zs) = self.hash_piece(region, offset, piece, &xa, ya, final_piece)?;
            offset += piece.num_words;
            xa = x;
            ya = y;
            zs_sum.push(zs);
        }
        let y_cell = region.assign_advice(self.double_and_add.lambda1, offset, &mut || ya)?;
        region.assign_advice(self.double_and_add.lambda2, offset, &mut || {
            Some(PallasFp::zero())
        })?;
        region.assign_advice(self.double_and_add.x_p, offset, &mut || {
            Some(PallasFp::zero())
        })?;
        Ok((xa, y_cell, zs_sum))
    }

    pub fn extract(&self, point: &EccPoint) -> AssignedCell<PallasFp> {
        point.get_x()
    }

    #[cfg(feature = "alloc")]
    pub fn to_debug_string(&self) -> String {
        alloc::string::String::from("SinsemillaConfig")
    }
}

#[derive(Clone)]
pub struct MerkleConfig {
    pub sinsemilla_config: SinsemillaConfig,
    pub q_decompose: Selector,
    pub cond_swap: CondSwapConfig,
}

impl MerkleConfig {
    pub fn advices(&self) -> Vec<AssignmentColumn> {
        self.sinsemilla_config
            .advices()
            .into_iter()
            .map(advice_of)
            .collect()
    }

    pub fn configure(
        meta: &mut ConstraintSystem,
        sinsemilla_config: &SinsemillaConfig,
    ) -> Halo2Result<Self> {
        let advices = sinsemilla_config.advices();
        if advices.len() != 5 {
            return Err(Halo2Error::operation_failed(
                "merkle::configure",
                "advice count",
            ));
        }
        let cond_swap = CondSwapConfig::configure(meta, advices.clone())?;
        let q_decompose = meta.selector();
        let cfg = Self {
            sinsemilla_config: sinsemilla_config.clone(),
            q_decompose,
            cond_swap,
        };
        let adv = advices;
        meta.create_gate(&mut |meta: &mut VirtualCells<'_>| {
            let q = meta.query_selector(cfg.q_decompose);
            let l_whole = meta.query_advice(adv[4], Rotation::next());
            let two_pow_5 = PallasFp::from_u64(1u64 << 5);
            let two_pow_10 = two_pow_5.square_vartime();
            let a_whole = meta.query_advice(adv[0], Rotation::cur());
            let b_whole = meta.query_advice(adv[1], Rotation::cur());
            let c_whole = meta.query_advice(adv[2], Rotation::cur());
            let left_node = meta.query_advice(adv[3], Rotation::cur());
            let right_node = meta.query_advice(adv[4], Rotation::cur());
            let z1_a = meta.query_advice(adv[0], Rotation::next());
            let a0 = a_whole.try_sub(&z1_a.scale(two_pow_10))?;
            let z1_b = meta.query_advice(adv[1], Rotation::next());
            let b1 = meta.query_advice(adv[2], Rotation::next());
            let b2 = meta.query_advice(adv[3], Rotation::next());
            let b1b2 = z1_b.try_sub(&b1.try_add(&b2.scale(two_pow_5))?)?;
            let b0 = b_whole.try_sub(&z1_b.scale(two_pow_10))?;
            let two_pow_240 = PallasFp::from_u64(2).pow_u64(240);
            let left_check = z1_a
                .try_add(&b0.try_add(&b1.scale(two_pow_10))?.scale(two_pow_240))?
                .try_sub(&left_node)?;
            let right_check = b2
                .try_add(&c_whole.scale(two_pow_5))?
                .try_sub(&right_node)?;
            Ok(Constraints {
                selector: Some(q),
                constraints: vec![a0.try_sub(&l_whole)?, left_check, right_check, b1b2],
            })
        })?;
        Ok(cfg)
    }

    pub fn hash_layer<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        q: &PallasAffine,
        l: usize,
        left: &AssignedCell<PallasFp>,
        right: &AssignedCell<PallasFp>,
    ) -> Halo2Result<AssignedCell<PallasFp>> {
        let adv = self.advices();
        let a = SinsemillaMessagePiece::from_subpieces(
            &self.sinsemilla_config,
            layouter,
            vec![
                RangeConstrained {
                    inner: Some(PallasFp::from_u64(l as u64)),
                    num_bits: 10,
                },
                RangeConstrained::bitrange_of(left.value, 0, 240),
            ],
        )?;
        let b0 = RangeConstrained::bitrange_of(left.value, 240, 250);
        let b1 = self.sinsemilla_config.lookup_config.witness_short(
            layouter,
            left.value,
            250,
            PALLAS_NUM_BITS,
        )?;
        let b2 = self
            .sinsemilla_config
            .lookup_config
            .witness_short(layouter, right.value, 0, 5)?;
        let b = SinsemillaMessagePiece::from_subpieces(
            &self.sinsemilla_config,
            layouter,
            vec![b0, b1.value(), b2.value()],
        )?;
        let c = SinsemillaMessagePiece::from_subpieces(
            &self.sinsemilla_config,
            layouter,
            vec![RangeConstrained::bitrange_of(
                right.value,
                5,
                PALLAS_NUM_BITS,
            )],
        )?;
        let message = SinsemillaMessage {
            messages: vec![a.clone(), b.clone(), c.clone()],
        };
        let (point, zs) = self.hash_to_point(layouter, q, &message)?;
        let hash = self.sinsemilla_config.extract(&point);
        let z1_a = zs[0]
            .get(1)
            .copied()
            .ok_or_else(|| Halo2Error::operation_failed("merkle::layer", "missing z1a"))?;
        let z1_b = zs[1]
            .get(1)
            .copied()
            .ok_or_else(|| Halo2Error::operation_failed("merkle::layer", "missing z1b"))?;
        let b1 = b1.inner;
        let b2 = b2.inner;
        layouter.assign_region(&mut |region: &mut Region<'_>| {
            self.q_decompose.enable(region, 0)?;
            region.assign_advice_from_constant(adv[4], 1, PallasFp::from_u64(l as u64))?;
            a.cell_value.copy_advice(region, adv[0], 0)?;
            b.cell_value.copy_advice(region, adv[1], 0)?;
            c.cell_value.copy_advice(region, adv[2], 0)?;
            left.copy_advice(region, adv[3], 0)?;
            right.copy_advice(region, adv[4], 0)?;
            z1_a.copy_advice(region, adv[0], 1)?;
            z1_b.copy_advice(region, adv[1], 1)?;
            b1.copy_advice(region, adv[2], 1)?;
            b2.copy_advice(region, adv[3], 1)?;
            Ok(())
        })?;
        Ok(hash)
    }

    pub fn witness_message_piece<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        value: Option<PallasFp>,
        num_words: usize,
    ) -> Halo2Result<SinsemillaMessagePiece> {
        self.sinsemilla_config
            .witness_message_piece(layouter, value, num_words)
    }

    pub fn hash_to_point<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        q: &PallasAffine,
        message: &SinsemillaMessage,
    ) -> Halo2Result<(EccPoint, Vec<Vec<AssignedCell<PallasFp>>>)> {
        self.sinsemilla_config.hash_to_point(layouter, q, message)
    }

    pub fn hash_to_point_with_private_init<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        q: &EccPoint,
        message: &SinsemillaMessage,
    ) -> Halo2Result<(EccPoint, Vec<Vec<AssignedCell<PallasFp>>>)> {
        self.sinsemilla_config
            .hash_to_point_with_private_init(layouter, q, message)
    }

    pub fn mux<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        choice: &AssignedCell<PallasFp>,
        left: &AssignedCell<PallasFp>,
        right: &AssignedCell<PallasFp>,
    ) -> Halo2Result<AssignedCell<PallasFp>> {
        self.cond_swap.mux(layouter, choice, left, right)
    }

    pub fn swap<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        node: &AssignedCell<PallasFp>,
        sibling: Option<PallasFp>,
        swap: Option<bool>,
    ) -> Halo2Result<(AssignedCell<PallasFp>, AssignedCell<PallasFp>)> {
        self.cond_swap.swap(layouter, node, sibling, swap)
    }
}

fn advice_of(col: AssignmentColumn) -> AssignmentColumn {
    col
}

pub trait IntoExpression {
    #[allow(clippy::wrong_self_convention)] // Name matches the upstream gadget/Boolean API; method borrows to preserve the value.
    fn into_expr(&self) -> Expression;
}

impl IntoExpression for PallasFp {
    fn into_expr(&self) -> Expression {
        Expression::constant(*self)
    }
}

#[derive(Clone, Copy)]
pub struct CondSwapConfig {
    pub q_swap: Selector,
    pub a: AssignmentColumn,
    pub b: AssignmentColumn,
    pub a_swapped: AssignmentColumn,
    pub b_swapped: AssignmentColumn,
    pub swap_column: AssignmentColumn,
}

impl CondSwapConfig {
    pub fn configure(
        meta: &mut ConstraintSystem,
        advices: Vec<AssignmentColumn>,
    ) -> Halo2Result<Self> {
        let a = *advices
            .first()
            .ok_or_else(|| Halo2Error::operation_failed("condswap::configure", "no advices"))?;
        meta.enable_equality(a);
        let config = Self {
            q_swap: meta.selector(),
            a,
            b: *advices.get(1).ok_or_else(|| {
                Halo2Error::operation_failed("condswap::configure", "short advices")
            })?,
            a_swapped: *advices.get(2).ok_or_else(|| {
                Halo2Error::operation_failed("condswap::configure", "short advices")
            })?,
            b_swapped: *advices.get(3).ok_or_else(|| {
                Halo2Error::operation_failed("condswap::configure", "short advices")
            })?,
            swap_column: *advices.get(4).ok_or_else(|| {
                Halo2Error::operation_failed("condswap::configure", "short advices")
            })?,
        };
        meta.create_gate(&mut |meta: &mut VirtualCells<'_>| {
            let q = meta.query_selector(config.q_swap);
            let a_cur = meta.query_advice(config.a, Rotation::cur());
            let b_cur = meta.query_advice(config.b, Rotation::cur());
            let a_sw = meta.query_advice(config.a_swapped, Rotation::cur());
            let b_sw = meta.query_advice(config.b_swapped, Rotation::cur());
            let swap = meta.query_advice(config.swap_column, Rotation::cur());
            let a_check = a_sw.try_sub(&ternary_inner(&swap, &b_cur, &a_cur)?)?;
            let b_check = b_sw.try_sub(&ternary_inner(&swap, &a_cur, &b_cur)?)?;
            let bool_check = bool_check_expr(swap)?;
            Ok(Constraints {
                selector: Some(q),
                constraints: vec![a_check, b_check, bool_check],
            })
        })?;
        Ok(config)
    }

    pub fn swap<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        node: &AssignedCell<PallasFp>,
        sibling: Option<PallasFp>,
        swap: Option<bool>,
    ) -> Halo2Result<(AssignedCell<PallasFp>, AssignedCell<PallasFp>)> {
        layouter.assign_region(&mut |region: &mut Region<'_>| {
            self.q_swap.enable(region, 0)?;
            let a = node.copy_advice(region, self.a, 0)?;
            let b = region.assign_advice(self.b, 0, &mut || sibling)?;
            let swap_val: Option<PallasFp> = swap.map(|s| PallasFp::from_u64(s as u64));
            region.assign_advice(self.swap_column, 0, &mut || swap_val)?;
            let (av, bv, sw) = (a.value, b.value, swap);
            let a_swapped_val = match (av, bv, sw) {
                (Some(_), Some(y), Some(true)) => Some(y),
                (Some(x), Some(_), Some(false)) => Some(x),
                _ => None,
            };
            let a_swapped = region.assign_advice(self.a_swapped, 0, &mut || a_swapped_val)?;
            let b_swapped_val = match (av, bv, sw) {
                (Some(x), Some(_), Some(true)) => Some(x),
                (Some(_), Some(y), Some(false)) => Some(y),
                _ => None,
            };
            let b_swapped = region.assign_advice(self.b_swapped, 0, &mut || b_swapped_val)?;
            Ok((a_swapped, b_swapped))
        })
    }

    pub fn mux<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        choice: &AssignedCell<PallasFp>,
        left: &AssignedCell<PallasFp>,
        right: &AssignedCell<PallasFp>,
    ) -> Halo2Result<AssignedCell<PallasFp>> {
        layouter.assign_region(&mut |region: &mut Region<'_>| {
            self.q_swap.enable(region, 0)?;
            let l = left.copy_advice(region, self.a, 0)?;
            let r = right.copy_advice(region, self.b, 0)?;
            let c = choice.copy_advice(region, self.swap_column, 0)?;
            let a_val = match (l.value, r.value, c.value) {
                (Some(x), Some(_), Some(ch)) => {
                    if ch.is_zero() {
                        Some(x)
                    } else {
                        r.value
                    }
                }
                _ => None,
            };
            let b_val = match (l.value, r.value, c.value) {
                (Some(_), Some(y), Some(ch)) => {
                    if ch.is_zero() {
                        Some(y)
                    } else {
                        l.value
                    }
                }
                _ => None,
            };
            region.assign_advice(self.b_swapped, 0, &mut || b_val)?;
            region.assign_advice(self.a_swapped, 0, &mut || a_val)
        })
    }
}

fn ternary_inner(swap: &Expression, b: &Expression, a: &Expression) -> Halo2Result<Expression> {
    crate::zk::orchard_halo2::utility::utils::ternary_expr(swap, b, a)
}

pub struct HalOrchardMerklePath<'a> {
    pub chips: Vec<&'a MerkleConfig>,
    pub q: PallasAffine,
    pub leaf_position: Option<usize>,
    pub path: Option<Vec<PallasFp>>,
    pub path_length: usize,
}

impl<'a> HalOrchardMerklePath<'a> {
    pub fn with_length(
        chips: Vec<&'a MerkleConfig>,
        q: PallasAffine,
        leaf_position: Option<usize>,
        path: Option<Vec<PallasFp>>,
    ) -> Self {
        Self {
            chips,
            q,
            leaf_position,
            path,
            path_length: 32,
        }
    }

    pub fn calculate_root<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        leaf: &AssignedCell<PallasFp>,
    ) -> Halo2Result<AssignedCell<PallasFp>> {
        if self.chips.is_empty() {
            return Err(Halo2Error::operation_failed("merkle::root", "no chips"));
        }
        let layers_per_chip = (self.path_length + self.chips.len() - 1) / self.chips.len();
        let mut chips: Vec<&MerkleConfig> = Vec::with_capacity(self.path_length);
        for i in 0..self.path_length {
            chips.push(self.chips[(i / layers_per_chip).min(self.chips.len() - 1)]);
        }
        let path: Vec<Option<PallasFp>> = match &self.path {
            Some(p) => p.iter().copied().map(Some).collect(),
            None => vec![None; self.path_length],
        };
        let mut pos: Vec<Option<bool>> = vec![None; self.path_length];
        if let Some(lp) = self.leaf_position {
            for (i, slot) in pos.iter_mut().enumerate() {
                *slot = Some(((lp >> i) & 1) == 1);
            }
        }
        let mut node = *leaf;
        for l in 0..self.path_length {
            let sibling = path[l];
            let (left, right) = chips[l].swap(layouter, &node, sibling, pos[l])?;
            node = chips[l].hash_layer(layouter, &self.q, l, &left, &right)?;
        }
        Ok(node)
    }
}
