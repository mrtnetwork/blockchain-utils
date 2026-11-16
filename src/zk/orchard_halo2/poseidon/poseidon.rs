//! Implements poseidon/poseidon logic (Poseidon Pow5 chip + sponge).
//! Round constants/MDS borrow the compile-time `spec_const` tables; the MDS
//! inverse is derived once per `configure` via 3x3 Gauss-Jordan (exact field
//! algebra, no hashing regenerated). Result style, no `assert!`.

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

use crate::zk::orchard_halo2::error::{Halo2Error, Halo2Result};
use crate::zk::orchard_halo2::field::PallasFp;
use crate::zk::orchard_halo2::plonk::column::{AssignmentColumn, Selector};
use crate::zk::orchard_halo2::plonk::constraint::{ConstraintSystem, Constraints, VirtualCells};
use crate::zk::orchard_halo2::plonk::expression::Expression;
use crate::zk::orchard_halo2::poly::poly::Rotation;
use crate::zk::orchard_halo2::poseidon::spec_const::{
    mds_limbs, round_constant_limbs, POSEIDON_FULL_ROUNDS, POSEIDON_PARTIAL_ROUNDS, POSEIDON_RATE,
    POSEIDON_WIDTH,
};
use crate::zk::orchard_halo2::utility::layouter::{AssignedCell, Layouter, Region};

fn pow5(v: &Expression) -> Halo2Result<Expression> {
    let v2 = v.try_mul_expr(v)?;
    let v4 = v2.try_mul_expr(&v2)?;
    v4.try_mul_expr(v)
}

fn load_round_constants() -> Halo2Result<Vec<Vec<PallasFp>>> {
    let mut out = Vec::with_capacity(64);
    for r in 0..64 {
        let mut row = Vec::with_capacity(POSEIDON_WIDTH);
        for l in 0..POSEIDON_WIDTH {
            let limbs = round_constant_limbs(r, l)?;
            row.push(PallasFp::from_le_limbs(&limbs)?);
        }
        out.push(row);
    }
    Ok(out)
}

fn load_mds() -> Halo2Result<Vec<Vec<PallasFp>>> {
    let mut out = Vec::with_capacity(POSEIDON_WIDTH);
    for r in 0..POSEIDON_WIDTH {
        let mut row = Vec::with_capacity(POSEIDON_WIDTH);
        for c in 0..POSEIDON_WIDTH {
            row.push(PallasFp::from_le_limbs(&mds_limbs(r, c)?)?);
        }
        out.push(row);
    }
    Ok(out)
}

/// 3x3 matrix inverse (Gauss-Jordan). Deterministic field algebra.
fn invert_3x3(m: &[Vec<PallasFp>]) -> Halo2Result<Vec<Vec<PallasFp>>> {
    if m.len() != 3 || m.iter().any(|r| r.len() != 3) {
        return Err(Halo2Error::operation_failed(
            "poseidon::mds_inv",
            "bad matrix",
        ));
    }
    let mut a: Vec<Vec<PallasFp>> = m.to_vec();
    let mut inv: Vec<Vec<PallasFp>> = vec![vec![PallasFp::zero(); 3]; 3];
    for (i, row) in inv.iter_mut().enumerate() {
        row[i] = PallasFp::one();
    }
    for col in 0..3 {
        let mut pivot = None;
        for (row, a_row) in a.iter().enumerate().skip(col) {
            if !a_row[col].is_zero() {
                pivot = Some(row);
                break;
            }
        }
        let p = pivot
            .ok_or_else(|| Halo2Error::operation_failed("poseidon::mds_inv", "singular matrix"))?;
        a.swap(col, p);
        inv.swap(col, p);
        let pinv = a[col][col].invert()?;
        for j in 0..3 {
            a[col][j] = a[col][j].mul_vartime(&pinv);
            inv[col][j] = inv[col][j].mul_vartime(&pinv);
        }
        for row in 0..3 {
            if row != col && !a[row][col].is_zero() {
                let factor = a[row][col];
                for j in 0..3 {
                    a[row][j] = a[row][j].sub_vartime(&factor.mul_vartime(&a[col][j]));
                    inv[row][j] = inv[row][j].sub_vartime(&factor.mul_vartime(&inv[col][j]));
                }
            }
        }
    }
    Ok(inv)
}

#[derive(Clone)]
pub struct Pow5Config {
    pub state: Vec<AssignmentColumn>,
    pub partial_sbox: AssignmentColumn,
    pub rc_a: Vec<AssignmentColumn>,
    pub rc_b: Vec<AssignmentColumn>,
    pub s_full: Selector,
    pub s_partial: Selector,
    pub s_pad_and_add: Selector,
    pub half_full_rounds: usize,
    pub half_partial_rounds: usize,
    pub round_constants: Vec<Vec<PallasFp>>,
    pub m_reg: Vec<Vec<PallasFp>>,
    pub m_inv: Vec<Vec<PallasFp>>,
}

impl Pow5Config {
    pub fn width() -> usize {
        POSEIDON_WIDTH
    }

    pub fn rate() -> usize {
        POSEIDON_RATE
    }

    pub fn configure(
        meta: &mut ConstraintSystem,
        state: Vec<AssignmentColumn>,
        partial_sbox: AssignmentColumn,
        rc_a: Vec<AssignmentColumn>,
        rc_b: Vec<AssignmentColumn>,
    ) -> Halo2Result<Self> {
        let width = POSEIDON_WIDTH;
        let rate = POSEIDON_RATE;
        if state.len() != width || rc_a.len() != width || rc_b.len() != width {
            return Err(Halo2Error::operation_failed(
                "poseidon::configure",
                "width mismatch",
            ));
        }
        let half_full = POSEIDON_FULL_ROUNDS / 2;
        let half_partial = POSEIDON_PARTIAL_ROUNDS / 2;
        let round_constants = load_round_constants()?;
        let m_reg = load_mds()?;
        let m_inv = invert_3x3(&m_reg)?;

        for col in state.iter().chain(rc_b.iter()) {
            meta.enable_equality(*col);
        }
        let s_full = meta.selector();
        let s_partial = meta.selector();
        let s_pad_and_add = meta.selector();

        // Full rounds gate.
        {
            let (state_c, rc_a_c, m) = (state.clone(), rc_a.clone(), m_reg.clone());
            meta.create_gate(&mut |meta: &mut VirtualCells<'_>| {
                let s = meta.query_selector(s_full);
                let mut constraints = Vec::with_capacity(width);
                for next_idx in 0..width {
                    let state_next = meta.query_advice(state_c[next_idx], Rotation::next());
                    let mut expr: Option<Expression> = None;
                    for idx in 0..width {
                        let state_cur = meta.query_advice(state_c[idx], Rotation::cur());
                        let rc = meta.query_fixed(rc_a_c[idx]);
                        let sum = state_cur.try_add(&rc)?;
                        let term = pow5(&sum)?.scale(m[next_idx][idx]);
                        expr = Some(match expr {
                            None => term,
                            Some(e) => e.try_add(&term)?,
                        });
                    }
                    let e = expr.ok_or_else(|| {
                        Halo2Error::operation_failed("poseidon::full_gate", "empty row")
                    })?;
                    constraints.push(e.try_sub(&state_next)?);
                }
                Ok(Constraints {
                    selector: Some(s),
                    constraints,
                })
            })?;
        }

        // Partial rounds gate.
        {
            let (state_c, psb, rc_a_c, rc_b_c, m, mi) = (
                state.clone(),
                partial_sbox,
                rc_a.clone(),
                rc_b.clone(),
                m_reg.clone(),
                m_inv.clone(),
            );
            meta.create_gate(&mut |meta: &mut VirtualCells<'_>| {
                let cur0 = meta.query_advice(state_c[0], Rotation::cur());
                let mid0 = meta.query_advice(psb, Rotation::cur());
                let rc_a0 = meta.query_fixed(rc_a_c[0]);
                let rc_b0 = meta.query_fixed(rc_b_c[0]);
                let s = meta.query_selector(s_partial);

                // mid(idx): mid0*m[idx][0] + Σ (cur_i + rc_a_i)*m[idx][i]
                let mid = |meta: &mut VirtualCells<'_>, idx: usize| -> Halo2Result<Expression> {
                    let mut acc = mid0.scale(m[idx][0]);
                    for i in 1..width {
                        let cur = meta.query_advice(state_c[i], Rotation::cur());
                        let rc = meta.query_fixed(rc_a_c[i]);
                        let t = cur.try_add(&rc)?.scale(m[idx][i]);
                        acc = acc.try_add(&t)?;
                    }
                    Ok(acc)
                };
                // next(idx): Σ next_j * mInv[idx][j]
                let next = |meta: &mut VirtualCells<'_>, idx: usize| -> Halo2Result<Expression> {
                    let mut acc: Option<Expression> = None;
                    for j in 0..width {
                        let nxt = meta.query_advice(state_c[j], Rotation::next());
                        let t = nxt.scale(mi[idx][j]);
                        acc = Some(match acc {
                            None => t,
                            Some(e) => e.try_add(&t)?,
                        });
                    }
                    acc.ok_or_else(|| {
                        Halo2Error::operation_failed("poseidon::partial_gate", "empty row")
                    })
                };
                let mut constraints = Vec::with_capacity(width + 1);
                constraints.push(pow5(&cur0.try_add(&rc_a0)?)?.try_sub(&mid0)?);
                let mid0e = mid(meta, 0)?;
                constraints.push(pow5(&mid0e.try_add(&rc_b0)?)?.try_sub(&next(meta, 0)?)?);
                for (i, col) in rc_b_c.iter().enumerate().skip(1) {
                    let rc = meta.query_fixed(*col);
                    constraints.push(mid(meta, i)?.try_add(&rc)?.try_sub(&next(meta, i)?)?);
                }
                Ok(Constraints {
                    selector: Some(s),
                    constraints,
                })
            })?;
        }

        // Pad-and-add gate.
        {
            let state_c = state.clone();
            meta.create_gate(&mut |meta: &mut VirtualCells<'_>| {
                let initial_rate = meta.query_advice(state_c[rate], Rotation::prev());
                let output_rate = meta.query_advice(state_c[rate], Rotation::next());
                let s = meta.query_selector(s_pad_and_add);
                let mut constraints = Vec::with_capacity(rate + 1);
                for col in state_c.iter().take(rate) {
                    let initial = meta.query_advice(*col, Rotation::prev());
                    let input = meta.query_advice(*col, Rotation::cur());
                    let output = meta.query_advice(*col, Rotation::next());
                    constraints.push(initial.try_add(&input)?.try_sub(&output)?);
                }
                constraints.push(initial_rate.try_sub(&output_rate)?);
                Ok(Constraints {
                    selector: Some(s),
                    constraints,
                })
            })?;
        }

        Ok(Self {
            state,
            partial_sbox,
            rc_a,
            rc_b,
            s_full,
            s_partial,
            s_pad_and_add,
            half_full_rounds: half_full,
            half_partial_rounds: half_partial,
            round_constants,
            m_reg,
            m_inv,
        })
    }

    /// Initial state: rate zeros + `2^65` capacity (`BigInt.two << 64`).
    pub fn initial_state<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
    ) -> Halo2Result<Vec<PoseidonStateWord>> {
        let rate = POSEIDON_RATE;
        let state_cols = self.state.clone();
        let words = layouter.assign_region(&mut |region: &mut Region<'_>| {
            let mut words: Vec<PoseidonStateWord> = Vec::new();
            // `loadStateWord`: every word (including zeros) goes through
            // `assignAdviceFromConstant`, which also records plan constants.
            for col in state_cols.iter().take(rate) {
                let cell =
                    region.assign_advice_from_constant(*col, 0, PallasFp::zero())?;
                words.push(PoseidonStateWord { inner: cell });
            }
            let cap = PallasFp::from_u64(2).pow_u64(65);
            let cell = region.assign_advice_from_constant(state_cols[rate], 0, cap)?;
            words.push(PoseidonStateWord { inner: cell });
            Ok(words)
        })?;
        if words.len() != POSEIDON_WIDTH {
            return Err(Halo2Error::operation_failed(
                "poseidon::initial",
                "width mismatch",
            ));
        }
        Ok(words)
    }

    pub fn add_input<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        initial: Vec<PoseidonStateWord>,
        input: Absorbing<PaddedWord>,
    ) -> Halo2Result<Vec<PoseidonStateWord>> {
        let width = POSEIDON_WIDTH;
        if initial.len() != width {
            return Err(Halo2Error::operation_failed(
                "poseidon::add_input",
                "width mismatch",
            ));
        }
        let cfg = self.clone();
        layouter.assign_region(&mut |region: &mut Region<'_>| {
            region.enable_selector(cfg.s_pad_and_add, 1)?;
            let mut loaded_init = Vec::with_capacity(width);
            for (i, w) in initial.iter().enumerate().take(width) {
                let c = w.inner.copy_advice(region, cfg.state[i], 0)?;
                loaded_init.push(PoseidonStateWord { inner: c });
            }
            let exposed = input.exposed();
            let mut loaded_input: Vec<PoseidonStateWord> = Vec::new();
            for (i, padded) in exposed.iter().enumerate() {
                let p = padded.as_ref().ok_or_else(|| {
                    Halo2Error::operation_failed("poseidon::add_input", "input not padded")
                })?;
                match p {
                    PaddedWord::Message(cell) => {
                        let nc = cell.copy_advice(region, cfg.state[i], 1)?;
                        region.constrain_equal(cell.cell, nc.cell)?;
                        loaded_input.push(PoseidonStateWord { inner: nc });
                    }
                    PaddedWord::Padding(v) => {
                        let fcell = region.assign_fixed(cfg.rc_b[i], 1, &mut || Some(*v))?;
                        let nc = region.assign_advice(cfg.state[i], 1, &mut || Some(*v))?;
                        region.constrain_equal(fcell.cell, nc.cell)?;
                        loaded_input.push(PoseidonStateWord { inner: nc });
                    }
                }
            }
            let mut output = Vec::with_capacity(width);
            for i in 0..width {
                let mut value: Option<PallasFp> = loaded_init[i].inner.value;
                if i < loaded_input.len() {
                    if let Some(iv) = loaded_input[i].inner.value {
                        value = Some(match value {
                            Some(a) => a.add_vartime(&iv),
                            None => iv,
                        });
                    }
                }
                let c = region.assign_advice(cfg.state[i], 2, &mut || value)?;
                output.push(PoseidonStateWord { inner: c });
            }
            Ok(output)
        })
    }

    pub fn get_output(&self, words: Vec<PoseidonStateWord>) -> Squeezing<PoseidonStateWord> {
        Squeezing {
            items: words.into_iter().take(2).map(Some).collect(),
            pos: 0,
        }
    }

    pub fn permute<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        initial: Vec<PoseidonStateWord>,
    ) -> Halo2Result<Vec<PoseidonStateWord>> {
        let cfg = self.clone();
        layouter.assign_region(&mut |region: &mut Region<'_>| {
            let mut state = Pow5State::load(region, &initial, &cfg)?;
            for i in 0..cfg.half_full_rounds {
                state = state.full_round(region, i, i, &cfg)?;
            }
            for r in 0..cfg.half_partial_rounds {
                state = state.partial_round(
                    region,
                    &cfg,
                    cfg.half_full_rounds + 2 * r,
                    cfg.half_full_rounds + r,
                )?;
            }
            for r in 0..cfg.half_full_rounds {
                state = state.full_round(
                    region,
                    cfg.half_full_rounds + 2 * cfg.half_partial_rounds + r,
                    cfg.half_full_rounds + cfg.half_partial_rounds + r,
                    &cfg,
                )?;
            }
            Ok(state.words)
        })
    }

    #[cfg(feature = "alloc")]
    pub fn to_debug_string(&self) -> String {
        alloc::format!(
            "Pow5Config(half_full: {}, half_partial: {})",
            self.half_full_rounds,
            self.half_partial_rounds
        )
    }
}

struct Pow5State {
    words: Vec<PoseidonStateWord>,
}

impl Pow5State {
    fn load(
        region: &mut Region<'_>,
        initial: &[PoseidonStateWord],
        cfg: &Pow5Config,
    ) -> Halo2Result<Self> {
        let mut words = Vec::with_capacity(POSEIDON_WIDTH);
        for (i, w) in initial.iter().enumerate().take(POSEIDON_WIDTH) {
            words.push(PoseidonStateWord {
                inner: w.inner.copy_advice(region, cfg.state[i], 0)?,
            });
        }
        Ok(Self { words })
    }

    // `FnMut` sugar elides a higher-ranked lifetime that a named alias would
    // unify with the outer borrow, breaking borrowck; keep inline signature.
    #[allow(clippy::type_complexity)]
    fn round(
        region: &mut Region<'_>,
        round: usize,
        offset: usize,
        gate: Selector,
        cfg: &Pow5Config,
        round_fn: &mut dyn FnMut(&mut Region<'_>) -> Halo2Result<(usize, Vec<Option<PallasFp>>)>,
    ) -> Halo2Result<Self> {
        gate.enable(region, offset)?;
        for i in 0..POSEIDON_WIDTH {
            let rc = *cfg
                .round_constants
                .get(round)
                .and_then(|r| r.get(i))
                .ok_or_else(|| Halo2Error::operation_failed("poseidon::round", "rc overflow"))?;
            region.assign_fixed(cfg.rc_a[i], offset, &mut || Some(rc))?;
        }
        let (_, next_state) = round_fn(region)?;
        let mut state = Vec::with_capacity(POSEIDON_WIDTH);
        for (i, v) in next_state.into_iter().enumerate().take(POSEIDON_WIDTH) {
            state.push(PoseidonStateWord {
                inner: region.assign_advice(cfg.state[i], offset + 1, &mut || v)?,
            });
        }
        Ok(Self { words: state })
    }

    fn full_round(
        self,
        region: &mut Region<'_>,
        round: usize,
        offset: usize,
        cfg: &Pow5Config,
    ) -> Halo2Result<Self> {
        let words = self.words;
        Self::round(region, round, offset, cfg.s_full, cfg, &mut |_region| {
            let mut q: Vec<Option<PallasFp>> = Vec::with_capacity(words.len());
            for (i, w) in words.iter().enumerate() {
                let c = *cfg
                    .round_constants
                    .get(round)
                    .and_then(|r| r.get(i))
                    .ok_or_else(|| Halo2Error::operation_failed("poseidon::full", "rc overflow"))?;
                q.push(w.inner.value.map(|v| v.add_vartime(&c)));
            }
            let mut r: Vec<Option<PallasFp>> = Vec::with_capacity(q.len());
            for v in q.iter() {
                r.push(match v {
                    Some(x) => {
                        let x2 = x.square_vartime();
                        Some(x2.square_vartime().mul_vartime(x))
                    }
                    None => None,
                });
            }
            let mut next = Vec::with_capacity(POSEIDON_WIDTH);
            for idx in 0..POSEIDON_WIDTH {
                let row = &cfg.m_reg[idx];
                let mut acc = PallasFp::zero();
                let mut missing = false;
                for (j, rv) in r.iter().enumerate() {
                    match rv {
                        Some(x) => acc = acc.add_vartime(&row[j].mul_vartime(x)),
                        None => {
                            missing = true;
                            break;
                        }
                    }
                }
                next.push(if missing { None } else { Some(acc) });
            }
            Ok((round + 1, next))
        })
    }

    fn partial_round(
        self,
        region: &mut Region<'_>,
        cfg: &Pow5Config,
        round: usize,
        offset: usize,
    ) -> Halo2Result<Self> {
        let words = self.words;
        Self::round(region, round, offset, cfg.s_partial, cfg, &mut |region| {
            let p: Vec<Option<PallasFp>> = words.iter().map(|w| w.inner.value).collect();
            let mut r: Option<Vec<Option<PallasFp>>> = None;
            if let Some(p0) = p[0] {
                let rc0 = cfg.round_constants[round][0];
                let r0 = pow5_fp(p0.add_vartime(&rc0));
                let mut row = Vec::with_capacity(p.len());
                row.push(Some(r0));
                for (k, pv) in p.iter().enumerate().skip(1) {
                    row.push(pv.as_ref().map(|x| x.add_vartime(&cfg.round_constants[round][k])));
                }
                r = Some(row);
            }
            let r0val = match &r {
                Some(row) => row[0],
                None => None,
            };
            region.assign_advice(cfg.partial_sbox, offset, &mut || r0val)?;
            let mut p_mid: Vec<Option<PallasFp>> = Vec::with_capacity(POSEIDON_WIDTH);
            for mi in cfg.m_reg.iter() {
                match &r {
                    Some(row) => {
                        let mut acc = PallasFp::zero();
                        let mut missing = false;
                        for (j, rv) in row.iter().enumerate() {
                            match rv {
                                Some(x) => acc = acc.add_vartime(&mi[j].mul_vartime(x)),
                                None => {
                                    missing = true;
                                    break;
                                }
                            }
                        }
                        p_mid.push(if missing { None } else { Some(acc) });
                    }
                    None => p_mid.push(None),
                }
            }
            for i in 0..POSEIDON_WIDTH {
                let rc = cfg.round_constants[round + 1][i];
                region.assign_fixed(cfg.rc_b[i], offset, &mut || Some(rc))?;
            }
            let mut r_mid: Option<Vec<Option<PallasFp>>> = None;
            if let Some(pm0) = p_mid[0] {
                let rc0 = cfg.round_constants[round + 1][0];
                let r0 = pow5_fp(pm0.add_vartime(&rc0));
                let mut row = Vec::with_capacity(p_mid.len());
                row.push(Some(r0));
                for (k, pv) in p_mid.iter().enumerate().skip(1) {
                    row.push(pv.as_ref().map(|x| x.add_vartime(&cfg.round_constants[round + 1][k])));
                }
                r_mid = Some(row);
            }
            let mut state: Vec<Option<PallasFp>> = Vec::with_capacity(POSEIDON_WIDTH);
            for mi in cfg.m_reg.iter() {
                match &r_mid {
                    Some(row) => {
                        let mut acc = PallasFp::zero();
                        let mut missing = false;
                        for (j, rv) in row.iter().enumerate() {
                            match rv {
                                Some(x) => acc = acc.add_vartime(&mi[j].mul_vartime(x)),
                                None => {
                                    missing = true;
                                    break;
                                }
                            }
                        }
                        state.push(if missing { None } else { Some(acc) });
                    }
                    None => state.push(None),
                }
            }
            Ok((round + 2, state))
        })
    }
}

fn pow5_fp(x: PallasFp) -> PallasFp {
    let x2 = x.square_vartime();
    x2.square_vartime().mul_vartime(&x)
}

#[derive(Clone)]
pub enum PaddedWord {
    Message(AssignedCell<PallasFp>),
    Padding(PallasFp),
}

#[derive(Clone)]
pub struct PoseidonStateWord {
    pub inner: AssignedCell<PallasFp>,
}

pub struct Absorbing<T> {
    items: Vec<Option<T>>,
}

impl<T> Absorbing<T> {
    pub fn new(items: Vec<Option<T>>) -> Self {
        Self { items }
    }

    pub fn exposed(&self) -> &[Option<T>] {
        &self.items
    }

    /// Absorb one element into the first empty slot; `Err` when full.
    pub fn absorb(&mut self, value: T) -> Halo2Result<()> {
        for slot in self.items.iter_mut() {
            if slot.is_none() {
                *slot = Some(value);
                return Ok(());
            }
        }
        Err(Halo2Error::operation_failed(
            "sponge::absorb",
            "state is full",
        ))
    }
}

pub struct Squeezing<T> {
    items: Vec<Option<T>>,
    pos: usize,
}

impl<T: Clone> Squeezing<T> {
    pub fn squeeze(&mut self) -> Option<T> {
        while self.pos < self.items.len() {
            let v = self.items[self.pos].clone();
            self.pos += 1;
            if v.is_some() {
                return v;
            }
        }
        None
    }
}

pub struct SpongeAbsorbing {
    pub chip: Pow5Config,
    pub mode: Absorbing<PaddedWord>,
    pub state: Vec<PoseidonStateWord>,
}

impl SpongeAbsorbing {
    pub fn rate(&self) -> usize {
        POSEIDON_RATE
    }

    pub fn init<L: Layouter + ?Sized>(layouter: &mut L, chip: &Pow5Config) -> Halo2Result<Self> {
        let state = chip.initial_state(layouter)?;
        Ok(Self {
            chip: chip.clone(),
            mode: Absorbing::new(vec![None; POSEIDON_RATE]),
            state,
        })
    }

    fn poseidon_sponge<L: Layouter + ?Sized>(
        &self,
        layouter: &mut L,
        input: Option<Absorbing<PaddedWord>>,
    ) -> Halo2Result<Squeezing<PoseidonStateWord>> {
        // Mirrors Ref: `state` is borrowed per call, never reassigned.
        let mut state = self.state.clone();
        if let Some(inp) = input {
            state = self.chip.add_input(layouter, state, inp)?;
        }
        state = self.chip.permute(layouter, state)?;
        Ok(self.chip.get_output(state))
    }

    /// Absorb one element; applies the sponge when full, then retries.
    pub fn absorb<L: Layouter + ?Sized>(
        &mut self,
        layouter: &mut L,
        value: PaddedWord,
    ) -> Halo2Result<()> {
        if self.mode.absorb(value.clone()).is_ok() {
            return Ok(());
        }
        let full = core::mem::replace(&mut self.mode, Absorbing::new(vec![None; POSEIDON_RATE]));
        let _ = self.poseidon_sponge(layouter, Some(full))?;
        self.mode
            .absorb(value)
            .map_err(|_| Halo2Error::operation_failed("sponge::absorb", "state is full"))
    }

    pub fn finish_absorbing<L: Layouter + ?Sized>(
        &mut self,
        layouter: &mut L,
    ) -> Halo2Result<SpongeSqueezing> {
        let full = core::mem::replace(&mut self.mode, Absorbing::new(vec![None; POSEIDON_RATE]));
        let mode = self.poseidon_sponge(layouter, Some(full))?;
        Ok(SpongeSqueezing {
            mode,
            state: self.state.clone(),
        })
    }
}

pub struct SpongeSqueezing {
    pub mode: Squeezing<PoseidonStateWord>,
    pub state: Vec<PoseidonStateWord>,
}

impl SpongeSqueezing {
    pub fn squeeze(&mut self) -> Halo2Result<AssignedCell<PallasFp>> {
        self.mode
            .squeeze()
            .map(|w| w.inner)
            .ok_or_else(|| Halo2Error::operation_failed("sponge::squeeze", "empty squeeze"))
    }

    pub fn squeeze_with_permute<L: Layouter + ?Sized>(
        &mut self,
        layouter: &mut L,
        chip: &Pow5Config,
    ) -> Halo2Result<AssignedCell<PallasFp>> {
        if let Some(v) = self.mode.squeeze() {
            return Ok(v.inner);
        }
        let state = core::mem::take(&mut self.state);
        let state = chip.permute(layouter, state)?;
        self.state = state.clone();
        self.mode = chip.get_output(state);
        self.mode
            .squeeze()
            .map(|w| w.inner)
            .ok_or_else(|| Halo2Error::operation_failed("sponge::squeeze", "empty squeeze"))
    }
}

/// Hash wrapper: init → absorb messages → finish → squeeze.
pub struct HaloPoseidonHash {
    pub sponge: SpongeAbsorbing,
}

impl HaloPoseidonHash {
    pub fn init<L: Layouter + ?Sized>(layouter: &mut L, chip: &Pow5Config) -> Halo2Result<Self> {
        Ok(Self {
            sponge: SpongeAbsorbing::init(layouter, chip)?,
        })
    }

    fn padding(&self, input_len: usize) -> Halo2Result<Vec<PaddedWord>> {
        if input_len != POSEIDON_RATE {
            return Err(Halo2Error::operation_failed(
                "poseidon::padding",
                "bad input length",
            ));
        }
        Ok(Vec::new())
    }

    pub fn hash<L: Layouter + ?Sized>(
        &mut self,
        layouter: &mut L,
        messages: Vec<AssignedCell<PallasFp>>,
    ) -> Halo2Result<AssignedCell<PallasFp>> {
        let mut words: Vec<PaddedWord> = messages.into_iter().map(PaddedWord::Message).collect();
        for p in self.padding(words.len())? {
            words.push(p);
        }
        for w in words.into_iter() {
            self.sponge.absorb(layouter, w)?;
        }
        let mut squeezing = self.sponge.finish_absorbing(layouter)?;
        squeezing.squeeze()
    }
}
