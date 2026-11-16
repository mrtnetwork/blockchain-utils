//! Implements chip/add logic (complete + incomplete addition).
//! Gate polynomials use `try_*` operators; exceptional-case ABCD logic is
//! mirrored exactly. `EccPoint` cells hold `Assigned`.

#[cfg(feature = "alloc")]
use alloc::string::String;
// `Vec` is prelude under `std`; import from `alloc` only for `no_std`.
#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::vec::Vec;

use crate::zk::orchard_halo2::chip::ecc::EccPoint;
use crate::zk::orchard_halo2::error::{Halo2Error, Halo2Result};
use crate::zk::orchard_halo2::field::PallasFp;
use crate::zk::orchard_halo2::plonk::assigned::Assigned;
use crate::zk::orchard_halo2::plonk::column::AssignmentColumn;
use crate::zk::orchard_halo2::plonk::column::Selector;
use crate::zk::orchard_halo2::plonk::constraint::{ConstraintSystem, Constraints, VirtualCells};
use crate::zk::orchard_halo2::plonk::expression::Expression;
use crate::zk::orchard_halo2::poly::poly::Rotation;
use crate::zk::orchard_halo2::utility::layouter::Region;

#[derive(Clone, Copy)]
pub struct AddConfig {
    pub q_add: Selector,
    pub lambda: AssignmentColumn,
    pub x_p: AssignmentColumn,
    pub y_p: AssignmentColumn,
    pub x_qr: AssignmentColumn,
    pub y_qr: AssignmentColumn,
    pub alpha: AssignmentColumn,
    pub beta: AssignmentColumn,
    pub gamma: AssignmentColumn,
    pub delta: AssignmentColumn,
}

impl AddConfig {
    #[allow(clippy::too_many_arguments)] // Gate API mirrors upstream halo2 circuit signatures; regrouping args would churn call sites.
    pub fn configure(
        meta: &mut ConstraintSystem,
        x_p: AssignmentColumn,
        y_p: AssignmentColumn,
        x_qr: AssignmentColumn,
        y_qr: AssignmentColumn,
        lambda: AssignmentColumn,
        alpha: AssignmentColumn,
        beta: AssignmentColumn,
        gamma: AssignmentColumn,
        delta: AssignmentColumn,
    ) -> Halo2Result<Self> {
        meta.enable_equality(x_p);
        meta.enable_equality(y_p);
        meta.enable_equality(x_qr);
        meta.enable_equality(y_qr);
        let config = Self {
            q_add: meta.selector(),
            lambda,
            x_p,
            y_p,
            x_qr,
            y_qr,
            alpha,
            beta,
            gamma,
            delta,
        };
        config.create_gate(meta)?;
        Ok(config)
    }

    fn create_gate(&self, meta: &mut ConstraintSystem) -> Halo2Result<()> {
        meta.create_gate(&mut |meta: &mut VirtualCells<'_>| {
            let q_add = meta.query_selector(self.q_add);
            let x_p = meta.query_advice(self.x_p, Rotation::cur());
            let y_p = meta.query_advice(self.y_p, Rotation::cur());
            let x_q = meta.query_advice(self.x_qr, Rotation::cur());
            let y_q = meta.query_advice(self.y_qr, Rotation::cur());
            let x_r = meta.query_advice(self.x_qr, Rotation::next());
            let y_r = meta.query_advice(self.y_qr, Rotation::next());
            let lambda = meta.query_advice(self.lambda, Rotation::cur());
            let alpha = meta.query_advice(self.alpha, Rotation::cur());
            let beta = meta.query_advice(self.beta, Rotation::cur());
            let gamma = meta.query_advice(self.gamma, Rotation::cur());
            let delta = meta.query_advice(self.delta, Rotation::cur());

            let xq_minus_xp = x_q.try_sub(&x_p)?;
            let xp_minus_xr = x_p.try_sub(&x_r)?;
            let yq_plus_yp = y_q.try_add(&y_p)?;

            let if_alpha = xq_minus_xp.try_mul_expr(&alpha)?;
            let if_beta = x_p.try_mul_expr(&beta)?;
            let if_gamma = x_q.try_mul_expr(&gamma)?;
            let if_delta = yq_plus_yp.try_mul_expr(&delta)?;

            let one = Expression::constant(PallasFp::one());
            let two = Expression::constant(PallasFp::from_u64(2));
            let three = Expression::constant(PallasFp::from_u64(3));

            let yq_minus_yp = y_q.try_sub(&y_p)?;
            let incomplete = xq_minus_xp.try_mul_expr(&lambda)?.try_sub(&yq_minus_yp)?;
            let poly1 = xq_minus_xp.try_mul_expr(&incomplete)?;

            let poly2 = one.try_sub(&if_alpha)?.try_mul_expr(
                &two.try_mul_expr(&y_p)?
                    .try_mul_expr(&lambda)?
                    .try_sub(&three.try_mul_expr(&x_p.try_mul_expr(&x_p)?)?)?,
            )?;

            let non_xr = lambda
                .try_mul_expr(&lambda)?
                .try_sub(&x_p)?
                .try_sub(&x_q)?
                .try_sub(&x_r)?;
            let non_yr = lambda
                .try_mul_expr(&xp_minus_xr)?
                .try_sub(&y_p)?
                .try_sub(&y_r)?;

            let poly3a = x_p
                .try_mul_expr(&x_q)?
                .try_mul_expr(&xq_minus_xp)?
                .try_mul_expr(&non_xr)?;
            let poly3b = x_p
                .try_mul_expr(&x_q)?
                .try_mul_expr(&xq_minus_xp)?
                .try_mul_expr(&non_yr)?;
            let poly3c = x_p
                .try_mul_expr(&x_q)?
                .try_mul_expr(&yq_plus_yp)?
                .try_mul_expr(&non_xr)?;
            let poly3d = x_p
                .try_mul_expr(&x_q)?
                .try_mul_expr(&yq_plus_yp)?
                .try_mul_expr(&non_yr)?;

            let poly4a = one.try_sub(&if_beta)?.try_mul_expr(&x_r.try_sub(&x_q)?)?;
            let poly4b = one.try_sub(&if_beta)?.try_mul_expr(&y_r.try_sub(&y_q)?)?;
            let poly5a = one.try_sub(&if_gamma)?.try_mul_expr(&x_r.try_sub(&x_p)?)?;
            let poly5b = one.try_sub(&if_gamma)?.try_mul_expr(&y_r.try_sub(&y_p)?)?;
            let one_minus = one.try_sub(&if_alpha)?.try_sub(&if_delta)?;
            let poly6a = one_minus.try_mul_expr(&x_r)?;
            let poly6b = one_minus.try_mul_expr(&y_r)?;

            Ok(Constraints {
                selector: Some(q_add),
                constraints: vec![
                    poly1, poly2, poly3a, poly3b, poly3c, poly3d, poly4a, poly4b, poly5a, poly5b,
                    poly6a, poly6b,
                ],
            })
        })
    }

    pub fn assign_region(
        &self,
        p: &EccPoint,
        q: &EccPoint,
        offset: usize,
        region: &mut Region<'_>,
    ) -> Halo2Result<EccPoint> {
        self.q_add.enable(region, offset)?;
        p.x.copy_advice(region, self.x_p, offset)?;
        p.y.copy_advice(region, self.y_p, offset)?;
        q.x.copy_advice(region, self.x_qr, offset)?;
        q.y.copy_advice(region, self.y_qr, offset)?;

        let xp = p.x.value;
        let yp = p.y.value;
        let xq = q.x.value;
        let yq = q.y.value;

        let alpha: Option<Assigned> = match (xq, xp) {
            (Some(a), Some(b)) => Some(a.try_sub(&b).invert()),
            _ => None,
        };
        region.assign_advice(self.alpha, offset, &mut || alpha)?;

        let beta: Option<Assigned> = xp.map(|v| v.invert());
        region.assign_advice(self.beta, offset, &mut || beta)?;

        let gamma: Option<Assigned> = xq.map(|v| v.invert());
        region.assign_advice(self.gamma, offset, &mut || gamma)?;

        let mut delta: Option<Assigned> = None;
        if let (Some(a), Some(b), Some(c), Some(d)) = (xp, xq, yp, yq) {
            delta = Some(if a.assigned_eq(&b) {
                c.try_add(&d).invert()
            } else {
                Assigned::Zero
            });
        }
        region.assign_advice(self.delta, offset, &mut || delta)?;

        let mut lambda: Option<Assigned> = None;
        if let (Some(a), Some(b), Some(c), Some(d), Some(al)) = (xp, yp, xq, yq, alpha) {
            if !a.assigned_eq(&c) {
                lambda = Some(d.try_sub(&b).try_mul(&al));
            } else if !b.is_zero() {
                let three_xp2 = a
                    .square()
                    .try_mul(&Assigned::Trivial(PallasFp::from_u64(3)));
                let inv_two_yp = b.invert().try_mul(&Assigned::Trivial(PallasFp::two_inv()));
                lambda = Some(three_xp2.try_mul(&inv_two_yp));
            } else {
                lambda = Some(Assigned::Zero);
            }
        }
        region.assign_advice(self.lambda, offset, &mut || lambda)?;

        let (mut xr, mut yr): (Option<Assigned>, Option<Assigned>) = (None, None);
        if let (Some(a), Some(b), Some(c), Some(d), Some(l)) = (xp, yp, xq, yq, lambda) {
            if a.is_zero() {
                xr = Some(c);
                yr = Some(d);
            } else if c.is_zero() {
                xr = Some(a);
                yr = Some(b);
            } else if a.assigned_eq(&c) && d.assigned_eq(&b.neg()) {
                xr = Some(Assigned::Zero);
                yr = Some(Assigned::Zero);
            } else {
                let x = l.square().try_sub(&a).try_sub(&c);
                let y = l.try_mul(&a.try_sub(&x)).try_sub(&b);
                xr = Some(x);
                yr = Some(y);
            }
        }
        let x_cell = region.assign_advice(self.x_qr, offset + 1, &mut || xr)?;
        let y_cell = region.assign_advice(self.y_qr, offset + 1, &mut || yr)?;
        Ok(EccPoint {
            x: x_cell,
            y: y_cell,
        })
    }

    #[cfg(feature = "alloc")]
    pub fn to_debug_string(&self) -> String {
        alloc::string::String::from("AddConfig")
    }
}

#[derive(Clone, Copy)]
pub struct AddIncompleteConfig {
    pub q_add_incomplete: Selector,
    pub x_p: AssignmentColumn,
    pub y_p: AssignmentColumn,
    pub x_qr: AssignmentColumn,
    pub y_qr: AssignmentColumn,
}

impl AddIncompleteConfig {
    pub fn configure(
        meta: &mut ConstraintSystem,
        x_p: AssignmentColumn,
        y_p: AssignmentColumn,
        x_qr: AssignmentColumn,
        y_qr: AssignmentColumn,
    ) -> Halo2Result<Self> {
        meta.enable_equality(x_p);
        meta.enable_equality(y_p);
        meta.enable_equality(x_qr);
        meta.enable_equality(y_qr);
        let config = Self {
            q_add_incomplete: meta.selector(),
            x_p,
            y_p,
            x_qr,
            y_qr,
        };
        config.create_gate(meta)?;
        Ok(config)
    }

    fn create_gate(&self, meta: &mut ConstraintSystem) -> Halo2Result<()> {
        meta.create_gate(&mut |meta: &mut VirtualCells<'_>| {
            let q = meta.query_selector(self.q_add_incomplete);
            let x_p_cur = meta.query_advice(self.x_p, Rotation::cur());
            let y_p_cur = meta.query_advice(self.y_p, Rotation::cur());
            let x_q = meta.query_advice(self.x_qr, Rotation::cur());
            let y_q = meta.query_advice(self.y_qr, Rotation::cur());
            let x_r = meta.query_advice(self.x_qr, Rotation::next());
            let y_r = meta.query_advice(self.y_qr, Rotation::next());

            let poly1 = x_r
                .try_add(&x_q)?
                .try_add(&x_p_cur)?
                .try_mul_expr(&x_p_cur.try_sub(&x_q)?)?
                .try_mul_expr(&x_p_cur.try_sub(&x_q)?)?
                .try_sub(&y_p_cur.try_sub(&y_q)?.square()?)?;
            let poly2 = y_r
                .try_add(&y_q)?
                .try_mul_expr(&x_p_cur.try_sub(&x_q)?)?
                .try_sub(&y_p_cur.try_sub(&y_q)?.try_mul_expr(&x_q.try_sub(&x_r)?)?)?;
            Ok(Constraints {
                selector: Some(q),
                constraints: vec![poly1, poly2],
            })
        })
    }

    pub fn assign_region(
        &self,
        p: &EccPoint,
        q: &EccPoint,
        offset: usize,
        region: &mut Region<'_>,
    ) -> Halo2Result<EccPoint> {
        self.q_add_incomplete.enable(region, offset)?;
        let xp = p.x.value;
        let yp = p.y.value;
        let xq = q.x.value;
        let yq = q.y.value;
        if let (Some(a), Some(b), Some(c), Some(d)) = (xp, yp, xq, yq) {
            let p_inf = a.is_zero() && b.is_zero();
            let q_inf = c.is_zero() && d.is_zero();
            if p_inf || q_inf || a.assigned_eq(&c) {
                return Err(Halo2Error::operation_failed(
                    "add_incomplete::assign",
                    "zero point addition",
                ));
            }
        }
        p.x.copy_advice(region, self.x_p, offset)?;
        p.y.copy_advice(region, self.y_p, offset)?;
        q.x.copy_advice(region, self.x_qr, offset)?;
        q.y.copy_advice(region, self.y_qr, offset)?;

        let (mut xr, mut yr): (Option<Assigned>, Option<Assigned>) = (None, None);
        if let (Some(a), Some(b), Some(c), Some(d)) = (xp, yp, xq, yq) {
            let lambda = d.try_sub(&b).try_mul(&c.try_sub(&a).invert());
            let x = lambda.square().try_sub(&a).try_sub(&c);
            let y = lambda.try_mul(&a.try_sub(&x)).try_sub(&b);
            xr = Some(x);
            yr = Some(y);
        }
        let x_cell = region.assign_advice(self.x_qr, offset + 1, &mut || xr)?;
        let y_cell = region.assign_advice(self.y_qr, offset + 1, &mut || yr)?;
        Ok(EccPoint {
            x: x_cell,
            y: y_cell,
        })
    }
}
