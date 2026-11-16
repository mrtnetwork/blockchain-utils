//! Implements poly/commitment/msm logic (`MSM` accumulator).
//! Ordered map keyed by x LE bytes (linear search; small n). `assert`s on
//! matching `-y` become release-semantics: same y → add, else subtract.
//! `eval` runs serial MSM and reports identity. Result style, no `assert!`.

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

use crate::zk::orchard_halo2::curve::{msm_vesta, VestaAffine};
use crate::zk::orchard_halo2::error::{Halo2Error, Halo2Result};
use crate::zk::orchard_halo2::field::{PallasFp, VestaFq};
use crate::zk::orchard_halo2::poly::params::PolyParams;

#[derive(Clone, Copy)]
struct OtherTerm {
    scalar: PallasFp,
    y: VestaFq,
}

#[derive(Clone)]
pub struct Msm<'a> {
    pub params: &'a PolyParams,
    g_scalars: Option<Vec<PallasFp>>,
    w_scalar: Option<PallasFp>,
    u_scalar: Option<PallasFp>,
    other: Vec<([u8; 32], OtherTerm)>,
}

impl<'a> Msm<'a> {
    pub fn new(params: &'a PolyParams) -> Self {
        Self {
            params,
            g_scalars: None,
            w_scalar: None,
            u_scalar: None,
            other: Vec::new(),
        }
    }

    pub fn clone_msm(&self) -> Self {
        Self {
            params: self.params,
            g_scalars: self.g_scalars.clone(),
            w_scalar: self.w_scalar,
            u_scalar: self.u_scalar,
            other: self.other.clone(),
        }
    }

    #[cfg(feature = "alloc")]
    pub fn to_debug_string(&self) -> String {
        alloc::format!(
            "MSM(g: {}, w: {}, u: {}, other: {})",
            self.g_scalars.as_ref().map(|g| g.len()).unwrap_or(0),
            self.w_scalar.is_some(),
            self.u_scalar.is_some(),
            self.other.len()
        )
    }

    fn merge_other(&mut self, x: VestaFq, x_le: [u8; 32], scalar: PallasFp, y: VestaFq) {
        for (ex, term) in self.other.iter_mut() {
            if *ex == x_le {
                if term.y == y {
                    term.scalar = term.scalar.add_vartime(&scalar);
                } else {
                    term.scalar = term.scalar.sub_vartime(&scalar);
                }
                return;
            }
        }
        let _ = x;
        self.other.push((x_le, OtherTerm { scalar, y }));
    }

    pub fn add_msm(&mut self, o: &Msm<'a>) -> Halo2Result<()> {
        for (x_le, term) in o.other.iter() {
            let x = VestaFq::from_le_array(x_le)?;
            self.merge_other(x, *x_le, term.scalar, term.y);
        }
        if let Some(g) = &o.g_scalars {
            let _ = self.add_to_g_scalars(g);
        }
        if let Some(w) = o.w_scalar {
            self.add_to_w_scalar(w);
        }
        if let Some(u) = o.u_scalar {
            self.add_to_u_scalar(u);
        }
        Ok(())
    }

    pub fn append_term(&mut self, scalar: PallasFp, point: &VestaAffine) -> Halo2Result<()> {
        if point.is_identity() {
            return Ok(());
        }
        let (x_le, y_le, _) = point.to_affine_le()?;
        let x = VestaFq::from_le_array(&x_le)?;
        let y = VestaFq::from_le_array(&y_le)?;
        self.merge_other(x, x_le, scalar, y);
        Ok(())
    }

    pub fn add_constant_term(&mut self, constant: PallasFp) -> Halo2Result<()> {
        match &mut self.g_scalars {
            Some(g) => {
                let first = g
                    .get_mut(0)
                    .ok_or_else(|| Halo2Error::operation_failed("msm::constant", "empty g"))?;
                *first = first.add_vartime(&constant);
                Ok(())
            }
            None => {
                let mut scalars = vec![PallasFp::zero(); self.params.n];
                if scalars.is_empty() {
                    return Err(Halo2Error::operation_failed("msm::constant", "empty n"));
                }
                scalars[0] = scalars[0].add_vartime(&constant);
                self.g_scalars = Some(scalars);
                Ok(())
            }
        }
    }

    pub fn add_to_g_scalars(&mut self, scalars: &[PallasFp]) -> Halo2Result<()> {
        if scalars.len() != self.params.n {
            return Err(Halo2Error::operation_failed(
                "msm::g_scalars",
                "length mismatch",
            ));
        }
        match &mut self.g_scalars {
            Some(g) => {
                for (a, b) in g.iter_mut().zip(scalars.iter()) {
                    *a = a.add_vartime(b);
                }
            }
            None => {
                self.g_scalars = Some(scalars.to_vec());
            }
        }
        Ok(())
    }

    pub fn add_to_w_scalar(&mut self, scalar: PallasFp) {
        self.w_scalar = Some(match self.w_scalar {
            Some(w) => w.add_vartime(&scalar),
            None => scalar,
        });
    }

    pub fn add_to_u_scalar(&mut self, scalar: PallasFp) {
        self.u_scalar = Some(match self.u_scalar {
            Some(u) => u.add_vartime(&scalar),
            None => scalar,
        });
    }

    pub fn scale(&mut self, factor: PallasFp) {
        if let Some(g) = &mut self.g_scalars {
            for v in g.iter_mut() {
                *v = v.mul_vartime(&factor);
            }
        }
        for (_, term) in self.other.iter_mut() {
            term.scalar = term.scalar.mul_vartime(&factor);
        }
        if let Some(w) = self.w_scalar {
            self.w_scalar = Some(w.mul_vartime(&factor));
        }
        if let Some(u) = self.u_scalar {
            self.u_scalar = Some(u.mul_vartime(&factor));
        }
    }

    /// Evaluate: MSM == identity? Returns `Ok(true/false)`.
    pub fn eval(&self) -> Halo2Result<bool> {
        let mut scalars: Vec<PallasFp> = Vec::new();
        let mut bases: Vec<VestaAffine> = Vec::new();
        for (x_le, term) in self.other.iter() {
            scalars.push(term.scalar);
            bases.push(VestaAffine::from_le_xy(*x_le, term.y.to_le_bytes())?);
        }
        if let Some(w) = self.w_scalar {
            scalars.push(w);
            bases.push(self.params.w);
        }
        if let Some(u) = self.u_scalar {
            scalars.push(u);
            bases.push(self.params.u);
        }
        if let Some(g) = &self.g_scalars {
            if g.len() != self.params.g.len() {
                return Err(Halo2Error::operation_failed(
                    "msm::eval",
                    "g length mismatch",
                ));
            }
            scalars.extend_from_slice(g);
            bases.extend_from_slice(&self.params.g);
        }
        let acc = msm_vesta(&scalars, &bases)?;
        Ok(acc.is_identity())
    }
}
