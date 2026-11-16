//! Implements poly/params logic (`PolyParams`).
//! Bases `g`/`w`/`u` are compile-time Vesta compressed LE constants
//! (`tables::IPA_G/W/U`, bit-exact from `hashToCurve`). `gLagrange`
//! is derived at runtime via point FFT (no per-element hashing).
//! Result style, no `assert!`.

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

use crate::zk::orchard_halo2::curve::{msm_vesta, VestaAffine, VestaProjective, VestaScalar};
use crate::zk::orchard_halo2::error::{Halo2Error, Halo2Result};
use crate::zk::orchard_halo2::field::PallasFp;
use crate::zk::orchard_halo2::poly::poly::{Basis, Polynomial};
use crate::zk::orchard_halo2::tables::IPA_G_MAX_K;
use crate::zk::orchard_halo2::tables_ipa_mont::{IPA_G_MONT, IPA_U_MONT, IPA_W_MONT};
use crate::zk::orchard_halo2::utility::utils::best_fft_points;

#[derive(Clone)]
pub struct PolyParams {
    pub k: u32,
    pub n: usize,
    pub g: Vec<VestaAffine>,
    pub g_lagrange: Vec<VestaAffine>,
    pub w: VestaAffine,
    pub u: VestaAffine,
}

impl PolyParams {
    #[cfg(feature = "alloc")]
    pub fn to_debug_string(&self) -> String {
        alloc::format!("PolyParams(k: {}, n: {})", self.k, self.n)
    }

    /// `newParams(k)`: first `2^k` bases of the k=11 table + FFT Lagrange.
    pub fn new_params(k: u32) -> Halo2Result<Self> {
        if k >= 32 {
            return Err(Halo2Error::operation_failed("params::new", "k too large"));
        }
        if (k as usize) > IPA_G_MAX_K {
            return Err(Halo2Error::operation_failed(
                "params::new",
                "k above precomputed table",
            ));
        }
        let n: usize = 1usize << k;
        let mut g: Vec<VestaAffine> = Vec::with_capacity(n);
        // IPA bases from Montgomery-limb tables (unchecked: trusted vendored
        // points; no decompression/sqrt, no Montgomery conversion).
        for row in IPA_G_MONT.iter().take(n) {
            g.push(VestaAffine::from_affine_mont_limbs(row[0], row[1]));
        }
        // alphaInv = rou_inv^(2^(S-k))
        let mut alpha_inv = PallasFp::root_of_unity();
        let inv = alpha_inv.invert()?;
        alpha_inv = inv;
        for _ in k..32 {
            alpha_inv = alpha_inv.square_vartime();
        }
        let mut proj: Vec<VestaProjective> = Vec::with_capacity(n);
        for b in g.iter() {
            proj.push(b.to_projective()?);
        }
        best_fft_points(&mut proj, alpha_inv, k)?;
        let mut minv = PallasFp::two_inv();
        let mut acc = PallasFp::one();
        for _ in 0..k {
            acc = acc.mul_vartime(&minv);
        }
        minv = acc;
        let mut g_lagrange: Vec<VestaAffine> = Vec::with_capacity(n);
        for p in proj.iter() {
            let scaled = scale_projective(p, &minv)?;
            g_lagrange.push(scaled);
        }
        let w = VestaAffine::from_affine_mont_limbs(IPA_W_MONT[0], IPA_W_MONT[1]);
        let u = VestaAffine::from_affine_mont_limbs(IPA_U_MONT[0], IPA_U_MONT[1]);
        Ok(Self {
            k,
            n,
            g,
            g_lagrange,
            w,
            u,
        })
    }

    /// Commit (coeff basis) blinded by `r`: MSM(values + [r], g + [w]).
    pub fn commit(&self, poly: &Polynomial<PallasFp>, r: PallasFp) -> Halo2Result<VestaProjective> {
        let mut coeffs: Vec<PallasFp> = Vec::with_capacity(poly.values.len() + 1);
        coeffs.extend_from_slice(&poly.values);
        coeffs.push(r);
        let mut bases: Vec<VestaAffine> = Vec::with_capacity(self.g.len() + 1);
        bases.extend_from_slice(&self.g[..core::cmp::min(self.g.len(), poly.values.len())]);
        if bases.len() != poly.values.len() {
            return Err(Halo2Error::operation_failed(
                "params::commit",
                "length mismatch",
            ));
        }
        bases.push(self.w);
        msm_vesta(&coeffs, &bases)
    }

    /// Commit in Lagrange basis (uses `g_lagrange`).
    pub fn commit_lagrange(
        &self,
        poly: &Polynomial<PallasFp>,
        r: PallasFp,
    ) -> Halo2Result<VestaProjective> {
        let mut coeffs: Vec<PallasFp> = Vec::with_capacity(poly.values.len() + 1);
        coeffs.extend_from_slice(&poly.values);
        coeffs.push(r);
        let mut bases: Vec<VestaAffine> = Vec::with_capacity(self.g_lagrange.len() + 1);
        bases.extend_from_slice(
            &self.g_lagrange[..core::cmp::min(self.g_lagrange.len(), poly.values.len())],
        );
        if bases.len() != poly.values.len() {
            return Err(Halo2Error::operation_failed(
                "params::commit_lagrange",
                "length mismatch",
            ));
        }
        bases.push(self.w);
        msm_vesta(&coeffs, &bases)
    }
}

/// Scale a projective point by a scalar: `p * s` (`gProjective[i] *= minv`).
fn scale_projective(p: &VestaProjective, s: &PallasFp) -> Halo2Result<VestaAffine> {
    let q = p.mul_vartime(&VestaScalar::from_bytes_le(&s.to_le_bytes())?);
    let (x_le, y_le, ident) = q.to_affine_le()?;
    if ident {
        return Ok(VestaAffine::identity());
    }
    Ok(VestaAffine::from_le_xy(x_le, y_le)?)
}

pub fn basis_tag(_b: Basis) -> &'static str {
    "basis"
}
