//! Implements poly/domain logic (`EvaluationDomain`).
//! All `assert!` become `Halo2Result`. Debug via `format!` (BE `0x` omega).

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

use crate::zk::orchard_halo2::error::{Halo2Error, Halo2Result};
use crate::zk::orchard_halo2::field::PallasFp;
use crate::zk::orchard_halo2::plonk::assigned::{assigned_from_fp, Assigned};
use crate::zk::orchard_halo2::poly::poly::{Basis, Polynomial, Rotation};
use crate::zk::orchard_halo2::utility::utils::{batch_invert, best_fft_field};

pub const PASTA_S: u32 = 32;

#[derive(Clone)]
pub struct EvaluationDomain {
    pub n: usize,
    pub k: u32,
    pub extended_k: u32,
    pub omega: PallasFp,
    pub omega_inv: PallasFp,
    pub extended_omega: PallasFp,
    pub extended_omega_inv: PallasFp,
    pub g_coset: PallasFp,
    pub g_coset_inv: PallasFp,
    pub quotient_poly_degree: usize,
    pub ifft_divisor: PallasFp,
    pub extended_ifft_divisor: PallasFp,
    pub t_evaluations: Vec<PallasFp>,
    pub barycentric_weight: PallasFp,
}

impl EvaluationDomain {
    #[cfg(feature = "alloc")]
    pub fn to_debug_string(&self) -> String {
        alloc::format!(
            "PinnedEvaluationDomain {{ k: {}, extended_k: {}, omega: {} }}",
            self.k,
            self.extended_k,
            self.omega.to_debug_string()
        )
    }

    /// `newDomain(j, k)`: j = quotient degree + 1. No `assert!`.
    pub fn new_domain(j: usize, k: u32) -> Halo2Result<Self> {
        if j == 0 {
            return Err(Halo2Error::operation_failed("domain::new", "zero degree"));
        }
        if k >= 32 {
            return Err(Halo2Error::operation_failed("domain::new", "k too large"));
        }
        let quotient_poly_degree = j - 1;
        let n: usize = 1usize << k;
        let mut extended_k = k;
        while (1usize << extended_k) < n.saturating_mul(quotient_poly_degree.max(1)) {
            extended_k += 1;
            if extended_k >= PASTA_S {
                return Err(Halo2Error::operation_failed(
                    "domain::new",
                    "extended_k overflow",
                ));
            }
        }
        let mut extended_omega = PallasFp::root_of_unity();
        for _ in extended_k..PASTA_S {
            extended_omega = extended_omega.square_vartime();
        }
        let mut omega = extended_omega;
        for _ in k..extended_k {
            omega = omega.square_vartime();
        }
        let g_coset = PallasFp::zeta();
        let g_coset_inv = g_coset.square_vartime();
        // t evaluations: powers of extended_omega^e * zeta^n, minus one.
        let e = n as u64;
        let orig = pow_u64_field(PallasFp::zeta(), n as u64);
        let step = pow_u64_field(extended_omega, e);
        let mut t_evals: Vec<PallasFp> = Vec::new();
        let mut cur = orig;
        loop {
            t_evals.push(cur);
            cur = cur.mul_vartime(&step);
            if cur == orig {
                break;
            }
            if t_evals.len() > (1usize << (extended_k - k)) + 1 {
                return Err(Halo2Error::operation_failed(
                    "domain::new",
                    "t cycle overflow",
                ));
            }
        }
        if t_evals.len() != (1usize << (extended_k - k)) {
            return Err(Halo2Error::operation_failed(
                "domain::new",
                "t length mismatch",
            ));
        }
        for v in t_evals.iter_mut() {
            *v = v.sub_vartime(&PallasFp::one());
        }
        let t_len = t_evals.len();
        // Raw (non-inverted) auxiliaries; the batch inversion below inverts
        // everything exactly once, mirroring the reference (which pushes `from(1<<k)`
        // etc. and reads back the inverses).
        let ifft_raw = pow2_u64(k)?;
        let extended_ifft_raw = pow2_u64(extended_k)?;
        let barycentric_raw = PallasFp::from_u128_reduce(n as u128);
        let mut with_aux = t_evals.clone();
        with_aux.push(ifft_raw);
        with_aux.push(extended_ifft_raw);
        with_aux.push(barycentric_raw);
        with_aux.push(extended_omega);
        with_aux.push(omega);
        batch_invert(&mut with_aux)?;
        let omega_inv = with_aux[t_len + 4];
        let extended_omega_inv = with_aux[t_len + 3];
        Ok(Self {
            n,
            k,
            extended_k,
            omega,
            omega_inv,
            extended_omega,
            extended_omega_inv,
            g_coset,
            g_coset_inv,
            quotient_poly_degree,
            ifft_divisor: with_aux[t_len],
            extended_ifft_divisor: with_aux[t_len + 1],
            t_evaluations: with_aux[..t_len].to_vec(),
            barycentric_weight: with_aux[t_len + 2],
        })
    }

    pub fn extended_len(&self) -> usize {
        1usize << self.extended_k
    }

    pub fn empty_lagrange(&self) -> Polynomial<PallasFp> {
        Polynomial::new(vec![PallasFp::zero(); self.n], Basis::Lagrange)
    }

    pub fn empty_extended(&self) -> Polynomial<PallasFp> {
        Polynomial::new(vec![PallasFp::zero(); self.extended_len()], Basis::Extended)
    }

    pub fn empty_coeff(&self) -> Polynomial<PallasFp> {
        Polynomial::new(vec![PallasFp::zero(); self.n], Basis::Coeff)
    }

    pub fn empty_lagrange_assigned(&self) -> Polynomial<Assigned> {
        Polynomial::new(
            vec![Assigned::Trivial(PallasFp::zero()); self.n],
            Basis::Lagrange,
        )
    }

    pub fn lagrange_from_vec(&self, values: Vec<PallasFp>) -> Halo2Result<Polynomial<PallasFp>> {
        if values.len() != self.n {
            return Err(Halo2Error::operation_failed(
                "domain::lagrange_from_vec",
                "length mismatch",
            ));
        }
        Ok(Polynomial::new(values, Basis::Lagrange))
    }

    pub fn coeff_from_vec(&self, values: Vec<PallasFp>) -> Halo2Result<Polynomial<PallasFp>> {
        if values.len() != self.n {
            return Err(Halo2Error::operation_failed(
                "domain::coeff_from_vec",
                "length mismatch",
            ));
        }
        Ok(Polynomial::new(values, Basis::Coeff))
    }

    pub fn lagrange_to_coeff(
        &self,
        mut a: Polynomial<PallasFp>,
    ) -> Halo2Result<Polynomial<PallasFp>> {
        if a.values.len() != (1usize << self.k) {
            return Err(Halo2Error::operation_failed(
                "domain::lagrange_to_coeff",
                "length mismatch",
            ));
        }
        self.ifft(&mut a.values, self.omega_inv, self.k, self.ifft_divisor)?;
        a.basis = Basis::Coeff;
        Ok(a)
    }

    pub fn ifft(
        &self,
        a: &mut [PallasFp],
        omega_inv: PallasFp,
        log_n: u32,
        divisor: PallasFp,
    ) -> Halo2Result<()> {
        best_fft_field(a, omega_inv, log_n)?;
        for v in a.iter_mut() {
            *v = v.mul_vartime(&divisor);
        }
        Ok(())
    }

    pub fn distribute_powers_zeta(&self, a: &mut [PallasFp], into_coset: bool) {
        let pair = if into_coset {
            [self.g_coset, self.g_coset_inv]
        } else {
            [self.g_coset_inv, self.g_coset]
        };
        for (index, v) in a.iter_mut().enumerate() {
            match index % 3 {
                1 => *v = v.mul_vartime(&pair[0]),
                2 => *v = v.mul_vartime(&pair[1]),
                _ => {}
            }
        }
    }

    pub fn coeff_to_extended(
        &self,
        mut ax: Polynomial<PallasFp>,
    ) -> Halo2Result<Polynomial<PallasFp>> {
        if ax.values.len() != (1usize << self.k) {
            return Err(Halo2Error::operation_failed(
                "domain::coeff_to_extended",
                "length mismatch",
            ));
        }
        self.distribute_powers_zeta(&mut ax.values, true);
        let target = self.extended_len();
        if ax.values.len() < target {
            ax.values.resize(target, PallasFp::zero());
        } else {
            ax.values.truncate(target);
        }
        best_fft_field(&mut ax.values, self.extended_omega, self.extended_k)?;
        ax.basis = Basis::Extended;
        Ok(ax)
    }

    pub fn chunk_of_rotated_extended(
        &self,
        poly: &Polynomial<PallasFp>,
        rotation: Rotation,
        chunk_size: usize,
        chunk_index: usize,
    ) -> Halo2Result<Vec<PallasFp>> {
        let shift = (self.extended_k - self.k) as usize;
        let scaled = (1usize << shift)
            .checked_mul(rotation.location.unsigned_abs() as usize)
            .ok_or_else(|| Halo2Error::operation_failed("domain::chunk", "shift overflow"))?;
        poly.chunk_of_rotated(rotation.location < 0, scaled, chunk_size, chunk_index)
    }

    pub fn divide_by_vanishing_poly(
        &self,
        mut a: Polynomial<PallasFp>,
    ) -> Halo2Result<Polynomial<PallasFp>> {
        if a.values.len() != self.extended_len() {
            return Err(Halo2Error::operation_failed(
                "domain::divide",
                "length mismatch",
            ));
        }
        if self.t_evaluations.is_empty() {
            return Err(Halo2Error::operation_failed("domain::divide", "empty t"));
        }
        for (i, v) in a.values.iter_mut().enumerate() {
            let t = self.t_evaluations[i % self.t_evaluations.len()];
            *v = v.mul_vartime(&t);
        }
        Ok(a)
    }

    pub fn extended_to_coeff(&self, mut a: Polynomial<PallasFp>) -> Halo2Result<Vec<PallasFp>> {
        if a.values.len() != self.extended_len() {
            return Err(Halo2Error::operation_failed(
                "domain::extended_to_coeff",
                "length mismatch",
            ));
        }
        self.ifft(
            &mut a.values,
            self.extended_omega_inv,
            self.extended_k,
            self.extended_ifft_divisor,
        )?;
        self.distribute_powers_zeta(&mut a.values, false);
        let trunc = self.n.saturating_mul(self.quotient_poly_degree);
        a.values.truncate(trunc);
        Ok(a.values)
    }

    pub fn rotate_omega(&self, value: PallasFp, rotation: Rotation) -> PallasFp {
        if rotation.location >= 0 {
            value.mul_vartime(&pow_u64_field(self.omega, rotation.location as u64))
        } else {
            value.mul_vartime(&pow_u64_field(
                self.omega_inv,
                rotation.location.unsigned_abs() as u64,
            ))
        }
    }

    pub fn lagrange_range(
        &self,
        x: PallasFp,
        xn: PallasFp,
        rotations: &[i32],
    ) -> Halo2Result<Vec<PallasFp>> {
        let mut results: Vec<PallasFp> = Vec::with_capacity(rotations.len());
        for r in rotations {
            let rot = Rotation { location: *r };
            results.push(x.sub_vartime(&self.rotate_omega(PallasFp::one(), rot)));
        }
        batch_invert(&mut results)?;
        let common = xn
            .sub_vartime(&PallasFp::one())
            .mul_vartime(&self.barycentric_weight);
        for (i, r) in rotations.iter().enumerate() {
            let rot = Rotation { location: *r };
            results[i] = self.rotate_omega(results[i].mul_vartime(&common), rot);
        }
        Ok(results)
    }
}

fn pow_u64_field(base: PallasFp, mut e: u64) -> PallasFp {
    let mut acc = PallasFp::one();
    let mut b = base;
    while e > 0 {
        if (e & 1) == 1 {
            acc = acc.mul_vartime(&b);
        }
        b = b.square_vartime();
        e >>= 1;
    }
    acc
}

/// `2^k` as a field element (raw, non-inverted helper for domain setup).
fn pow2_u64(k: u32) -> Halo2Result<PallasFp> {
    if k >= 64 {
        return Err(Halo2Error::operation_failed("domain::pow2", "k too large"));
    }
    Ok(PallasFp::from_u64(1u64 << k))
}

pub fn assigned_trivial_vec(n: usize) -> Vec<Assigned> {
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        v.push(assigned_from_fp(PallasFp::zero()));
    }
    v
}
