//! Implements plonk/key logic — key structs + `VerifyingKey::build`.
//! `transcript_repr` is Blake2b-512 (`Halo2-Verify-Key`) over
//! `len(u64 LE) || debug_string`, pinned against the three known circuit
//! version hashes (mismatch → `Err`, never `assert!`).
//! Keygen entry points (need the Orchard circuit) land in the orchard pass.

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

use crate::zk::orchard_halo2::blake2b::Blake2b;
use crate::zk::orchard_halo2::curve::VestaAffine;
use crate::zk::orchard_halo2::error::{Halo2Error, Halo2Result};
use crate::zk::orchard_halo2::field::PallasFp;
use crate::zk::orchard_halo2::plonk::constraint::ConstraintSystem;
use crate::zk::orchard_halo2::plonk::permutation::{
    PermutationProvingKey, PermutationVerifyingKey,
};
use crate::zk::orchard_halo2::poly::domain::EvaluationDomain;
use crate::zk::orchard_halo2::poly::poly::Polynomial;
use crate::zk::orchard_halo2::transcript::transcript::TranscriptWriter;

pub const VERIFY_KEY_PERSONALIZATION: &[u8; 16] = b"Halo2-Verify-Key";

/// Known `transcript_repr` values (BE-hex) stored as LE bytes:
/// `FixedPostNu6_2`, `InsecurePreNu6_2`, `PostNu6_3`.
pub const KNOWN_REPR_FIXED_POST_NU6_2: [u8; 32] = [
    113, 82, 45, 211, 18, 56, 175, 61, 162, 46, 109, 154, 203, 236, 45, 3, 224, 254, 223, 38, 136,
    85, 60, 243, 190, 11, 190, 89, 143, 212, 247, 11,
];
pub const KNOWN_REPR_INSECURE_PRE_NU6_2: [u8; 32] = [
    25, 8, 109, 112, 193, 30, 250, 205, 153, 204, 186, 133, 145, 214, 202, 223, 2, 218, 36, 245,
    229, 162, 77, 125, 91, 87, 215, 2, 2, 87, 48, 21,
];
pub const KNOWN_REPR_POST_NU6_3: [u8; 32] = [
    153, 180, 250, 84, 41, 191, 31, 114, 187, 186, 156, 22, 32, 226, 1, 32, 98, 135, 210, 204, 99,
    115, 1, 45, 91, 185, 159, 237, 183, 247, 34, 5,
];

#[derive(Clone)]
pub struct PlonkVerifyingKey {
    pub domain: EvaluationDomain,
    pub fixed_commitments: Vec<VestaAffine>,
    pub permutation: PermutationVerifyingKey,
    pub cs: ConstraintSystem,
    pub cs_degree: usize,
    pub transcript_repr: PallasFp,
}

impl PlonkVerifyingKey {
    pub fn build(
        domain: EvaluationDomain,
        fixed_commitments: Vec<VestaAffine>,
        permutation: PermutationVerifyingKey,
        cs: ConstraintSystem,
    ) -> Halo2Result<Self> {
        let cs_degree = cs.degree()?;
        let mut key = Self {
            domain,
            fixed_commitments,
            permutation,
            cs,
            cs_degree,
            transcript_repr: PallasFp::zero(),
        };
        let debug = key.to_debug_string();
        let mut h = Blake2b::new(VERIFY_KEY_PERSONALIZATION)?;
        h.update(&(debug.len() as u64).to_le_bytes());
        h.update(debug.as_bytes());
        let digest = h.finalize();
        let sc = PallasFp::from_le_bytes64_wrapping(&digest)?;
        let le = sc.to_le_bytes();
        if le != KNOWN_REPR_FIXED_POST_NU6_2
            && le != KNOWN_REPR_INSECURE_PRE_NU6_2
            && le != KNOWN_REPR_POST_NU6_3
        {
            #[cfg(feature = "alloc")]
            {
                return Err(Halo2Error::with_message(
                    "keygen_vk::transcript_repr",
                    "unknown circuit version",
                    crate::zk::orchard_halo2::bytes::to_hex_be_prefixed_alloc(&le),
                ));
            }
            #[cfg(not(feature = "alloc"))]
            {
                return Err(Halo2Error::operation_failed(
                    "keygen_vk::transcript_repr",
                    "unknown circuit version",
                ));
            }
        }
        key.transcript_repr = sc;
        Ok(key)
    }

    #[cfg(feature = "alloc")]
    pub fn to_debug_string(&self) -> String {
        let fixed: Vec<String> = self
            .fixed_commitments
            .iter()
            .map(|e| {
                let (xb, yb) = match e.to_affine_le() {
                    Ok((x, y, _)) => (x, y),
                    Err(_) => ([0u8; 32], [0u8; 32]),
                };
                alloc::format!(
                    "({}, {})",
                    crate::zk::orchard_halo2::bytes::to_hex_be_prefixed_alloc(&xb),
                    crate::zk::orchard_halo2::bytes::to_hex_be_prefixed_alloc(&yb)
                )
            })
            .collect();
        alloc::format!(
            "PinnedVerificationKey {{ base_modulus: \"0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001\", scalar_modulus: \"0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001\", domain: {}, cs: {}, fixed_commitments: [{}], permutation: {} }}",
            self.domain.to_debug_string(),
            self.cs.to_debug_string(),
            fixed.join(", "),
            self.permutation.to_debug_string()
        )
    }

    pub fn hash_into(&self, transcript: &mut TranscriptWriter) -> Halo2Result<()> {
        transcript.absorb_scalar_le(&self.transcript_repr.to_le_bytes())
    }

    pub fn hash_into_transcript(
        &self,
        transcript: &mut crate::zk::orchard_halo2::transcript::transcript::TranscriptReader<'_>,
    ) -> Halo2Result<()> {
        transcript.absorb_scalar_le(&self.transcript_repr.to_le_bytes())
    }
}

#[derive(Clone)]
pub struct PlonkProvingKey {
    pub vk: PlonkVerifyingKey,
    pub l0: Polynomial<PallasFp>,
    pub l_blind: Polynomial<PallasFp>,
    pub l_last: Polynomial<PallasFp>,
    pub fixed_values: Vec<Polynomial<PallasFp>>,
    pub fixed_polys: Vec<Polynomial<PallasFp>>,
    pub fixed_cosets: Vec<Polynomial<PallasFp>>,
    pub permutation: PermutationProvingKey,
}

// —— key generation (needs the Orchard circuit; see orchard pass) ——

use crate::zk::orchard_halo2::crypto_context::DefaultCryptoContext;
use crate::zk::orchard_halo2::field::PallasFp as Fp2;
use crate::zk::orchard_halo2::floor_planner::v1::v1_synthesize;
use crate::zk::orchard_halo2::orchard::circuit::{OrchardCircuit, OrchardCircuitConfig};
use crate::zk::orchard_halo2::plonk::assignment::PlonkAssembly;
use crate::zk::orchard_halo2::plonk::permutation::PermutationAssembly;
use crate::zk::orchard_halo2::poly::params::PolyParams;

pub struct KeygenDomain {
    pub domain: EvaluationDomain,
    pub cs: ConstraintSystem,
    pub config: OrchardCircuitConfig,
}

pub fn create_domain(
    params: &PolyParams,
    context: &DefaultCryptoContext,
) -> Halo2Result<KeygenDomain> {
    let mut cs = ConstraintSystem::default_config();
    let config = OrchardCircuitConfig::configure(&mut cs, context)?;
    let degree = cs.degree()?;
    let domain = EvaluationDomain::new_domain(degree, params.k)?;
    Ok(KeygenDomain { domain, cs, config })
}

pub fn keygen_vk(
    circuit: &OrchardCircuit,
    context: &DefaultCryptoContext,
    _k: u32,
    params: &PolyParams,
) -> Halo2Result<PlonkVerifyingKey> {
    let KeygenDomain {
        domain,
        mut cs,
        config,
    } = create_domain(params, context)?;
    if params.n < cs.minimum_rows() {
        return Err(Halo2Error::operation_failed("keygen_vk", "not enough rows"));
    }
    let num_fixed = cs.num_fixed_columns();
    let num_selectors = cs.num_selectors();
    let blinding = cs.blinding_factors();
    let mut fixed = Vec::with_capacity(num_fixed);
    for _ in 0..num_fixed {
        fixed.push(domain.empty_lagrange_assigned());
    }
    let mut assembly = PlonkAssembly {
        k: params.k,
        fixed,
        permutation: PermutationAssembly::new_assembly(params.n, &cs.permutation),
        selectors: vec![vec![false; params.n]; num_selectors],
        usable_rows: crate::zk::orchard_halo2::plonk::assignment::UsableRows {
            start: 0,
            end: params.n - (blinding + 1),
        },
    };
    v1_synthesize(
        &mut assembly,
        circuit,
        &config,
        cs.constants.clone(),
        context,
    )?;
    let mut fixed_vals = Polynomial::batch_invert_assigned(&assembly.fixed)?;
    let selector_polys = cs.compress_selectors(assembly.selectors)?;
    for poly in selector_polys.into_iter() {
        fixed_vals.push(domain.lagrange_from_vec(poly)?);
    }
    let permutation_vk = assembly
        .permutation
        .build_vk(params, &domain, &cs.permutation)?;
    let mut fixed_commitments = Vec::with_capacity(fixed_vals.len());
    for poly in fixed_vals.iter() {
        let c = params.commit_lagrange(poly, Fp2::one())?;
        let (x, y, ident) = c.to_affine_le()?;
        fixed_commitments.push(if ident {
            VestaAffine::identity()
        } else {
            VestaAffine::from_le_xy(x, y)?
        });
    }
    PlonkVerifyingKey::build(domain, fixed_commitments, permutation_vk, cs)
}

pub fn keygen_pk(
    circuit: &OrchardCircuit,
    params: &PolyParams,
    vk: PlonkVerifyingKey,
    context: &DefaultCryptoContext,
) -> Halo2Result<PlonkProvingKey> {
    let mut cs = ConstraintSystem::default_config();
    let config = OrchardCircuitConfig::configure(&mut cs, context)?;
    if params.n < cs.minimum_rows() {
        return Err(Halo2Error::operation_failed("keygen_pk", "not enough rows"));
    }
    let num_fixed = cs.num_fixed_columns();
    let num_selectors = cs.num_selectors();
    let blinding = cs.blinding_factors();
    let mut fixed = Vec::with_capacity(num_fixed);
    for _ in 0..num_fixed {
        fixed.push(vk.domain.empty_lagrange_assigned());
    }
    let mut assembly = PlonkAssembly {
        k: params.k,
        fixed,
        permutation: PermutationAssembly::new_assembly(params.n, &cs.permutation),
        selectors: vec![vec![false; params.n]; num_selectors],
        usable_rows: crate::zk::orchard_halo2::plonk::assignment::UsableRows {
            start: 0,
            end: params.n - (blinding + 1),
        },
    };
    v1_synthesize(
        &mut assembly,
        circuit,
        &config,
        cs.constants.clone(),
        context,
    )?;
    let fixed_vals = Polynomial::batch_invert_assigned(&assembly.fixed)?;
    let mut with_selectors = fixed_vals;
    let selector_polys = cs.compress_selectors(assembly.selectors)?;
    for poly in selector_polys.into_iter() {
        with_selectors.push(vk.domain.lagrange_from_vec(poly)?);
    }
    let mut fixed_polys = Vec::with_capacity(with_selectors.len());
    for poly in with_selectors.iter() {
        fixed_polys.push(vk.domain.lagrange_to_coeff(poly.clone())?);
    }
    let mut fixed_cosets = Vec::with_capacity(fixed_polys.len());
    for poly in fixed_polys.iter() {
        fixed_cosets.push(vk.domain.coeff_to_extended(poly.clone())?);
    }
    let permutation = assembly
        .permutation
        .build_pk(params, &vk.domain, &cs.permutation)?;
    // l0 / lBlind / lLast (extended).
    let mut l0 = vk.domain.empty_lagrange();
    l0.values[0] = Fp2::one();
    let l0 = vk
        .domain
        .coeff_to_extended(vk.domain.lagrange_to_coeff(l0)?)?;
    let mut l_blind = vk.domain.empty_lagrange();
    for i in 0..blinding {
        let idx = l_blind.values.len() - 1 - i;
        l_blind.values[idx] = Fp2::one();
    }
    let l_blind = vk
        .domain
        .coeff_to_extended(vk.domain.lagrange_to_coeff(l_blind)?)?;
    let mut l_last = vk.domain.empty_lagrange();
    l_last.values[params.n - blinding - 1] = Fp2::one();
    let l_last = vk
        .domain
        .coeff_to_extended(vk.domain.lagrange_to_coeff(l_last)?)?;
    Ok(PlonkProvingKey {
        vk,
        l0,
        l_blind,
        l_last,
        fixed_values: with_selectors,
        fixed_polys,
        fixed_cosets,
        permutation,
    })
}
