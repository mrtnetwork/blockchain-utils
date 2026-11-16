//! R1CS gadget scaffolding for Sapling Spend (phase toward full circuit).
//!
//! Full boolean gadgets (3-bit lookup, Edwards add, Blake2s CS) are large; this
//! module provides:
//! 1. Documented constraint inventory matching the reference implementation
//! 2. A **public-input binding** R1CS: private copies of the 7 public Frs
//!    (same arity as production) for prove wiring tests
//! 3. Hooks where window/Pedersen/Blake gadgets will attach

use crate::curve::bls::Scalar;
use crate::zk::groth16::setup_from_r1cs_synthetic;
use crate::zk::groth16::{
    ConstraintBls, LinearCombinationBls, ProvingKeyBls as ProvingKey, R1csBls,
};
use crate::zk::sapling::spend::SPEND_NUM_PUBLIC;
use alloc::vec::Vec;

/// Inventory of major Spend circuit stages (reference order).
pub const SPEND_GADGET_STAGES: &[&str] = &[
    "witness_ak + small_order",
    "rk = ak + [ar]G  → inputize rk",
    "nk = [nsk]H",
    "ivk = BLAKE2s(Zcashivk, ak||nk)[0..255]",
    "g_d witness + small_order",
    "pk_d = [ivk] g_d",
    "exposeValueCommitment → inputize cv",
    "noteContents = value||g_d||pk_d (576 bits)",
    "cm = Pedersen(NoteCommitment) + [rcm]G_rcm",
    "Merkle path 32× Pedersen(MerkleTree(i))",
    "anchor enforce + inputize rt",
    "rho = cm + [pos]J",
    "nf = BLAKE2s(Zcash_nf, nk||rho) → multipack inputize",
];

/// Public-input binding circuit: `priv_i * 1 = pub_i` for i in 0..7.
///
/// Used until boolean gadgets are ported; keeps Groth16 arity correct.
pub fn spend_public_binding_circuit() -> R1csBls {
    let num_public = SPEND_NUM_PUBLIC;
    let num_variables = 1 + num_public * 2;
    let mut constraints = Vec::new();
    for i in 0..num_public {
        let pub_idx = 1 + i;
        let priv_idx = 1 + num_public + i;
        let mut a = LinearCombinationBls::new();
        a.add_term(priv_idx, Scalar::one());
        let mut b = LinearCombinationBls::new();
        b.add_term(0, Scalar::one());
        let mut c = LinearCombinationBls::new();
        c.add_term(pub_idx, Scalar::one());
        constraints.push(ConstraintBls { a, b, c });
    }
    R1csBls {
        num_public,
        num_variables,
        constraints,
    }
}

pub fn spend_public_binding_assignment(public: &[Scalar]) -> Vec<Scalar> {
    assert_eq!(public.len(), SPEND_NUM_PUBLIC);
    let mut z = Vec::with_capacity(1 + SPEND_NUM_PUBLIC * 2);
    z.push(Scalar::one());
    z.extend_from_slice(public);
    z.extend_from_slice(public);
    z
}

pub fn setup_spend_public_binding_synthetic() -> (ProvingKey, R1csBls) {
    let cs = spend_public_binding_circuit();
    let mut pk = setup_from_r1cs_synthetic(&cs);
    pk.clear_trapdoor();
    (pk, cs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::jubjub::JubJubPoint;
    use crate::curve::traits::CurvePoint;
    use crate::zk::groth16::{prove_bls_with_randomness, verify};
    use crate::zk::sapling::builder::spend_public_scalars_from_witness;
    use crate::zk::sapling::constants::{proof_generation_key_generator, spending_key_generator};
    use crate::zk::sapling::spend::{SpendWitness, SPEND_NUM_PUBLIC};

    fn point_bytes(p: &JubJubPoint) -> [u8; 32] {
        let mut b = [0u8; 32];
        p.to_bytes_compressed(&mut b).unwrap();
        b
    }

    #[test]
    fn gadget_stage_inventory_complete() {
        assert!(SPEND_GADGET_STAGES.len() >= 12);
    }

    #[test]
    fn binding_circuit_with_native_publics() {
        let mut w = SpendWitness::synthetic();
        w.ak = point_bytes(&proof_generation_key_generator());
        w.g_d = point_bytes(&spending_key_generator());
        w.pk_d = [0u8; 32];
        let public = spend_public_scalars_from_witness(&w).expect("native pi");
        assert_eq!(public.len(), SPEND_NUM_PUBLIC);
        let (pk, cs) = setup_spend_public_binding_synthetic();
        let z = spend_public_binding_assignment(&public);
        assert!(cs.is_satisfied(&z));
        let proof =
            prove_bls_with_randomness(&pk, &cs, &z, &Scalar::from_u64(3), &Scalar::from_u64(5))
                .expect("prove multi-row binding");
        verify(&pk.vk, &public, &proof).expect("verify multi-row binding");
    }
}
