//! Implements orchard prover and verifier logic.
//! Thin batch wrappers over `PlonkProver` / `PlonkVerifier`.

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

use crate::zk::orchard_halo2::crypto_context::DefaultCryptoContext;
use crate::zk::orchard_halo2::error::Halo2Result;
use crate::zk::orchard_halo2::field::PallasFp;
use crate::zk::orchard_halo2::orchard::circuit::{
    OrchardCircuit, OrchardCircuitConfig, OrchardProtocolVersion,
};
use crate::zk::orchard_halo2::plonk::key::{PlonkProvingKey, PlonkVerifyingKey};
use crate::zk::orchard_halo2::poly::params::PolyParams;
use crate::zk::orchard_halo2::proof::prover::PlonkProver;
use crate::zk::orchard_halo2::proof::verifier::PlonkVerifier;

pub struct OrchardBatchProofInputs {
    pub circuit: OrchardCircuit,
    pub instance: Vec<Vec<PallasFp>>,
}

pub struct OrchardBatchProofParams {
    pub args: Vec<OrchardBatchProofInputs>,
}

pub struct DefaultOrchardProver {
    pub prover: PlonkProver,
}

impl DefaultOrchardProver {
    pub fn build(
        context: &DefaultCryptoContext,
        version: OrchardProtocolVersion,
        k: u32,
    ) -> Halo2Result<Self> {
        Ok(Self {
            prover: PlonkProver::build(context, version, k)?,
        })
    }

    pub fn with_keys(
        params: PolyParams,
        pk: PlonkProvingKey,
        config: OrchardCircuitConfig,
        context: DefaultCryptoContext,
    ) -> Self {
        Self {
            prover: PlonkProver::with_keys(params, pk, config, context),
        }
    }

    pub fn to_verifier(&self) -> DefaultOrchardVerifier {
        DefaultOrchardVerifier {
            verifier: PlonkVerifier::with_keys(
                self.prover.params.clone(),
                self.prover.proving_key.vk.clone(),
            ),
        }
    }

    pub fn create_orchard_proof(
        &self,
        args: &OrchardBatchProofParams,
        rng: &mut dyn crate::zk::orchard_halo2::rng::BlindRng,
    ) -> Halo2Result<Vec<u8>> {
        let circuits: Vec<OrchardCircuit> = args.args.iter().map(|a| a.circuit.clone()).collect();
        let instances: Vec<Vec<Vec<PallasFp>>> =
            args.args.iter().map(|a| a.instance.clone()).collect();
        self.prover.create_proof(&circuits, &instances, rng)
    }

    #[cfg(feature = "alloc")]
    pub fn to_debug_string(&self) -> String {
        alloc::string::String::from("DefaultOrchardProver")
    }
}

pub struct OrchardBatchVerifyProofInputs {
    pub proof_bytes: Vec<u8>,
    pub instances: Vec<Vec<Vec<PallasFp>>>,
}

pub struct DefaultOrchardVerifier {
    pub verifier: PlonkVerifier,
}

impl DefaultOrchardVerifier {
    pub fn build(
        context: &DefaultCryptoContext,
        version: OrchardProtocolVersion,
        k: u32,
    ) -> Halo2Result<Self> {
        Ok(Self {
            verifier: PlonkVerifier::build(context, version, k)?,
        })
    }

    pub fn with_keys(params: PolyParams, vk: PlonkVerifyingKey) -> Self {
        Self {
            verifier: PlonkVerifier::with_keys(params, vk),
        }
    }

    pub fn verify_orchard_proof(&self, args: &OrchardBatchVerifyProofInputs) -> Halo2Result<bool> {
        self.verifier
            .verify_sync(&args.proof_bytes, &args.instances)
    }

    #[cfg(feature = "alloc")]
    pub fn to_debug_string(&self) -> String {
        alloc::string::String::from("DefaultOrchardVerifier")
    }
}
