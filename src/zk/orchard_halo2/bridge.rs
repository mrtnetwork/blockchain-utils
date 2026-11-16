//! Field-level Action bridge for FFI/WASM (external wire scheme).
//!
//! No wallet parsing lives here: Callers send circuit witness fields and
//! instance limbs; this module only decodes (range/on-curve checked),
//! enforces the version/flag rule, and drives prove/verify.
//!
//! Circuit blob (1716 bytes, LE, canonical encodings):
//! ```text
//! path[32][32] | pos u32 | gd_old[64] | pkd_old[64] | v_old u64 |
//! rho_old[32] | psi_old[32] | rcm_old[32] | cm_old[64] | alpha[32] |
//! ak[64] | nk[32] | rivk[32] | gd_new[64] | pkd_new[64] | v_new u64 |
//! psi_new[32] | rcm_new[32] | rcv[32]
//! ```
//! Points are `x || y` (32 bytes each). Scalars/fields are 32-byte LE.
//!
//! Instances: `10 x 32` bytes per action (single column, official layout:
//! anchor, cv_x, cv_y, nf, rk_x, rk_y, cmx, enable_spend, enable_output,
//! disable_cross_address). Row 9 rule: version 2 (NU6.3) requires row 9 to
//! equal the flag limb (`[flag, 0..]`); versions 0/1 require `flag == false`
//! and pass row 9 through (unconstrained pre-NU6.3).
//!
//! Versions: 0 = insecure (pre-NU6.2), 1 = fixed (post-NU6.2), 2 = NU6.3.
//! Errors are [`OrchardError`] codes only (no strings cross the boundary).

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::zk::orchard_halo2::curve::PallasAffine;
use crate::zk::orchard_halo2::error::OrchardError;
use crate::zk::orchard_halo2::field::{PallasFp, VestaFq};
use crate::zk::orchard_halo2::orchard::circuit::{OrchardCircuit, OrchardProtocolVersion};
use crate::zk::orchard_halo2::orchard::prover::{
    DefaultOrchardProver, OrchardBatchProofInputs, OrchardBatchProofParams,
};
use crate::zk::orchard_halo2::rng::ChaChaBlindRng;

/// Size of one packed circuit blob.
pub const CIRCUIT_BLOB_LEN: usize = 1716;
/// Instance limbs per action (single column).
pub const INSTANCE_LIMBS: usize = 10;
/// Instance bytes per action.
pub const INSTANCE_BLOB_LEN: usize = INSTANCE_LIMBS * 32;
/// Proof bytes (k = 11, one action batch).
pub const PROOF_LEN: usize = 4992;
/// Blinding seed bytes per prove call.
pub const SEED_LEN: usize = 32;
/// Domain parameter (shared by all versions).
pub const CIRCUIT_K: u32 = 11;

/// Wire version discriminant → circuit version.
pub fn parse_version(v: u32) -> Result<OrchardProtocolVersion, OrchardError> {
    match v {
        0 => Ok(OrchardProtocolVersion::InsecureV1),
        1 => Ok(OrchardProtocolVersion::V2),
        2 => Ok(OrchardProtocolVersion::V3),
        _ => Err(OrchardError::InvalidEncoding),
    }
}

/// Flag limb encoding: first byte 0/1, rest zero.
fn flag_limb(flag: bool) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0] = u8::from(flag);
    b
}

fn take<'a>(b: &'a [u8], n: usize, off: &mut usize) -> Result<&'a [u8], OrchardError> {
    let end = off.checked_add(n).ok_or(OrchardError::InvalidLength)?;
    let s = b.get(*off..end).ok_or(OrchardError::InvalidLength)?;
    *off = end;
    Ok(s)
}

fn u32le(b: &[u8]) -> Result<u32, OrchardError> {
    b.try_into()
        .map(u32::from_le_bytes)
        .map_err(|_| OrchardError::InvalidLength)
}

fn u64le(b: &[u8]) -> Result<u64, OrchardError> {
    b.try_into()
        .map(u64::from_le_bytes)
        .map_err(|_| OrchardError::InvalidLength)
}

fn fp_le(b: &[u8]) -> Result<PallasFp, OrchardError> {
    let a: &[u8; 32] = b.try_into().map_err(|_| OrchardError::InvalidLength)?;
    PallasFp::from_le_array(a).map_err(OrchardError::from)
}

fn fq_le(b: &[u8]) -> Result<VestaFq, OrchardError> {
    let a: &[u8; 32] = b.try_into().map_err(|_| OrchardError::InvalidLength)?;
    VestaFq::from_le_array(a).map_err(OrchardError::from)
}

fn pt_xy(b: &[u8]) -> Result<PallasAffine, OrchardError> {
    if b.len() != 64 {
        return Err(OrchardError::InvalidLength);
    }
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(&b[..32]);
    y.copy_from_slice(&b[32..]);
    PallasAffine::from_le_xy(x, y).map_err(OrchardError::from)
}

/// Decode one 1716-byte circuit blob (all witness fields `Some`).
pub fn parse_circuit(
    blob: &[u8],
    version: OrchardProtocolVersion,
) -> Result<OrchardCircuit, OrchardError> {
    if blob.len() != CIRCUIT_BLOB_LEN {
        return Err(OrchardError::InvalidLength);
    }
    let mut o = 0usize;
    let path_raw = take(blob, 1024, &mut o)?;
    let mut path = Vec::with_capacity(32);
    for i in 0..32 {
        path.push(fp_le(&path_raw[i * 32..(i + 1) * 32])?);
    }
    let pos = u32le(take(blob, 4, &mut o)?)? as usize;
    let gd_old = pt_xy(take(blob, 64, &mut o)?)?;
    let pkd_old = pt_xy(take(blob, 64, &mut o)?)?;
    let v_old = u64le(take(blob, 8, &mut o)?)?;
    let rho_old = fp_le(take(blob, 32, &mut o)?)?;
    let psi_old = fp_le(take(blob, 32, &mut o)?)?;
    let rcm_old = fq_le(take(blob, 32, &mut o)?)?;
    let cm_old = pt_xy(take(blob, 64, &mut o)?)?;
    let alpha = fq_le(take(blob, 32, &mut o)?)?;
    let ak = pt_xy(take(blob, 64, &mut o)?)?;
    let nk = fp_le(take(blob, 32, &mut o)?)?;
    let rivk = fq_le(take(blob, 32, &mut o)?)?;
    let gd_new = pt_xy(take(blob, 64, &mut o)?)?;
    let pkd_new = pt_xy(take(blob, 64, &mut o)?)?;
    let v_new = u64le(take(blob, 8, &mut o)?)?;
    let psi_new = fp_le(take(blob, 32, &mut o)?)?;
    let rcm_new = fq_le(take(blob, 32, &mut o)?)?;
    let rcv = fq_le(take(blob, 32, &mut o)?)?;
    if o != CIRCUIT_BLOB_LEN {
        return Err(OrchardError::Internal);
    }
    Ok(OrchardCircuit {
        path: Some(path),
        pos: Some(pos),
        gd_old: Some(gd_old),
        pkd_old: Some(pkd_old),
        v_old: Some(v_old),
        rho_old: Some(rho_old),
        psi_old: Some(psi_old),
        rcm_old: Some(rcm_old),
        cm_old: Some(cm_old),
        alpha: Some(alpha),
        ak: Some(ak),
        nk: Some(nk),
        rivk: Some(rivk),
        gd_new: Some(gd_new),
        pkd_new: Some(pkd_new),
        v_new: Some(v_new),
        psi_new: Some(psi_new),
        rcm_new: Some(rcm_new),
        rcv: Some(rcv),
        version,
    })
}

/// Decode `n * 320` instance bytes into per-action single columns,
/// enforcing the row-9 flag rule for `version`.
pub fn parse_instances(
    bytes: &[u8],
    version: OrchardProtocolVersion,
    disable_cross_address: bool,
) -> Result<Vec<Vec<PallasFp>>, OrchardError> {
    if !bytes.len().is_multiple_of(INSTANCE_BLOB_LEN) || bytes.is_empty() {
        return Err(OrchardError::InvalidLength);
    }
    if disable_cross_address && version != OrchardProtocolVersion::V3 {
        return Err(OrchardError::InvalidEncoding);
    }
    let want_flag = flag_limb(disable_cross_address);
    let mut out = Vec::with_capacity(bytes.len() / INSTANCE_BLOB_LEN);
    for action in bytes.chunks(INSTANCE_BLOB_LEN) {
        let mut col = Vec::with_capacity(INSTANCE_LIMBS);
        for i in 0..INSTANCE_LIMBS {
            col.push(fp_le(&action[i * 32..(i + 1) * 32])?);
        }
        if version == OrchardProtocolVersion::V3 {
            let mut row9 = [0u8; 32];
            row9.copy_from_slice(&action[9 * 32..10 * 32]);
            if row9 != want_flag {
                return Err(OrchardError::InvalidEncoding);
            }
        }
        out.push(col);
    }
    Ok(out)
}

/// Build a prover (params + keys) for `version`. Expensive: cache per version.
pub fn build_prover(version: OrchardProtocolVersion) -> Result<DefaultOrchardProver, OrchardError> {
    use crate::zk::orchard_halo2::crypto_context::DefaultCryptoContext;
    DefaultOrchardProver::build(&DefaultCryptoContext, version, CIRCUIT_K)
        .map_err(|_| OrchardError::Internal)
}

/// Prove N actions. `circuits` = concatenated 1716-byte blobs.
pub fn create_proof(
    prover: &DefaultOrchardProver,
    circuits_blob: &[u8],
    seed: &[u8; SEED_LEN],
    version: OrchardProtocolVersion,
    instances: Vec<Vec<PallasFp>>,
) -> Result<Vec<u8>, OrchardError> {
    if !circuits_blob.len().is_multiple_of(CIRCUIT_BLOB_LEN) || circuits_blob.is_empty() {
        return Err(OrchardError::InvalidLength);
    }
    let n = circuits_blob.len() / CIRCUIT_BLOB_LEN;
    if instances.len() != n {
        return Err(OrchardError::InvalidLength);
    }
    let mut args = Vec::with_capacity(n);
    for (i, chunk) in circuits_blob.chunks(CIRCUIT_BLOB_LEN).enumerate() {
        let circuit = parse_circuit(chunk, version)?;
        let inst = instances.get(i).ok_or(OrchardError::InvalidLength)?.clone();
        args.push(OrchardBatchProofInputs {
            circuit,
            instance: vec![inst],
        });
    }
    let mut rng = ChaChaBlindRng::from_seed(seed);
    prover
        .create_orchard_proof(&OrchardBatchProofParams { args }, &mut rng)
        .map_err(|_| OrchardError::ProveFailed)
}

/// Verify a proof against per-action single-column instances.
pub fn verify_proof(
    prover: &DefaultOrchardProver,
    proof: &[u8],
    instances: &[Vec<PallasFp>],
) -> Result<bool, OrchardError> {
    use crate::zk::orchard_halo2::proof::verifier::PlonkVerifier;
    // A proof covers a whole batch of actions, and the transcript grows with
    // the batch, so the proof length is not fixed: it is only bounded from
    // below by the single-action size. The verifier checks that the proof is
    // consumed exactly, which validates its real length.
    if proof.len() < PROOF_LEN {
        return Err(OrchardError::InvalidLength);
    }
    let v = PlonkVerifier::with_keys(
        prover.prover.params.clone(),
        prover.prover.proving_key.vk.clone(),
    );
    // Instance layout: one proof per action, and the Orchard circuit has a
    // single instance column holding the 10 public values of that action
    // (one per row). So each action becomes one proof with one column.
    let inst3: Vec<Vec<Vec<PallasFp>>> = instances
        .iter()
        .map(|action| vec![action.clone()])
        .collect();
    v.verify_sync(proof, &inst3)
        .map_err(|_| OrchardError::Internal)
}
