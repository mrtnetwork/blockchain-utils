//! Chain-specific Groth16 proof / VK / public-input codecs (G3).
//!
//! | Chain   | Curve   | Proof layout                                      |
//! |---------|---------|---------------------------------------------------|
//! | Zcash   | BLS12   | compressed 48‖96‖48 = **192**                     |
//! | Sui     | BN254   | uncompressed 64‖128‖64 = **256**                  |
//! | Aptos   | BN254   | uncompressed 64‖128‖64 = **256** (same as Sui)    |
//! | Tezos   | BLS12*  | compressed 48‖96‖48 = **192** (Sapling-compatible)|
//!
//! \* Tezos zk-rollups historically use BLS12-381 Groth16-compatible layouts
//!    for some circuits; BN254 path also provided for Ethereum-aligned tools.

mod aptos;
mod sui;
mod tezos;
mod zcash;
mod zcash_params;

pub use aptos::{
    pack_public_inputs_aptos, unpack_public_inputs_aptos, AptosProofBytes, AptosVkBytes,
};
pub use sui::{pack_public_inputs_sui, unpack_public_inputs_sui, SuiProofBytes, SuiVkBytes};
pub use tezos::{
    pack_public_inputs_tezos, unpack_public_inputs_tezos, TezosProofBytes, TezosVkBytes,
};
pub use zcash::{
    pack_public_inputs_zcash, unpack_public_inputs_zcash, ZcashProofBytes, ZcashVkBytes,
};
pub use zcash_params::{BellmanVerifyingKey, ZcashParameters};
