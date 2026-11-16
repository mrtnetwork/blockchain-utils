//! C ABI exports.

pub mod bls;
pub mod curve;
#[cfg(feature = "alloc")]
pub mod ff1;
pub mod hash;
pub mod kdf;
pub mod mldsa;
mod reddsa;
pub mod signature;
pub mod x25519;
pub use reddsa::{
    bu_reddsa_jubjub_auth_pk, bu_reddsa_jubjub_auth_sign, bu_reddsa_jubjub_auth_verify,
    bu_reddsa_jubjub_binding_pk, bu_reddsa_jubjub_binding_sign, bu_reddsa_jubjub_binding_verify,
    bu_reddsa_pallas_auth_pk, bu_reddsa_pallas_auth_sign, bu_reddsa_pallas_auth_verify,
    bu_reddsa_pallas_binding_pk, bu_reddsa_pallas_binding_sign, bu_reddsa_pallas_binding_verify,
};
#[cfg(all(feature = "ffi", feature = "hw"))]
pub mod hw;
pub mod musig2;
#[cfg(all(feature = "ffi", feature = "alloc"))]
pub mod frost;
#[cfg(all(feature = "ffi", feature = "alloc"))]
pub mod dkls23;
#[cfg(all(feature = "ffi", feature = "alloc"))]
pub use musig2::{
    bu_musig2_key_agg, bu_musig2_key_agg_tweak, bu_musig2_nonce_agg, bu_musig2_nonce_gen,
    bu_musig2_partial_sig_agg, bu_musig2_partial_sig_verify, bu_musig2_partial_sign,
};
#[cfg(all(feature = "ffi", feature = "alloc"))]
pub use frost::{
    bu_frost_ed_aggregate, bu_frost_ed_binding_factors, bu_frost_ed_combine, bu_frost_ed_commit,
    bu_frost_ed_group_commitment, bu_frost_ed_group_info, bu_frost_ed_shard, bu_frost_ed_sign,
    bu_frost_ed_verify, bu_frost_ed_verify_share, bu_frost_ed_vss_commit, bu_frost_ed_vss_verify,
    bu_frost_k1_aggregate, bu_frost_k1_binding_factors, bu_frost_k1_combine, bu_frost_k1_commit,
    bu_frost_k1_group_commitment, bu_frost_k1_group_info, bu_frost_k1_shard, bu_frost_k1_sign,
    bu_frost_k1_verify, bu_frost_k1_verify_share, bu_frost_k1_vss_commit, bu_frost_k1_vss_verify,
    BU_FROST_ERR, BU_FROST_ERR_KEY, BU_FROST_ERR_LEN, BU_FROST_ERR_VERIFY, BU_FROST_OK,
};
#[cfg(all(feature = "ffi", feature = "alloc"))]
pub use dkls23::{
    bu_dkls23_agg_keys, bu_dkls23_dkg, bu_dkls23_import_secrets, bu_dkls23_refresh, bu_dkls23_sign,
    bu_dkls23_verify, bu_dkls23_x_only, BU_DKLS23_ERR, BU_DKLS23_ERR_KEY, BU_DKLS23_ERR_LEN,
    BU_DKLS23_ERR_VERIFY, BU_DKLS23_OK,
};
pub mod aead;
pub mod cipher;
pub mod rng;
pub mod schnorrkel;
pub mod transcript;
pub mod zkcodes;

#[cfg(feature = "groth16")]
pub mod groth16;
#[cfg(all(
    feature = "ffi",
    any(feature = "orchard-halo2", feature = "zcash-halo2")
))]
pub mod orchard;
#[cfg(all(
    feature = "ffi",
    any(feature = "zcash-sapling", feature = "groth16-prover")
))]
pub mod sapling;

#[cfg(all(
    feature = "ffi",
    any(
        feature = "zcash-incrementalmerkle",
        all(feature = "groth16-prover", feature = "orchard-halo2")
    )
))]
pub mod merkle;
#[cfg(all(feature = "ffi", feature = "monero"))]
pub mod monero;
#[cfg(all(feature = "ffi", feature = "solana-zk"))]
pub mod solana_zk;
#[cfg(all(feature = "ffi", feature = "monero"))]
pub use monero::{
    bu_monero_bp_plus_prove_amounts, bu_monero_bp_plus_prove_scalars, bu_monero_bp_plus_verify,
    bu_monero_unlock_batch, BU_MONERO_ERR_CRYPTO, BU_MONERO_ERR_INTERNAL, BU_MONERO_ERR_LENGTH,
    BU_MONERO_ERR_NULL, BU_MONERO_ERR_PARSE, BU_MONERO_INVALID, BU_MONERO_OK,
    BU_MONERO_UNLOCK_RECORD_LEN,
};
#[cfg(all(feature = "ffi", feature = "solana-zk"))]
pub use solana_zk::{
    bu_solana_zk_ae_decrypt, bu_solana_zk_ae_encrypt, bu_solana_zk_decrypt_u32,
    bu_solana_zk_encrypt_with, bu_solana_zk_prove_batched_range,
    bu_solana_zk_prove_batched_grouped_validity_2,
    bu_solana_zk_prove_batched_grouped_validity_3,
    bu_solana_zk_prove_ciphertext_equality, bu_solana_zk_prove_equality,
    bu_solana_zk_prove_grouped_validity_2, bu_solana_zk_prove_grouped_validity_3,
    bu_solana_zk_prove_percentage_with_cap, bu_solana_zk_prove_pubkey_validity,
    bu_solana_zk_prove_transfer, bu_solana_zk_prove_transfer_with_fee,
    bu_solana_zk_prove_withdraw,
    bu_solana_zk_prove_zero_ciphertext, bu_solana_zk_pubkey_from_secret,
    bu_solana_zk_validate_ae, bu_solana_zk_validate_ciphertext,
    bu_solana_zk_validate_pubkey, bu_solana_zk_verify_batched_grouped_validity_2,
    bu_solana_zk_verify_batched_grouped_validity_3, bu_solana_zk_verify_batched_range,
    bu_solana_zk_verify_ciphertext_equality,
    bu_solana_zk_verify_equality, bu_solana_zk_verify_grouped_validity_2,
    bu_solana_zk_verify_grouped_validity_3, bu_solana_zk_verify_percentage_with_cap,
    bu_solana_zk_verify_pubkey_validity, bu_solana_zk_verify_zero_ciphertext,
    BU_SOLANA_ZK_ERR_BACKEND, BU_SOLANA_ZK_ERR_CRYPTO, BU_SOLANA_ZK_ERR_INTERNAL,
    BU_SOLANA_ZK_ERR_LENGTH, BU_SOLANA_ZK_ERR_NULL, BU_SOLANA_ZK_ERR_PARSE, BU_SOLANA_ZK_OK,
};
#[cfg(all(feature = "ffi", feature = "orchard-halo2"))]
pub use orchard::{
    bu_orchard_create_proof, bu_orchard_pk_free, bu_orchard_pk_new_for_version,
    bu_orchard_verify_proof, BU_ORCHARD_ERR_INTERNAL, BU_ORCHARD_ERR_LENGTH, BU_ORCHARD_ERR_NULL,
    BU_ORCHARD_ERR_PARSE, BU_ORCHARD_ERR_PROVE, BU_ORCHARD_ERR_VERIFY, BU_ORCHARD_INPUT_LEN,
    BU_ORCHARD_INSTANCE_LEN, BU_ORCHARD_OK, BU_ORCHARD_PROOF_LEN, BU_ORCHARD_SEED_LEN,
};

#[cfg(all(
    feature = "ffi",
    any(
        feature = "zcash-incrementalmerkle",
        all(feature = "groth16-prover", feature = "orchard-halo2")
    )
))]
pub use merkle::{
    bu_merkle_checkpoint, bu_merkle_close_context, bu_merkle_create_context,
    bu_merkle_create_witness, bu_merkle_get_context, bu_merkle_insert_chain_state,
    bu_merkle_merge_state, bu_merkle_update_state, bu_merkle_update_subtree,
};

pub use hash::{
    bu_hash_algo, bu_hash_block_size, bu_hash_clean, bu_hash_digest_len, bu_hash_finish,
    bu_hash_finish_n, bu_hash_free, bu_hash_free_state, bu_hash_new, bu_hash_new_simple,
    bu_hash_reset, bu_hash_restore_state, bu_hash_save_state, bu_hash_update, bu_pedersen_hash,
    bu_pedersen_hash_bitstring, bu_poseidon_hash, bu_poseidon_hash_two, bu_poseidon_permute,
    bu_sinsemilla_commit, bu_sinsemilla_hash_bits, bu_sinsemilla_hash_bitstring,
    bu_sinsemilla_short_commit, BuHash, BuHashConfig, BuHashState, BU_HASH_BLAKE2B,
    BU_HASH_BLAKE2S, BU_HASH_FLAG_HMAC, BU_HASH_KECCAK224, BU_HASH_KECCAK256, BU_HASH_KECCAK384,
    BU_HASH_KECCAK512, BU_HASH_MAX_DIGEST, BU_HASH_MAX_XOF, BU_HASH_MD4, BU_HASH_MD5,
    BU_HASH_RIPEMD128, BU_HASH_RIPEMD160, BU_HASH_RIPEMD256, BU_HASH_RIPEMD320, BU_HASH_SHA1,
    BU_HASH_SHA224, BU_HASH_SHA256, BU_HASH_SHA384, BU_HASH_SHA3_224, BU_HASH_SHA3_256,
    BU_HASH_SHA3_384, BU_HASH_SHA3_512, BU_HASH_SHA512, BU_HASH_SHA512_256, BU_HASH_SHAKE128,
    BU_HASH_SHAKE256, BU_HASH_XXH32, BU_HASH_XXH3_128, BU_HASH_XXH3_256, BU_HASH_XXH3_64,
    BU_HASH_XXH64, BU_PEDERSEN_MERKLE_TREE, BU_PEDERSEN_NOTE_COMMITMENT, BU_ZCASH_ERR_BUFFER,
    BU_ZCASH_ERR_DOMAIN, BU_ZCASH_ERR_INTERNAL, BU_ZCASH_ERR_INVALID_INPUT, BU_ZCASH_ERR_NULL,
    BU_ZCASH_OK,
};

pub use kdf::{
    bu_hkdf, bu_pbkdf2, bu_scrypt, BU_HKDF_SHA256, BU_HKDF_SHA512, BU_PBKDF2_SHA256,
    BU_PBKDF2_SHA512,
};

pub use curve::{
    bu_bls_hash_to_g1, bu_bls_hash_to_g2, bu_curve_add, bu_curve_compress,
    bu_curve_generate_secret, bu_curve_generator, bu_curve_identity, bu_curve_is_infinity,
    bu_curve_mul, bu_curve_mul_add, bu_curve_mul_base, bu_curve_neg, bu_curve_point_len,
    bu_curve_point_len_uncomp, bu_curve_sc_add, bu_curve_sc_check, bu_curve_sc_mul,
    bu_curve_sc_neg, bu_curve_sc_reduce, bu_curve_sc_sub, bu_curve_scalar_len, bu_curve_sub,
    bu_curve_uncompress, bu_ed25519_from_fe_bytes, bu_ed25519_from_fe_bytes_clear_cofactor,
    bu_ed25519_sc_reduce32, bu_ed25519_sc_reduce64, bu_jubjub_sc_reduce64, bu_pallas_hash_to_curve,
    bu_pallas_hash_to_curve_pasta, bu_pallas_sc_reduce64, bu_vesta_hash_to_curve,
    bu_vesta_sc_reduce64, BU_CURVE_BLS12_G1, BU_CURVE_BLS12_G2, BU_CURVE_ED25519,
    BU_CURVE_ERR_BUFFER, BU_CURVE_ERR_INVALID_CURVE, BU_CURVE_ERR_INVALID_POINT,
    BU_CURVE_ERR_INVALID_SCALAR, BU_CURVE_ERR_NULL, BU_CURVE_ERR_UNSUPPORTED, BU_CURVE_JUBJUB,
    BU_CURVE_OK, BU_CURVE_PALLAS, BU_CURVE_RISTRETTO, BU_CURVE_SECP256K1, BU_CURVE_SECP256R1,
    BU_CURVE_VESTA,
};

pub use x25519::{
    bu_ed25519_pk_to_x25519, bu_ed25519_seed_to_x25519, bu_x25519, bu_x25519_dh, bu_x25519_dh_raw,
    bu_x25519_public_key, BU_X25519_ERR_BUFFER, BU_X25519_ERR_INVALID, BU_X25519_ERR_NULL,
    BU_X25519_OK,
};

#[cfg(feature = "alloc")]
pub use ff1::{
    bu_ff1_decrypt, bu_ff1_decrypt_binary, bu_ff1_encrypt, bu_ff1_encrypt_binary,
    BU_FF1_ERR_BUFFER, BU_FF1_ERR_INVALID, BU_FF1_ERR_LENGTH, BU_FF1_ERR_NULL, BU_FF1_ERR_RADIX,
    BU_FF1_OK,
};

pub use signature::{
    bu_ecdsa_k1_public_key, bu_ecdsa_k1_recover, bu_ecdsa_k1_recover_any, bu_ecdsa_k1_sign,
    bu_ecdsa_k1_sign_ex, bu_ecdsa_k1_verify, bu_ecdsa_r1_public_key, bu_ecdsa_r1_recover,
    bu_ecdsa_r1_recovery_id, bu_ecdsa_r1_sign, bu_ecdsa_r1_sign_ex, bu_ecdsa_r1_verify,
    bu_ed25519_public_key, bu_ed25519_public_key_variant, bu_ed25519_sign, bu_ed25519_sign_variant,
    bu_ed25519_verify, bu_ed25519_verify_variant, bu_schnorr_bch_sign, bu_schnorr_bch_verify,
    bu_schnorr_public_key, bu_schnorr_sign, bu_schnorr_sign_aux, bu_schnorr_tweak_public,
    bu_schnorr_tweak_secret, bu_schnorr_verify, BU_SIG_ERR_BUFFER, BU_SIG_ERR_INTERNAL,
    BU_SIG_ERR_INVALID_PK, BU_SIG_ERR_INVALID_SIG, BU_SIG_ERR_INVALID_SK, BU_SIG_ERR_NULL,
    BU_SIG_ERR_VERIFY, BU_SIG_OK,
};

pub use schnorrkel::{
    bu_sr25519_derive_public, bu_sr25519_dleq_prove, bu_sr25519_dleq_verify,
    bu_sr25519_hard_derive, bu_sr25519_is_valid_public_key, bu_sr25519_is_valid_secret_key,
    bu_sr25519_public_key, bu_sr25519_public_key_from_secret, bu_sr25519_secret_from_seed,
    bu_sr25519_sign, bu_sr25519_soft_derive, bu_sr25519_to_ed25519_bytes, bu_sr25519_verify,
    bu_sr25519_vrf_hash, bu_sr25519_vrf_in_out, bu_sr25519_vrf_sign, bu_sr25519_vrf_verify,
    BU_SR25519_ERR_INVALID, BU_SR25519_ERR_LEN, BU_SR25519_ERR_NULL, BU_SR25519_ERR_VERIFY,
    BU_SR25519_OK,
};

pub use aead::{
    bu_aes_gcm_decrypt, bu_aes_gcm_encrypt, bu_chacha20poly1305_decrypt,
    bu_chacha20poly1305_encrypt, bu_salsabox_beforenm, bu_salsabox_decrypt, bu_salsabox_encrypt,
    bu_xsalsa20poly1305_decrypt, bu_xsalsa20poly1305_encrypt, BU_AEAD_ERR_AUTH, BU_AEAD_ERR_BUFFER,
    BU_AEAD_ERR_INTERNAL, BU_AEAD_ERR_KEY, BU_AEAD_ERR_NONCE, BU_AEAD_ERR_NULL, BU_AEAD_OK,
};

pub use rng::{bu_rng_fill, bu_rng_is_seeded, bu_rng_seed};

#[cfg(feature = "groth16")]
pub use groth16::{
    bu_groth16_bls_proof_len, bu_groth16_bn254_proof_len, bu_groth16_verify_bls,
    bu_groth16_verify_bn254, BU_G16_ERR_ENCODING, BU_G16_ERR_INPUTS, BU_G16_ERR_INTERNAL,
    BU_G16_ERR_LENGTH, BU_G16_ERR_NULL, BU_G16_ERR_VERIFY, BU_G16_OK,
};
#[cfg(all(
    feature = "ffi",
    any(feature = "zcash-sapling", feature = "groth16-prover")
))]
pub use sapling::{
    bu_sapling_params_free, bu_sapling_prove, bu_sapling_set_output_params,
    bu_sapling_set_spend_params, bu_sapling_verify, BuSaplingParams, BU_SAPLING_ERR_INTERNAL,
    BU_SAPLING_ERR_KIND, BU_SAPLING_ERR_LENGTH, BU_SAPLING_ERR_NULL, BU_SAPLING_ERR_PARSE,
    BU_SAPLING_ERR_PROVE, BU_SAPLING_ERR_VERIFY, BU_SAPLING_OK, BU_SAPLING_OUTPUT_INPUT_LEN,
    BU_SAPLING_SPEND_INPUT_LEN,
};

pub use transcript::{
    bu_merlin_append, bu_merlin_challenge, bu_merlin_fork, bu_merlin_free, bu_merlin_new,
    bu_strobe_ad, bu_strobe_free, bu_strobe_key, bu_strobe_new, bu_strobe_prf, BuMerlin, BuStrobe,
    BU_TR_ERR_BUFFER, BU_TR_ERR_NULL, BU_TR_OK,
};
pub use zkcodes::{
    bu_build_features, bu_build_version, bu_zk_enable_logging, bu_zk_version, ZK_API_VERSION,
    ZK_ERR_ENCODING, ZK_ERR_HASH, ZK_ERR_INPUT, ZK_ERR_INTERNAL, ZK_ERR_KEY, ZK_ERR_MERKLE,
    ZK_ERR_MISSING, ZK_ERR_PROOF, ZK_ERR_WITNESS, ZK_OK,
};

/// Allocate `size` zeroed bytes for WASM/JS callers. Free with [`bu_free`].
///
/// Layout: `[usize: capacity][payload...]`. Callers only use the payload pointer.
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_malloc(size: usize) -> *mut u8 {
    if size == 0 {
        return core::ptr::null_mut();
    }
    let mut v = alloc::vec::Vec::<u8>::with_capacity(size + core::mem::size_of::<usize>());
    let cap = size;
    v.extend_from_slice(&cap.to_ne_bytes());
    v.resize(core::mem::size_of::<usize>() + size, 0);
    let ptr = v.as_mut_ptr();
    core::mem::forget(v);
    // return payload start
    ptr.add(core::mem::size_of::<usize>())
}

/// Free a buffer returned by [`bu_malloc`].
#[no_mangle]
/// # Safety
/// Pointer arguments must be non-null and address readable/writable
/// memory of at least the documented lengths. Null pointers are
/// rejected with an error code; short or invalid buffers are the
/// caller’s responsibility.
pub unsafe extern "C" fn bu_free(ptr: *mut u8, _size: usize) {
    if ptr.is_null() {
        return;
    }
    let header = ptr.sub(core::mem::size_of::<usize>());
    let mut len_bytes = [0u8; core::mem::size_of::<usize>()];
    core::ptr::copy_nonoverlapping(
        header,
        len_bytes.as_mut_ptr(),
        core::mem::size_of::<usize>(),
    );
    let payload_len = usize::from_ne_bytes(len_bytes);
    let total = core::mem::size_of::<usize>() + payload_len;
    let _ = alloc::vec::Vec::from_raw_parts(header, total, total);
}

pub use cipher::{
    bu_aes_block_size, bu_aes_cbc_decrypt, bu_aes_cbc_encrypt, bu_aes_ctr, bu_aes_decrypt_block,
    bu_aes_ecb_decrypt, bu_aes_ecb_decrypt_padded, bu_aes_ecb_encrypt, bu_aes_ecb_encrypt_padded,
    bu_aes_encrypt_block, bu_aes_free, bu_aes_new, bu_chacha20_stream_xor, bu_chacha20_xor,
    bu_keccak_f1600, BuAes, BU_CIPHER_ERR_IV, BU_CIPHER_ERR_KEY, BU_CIPHER_ERR_LEN,
    BU_CIPHER_ERR_NULL, BU_CIPHER_OK,
};

#[cfg(all(feature = "ffi", feature = "hw"))]
pub use hw::{
    bu_hw_bitbox_btc_pub_request, bu_hw_bitbox_decrypt, bu_hw_bitbox_encrypt, bu_hw_bitbox_free,
    bu_hw_bitbox_hs_hash, bu_hw_bitbox_hs_m1, bu_hw_bitbox_hs_m2, bu_hw_bitbox_hs_m3,
    bu_hw_bitbox_hs_new, bu_hw_bitbox_hs_split, bu_hw_bitbox_pub_parse, bu_hw_bitbox_sign_change,
    bu_hw_bitbox_sign_init, bu_hw_bitbox_sign_input, bu_hw_bitbox_sign_next_parse,
    bu_hw_bitbox_sign_next_prev_index, bu_hw_bitbox_sign_next_signature, bu_hw_bitbox_sign_output,
    bu_hw_bitbox_sign_prevtx_init, bu_hw_bitbox_sign_prevtx_input, bu_hw_bitbox_sign_prevtx_output,
    bu_hw_coin_count, bu_hw_device_count, bu_hw_get_address_request, bu_hw_hid_frame,
    bu_hw_hid_unframe, bu_hw_identity_encode, bu_hw_is_airgap, bu_hw_ledger_fingerprint_parse,
    bu_hw_ledger_fingerprint_request, bu_hw_parse_address_response, bu_hw_parse_path,
    bu_hw_parse_sign_response, bu_hw_parse_tx_request, bu_hw_psbt_counts, bu_hw_qr_parse,
    bu_hw_qr_request, bu_hw_sign_identity_request, bu_hw_sign_request, bu_hw_sign_tx_start,
    bu_hw_signed_identity_address, bu_hw_signed_identity_pubkey, bu_hw_signed_identity_signature,
    bu_hw_supports_coin, bu_hw_tx_ack_bin_output, bu_hw_tx_ack_change, bu_hw_tx_ack_input,
    bu_hw_tx_ack_meta, bu_hw_tx_ack_output, bu_hw_tx_request_serialized,
    bu_hw_tx_request_signature, bu_hw_tx_request_txhash, bu_hw_ur_decode_payload,
    bu_hw_ur_decode_type, bu_hw_ur_encode, bu_hw_validate_path, BU_HW_BITBOX02, BU_HW_COIN_COUNT,
    BU_HW_COLDCARD_QR, BU_HW_ERR_BUFFER, BU_HW_ERR_INVALID, BU_HW_ERR_NULL,
    BU_HW_ERR_UNIMPLEMENTED, BU_HW_ERR_UNSUPPORTED, BU_HW_JADE_QR, BU_HW_KEEPKEY, BU_HW_KEYSTONE3,
    BU_HW_KEYSTONE_PRO, BU_HW_LEDGER_FLEX, BU_HW_LEDGER_STAX, BU_HW_LEDGER_S_PLUS, BU_HW_LEDGER_X,
    BU_HW_OK, BU_HW_ONEKEY, BU_HW_PASSPORT, BU_HW_TREZOR_ONE, BU_HW_TREZOR_SAFE3,
    BU_HW_TREZOR_SAFE5, BU_HW_TREZOR_SAFE7, BU_HW_TREZOR_T,
};

pub use bls::{
    bu_bls_aggregate_pks_g1, bu_bls_aggregate_pks_g2, bu_bls_aggregate_sigs_g1,
    bu_bls_aggregate_sigs_g2, bu_bls_aggregate_verify_min_pk, bu_bls_aggregate_verify_min_sig,
    bu_bls_batch_verify_min_pk, bu_bls_batch_verify_min_sig, bu_bls_fast_aggregate_verify_min_pk,
    bu_bls_fast_aggregate_verify_min_sig, bu_bls_sign_min_pk, bu_bls_sign_min_sig,
    bu_bls_sk_to_pk_g1, bu_bls_sk_to_pk_g2, bu_bls_verify_min_pk, bu_bls_verify_min_sig,
};
pub use mldsa::{
    bu_mldsa_keygen, bu_mldsa_pk_from_sk, bu_mldsa_sign, bu_mldsa_sizes, bu_mldsa_verify,
};
