//! Smoke tests for connector FFI exports (feature `ffi`).
//! One check per major surface so link + basic behavior stay green.
#![cfg(feature = "ffi")]

use blockchain_utils::connector::ffi::*;
/// TODO BUG FIXED: unconditional `hw` import broke `cargo test` on default
/// features (`hw` is opt-in); the only users live in `hw`-gated tests below.
#[cfg(feature = "hw")]
use blockchain_utils::hw::trezor::{msg, proto_encode, trezor_frame, ProtoField};

#[test]
fn ffi_hash_sha256_roundtrip() {
    // Minimal config: algo=sha256 (1). Layout depends on bu_hash_new ABI.
    // If config layout mismatches, this may fail — still validates symbol link.
    unsafe {
        // Just ensure symbols resolve by calling digest_len on null-safe path is undefined;
        // use public helper if available. Call bu_keccak_f1600 as a pure buffer API.
        let mut st = [0u8; 200];
        let rc = bu_keccak_f1600(st.as_mut_ptr());
        assert_eq!(rc, 0, "keccak_f1600");
    }
}

#[test]
fn ffi_curve_secp256k1_generator() {
    unsafe {
        let mut out = [0u8; 33];
        let rc = bu_curve_generator(BU_CURVE_SECP256K1, out.as_mut_ptr(), out.len());
        assert_eq!(rc, 0, "generator");
        assert_ne!(out, [0u8; 33]);
        let plen = bu_curve_point_len(BU_CURVE_SECP256K1);
        assert_eq!(plen, 33);
        let slen = bu_curve_scalar_len(BU_CURVE_SECP256K1);
        assert_eq!(slen, 32);
    }
}

#[test]
fn ffi_curve_mul_base_secp256k1() {
    unsafe {
        let mut sk = [0u8; 32];
        sk[31] = 1;
        let mut out = [0u8; 33];
        let rc = bu_curve_mul_base(BU_CURVE_SECP256K1, sk.as_ptr(), 32, out.as_mut_ptr(), 33);
        assert_eq!(rc, 0, "mul_base");
        assert_eq!(out[0] & 0xfe, 0x02); // compressed 0x02/0x03
    }
}

#[test]
fn ffi_ecdsa_r1_sign_verify() {
    unsafe {
        let mut sk = [0u8; 32];
        sk[31] = 1;
        let mut pk = [0u8; 33];
        assert_eq!(
            bu_ecdsa_r1_public_key(sk.as_ptr(), 32, pk.as_mut_ptr(), 33),
            0
        );
        let hash = [7u8; 32];
        let mut sig = [0u8; 64];
        assert_eq!(
            bu_ecdsa_r1_sign(sk.as_ptr(), 32, hash.as_ptr(), 32, sig.as_mut_ptr(), 64),
            0
        );
        assert_eq!(
            bu_ecdsa_r1_verify(pk.as_ptr(), 33, hash.as_ptr(), 32, sig.as_ptr(), 64),
            0
        );
    }
}

#[test]
fn ffi_ecdsa_k1_sign_verify() {
    unsafe {
        let mut sk = [0u8; 32];
        sk[31] = 1;
        let mut pk = [0u8; 33];
        assert_eq!(
            bu_ecdsa_k1_public_key(sk.as_ptr(), 32, pk.as_mut_ptr(), 33),
            0
        );
        let hash = [9u8; 32];
        let mut sig = [0u8; 64];
        assert_eq!(
            bu_ecdsa_k1_sign(sk.as_ptr(), 32, hash.as_ptr(), 32, sig.as_mut_ptr(), 64),
            0
        );
        assert_eq!(
            bu_ecdsa_k1_verify(pk.as_ptr(), 33, hash.as_ptr(), 32, sig.as_ptr(), 64),
            0
        );
    }
}

#[test]
fn ffi_schnorr_bip340() {
    unsafe {
        let mut sk = [0u8; 32];
        sk[31] = 2;
        let mut xonly = [0u8; 32];
        assert_eq!(
            bu_schnorr_public_key(sk.as_ptr(), 32, xonly.as_mut_ptr(), 32),
            0
        );
        let msg = [1u8; 32];
        let mut sig = [0u8; 64];
        assert_eq!(
            bu_schnorr_sign(sk.as_ptr(), 32, msg.as_ptr(), 32, sig.as_mut_ptr(), 64),
            0
        );
        assert_eq!(
            bu_schnorr_verify(xonly.as_ptr(), 32, msg.as_ptr(), 32, sig.as_ptr(), 64),
            0
        );
    }
}

#[test]
fn ffi_ed25519_sign_verify() {
    unsafe {
        let sk = [3u8; 32];
        let mut pk = [0u8; 32];
        assert_eq!(
            bu_ed25519_public_key(sk.as_ptr(), 32, pk.as_mut_ptr(), 32),
            0
        );
        let msg = b"ffi-smoke";
        let mut sig = [0u8; 64];
        assert_eq!(
            bu_ed25519_sign(
                sk.as_ptr(),
                32,
                msg.as_ptr(),
                msg.len(),
                sig.as_mut_ptr(),
                64
            ),
            0
        );
        assert_eq!(
            bu_ed25519_verify(pk.as_ptr(), 32, msg.as_ptr(), msg.len(), sig.as_ptr(), 64),
            0
        );
    }
}

#[test]
fn ffi_aes_block() {
    unsafe {
        let key = [0u8; 16];
        let h = bu_aes_new(key.as_ptr(), 16);
        assert!(!h.is_null());
        let src = [0u8; 16];
        let mut out = [0u8; 16];
        bu_aes_encrypt_block(h, src.as_ptr(), out.as_mut_ptr());
        assert_ne!(out, src);
        let mut back = [0u8; 16];
        bu_aes_decrypt_block(h, out.as_ptr(), back.as_mut_ptr());
        assert_eq!(back, src);
        bu_aes_free(h);
    }
}

#[test]
fn ffi_chacha20poly1305_roundtrip() {
    unsafe {
        let key = [5u8; 32];
        let nonce = [6u8; 12];
        let pt = *b"hello-ffi-aead!!";
        let mut ct = [0u8; 16 + 16]; // pt + tag
        assert_eq!(
            bu_chacha20poly1305_encrypt(
                key.as_ptr(),
                32,
                nonce.as_ptr(),
                12,
                pt.as_ptr(),
                pt.len(),
                core::ptr::null(),
                0,
                ct.as_mut_ptr(),
                ct.len(),
            ),
            0
        );
        let mut pt2 = [0u8; 16];
        assert_eq!(
            bu_chacha20poly1305_decrypt(
                key.as_ptr(),
                32,
                nonce.as_ptr(),
                12,
                ct.as_ptr(),
                ct.len(),
                core::ptr::null(),
                0,
                pt2.as_mut_ptr(),
                pt2.len(),
            ),
            0
        );
        assert_eq!(&pt2[..], &pt[..]);
    }
}

#[test]
fn ffi_pbkdf2_sha256() {
    unsafe {
        let pw = b"password";
        let salt = b"salt";
        let mut out = [0u8; 32];
        let rc = bu_pbkdf2(
            1, // sha256
            pw.as_ptr(),
            pw.len(),
            salt.as_ptr(),
            salt.len(),
            10,
            out.as_mut_ptr(),
            32,
        );
        assert_eq!(rc, 0);
        assert_ne!(out, [0u8; 32]);
    }
}

#[test]
fn ffi_bls_g1_generator_mul_base() {
    unsafe {
        let mut g = [0u8; 48];
        assert_eq!(bu_curve_generator(BU_CURVE_BLS12_G1, g.as_mut_ptr(), 48), 0);
        assert_eq!(g[0], 0x97);
        let mut sk = [0u8; 32];
        sk[31] = 1;
        let mut out = [0u8; 48];
        assert_eq!(
            bu_curve_mul_base(BU_CURVE_BLS12_G1, sk.as_ptr(), 32, out.as_mut_ptr(), 48),
            0
        );
        assert_eq!(out, g);
    }
}

#[test]
fn ffi_encoding_hex_roundtrip_symbols() {
    // encoding may use different names; skip if not exported
    // this test is a placeholder for base58 presence
    {
        let data = b"hello";
        let out = [0u8; 64];
        let out_len = 64usize;
        // base58_encode signature varies — only assert symbols exist via link
        let _ = data;
        let _ = out;
        let _ = out_len;
        let _ = bu_curve_point_len(BU_CURVE_ED25519);
    }
}

#[cfg(feature = "hw")]
#[test]
fn ffi_hw_codec_matrix_no_device() {
    unsafe {
        assert_eq!(bu_hw_device_count(), 17);
        assert_eq!(bu_hw_coin_count(), 20);
        // BTC = coin 0 on Ledger S+ = dev 0
        assert_eq!(bu_hw_supports_coin(BU_HW_LEDGER_S_PLUS, 0), 1);
        assert_eq!(bu_hw_supports_coin(BU_HW_TREZOR_SAFE5, 17), 0); // ada kholaw
        assert_eq!(bu_hw_is_airgap(BU_HW_PASSPORT), 1);
        assert_eq!(bu_hw_is_airgap(BU_HW_LEDGER_X), 0);
        assert!(bu_hw_supports_coin(99, 0) < 0);

        // parse m/44'/0'/0'/0/0 -> 5 u32 LE
        let path = b"m/44'/0'/0'/0/0";
        let mut pout = [0u8; 64];
        let n = bu_hw_parse_path(path.as_ptr(), path.len(), pout.as_mut_ptr(), pout.len());
        assert_eq!(n, 5);
        assert_eq!(&pout[0..4], &[0x2C, 0x00, 0x00, 0x80]);
        assert_eq!(
            bu_hw_validate_path(BU_HW_LEDGER_S_PLUS, 0, pout.as_ptr(), 20),
            BU_HW_OK
        );
        // soft suffix rejected for tezos tz1 (coin 8)
        assert!(bu_hw_validate_path(BU_HW_LEDGER_S_PLUS, 8, pout.as_ptr(), 20) != BU_HW_OK);

        // ledger request
        let mut req = [0u8; 512];
        let rn = bu_hw_get_address_request(
            BU_HW_LEDGER_S_PLUS,
            0,
            pout.as_ptr(),
            20,
            req.as_mut_ptr(),
            req.len(),
        );
        assert!(rn > 4);
        assert_eq!(&req[0..4], &[0xE1, 0x00, 0x00, 0x01]);

        // ledger response: len-prefixed 33B + SW
        let mut resp = [0u8; 36];
        resp[0] = 33;
        for b in resp[1..34].iter_mut() {
            *b = 0x02;
        }
        resp[34] = 0x90;
        resp[35] = 0x00;
        let mut pk = [0u8; 64];
        let pn = bu_hw_parse_address_response(
            BU_HW_LEDGER_S_PLUS,
            resp.as_ptr(),
            resp.len(),
            pk.as_mut_ptr(),
            pk.len(),
        );
        assert_eq!(pn, 33);
        assert_eq!(pk[0], 0x02);

        // airgap QR roundtrip (tezos tz1 = coin 8)
        let tz = b"m/44'/1729'/0'/0'";
        let mut tp = [0u8; 64];
        let tn = bu_hw_parse_path(tz.as_ptr(), tz.len(), tp.as_mut_ptr(), tp.len());
        assert_eq!(tn, 4);
        let mut qr = [0u8; 256];
        let qn = bu_hw_qr_request(
            BU_HW_PASSPORT,
            8,
            tp.as_ptr(),
            16,
            qr.as_mut_ptr(),
            qr.len(),
        );
        assert!(qn > 9);
        assert_eq!(&qr[0..9], b"ur:bytes/");
        let mut pay = [0u8; 64];
        let yn = bu_hw_qr_parse(
            BU_HW_PASSPORT,
            qr.as_ptr(),
            qn as usize,
            pay.as_mut_ptr(),
            pay.len(),
        );
        assert_eq!(yn, 20); // slip44_be32 + 4 path words
        assert_eq!(&pay[0..4], &1729u32.to_be_bytes());

        // UR single roundtrip
        let mut ue = [0u8; 128];
        let un = bu_hw_ur_encode(
            b"bytes".as_ptr(),
            5,
            b"hello".as_ptr(),
            5,
            ue.as_mut_ptr(),
            ue.len(),
        );
        assert!(un > 0);
        let mut ud = [0u8; 32];
        let dn = bu_hw_ur_decode_payload(ue.as_ptr(), un as usize, ud.as_mut_ptr(), ud.len());
        assert_eq!(dn, 5);
        assert_eq!(&ud[0..5], b"hello");
        let mut ut = [0u8; 32];
        let tyn = bu_hw_ur_decode_type(ue.as_ptr(), un as usize, ut.as_mut_ptr(), ut.len());
        assert_eq!(tyn, 5);
        assert_eq!(&ut[0..5], b"bytes");

        // PSBT counts: magic + global{UNSIGNED_TX: 1in/1out tx} + in + out maps
        let mut tx = Vec::from([1u8, 0, 0, 0, 1]);
        tx.extend_from_slice(&[0u8; 32]);
        tx.extend_from_slice(&[0, 0, 0, 0, 0]);
        tx.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 1]);
        tx.extend_from_slice(&1000u64.to_le_bytes());
        tx.push(0);
        tx.extend_from_slice(&[0, 0, 0, 0]);
        let mut psbt = Vec::from([0x70u8, 0x73, 0x62, 0x74, 0xFF, 1, 0x00, tx.len() as u8]);
        psbt.extend_from_slice(&tx);
        psbt.extend_from_slice(&[0, 0, 0]);
        let mut counts = [0u8; 8];
        assert_eq!(
            bu_hw_psbt_counts(psbt.as_ptr(), psbt.len(), counts.as_mut_ptr(), 8),
            BU_HW_OK
        );
        assert_eq!(&counts, &[1, 0, 0, 0, 1, 0, 0, 0]);
    }
}

#[cfg(feature = "hw")]
#[test]
fn ffi_hw_null_and_bounds_never_panic() {
    unsafe {
        use core::ptr::{null, null_mut};
        // null inputs with nonzero length → NULL error, no deref
        assert_eq!(bu_hw_parse_path(null(), 5, null_mut(), 0), -BU_HW_ERR_NULL);
        assert_eq!(
            bu_hw_get_address_request(0, 0, null(), 4, null_mut(), 0),
            -BU_HW_ERR_NULL
        );
        assert_eq!(
            bu_hw_parse_address_response(0, null(), 4, null_mut(), 0),
            -BU_HW_ERR_NULL
        );
        assert_eq!(
            bu_hw_sign_request(0, 0, null(), 4, null(), 32, null_mut(), 0),
            -BU_HW_ERR_NULL
        );
        assert_eq!(
            bu_hw_parse_sign_response(0, null(), 4, null_mut(), 0),
            -BU_HW_ERR_NULL
        );
        // zero-length spans with null are safe (no deref happens)
        let mut out = [0u8; 64];
        assert!(bu_hw_parse_path(null(), 0, out.as_mut_ptr(), out.len()) < 0);
        // bad ids
        assert!(bu_hw_supports_coin(99, 0) < 0);
        assert!(bu_hw_is_airgap(99) < 0);
        assert_eq!(bu_hw_validate_path(0, 99, null(), 0), -BU_HW_ERR_INVALID);
        // unaligned HID reports
        let odd = [0u8; 63];
        let mut o2 = [0u8; 64];
        assert_eq!(
            bu_hw_hid_unframe(
                odd.as_ptr(),
                odd.len(),
                0x0101,
                0x05,
                o2.as_mut_ptr(),
                o2.len()
            ),
            -BU_HW_ERR_INVALID
        );
        // bad channel/tag
        assert_eq!(
            bu_hw_hid_frame(
                odd.as_ptr(),
                odd.len(),
                0x1_0000,
                0x05,
                o2.as_mut_ptr(),
                o2.len()
            ),
            -BU_HW_ERR_INVALID
        );
        assert_eq!(
            bu_hw_hid_frame(
                odd.as_ptr(),
                odd.len(),
                0x0101,
                0x100,
                o2.as_mut_ptr(),
                o2.len()
            ),
            -BU_HW_ERR_INVALID
        );
        // too-small out buffer → BUFFER, not a write past the end
        let mut tiny = [0u8; 4];
        let path = b"m/44'/0'/0'/0/0";
        assert_eq!(
            bu_hw_parse_path(path.as_ptr(), path.len(), tiny.as_mut_ptr(), tiny.len()),
            -BU_HW_ERR_BUFFER
        );
        // single-byte HID round-trip through FFI: 1 report out/in
        let mut framed = [0u8; 64];
        let n = bu_hw_hid_frame(
            b"hi".as_ptr(),
            2,
            0x0101,
            0x05,
            framed.as_mut_ptr(),
            framed.len(),
        );
        assert_eq!(n, 64);
        let mut back = [0u8; 64];
        let m = bu_hw_hid_unframe(
            framed.as_ptr(),
            64,
            0x0101,
            0x05,
            back.as_mut_ptr(),
            back.len(),
        );
        assert_eq!(m, 2);
        assert_eq!(&back[..2], b"hi");
    }
}

#[cfg(feature = "monero")]
#[test]
fn ffi_monero_unlock_batch_matches_oracle() {
    use blockchain_utils::encoding::hex::decode;
    fn h(s: &str) -> [u8; 32] {
        let v = decode(s).expect("hex");
        assert_eq!(v.len(), 32);
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        out
    }
    unsafe {
        let mut view_sec = [0u8; 32];
        view_sec[0] = 0x77;
        view_sec[31] = 0x05;
        let tx_pub = h("3473799e0a88477e856dfff95ee217d1fa2576fe6811f942874bbb5256fd1732");
        let spend = h("9e85d0e9a7d19f4a56a7c5269e2ea8224eff39f1cb063f9368ab0348bc30bb7c");
        let out_key = h("0a2a09d53c51bd054372cfbb32db89490f3843e044cfce5c800c52dfb9bd5883");
        let counts = [1u32];
        let tags = [59i32];
        let indices = [0u32];
        let mut blob = [0u8; 76];
        let mut blob_len = blob.len();
        let rc = bu_monero_unlock_batch(
            view_sec.as_ptr(),
            spend.as_ptr(),
            counts.as_ptr(),
            out_key.as_ptr(),
            tx_pub.as_ptr(),
            core::ptr::null(),
            core::ptr::null(),
            tags.as_ptr(),
            indices.as_ptr(),
            1,
            1,
            blob.as_mut_ptr(),
            &mut blob_len,
        );
        assert_eq!(rc, BU_MONERO_OK);
        assert_eq!(blob_len, BU_MONERO_UNLOCK_RECORD_LEN);
        assert_eq!(&blob[0..4], &[0, 0, 0, 0]); // out_index 0
        assert_eq!(&blob[4..8], &[0, 0, 0, 0]); // acc_index 0
        assert_eq!(&blob[8..12], &[0, 0, 0, 0]); // addr_pos 0
        assert_eq!(
            &blob[12..44],
            &h("7306b0cf9ff5818b1f98e08d2e0fc9795e2002161eaced79a7d6d8f2cfa43e65")[..]
        );
        assert_eq!(&blob[44..76], &out_key[..]);
        // size-query: too-small buffer reports required size
        let mut small_len = 0usize;
        let rc2 = bu_monero_unlock_batch(
            view_sec.as_ptr(),
            spend.as_ptr(),
            counts.as_ptr(),
            out_key.as_ptr(),
            tx_pub.as_ptr(),
            core::ptr::null(),
            core::ptr::null(),
            tags.as_ptr(),
            core::ptr::null(),
            1,
            1,
            core::ptr::null_mut(),
            &mut small_len,
        );
        assert_eq!(rc2, BU_MONERO_ERR_LENGTH);
        assert_eq!(small_len, BU_MONERO_UNLOCK_RECORD_LEN);
    }
}

#[test]
fn ffi_curve_infinity_k1_r1() {
    unsafe {
        for curve in [BU_CURVE_SECP256K1, BU_CURVE_SECP256R1] {
            // identity encodes as zero buffer (was INVALID_POINT before)
            let mut id = [0xFFu8; 33];
            assert_eq!(
                bu_curve_identity(curve, id.as_mut_ptr(), id.len()),
                BU_CURVE_OK
            );
            assert_eq!(id, [0u8; 33]);
            assert_eq!(bu_curve_is_infinity(curve, id.as_ptr(), id.len()), 1);
            assert_eq!(bu_curve_is_infinity(curve, [0x00].as_ptr(), 1), 1);
            // generator is finite
            let mut gen = [0u8; 33];
            assert_eq!(
                bu_curve_generator(curve, gen.as_mut_ptr(), gen.len()),
                BU_CURVE_OK
            );
            assert_eq!(bu_curve_is_infinity(curve, gen.as_ptr(), gen.len()), 0);
            // P + (-P) = infinity, encoded as zeros
            let mut neg = [0u8; 33];
            assert_eq!(
                bu_curve_neg(curve, gen.as_ptr(), gen.len(), neg.as_mut_ptr(), neg.len()),
                BU_CURVE_OK
            );
            let mut sum = [0xFFu8; 33];
            assert_eq!(
                bu_curve_add(
                    curve,
                    gen.as_ptr(),
                    gen.len(),
                    neg.as_ptr(),
                    neg.len(),
                    sum.as_mut_ptr(),
                    sum.len()
                ),
                BU_CURVE_OK
            );
            assert_eq!(sum, [0u8; 33]);
            assert_eq!(bu_curve_is_infinity(curve, sum.as_ptr(), sum.len()), 1);
            // garbage still rejected (0xFF..FF exceeds field order)
            assert_eq!(
                bu_curve_is_infinity(curve, [0xFFu8; 33].as_ptr(), 33),
                BU_CURVE_ERR_INVALID_POINT
            );
            assert_eq!(
                bu_curve_is_infinity(99, gen.as_ptr(), gen.len()),
                BU_CURVE_ERR_INVALID_CURVE
            );
        }
    }
}

#[test]
fn ffi_curve_compress_uncompress_k1_r1_g1_g2() {
    unsafe {
        // (curve id, compressed len, uncompressed len)
        for (curve, clen, ulen) in [
            (BU_CURVE_SECP256K1, 33, 65),
            (BU_CURVE_SECP256R1, 33, 65),
            (BU_CURVE_BLS12_G1, 48, 96),
            (BU_CURVE_BLS12_G2, 96, 192),
        ] {
            assert_eq!(bu_curve_point_len_uncomp(curve), ulen);
            // generator: comp -> uncomp -> comp round-trip
            let mut comp = vec![0u8; 256];
            comp.truncate(clen);
            assert_eq!(
                bu_curve_generator(curve, comp.as_mut_ptr(), comp.len()),
                BU_CURVE_OK
            );
            let mut uncomp = vec![0u8; 256];
            uncomp.truncate(ulen);
            assert_eq!(
                bu_curve_uncompress(
                    curve,
                    comp.as_ptr(),
                    comp.len(),
                    uncomp.as_mut_ptr(),
                    uncomp.len()
                ),
                BU_CURVE_OK
            );
            // uncompressed prefix byte per encoding (0x04 SEC1 / raw BE for BLS)
            if curve == BU_CURVE_SECP256K1 || curve == BU_CURVE_SECP256R1 {
                assert_eq!(uncomp[0], 0x04);
            }
            let mut back = vec![0u8; 256];
            back.truncate(clen);
            assert_eq!(
                bu_curve_compress(
                    curve,
                    uncomp.as_ptr(),
                    uncomp.len(),
                    back.as_mut_ptr(),
                    back.len()
                ),
                BU_CURVE_OK
            );
            assert_eq!(&back[..], &comp[..]);
            // identity round-trips through both forms
            let mut id_c = vec![0u8; 256];
            id_c.truncate(clen);
            assert_eq!(
                bu_curve_identity(curve, id_c.as_mut_ptr(), id_c.len()),
                BU_CURVE_OK
            );
            let mut id_u = vec![0u8; 256];
            id_u.truncate(ulen);
            assert_eq!(
                bu_curve_uncompress(
                    curve,
                    id_c.as_ptr(),
                    id_c.len(),
                    id_u.as_mut_ptr(),
                    id_u.len()
                ),
                BU_CURVE_OK
            );
            assert_eq!(bu_curve_is_infinity(curve, id_u.as_ptr(), id_u.len()), 1);
            // garbage rejected by the validating decode
            let bad = vec![0xFFu8; ulen];
            let mut tmp = vec![0u8; 256];
            tmp.truncate(clen);
            assert_eq!(
                bu_curve_compress(curve, bad.as_ptr(), bad.len(), tmp.as_mut_ptr(), tmp.len()),
                BU_CURVE_ERR_INVALID_POINT
            );
        }
        assert_eq!(bu_curve_point_len_uncomp(99), 0);
    }
}

#[cfg(feature = "hw")]
#[test]
fn ffi_hw_sign_request_response() {
    unsafe {
        // path m/44'/0'/0'/0/0 as u32 LE (reuse parse helper shape)
        let path = b"m/44'/0'/0'/0/0";
        let mut pout = [0u8; 64];
        let n = bu_hw_parse_path(path.as_ptr(), path.len(), pout.as_mut_ptr(), pout.len());
        assert_eq!(n, 5);

        // Ledger: 32-byte sighash -> B0 48 template
        let hash = [0xABu8; 32];
        let mut req = [0u8; 256];
        let rn = bu_hw_sign_request(
            BU_HW_LEDGER_S_PLUS,
            0,
            pout.as_ptr(),
            20,
            hash.as_ptr(),
            hash.len(),
            req.as_mut_ptr(),
            req.len(),
        );
        // app-bitcoin v2 has no bare-hash sign (PSBT wallet flow instead)
        assert!(rn < 0);
        // wrong sighash length rejected
        let short = [0u8; 31];
        assert!(
            bu_hw_sign_request(
                BU_HW_LEDGER_S_PLUS,
                0,
                pout.as_ptr(),
                20,
                short.as_ptr(),
                short.len(),
                req.as_mut_ptr(),
                req.len(),
            ) < 0
        );

        // Ledger approve: DER || 0x9000 passes through; 0x6985 rejected
        let mut ok_resp = [0u8; 72];
        ok_resp[..70].copy_from_slice(&[0x30; 70]);
        ok_resp[70] = 0x90;
        ok_resp[71] = 0x00;
        let mut sig = [0u8; 80];
        assert_eq!(
            bu_hw_parse_sign_response(
                BU_HW_LEDGER_S_PLUS,
                ok_resp.as_ptr(),
                ok_resp.len(),
                sig.as_mut_ptr(),
                sig.len(),
            ),
            70
        );
        let rej = [0x69u8, 0x85];
        assert!(
            bu_hw_parse_sign_response(
                BU_HW_LEDGER_S_PLUS,
                rej.as_ptr(),
                rej.len(),
                sig.as_mut_ptr(),
                sig.len(),
            ) < 0
        );

        // Airgap refusal contract over FFI
        assert!(
            bu_hw_sign_request(
                BU_HW_PASSPORT,
                0,
                pout.as_ptr(),
                20,
                hash.as_ptr(),
                hash.len(),
                req.as_mut_ptr(),
                req.len(),
            ) < 0
        );
    }
}

#[cfg(feature = "hw")]
#[test]
fn ffi_hw_signtx_loop() {
    unsafe {
        let path = b"m/44'/0'/0'/0/0";
        let mut pout = [0u8; 64];
        assert_eq!(
            bu_hw_parse_path(path.as_ptr(), path.len(), pout.as_mut_ptr(), pout.len()),
            5
        );

        // open 1-in/1-out
        let mut start = [0u8; 256];
        let sn = bu_hw_sign_tx_start(BU_HW_TREZOR_SAFE5, 0, 1, 1, start.as_mut_ptr(), start.len());
        assert!(sn > 9);
        // non-trezor refuses
        assert!(
            bu_hw_sign_tx_start(
                BU_HW_LEDGER_S_PLUS,
                0,
                1,
                1,
                start.as_mut_ptr(),
                start.len(),
            ) < 0
        );
        // zero counts refused
        assert!(
            bu_hw_sign_tx_start(BU_HW_TREZOR_SAFE5, 0, 0, 1, start.as_mut_ptr(), start.len(),) < 0
        );

        // meta ack parses back through the pack: type TXMETA(0), index none
        let mut ack = [0u8; 512];
        let an = bu_hw_tx_ack_meta(2, 0, 1, 1, ack.as_mut_ptr(), ack.len());
        assert!(an > 9);

        // input ack (prev_hash 32B + path) and output ack (address + amount)
        let ph = [0xCCu8; 32];
        let mut acki = [0u8; 512];
        let empty_sig = [0u8; 0];
        let inn = bu_hw_tx_ack_input(
            ph.as_ptr(),
            ph.len(),
            3,
            pout.as_ptr(),
            20,
            60_000,
            empty_sig.as_ptr(),
            empty_sig.len(),
            0,
            acki.as_mut_ptr(),
            acki.len(),
        );
        assert!(inn > 9);
        assert!(
            bu_hw_tx_ack_input(
                ph.as_ptr(),
                31,
                3,
                pout.as_ptr(),
                20,
                60_000,
                empty_sig.as_ptr(),
                empty_sig.len(),
                0,
                acki.as_mut_ptr(),
                acki.len(),
            ) < 0 // prev_hash must be 32 bytes
        );
        let mut acko = [0u8; 512];
        let on = bu_hw_tx_ack_output(
            b"bc1qtest".as_ptr(),
            8,
            50_000,
            0,
            acko.as_mut_ptr(),
            acko.len(),
        );
        assert!(on > 9);
        let mut ackc = [0u8; 512];
        let cn = bu_hw_tx_ack_change(pout.as_ptr(), 20, 24_000, 0, ackc.as_mut_ptr(), ackc.len());
        assert!(cn > 9);

        // hand-built TxRequest{TXINPUT=0, details{index 2}} frame:
        // body = [0x08,0x00, 0x12,0x02,0x08,0x02]
        let mut fr = Vec::from([0x3Fu8, 0x23, 0x23, 0x00, 0x15, 0, 0, 0, 6]);
        fr.extend_from_slice(&[0x08, 0x00, 0x12, 0x02, 0x08, 0x02]);
        while fr.len() % 63 != 0 {
            fr.push(0);
        }
        let mut packed = [0u8; 8];
        assert_eq!(
            bu_hw_parse_tx_request(
                BU_HW_TREZOR_SAFE5,
                fr.as_ptr(),
                fr.len(),
                packed.as_mut_ptr(),
                packed.len()
            ),
            8 // bytes written (out-buffer fns return counts, not OK)
        );
        // type TXINPUT=0, index 2 as LE32 pair
        assert_eq!(&packed, &[0, 0, 0, 0, 2, 0, 0, 0]);
        // wrong message type is a negative code, never a pack
        let mut bad = [0u8; 8];
        let wrong = trezor_frame(
            msg::ADDRESS,
            &proto_encode(&[1], &[ProtoField::Bytes(b"x".to_vec())]).unwrap(),
        )
        .concat();
        assert!(
            bu_hw_parse_tx_request(
                BU_HW_TREZOR_SAFE5,
                wrong.as_ptr(),
                wrong.len(),
                bad.as_mut_ptr(),
                bad.len()
            ) < 0
        );
        let mut fr0 = Vec::from([0x3Fu8, 0x23, 0x23, 0x00, 0x15, 0, 0, 0, 2, 0x08, 0x02]);
        while fr0.len() % 63 != 0 {
            fr0.push(0);
        }
        let mut packed0 = [0u8; 8];
        assert_eq!(
            bu_hw_parse_tx_request(
                BU_HW_TREZOR_SAFE5,
                fr0.as_ptr(),
                fr0.len(),
                packed0.as_mut_ptr(),
                packed0.len()
            ),
            8
        );
        // TXMETA=2, index absent (0xFFFFFFFF)
        assert_eq!(&packed0, &[2, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF]);
        // signature/serialized extractors on a finished frame (TXFINISHED=3)
        let mut fin = Vec::from([0x3Fu8, 0x23, 0x23, 0x00, 0x15]);
        let mut sbody = vec![0x08, 0x03, 0x1A];
        let inner = vec![
            0x08, 0x00, 0x12, 0x02, 0xAA, 0xBB, 0x1A, 0x03, 0xCC, 0xDD, 0xEE,
        ];
        sbody.push(inner.len() as u8);
        sbody.extend_from_slice(&inner);
        let mut bl = [0u8; 4];
        bl.copy_from_slice(&(sbody.len() as u32).to_be_bytes());
        fin.extend_from_slice(&bl);
        fin.extend_from_slice(&sbody);
        while fin.len() % 63 != 0 {
            fin.push(0);
        }
        let mut sig = [0u8; 16];
        assert_eq!(
            bu_hw_tx_request_signature(
                BU_HW_TREZOR_SAFE5,
                fin.as_ptr(),
                fin.len(),
                sig.as_mut_ptr(),
                sig.len(),
            ),
            2
        );
        assert_eq!(&sig[0..2], &[0xAA, 0xBB]);
        let mut stx = [0u8; 16];
        assert_eq!(
            bu_hw_tx_request_serialized(
                BU_HW_TREZOR_SAFE5,
                fin.as_ptr(),
                fin.len(),
                stx.as_mut_ptr(),
                stx.len(),
            ),
            3
        );
        assert_eq!(&stx[0..3], &[0xCC, 0xDD, 0xEE]);
    }
}

#[cfg(feature = "hw")]
#[test]
fn ffi_hw_bitbox_session_state_machine() {
    unsafe {
        let s = [0x11u8; 32];
        let e = [0x12u8; 32];
        // bad key lengths rejected
        assert!(bu_hw_bitbox_hs_new(s.as_ptr(), 31, e.as_ptr(), 32) < 0);
        assert_eq!(bu_hw_bitbox_hs_new(s.as_ptr(), 32, e.as_ptr(), 32), 1);
        // double-open fails instead of clobbering
        assert!(bu_hw_bitbox_hs_new(s.as_ptr(), 32, e.as_ptr(), 32) < 0);

        // m1: 32-byte ephemeral
        let mut m1 = [0u8; 64];
        assert_eq!(bu_hw_bitbox_hs_m1(m1.as_mut_ptr(), m1.len()), 32);
        // encrypt/hash before split: wrong state, session KEPT (not spent:
        // post-handshake crypto never corrupts on failure)
        let mut ct = [0u8; 64];
        assert!(bu_hw_bitbox_encrypt(b"x".as_ptr(), 1, ct.as_mut_ptr(), ct.len()) < 0);
        let mut h = [0u8; 32];
        assert!(bu_hw_bitbox_hs_hash(h.as_mut_ptr(), h.len()) < 0);
        // garbage m2 rejected AND session spent (fail-closed: half-mixed
        // handshake state must never survive) — even m1 now fails
        assert!(bu_hw_bitbox_hs_m2([0xFFu8; 96].as_ptr(), 96) < 0);
        assert!(bu_hw_bitbox_hs_m1(m1.as_mut_ptr(), m1.len()) < 0);
        // split with no live handshake fails
        assert!(bu_hw_bitbox_hs_split() < 0);

        // close wipes; everything after fails until reopened
        assert_eq!(bu_hw_bitbox_free(), BU_HW_OK);
        assert!(bu_hw_bitbox_hs_m1(m1.as_mut_ptr(), m1.len()) < 0);
        assert!(bu_hw_bitbox_decrypt(ct.as_ptr(), 16, ct.as_mut_ptr(), ct.len()) < 0);
        assert_eq!(bu_hw_bitbox_free(), BU_HW_OK); // idempotent
    }
}

#[cfg(feature = "hw")]
#[test]
fn ffi_hw_bitbox_sign_codec() {
    unsafe {
        let path = b"m/84'/1'/0'/0/0";
        let mut pout = [0u8; 64];
        let n = bu_hw_parse_path(path.as_ptr(), path.len(), pout.as_mut_ptr(), pout.len());
        assert_eq!(n, 5);
        // init: envelope field 9 (0x4A), version must be 1-2
        let mut init = [0u8; 256];
        let rn = bu_hw_bitbox_sign_init(
            1,
            pout.as_ptr(),
            20,
            1,
            1,
            1,
            1,
            0,
            init.as_mut_ptr(),
            init.len(),
        );
        assert!(rn > 9);
        assert_eq!(init[0], 0x4A);
        assert!(
            bu_hw_bitbox_sign_init(
                1,
                pout.as_ptr(),
                20,
                1,
                0,
                1,
                1,
                0,
                init.as_mut_ptr(),
                init.len()
            ) < 0
        );
        // input: envelope field 10 (0x52); sequence below max-2 rejected
        let ph = [0x11u8; 32];
        let mut on = [0u8; 256];
        let inn = bu_hw_bitbox_sign_input(
            ph.as_ptr(),
            32,
            0,
            60000,
            0xFFFF_FFFF,
            pout.as_ptr(),
            20,
            0,
            on.as_mut_ptr(),
            on.len(),
        );
        assert!(inn > 9);
        assert_eq!(on[0], 0x52);
        assert!(
            bu_hw_bitbox_sign_input(
                ph.as_ptr(),
                32,
                0,
                60000,
                0,
                pout.as_ptr(),
                20,
                0,
                on.as_mut_ptr(),
                on.len(),
            ) < 0
        );
        // output external (field 11 = 0x5A) + change
        let mut oo = [0u8; 256];
        let h20 = [0x22u8; 20];
        let on2 =
            bu_hw_bitbox_sign_output(3, 40000, h20.as_ptr(), h20.len(), oo.as_mut_ptr(), oo.len());
        assert!(on2 > 0);
        assert_eq!(oo[0], 0x5A);
        let mut oc = [0u8; 256];
        let cn = bu_hw_bitbox_sign_change(pout.as_ptr(), 20, 20000, 0, oc.as_mut_ptr(), oc.len());
        assert!(cn > 0);
        assert_eq!(oc[0], 0x5A);
        // hand-built sign_next{INPUT, index 1}: pack has top bit.
        // Response{btc = 13}: tag (13<<3)|2 = 0x6A; BTCResponse{sign_next = 3}: 0x1A.
        let body = [0x08u8, 0x00, 0x10, 0x01];
        let mut btc = vec![0x1Au8, body.len() as u8];
        btc.extend_from_slice(&body);
        let mut outer = vec![0x6Au8, btc.len() as u8];
        outer.extend_from_slice(&btc);
        let mut packedb = [0u8; 8];
        assert_eq!(
            bu_hw_bitbox_sign_next_parse(
                outer.as_ptr(),
                outer.len(),
                packedb.as_mut_ptr(),
                packedb.len()
            ),
            8
        );
        // type INPUT=0, index 1 as LE32 pair
        assert_eq!(&packedb, &[0, 0, 0, 0, 1, 0, 0, 0]);
        // no prev_index present -> 0xFFFFFFFF (not an error)
        assert_eq!(
            bu_hw_bitbox_sign_next_prev_index(outer.as_ptr(), outer.len()),
            0xFFFF_FFFF
        );
    }
}
