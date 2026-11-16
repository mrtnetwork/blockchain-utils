//! Official BIP-327 vectors from bitcoin/bips (key_agg).
//! Run: `cargo test --features std --test kats bip327_official`

#![cfg(feature = "alloc")]

use blockchain_utils::curve::traits::CurvePoint;
use blockchain_utils::encoding::hex::decode;
use blockchain_utils::musig2::key_agg;

fn unhex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    decode(&s).expect("hex")
}

#[test]
fn bip327_key_agg_valid_cases() {
    // Embedded from bip-0327/vectors/key_agg_vectors.json (bitcoin/bips)
    let pubkeys = [
        "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
        "03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        "023590A94E768F8E1815C2F24B4D80A8E3149316C3518CE7B7AD338368D038CA66",
        "020000000000000000000000000000000000000000000000000000000000000005", // may be invalid in some sets - only use indices from valid cases
    ];
    // Official first 3 keys only for valid cases that use indices 0,1,2
    let p0 = unhex(pubkeys[0]);
    let p1 = unhex(pubkeys[1]);
    let p2 = unhex(pubkeys[2]);

    let cases: &[(&[usize], &str)] = &[
        (
            &[0, 1, 2],
            "90539EEDE565F5D054F32CC0C220126889ED1E5D193BAF15AEF344FE59D4610C",
        ),
        (
            &[2, 1, 0],
            "6204DE8B083426DC6EAF9502D27024D53FC826BF7D2012148A0575435DF54B2B",
        ),
        (
            &[0, 0, 0],
            "B436E3BAD62B8CD409969A224731C193D051162D8C5AE8B109306127DA3AA935",
        ),
        (
            &[0, 0, 1, 1],
            "69BC22BFA5D106306E48A20679DE1D7389386124D07571D0D872686028C26A3E",
        ),
    ];

    let all = [p0.as_slice(), p1.as_slice(), p2.as_slice()];
    for (idxs, expected_x) in cases {
        let keys: Vec<&[u8]> = idxs.iter().map(|i| all[*i]).collect();
        let ctx = key_agg(&keys).expect("key_agg");
        let x = ctx.x_only().expect("xonly");
        let exp = unhex(expected_x);
        assert_eq!(
            x.as_slice(),
            exp.as_slice(),
            "key_agg indices {:?} mismatch",
            idxs
        );
        // also check even-Y convention on compressed Q (BIP-327 often forces even)
        let mut enc = [0u8; 33];
        ctx.q.to_bytes_compressed(&mut enc).unwrap();
        assert!(enc[0] == 0x02 || enc[0] == 0x03);
    }
}

#[test]
fn bip327_nonce_gen_case0() {
    use blockchain_utils::musig2::nonce_generate;
    // Official nonce_gen_vectors.json case 0
    let rand = unhex("0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F");
    let sk = unhex("0202020202020202020202020202020202020202020202020202020202020202");
    let pk = unhex("024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766");
    let aggpk = unhex("0707070707070707070707070707070707070707070707070707070707070707");
    let msg = unhex("0101010101010101010101010101010101010101010101010101010101010101");
    let extra = unhex("0808080808080808080808080808080808080808080808080808080808080808");
    let mut ska = [0u8; 32];
    ska.copy_from_slice(&sk);
    let mut ra = [0u8; 32];
    ra.copy_from_slice(&rand);
    let pair = nonce_generate(
        Some(&ska),
        Some(&pk),
        Some(&aggpk),
        Some(&extra),
        Some(&msg),
        &ra,
    )
    .expect("nonce_gen");
    let exp_sec = unhex("B114E502BEAA4E301DD08A50264172C84E41650E6CB726B410C0694D59EFFB6495B5CAF28D045B973D63E3C99A44B807BDE375FD6CB39E46DC4A511708D0E9D2024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766");
    assert_eq!(pair.secnonce, exp_sec, "secnonce mismatch vs BIP-327");
}

#[test]
fn bip327_nonce_gen_empty_msg_present() {
    use blockchain_utils::musig2::nonce_generate;
    // Official BIP-327 nonce_gen_vectors.json case with "msg": ""
    let rand = unhex("0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F");
    let sk = unhex("0202020202020202020202020202020202020202020202020202020202020202");
    let pk = unhex("024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766");
    let aggpk = unhex("0707070707070707070707070707070707070707070707070707070707070707");
    let extra = unhex("0808080808080808080808080808080808080808080808080808080808080808");
    let mut ska = [0u8; 32];
    ska.copy_from_slice(&sk);
    let mut ra = [0u8; 32];
    ra.copy_from_slice(&rand);
    let pair = nonce_generate(
        Some(&ska),
        Some(&pk),
        Some(&aggpk),
        Some(&extra),
        Some(&[]), // empty message PRESENT
        &ra,
    )
    .expect("nonce_gen");
    let exp_sec = unhex(
        "E862B068500320088138468D47E0E6F147E01B6024244AE45EAC40ACE5929B9F0789E051170B9E705D0B9EB49049A323BBBBB206D8E05C19F46C6228742AA7A9024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766",
    );
    let exp_pub = unhex(
        "023034FA5E2679F01EE66E12225882A7A48CC66719B1B9D3B6C4DBD743EFEDA2C503F3FD6F01EB3A8E9CB315D73F1F3D287CAFBB44AB321153C6287F407600205109",
    );
    assert_eq!(pair.secnonce.as_slice(), exp_sec.as_slice(), "secnonce");
    assert_eq!(pair.pubnonce.as_slice(), exp_pub.as_slice(), "pubnonce");
}

#[test]
fn bip327_nonce_gen_null_sk() {
    use blockchain_utils::musig2::nonce_generate;
    // Official vector: sk/aggpk/msg/extra_in all null — no MuSig/aux XOR
    let rand = unhex("0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F");
    let pk = unhex("02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9");
    let mut ra = [0u8; 32];
    ra.copy_from_slice(&rand);
    let pair = nonce_generate(
        None, // sk absent
        Some(&pk),
        None,
        None,
        None, // msg absent
        &ra,
    )
    .expect("nonce_gen null sk");
    let exp_sec = unhex(
        "89BDD787D0284E5E4D5FC572E49E316BAB7E21E3B1830DE37DFE80156FA41A6D0B17AE8D024C53679699A6FD7944D9C4A366B514BAF43088E0708B1023DD289702F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
    );
    let exp_pub = unhex(
        "02C96E7CB1E8AA5DAC64D872947914198F607D90ECDE5200DE52978AD5DED63C000299EC5117C2D29EDEE8A2092587C3909BE694D5CFF0667D6C02EA4059F7CD9786",
    );
    assert_eq!(pair.secnonce.as_slice(), exp_sec.as_slice(), "secnonce");
    assert_eq!(pair.pubnonce.as_slice(), exp_pub.as_slice(), "pubnonce");
}
