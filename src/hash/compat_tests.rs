//! Reference hash parity tests (state / reset / clean / vectors).

#![cfg(test)]

extern crate alloc;

use super::digest::{HashState, SerializableHash};
use super::keccak::Keccak;
use super::md4::Md4;
use super::md5::Md5;
use super::ripemd160::Ripemd160;
use super::ripemd_ext::{Ripemd128, Ripemd256, Ripemd320};
use super::sha1::Sha1;
use super::sha256::Sha256;
use super::sha512::Sha512;

fn dec(s: &str) -> alloc::vec::Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn state_roundtrip_sha256() {
    let mut k = Sha256::new();
    k.update(&[0, 0]);
    let r = k.save_state();
    let mut d1 = [0u8; 32];
    k.clone().finalize_into(&mut d1);
    let mut d2 = [0u8; 32];
    k.clone().finalize_into(&mut d2);
    assert_eq!(d1, d2, "digest idempotent");
    k.reset();
    k.update(&[0, 0]);
    let mut d3 = [0u8; 32];
    k.clone().finalize_into(&mut d3);
    assert_eq!(d1, d3, "reset restores");
    k.clean();
    k.reset(); // no-op when cleaned
    k.update(&[0, 0]);
    let mut g = Sha256::new();
    g.restore_state(&r);
    let mut d4 = [0u8; 32];
    g.finalize_into(&mut d4);
    assert_eq!(d1, d4, "restore_state");
}

macro_rules! vector_split_update {
    ($name:ident, $new:expr, $finalize:expr, $msg:expr, $hash:expr, $outlen:expr) => {
        #[test]
        fn $name() {
            let message = dec($msg);
            let expected = dec($hash);
            assert!(message.len() > 10);
            let mut k = $new;
            k.update(&message[..10]);
            k.update(&message[10..]);
            let mut out = [0u8; 64];
            $finalize(&mut k, &mut out[..$outlen]);
            assert_eq!(&out[..$outlen], &expected[..], "split update");
            k.reset();
            k.update(&message);
            let mut out2 = [0u8; 64];
            $finalize(&mut k, &mut out2[..$outlen]);
            assert_eq!(&out2[..$outlen], &expected[..], "after reset");
        }
    };
}

#[test]
fn sha256_state_semantics() {
    state_roundtrip_sha256();
}

#[test]
fn sha1_state_semantics() {
    let mut k = Sha1::new();
    k.update(&[0, 0]);
    let r = k.save_state();
    let d1 = k.clone().finalize().unwrap();
    let d2 = k.clone().finalize().unwrap();
    assert_eq!(d1, d2);
    k.reset();
    k.update(&[0, 0]);
    assert_eq!(k.clone().finalize().unwrap(), d1);
    k.clean();
    let mut g = Sha1::new();
    g.restore_state(&r);
    assert_eq!(g.finalize().unwrap(), d1);
}

#[test]
fn sha512_state_semantics() {
    let mut k = Sha512::new();
    k.update(&[0, 0]);
    let r = k.save_state();
    let d1 = k.clone().finalize();
    let d2 = k.clone().finalize();
    assert_eq!(d1, d2);
    k.reset();
    k.update(&[0, 0]);
    assert_eq!(k.clone().finalize(), d1);
    k.clean();
    let mut g = Sha512::new();
    g.restore_state(&r);
    assert_eq!(g.finalize(), d1);
}

vector_split_update!(
    sha1_vector,
    Sha1::new(),
    |k: &mut Sha1, out: &mut [u8]| {
        let d = k.clone().finalize().unwrap();
        out[..20].copy_from_slice(&d);
    },
    "36afe0751c3f5d7300591d205ea2aa6730ad2b7eb7767589bb4124792767e54d243d345c00bdcdfbf33f72c94e590224b7308dcd942effa9faaa86100c7cd78e6af9bff21f1107c473",
    "2a6a79d8d3c76131af5503e405372bb7f5a1bb7f",
    20
);

vector_split_update!(
    sha256_vector,
    Sha256::new(),
    |k: &mut Sha256, out: &mut [u8]| {
        k.clone().finalize_into(out);
    },
    "2f52ce1defae10d59bcf5ef33c2d52bf4ad214748805af710e1daa56e2c76b98e593c2a1415b88b47b46cc1c9296577235606a2a175589204d5edb0e19e58b3282fa0815474b10625f998c3f8d5dee7f2e6bd8a3e8032aeb4ae3a21ac918f8d9fa8c7a4cfe70980437dda893f594d37beafdb9950fd7634e7beb11e799b9a63e36224c703cac5c7aaac07335c72061139c4503b55f231062e856c6dbd151480d4b024d44a3576bfe4c062d2161788368b936c4b53ef56b23a129c37eca20cde82cc0c6b8d285d63c67b7c221b0683931891977ae74eb89bca7a34a58be8bb0fc7ab1ea5b186d1c6a51ae639931a8b7eca64c83585c6ab0",
    "11999394ab139df9657eaae6a9f63b0617c69b879841364522106b2c545c5e17",
    32
);

vector_split_update!(
    sha512_vector,
    Sha512::new(),
    |k: &mut Sha512, out: &mut [u8]| {
        k.clone().finalize_into(out);
    },
    "0273d85416ac8a078f111c636233e43853dab3d46a179ea4b4f658bd594f99f68aef0e4b4a76f12d8ec541c792322b85384528fa2ba81fa2b5d4a36f95ca87cf491eb491cee27388d2a71b3d985b699687be5fd3a4d3d1e1961d4866b515211ad6aab7706e2a79c9e7bc0e0dcbf023d876a7f0",
    "1d8ed7bd0513736f06b31e2c26ef9a93154645d20fde60d4b21cc980fa751f99db8b0170704c9b07278b498cfed56cc70772afdcdf6e36105ac8912563325854",
    64
);

vector_split_update!(
    sha512_256_vector,
    Sha512::new_512_256(),
    |k: &mut Sha512, out: &mut [u8]| {
        let d = k.clone().finalize_512_256();
        out[..32].copy_from_slice(&d);
    },
    "9f5a6fcccfa911a4cd45cd3f943aa5e088f6607090bdd08f387958d9bf68f9fcdd825eb1b3d25552d212bc0e3b9ba8ef28aca388c1a49deefd6a52bcaffb186486276d25356d885f8d22d2fbdb9b4080bb36cf85b7b7448b8b9929068c0708a763813e79a3f17a2127d5662e4353b16cbb48bb08038b36672f77135184ccec8f25704d1b4b1e8ff588e4fd99003452dc97d9",
    "06771a6387b95401ac42ef77a10fa13004bb8457aeee6097561caf8e8f41cd2e",
    32
);

vector_split_update!(
    md5_vector,
    Md5::new(),
    |k: &mut Md5, out: &mut [u8]| {
        let d = k.clone().finalize().unwrap();
        out[..16].copy_from_slice(&d);
    },
    "f87de6b171ba4ca39ad7ade82741fa27cf2b39c661d2f837e96e5b321970b7811c3539eeb8ff364e25635be533bb007e6b249fd92162815d3a9e6b30abdce93fe6f6f3fe18d4af989748237d1535562026a6e75cc9b5a627ea7002c1938461537f916a3f203370f11f2c8c6743674a0bd51358ac10f8c0f85c5807f94bee",
    "0c32fe27dd71b130fdced679bb80bdc6",
    16
);

vector_split_update!(
    md4_vector,
    Md4::new(),
    |k: &mut Md4, out: &mut [u8]| {
        let d = k.clone().finalize().unwrap();
        out[..16].copy_from_slice(&d);
    },
    "aec4b5047d19b0cec91957ddbb654f0f7c0925dfc827538c84243f351280661e552118eebe14385f318e86f9ca6f4875abfefa2c326da88d7a77514df6800e8e638e0d41d2ba8d60eff8c9674da1a77937146d2c126db536c02137282443f4086749dfdc04d848556001d896467c076c4aac98e7be76ff1b9c3ab72ae2949874fee6f0eb75d457de7512c82f65fe104cca408a4d962df6d4539a5ce031e0d0a94de52ff0ef63ce653c9bd42fe38f63689e5d883b0b80c50bd6369b83d9",
    "9a416d790189b257804ae4648582332b",
    16
);

#[test]
fn shake256_second_digest_differs_xof() {
    let mut k = Keccak::shake256();
    k.update(&[0, 0]);
    let mut d1 = [0u8; 32];
    k.finish_into_mut(&mut d1).unwrap();
    let mut d2 = [0u8; 32];
    k.finish_into_mut(&mut d2).unwrap();
    assert_ne!(d1, d2, "SHAKE second squeeze must differ (XOF)");
    k.reset();
    k.update(&[0, 0]);
    let mut d3 = [0u8; 32];
    k.finish_into_mut(&mut d3).unwrap();
    assert_eq!(d1, d3);
    k.clean();
    assert!(k.is_cleaned());
}

#[test]
fn shake256_vector() {
    fn dec(s: &str) -> alloc::vec::Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    let inp = dec("10d809a262c4579c78053effd68d89aa8cb1");
    let expected = dec("431c1a0010602f886855406ed496dc3726858470d810428041716dc3cda87591a8ee80c0c15299462b4a3a589835d01239fb937a9a5d62d450974d7f6240bab0019b2d1670c0907c981f8ca75eaabd86e2e104");
    let mut h = Keccak::shake256();
    h.update(&inp[..1]);
    h.update(&inp[1..]);
    let mut out = alloc::vec![0u8; 83];
    h.finish_into_mut(&mut out).unwrap();
    assert_eq!(out, expected);
    h.reset();
    h.update(&inp);
    let mut out2 = alloc::vec![0u8; 83];
    h.finish_into_mut(&mut out2).unwrap();
    assert_eq!(out2, expected);
}

#[test]
fn keccak256_vector() {
    fn dec(s: &str) -> alloc::vec::Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    let message = dec("97126b5563e524fe799a672ae7267f6a966f7d566360d5de3c8d06a84314cb3532becc1c27112a4448e55a0fbf077c299a5cfe78ec49e69828559061cfd0af07ab145c687144be467adfdc01619827b8fa79414ccf12017edda1b1a2e749d57fa25676172749b4268d0cce31ba11878674002953ebc8fc4f1e0875bf096e3f7cc886cbcf3ac0196634a5d25afc41879d");
    let expected = dec("ed05af23000728be0bdd12f06f977960b64699d38051858dfd1712b02ee9078f");
    let mut k = Keccak::keccak256();
    k.update(&message[..10]);
    k.update(&message[10..]);
    let mut out = [0u8; 32];
    k.clone().finalize_into(&mut out).unwrap();
    assert_eq!(&out[..], &expected[..]);
    k.reset();
    k.update(&message);
    let mut out2 = [0u8; 32];
    k.clone().finalize_into(&mut out2).unwrap();
    assert_eq!(&out2[..], &expected[..]);
}

#[test]
fn keccak_fixed_digest_idempotent() {
    let mut k = Keccak::keccak256();
    k.update(&[0, 0]);
    let mut d1 = [0u8; 32];
    k.clone().finalize_into(&mut d1).unwrap();
    let mut d2 = [0u8; 32];
    k.clone().finalize_into(&mut d2).unwrap();
    assert_eq!(d1, d2);
}

#[test]
fn sha3_256_state() {
    let mut k = Keccak::sha3_256();
    k.update(&[0, 0]);
    let mut d1 = [0u8; 32];
    k.clone().finalize_into(&mut d1).unwrap();
    let mut d2 = [0u8; 32];
    k.clone().finalize_into(&mut d2).unwrap();
    assert_eq!(d1, d2);
    k.reset();
    k.update(&[0, 0]);
    let mut d3 = [0u8; 32];
    k.clone().finalize_into(&mut d3).unwrap();
    assert_eq!(d1, d3);
    k.clean();
    assert!(k.is_cleaned());
}

#[test]
fn ripemd128_vector() {
    fn dec(s: &str) -> alloc::vec::Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    let message = dec("3f6d0be05677cd39efb664645a9a7bb776ce7f4b015632b733a659c65be673cfb7c455f0f05c432764ecb152afb78cc9ead5c1b566fd097f9d208ce7cbd65f881724de");
    let expected = dec("581909931c1cff5158f981fb88fa69a2");
    let mut h = Ripemd128::new();
    h.update(&message[..10.min(message.len())]);
    if message.len() > 10 {
        h.update(&message[10..]);
    }
    let got = h.clone().finalize();
    assert_eq!(&got[..], &expected[..]);
    h.reset();
    h.update(&message);
    assert_eq!(&h.finalize()[..], &expected[..]);
}

#[test]
fn ripemd160_vector() {
    fn dec(s: &str) -> alloc::vec::Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    let message = dec("8652a3ba1af4bfbcf1cefe8fd950f409359aa64f656323e4b39a241085da2d45cc1c0289990c859cdc8110e704e6c7ca01401da10ed89e8bafd353aff99e6f360ce1f1825b0ac370bcbcb8f5f7e0dc46131181dc890f6748d182a47c942785592305f395c364ebbb6a34d17019f0e06c29ff1dadbf8bc62c57a674801dd96a49adcb84c56294a1c4835bb3642e95f2aa3632f78bcc68892fa60b38ce0532ae986162a38ec3c90d24a7f16274041909618bb5415f2dc2cda1e49b725bcb21de3e6d618b344c1eefbabe235dc991d38e4221");
    let expected = dec("94c58003752916ee99de81abedada947f9f856e3");
    let mut h = Ripemd160::new();
    h.update(&message[..10]);
    h.update(&message[10..]);
    assert_eq!(&h.clone().finalize()[..], &expected[..]);
    h.reset();
    h.update(&message);
    assert_eq!(&h.finalize()[..], &expected[..]);
}

#[test]
fn ripemd256_vector() {
    fn dec(s: &str) -> alloc::vec::Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    let message = dec("98c66d857059a20cb226005dc8572f690e2035acd41f7ff70a5aff7f21fab212c179ab900915c2e3876007ac17d93ebaa50f39c54754e14c2c0e3d1288f68795fe442b2549111f22355311eaf7fd6415c761c5b5c5ecf4605a5c9e97f3c2f316c81dd714da5c0c2f35551eed377095c9124e5bd64004f8fc4813066cbf5c940ac84258994c4c5d7f578de99b5cb521611a570f77da559d053e73194ad3a7d8cd01688f0594c54e5e35e44ed38ecdb9130a6aa2cb8a96f4298c91aad9f18cf389f4dfe45aaa01777c056c5e69a1ffbc9bee5f1376e2882f669871ed4878f7860699e1c9dc9d7a31");
    let expected = dec("ce1438376e31b05b3b686a153e3af89effb0ddb4aab829669baaf67f536d71b6");
    let mut h = Ripemd256::new();
    h.update(&message[..10]);
    h.update(&message[10..]);
    assert_eq!(&h.clone().finalize()[..], &expected[..]);
    h.reset();
    h.update(&message);
    assert_eq!(&h.finalize()[..], &expected[..]);
}

#[test]
fn ripemd320_vector() {
    fn dec(s: &str) -> alloc::vec::Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    let message = dec("961039bcd5f8ae11fc0d67b774ba34d797550a6022acc3d680152f46978f25c696f725cf1aff56370e9f28c415f71893ec1cf283dbaaf3f6887a965e56dc835b4afcf8d28d6d882966d84e22fa40c5667385ae2391800c6bdd0e02b1f4b1816de746439523acb63165af1d3d73ee6c457d3c7b67970d9d33c0ae583ea7db72ef284082d30dc5f2689945e612b0709b9a8daa17063bd927fbb7f368127d00c68fdacdc95393990597b4d16587fbd33a92a144b74dd53af63c9cb387f734a12f27a9011c5768375faf952953ab6961bb08703e0d5747a4c107e86a8a979d5c24a6b820cade403933a55502bd620fcd07f6b4559d089460f5580b77395985e421d7f1c3");
    let expected =
        dec("60430dacd1cb00eb9498597d92d2b0de4909ccb657e685af7a57b943d8f828365cb0ac3fab436acf");
    let mut h = Ripemd320::new();
    h.update(&message[..10]);
    h.update(&message[10..]);
    assert_eq!(&h.clone().finalize()[..], &expected[..]);
    h.reset();
    h.update(&message);
    assert_eq!(&h.finalize()[..], &expected[..]);
}
