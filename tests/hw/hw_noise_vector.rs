//! Official cacnoise vectors for `Noise_XX_25519_ChaChaPoly_SHA256`
//! (shipped in `snow`'s `tests/vectors/snow.txt`). Byte-exact independent
//! proof our handshake matches the spec — stronger than interop, since both
//! sides here are pinned to third-party bytes.
//!
//! Run: `cargo test --features hw --test hw_noise_vector`

#![cfg(feature = "hw")]

use blockchain_utils::encoding::hex::decode;
use blockchain_utils::hw::noise::NoiseXX;

fn hexd(s: &str) -> Vec<u8> {
    decode(s).expect("hex")
}

fn hex32(s: &str) -> [u8; 32] {
    let v = hexd(s);
    let mut o = [0u8; 32];
    o.copy_from_slice(&v);
    o
}

// Vector fields (snow.txt, protocol Noise_XX_25519_ChaChaPoly_SHA256).
const S_I: &str = "7dec208517a3b81a2861d7a71266d5d6dc944c5a8816634a86fe63198a0148ee";
const E_I: &str = "a32daf21e93c0131495ce1d903181fde81cc46937daaeb990bae7c992709421e";
const S_R: &str = "4d0aed5098e3b4ef20357e9f686ce66204c792b358da2e475017d6c485304881";
const E_R: &str = "4eece0f195d026db035ff987597c429d3ad3bcc2944df37d649528951b2a27c5";
const PROLOGUE: &str = "5468657265206973206e6f20726967687420616e642077726f6e672e2054686572652773206f6e6c792066756e20616e6420626f72696e672e";
// messages[i].payload / .ciphertext
const P1: &str = "d03c489139e645d0711a3c9e810d776b46a84912463fafa87b884eebf242dc34";
const C1: &str = "f9fa868ba97ab8a2686deccfaad5a484ee10a5bb85e3d1dce015a84797f92818d03c489139e645d0711a3c9e810d776b46a84912463fafa87b884eebf242dc34";
const P2: &str = "d8190a92f7dc0c93dbea9118ba8055751fb7c6590c416ffbd419964132b99a85";
const C2: &str = "8c4e6fdb7d09d501a86f7eca5c234522751706ed409182c05cdf5f827d4dae47b81c6c5f43b025692c24391eefee725c17d8cb0fbe3e4abb8aedf42c4fd2592d4ea48ac08989d6ae8b4adae08b2c34087c808c7aa55a63c02b0fab9e930612336bd43eaea04d3c670a0a146691aa9cc9d357872320dc735dbc48580cffb553db";
const P3: &str = "77891b19dcb92ef7c055b672c4a5aa7fdf1c84146b8b303459022729473ce254";
const C3: &str = "933ca6b5ed60df3df66121f0ab49a09e49efa45c613a86a3cecbf4c535cef2f83f72b42837b18e3572f2fdc2b74c331e2368a545cef54bdca081678ab0e9dd5348122459e0c034c851984d88ce610963d43cde6cfe73a67fbd5a63e8bfca96d0";
const P4: &str = "d7efdf988072881941db045a42882433817555128fbf5663e56081712ec7d212";
const C4: &str = "54ef0ff0629e1aaa7685a2806ab111cba76b52331f2642276736f415868eacb69ab2577f3bda0cbf72f879685f6ed25f";
const P5: &str = "dd7bf01a588bafb52c6cfba952e5d8fe35cc2b3f92b4730ae2474615157345ce";
const C5: &str = "356be70f110306d5c699bb834bb9d58d909e325924dfbec972e406e6f294dc63e1daebefe8a62a334facc8048ab4ad66";

#[test]
fn official_xx_vector_replays_exactly() {
    let (s_i, e_i, s_r, e_r) = (hex32(S_I), hex32(E_I), hex32(S_R), hex32(E_R));
    let (prologue, p1, c1, p2, c2, p3, c3) = (
        hexd(PROLOGUE),
        hexd(P1),
        hexd(C1),
        hexd(P2),
        hexd(C2),
        hexd(P3),
        hexd(C3),
    );

    // Initiator side reproduces messages 1 and 3 byte-for-byte.
    let mut init = NoiseXX::new_initiator_with_prologue(s_i, e_i, &prologue);
    let m1 = init.write_message_1(&p1).unwrap();
    assert_eq!(m1, c1, "message 1 mismatch");

    // Responder side reproduces message 2 byte-for-byte.
    let mut resp = NoiseXX::new_responder_with_prologue(s_r, e_r, &prologue);
    let payload_out = resp.read_message_1(&c1).unwrap();
    assert_eq!(payload_out, p1, "message 1 payload mismatch");
    let m2 = resp.write_message_2(&p2).unwrap();
    assert_eq!(m2, c2, "message 2 mismatch");

    // Initiator ingests message 2 (recovers static + payload), emits 3.
    let payload_out = init.read_message_2(&c2).unwrap();
    assert_eq!(payload_out, p2, "message 2 payload mismatch");
    assert_eq!(
        init.peer_static().unwrap(),
        blockchain_utils::curve::x25519::public_key(&s_r)
    );
    let m3 = init.write_message_3(&p3).unwrap();
    assert_eq!(m3, c3, "message 3 mismatch");

    // Responder ingests message 3, then transport messages decrypt.
    let payload_out = resp.read_message_3(&c3).unwrap();
    assert_eq!(payload_out, p3, "message 3 payload mismatch");
    assert_eq!(
        resp.peer_static().unwrap(),
        blockchain_utils::curve::x25519::public_key(&s_i)
    );

    // Handshake hashes agree (not in the vector file — cross-checked).
    let mut ta = init.split().unwrap();
    let mut tb = resp.split().unwrap();
    assert_eq!(ta.handshake_hash(), tb.handshake_hash());

    // Transport direction (snow harness keeps the message index running:
    // handshake msgs are 0,1,2, so index 3 is odd => responder sends
    // first): C4 = resp->init (k2), C5 = init->resp (k1).
    let (p4, c4, p5, c5) = (hexd(P4), hexd(C4), hexd(P5), hexd(C5));
    assert_eq!(ta.decrypt(&c4).unwrap(), p4, "transport r->i mismatch");
    assert_eq!(tb.decrypt(&c5).unwrap(), p5, "transport i->r mismatch");
    // And our encryption reproduces the vector ciphertexts exactly.
    assert_eq!(
        tb.encrypt(&p4).unwrap(),
        c4,
        "transport r->i encrypt mismatch"
    );
    assert_eq!(
        ta.encrypt(&p5).unwrap(),
        c5,
        "transport i->r encrypt mismatch"
    );
}
