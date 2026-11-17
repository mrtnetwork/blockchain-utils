# blockchain-utils

Pure `no_std`, zero-dependency cryptographic and blockchain utilities with constant-time primitives.

Core library has **zero required dependencies**. Optional `wasm-bindgen` is only pulled in under the `wasm` feature. Suitable for bare metal, `wasm32-unknown-unknown`, native hosts, native FFI (`cdylib`), and WASM builds.

## Features

- `no_std` compatible (`--no-default-features --features alloc` for pure `no_std` + alloc)
- Constant-time operations where secrets are involved (`ct`, `bytes`)
- Hash: SHA-1, SHA-2, Keccak/SHA-3, BLAKE2b/s, HMAC, HKDF, PBKDF2, scrypt, MD4/MD5, RIPEMD-160
- Fields and curves: secp256k1, secp256r1, Ed25519/Ristretto, BLS12-381, JubJub, Pallas/Vesta, BN254 Fr
- Signatures: ECDSA, Schnorr/BIP-340, EdDSA, BLS, RedDSA, ML-DSA, Schnorrkel
- Threshold / multisig: BIP-327 MuSig2, FROST (RFC 9591, secp256k1 + Ed25519), DKLS23
- AEAD / ciphers: AES-GCM, ChaCha20-Poly1305, XSalsa20-Poly1305, NaCl `crypto_box`, AES-ECB/CBC/CTR
- Zero-knowledge: Groth16 verifier (BLS12-381), Orchard Halo2 implementation, Solana confidential-transfer ZK (Twisted ElGamal + Bulletproofs), circomlib-compatible Poseidon-BN254, Zcash Sapling/Orchard/IncrementalMerkle
- Monero: Bulletproofs+ prove/verify and output scanning
- Hardware wallets: APDU / Trezor / UR / PSBT codecs + unified `HardwareWallet` interface (transport injected by `ffi`/`wasm`, nothing in `hw` touches hardware)
- C ABI exports for native FFI (`ffi` feature) and `wasm-bindgen` exports for web (`wasm` feature)

## Installation

Requires Rust 2021 edition.

```toml
[dependencies]
blockchain-utils = { version = "0.1.0", default-features = false, features = ["alloc"] }
```

Default (host) build with everything on:

```toml
[dependencies]
blockchain-utils = "0.1.0"
```

Build from source:

```sh
cargo build
cargo build --no-default-features --features alloc   # pure no_std + alloc
cargo build --no-default-features                    # core only, no alloc
```

## Usage

```rust
use blockchain_utils::hash::sha256::sha256;
use blockchain_utils::hash::keccak::keccak256;

let digest = sha256(b"hello").unwrap();
let eth_hash = keccak256(b"hello").unwrap();
```

Hex (requires `alloc`):

```rust
use blockchain_utils::{hex_encode, hex_decode};

let s = hex_encode(&[0xde, 0xad, 0xbe, 0xef]);
let bytes = hex_decode(&s).unwrap();
```

Constant-time helpers:

```rust
use blockchain_utils::{ct_eq_bool, secure_eq};

assert!(ct_eq_bool(&[1u8, 2, 3], &[1u8, 2, 3]));
assert!(secure_eq(&[1u8], &[1u8]));
```

Feature-gated modules (check `Cargo.toml` / `src/lib.rs`):

```rust
#[cfg(feature = "monero")]
{
    // blockchain_utils::monero::...
}

#[cfg(feature = "solana-zk")]
{
    // blockchain_utils::solana_zk::...
}
```

## Feature flags

| Flag | Default | Description |
|------|---------|-------------|
| `std` | on | `std` support (implies `alloc`) |
| `alloc` | on (via `std`) | Allocation-requiring APIs |
| `ffi` | on | C ABI exports for native (`.so`/`cdylib`) |
| `wasm` | off | `wasm-bindgen` exports for web |
| `groth16` | on | Groth16 verifier (BLS12-381) |
| `groth16-prover` | on (via `zcash-full`) | Groth16 prover machinery |
| `poseidon-bn254` | on | circomlib-compatible Poseidon over BN254 Fr (~404 KB tables) |
| `multicore` | on | Parallel MSM/FFT for native proving (OS threads, not for wasm32) |
| `solana-zk` | on | Solana confidential-transfer ZK (Token-2022 compatible) |
| `orchard-halo2` / `zcash-halo2` | on (via `zcash-full`) | Orchard Halo2 circuits |
| `zcash-sapling` | on (via `zcash-full`) | Sapling prove/verify |
| `zcash-incrementalmerkle` | on (via `zcash-full`) | Frontier Merkle contexts (Sapling/Orchard/Ironwood) |
| `zcash-full` | on | All of the above Zcash modules |
| `monero` | on | Bulletproofs+ and output scanning |
| `hw` | off | Hardware-wallet codecs + `HardwareWallet` trait |

Minimal `no_std` build: `--no-default-features --features alloc`.
Table generators: see `examples/gen_pedersen_tables.rs`, `examples/gen_poseidon_bn254_tables.rs`, `examples/gen_solana_bsgs_table.rs`.

## Module overview

| Module | Description |
|--------|-------------|
| `error` | Crate-wide `Error` / `Result` |
| `ct`, `bytes` | Constant-time helpers, secure compare/zeroize |
| `rng` | Deterministic ChaCha20 RNG |
| `hash` | SHA-2, Keccak, BLAKE2, HMAC, HKDF, … |
| `field`, `curve` | Prime fields; secp256k1, Ed25519, BLS, Pasta, … |
| `signature` | ECDSA, Schnorr, EdDSA, BLS, PQ (ML-DSA) |
| `aead`, `cipher` | AES-GCM, ChaCha20-Poly1305, XSalsa20, AES-ECB/CBC/CTR |
| `encoding` | Hex |
| `keys`, `merlin`, `strobe` | Key helpers, Merlin/Strobe transcripts |
| `musig2`, `frost`, `dkls23`, `schnorrkel` | Multisig / threshold schemes |
| `zk` | Groth16, Orchard Halo2, IncrementalMerkle |
| `monero` | Bulletproofs+, output scanning |
| `solana_zk` | Twisted ElGamal + Bulletproofs + Sigma proofs |
| `hw` | APDU / Trezor / UR / PSBT codecs, `HardwareWallet` trait |
| `connector` | C ABI (`ffi`) / wasm-bindgen (`wasm`) exports |
| `multicore` | Parallel MSM/FFT helpers |

## Testing

```sh
cargo test
cargo test --no-default-features --features alloc
cargo test --all-features
```

Known-answer / vector tests live in `tests/kats/` (`tests/vectors/`), plus differential tests (`tests/diff/`), HW codec tests (`tests/hw/`), threshold tests (`tests/dkls23/`), and Groth16 compat tests (`tests/benches/`). CI: `.github/workflows/ci.yml`, helpers `scripts/ci_kats.sh`, `scripts/ci_p0.sh`.

Release profile uses LTO + `strip = true`; debug symbols are archived per release for symbolication.

## Security

Constant-time primitives are used for secret data, with timing/static-analysis harnesses under `scripts/` (`timing_harness/`, `timing_scalar_mul.sh`, `sidechannel_static.sh`). This is cryptographic code: audit before production use with real funds. No warranty.

## License

MIT license ([LICENSE-MIT](LICENSE-MIT)).

## Support

<details>
<summary><b>Support This Project — Click to show wallets</b></summary>

<br>

If this project helped you, consider supporting:

| Network | Address |
|---------|---------|
| ETH / EVM | `0xDdEDf30f96E6e2674Fab476bfC36201074081bcC` |
| TRON / TRC20 | `TDfY8zN3sobm2agzCmzzTYj7r4xxeVtcDL` |
| SOL | `BeV1GsY9W7hNBRqQasnq9LjFJPCwkqVghuNH7Yq7vp3d` |
| ADA | `addr1q83pedgpuka83q7rmfk2x3mepeq53x7fgucptye93d0sr9rj08fhhkk3ymxa59ydsrtg5ky5fe437ncw2mp7cnplsc0qwj0lzv` |
| SUI | `0xaaba244910f612f37d2cc090f9c78235753925c2ade5e2b1e79dc5d18ef4aa59` |
| APTOS | `0xfbdf4caecade57dafb08f633e2f4ef1518644b396b11f39026a0571ae6691b70` |
| TON | `UQCXNPerK6BKJng7h-Ph6Up4d6GlAFdXUrEL-5Fc9zAYhdFO` |
| BTC | `bc1q92fvc5jm4k8e5wegzmhzdv72gwe43sgfnuspgzfmj7llkd8xhmusgd44qf` |
| STELLAR | `GAMSM5WVDFDLEEG7W3D64AJGN75IX7PVXXOT7WIX4NKT4SS2ERF4N2XN` |

Thank you!

</details>
