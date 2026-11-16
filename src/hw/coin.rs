//! Coin profiles: SLIP44 id + curve + derivation rules.
//!
//! mirrors the reference implementation
//! Address *encoding* itself lives in `crate::encoding`; this table only says
//! *which curve* and *which path shape* a coin needs, so HW requests can be
//! built and validated without a device.

use crate::keys::CryptoKeyType;

/// Curve family relevant for HW derivation policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum HwCurve {
    /// BIP32 secp256k1 (allows non-hardened suffix `0'/0/0`).
    Secp256k1,
    /// SLIP10 secp256k1 (same math, hardened-only devices e.g. Ledger Tezos app).
    Secp256k1Slip10,
    /// SLIP10 ed25519 (hardened-only, e.g. Solana `0'`, Tezos tz1 `0'/0'`).
    Ed25519,
    /// SLIP10 NIST P-256 (hardened-only, e.g. Tezos tz3).
    Nist256p1,
    /// Cardano Kholaw / Icarus (Byron). Not on Ledger/Trezor generic apps.
    Ed25519Kholaw,
    /// sr25519 / BLS / PQC: no generic HW support in v1.
    Unsupported,
}

impl HwCurve {
    /// True when non-hardened child indexes may appear after account'.
    pub const fn allows_unhardened_suffix(self) -> bool {
        matches!(self, Self::Secp256k1)
    }

    /// Map from crate key type.
    pub const fn from_key_type(t: CryptoKeyType) -> Self {
        match t {
            CryptoKeyType::Secp256k1 => Self::Secp256k1,
            CryptoKeyType::Ed25519
            | CryptoKeyType::Ed25519Blake2b
            | CryptoKeyType::Ed25519Monero => Self::Ed25519,
            CryptoKeyType::Nist256p1 | CryptoKeyType::Nist256p1Hybrid => Self::Nist256p1,
            CryptoKeyType::Ed25519Kholaw => Self::Ed25519Kholaw,
            _ => Self::Unsupported,
        }
    }
}

/// Minimal per-coin HW profile (`BipCoinConfig` subset).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoinProfile {
    /// Short id, e.g. `"btc"`, `"xtz-tz1"`.
    pub id: &'static str,
    /// SLIP44 coin type, e.g. 0, 60, 1729, 501.
    pub slip44: u32,
    /// Curve / derivation policy.
    pub curve: HwCurve,
    /// Crate key type (for cross-checks).
    pub key_type: CryptoKeyType,
    /// Default suffix after `m/purpose'/slip44'/account'`, e.g. `"0'/0/0"`.
    pub def_suffix: &'static str,
    /// Native suffix variant where different (e.g. Tezos `"0'/0'"`).
    /// `None` means same as `def_suffix`.
    pub native_suffix: Option<&'static str>,
    /// BIP purpose, usually 44 (49/84/86 for BTC variants).
    pub purpose: u32,
}

impl CoinProfile {
    pub const fn new(
        id: &'static str,
        slip44: u32,
        key_type: CryptoKeyType,
        curve: HwCurve,
        purpose: u32,
        def_suffix: &'static str,
    ) -> Self {
        Self {
            id,
            slip44,
            curve,
            key_type,
            def_suffix,
            native_suffix: None,
            purpose,
        }
    }

    pub const fn with_native(mut self, suffix: &'static str) -> Self {
        self.native_suffix = Some(suffix);
        self
    }

    /// Suffix actually used (`native` selects `native_suffix` when present).
    pub const fn suffix(self, native: bool) -> &'static str {
        match (native, self.native_suffix) {
            (true, Some(s)) => s,
            _ => self.def_suffix,
        }
    }

    // ---- well-known coins (SLIP44 ids match `Slip44`) ----
    pub const BITCOIN: Self = Self::new(
        "btc",
        0,
        CryptoKeyType::Secp256k1,
        HwCurve::Secp256k1,
        44,
        "0'/0/0",
    );
    pub const BITCOIN_SEGWIT: Self = Self::new(
        "btc-segwit",
        0,
        CryptoKeyType::Secp256k1,
        HwCurve::Secp256k1,
        84,
        "0'/0/0",
    );
    pub const BITCOIN_TAPROOT: Self = Self::new(
        "btc-taproot",
        0,
        CryptoKeyType::Secp256k1,
        HwCurve::Secp256k1,
        86,
        "0'/0/0",
    );
    pub const ETHEREUM: Self = Self::new(
        "eth",
        60,
        CryptoKeyType::Secp256k1,
        HwCurve::Secp256k1,
        44,
        "0'/0/0",
    );
    pub const TRON: Self = Self::new(
        "trx",
        195,
        CryptoKeyType::Secp256k1,
        HwCurve::Secp256k1,
        44,
        "0'/0/0",
    );
    pub const RIPPLE: Self = Self::new(
        "xrp",
        144,
        CryptoKeyType::Secp256k1,
        HwCurve::Secp256k1,
        44,
        "0'/0/0",
    );
    pub const COSMOS: Self = Self::new(
        "atom",
        118,
        CryptoKeyType::Secp256k1,
        HwCurve::Secp256k1,
        44,
        "0'/0/0",
    );
    pub const FILECOIN_SECP: Self = Self::new(
        "fil-secp",
        461,
        CryptoKeyType::Secp256k1,
        HwCurve::Secp256k1,
        44,
        "0'/0/0",
    );
    pub const TEZOS_TZ1: Self = Self::new(
        "xtz-tz1",
        1729,
        CryptoKeyType::Ed25519,
        HwCurve::Ed25519,
        44,
        "0'/0'",
    )
    .with_native("0'/0'");
    pub const TEZOS_TZ2: Self = Self::new(
        "xtz-tz2",
        1729,
        CryptoKeyType::Secp256k1,
        HwCurve::Secp256k1Slip10,
        44,
        "0'/0'",
    )
    .with_native("0'/0'");
    pub const TEZOS_TZ3: Self = Self::new(
        "xtz-tz3",
        1729,
        CryptoKeyType::Nist256p1,
        HwCurve::Nist256p1,
        44,
        "0'/0'",
    )
    .with_native("0'/0'");
    pub const SOLANA: Self = Self::new(
        "sol",
        501,
        CryptoKeyType::Ed25519,
        HwCurve::Ed25519,
        44,
        "0'",
    );
    pub const APTOS: Self = Self::new(
        "apt",
        637,
        CryptoKeyType::Ed25519,
        HwCurve::Ed25519,
        44,
        "0'/0'/0'",
    );
    pub const SUI_ED: Self = Self::new(
        "sui-ed",
        784,
        CryptoKeyType::Ed25519,
        HwCurve::Ed25519,
        44,
        "0'/0'/0'",
    );
    pub const NEAR: Self = Self::new(
        "near",
        397,
        CryptoKeyType::Ed25519,
        HwCurve::Ed25519,
        44,
        "0'",
    );
    pub const STELLAR: Self = Self::new(
        "xlm",
        148,
        CryptoKeyType::Ed25519,
        HwCurve::Ed25519,
        44,
        "0'",
    );
    pub const POLKADOT_SLIP: Self = Self::new(
        "dot-slip",
        354,
        CryptoKeyType::Ed25519,
        HwCurve::Ed25519,
        44,
        "0'/0'/0'",
    );
    pub const CARDANO_ICARUS: Self = Self::new(
        "ada-icarus",
        1815,
        CryptoKeyType::Ed25519Kholaw,
        HwCurve::Ed25519Kholaw,
        44,
        "0'/0/0",
    );
    pub const MONERO_SLIP: Self = Self::new(
        "xmr-slip",
        128,
        CryptoKeyType::Ed25519,
        HwCurve::Ed25519,
        44,
        "0'/0'/0'",
    );
    /// Zcash transparent ONLY (t-addrs, BTC-like P2PKH flow).
    /// Shielded (Sapling/Orchard/ZIP32) exists on no hardware wallet.
    pub const ZCASH_TRANSPARENT: Self = Self::new(
        "zec-t",
        133,
        CryptoKeyType::Secp256k1,
        HwCurve::Secp256k1,
        44,
        "0'/0/0",
    );
    /// Bitcoin testnet (SLIP44 1) for Ledger test builds / regtest flows.
    /// Appended LAST — `WELL_KNOWN_COINS` order is a wire-stable FFI id.
    pub const BITCOIN_TESTNET: Self = Self::new(
        "btc-testnet",
        1,
        CryptoKeyType::Secp256k1,
        HwCurve::Secp256k1,
        44,
        "0'/0/0",
    );
}

/// All v1 profiles (matches the reference implementation.
pub const WELL_KNOWN_COINS: &[CoinProfile] = &[
    CoinProfile::BITCOIN,
    CoinProfile::BITCOIN_SEGWIT,
    CoinProfile::BITCOIN_TAPROOT,
    CoinProfile::ETHEREUM,
    CoinProfile::TRON,
    CoinProfile::RIPPLE,
    CoinProfile::COSMOS,
    CoinProfile::FILECOIN_SECP,
    CoinProfile::TEZOS_TZ1,
    CoinProfile::TEZOS_TZ2,
    CoinProfile::TEZOS_TZ3,
    CoinProfile::SOLANA,
    CoinProfile::APTOS,
    CoinProfile::SUI_ED,
    CoinProfile::NEAR,
    CoinProfile::STELLAR,
    CoinProfile::POLKADOT_SLIP,
    CoinProfile::CARDANO_ICARUS,
    CoinProfile::MONERO_SLIP,
    CoinProfile::ZCASH_TRANSPARENT,
    CoinProfile::BITCOIN_TESTNET,
];

/// Find profile by `id`.
pub fn find_coin(id: &str) -> Option<CoinProfile> {
    WELL_KNOWN_COINS.iter().find(|c| c.id == id).copied()
}
