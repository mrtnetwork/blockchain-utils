//! Key-type enumeration (parity with `CryptoKeyType`).

/// Algorithm / curve identifier for a key.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum CryptoKeyType {
    /// Ed25519 (RFC 8032).
    Ed25519,
    /// Ed25519 with Blake2b prehash (Cardano-style).
    Ed25519Blake2b,
    /// Ed25519 Kholaw (Cardano Byron / Icarus).
    Ed25519Kholaw,
    /// Ed25519 Monero variant.
    Ed25519Monero,
    /// NIST P-256 / secp256r1.
    Nist256p1,
    /// NIST P-256 hybrid derivation mode.
    Nist256p1Hybrid,
    /// secp256k1.
    Secp256k1,
    /// Schnorrkel / sr25519 (Ristretto).
    Sr25519,
    /// BLS12-381 G1 key.
    Bls12G1,
    /// BLS12-381 G2 key.
    Bls12G2,
    /// BLS12-381 G1 aggregate mode.
    Bls12G1Aggregate,
    /// BLS12-381 G2 aggregate mode.
    Bls12G2Aggregate,
    /// ML-DSA / Dilithium (NIST PQC).
    MlDsa,
    /// RedDSA Pallas binding key (Zcash Orchard).
    RedPallasBinding,
    /// RedDSA Pallas spend key.
    RedPallasSpend,
    /// RedDSA Jubjub binding key (Zcash Sapling).
    RedJubjubBinding,
    /// RedDSA Jubjub spend key.
    RedJubjubSpend,
    /// DKLs23 threshold ECDSA over secp256k1.
    Dkls23K1,
    /// DKLs23 threshold ECDSA over secp256r1 (NIST P-256).
    Dkls23R1,
}

impl CryptoKeyType {
    /// Human-readable name (matches the reference implementation.name` style where possible).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::Ed25519Blake2b => "ed25519Blake2b",
            Self::Ed25519Kholaw => "ed25519Kholaw",
            Self::Ed25519Monero => "ed25519Monero",
            Self::Nist256p1 => "nist256p1",
            Self::Nist256p1Hybrid => "nist256p1Hybrid",
            Self::Secp256k1 => "secp256k1",
            Self::Sr25519 => "sr25519",
            Self::Bls12G1 => "bls12G1",
            Self::Bls12G2 => "bls12G2",
            Self::Bls12G1Aggregate => "bls12G1Aggregate",
            Self::Bls12G2Aggregate => "bls12G2Aggregate",
            Self::MlDsa => "mldsa",
            Self::RedPallasBinding => "redPallasBinding",
            Self::RedPallasSpend => "redPallasSpend",
            Self::RedJubjubBinding => "redJubjubBinding",
            Self::RedJubjubSpend => "redJubjubSpend",
            Self::Dkls23K1 => "dkls23K1",
            Self::Dkls23R1 => "dkls23R1",
        }
    }

    /// True for any Ed25519-family variant.
    pub const fn is_ed25519_family(self) -> bool {
        matches!(
            self,
            Self::Ed25519 | Self::Ed25519Blake2b | Self::Ed25519Kholaw | Self::Ed25519Monero
        )
    }

    /// True when this crate has a working implementation.
    pub const fn is_implemented(self) -> bool {
        matches!(
            self,
            Self::Secp256k1
                | Self::Nist256p1
                | Self::Ed25519
                | Self::Sr25519
                | Self::Dkls23K1
                | Self::Dkls23R1
        )
    }
}

/// ECDSA signature wire encoding (`ECDSASignatureEncoding`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EcdsaSignatureEncoding {
    /// Raw `r || s` (32+32).
    Raw,
    /// `r || s || recovery_id` (suffix).
    SuffixRecoveryId,
    /// `recovery_id || r || s` (prefix).
    PrefixRecoveryId,
    /// Ethereum legacy (homestead) encoding.
    EthereumLegacy,
    /// ASN.1 DER.
    Der,
}
