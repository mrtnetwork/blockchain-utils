//! Sinsemilla hash-to-group (Zcash Orchard / NU5).
//!
//! Spec: https://zips.z.cash/protocol/nu5.pdf#concretesinsemillahash
//!
//! S[0..1024] are **compile-time `PallasPoint` constants** (affine Montgomery limbs)
//! in `sinsemilla_s_points.rs` — no runtime hash-to-curve, no `std`, no decompress cache.

use crate::curve::pallas::{hash_to_curve_pasta, to_bytes_pasta, PallasPoint};
use crate::curve::traits::CurvePoint;
use crate::hash::HashResult;

/// Chunk bit-width.
pub const K: usize = 10;
/// Max chunks (Orchard).
pub const C: usize = 253;

const Q_PERSONALIZATION: &str = "z.cash:SinsemillaQ";
// Test-only (S-domain spot checks below).
#[cfg(test)]
const S_PERSONALIZATION: &str = "z.cash:SinsemillaS";

/// Number of S generators (`1 << K`).
pub const S_TABLE_LEN: usize = 1 << K;

/// Compile-time S table as `PallasPoint` (always linked; no_std).
mod s_points {
    include!("sinsemilla_s_points.rs");
}

/// Look up S[idx] — pure const table, zero runtime generation.
#[inline]
fn s_point(idx: usize) -> PallasPoint {
    s_points::S_POINTS[idx]
}

/// Public S[idx] for circuit fixed/lookup table loading (Orchard Sinsemilla).
#[inline]
pub fn s_generator(idx: usize) -> PallasPoint {
    assert!(idx < S_TABLE_LEN);
    s_point(idx)
}

#[inline]
fn r_base_for(domain: &str) -> PallasPoint {
    let mut r_prefix = alloc::string::String::from(domain);
    r_prefix.push_str("-r");
    hash_to_curve_pasta(&r_prefix, &[])
}

#[inline]
fn q_for_domain(domain: &str) -> PallasPoint {
    hash_to_curve_pasta(Q_PERSONALIZATION, domain.as_bytes())
}

/// Sinsemilla hasher for a fixed domain string.
#[derive(Clone, Copy, Debug)]
pub struct Sinsemilla {
    q: PallasPoint,
}

/// Orchard MerkleCRH domain point as a compile-time constant (from the
/// `@generated` `SINS_MERKLE_Q` limbs): domain derivation runs zero times
/// at runtime instead of once per tree combine. Same single-home rule as
/// the Pedersen tables — no per-call `from_domain`, no `OnceLock`.
pub(crate) const MERKLE_CRH: Sinsemilla = Sinsemilla {
    q: PallasPoint::from_affine_mont_limbs(
        crate::hash::pedersen_tables::SINS_MERKLE_Q.0,
        crate::hash::pedersen_tables::SINS_MERKLE_Q.1,
    ),
};

impl Sinsemilla {
    /// `HashDomain.fromDomain(domain)` — Q from domain UTF-8 bytes.
    pub fn from_domain(domain: &str) -> HashResult<Self> {
        let q = q_for_domain(domain);
        Ok(Self { q })
    }

    /// Montgomery `(x, y)` limbs of the domain point, for `@generated`
    /// constant tables (`hash::pedersen_tables::SINS_MERKLE_Q`).
    pub fn domain_point_limbs(&self) -> ([u64; 4], [u64; 4]) {
        // Infallible for non-identity domain points.
        self.q
            .to_affine_mont_limbs()
            .unwrap_or(([0u64; 4], [0u64; 4]))
    }

    /// Hash a bit-string (`'0'`/`'1'` ASCII as in reference vectors).
    pub fn hash_bitstring(&self, bits: &str) -> PallasPoint {
        let mut bools = alloc::vec::Vec::with_capacity(bits.len() + K);
        for c in bits.chars() {
            bools.push(c == '1');
        }
        self.hash_bits(&bools)
    }

    /// Hash boolean bits with Sinsemilla padding to a multiple of K.
    ///
    /// Always produces a point (complete addition). Prefer [`try_hash_bits`]
    /// when matching the reference implementation.
    pub fn hash_bits(&self, msg: &[bool]) -> PallasPoint {
        self.try_hash_bits(msg)
            .unwrap_or_else(PallasPoint::identity)
    }

    ///  incomplete accumulation: returns `None` when an
    /// intermediate sum would use identity or `P == ±Q` (see `_IncompletePoint`).
    /// Incomplete addition matching `sinsemilla` crate / protocol:
    /// ⊥ if either is ∞ or x-coordinates equal (P = ±Q).
    fn incomplete_add(p: &PallasPoint, q: &PallasPoint) -> Option<PallasPoint> {
        if p.ct_is_identity() == 1 || q.ct_is_identity() == 1 {
            return None;
        }
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        let mut c = [0u8; 32];
        p.to_bytes_compressed(&mut a).ok()?;
        q.to_bytes_compressed(&mut b).ok()?;
        q.neg().to_bytes_compressed(&mut c).ok()?;
        // Same compressed encoding ⇒ same point; same x different y ⇒ P = −Q
        // Pasta: x is LE in low 255 bits; equal x (ignore sign bit) ⇒ ⊥
        let mut ax = a;
        let mut bx = b;
        ax[31] &= 0x7f;
        bx[31] &= 0x7f;
        if ax == bx {
            return None;
        }
        Some(p.add(q))
    }

    pub fn try_hash_bits(&self, msg: &[bool]) -> Option<PallasPoint> {
        let mut padded = alloc::vec::Vec::from(msg);
        let rem = padded.len() % K;
        if rem != 0 {
            padded.extend(core::iter::repeat_n(false, K - rem));
        }
        // Upstream: fold (acc + S) + acc  (two incomplete adds)
        let mut acc: Option<PallasPoint> = Some(self.q);
        let mut i = 0;
        while i + K <= padded.len() {
            let mut idx: usize = 0;
            for j in 0..K {
                if padded[i + j] {
                    idx |= 1 << j;
                }
            }
            let cur = acc?;
            let s = s_point(idx);
            let t = Self::incomplete_add(&cur, &s)?;
            acc = Self::incomplete_add(&t, &cur);
            i += K;
        }
        acc
    }

    /// Hash whole bytes as little-endian bits (LSB first within each byte).
    pub fn hash_bytes(&self, msg: &[u8]) -> PallasPoint {
        let mut bits = alloc::vec::Vec::with_capacity(msg.len() * 8);
        for &b in msg {
            for i in 0..8 {
                bits.push(((b >> i) & 1) == 1);
            }
        }
        self.hash_bits(&bits)
    }
}

/// One-shot under domain string.
pub fn sinsemilla_hash(domain: &str, msg_bits: &str) -> HashResult<PallasPoint> {
    Ok(Sinsemilla::from_domain(domain)?.hash_bitstring(msg_bits))
}

/// Orchard / NU5 Sinsemilla commitment (protocol §5.4.8.4).
///
/// Matches `CommitDomainNative.create(domain)`:
/// - `Q = H2C("z.cash:SinsemillaQ", UTF8(domain || "-M"))`
/// - `R = H2C(domain || "-r", [])`
/// - `Commit = HashToPoint(msg) + [r] R`
pub fn sinsemilla_commit(
    domain: &str,
    msg_bits: &[bool],
    r_scalar_le: &[u8; 32],
) -> HashResult<PallasPoint> {
    use crate::curve::pallas::Scalar;
    use crate::hash::HashError;

    let m_domain = {
        let mut s = alloc::string::String::from(domain);
        s.push_str("-M");
        s
    };
    let hasher = Sinsemilla::from_domain(&m_domain)?;
    let h = match hasher.try_hash_bits(msg_bits) {
        Some(p) => p,
        None => return Err(HashError::Failure("sinsemilla_null")),
    };

    let r_base = r_base_for(domain);
    let r = Scalar::from_bytes_le(r_scalar_le).map_err(|_| HashError::InvalidLength)?;
    Ok(h.add(&r_base.mul(&r)))
}

/// `shortCommit` = affine *x* of [`sinsemilla_commit`] (LE 32-byte field element).
pub fn sinsemilla_short_commit(
    domain: &str,
    msg_bits: &[bool],
    r_scalar_le: &[u8; 32],
) -> HashResult<[u8; 32]> {
    let p = sinsemilla_commit(domain, msg_bits, r_scalar_le)?;
    // Pasta compressed: LE x with y-sign in high bit of byte 31; p < 2^255 so clear sign.
    let mut x_le = to_bytes_pasta(&p);
    x_le[31] &= 0x7f;
    Ok(x_le)
}

/// Convenience: bits encoded as ASCII `'0'`/`'1'` string (same as hash vectors).
pub fn sinsemilla_commit_bitstring(
    domain: &str,
    bits: &str,
    r_scalar_le: &[u8; 32],
) -> HashResult<PallasPoint> {
    let mut bools = alloc::vec::Vec::with_capacity(bits.len());
    for c in bits.chars() {
        bools.push(c == '1');
    }
    sinsemilla_commit(domain, &bools, r_scalar_le)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::pallas::{from_bytes_pasta, to_bytes_pasta};

    #[test]
    fn sinsemilla_deterministic() {
        let a = sinsemilla_hash("test", "1010").unwrap();
        let b = sinsemilla_hash("test", "1010").unwrap();
        assert_eq!(to_bytes_pasta(&a), to_bytes_pasta(&b));
    }

    #[test]
    fn sinsemilla_domain_sep() {
        let a = to_bytes_pasta(&sinsemilla_hash("dom-a", "1").unwrap());
        let b = to_bytes_pasta(&sinsemilla_hash("dom-b", "1").unwrap());
        assert_ne!(a, b);
    }

    #[test]
    fn s_table_distinct() {
        let p0 = s_point(0);
        let p1 = s_point(1);
        assert_ne!(to_bytes_pasta(&p0), to_bytes_pasta(&p1));
    }

    #[test]
    fn s0_matches_compressed_table() {
        mod c {
            include!("sinsemilla_s_table.rs");
        }
        let p = s_point(0);
        assert_eq!(to_bytes_pasta(&p), c::S_TABLE_COMPRESSED[0]);
        let p10 = s_point(10);
        assert_eq!(to_bytes_pasta(&p10), c::S_TABLE_COMPRESSED[10]);
    }

    #[test]
    fn pasta_roundtrip_s0() {
        let p = hash_to_curve_pasta(S_PERSONALIZATION, &0u32.to_le_bytes());
        let b = to_bytes_pasta(&p);
        let q = from_bytes_pasta(&b).unwrap();
        assert_eq!(to_bytes_pasta(&p), to_bytes_pasta(&q));
    }
}

#[cfg(all(test, feature = "std"))]
mod gen_s_table {
    use crate::curve::pallas::{from_bytes_pasta, to_bytes_pasta};
    use std::io::Write;

    /// Emit `sinsemilla_s_points.rs` from compressed bytes (no H2C).
    /// `cargo test -p blockchain-utils --lib --features std gen_s_table -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn generate_s_point_const_file() {
        // Prefer existing compressed table if present; else derive via H2C.
        let compressed: [[u8; 32]; 1024] = {
            mod c {
                include!("sinsemilla_s_table.rs");
            }
            c::S_TABLE_COMPRESSED
        };
        let path = std::env::temp_dir().join("sinsemilla_s_points.rs");
        let mut f = std::fs::File::create(&path).expect("create");
        writeln!(
            f,
            "// @generated — Sinsemilla S[0..1024] as affine Montgomery PallasPoint."
        )
        .unwrap();
        writeln!(
            f,
            "// S[i] = hash_to_curve(\"z.cash:SinsemillaS\", i_le). Do not edit."
        )
        .unwrap();
        writeln!(f, "use crate::curve::pallas::PallasPoint;").unwrap();
        writeln!(f).unwrap();
        writeln!(f, "/// Compile-time S table (affine, z = R).").unwrap();
        writeln!(f, "pub static S_POINTS: [PallasPoint; 1024] = [").unwrap();
        for (i, c) in compressed.iter().enumerate().take(1024) {
            let p = from_bytes_pasta(c).expect("decompress S");
            let (x, y) = p.to_affine_mont_limbs().expect("affine");
            writeln!(
                f,
                "    PallasPoint::from_affine_mont_limbs({:?}, {:?}),",
                x, y
            )
            .unwrap();
            if i % 128 == 0 {
                eprintln!("S-points gen {i}/1024");
            }
        }
        writeln!(f, "];").unwrap();
        // Sanity: S[0] compressed matches
        let p0 = from_bytes_pasta(&compressed[0]).unwrap();
        assert_eq!(to_bytes_pasta(&p0), compressed[0]);
        eprintln!("wrote {}", path.display());
    }
}
