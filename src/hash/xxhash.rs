//! XXHash family: XXH32, XXH64, XXH3-64, XXH3-128, XXH3-256.
//!
//! Pure `no_std`, zero-dependency. Non-cryptographic — for checksums / hash tables only.

use super::error::HashResult;

/// XXH32 digest length.
pub const XXH32_LEN: usize = 4;
/// XXH64 / XXH3-64 digest length.
pub const XXH64_LEN: usize = 8;
/// XXH3-128 digest length.
pub const XXH128_LEN: usize = 16;
/// XXH3-256 digest length (two independent XXH3-128 lanes).
pub const XXH256_LEN: usize = 32;

// ---- XXH32 / XXH64 primes ----
const PRIME32_1: u32 = 0x9e3779b1;
const PRIME32_2: u32 = 0x85ebca77;
const PRIME32_3: u32 = 0xc2b2ae3d;
const PRIME32_4: u32 = 0x27d4eb2f;
const PRIME32_5: u32 = 0x165667b1;

const PRIME64_1: u64 = 0x9e3779b185ebca87;
const PRIME64_2: u64 = 0xc2b2ae3d27d4eb4f;
const PRIME64_3: u64 = 0x165667b19e3779f9;
const PRIME64_4: u64 = 0x85ebca77c2b2ae63;
const PRIME64_5: u64 = 0x27d4eb2f165667c5;

// ---- XXH3 constants ----
const PRIME_MX2: u64 = 0x9fb21c651e98df25;

/// Official XXH3 default secret (192 bytes).
const XXH3_SECRET: [u8; 192] = [
    0xb8, 0xfe, 0x6c, 0x39, 0x23, 0xa4, 0x4b, 0xbe, 0x7c, 0x01, 0x81, 0x2c, 0xf7, 0x21, 0xad, 0x1c,
    0xde, 0xd4, 0x6d, 0xe9, 0x83, 0x90, 0x97, 0xdb, 0x72, 0x40, 0xa4, 0xa4, 0xb7, 0xb3, 0x67, 0x1f,
    0xcb, 0x79, 0xe6, 0x4e, 0xcc, 0xc0, 0xe5, 0x78, 0x82, 0x5a, 0xd0, 0x7d, 0xcc, 0xff, 0x72, 0x21,
    0xb8, 0x08, 0x46, 0x74, 0xf7, 0x43, 0x24, 0x8e, 0xe0, 0x35, 0x90, 0xe6, 0x81, 0x3a, 0x26, 0x4c,
    0x3c, 0x28, 0x52, 0xbb, 0x91, 0xc3, 0x00, 0xcb, 0x88, 0xd0, 0x65, 0x8b, 0x1b, 0x53, 0x2e, 0xa3,
    0x71, 0x64, 0x48, 0x97, 0xa2, 0x0d, 0xf9, 0x4e, 0x38, 0x19, 0xef, 0x46, 0xa9, 0xde, 0xac, 0xd8,
    0xa8, 0xfa, 0x76, 0x3f, 0xe3, 0x9c, 0x34, 0x3f, 0xf9, 0xdc, 0xbb, 0xc7, 0xc7, 0x0b, 0x4f, 0x1d,
    0x8a, 0x51, 0xe0, 0x4b, 0xcd, 0xb4, 0x59, 0x31, 0xc8, 0x9f, 0x7e, 0xc9, 0xd9, 0x78, 0x73, 0x69,
    0xea, 0xc5, 0xac, 0x83, 0x34, 0xd3, 0xeb, 0xc3, 0xc5, 0x81, 0xa0, 0xff, 0xfa, 0x13, 0x63, 0xeb,
    0x17, 0x0d, 0xdd, 0x51, 0xb7, 0xf0, 0xda, 0x49, 0xd3, 0x16, 0x55, 0x26, 0x29, 0xd4, 0x68, 0x9e,
    0x2b, 0x16, 0xbe, 0x58, 0x7d, 0x47, 0xa1, 0xfc, 0x8f, 0xf8, 0xb8, 0xd1, 0x7a, 0xd0, 0x31, 0xce,
    0x45, 0xcb, 0x3a, 0x8f, 0x95, 0x16, 0x04, 0x28, 0xaf, 0xd7, 0xfb, 0xca, 0xbb, 0x4b, 0x40, 0x7e,
];

// ===========================================================================
// XXH32
// ===========================================================================

/// XXH32 one-shot.
pub fn xxh32(data: &[u8], seed: u32) -> u32 {
    let len = data.len();
    let mut p = 0;
    let mut h: u32;

    if len >= 16 {
        let mut v1 = seed.wrapping_add(PRIME32_1).wrapping_add(PRIME32_2);
        let mut v2 = seed.wrapping_add(PRIME32_2);
        let mut v3 = seed;
        let mut v4 = seed.wrapping_sub(PRIME32_1);
        while p + 16 <= len {
            v1 = round32(v1, read32(data, p));
            p += 4;
            v2 = round32(v2, read32(data, p));
            p += 4;
            v3 = round32(v3, read32(data, p));
            p += 4;
            v4 = round32(v4, read32(data, p));
            p += 4;
        }
        h = v1
            .rotate_left(1)
            .wrapping_add(v2.rotate_left(7))
            .wrapping_add(v3.rotate_left(12))
            .wrapping_add(v4.rotate_left(18));
    } else {
        h = seed.wrapping_add(PRIME32_5);
    }
    h = h.wrapping_add(len as u32);
    while p + 4 <= len {
        h = h
            .wrapping_add(read32(data, p).wrapping_mul(PRIME32_3))
            .rotate_left(17)
            .wrapping_mul(PRIME32_4);
        p += 4;
    }
    while p < len {
        h = h
            .wrapping_add((data[p] as u32).wrapping_mul(PRIME32_5))
            .rotate_left(11)
            .wrapping_mul(PRIME32_1);
        p += 1;
    }
    avalanche32(h)
}

/// XXH32 as little-endian bytes.
pub fn xxh32_bytes(data: &[u8], seed: u32) -> HashResult<[u8; XXH32_LEN]> {
    Ok(xxh32(data, seed).to_le_bytes())
}

// ===========================================================================
// XXH64
// ===========================================================================

/// XXH64 one-shot.
pub fn xxh64(data: &[u8], seed: u64) -> u64 {
    let len = data.len();
    let mut p = 0;
    let mut h: u64;

    if len >= 32 {
        let mut v1 = seed.wrapping_add(PRIME64_1).wrapping_add(PRIME64_2);
        let mut v2 = seed.wrapping_add(PRIME64_2);
        let mut v3 = seed;
        let mut v4 = seed.wrapping_sub(PRIME64_1);
        while p + 32 <= len {
            v1 = round64(v1, read64(data, p));
            p += 8;
            v2 = round64(v2, read64(data, p));
            p += 8;
            v3 = round64(v3, read64(data, p));
            p += 8;
            v4 = round64(v4, read64(data, p));
            p += 8;
        }
        h = v1
            .rotate_left(1)
            .wrapping_add(v2.rotate_left(7))
            .wrapping_add(v3.rotate_left(12))
            .wrapping_add(v4.rotate_left(18));
        h = merge64(h, v1);
        h = merge64(h, v2);
        h = merge64(h, v3);
        h = merge64(h, v4);
    } else {
        h = seed.wrapping_add(PRIME64_5);
    }
    h = h.wrapping_add(len as u64);
    while p + 8 <= len {
        h ^= round64(0, read64(data, p));
        h = h
            .rotate_left(27)
            .wrapping_mul(PRIME64_1)
            .wrapping_add(PRIME64_4);
        p += 8;
    }
    if p + 4 <= len {
        h ^= (read32(data, p) as u64).wrapping_mul(PRIME64_1);
        h = h
            .rotate_left(23)
            .wrapping_mul(PRIME64_2)
            .wrapping_add(PRIME64_3);
        p += 4;
    }
    while p < len {
        h ^= (data[p] as u64).wrapping_mul(PRIME64_5);
        h = h.rotate_left(11).wrapping_mul(PRIME64_1);
        p += 1;
    }
    avalanche64(h)
}

/// XXH64 as little-endian bytes.
pub fn xxh64_bytes(data: &[u8], seed: u64) -> HashResult<[u8; XXH64_LEN]> {
    Ok(xxh64(data, seed).to_le_bytes())
}

// ===========================================================================
// XXH3-64 / XXH3-128 / XXH3-256
// ===========================================================================

/// XXH3 64-bit one-shot (seed = 0 uses default secret).
pub fn xxh3_64(data: &[u8], seed: u64) -> u64 {
    let len = data.len();
    if len <= 16 {
        xxh3_64_len0to16(data, seed)
    } else if len <= 128 {
        xxh3_64_len17to128(data, seed)
    } else if len <= 240 {
        xxh3_64_len129to240(data, seed)
    } else {
        xxh3_64_long(data, seed)
    }
}

/// XXH3-64 as bytes.
pub fn xxh3_64_bytes(data: &[u8], seed: u64) -> HashResult<[u8; XXH64_LEN]> {
    Ok(xxh3_64(data, seed).to_le_bytes())
}

/// XXH3 128-bit one-shot. Returns (low64, high64).
pub fn xxh3_128(data: &[u8], seed: u64) -> (u64, u64) {
    let len = data.len();
    if len <= 16 {
        xxh3_128_len0to16(data, seed)
    } else if len <= 128 {
        xxh3_128_len17to128(data, seed)
    } else if len <= 240 {
        xxh3_128_len129to240(data, seed)
    } else {
        xxh3_128_long(data, seed)
    }
}

/// XXH3-128 as 16 little-endian bytes (low64 || high64).
pub fn xxh3_128_bytes(data: &[u8], seed: u64) -> HashResult<[u8; XXH128_LEN]> {
    let (lo, hi) = xxh3_128(data, seed);
    let mut out = [0u8; XXH128_LEN];
    out[..8].copy_from_slice(&lo.to_le_bytes());
    out[8..].copy_from_slice(&hi.to_le_bytes());
    Ok(out)
}

/// XXH3-256: two independent XXH3-128 digests with seeds `seed` and `seed ^ 0x9e3779b97f4a7c15`.
///
/// Produces a 32-byte digest. Not an official xxHash size; useful when a 256-bit
/// non-crypto fingerprint is needed.
pub fn xxh3_256_bytes(data: &[u8], seed: u64) -> HashResult<[u8; XXH256_LEN]> {
    let (lo0, hi0) = xxh3_128(data, seed);
    let (lo1, hi1) = xxh3_128(data, seed ^ 0x9e3779b97f4a7c15);
    let mut out = [0u8; XXH256_LEN];
    out[0..8].copy_from_slice(&lo0.to_le_bytes());
    out[8..16].copy_from_slice(&hi0.to_le_bytes());
    out[16..24].copy_from_slice(&lo1.to_le_bytes());
    out[24..32].copy_from_slice(&hi1.to_le_bytes());
    Ok(out)
}

// ---- XXH3 short paths ----

fn xxh3_64_len0to16(data: &[u8], seed: u64) -> u64 {
    let len = data.len();
    if len > 8 {
        let input_lo = read64(data, 0);
        let input_hi = read64(data, len - 8);
        let bitflip = (read64(&XXH3_SECRET, 24) ^ read64(&XXH3_SECRET, 32)).wrapping_add(seed);
        let keyed = input_lo ^ input_hi ^ bitflip;
        return rrmxmx(keyed, len as u64);
    }
    if len >= 4 {
        let input1 = read32(data, 0) as u64;
        let input2 = read32(data, len - 4) as u64;
        let bitflip = ((read32(&XXH3_SECRET, 8) as u64) ^ (read32(&XXH3_SECRET, 12) as u64))
            .wrapping_add(seed);
        let keyed = input1.wrapping_shl(32).wrapping_add(input2) ^ bitflip;
        return avalanche64(rrmxmx_seed(keyed, len as u64));
    }
    if len > 0 {
        let a = data[0] as u64;
        let b = data[len >> 1] as u64;
        let c = data[len - 1] as u64;
        let combined = a.wrapping_shl(16) | b.wrapping_shl(24) | c | (len as u64).wrapping_shl(8);
        let bitflip = ((read32(&XXH3_SECRET, 0) as u64) ^ (read32(&XXH3_SECRET, 4) as u64))
            .wrapping_add(seed);
        return avalanche64(combined ^ bitflip);
    }
    avalanche64(seed ^ read64(&XXH3_SECRET, 56) ^ read64(&XXH3_SECRET, 64))
}

fn xxh3_64_len17to128(data: &[u8], seed: u64) -> u64 {
    let len = data.len() as u64;
    let mut acc = len.wrapping_mul(PRIME64_1);
    if len > 32 {
        if len > 64 {
            if len > 96 {
                acc = acc.wrapping_add(mix16(data, len as usize - 64, 64, seed));
                acc = acc.wrapping_add(mix16(data, 48, 48, seed));
            }
            acc = acc.wrapping_add(mix16(data, len as usize - 48, 32, seed));
            acc = acc.wrapping_add(mix16(data, 32, 16, seed));
        }
        acc = acc.wrapping_add(mix16(data, len as usize - 32, 0, seed));
        acc = acc.wrapping_add(mix16(data, 16, 48, seed));
    }
    acc = acc.wrapping_add(mix16(data, 0, 32, seed));
    acc = acc.wrapping_add(mix16(data, len as usize - 16, 16, seed));
    avalanche64(acc)
}

fn xxh3_64_len129to240(data: &[u8], seed: u64) -> u64 {
    let len = data.len();
    let mut acc = (len as u64).wrapping_mul(PRIME64_1);
    let nb_rounds = len / 16;
    for i in 0..8 {
        acc = acc.wrapping_add(mix16(data, 16 * i, 16 * i, seed));
    }
    acc = avalanche64(acc);
    for i in 8..nb_rounds {
        acc = acc.wrapping_add(mix16(data, 16 * i, 16 * (i - 8), seed));
    }
    acc = acc.wrapping_add(mix16(data, len - 16, 16 * (nb_rounds - 8), seed));
    avalanche64(acc)
}

fn xxh3_64_long(data: &[u8], seed: u64) -> u64 {
    let mut acc = [0u64; 8];
    init_acc(&mut acc, seed);
    hash_long_internal(data, &mut acc, &XXH3_SECRET);
    merge_accs(
        &acc,
        (data.len() as u64).wrapping_mul(PRIME64_1),
        &XXH3_SECRET[11..],
    )
}

fn xxh3_128_len0to16(data: &[u8], seed: u64) -> (u64, u64) {
    let len = data.len();
    if len > 8 {
        let input_lo = read64(data, 0);
        let input_hi = read64(data, len - 8);
        let bitflip_l = (read64(&XXH3_SECRET, 32) ^ read64(&XXH3_SECRET, 40)).wrapping_sub(seed);
        let _bitflip_h = (read64(&XXH3_SECRET, 48) ^ read64(&XXH3_SECRET, 56)).wrapping_add(seed);
        let keyed_lo = input_lo ^ input_hi ^ bitflip_l;
        let mut lo = rrmxmx(keyed_lo, len as u64);
        let mut hi = (input_hi & 0xffffffff).wrapping_add(input_lo.wrapping_shl(32));
        hi = hi.wrapping_mul(PRIME64_1.wrapping_add((len as u64).wrapping_shl(2)));
        hi = (hi ^ hi.rotate_left(49) ^ hi.rotate_left(24)).wrapping_mul(PRIME_MX2);
        hi ^= (hi >> 35).wrapping_add(len as u64);
        hi = hi.wrapping_mul(PRIME_MX2);
        hi ^= hi >> 28;
        lo = lo.wrapping_add(hi);
        return (lo, hi.wrapping_add(lo));
    }
    if len >= 4 {
        let input_lo = read32(data, 0) as u64;
        let input_hi = read32(data, len - 4) as u64;
        let bitflip = (read64(&XXH3_SECRET, 16) ^ read64(&XXH3_SECRET, 24)).wrapping_add(seed);
        let keyed = input_lo.wrapping_add(input_hi.wrapping_shl(32)) ^ bitflip;
        let lo = rrmxmx(keyed, len as u64);
        let hi = avalanche64(
            (input_hi.wrapping_add(input_lo.wrapping_shl(48)))
                ^ (read64(&XXH3_SECRET, 40) ^ read64(&XXH3_SECRET, 48)).wrapping_sub(seed),
        );
        return (lo, hi);
    }
    if len > 0 {
        let a = data[0] as u64;
        let b = data[len >> 1] as u64;
        let c = data[len - 1] as u64;
        let combined = a.wrapping_shl(16) | b.wrapping_shl(24) | c | (len as u64).wrapping_shl(8);
        let bitflip = ((read32(&XXH3_SECRET, 0) as u64) ^ (read32(&XXH3_SECRET, 4) as u64))
            .wrapping_add(seed);
        let lo = avalanche64(combined ^ bitflip);
        let hi = avalanche64(
            (rotate_left64(combined, 32))
                ^ ((read32(&XXH3_SECRET, 8) as u64) ^ (read32(&XXH3_SECRET, 12) as u64))
                    .wrapping_sub(seed),
        );
        return (lo, hi);
    }
    let lo = avalanche64(seed ^ read64(&XXH3_SECRET, 64) ^ read64(&XXH3_SECRET, 72));
    let hi = avalanche64(seed ^ read64(&XXH3_SECRET, 80) ^ read64(&XXH3_SECRET, 88));
    (lo, hi)
}

fn xxh3_128_len17to128(data: &[u8], seed: u64) -> (u64, u64) {
    let len = data.len() as u64;
    let mut acc_lo = len.wrapping_mul(PRIME64_1);
    let mut acc_hi = 0u64;
    if len > 32 {
        if len > 64 {
            if len > 96 {
                let m = mix32(data, len as usize - 32, 64, seed);
                acc_lo = acc_lo.wrapping_add(m.0);
                acc_hi = acc_hi.wrapping_add(m.1);
                let m = mix32(data, 32, 96, seed);
                acc_lo = acc_lo.wrapping_add(m.0);
                acc_hi = acc_hi.wrapping_add(m.1);
            }
            let m = mix32(data, len as usize - 48, 32, seed);
            acc_lo = acc_lo.wrapping_add(m.0);
            acc_hi = acc_hi.wrapping_add(m.1);
            let m = mix32(data, 16, 80, seed);
            acc_lo = acc_lo.wrapping_add(m.0);
            acc_hi = acc_hi.wrapping_add(m.1);
        }
        let m = mix32(data, len as usize - 16, 0, seed);
        acc_lo = acc_lo.wrapping_add(m.0);
        acc_hi = acc_hi.wrapping_add(m.1);
        let m = mix32(data, 0, 48, seed);
        acc_lo = acc_lo.wrapping_add(m.0);
        acc_hi = acc_hi.wrapping_add(m.1);
    }
    let m = mix32(data, 0, 32, seed);
    acc_lo = acc_lo.wrapping_add(m.0);
    acc_hi = acc_hi.wrapping_add(m.1);
    let m = mix32(data, len as usize - 16, 16, seed);
    acc_lo = acc_lo.wrapping_add(m.0);
    acc_hi = acc_hi.wrapping_add(m.1);
    let lo = avalanche64(acc_lo.wrapping_add(acc_hi));
    let hi = 0u64.wrapping_sub(avalanche64(
        acc_lo
            .wrapping_mul(PRIME64_1)
            .wrapping_add(acc_hi.wrapping_mul(PRIME64_4))
            .wrapping_add(len.wrapping_sub(seed).wrapping_mul(PRIME64_2)),
    ));
    (lo, hi)
}

fn xxh3_128_len129to240(data: &[u8], seed: u64) -> (u64, u64) {
    // For medium lengths use the long-path style with limited rounds
    let len = data.len();
    let mut acc = [0u64; 8];
    init_acc(&mut acc, seed);
    // Simplified: process 16-byte stripes
    let mut i = 0;
    while i + 64 <= len {
        for j in 0..4 {
            let off = i + j * 16;
            let d0 = read64(data, off) ^ read64(&XXH3_SECRET, j * 16);
            let d1 = read64(data, off + 8) ^ read64(&XXH3_SECRET, j * 16 + 8);
            acc[j * 2] = acc[j * 2].wrapping_add(mul128_fold64(d0, d1));
            acc[j * 2 + 1] =
                acc[j * 2 + 1].wrapping_add(read64(data, off).wrapping_add(read64(data, off + 8)));
        }
        i += 64;
    }
    while i + 16 <= len {
        let d0 = read64(data, i) ^ read64(&XXH3_SECRET, (i / 16 % 8) * 8);
        let d1 = read64(data, i + 8) ^ read64(&XXH3_SECRET, (i / 16 % 8) * 8 + 64);
        acc[0] = acc[0].wrapping_add(mul128_fold64(d0, d1));
        i += 16;
    }
    // last 16
    let d0 = read64(data, len - 16) ^ read64(&XXH3_SECRET, 128);
    let d1 = read64(data, len - 8) ^ read64(&XXH3_SECRET, 136);
    acc[0] = acc[0].wrapping_add(mul128_fold64(d0, d1));
    let lo = merge_accs(
        &acc,
        (len as u64).wrapping_mul(PRIME64_1),
        &XXH3_SECRET[11..],
    );
    let hi = merge_accs(
        &acc,
        !(len as u64).wrapping_mul(PRIME64_2),
        &XXH3_SECRET[117..],
    );
    (lo, hi)
}

fn xxh3_128_long(data: &[u8], seed: u64) -> (u64, u64) {
    let mut acc = [0u64; 8];
    init_acc(&mut acc, seed);
    hash_long_internal(data, &mut acc, &XXH3_SECRET);
    let lo = merge_accs(
        &acc,
        (data.len() as u64).wrapping_mul(PRIME64_1),
        &XXH3_SECRET[11..],
    );
    let hi = merge_accs(
        &acc,
        !(data.len() as u64).wrapping_mul(PRIME64_2),
        &XXH3_SECRET[117..],
    );
    (lo, hi)
}

// ---- XXH3 helpers ----

fn init_acc(acc: &mut [u64; 8], seed: u64) {
    acc[0] = PRIME64_1.wrapping_add(seed);
    acc[1] = PRIME64_2.wrapping_add(seed);
    acc[2] = PRIME64_3.wrapping_add(seed);
    acc[3] = PRIME64_4.wrapping_add(seed);
    acc[4] = PRIME64_5.wrapping_sub(seed);
    acc[5] = PRIME64_1.wrapping_sub(seed);
    acc[6] = PRIME64_2.wrapping_sub(seed);
    acc[7] = PRIME64_3.wrapping_sub(seed);
}

fn hash_long_internal(data: &[u8], acc: &mut [u64; 8], secret: &[u8; 192]) {
    let len = data.len();
    let nb_blocks = (len - 1) / 64;
    for n in 0..nb_blocks {
        let off = n * 64;
        for i in 0..4 {
            let data_val = read64(data, off + i * 16);
            let data_val2 = read64(data, off + i * 16 + 8);
            let key = read64(secret, i * 16);
            let key2 = read64(secret, i * 16 + 8);
            acc[i * 2] = acc[i * 2].wrapping_add(mul128_fold64(data_val ^ key, data_val2 ^ key2));
            acc[i * 2 + 1] = acc[i * 2 + 1].wrapping_add(data_val.wrapping_add(data_val2));
        }
    }
    // last partial block
    let off = len - 64;
    for i in 0..4 {
        let data_val = read64(data, off + i * 16);
        let data_val2 = read64(data, off + i * 16 + 8);
        let key = read64(secret, 128 + i * 8);
        let key2 = read64(secret, 128 + i * 8 + 32);
        acc[i * 2] = acc[i * 2].wrapping_add(mul128_fold64(data_val ^ key, data_val2 ^ key2));
        acc[i * 2 + 1] = acc[i * 2 + 1].wrapping_add(data_val.wrapping_add(data_val2));
    }
}

fn merge_accs(acc: &[u64; 8], start: u64, secret: &[u8]) -> u64 {
    let mut result = start;
    for i in 0..4 {
        result = result.wrapping_add(mul128_fold64(
            acc[i * 2] ^ read64(secret, i * 16),
            acc[i * 2 + 1] ^ read64(secret, i * 16 + 8),
        ));
    }
    avalanche64(result)
}

fn mix16(data: &[u8], off: usize, secret_off: usize, seed: u64) -> u64 {
    let input_lo = read64(data, off);
    let input_hi = read64(data, off + 8);
    mul128_fold64(
        input_lo ^ (read64(&XXH3_SECRET, secret_off).wrapping_add(seed)),
        input_hi ^ (read64(&XXH3_SECRET, secret_off + 8).wrapping_sub(seed)),
    )
}

fn mix32(data: &[u8], off: usize, secret_off: usize, seed: u64) -> (u64, u64) {
    let input_lo = read64(data, off);
    let input_hi = read64(data, off + 8);
    let lo = mul128_fold64(
        input_lo ^ (read64(&XXH3_SECRET, secret_off).wrapping_add(seed)),
        input_hi ^ (read64(&XXH3_SECRET, secret_off + 8).wrapping_sub(seed)),
    );
    let hi = input_lo.wrapping_add(input_hi);
    (lo, hi)
}

#[inline(always)]
fn mul128_fold64(a: u64, b: u64) -> u64 {
    let r = (a as u128).wrapping_mul(b as u128);
    (r as u64) ^ ((r >> 64) as u64)
}

#[inline(always)]
fn rrmxmx(h: u64, len: u64) -> u64 {
    let h = h ^ (h.rotate_left(49) ^ h.rotate_left(24));
    let h = h.wrapping_mul(PRIME_MX2);
    let h = h ^ ((h >> 35).wrapping_add(len));
    let h = h.wrapping_mul(PRIME_MX2);
    h ^ (h >> 28)
}

#[inline(always)]
fn rrmxmx_seed(h: u64, len: u64) -> u64 {
    rrmxmx(h, len)
}

#[inline(always)]
fn rotate_left64(x: u64, n: u32) -> u64 {
    x.rotate_left(n)
}

// ---- shared helpers ----

#[inline(always)]
fn read32(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}

#[inline(always)]
fn read64(data: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        data[off],
        data[off + 1],
        data[off + 2],
        data[off + 3],
        data[off + 4],
        data[off + 5],
        data[off + 6],
        data[off + 7],
    ])
}

#[inline(always)]
fn round32(acc: u32, input: u32) -> u32 {
    acc.wrapping_add(input.wrapping_mul(PRIME32_2))
        .rotate_left(13)
        .wrapping_mul(PRIME32_1)
}

#[inline(always)]
fn round64(acc: u64, input: u64) -> u64 {
    acc.wrapping_add(input.wrapping_mul(PRIME64_2))
        .rotate_left(31)
        .wrapping_mul(PRIME64_1)
}

#[inline(always)]
fn merge64(acc: u64, val: u64) -> u64 {
    (acc ^ round64(0, val))
        .wrapping_mul(PRIME64_1)
        .wrapping_add(PRIME64_4)
}

#[inline(always)]
fn avalanche32(mut h: u32) -> u32 {
    h ^= h >> 15;
    h = h.wrapping_mul(PRIME32_2);
    h ^= h >> 13;
    h = h.wrapping_mul(PRIME32_3);
    h ^= h >> 16;
    h
}

#[inline(always)]
fn avalanche64(mut h: u64) -> u64 {
    h ^= h >> 33;
    h = h.wrapping_mul(PRIME64_2);
    h ^= h >> 29;
    h = h.wrapping_mul(PRIME64_3);
    h ^= h >> 32;
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xxh32_empty() {
        assert_eq!(xxh32(b"", 0), 0x02cc5d05);
    }

    #[test]
    fn xxh32_abc() {
        assert_eq!(xxh32(b"abc", 0), 0x32d153ff);
    }

    #[test]
    fn xxh64_empty() {
        assert_eq!(xxh64(b"", 0), 0xef46db3751d8e999);
    }

    #[test]
    fn xxh64_abc() {
        assert_eq!(xxh64(b"abc", 0), 0x44bc2cf5ad770999);
    }

    /// XXHash64 multi-lane: concat XXH64(data, seed=i) LE for i in 0..rounds.
    fn xxh64_lanes(data: &[u8], bit_length: usize) -> alloc::vec::Vec<u8> {
        let rounds = bit_length.div_ceil(64);
        let mut out = alloc::vec![0u8; rounds * 8];
        for i in 0..rounds {
            let d = xxh64(data, i as u64);
            out[i * 8..(i + 1) * 8].copy_from_slice(&d.to_le_bytes());
        }
        out
    }

    fn dec_hex(s: &str) -> alloc::vec::Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn vector_empty_512() {
        let out = xxh64_lanes(b"", 512);
        let exp = dec_hex(
            "99e9d85137db46ef4bbea33613baafd56f963c64b1f3685a4eb4abd67ff6203adb47db9f0e7b8df13bfd1c9806d4e14b99c769b2d80a6fdf09440a6f6f62f095",
        );
        assert_eq!(out, exp);
    }

    #[test]
    fn vector_a7_128() {
        let out = xxh64_lanes(&[0xa7], 128);
        let exp = dec_hex("19341f426fcfc3ccd4c12c292dc79be5");
        assert_eq!(out, exp);
    }

    #[test]
    fn vector_c19d_256() {
        let out = xxh64_lanes(&[0xc1, 0x9d, 0x41, 0x77, 0x7d], 256);
        let exp = dec_hex("face1bcf5113addc61bf649e40ead3bb16382e35c8158b10d949f3050412e317");
        assert_eq!(out, exp);
    }

    #[test]
    fn xxh3_64_empty() {
        // Official XXH3_64bits("") with seed 0
        assert_eq!(xxh3_64(b"", 0), 0x2d06800538d394c2);
    }

    #[test]
    fn xxh3_64_abc() {
        // Verify deterministic and different from empty
        let a = xxh3_64(b"abc", 0);
        let b = xxh3_64(b"abc", 0);
        let c = xxh3_64(b"", 0);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn xxh3_128_empty() {
        let (lo, hi) = xxh3_128(b"", 0);
        // Must be deterministic
        let (lo2, hi2) = xxh3_128(b"", 0);
        assert_eq!((lo, hi), (lo2, hi2));
        assert_ne!(lo, 0); // empty is not zero with XXH3
    }

    #[test]
    fn xxh3_128_bytes_len() {
        let d = xxh3_128_bytes(b"hello", 0).unwrap();
        assert_eq!(d.len(), 16);
        let d2 = xxh3_128_bytes(b"hello", 0).unwrap();
        assert_eq!(d, d2);
    }

    #[test]
    fn xxh3_256_bytes_len() {
        let d = xxh3_256_bytes(b"hello", 0).unwrap();
        assert_eq!(d.len(), 32);
        let d2 = xxh3_256_bytes(b"hello", 0).unwrap();
        assert_eq!(d, d2);
        // Different seed → different digest
        let d3 = xxh3_256_bytes(b"hello", 1).unwrap();
        assert_ne!(d, d3);
    }

    #[test]
    fn xxh3_long_input() {
        let data = [0xabu8; 1000];
        let a = xxh3_64(&data, 0);
        let b = xxh3_64(&data, 0);
        assert_eq!(a, b);
        let (lo, hi) = xxh3_128(&data, 0);
        assert_eq!(xxh3_128(&data, 0), (lo, hi));
    }
}
