//! Vesta curve (Pasta pair with Pallas).
//!
//! Short Weierstrass: y² = x³ + 5 over Fp where p = Pallas group order.
//! Full Jacobian arithmetic, constant-time scalar multiplication.

use crate::ct::{ct_eq, ct_select_u8};
use crate::curve::error::{CurveError, CurveResult};
use crate::curve::traits::{CurvePoint, FieldElement, Scalar as ScalarTrait};

/// Vesta base field = Pallas group order (big-endian).
pub const P_BE: [u8; 32] = [
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x22, 0x46, 0x98, 0xfc, 0x09, 0x94, 0xa8, 0xdd, 0x8c, 0x46, 0xeb, 0x21, 0x00, 0x00, 0x00, 0x01,
];

/// Vesta group order = Pallas base field.
pub const N_BE: [u8; 32] = [
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x22, 0x46, 0x98, 0xfc, 0x09, 0x4c, 0xf9, 0x1b, 0x99, 0x2d, 0x30, 0xed, 0x00, 0x00, 0x00, 0x01,
];

fn p_limbs() -> [u64; 4] {
    [
        0x8c46_eb21_0000_0001,
        0x2246_98fc_0994_a8dd,
        0x0000_0000_0000_0000,
        0x4000_0000_0000_0000,
    ]
}

fn r256_p() -> [u64; 4] {
    [
        0x5b2b_3e9c_ffff_fffd,
        0x992c_350b_e342_0567,
        0xffff_ffff_ffff_ffff,
        0x3fff_ffff_ffff_ffff,
    ]
}

const P_INV: u64 = 0x8c46_eb20_ffff_ffff;

fn r2_p() -> [u64; 4] {
    [
        0xfc96_78ff_0000_000f,
        0x67bb_433d_891a_16e3,
        0x7fae_2310_04cc_f590,
        0x096d_41af_7ccf_daa9,
    ]
}

fn n_limbs() -> [u64; 4] {
    [
        0x992d_30ed_0000_0001,
        0x2246_98fc_094c_f91b,
        0x0000_0000_0000_0000,
        0x4000_0000_0000_0000,
    ]
}

fn r256_n() -> [u64; 4] {
    [
        0x3478_6d38_ffff_fffd,
        0x992c_350b_e419_14ad,
        0xffff_ffff_ffff_ffff,
        0x3fff_ffff_ffff_ffff,
    ]
}

#[derive(Clone, Copy, Debug)]
pub struct Fe {
    pub(crate) n: [u64; 4],
}

impl Fe {
    pub const fn zero() -> Self {
        Self { n: [0; 4] }
    }
    /// Construct from Montgomery limbs (no reduction). For const tables only.
    pub const fn from_raw_mont(n: [u64; 4]) -> Self {
        Self { n }
    }
    /// Raw Montgomery limbs (for const emission).
    pub const fn to_raw_mont(self) -> [u64; 4] {
        self.n
    }
    pub fn one() -> Self {
        Self { n: r256_p() }
    }

    fn cmp_p(&self) -> i8 {
        let p = p_limbs();
        for i in (0..4).rev() {
            if self.n[i] < p[i] {
                return -1;
            }
            if self.n[i] > p[i] {
                return 1;
            }
        }
        0
    }
    /// Branchless `self >= p ? 1 : 0` (flag accumulation, no early exit).
    /// Mirrors Pallas `ge_p`; used by the constant-time [`Fe::add`].
    fn ge_p(&self) -> u8 {
        let p = p_limbs();
        let mut gt = 0u8;
        let mut eq = 1u8;
        for i in (0..4).rev() {
            gt |= eq & u8::from(self.n[i] > p[i]);
            eq &= u8::from(self.n[i] == p[i]);
        }
        gt | eq
    }
    fn sub_p(&self) -> Self {
        let p = p_limbs();
        let mut borrow = 0u64;
        let mut n = [0u64; 4];
        for i in 0..4 {
            let (d1, b1) = self.n[i].overflowing_sub(p[i]);
            let (d2, b2) = d1.overflowing_sub(borrow);
            n[i] = d2;
            borrow = u64::from(b1 | b2);
        }
        Self { n }
    }
    fn reduce(&self) -> Self {
        // Branchless CT: mirrors Pallas (ge_p + ct_select). The old
        // `if cmp_p >= 0` branched on secret limbs.
        let need = self.ge_p();
        Fe::ct_select(need, &self.sub_p(), self)
    }
    fn sub_mod(&self, m: &[u64; 4]) -> Self {
        let mut borrow = 0u64;
        let mut n = [0u64; 4];
        for i in 0..4 {
            let (d1, b1) = self.n[i].overflowing_sub(m[i]);
            let (d2, b2) = d1.overflowing_sub(borrow);
            n[i] = d2;
            borrow = u64::from(b1 | b2);
        }
        Self { n }
    }
    /// Branchless `self >= m ? 1 : 0` for secret paths (mirrors `ge_p`).
    fn ge_mod_ct(&self, m: &[u64; 4]) -> u8 {
        let mut gt = 0u8;
        let mut eq = 1u8;
        for i in (0..4).rev() {
            gt |= eq & u8::from(self.n[i] > m[i]);
            eq &= u8::from(self.n[i] == m[i]);
        }
        gt | eq
    }
    pub fn from_bytes_be(bytes: &[u8; 32]) -> CurveResult<Self> {
        let mut n = [0u64; 4];
        for (i, ni) in n.iter_mut().enumerate() {
            let o = 24 - i * 8;
            *ni = u64::from_be_bytes([
                bytes[o],
                bytes[o + 1],
                bytes[o + 2],
                bytes[o + 3],
                bytes[o + 4],
                bytes[o + 5],
                bytes[o + 6],
                bytes[o + 7],
            ]);
        }
        let fe = Self { n };
        if fe.cmp_p() >= 0 {
            return Err(CurveError::InvalidEncoding);
        }
        Ok(Self::mont_mul_raw(&fe.n, &r2_p()))
    }
    pub fn to_bytes_be(&self, out: &mut [u8; 32]) {
        let r = Self::mont_mul_raw(&self.n, &[1, 0, 0, 0]).reduce();
        for i in 0..4 {
            let o = 24 - i * 8;
            out[o..o + 8].copy_from_slice(&r.n[i].to_be_bytes());
        }
    }

    // ---- Orchard LE conveniences (fallible, no panics) ----

    /// Canonical LE decode with range check.
    pub fn from_le_array(bytes: &[u8; 32]) -> CurveResult<Self> {
        let mut be = [0u8; 32];
        for i in 0..32 {
            be[i] = bytes[31 - i];
        }
        Self::from_bytes_be(&be)
    }

    /// Canonical LE decode from a slice.
    pub fn from_le_bytes_checked(bytes: &[u8]) -> CurveResult<Self> {
        if bytes.len() != 32 {
            return Err(CurveError::InvalidLength);
        }
        let mut b = [0u8; 32];
        b.copy_from_slice(bytes);
        Self::from_le_array(&b)
    }

    /// Build from raw LE limbs with range check.
    pub fn from_le_limbs(limbs: &[u64; 4]) -> CurveResult<Self> {
        let mut be = [0u8; 32];
        for i in 0..4 {
            be[i * 8..(i + 1) * 8].copy_from_slice(&limbs[3 - i].to_be_bytes());
        }
        Self::from_bytes_be(&be)
    }

    /// Wrapping 64-byte LE decode: reduce mod m into Montgomery form.
    pub fn from_le_bytes64_wrapping(bytes: &[u8]) -> CurveResult<Self> {
        if bytes.len() != 64 {
            return Err(CurveError::InvalidLength);
        }
        let mut limbs = [0u64; 8];
        for (i, li) in limbs.iter_mut().enumerate() {
            let o = i * 8;
            *li = u64::from_le_bytes([
                bytes[o],
                bytes[o + 1],
                bytes[o + 2],
                bytes[o + 3],
                bytes[o + 4],
                bytes[o + 5],
                bytes[o + 6],
                bytes[o + 7],
            ]);
        }
        let c = reduce_512_via_r(&limbs, &r256_p(), &p_limbs());
        Ok(Self::mont_mul_raw(&c.n, &r2_p()))
    }

    /// Small integer (always `< m`).
    pub fn from_u64(v: u64) -> Self {
        Self::mont_mul_raw(&[v, 0, 0, 0], &r2_p())
    }

    /// Canonical LE encoding.
    pub fn to_le_bytes(&self) -> [u8; 32] {
        let r = Self::mont_mul_raw(&self.n, &[1, 0, 0, 0]).reduce();
        let mut out = [0u8; 32];
        for i in 0..4 {
            out[i * 8..(i + 1) * 8].copy_from_slice(&r.n[i].to_le_bytes());
        }
        out
    }

    /// Canonical LE bits (bit `i` = coefficient of `2^i`).
    pub fn to_bits_le(&self, out: &mut [bool; 256]) {
        let le = self.to_le_bytes();
        for i in 0..32 {
            for j in 0..8 {
                out[i * 8 + j] = ((le[i] >> j) & 1) == 1;
            }
        }
    }

    /// Low 32 bits of the canonical value.
    pub fn get_lower_32(&self) -> u32 {
        let le = self.to_le_bytes();
        u32::from_le_bytes([le[0], le[1], le[2], le[3]])
    }

    /// Binary power by `u64` exponent.
    /// Variable-time in the exponent (see Pallas `pow_u64` docs).
    /// Public exponents only; never on secrets.
    pub fn pow_u64(&self, mut e: u64) -> Self {
        let mut acc = Self::one();
        let mut b = *self;
        while e > 0 {
            if (e & 1) == 1 {
                acc = acc.mul(&b);
            }
            b = b.square();
            e >>= 1;
        }
        acc
    }

    /// Double via add.
    pub fn double(&self) -> Self {
        self.add(self)
    }

    /// Debug hex: BE `0x`-prefixed canonical encoding.
    pub fn to_debug_string(&self) -> alloc::string::String {
        let mut be = [0u8; 32];
        self.to_bytes_be(&mut be);
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut s = alloc::string::String::from("0x");
        for b in be.iter() {
            s.push(HEX[(b >> 4) as usize] as char);
            s.push(HEX[(b & 15) as usize] as char);
        }
        s
    }

    pub fn ct_select(choice: u8, a: &Self, b: &Self) -> Self {
        let c = core::hint::black_box(choice) & 1;
        let mask = (c as u64).wrapping_neg();
        let mut n = [0u64; 4];
        for ((ni, ai), bi) in n.iter_mut().zip(a.n.iter()).zip(b.n.iter()) {
            *ni = (*ai & mask) | (*bi & !mask);
        }
        Self { n }
    }
    pub fn add(&self, other: &Self) -> Self {
        let mut carry = 0u64;
        let mut n = [0u64; 4];
        for ((ni, si), oi) in n.iter_mut().zip(self.n.iter()).zip(other.n.iter()) {
            let t = *si as u128 + *oi as u128 + carry as u128;
            *ni = t as u64;
            carry = (t >> 64) as u64;
        }
        // Branchless conditional subtract (was `if carry || cmp_p`; the
        // branch direction leaked secret limb values). Mirrors Pallas.
        let mut r = Self { n };
        let need = (carry != 0) as u8 | r.ge_p();
        r = Fe::ct_select(need, &r.sub_p(), &r);
        r.reduce()
    }
    pub fn neg(&self) -> Self {
        let p = p_limbs();
        let mut borrow = 0u64;
        let mut n = [0u64; 4];
        for i in 0..4 {
            let (d1, b1) = p[i].overflowing_sub(self.n[i]);
            let (d2, b2) = d1.overflowing_sub(borrow);
            n[i] = d2;
            borrow = u64::from(b1 | b2);
        }
        let raw = Self { n };
        Fe::ct_select(self.is_zero() as u8, &Fe::zero(), &raw)
    }
    pub fn sub(&self, other: &Self) -> Self {
        self.add(&other.neg())
    }
    pub fn mul(&self, other: &Self) -> Self {
        Self::mont_mul_raw(&self.n, &other.n)
    }

    /// Variable-time addition: same value as [`add`](Self::add), single
    /// conditional subtract (canonical inputs only: `a + b < 2p < 2^256`
    /// since Vesta order < 2^255, so carry is impossible). Batching paths
    /// only; [`add`](Self::add) is unchanged.
    #[inline]
    pub fn add_vartime(&self, other: &Self) -> Self {
        let mut carry = 0u64;
        let mut n = [0u64; 4];
        for ((ni, si), oi) in n.iter_mut().zip(self.n.iter()).zip(other.n.iter()) {
            let t = *si as u128 + *oi as u128 + carry as u128;
            *ni = t as u64;
            carry = (t >> 64) as u64;
        }
        let mut r = Self { n };
        if carry != 0 || r.cmp_p() >= 0 {
            r = r.sub_p();
        }
        r
    }

    /// Variable-time subtraction (canonical inputs only). See [`add_vartime`](Self::add_vartime).
    #[inline]
    pub fn sub_vartime(&self, other: &Self) -> Self {
        self.add_vartime(&other.neg())
    }

    /// Variable-time Montgomery multiplication: same value as [`mul`](Self::mul).
    /// Straight-line schoolbook + SOS reduction: 32 `mac` chains fully
    /// unrolled, single sbb-chain final subtract. Canonical inputs,
    /// canonical output. Batching paths only; [`mul`](Self::mul) is unchanged.
    #[inline(always)]
    pub fn mul_vartime(&self, other: &Self) -> Self {
        #[inline(always)]
        fn mac(a: u64, b: u64, c: u64, carry: u64) -> (u64, u64) {
            let ret = (a as u128) + (b as u128) * (c as u128) + (carry as u128);
            (ret as u64, (ret >> 64) as u64)
        }
        #[inline(always)]
        fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
            let ret = (a as u128) + (b as u128) + (carry as u128);
            (ret as u64, (ret >> 64) as u64)
        }
        #[inline(always)]
        fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
            let ret = (a as u128).wrapping_sub((b as u128) + ((borrow >> 63) as u128));
            (ret as u64, (ret >> 64) as u64)
        }
        let a = self.n;
        let b = other.n;
        let p = p_limbs();
        let (r0, carry) = mac(0, a[0], b[0], 0);
        let (r1, carry) = mac(0, a[0], b[1], carry);
        let (r2, carry) = mac(0, a[0], b[2], carry);
        let (r3, r4) = mac(0, a[0], b[3], carry);
        let (r1, carry) = mac(r1, a[1], b[0], 0);
        let (r2, carry) = mac(r2, a[1], b[1], carry);
        let (r3, carry) = mac(r3, a[1], b[2], carry);
        let (r4, r5) = mac(r4, a[1], b[3], carry);
        let (r2, carry) = mac(r2, a[2], b[0], 0);
        let (r3, carry) = mac(r3, a[2], b[1], carry);
        let (r4, carry) = mac(r4, a[2], b[2], carry);
        let (r5, r6) = mac(r5, a[2], b[3], carry);
        let (r3, carry) = mac(r3, a[3], b[0], 0);
        let (r4, carry) = mac(r4, a[3], b[1], carry);
        let (r5, carry) = mac(r5, a[3], b[2], carry);
        let (r6, r7) = mac(r6, a[3], b[3], carry);
        let k = r0.wrapping_mul(P_INV);
        let (_, carry) = mac(r0, k, p[0], 0);
        let (r1, carry) = mac(r1, k, p[1], carry);
        let (r2, carry) = mac(r2, k, p[2], carry);
        let (r3, carry) = mac(r3, k, p[3], carry);
        let (r4, carry2) = adc(r4, 0, carry);
        let k = r1.wrapping_mul(P_INV);
        let (_, carry) = mac(r1, k, p[0], 0);
        let (r2, carry) = mac(r2, k, p[1], carry);
        let (r3, carry) = mac(r3, k, p[2], carry);
        let (r4, carry) = mac(r4, k, p[3], carry);
        let (r5, carry2) = adc(r5, carry2, carry);
        let k = r2.wrapping_mul(P_INV);
        let (_, carry) = mac(r2, k, p[0], 0);
        let (r3, carry) = mac(r3, k, p[1], carry);
        let (r4, carry) = mac(r4, k, p[2], carry);
        let (r5, carry) = mac(r5, k, p[3], carry);
        let (r6, carry2) = adc(r6, carry2, carry);
        let k = r3.wrapping_mul(P_INV);
        let (_, carry) = mac(r3, k, p[0], 0);
        let (r4, carry) = mac(r4, k, p[1], carry);
        let (r5, carry) = mac(r5, k, p[2], carry);
        let (r6, carry) = mac(r6, k, p[3], carry);
        let (r7, _) = adc(r7, carry2, carry);
        let (d0, b) = sbb(r4, p[0], 0);
        let (d1, b) = sbb(r5, p[1], b);
        let (d2, b) = sbb(r6, p[2], b);
        let (d3, b) = sbb(r7, p[3], b);
        let (d0, c) = adc(d0, p[0] & b, 0);
        let (d1, c) = adc(d1, p[1] & b, c);
        let (d2, c) = adc(d2, p[2] & b, c);
        let (d3, _) = adc(d3, p[3] & b, c);
        Self {
            n: [d0, d1, d2, d3],
        }
    }

    #[inline]
    fn mont_mul_raw(a: &[u64; 4], b: &[u64; 4]) -> Self {
        let pmod = p_limbs();
        let mut t = [0u64; 8];
        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 {
                let z = t[i + j] as u128 + (a[i] as u128) * (b[j] as u128) + carry;
                t[i + j] = z as u64;
                carry = z >> 64;
            }
            let z = t[i + 4] as u128 + carry;
            t[i + 4] = z as u64;
            // Fixed drain over public index range (no `while c != 0`).
            let mut c = z >> 64;
            for tk in t.iter_mut().skip(i + 5) {
                let z = *tk as u128 + c;
                *tk = z as u64;
                c = z >> 64;
            }
        }
        for i in 0..4 {
            let m = t[i].wrapping_mul(P_INV);
            let mut carry = 0u128;
            for j in 0..4 {
                let z = t[i + j] as u128 + (m as u128) * (pmod[j] as u128) + carry;
                t[i + j] = z as u64;
                carry = z >> 64;
            }
            for tk in t.iter_mut().skip(i + 4) {
                let z = *tk as u128 + carry;
                *tk = z as u64;
                carry = z >> 64;
            }
        }
        let r = Self {
            n: [t[4], t[5], t[6], t[7]],
        };
        // Branchless final subtract (was `if cmp_p >= 0` on secrets).
        let need = r.ge_p();
        Fe::ct_select(need, &r.sub_p(), &r)
    }

    pub fn square(&self) -> Self {
        self.mul(self)
    }
    pub fn invert(&self) -> CurveResult<Self> {
        if self.is_zero() {
            return Err(CurveError::NotInvertible);
        }
        // Exponent is public (p-2); ladder is branchless via ct_select so a
        // secret base never causes a mul-skip timing delta.
        let mut exp = P_BE;
        let mut borrow = 2u32;
        for i in (0..32).rev() {
            let v = exp[i] as u32;
            let (d, b) = v.overflowing_sub(borrow);
            exp[i] = d as u8;
            borrow = u32::from(b);
        }
        let base = *self;
        let mut result = Self::one();
        for byte in exp.iter() {
            for bit in (0..8).rev() {
                let sq = result.square();
                let mulled = sq.mul(&base);
                let bit_set = (byte >> bit) & 1;
                result = Self::ct_select(bit_set, &mulled, &sq);
            }
        }
        Ok(result)
    }

    /// Variable-time square: same value as [`square`](Self::square).
    /// Canonical-input contract, prover/batch paths only.
    pub fn square_vartime(&self) -> Self {
        self.mul_vartime(self)
    }
    pub fn is_zero(&self) -> bool {
        self.reduce().n.iter().fold(0u64, |a, &x| a | x) == 0
    }
}

/// Reduce 8×u64 product via R = 2^256 mod modulus.
/// Handles carry from low+high*R fully (no dropped overflow).
fn reduce_512_via_r(limbs: &[u64; 8], _r: &[u64; 4], modulus: &[u64; 4]) -> Fe {
    // result = (...((0 * 2^64 + limbs[7]) * 2^64 + limbs[6]) ...) + limbs[0]  mod p
    let mut acc = Fe { n: [0; 4] };
    for i in (0..8).rev() {
        // acc = acc * 2^64 + limbs[i]
        // shift left 64 bits
        let mut shifted = [0u64; 5];
        shifted[1] = acc.n[0];
        shifted[2] = acc.n[1];
        shifted[3] = acc.n[2];
        shifted[4] = acc.n[3];
        // add limbs[i] into shifted[0]
        let (s0, _c0) = (limbs[i] as u128).overflowing_add(0);
        let _ = s0;
        shifted[0] = limbs[i];
        // reduce 5-limb number mod p: take low 4 + high * 2^256 ≡ high * R, but
        // simpler: subtract p while >= 2^256 or >= p
        // Convert shifted to Fe-sized by folding shifted[4]
        let mut n = [shifted[0], shifted[1], shifted[2], shifted[3]];
        let mut hi = shifted[4] as u128;
        // Fixed-iteration residual fold (bound covers worst-case carry chain).
        // Was `while hi != 0` (secret-dependent trip count).
        for _ in 0..32 {
            let h = (hi & 0xffff_ffff_ffff_ffff) as u64;
            hi >>= 64;
            let mut carry = 0u128;
            for j in 0..4 {
                let t = n[j] as u128 + (h as u128) * (_r[j] as u128) + carry;
                n[j] = t as u64;
                carry = t >> 64;
            }
            hi += carry;
        }
        acc = Fe { n };
        // Fixed 8x masked subtracts (was `for 0..3 { if >= {sub} else break }`).
        for _ in 0..8 {
            let need = acc.ge_mod_ct(modulus);
            acc = Fe::ct_select(need, &acc.sub_mod(modulus), &acc);
        }
    }
    acc
}

impl PartialEq for Fe {
    fn eq(&self, other: &Self) -> bool {
        self.to_le_bytes() == other.to_le_bytes()
    }
}
impl Eq for Fe {}

impl PartialOrd for Fe {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Fe {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        // Numeric order: canonical bytes compared MSB-first.
        let a = self.to_le_bytes();
        let b = other.to_le_bytes();
        for i in (0..32).rev() {
            if a[i] != b[i] {
                return a[i].cmp(&b[i]);
            }
        }
        core::cmp::Ordering::Equal
    }
}

impl FieldElement for Fe {
    const BYTES: usize = 32;
    fn zero() -> Self {
        Fe::zero()
    }
    fn one() -> Self {
        Fe::one()
    }
    fn add(&self, rhs: &Self) -> Self {
        Fe::add(self, rhs)
    }
    fn sub(&self, rhs: &Self) -> Self {
        Fe::sub(self, rhs)
    }
    fn neg(&self) -> Self {
        Fe::neg(self)
    }
    fn mul(&self, rhs: &Self) -> Self {
        Fe::mul(self, rhs)
    }
    fn square(&self) -> Self {
        Fe::square(self)
    }
    fn invert(&self) -> CurveResult<Self> {
        Fe::invert(self)
    }
    fn from_bytes(bytes: &[u8]) -> CurveResult<Self> {
        if bytes.len() != 32 {
            return Err(CurveError::InvalidLength);
        }
        let mut b = [0u8; 32];
        b.copy_from_slice(bytes);
        Fe::from_bytes_be(&b)
    }
    fn to_bytes(&self, out: &mut [u8]) -> CurveResult<()> {
        if out.len() != 32 {
            return Err(CurveError::InvalidLength);
        }
        let mut b = [0u8; 32];
        self.to_bytes_be(&mut b);
        out.copy_from_slice(&b);
        Ok(())
    }
    fn ct_eq(&self, other: &Self) -> u8 {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        self.to_bytes_be(&mut a);
        other.to_bytes_be(&mut b);
        ct_eq(&a, &b)
    }
    fn is_zero(&self) -> bool {
        Fe::is_zero(self)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Scalar {
    pub(crate) n: [u64; 4],
}

impl Scalar {
    pub const fn zero() -> Self {
        Self { n: [0; 4] }
    }
    pub const fn one() -> Self {
        Self { n: [1, 0, 0, 0] }
    }

    /// Best-effort wipe (type is `Copy`; call explicitly after use).
    #[inline(never)]
    pub fn zeroize(&mut self) {
        for limb in self.n.iter_mut() {
            *limb = 0;
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        core::hint::black_box(self.n);
    }
    fn cmp_n(&self) -> i8 {
        let ord = n_limbs();
        for i in (0..4).rev() {
            if self.n[i] < ord[i] {
                return -1;
            }
            if self.n[i] > ord[i] {
                return 1;
            }
        }
        0
    }
    fn ge_n_ct(&self) -> u8 {
        let ord = n_limbs();
        let mut gt = 0u8;
        let mut eq = 1u8;
        for i in (0..4).rev() {
            gt |= eq & u8::from(self.n[i] > ord[i]);
            eq &= u8::from(self.n[i] == ord[i]);
        }
        gt | eq
    }
    fn sub_n(&self) -> Self {
        let ord = n_limbs();
        let mut borrow = 0u64;
        let mut n = [0u64; 4];
        for i in 0..4 {
            let (d1, b1) = self.n[i].overflowing_sub(ord[i]);
            let (d2, b2) = d1.overflowing_sub(borrow);
            n[i] = d2;
            borrow = u64::from(b1 | b2);
        }
        Self { n }
    }
    fn ct_select_ct(choice: u8, a: &Self, b: &Self) -> Self {
        let c = core::hint::black_box(choice) & 1;
        let mask = (c as u64).wrapping_neg();
        let mut n = [0u64; 4];
        for ((ni, ai), bi) in n.iter_mut().zip(a.n.iter()).zip(b.n.iter()) {
            *ni = (*ai & mask) | (*bi & !mask);
        }
        Self { n }
    }
    fn reduce(&self) -> Self {
        // Branchless CT (was `if cmp_n >= 0`). Mirrors Pallas.
        let need = self.ge_n_ct();
        Self::ct_select_ct(need, &self.sub_n(), self)
    }
    pub fn from_bytes_be(bytes: &[u8; 32]) -> CurveResult<Self> {
        let mut n = [0u64; 4];
        for (i, ni) in n.iter_mut().enumerate() {
            let o = 24 - i * 8;
            *ni = u64::from_be_bytes([
                bytes[o],
                bytes[o + 1],
                bytes[o + 2],
                bytes[o + 3],
                bytes[o + 4],
                bytes[o + 5],
                bytes[o + 6],
                bytes[o + 7],
            ]);
        }
        let s = Self { n };
        if s.cmp_n() >= 0 {
            return Err(CurveError::InvalidScalar);
        }
        Ok(s)
    }
    pub fn to_bytes_be(&self, out: &mut [u8; 32]) {
        let r = self.reduce();
        for i in 0..4 {
            let o = 24 - i * 8;
            out[o..o + 8].copy_from_slice(&r.n[i].to_be_bytes());
        }
    }
    pub fn add(&self, other: &Self) -> Self {
        let mut carry = 0u64;
        let mut n = [0u64; 4];
        for ((ni, si), oi) in n.iter_mut().zip(self.n.iter()).zip(other.n.iter()) {
            let t = *si as u128 + *oi as u128 + carry as u128;
            *ni = t as u64;
            carry = (t >> 64) as u64;
        }
        // Branchless CT: double-subtract via mask (was `if carry||cmp_n`).
        // Mirrors Pallas `add`: need + sub + reduce.
        let r = Self { n };
        let need = ((carry != 0) as u8) | r.ge_n_ct();
        let subbed = r.sub_n();
        let r2 = Self::ct_select_ct(need, &subbed, &r);
        r2.reduce()
    }
    pub fn neg(&self) -> Self {
        // Always compute ord-self, select zero when input is zero (no early return).
        let ord = n_limbs();
        let mut borrow = 0u64;
        let mut n = [0u64; 4];
        for i in 0..4 {
            let (d1, b1) = ord[i].overflowing_sub(self.n[i]);
            let (d2, b2) = d1.overflowing_sub(borrow);
            n[i] = d2;
            borrow = u64::from(b1 | b2);
        }
        let raw = Self { n };
        Self::ct_select_ct(self.is_zero() as u8, &Self::zero(), &raw)
    }
    pub fn mul(&self, other: &Self) -> Self {
        let mut prod = [0u128; 8];
        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 {
                let t = prod[i + j] + (self.n[i] as u128) * (other.n[j] as u128) + carry;
                prod[i + j] = t & 0xffff_ffff_ffff_ffff;
                carry = t >> 64;
            }
            // Fixed drain over public index range (no `while carry != 0`).
            for pr in prod.iter_mut().skip(i + 4) {
                let t = *pr + carry;
                *pr = t & 0xffff_ffff_ffff_ffff;
                carry = t >> 64;
            }
        }
        let mut limbs = [0u64; 8];
        for i in 0..8 {
            limbs[i] = prod[i] as u64;
        }

        let fe = reduce_512_via_r(&limbs, &r256_n(), &n_limbs());
        Self { n: fe.n }.reduce()
    }

    pub fn bit(&self, i: usize) -> u8 {
        if i >= 256 {
            return 0;
        }
        ((self.n[i / 64] >> (i % 64)) & 1) as u8
    }
    pub fn is_zero(&self) -> bool {
        self.n.iter().fold(0u64, |a, &x| a | x) == 0
    }

    /// Reduce 64-byte LE integer mod Vesta scalar order → 32-byte LE scalar.
    /// Matches `VestaFq.fromBytes64` (LE BigInt mod r).
    /// Branchless CT (masked add, no `if bit==1`). Proof-hot callers with
    /// public inputs should use `sc_reduce64_le_vartime` for speed.
    pub fn sc_reduce64_le(wide64: &[u8; 64]) -> Self {
        // Bit-by-bit: process 512-bit LE integer from MSB to LSB.
        // limbs[0] is least-significant 64 bits of the LE encoding.
        let mut limbs = [0u64; 8];
        for (i, li) in limbs.iter_mut().enumerate() {
            let o = i * 8;
            *li = u64::from_le_bytes([
                wide64[o],
                wide64[o + 1],
                wide64[o + 2],
                wide64[o + 3],
                wide64[o + 4],
                wide64[o + 5],
                wide64[o + 6],
                wide64[o + 7],
            ]);
        }
        let one = Self::one();
        let mut acc = Self::zero();
        // MSB is bit 511 of the integer = bit 63 of limbs[7]
        for limb_idx in (0..8).rev() {
            for bit in (0..64).rev() {
                acc = acc.add(&acc); // *2
                let b = ((limbs[limb_idx] >> bit) & 1) as u8;
                let added = acc.add(&one);
                acc = Self::ct_select_ct(b, &added, &acc);
            }
        }
        acc
    }

    /// Variable-time twin for proof/transcript paths (public inputs only).
    /// Same value as `sc_reduce64_le`, skips zero-bit adds. Never on secrets.
    pub fn sc_reduce64_le_vartime(wide64: &[u8; 64]) -> Self {
        let mut limbs = [0u64; 8];
        for (i, li) in limbs.iter_mut().enumerate() {
            let o = i * 8;
            *li = u64::from_le_bytes([
                wide64[o],
                wide64[o + 1],
                wide64[o + 2],
                wide64[o + 3],
                wide64[o + 4],
                wide64[o + 5],
                wide64[o + 6],
                wide64[o + 7],
            ]);
        }
        let mut acc = Self::zero();
        for limb_idx in (0..8).rev() {
            for bit in (0..64).rev() {
                acc = acc.add(&acc);
                if ((limbs[limb_idx] >> bit) & 1) == 1 {
                    acc = acc.add(&Self::one());
                }
            }
        }
        acc
    }
    pub fn to_bytes_le(&self, out: &mut [u8; 32]) {
        let r = self.reduce();
        for i in 0..4 {
            out[i * 8..(i + 1) * 8].copy_from_slice(&r.n[i].to_le_bytes());
        }
    }

    pub fn from_bytes_le(bytes: &[u8; 32]) -> CurveResult<Self> {
        let mut n = [0u64; 4];
        for i in 0..4 {
            n[i] = u64::from_le_bytes([
                bytes[i * 8],
                bytes[i * 8 + 1],
                bytes[i * 8 + 2],
                bytes[i * 8 + 3],
                bytes[i * 8 + 4],
                bytes[i * 8 + 5],
                bytes[i * 8 + 6],
                bytes[i * 8 + 7],
            ]);
        }
        let s = Self { n };
        if s.cmp_n() >= 0 {
            return Err(CurveError::InvalidScalar);
        }
        Ok(s)
    }
}

impl ScalarTrait for Scalar {
    const BYTES: usize = 32;
    fn zero() -> Self {
        Scalar::zero()
    }
    fn one() -> Self {
        Scalar::one()
    }
    fn add(&self, rhs: &Self) -> Self {
        Scalar::add(self, rhs)
    }
    fn mul(&self, rhs: &Self) -> Self {
        Scalar::mul(self, rhs)
    }
    fn neg(&self) -> Self {
        Scalar::neg(self)
    }
    fn from_bytes(bytes: &[u8]) -> CurveResult<Self> {
        if bytes.len() != 32 {
            return Err(CurveError::InvalidLength);
        }
        let mut b = [0u8; 32];
        b.copy_from_slice(bytes);
        Scalar::from_bytes_le(&b)
    }
    fn to_bytes(&self, out: &mut [u8]) -> CurveResult<()> {
        if out.len() != 32 {
            return Err(CurveError::InvalidLength);
        }
        let mut b = [0u8; 32];
        self.to_bytes_le(&mut b);
        out.copy_from_slice(&b);
        Ok(())
    }
    fn ct_eq(&self, other: &Self) -> u8 {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        self.to_bytes_le(&mut a);
        other.to_bytes_le(&mut b);
        ct_eq(&a, &b)
    }
    fn is_zero(&self) -> bool {
        Scalar::is_zero(self)
    }
}

#[derive(Clone, Copy, Debug)]
struct Jac {
    x: Fe,
    y: Fe,
    z: Fe,
    /// 1 = point at infinity, 0 = finite. Stored as u8 for CT select.
    infinity: u8,
}

impl Jac {
    fn identity() -> Self {
        Self {
            x: Fe::zero(),
            y: Fe::one(),
            z: Fe::zero(),
            infinity: 1,
        }
    }
    fn ct_is_identity(&self) -> u8 {
        self.infinity | self.z.ct_eq(&Fe::zero())
    }
    fn ct_select(choice: u8, a: &Self, b: &Self) -> Self {
        let c = choice & 1;
        Self {
            x: Fe::ct_select(c, &a.x, &b.x),
            y: Fe::ct_select(c, &a.y, &b.y),
            z: Fe::ct_select(c, &a.z, &b.z),
            infinity: ct_select_u8(c, a.infinity, b.infinity),
        }
    }
    fn generator() -> Self {
        let x = Fe::one().neg();
        let y = Fe::one().add(&Fe::one());
        Self {
            x,
            y,
            z: Fe::one(),
            infinity: 0,
        }
    }
    fn double(&self) -> Self {
        // Jacobian doubling for a=0 (inversion-free), same as Pallas.
        let yy = self.y.square();
        let mut s = self.x.mul(&yy);
        s = s.add(&s);
        s = s.add(&s); // 4 X Y²
        let xx = self.x.square();
        let m = xx.add(&xx).add(&xx); // 3 X²
        let x3 = m.square().sub(&s).sub(&s);
        let mut y4 = yy.square();
        y4 = y4.add(&y4);
        y4 = y4.add(&y4);
        y4 = y4.add(&y4); // 8 Y⁴
        let y3 = m.mul(&s.sub(&x3)).sub(&y4);
        let yz = self.y.mul(&self.z);
        let z3 = yz.add(&yz); // 2 Y Z
        let computed = Self {
            x: x3,
            y: y3,
            z: z3,
            infinity: 0,
        };
        let y_zero = self.y.ct_eq(&Fe::zero());
        Self::ct_select(self.infinity | y_zero, &Self::identity(), &computed)
    }
    fn add(&self, other: &Self) -> Self {
        let z1sq = self.z.square();
        let z2sq = other.z.square();
        let u1 = self.x.mul(&z2sq);
        let u2 = other.x.mul(&z1sq);
        let z1cu = z1sq.mul(&self.z);
        let z2cu = z2sq.mul(&other.z);
        let s1 = self.y.mul(&z2cu);
        let s2 = other.y.mul(&z1cu);
        let h = u2.sub(&u1);
        let r = s2.sub(&s1);
        let h2 = h.square();
        let h3 = h2.mul(&h);
        let u1h2 = u1.mul(&h2);
        let x3 = r.square().sub(&h3).sub(&u1h2).sub(&u1h2);
        let y3 = r.mul(&u1h2.sub(&x3)).sub(&s1.mul(&h3));
        let z3 = self.z.mul(&other.z).mul(&h);
        let mixed = Self {
            x: x3,
            y: y3,
            z: z3,
            infinity: 0,
        };
        let dbl = self.double();
        let eq_x = u1.ct_eq(&u2);
        let eq_y = s1.ct_eq(&s2);
        let both = eq_x & eq_y;
        let opp = eq_x & (eq_y ^ 1);
        let mut out = Self::ct_select(both, &dbl, &mixed);
        out = Self::ct_select(opp, &Self::identity(), &out);
        out = Self::ct_select(self.infinity, other, &out);
        out = Self::ct_select(other.infinity & (self.infinity ^ 1), self, &out);
        out
    }
    fn neg(&self) -> Self {
        let n = Self {
            x: self.x,
            y: self.y.neg(),
            z: self.z,
            infinity: self.infinity,
        };
        Self::ct_select(self.infinity, self, &n)
    }

    /// Variable-time mixed addition: `self` arbitrary Jacobian, `other` AFFINE
    /// (`z == 1`). Same sum as [`add`](Self::add) when the contract holds;
    /// falls back to the full formula on `H == 0` (doubling/edge case).
    /// Batching/MSM paths only: all Pippenger bases decode from compressed
    /// bytes (affine). The constant-time [`add`](Self::add) is unchanged.
    fn add_mixed_vartime(&self, other: &Self) -> Self {
        if self.infinity == 1 {
            return *other;
        }
        if other.infinity == 1 {
            return *self;
        }
        let z1sq = self.z.mul_vartime(&self.z);
        let u2 = other.x.mul_vartime(&z1sq);
        let s2 = other.y.mul_vartime(&z1sq).mul_vartime(&self.z);
        let h = u2.sub_vartime(&self.x);
        if h.is_zero() {
            return self.add(other);
        }
        let r = s2.sub_vartime(&self.y);
        let h2 = h.mul_vartime(&h);
        let h3 = h2.mul_vartime(&h);
        let u1h2 = self.x.mul_vartime(&h2);
        let x3 = r
            .mul_vartime(&r)
            .sub_vartime(&h3)
            .sub_vartime(&u1h2)
            .sub_vartime(&u1h2);
        let y3 = r
            .mul_vartime(&u1h2.sub_vartime(&x3))
            .sub_vartime(&self.y.mul_vartime(&h3));
        let z3 = self.z.mul_vartime(&h);
        Self {
            x: x3,
            y: y3,
            z: z3,
            infinity: 0,
        }
    }

    /// Variable-time addition used by batching code paths only.
    /// Skips identity inputs; otherwise the exact [`add`] formula with
    /// variable-time field ops (same sums; all batching values canonical).
    /// See [`VestaPoint::add_vartime`] for the timing contract.
    fn add_vartime(&self, other: &Self) -> Self {
        if self.infinity == 1 {
            return *other;
        }
        if other.infinity == 1 {
            return *self;
        }
        let z1sq = self.z.mul_vartime(&self.z);
        let z2sq = other.z.mul_vartime(&other.z);
        let u1 = self.x.mul_vartime(&z2sq);
        let u2 = other.x.mul_vartime(&z1sq);
        let z1cu = z1sq.mul_vartime(&self.z);
        let z2cu = z2sq.mul_vartime(&other.z);
        let s1 = self.y.mul_vartime(&z2cu);
        let s2 = other.y.mul_vartime(&z1cu);
        let h = u2.sub_vartime(&u1);
        let r = s2.sub_vartime(&s1);
        let h2 = h.mul_vartime(&h);
        let h3 = h2.mul_vartime(&h);
        let u1h2 = u1.mul_vartime(&h2);
        let x3 = r
            .mul_vartime(&r)
            .sub_vartime(&h3)
            .sub_vartime(&u1h2)
            .sub_vartime(&u1h2);
        let y3 = r
            .mul_vartime(&u1h2.sub_vartime(&x3))
            .sub_vartime(&s1.mul_vartime(&h3));
        let z3 = self.z.mul_vartime(&other.z).mul_vartime(&h);
        let mixed = Self {
            x: x3,
            y: y3,
            z: z3,
            infinity: 0,
        };
        let dbl = self.double();
        let eq_x = u1.ct_eq(&u2);
        let eq_y = s1.ct_eq(&s2);
        let both = eq_x & eq_y;
        let opp = eq_x & (eq_y ^ 1);
        let mut out = Self::ct_select(both, &dbl, &mixed);
        out = Self::ct_select(opp, &Self::identity(), &out);
        out = Self::ct_select(self.infinity, other, &out);
        out = Self::ct_select(other.infinity & (self.infinity ^ 1), self, &out);
        out
    }

    /// Variable-time doubling used by batching code paths only.
    /// Same formula as [`double`](Self::double) with variable-time field
    /// ops (same sums). See [`VestaPoint::add_vartime`] for the timing contract.
    fn double_vartime(&self) -> Self {
        if self.infinity == 1 {
            return Self::identity();
        }
        // Jacobian doubling for a=0 (inversion-free), same as Pallas.
        let yy = self.y.mul_vartime(&self.y);
        let mut s = self.x.mul_vartime(&yy);
        s = s.add_vartime(&s);
        s = s.add_vartime(&s); // 4 X Y²
        let xx = self.x.mul_vartime(&self.x);
        let m = xx.add_vartime(&xx).add_vartime(&xx); // 3 X²
        let x3 = m.mul_vartime(&m).sub_vartime(&s).sub_vartime(&s);
        let mut y4 = yy.mul_vartime(&yy);
        y4 = y4.add_vartime(&y4);
        y4 = y4.add_vartime(&y4);
        y4 = y4.add_vartime(&y4); // 8 Y⁴
        let y3 = m.mul_vartime(&s.sub_vartime(&x3)).sub_vartime(&y4);
        let yz = self.y.mul_vartime(&self.z);
        let z3 = yz.add_vartime(&yz); // 2 Y Z
        let computed = Self {
            x: x3,
            y: y3,
            z: z3,
            infinity: 0,
        };
        let y_zero = self.y.ct_eq(&Fe::zero());
        Self::ct_select(self.infinity | y_zero, &Self::identity(), &computed)
    }

    /// 4-bit fixed-window CT scalar mul (table select via ct_eq_u8).
    fn mul(&self, scalar: &Scalar) -> Self {
        let mut table = [Self::identity(); 16];
        table[1] = *self;
        for i in 2..16 {
            if i & 1 == 0 {
                table[i] = table[i / 2].double();
            } else {
                table[i] = table[i - 1].add(self);
            }
        }
        let mut r = Self::identity();
        for w in (0..64).rev() {
            r = r.double().double().double().double();
            let mut bits = 0u8;
            for b in 0..4 {
                bits |= (scalar.bit(w * 4 + b) & 1) << b;
            }
            let mut t = Self::identity();
            for (i, ti) in table.iter().enumerate() {
                let eq = crate::ct::ct_eq_u8(bits, i as u8);
                t = Self::ct_select(eq, ti, &t);
            }
            r = r.add(&t);
        }
        r
    }
    #[allow(clippy::wrong_self_convention)] // `to_affine(&self)` keeps the crate-wide point API; renaming would churn audited call sites.
    fn to_affine(&self) -> CurveResult<(Fe, Fe)> {
        if self.infinity == 1 {
            return Err(CurveError::InvalidPoint);
        }
        let z_inv = self.z.invert()?;
        let z2 = z_inv.square();
        let z3 = z2.mul(&z_inv);
        Ok((self.x.mul(&z2), self.y.mul(&z3)))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct VestaPoint {
    inner: Jac,
}

impl VestaPoint {
    pub fn generator() -> Self {
        Self {
            inner: Jac::generator(),
        }
    }

    /// Variable-time point addition (for MSM batching, never secret paths).
    ///
    /// Same group law as the constant-time [`add`][CurvePoint::add]; the only
    /// difference is operational: identity inputs short-circuit instead of
    /// flowing through `ct_select`. Timing therefore varies with input
    /// triviality — use only where that is public information (e.g. bucket
    /// warmup) or a negligible-probability event (uniform blinds that happen
    /// to be exactly zero). The constant-time methods are unchanged.
    pub fn add_vartime(&self, other: &Self) -> Self {
        Self {
            inner: self.inner.add_vartime(&other.inner),
        }
    }

    /// Variable-time mixed addition: `other` must be AFFINE (all Pippenger
    /// bases decode from compressed bytes). Same contract as [`add_vartime`].
    pub fn add_mixed_vartime(&self, other: &Self) -> Self {
        Self {
            inner: self.inner.add_mixed_vartime(&other.inner),
        }
    }

    /// Variable-time single-scalar multiplication (4-bit window, direct
    /// table indexing — no per-nibble selects).
    /// Same point as [`mul`][CurvePoint::mul] (same group law, only the
    /// evaluation schedule differs; affine outputs are identical).
    /// Batching/prover paths only — e.g. IPA generator folds with public
    /// challenges. The constant-time [`mul`][CurvePoint::mul] is unchanged.
    pub fn mul_vartime(&self, scalar: &Scalar) -> Self {
        let mut table = [Self::identity(); 16];
        table[1] = *self;
        for i in 2..16 {
            if i & 1 == 0 {
                table[i] = table[i / 2].double_vartime();
            } else {
                table[i] = table[i - 1].add_vartime(self);
            }
        }
        let mut sb = [0u8; 32];
        scalar.to_bytes_le(&mut sb);
        let mut r = Self::identity();
        for w in (0..64).rev() {
            r = r.double_vartime();
            r = r.double_vartime();
            r = r.double_vartime();
            r = r.double_vartime();
            let nib = (sb[w / 2] >> ((w % 2) * 4)) & 0xf;
            if nib != 0 {
                r = r.add_vartime(&table[nib as usize]);
            }
        }
        r
    }

    /// Variable-time point doubling (same contract as [`add_vartime`]).
    pub fn double_vartime(&self) -> Self {
        Self {
            inner: self.inner.double_vartime(),
        }
    }
}

/// Pippenger bucket multi-scalar multiplication (**variable-time** batching).
///
/// Computes the identical sum as the naive per-point loop. Uses only the
/// variable-time [`VestaPoint::add_vartime`]/[`double_vartime`] entry points;
/// the constant-time [`add`][CurvePoint::add]/`double`/`mul` methods are
/// untouched. Exact-zero scalars are skipped (negligible event for uniform
/// blinds; same convention as the naive loops this replaces).
///
/// # Timing: variable-time, prover-only. Never use with secret scalars.
pub fn pippenger_msm(bases: &[VestaPoint], scalars: &[Scalar]) -> VestaPoint {
    pippenger_msm_vartime(bases, scalars)
}

/// Variable-time Pippenger core (see [`pippenger_msm`]).
pub fn pippenger_msm_vartime(bases: &[VestaPoint], scalars: &[Scalar]) -> VestaPoint {
    let n = core::cmp::min(bases.len(), scalars.len());
    if n < 32 {
        // Small sizes: naive loop with variable-time single mul (fast path).
        let mut acc = VestaPoint::identity();
        for i in 0..n {
            if scalars[i].is_zero() {
                continue;
            }
            acc = acc.add_vartime(&bases[i].mul_vartime(&scalars[i]));
        }
        return acc;
    }
    // Window size 8: (256/8) passes over bases, 256 buckets per window.
    // All prove-path MSMs are <= 2048 points, where W=8 is optimal
    // (matches official adaptive c = ceil(ln n) at n=2048).
    const W: usize = 8;
    const NW: usize = 256 / W;
    // Scalar bytes once (no per-bit calls in the hot loop); nonzero flags
    // hoisted (uniform blinds are ~never exactly zero).
    let mut sbytes: alloc::vec::Vec<[u8; 32]> = alloc::vec::Vec::with_capacity(n);
    let mut nonzero: alloc::vec::Vec<bool> = alloc::vec::Vec::with_capacity(n);
    for s in scalars.iter().take(n) {
        let mut b = [0u8; 32];
        s.to_bytes_le(&mut b);
        nonzero.push(b.iter().any(|&x| x != 0));
        sbytes.push(b);
    }
    // Mixed bucket adds need affine bases. Const bases (params G/G_LAGRANGE)
    // decode affine; P7-collapsed generator tables do not — check once.
    let all_affine = bases
        .iter()
        .take(n)
        .all(|b| b.inner.z.ct_eq(&Fe::one()) == 1);
    let mut result = VestaPoint::identity();
    // Worker count for window fan-out (1 = sequential; no threads spawned).
    let mut nworkers = crate::multicore::num_threads().min(NW);
    if n < 256 {
        nworkers = 1;
    }
    if nworkers <= 1 {
        for j in (0..NW).rev() {
            for _ in 0..W {
                result = result.double_vartime();
            }
            result = result.add_vartime(&vesta_window_sum(
                j, bases, &sbytes, &nonzero, all_affine, n,
            ));
        }
        return result;
    }
    // Parallel windows, sequential combine (identical sums either way).
    let mut sums = alloc::vec![VestaPoint::identity(); NW];
    let chunk = NW.div_ceil(nworkers);
    crate::multicore::scope(|s| {
        let mut guards = alloc::vec::Vec::new();
        for (ci, slot) in sums.chunks_mut(chunk).enumerate() {
            let start = ci * chunk;
            // Borrow slices explicitly so worker closures own no outer borrows.
            let (bases, sbytes, nonzero) = (&bases[..n], &sbytes[..], &nonzero[..]);
            guards.push(s.spawn(move || {
                for (k, dst) in slot.iter_mut().enumerate() {
                    *dst = vesta_window_sum(start + k, bases, sbytes, nonzero, all_affine, n);
                }
            }));
        }
        for g in guards {
            crate::multicore::Scope::join(g);
        }
    });
    for j in (0..NW).rev() {
        for _ in 0..W {
            result = result.double_vartime();
        }
        result = result.add_vartime(&sums[j]);
    }
    result
}

/// Per-window independent bucket sum for [`pippenger_msm`] (no cross-window
/// state, so windows evaluate in any order or in parallel).
fn vesta_window_sum(
    j: usize,
    bases: &[VestaPoint],
    sbytes: &[[u8; 32]],
    nonzero: &[bool],
    all_affine: bool,
    n: usize,
) -> VestaPoint {
    const NB: usize = 1 << 8;
    let mut buckets = alloc::vec![VestaPoint::identity(); NB];
    for i in 0..n {
        if !nonzero[i] {
            continue;
        }
        // W=8: window j is byte j (LE scalars).
        let d = sbytes[i][j] as usize;
        if d == 0 {
            continue;
        }
        // Bases are affine (decoded from compressed bytes): mixed add.
        buckets[d] = if all_affine {
            buckets[d].add_mixed_vartime(&bases[i])
        } else {
            buckets[d].add_vartime(&bases[i])
        };
    }
    let mut running = VestaPoint::identity();
    let mut sum = VestaPoint::identity();
    for d in (1..NB).rev() {
        running = running.add_vartime(&buckets[d]);
        sum = sum.add_vartime(&running);
    }
    sum
}

impl VestaPoint {
    /// Affine point from Montgomery limbs (unchecked: no on-curve check,
    /// no conversion). Caller must supply trusted `x*R/y*R` limbs, `z = R`.
    /// Mirrors the Pallas version; for compile-time generator tables.
    pub const fn from_affine_mont_limbs(x: [u64; 4], y: [u64; 4]) -> Self {
        const Z_ONE: [u64; 4] = [
            0x5b2b_3e9c_ffff_fffd,
            0x992c_350b_e342_0567,
            0xffff_ffff_ffff_ffff,
            0x3fff_ffff_ffff_ffff,
        ];
        Self {
            inner: Jac {
                x: Fe::from_raw_mont(x),
                y: Fe::from_raw_mont(y),
                z: Fe::from_raw_mont(Z_ONE),
                infinity: 0,
            },
        }
    }

    /// Affine Montgomery (x, y) limbs; errors on identity.
    pub fn to_affine_mont_limbs(&self) -> CurveResult<([u64; 4], [u64; 4])> {
        let (x, y) = self.inner.to_affine()?;
        Ok((x.to_raw_mont(), y.to_raw_mont()))
    }
}

impl VestaPoint {
    /// Inherent identity (same as trait).
    pub fn identity() -> Self {
        Self {
            inner: Jac::identity(),
        }
    }

    /// Inherent identity test (same as trait).
    pub fn is_identity(&self) -> bool {
        self.inner.infinity == 1 || self.inner.z.is_zero()
    }

    /// Inherent doubling (same as trait CT version; cheap).
    pub fn double(&self) -> Self {
        Self {
            inner: self.inner.double(),
        }
    }

    /// Inherent negation (same as trait).
    pub fn neg(&self) -> Self {
        Self {
            inner: self.inner.neg(),
        }
    }

    /// Build from LE affine coordinates, by value (checks on-curve).
    pub fn from_le_xy(x_le: [u8; 32], y_le: [u8; 32]) -> CurveResult<Self> {
        Self::from_affine_le(&x_le, &y_le)
    }

    /// Build from LE affine coordinates (checks on-curve `y^2 == x^3 + 5`).
    pub fn from_affine_le(x_le: &[u8; 32], y_le: &[u8; 32]) -> CurveResult<Self> {
        let x = Fe::from_le_array(x_le)?;
        let y = Fe::from_le_array(y_le)?;
        let y2 = y.square();
        let x3 = x.square().mul(&x);
        let rhs = x3.add(&CURVE_B);
        if y2.ct_eq(&rhs) != 1 {
            return Err(CurveError::InvalidPoint);
        }
        Ok(Self {
            inner: Jac {
                x,
                y,
                z: Fe::one(),
                infinity: 0,
            },
        })
    }

    /// Affine coordinates directly (no bytes roundtrip): `x = X/Z^2`, `y = Y/Z^3`.
    /// Same values as [`to_affine_le`](Self::to_affine_le); errors on identity.
    /// Fast path for affine inputs (`z == 1`): no inversion.
    pub fn to_affine_coords(&self) -> CurveResult<(Fe, Fe)> {
        if self.is_identity() {
            return Err(CurveError::InvalidPoint);
        }
        if self.inner.z == Fe::one() {
            return Ok((self.inner.x, self.inner.y));
        }
        self.inner.to_affine()
    }

    /// LE affine coordinates + identity flag.
    pub fn to_affine_le(&self) -> CurveResult<([u8; 32], [u8; 32], bool)> {
        if self.is_identity() {
            return Ok(([0u8; 32], [0u8; 32], true));
        }
        let (x, y) = self.inner.to_affine()?;
        Ok((x.to_le_bytes(), y.to_le_bytes(), false))
    }

    /// Pasta compressed decode from a slice (all-zero → identity).
    pub fn from_compressed(bytes: &[u8]) -> CurveResult<Self> {
        use crate::curve::traits::CurvePoint as _;
        Self::from_bytes(bytes)
    }

    /// Pasta compressed encode (identity → zeros).
    pub fn to_compressed(&self) -> CurveResult<[u8; 32]> {
        use crate::curve::traits::CurvePoint as _;
        let mut out = [0u8; 32];
        self.to_bytes_compressed(&mut out)?;
        Ok(out)
    }

    /// Identity conversion (single point type).
    pub fn to_projective(&self) -> CurveResult<Self> {
        Ok(*self)
    }

    /// Debug string in Halo2 format `Vesta(x: 0x.., y: 0x..)`.
    pub fn to_debug_string(&self) -> alloc::string::String {
        fn hex_be_le(le: &[u8; 32]) -> alloc::string::String {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            let mut s = alloc::string::String::from("0x");
            for i in (0..32).rev() {
                s.push(HEX[(le[i] >> 4) as usize] as char);
                s.push(HEX[(le[i] & 15) as usize] as char);
            }
            s
        }
        if self.is_identity() {
            return alloc::string::String::from("Vesta(identity)");
        }
        let (x, y, _) = match self.to_affine_le() {
            Ok(v) => v,
            Err(_) => return alloc::string::String::from("Vesta(identity)"),
        };
        let mut s = alloc::string::String::from("Vesta(x: ");
        s.push_str(&hex_be_le(&x));
        s.push_str(", y: ");
        s.push_str(&hex_be_le(&y));
        s.push(')');
        s
    }
}

impl PartialEq for VestaPoint {
    fn eq(&self, other: &Self) -> bool {
        // Canonical compressed encoding (affine-normalized; identity → zeros).
        self.to_compressed().unwrap_or([0u8; 32]) == other.to_compressed().unwrap_or([0u8; 32])
    }
}
impl Eq for VestaPoint {}

impl CurvePoint for VestaPoint {
    type Scalar = Scalar;
    const COMPRESSED_BYTES: usize = 32;
    const UNCOMPRESSED_BYTES: usize = 64;

    fn identity() -> Self {
        Self {
            inner: Jac::identity(),
        }
    }
    fn ct_is_identity(&self) -> u8 {
        self.inner.ct_is_identity()
    }
    fn double(&self) -> Self {
        Self {
            inner: self.inner.double(),
        }
    }
    fn add(&self, other: &Self) -> Self {
        Self {
            inner: self.inner.add(&other.inner),
        }
    }
    fn neg(&self) -> Self {
        Self {
            inner: self.inner.neg(),
        }
    }
    fn mul(&self, scalar: &Self::Scalar) -> Self {
        Self {
            inner: self.inner.mul(scalar),
        }
    }
    fn from_bytes(bytes: &[u8]) -> CurveResult<Self> {
        // Pasta-style: LE x with y-sign in high bit of last byte.
        if bytes.len() == 32 {
            if bytes.iter().all(|&b| b == 0) {
                return Ok(Self::identity());
            }
            let sign = (bytes[31] >> 7) & 1;
            let mut le = [0u8; 32];
            le.copy_from_slice(bytes);
            le[31] &= 0x7f;
            let mut be = [0u8; 32];
            for i in 0..32 {
                be[i] = le[31 - i];
            }
            let x = Fe::from_bytes_be(&be)?;
            let y2 = x.square().mul(&x).add(&CURVE_B);
            let mut y = y2.sqrt().map_err(|_| CurveError::InvalidPoint)?;
            y = Fe::ct_select(sign ^ y.is_odd(), &y.neg(), &y);
            return Ok(Self {
                inner: Jac {
                    x,
                    y,
                    z: Fe::one(),
                    infinity: 0,
                },
            });
        }
        if bytes.len() == 64 {
            let mut xb = [0u8; 32];
            let mut yb = [0u8; 32];
            for i in 0..32 {
                xb[i] = bytes[31 - i];
                yb[i] = bytes[32 + 31 - i];
            }
            let x = Fe::from_bytes_be(&xb)?;
            let y = Fe::from_bytes_be(&yb)?;
            return Ok(Self {
                inner: Jac {
                    x,
                    y,
                    z: Fe::one(),
                    infinity: 0,
                },
            });
        }
        Err(CurveError::InvalidLength)
    }
    fn to_bytes_compressed(&self, out: &mut [u8]) -> CurveResult<()> {
        if out.len() != 32 {
            return Err(CurveError::InvalidLength);
        }
        if self.ct_is_identity() == 1 {
            out.fill(0);
            return Ok(());
        }
        let (x, y) = self
            .inner
            .to_affine()
            .map_err(|_| CurveError::InvalidPoint)?;
        let mut xb = [0u8; 32];
        let mut yb = [0u8; 32];
        x.to_bytes_be(&mut xb);
        y.to_bytes_be(&mut yb);
        for i in 0..32 {
            out[i] = xb[31 - i];
        }
        out[31] |= (yb[31] & 1) << 7;
        Ok(())
    }
    fn to_bytes_uncompressed(&self, out: &mut [u8]) -> CurveResult<()> {
        if out.len() != 64 {
            return Err(CurveError::InvalidLength);
        }
        if self.ct_is_identity() == 1 {
            out.fill(0);
            return Ok(());
        }
        let (x, y) = self
            .inner
            .to_affine()
            .map_err(|_| CurveError::InvalidPoint)?;
        let mut xb = [0u8; 32];
        let mut yb = [0u8; 32];
        x.to_bytes_be(&mut xb);
        y.to_bytes_be(&mut yb);
        for i in 0..32 {
            out[i] = xb[31 - i];
            out[32 + i] = yb[31 - i];
        }
        Ok(())
    }
}

impl Fe {
    pub fn legendre(&self) -> i8 {
        if self.is_zero() {
            return 0;
        }
        let mut exp = P_BE;
        let mut carry = 0u8;
        for e in exp.iter_mut() {
            let v = *e;
            *e = (v >> 1) | (carry << 7);
            carry = v & 1;
        }
        let base = *self;
        let mut result = Fe::one();
        for byte in exp.iter() {
            for bit in (0..8).rev() {
                result = result.square();
                if (byte >> bit) & 1 == 1 {
                    result = result.mul(&base);
                }
            }
        }
        if result.ct_eq(&Fe::one()) == 1 {
            1
        } else {
            -1
        }
    }

    pub fn sqrt(&self) -> CurveResult<Self> {
        if self.is_zero() {
            return Ok(Fe::zero());
        }
        if self.legendre() != 1 {
            return Err(CurveError::NotInvertible);
        }
        let mut z = Fe::one().add(&Fe::one());
        while z.legendre() != -1 {
            z = z.add(&Fe::one());
        }
        let s = 32u32;
        let mut q_bytes = P_BE;
        let mut borrow = 1u32;
        for i in (0..32).rev() {
            let v = q_bytes[i] as u32;
            if v >= borrow {
                q_bytes[i] = (v - borrow) as u8;
                borrow = 0;
            } else {
                q_bytes[i] = (v + 256 - borrow) as u8;
                borrow = 1;
            }
        }
        for i in (4..32).rev() {
            q_bytes[i] = q_bytes[i - 4];
        }
        for q in q_bytes.iter_mut().take(4) {
            *q = 0;
        }
        let mut c = Fe::one();
        let base_z = z;
        for byte in q_bytes.iter() {
            for bit in (0..8).rev() {
                c = c.square();
                if (byte >> bit) & 1 == 1 {
                    c = c.mul(&base_z);
                }
            }
        }
        let mut qp1 = q_bytes;
        let mut carry = 1u32;
        for i in (0..32).rev() {
            let v = qp1[i] as u32 + carry;
            qp1[i] = (v & 0xff) as u8;
            carry = v >> 8;
        }
        let mut carry_b = 0u8;
        for q in qp1.iter_mut() {
            let v = *q;
            *q = (v >> 1) | (carry_b << 7);
            carry_b = v & 1;
        }
        let mut r = Fe::one();
        let base_a = *self;
        for byte in qp1.iter() {
            for bit in (0..8).rev() {
                r = r.square();
                if (byte >> bit) & 1 == 1 {
                    r = r.mul(&base_a);
                }
            }
        }
        let mut t = Fe::one();
        for byte in q_bytes.iter() {
            for bit in (0..8).rev() {
                t = t.square();
                if (byte >> bit) & 1 == 1 {
                    t = t.mul(&base_a);
                }
            }
        }
        let mut m = s;
        while t.ct_eq(&Fe::one()) != 1 {
            let mut i = 1u32;
            let mut t2i = t.square();
            while t2i.ct_eq(&Fe::one()) != 1 && i < m {
                t2i = t2i.square();
                i += 1;
            }
            let mut b = c;
            for _ in 0..(m - i - 1) {
                b = b.square();
            }
            r = r.mul(&b);
            c = b.square();
            t = t.mul(&c);
            m = i;
        }
        Ok(r)
    }

    pub fn is_odd(&self) -> u8 {
        let c = Self::mont_mul_raw(&self.n, &[1, 0, 0, 0]).reduce();
        (c.n[0] & 1) as u8
    }

    pub fn sqrt_ratio(num: &Self, div: &Self) -> (u8, Self) {
        let inv = match div.invert() {
            Ok(v) => v,
            Err(_) => return (num.is_zero() as u8, Fe::zero()),
        };
        let ratio = num.mul(&inv);
        if ratio.is_zero() {
            return (1, Fe::zero());
        }
        match ratio.sqrt() {
            Ok(y) => (1, y),
            Err(_) => {
                let root = Fe::mont_mul_raw(
                    &[
                        0xa70e_2c11_02b6_d05f,
                        0x9bb9_7ea3_c106_f049,
                        0x9e5c_4dfd_492a_e26e,
                        0x2de6_a9b8_746d_3f58,
                    ],
                    &r2_p(),
                );
                let y = ratio.mul(&root).sqrt().unwrap_or(Fe::one());
                (0, y)
            }
        }
    }
}


fn expand_message_xmd(msg: &[u8], dst: &[u8], len: usize) -> alloc::vec::Vec<u8> {
    const B_IN: usize = 32;
    const S_IN: usize = 64;
    let ell = len.div_ceil(B_IN);
    assert!(ell <= 255);
    assert!(dst.len() < 256);

    let mut dst_prime = alloc::vec::Vec::with_capacity(dst.len() + 1);
    dst_prime.extend_from_slice(dst);
    dst_prime.push(dst.len() as u8);

    let l_i_b_str = [(len >> 8) as u8, (len & 0xff) as u8];

    let mut h = crate::hash::Sha256::new();
    h.update(&[0u8; S_IN]);
    h.update(msg);
    h.update(&l_i_b_str);
    h.update(&[0u8]);
    h.update(&dst_prime);
    let b0 = h.finalize();

    let mut h = crate::hash::Sha256::new();
    h.update(&b0);
    h.update(&[1u8]);
    h.update(&dst_prime);
    let mut bi = h.finalize();

    let mut out = alloc::vec::Vec::with_capacity(ell * B_IN);
    out.extend_from_slice(&bi);

    for i in 2..=ell {
        let mut xored = [0u8; B_IN];
        for j in 0..B_IN {
            xored[j] = b0[j] ^ bi[j];
        }
        let mut h = crate::hash::Sha256::new();
        h.update(&xored);
        h.update(&[i as u8]);
        h.update(&dst_prime);
        bi = h.finalize();
        out.extend_from_slice(&bi);
    }
    out.truncate(len);
    out
}

fn fe_from_uniform_bytes(buf: &[u8]) -> Fe {
    let n = buf.len().min(64);
    let mut padded = [0u8; 64];
    if n > 0 {
        padded[64 - n..].copy_from_slice(&buf[..n]);
    }
    let mut limbs = [0u64; 8];
    for i in 0..8 {
        let o = i * 8;
        limbs[7 - i] = u64::from_be_bytes([
            padded[o],
            padded[o + 1],
            padded[o + 2],
            padded[o + 3],
            padded[o + 4],
            padded[o + 5],
            padded[o + 6],
            padded[o + 7],
        ]);
    }
    // Canonical reduction then map into Montgomery domain
    let c = reduce_512_via_r(&limbs, &r256_p(), &p_limbs());
    Fe::mont_mul_raw(&c.n, &r2_p())
}

/// Montgomery limbs (precomputed; replaces per-call `fe_from_limbs`).
const ISO_A: Fe = Fe::from_raw_mont([0xe39dd73ce5fa2060, 0xa67a4eac41bd984a, 0x4e9334381c85040e, 0x287658b7203524b5]);
/// Montgomery limbs (precomputed; replaces per-call `fe_from_limbs`).
const ISO_B: Fe = Fe::from_raw_mont([0xe28772dcffffec3d, 0xa6dec34eab3aedd4, 0xfffffffffffffd5a, 0x3fffffffffffffff]);
/// Montgomery limbs (precomputed; replaces per-call `fe_from_limbs`).
const CURVE_B: Fe = Fe::from_raw_mont([0x96bc8c8cffffffed, 0x74c2a54b49f7778e, 0xfffffffffffffffd, 0x3fffffffffffffff]);
/// Montgomery limbs (precomputed; replaces per-call `fe_from_limbs`).
const SSWU_Z: Fe = Fe::from_raw_mont([0x7e67c2b400000034, 0xf6571331f2324d00, 0x6, 0x0]);
/// Montgomery limbs (precomputed; replaces per-call `fe_from_limbs`).
const SSWU_THETA: Fe = Fe::from_raw_mont([0x8ecbbc76a786d3d6, 0xdf6c9d9670dbfea1, 0xee4783b82e23b381, 0x2999ce687f903c5a]);
/// Isogeny constants in Montgomery form (zero runtime conversion).
/// Source: pasta_curves `VESTA_ISOGENY` limbs converted once via `fe_from_limbs`;
/// values are `to_raw_mont` dumps — do not hand-edit.
const ISO_FES: [Fe; 13] = [
    Fe::from_raw_mont([0xad6517ce71c71c72, 0xb24893c63b04974d, 0xaaaaaaaaaaaaaaaa, 0x2aaaaaaaaaaaaaaa]),
    Fe::from_raw_mont([0x46361151a9354d4b, 0x681b8597f431b790, 0xa27b0945498c318f, 0x3aa4c7434d930578]),
    Fe::from_raw_mont([0x33de750af21121c7, 0xf71496fffd0bf228, 0x5cfe5d49550435ff, 0x3cb4babf63329c09]),
    Fe::from_raw_mont([0xbff8f6d3e38e383b, 0xc3f6292a22e5b459, 0x555555555555553e, 0x1555555555555555]),
    Fe::from_raw_mont([0x15af42d6f2dfb79b, 0x96c2ea77491a2d26, 0xb653536f95edbe09, 0xfcb015dba2b313d]),
    Fe::from_raw_mont([0xc58961ee87ce8fe4, 0xb646fc62c0be0c9a, 0xced3d6bbf771b1fb, 0x270fb22f765674fc]),
    Fe::from_raw_mont([0x41fba4b025ed097c, 0xfcf1ec94c4b9f858, 0x8e38e38e38e38e38, 0x38e38e38e38e38e3]),
    Fe::from_raw_mont([0xe93e7e39549aa6a6, 0xc5310f49fee33036, 0x513d84a2a4c618c7, 0x3d5263a1a6c982bc]),
    Fe::from_raw_mont([0x9d728f7acce97bd7, 0x2e8f3c5fdb9f6044, 0x54fa00b78d0f70aa, 0x33ec021316643c22]),
    Fe::from_raw_mont([0xcf9720f8bda12ff4, 0x263ae4ccee9b8f6b, 0xc71c71c71c71c72f, 0x1c71c71c71c71c71]),
    Fe::from_raw_mont([0xe6aa59d2ec4f9369, 0x7347ac30f2719827, 0x917cfd2760e49d0e, 0x37b0820c9740c9dc]),
    Fe::from_raw_mont([0xc4553aaa976bafab, 0x8e5c2c38a57cf2, 0x6c7b8433e65515f3, 0x352f168e63035ef6]),
    Fe::from_raw_mont([0x965fe67000000870, 0x33aace90d650cd4f, 0x121, 0x0]),
];

/// 3-isogeny IsoEq → Vesta (Eq), matching pasta_curves `iso_map`.
fn iso_map_3(p: &Jac) -> Jac {
    if p.infinity == 1 {
        return Jac::identity();
    }
    let (x, y, z) = (p.x, p.y, p.z);
    let z2 = z.square();
    let z3 = z2.mul(&z);
    let z4 = z2.square();
    let z6 = z3.square();
    let iso: [Fe; 13] = ISO_FES;
    let num_x = iso[0]
        .mul(&x)
        .add(&iso[1].mul(&z2))
        .mul(&x)
        .add(&iso[2].mul(&z4))
        .mul(&x)
        .add(&iso[3].mul(&z6));
    let div_x = z2
        .mul(&x)
        .add(&iso[4].mul(&z4))
        .mul(&x)
        .add(&iso[5].mul(&z6));
    let num_y = iso[6]
        .mul(&x)
        .add(&iso[7].mul(&z2))
        .mul(&x)
        .add(&iso[8].mul(&z4))
        .mul(&x)
        .add(&iso[9].mul(&z6))
        .mul(&y);
    let div_y = x
        .add(&iso[10].mul(&z2))
        .mul(&x)
        .add(&iso[11].mul(&z4))
        .mul(&x)
        .add(&iso[12].mul(&z6))
        .mul(&z3);
    let zo = div_x.mul(&div_y);
    let xo = num_x.mul(&div_y).mul(&zo);
    let yo = num_y.mul(&div_x).mul(&zo.square());
    Jac {
        x: xo,
        y: yo,
        z: zo,
        infinity: 0,
    }
}

fn map_to_curve_sswu(u: &Fe) -> Jac {
    let (a, b, z, theta) = (ISO_A, ISO_B, SSWU_Z, SSWU_THETA);
    let z_u2 = z.mul(&u.square());
    let ta = z_u2.square().add(&z_u2);
    let num_x1 = b.mul(&ta.add(&Fe::one()));
    let neg_ta = ta.neg();
    let div_sel = Fe::ct_select(ta.is_zero() as u8, &z, &neg_ta);
    let div = a.mul(&div_sel);
    let num2_x1 = num_x1.square();
    let div2 = div.square();
    let div3 = div2.mul(&div);
    let num_gx1 = num2_x1.add(&a.mul(&div2)).mul(&num_x1).add(&b.mul(&div3));
    let num_x2 = z_u2.mul(&num_x1);
    let (gx1_is_square, y1) = Fe::sqrt_ratio(&num_gx1, &div3);
    let y2 = theta.mul(&z_u2).mul(u).mul(&y1);
    let num_x = Fe::ct_select(gx1_is_square, &num_x1, &num_x2);
    let y = Fe::ct_select(gx1_is_square, &y1, &y2);
    // sgn0 match — CT, no branch
    let y = Fe::ct_select(u.is_odd() ^ y.is_odd(), &y.neg(), &y);
    Jac {
        x: num_x.mul(&div),
        y: y.mul(&div3),
        z: div,
        infinity: 0,
    }
}

/// Map 64 LE uniform bytes → Fe (`fromBytes64` / pasta).
fn fe_from_bytes64_le(buf: &[u8]) -> Fe {
    let n = buf.len().min(64);
    let mut limbs = [0u64; 8];
    for (i, li) in limbs.iter_mut().enumerate().take(n / 8) {
        let o = i * 8;
        *li = u64::from_le_bytes([
            buf[o],
            buf[o + 1],
            buf[o + 2],
            buf[o + 3],
            buf[o + 4],
            buf[o + 5],
            buf[o + 6],
            buf[o + 7],
        ]);
    }
    let c = reduce_512_via_r(&limbs, &r256_p(), &p_limbs());
    Fe::mont_mul_raw(&c.n, &r2_p())
}

/// Pasta / Halo2 `hash_to_curve` using Blake2b-XMD field hash .
///
/// `domain_prefix` e.g. `"Halo2-Parameters"`; curve id fixed to `"vesta"`.
/// `u0||u1` come from the same construction as `PastaUtils.hashToFiled`.
pub fn hash_to_curve_from_field_hash(u0_le64: &[u8; 64], u1_le64: &[u8; 64]) -> VestaPoint {
    let u0 = fe_from_bytes64_le(u0_le64);
    let u1 = fe_from_bytes64_le(u1_le64);
    let sum = map_to_curve_sswu(&u0).add(&map_to_curve_sswu(&u1));
    VestaPoint {
        inner: iso_map_3(&sum),
    }
}

pub fn hash_to_curve(msg: &[u8], dst: &[u8]) -> VestaPoint {
    // L = 48 bytes per field element (RFC 9380 / pasta_curves)
    const L: usize = 48;
    let uniform = expand_message_xmd(msg, dst, 2 * L);
    let u0 = fe_from_uniform_bytes(&uniform[..L]);
    let u1 = fe_from_uniform_bytes(&uniform[L..2 * L]);
    // SSWU → IsoEq, then 3-isogeny → Vesta
    let sum = map_to_curve_sswu(&u0).add(&map_to_curve_sswu(&u1));
    VestaPoint {
        inner: iso_map_3(&sum),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mont_field_roundtrip() {
        let two = Fe::one().add(&Fe::one());
        let three = two.add(&Fe::one());
        assert_eq!(two.mul(&three).ct_eq(&two.add(&two).add(&two)), 1);
        let mut b = [0u8; 32];
        b[31] = 9;
        let fe = Fe::from_bytes_be(&b).unwrap();
        let mut out = [0u8; 32];
        fe.to_bytes_be(&mut out);
        assert_eq!(out, b);
    }

    #[test]
    fn hash_to_curve_runs() {
        let p = hash_to_curve(b"test", b"VESTA_XMD:SHA-256_SSWU_RO_");
        assert_eq!(p.ct_is_identity(), 0);
    }
    #[test]
    fn identity() {
        assert_eq!(VestaPoint::identity().ct_is_identity(), 1);
    }

    #[test]
    fn neg_one_arith() {
        let x = Fe::one().neg();
        let x2 = x.square();
        assert_eq!(x2.ct_eq(&Fe::one()), 1, "(-1)^2 == 1");
        let x3 = x2.mul(&x);
        assert_eq!(x3.ct_eq(&x), 1, "(-1)^3 == -1");
        let four = Fe::one().add(&Fe::one()).add(&Fe::one()).add(&Fe::one());
        let rhs = x3.add(&CURVE_B);
        assert_eq!(rhs.ct_eq(&four), 1, "(-1)^3+5 == 4");
        let two = Fe::one().add(&Fe::one());
        assert_eq!(two.square().ct_eq(&four), 1, "2^2 == 4");
    }

    #[test]
    fn mixed_add_and_pippenger_match() {
        use crate::curve::traits::CurvePoint;
        let aff = |p: &VestaPoint| {
            let (x, y) = p.inner.to_affine().unwrap();
            let mut bx = [0u8; 32];
            let mut by = [0u8; 32];
            x.to_bytes_be(&mut bx);
            y.to_bytes_be(&mut by);
            (bx, by)
        };
        let mut bases = Vec::new();
        for i in 0u8..40 {
            // Same decode path as params consts: compressed -> affine.
            let p = hash_to_curve(&[i], b"VESTA_XMD:SHA-256_SSWU_RO_");
            let mut enc = [0u8; 32];
            p.to_bytes_compressed(&mut enc).unwrap();
            bases.push(VestaPoint::from_bytes(&enc).unwrap());
        }
        // Const bases decode affine (z == 1): the mixed-add contract.
        for b in bases.iter() {
            assert_eq!(b.inner.z.ct_eq(&Fe::one()), 1, "affine base");
        }
        let mut scalars = Vec::new();
        for i in 1u64..=40 {
            let mut sb = [0u8; 32];
            sb[..8].copy_from_slice(&i.to_le_bytes());
            scalars.push(Scalar::from_bytes_le(&sb).unwrap());
        }
        // Mixed vs full add, incl. doubling edge (H == 0 fallback).
        for i in 0..40 {
            for j in 0..40 {
                assert_eq!(
                    aff(&bases[i].add_mixed_vartime(&bases[j])),
                    aff(&bases[i].add_vartime(&bases[j])),
                    "mixed {i},{j}"
                );
            }
        }
        // Projective self + affine other.
        let proj = bases[0].double_vartime();
        assert_eq!(
            aff(&proj.add_mixed_vartime(&bases[1])),
            aff(&proj.add_vartime(&bases[1])),
            "projective+affine"
        );
        // Pippenger vs naive, affine and projective bases.
        let mut expect = VestaPoint::identity();
        for (b, s) in bases.iter().zip(scalars.iter()) {
            expect = expect.add_vartime(&b.mul(s));
        }
        assert_eq!(
            aff(&pippenger_msm(&bases, &scalars)),
            aff(&expect),
            "msm affine"
        );
        let pbase: Vec<_> = bases.iter().map(|b| b.double_vartime()).collect();
        let mut expect2 = VestaPoint::identity();
        for (b, s) in pbase.iter().zip(scalars.iter()) {
            expect2 = expect2.add_vartime(&b.mul(s));
        }
        assert_eq!(
            aff(&pippenger_msm(&pbase, &scalars)),
            aff(&expect2),
            "msm projective"
        );
    }

    #[test]
    fn vartime_scalar_mul_matches_ct() {
        use crate::curve::traits::CurvePoint;
        let aff_pt = |p: &VestaPoint| {
            let (x, y) = p.inner.to_affine().unwrap();
            let mut bx = [0u8; 32];
            let mut by = [0u8; 32];
            x.to_bytes_be(&mut bx);
            y.to_bytes_be(&mut by);
            (bx, by)
        };
        let g = VestaPoint::generator();
        let cases: [u64; 5] = [1, 2, 3, 0xdead_beef_cafe, u64::MAX];
        // Zero scalar: both give identity.
        let s0 = Scalar::from_bytes_le(&[0u8; 32]).unwrap();
        assert_eq!(g.mul_vartime(&s0).ct_is_identity(), 1);
        assert_eq!(g.mul(&s0).ct_is_identity(), 1);
        for c in cases {
            let mut sb = [0u8; 32];
            sb[..8].copy_from_slice(&c.to_le_bytes());
            sb[8..16].copy_from_slice(&c.to_le_bytes());
            let s = Scalar::from_bytes_le(&sb).unwrap();
            assert_eq!(aff_pt(&g.mul_vartime(&s)), aff_pt(&g.mul(&s)), "scalar {c}");
        }
        // Projective base as well.
        let p = g.double_vartime().add_vartime(&g);
        let mut sb = [0u8; 32];
        sb[..8].copy_from_slice(&123456789u64.to_le_bytes());
        let s = Scalar::from_bytes_le(&sb).unwrap();
        assert_eq!(
            aff_pt(&p.mul_vartime(&s)),
            aff_pt(&p.mul(&s)),
            "projective base"
        );
    }

    #[test]
    fn on_curve_generator() {
        let g = VestaPoint::generator();
        let (x, y) = g.inner.to_affine().unwrap();
        let lhs = y.square();
        let rhs = x.square().mul(&x).add(&CURVE_B);
        assert_eq!(lhs.ct_eq(&rhs), 1, "generator on curve");
    }

    #[test]
    fn fe_vartime_matches_ct_random() {
        let mut s = 0x9e3779b97f4a7c15u64;
        let next = move || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        let mut nx = next;
        let rnd = |nx: &mut dyn FnMut() -> u64| {
            let mut be = [0u8; 32];
            for i in 0..4 {
                be[i * 8..(i + 1) * 8].copy_from_slice(&nx().to_be_bytes());
            }
            be[0] &= 0x3f;
            Fe::from_bytes_be(&be).expect("canonical")
        };
        for _ in 0..300 {
            let (a, b) = (rnd(&mut nx), rnd(&mut nx));
            assert_eq!(a.mul_vartime(&b).n, a.mul(&b).n, "mul");
            assert_eq!(a.add_vartime(&b).n, a.add(&b).n, "add");
            assert_eq!(a.sub_vartime(&b).n, a.sub(&b).n, "sub");
        }
    }

    #[test]
    fn fe_add() {
        let r = Fe::one().add(&Fe::one());
        let mut out = [0u8; 32];
        r.to_bytes_be(&mut out);
        assert_eq!(out[31], 2);
    }

    #[test]
    fn double_add() {
        let g = VestaPoint::generator();
        let d = g.double();
        let a = g.add(&g);
        let (dx, dy) = d.inner.to_affine().expect("double affine");
        let (ax, ay) = a.inner.to_affine().expect("add affine");
        assert_eq!(dx.ct_eq(&ax), 1, "2G double==add x");
        assert_eq!(dy.ct_eq(&ay), 1, "2G double==add y");
        let lhs = dy.square();
        let rhs = dx.square().mul(&dx).add(&CURVE_B);
        assert_eq!(lhs.ct_eq(&rhs), 1, "2G on curve");
    }

    #[test]
    fn mul_by_two_equals_double() {
        let g = VestaPoint::generator();
        let mut two = [0u8; 32];
        two[31] = 2;
        let s = Scalar::from_bytes_be(&two).unwrap();
        let m = g.mul(&s);
        let d = g.double();
        let (mx, my) = m.inner.to_affine().unwrap();
        let (dx, dy) = d.inner.to_affine().unwrap();
        assert_eq!(mx.ct_eq(&dx), 1);
        assert_eq!(my.ct_eq(&dy), 1);
    }

    #[test]
    fn mul_by_four_equals_double_double() {
        let g = VestaPoint::generator();
        let mut four = [0u8; 32];
        four[31] = 4;
        let s = Scalar::from_bytes_be(&four).unwrap();
        let m = g.mul(&s);
        let dd = g.double().double();
        let (mx, my) = m.inner.to_affine().unwrap();
        let (dx, dy) = dd.inner.to_affine().unwrap();
        assert_eq!(mx.ct_eq(&dx), 1, "4G mul==dd x");
        assert_eq!(my.ct_eq(&dy), 1, "4G mul==dd y");
        let lhs = dy.square();
        let rhs = dx.square().mul(&dx).add(&CURVE_B);
        assert_eq!(lhs.ct_eq(&rhs), 1, "4G on curve");
    }

    #[test]
    fn sswu_iso_on_curve_ct() {
        for u in [Fe::zero(), Fe::one()] {
            let p = iso_map_3(&map_to_curve_sswu(&u));
            let (ax, ay) = p.to_affine().expect("affine");
            let lhs = ay.square();
            let rhs = ax.square().mul(&ax).add(&CURVE_B);
            assert_eq!(lhs.ct_eq(&rhs), 1, "SSWU+iso on Vesta");
        }
    }

    #[test]
    fn hash_to_curve_deterministic() {
        let p = hash_to_curve(b"abc", b"VESTA_XMD:SHA-256_SSWU_RO_");
        assert_eq!(p.ct_is_identity(), 0);
        let (ax, ay) = p.inner.to_affine().expect("affine");
        let lhs = ay.square();
        let rhs = ax.square().mul(&ax).add(&CURVE_B);
        assert_eq!(lhs.ct_eq(&rhs), 1, "hash on Vesta");
        let p2 = hash_to_curve(b"abc", b"VESTA_XMD:SHA-256_SSWU_RO_");
        assert_eq!(p.inner.x.ct_eq(&p2.inner.x), 1);
    }

    #[test]
    fn hash_to_curve_locked() {
        let dst = b"VESTA_XMD:SHA-256_SSWU_RO_";
        let p = hash_to_curve(b"abc", dst);
        assert_eq!(p.ct_is_identity(), 0);
        let (ax, ay) = p.inner.to_affine().expect("affine");
        let lhs = ay.square();
        let rhs = ax.square().mul(&ax).add(&CURVE_B);
        assert_eq!(lhs.ct_eq(&rhs), 1);
        let p2 = hash_to_curve(b"abc", dst);
        assert_eq!(p.inner.x.ct_eq(&p2.inner.x), 1);
        let mut b1 = [0u8; 32];
        let mut b2 = [0u8; 32];
        p.to_bytes_compressed(&mut b1).unwrap();
        hash_to_curve(b"abcd", dst)
            .to_bytes_compressed(&mut b2)
            .unwrap();
        assert_ne!(b1, b2);
    }

    #[test]
    fn hash_to_curve_short_msg_distinct() {
        for dst in [
            b"Halo2-Parameters".as_slice(),
            b"VESTA_XMD:SHA-256_SSWU_RO_".as_slice(),
        ] {
            let mut b1 = [0u8; 32];
            let mut b2 = [0u8; 32];
            hash_to_curve(&[1], dst)
                .to_bytes_compressed(&mut b1)
                .unwrap();
            hash_to_curve(&[2], dst)
                .to_bytes_compressed(&mut b2)
                .unwrap();
            assert_ne!(
                b1,
                b2,
                "H2C([1]) != H2C([2]) dst={:?}",
                core::str::from_utf8(dst)
            );
            hash_to_curve(&[0, 0, 0, 0, 0], dst)
                .to_bytes_compressed(&mut b1)
                .unwrap();
            hash_to_curve(&[0, 0, 0, 0, 1], dst)
                .to_bytes_compressed(&mut b2)
                .unwrap();
            assert_ne!(b1, b2, "H2C(i=0) != H2C(i=1)");
        }
    }

    #[test]
    fn expand_message_short_distinct() {
        let a = expand_message_xmd(&[1], b"Halo2-Parameters", 64);
        let b = expand_message_xmd(&[2], b"Halo2-Parameters", 64);
        assert_ne!(a, b, "expand([1]) != expand([2])");
    }

    #[test]
    fn generator_ops() {
        let g = VestaPoint::generator();
        assert_eq!(g.add(&g.neg()).ct_is_identity(), 1);
        let mut two = [0u8; 32];
        two[31] = 2;
        let s = Scalar::from_bytes_be(&two).unwrap();
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        g.mul(&s).to_bytes_compressed(&mut a).unwrap();
        g.double().to_bytes_compressed(&mut b).unwrap();
        assert_eq!(a, b);
    }
}

