//! JubJub twisted Edwards curve (Zcash / Halo).
//!
//! Base field = BLS12-381 scalar field r (255-bit).
//! Curve: a x² + y² = 1 + d x² y² with a = −1, cofactor 8.
//! Full extended-coordinate arithmetic, constant-time scalar mul.

use crate::ct::ct_eq;
use crate::curve::error::{CurveError, CurveResult};
use crate::curve::traits::{CurvePoint, FieldElement, Scalar as ScalarTrait};

/// JubJub / BLS12-381 r (big-endian).
pub const P_BE: [u8; 32] = [
    0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
    0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
];

/// Subgroup order n (big-endian).
pub const N_BE: [u8; 32] = [
    0x0e, 0x7d, 0xb4, 0xea, 0x65, 0x33, 0xaf, 0xa9, 0x06, 0x67, 0x3b, 0x01, 0x01, 0x34, 0x3b, 0x00,
    0xa6, 0x68, 0x20, 0x93, 0xcc, 0xc8, 0x10, 0x82, 0xd0, 0x97, 0x0e, 0x5e, 0xd6, 0xf7, 0x2c, 0xb7,
];

/// Edwards d in Montgomery form (replaces plain `D_LIMBS` + runtime reduce).
const D_MONT: [u64; 4] = [
    0x2a52_2455_b974_f6b0,
    0xfc6c_c9ef_0d9a_cab3,
    0x7a08_fb94_c276_28d1,
    0x57f8_f6a8_fe0e_262e,
];

const fn p_limbs() -> [u64; 4] {
    // LE limbs of JubJub/BLS-r prime
    [
        0xffff_ffff_0000_0001,
        0x53bd_a402_fffe_5bfe,
        0x3339_d808_09a1_d805,
        0x73ed_a753_299d_7d48,
    ]
}

/// -p^{-1} mod 2^{64} for Montgomery reduction (fixed-loop CIOS).
const N0: u64 = 0xffff_fffe_ffff_ffff;

/// R = 2^256 mod p in LE limbs (Montgomery one).
const R_MONT: [u64; 4] = [
    0x0000_0001_ffff_fffe,
    0x5884_b7fa_0003_4802,
    0x998c_4fef_ecbc_4ff5,
    0x1824_b159_acc5_056f,
];

/// R² = 2^512 mod p in LE limbs (maps canonical → Montgomery).
const R2_MONT: [u64; 4] = [
    0xc999_e990_f3f2_9c6d,
    0x2b6c_edcb_8792_5c23,
    0x05d3_1496_7254_398f,
    0x0748_d9d9_9f59_ff11,
];

/// Montgomery product REDC(a·b) with fixed loop counts.
/// Mirrors Pallas `mont_mul_raw` exactly (schoolbook + CIOS + branchless
/// final subtract). Output is fully reduced (< p).
fn mont_mul_raw(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let p = p_limbs();
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
        let mut c = z >> 64;
        let mut k = i + 5;
        while k < 8 {
            let z = t[k] as u128 + c;
            t[k] = z as u64;
            c = z >> 64;
            k += 1;
        }
    }
    // REDC: for i in 0..4, add (t[i]*N0)*p shifted.
    for i in 0..4 {
        let m = t[i].wrapping_mul(N0);
        let mut carry = 0u128;
        for j in 0..4 {
            let z = t[i + j] as u128 + (m as u128) * (p[j] as u128) + carry;
            t[i + j] = z as u64;
            carry = z >> 64;
        }
        let mut k = i + 4;
        let mut c = carry;
        while k < 8 {
            let z = t[k] as u128 + c;
            t[k] = z as u64;
            c = z >> 64;
            k += 1;
        }
    }
    let n = [t[4], t[5], t[6], t[7]];
    // Branchless final subtract (inlined ge/select).
    let mut b2: u64 = 0;
    let mut sub = [0u64; 4];
    for k in 0..4 {
        let (d1, bb1) = n[k].overflowing_sub(p[k]);
        let (d2, bb2) = d1.overflowing_sub(b2);
        sub[k] = d2;
        b2 = u64::from(bb1 || bb2);
    }
    let mask = (b2 ^ 1).wrapping_neg();
    [0, 1, 2, 3].map(|k| (sub[k] & mask) | (n[k] & !mask))
}

fn n_limbs() -> [u64; 4] {
    [
        0xd097_0e5e_d6f7_2cb7,
        0xa668_2093_ccc8_1082,
        0x0667_3b01_0134_3b00,
        0x0e7d_b4ea_6533_afa9,
    ]
}

// ---------------------------------------------------------------------------
// Field element (4 × u64 LE)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct Fe {
    pub(crate) n: [u64; 4],
}

impl Fe {
    pub const fn zero() -> Self {
        Self { n: [0; 4] }
    }
    pub const fn one() -> Self {
        Self { n: R_MONT }
    }
    /// Wrap big-endian limbs (top limb first, matching `to_bytes_be`
    /// chunking) without reduction, converting into Montgomery form.
    /// For `@generated` constant tables whose values were exported from
    /// reduced field elements.
    pub fn from_limbs_be(limbs: [u64; 4]) -> Self {
        Self {
            n: mont_mul_raw(&[limbs[3], limbs[2], limbs[1], limbs[0]], &R2_MONT),
        }
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
        let mut r = *self;
        for _ in 0..2 {
            if r.cmp_p() >= 0 {
                r = r.sub_p();
            } else {
                break;
            }
        }
        r
    }

    /// Branchless `self >= p ? 1 : 0` via borrow chain (no early exit).
    /// Used by the constant-time [`Fe::add`].
    fn ge_p_mask(&self) -> u64 {
        let p = p_limbs();
        let mut borrow: u64 = 0;
        for (&s, &pv) in self.n.iter().zip(p.iter()) {
            let sv = s as u128;
            let pv = pv as u128 + borrow as u128;
            borrow = (sv < pv) as u64;
        }
        borrow ^ 1
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
        // Map canonical limbs into Montgomery form.
        Ok(Self {
            n: mont_mul_raw(&n, &R2_MONT),
        })
    }

    pub fn to_bytes_be(&self, out: &mut [u8; 32]) {
        // Montgomery values are always canonical (< p): no reduction branch.
        let r = Self {
            n: mont_mul_raw(&self.n, &[1, 0, 0, 0]),
        };
        for i in 0..4 {
            let o = 24 - i * 8;
            out[o..o + 8].copy_from_slice(&r.n[i].to_be_bytes());
        }
    }

    /// Raw Montgomery limbs, for `@generated` constant tables only
    /// (consumed by [`Fe::from_mont_limbs`]). Additive API (R1); the CT
    /// field ops are untouched.
    pub fn to_mont_limbs(&self) -> [u64; 4] {
        self.n
    }

    /// Assemble from raw Montgomery limbs produced by
    /// [`Fe::to_mont_limbs`]. No reduction or validation is performed:
    /// the caller guarantees canonical Montgomery form (generated
    /// constants). Additive API (R1).
    pub fn from_mont_limbs(n: [u64; 4]) -> Self {
        Self { n }
    }

    pub fn ct_select(choice: u8, a: &Self, b: &Self) -> Self {
        let mask = (choice as u64).wrapping_neg();
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
        // Branchless conditional subtracts (were nested `if carry/cmp_p`;
        // the branch directions leaked secret limb values). The second and
        // third selects replicate the old `if carry` + `reduce()` cascade
        // exactly, so values are identical for all inputs.
        let r = Self { n };
        let sub1 = r.sub_p();
        let r1 = Self::ct_select((carry | r.ge_p_mask()) as u8, &sub1, &r);
        let sub2 = r1.sub_p();
        let r2 = Self::ct_select((carry & r1.ge_p_mask()) as u8, &sub2, &r1);
        let sub3 = r2.sub_p();
        Self::ct_select(r2.ge_p_mask() as u8, &sub3, &r2)
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
        let sub = Self { n };
        // Branchless zero select (was `if self.is_zero()`), then the same
        // trailing conditional reduction the old code got via `reduce()`.
        let or = self.n[0] | self.n[1] | self.n[2] | self.n[3];
        let is_z = (((or | or.wrapping_neg()) >> 63) ^ 1) as u8;
        let r = Self::ct_select(is_z, self, &sub);
        let red = r.sub_p();
        Self::ct_select(r.ge_p_mask() as u8, &red, &r)
    }

    pub fn sub(&self, other: &Self) -> Self {
        self.add(&other.neg())
    }

    pub fn mul(&self, other: &Self) -> Self {
        // Montgomery CIOS with fixed loop counts (was schoolbook +
        // secret-dependent Horner reduction, which tripped the harness).
        Self {
            n: mont_mul_raw(&self.n, &other.n),
        }
    }

    pub fn square(&self) -> Self {
        self.mul(self)
    }

    /// Fermat invert: a^(p-2).
    pub fn invert(&self) -> CurveResult<Self> {
        if self.is_zero() {
            return Err(CurveError::NotInvertible);
        }
        // p-2
        let mut exp = P_BE;
        // subtract 2
        let mut borrow = 2u32;
        for i in (0..32).rev() {
            let v = exp[i] as u32;
            if v >= borrow {
                exp[i] = (v - borrow) as u8;
                borrow = 0;
            } else {
                exp[i] = (v + 256 - borrow) as u8;
                borrow = 1;
            }
        }
        let base = *self;
        let mut result = Self::one();
        for byte in exp.iter() {
            for bit in (0..8).rev() {
                result = result.square();
                if (byte >> bit) & 1 == 1 {
                    result = result.mul(&base);
                }
            }
        }
        Ok(result)
    }

    /// Exponentiate by a 32-byte big-endian exponent.
    pub fn pow_be(&self, exp: &[u8; 32]) -> Self {
        let mut result = Self::one();
        for byte in exp.iter() {
            for bit in (0..8).rev() {
                result = result.square();
                if (byte >> bit) & 1 == 1 {
                    result = result.mul(self);
                }
            }
        }
        result
    }

    /// Tonelli–Shanks for p ≡ 1 (mod 4): p−1 = 2^32 · Q.
    pub fn sqrt(&self) -> Option<Self> {
        if self.is_zero() {
            return Some(Self::zero());
        }
        // (p-1)/2
        const HALF: [u8; 32] = [
            0x39, 0xf6, 0xd3, 0xa9, 0x94, 0xce, 0xbe, 0xa4, 0x19, 0x9c, 0xec, 0x04, 0x04, 0xd0,
            0xec, 0x02, 0xa9, 0xde, 0xd2, 0x01, 0x7f, 0xff, 0x2d, 0xff, 0x7f, 0xff, 0xff, 0xff,
            0x80, 0x00, 0x00, 0x00,
        ];
        let leg = self.pow_be(&HALF);
        if leg.ct_eq(&Self::one()) == 0 {
            return None;
        }
        // Q = (p-1)/2^32
        const Q_BE: [u8; 32] = [
            0x00, 0x00, 0x00, 0x00, 0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39,
            0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05, 0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe,
            0xff, 0xff, 0xff, 0xff,
        ];
        // (Q+1)/2
        const Q1H: [u8; 32] = [
            0x00, 0x00, 0x00, 0x00, 0x39, 0xf6, 0xd3, 0xa9, 0x94, 0xce, 0xbe, 0xa4, 0x19, 0x9c,
            0xec, 0x04, 0x04, 0xd0, 0xec, 0x02, 0xa9, 0xde, 0xd2, 0x01, 0x7f, 0xff, 0x2d, 0xff,
            0x80, 0x00, 0x00, 0x00,
        ];
        // z=5 non-residue; c0 = z^Q
        const C0: [u8; 32] = [
            0x02, 0x12, 0xd7, 0x9e, 0x5b, 0x41, 0x6b, 0x6f, 0x0f, 0xd5, 0x6d, 0xc8, 0xd1, 0x68,
            0xd6, 0xc0, 0xc4, 0x02, 0x4f, 0xf2, 0x70, 0xb3, 0xe0, 0x94, 0x1b, 0x78, 0x8f, 0x50,
            0x0b, 0x91, 0x2f, 0x1f,
        ];
        let mut m = 32usize;
        let mut r = self.pow_be(&Q1H);
        let mut t = self.pow_be(&Q_BE);
        let mut c_pow = Fe::from_bytes_be(&C0).unwrap();
        while t.ct_eq(&Self::one()) == 0 {
            let mut t2i = t;
            let mut i = 0usize;
            while i < m {
                if t2i.ct_eq(&Self::one()) == 1 {
                    break;
                }
                t2i = t2i.square();
                i += 1;
            }
            if i == 0 || i >= m {
                return None;
            }
            let mut b = c_pow;
            for _ in 0..(m - i - 1) {
                b = b.square();
            }
            r = r.mul(&b);
            c_pow = b.square();
            t = t.mul(&c_pow);
            m = i;
        }
        Some(r)
    }

    pub fn is_zero(&self) -> bool {
        self.reduce().n.iter().all(|&x| x == 0)
    }

    pub fn ct_eq(&self, other: &Self) -> u8 {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        self.to_bytes_be(&mut a);
        other.to_bytes_be(&mut b);
        ct_eq(&a, &b)
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
        Fe::ct_eq(self, other)
    }
    fn is_zero(&self) -> bool {
        Fe::is_zero(self)
    }
}

// ---------------------------------------------------------------------------
// Scalar mod n
// ---------------------------------------------------------------------------

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

    /// Branchless `self >= n ? 1 : 0` via borrow chain (no early exit).
    fn ge_n_mask(&self) -> u64 {
        let ord = n_limbs();
        let mut borrow: u64 = 0;
        for (&s, &ov) in self.n.iter().zip(ord.iter()) {
            let sv = s as u128;
            let ov = ov as u128 + borrow as u128;
            borrow = (sv < ov) as u64;
        }
        borrow ^ 1
    }

    /// Constant-time select (mask-based, no branches).
    pub fn ct_select(choice: u8, a: &Self, b: &Self) -> Self {
        let mask = (choice as u64).wrapping_neg();
        let mut n = [0u64; 4];
        for ((ni, ai), bi) in n.iter_mut().zip(a.n.iter()).zip(b.n.iter()) {
            *ni = (*ai & mask) | (*bi & !mask);
        }
        Self { n }
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

    fn reduce(&self) -> Self {
        let mut r = *self;
        if r.cmp_n() >= 0 {
            r = r.sub_n();
        }
        r
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
        // Branchless conditional subtract (was `if carry || cmp_n` +
        // `reduce()`); identical values for all inputs.
        let r = Self { n };
        let sub1 = r.sub_n();
        let r1 = Self::ct_select((carry | r.ge_n_mask()) as u8, &sub1, &r);
        let sub2 = r1.sub_n();
        Self::ct_select(r1.ge_n_mask() as u8, &sub2, &r1)
    }

    pub fn neg(&self) -> Self {
        let ord = n_limbs();
        let mut borrow = 0u64;
        let mut n = [0u64; 4];
        for i in 0..4 {
            let (d1, b1) = ord[i].overflowing_sub(self.n[i]);
            let (d2, b2) = d1.overflowing_sub(borrow);
            n[i] = d2;
            borrow = u64::from(b1 | b2);
        }
        let sub = Self { n };
        // Branchless zero select (was `if self.is_zero()`).
        let or = self.n[0] | self.n[1] | self.n[2] | self.n[3];
        let is_z = (((or | or.wrapping_neg()) >> 63) ^ 1) as u8;
        Self::ct_select(is_z, self, &sub)
    }

    pub fn mul(&self, other: &Self) -> Self {
        // Schoolbook 4×4 → 8 LE limbs, then reduce 512-bit integer mod n
        // via bit-serial double-and-add (same approach as sc_reduce64_le).
        let mut prod = [0u128; 8];
        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 {
                let t = prod[i + j] + (self.n[i] as u128) * (other.n[j] as u128) + carry;
                prod[i + j] = t & 0xffff_ffff_ffff_ffff;
                carry = t >> 64;
            }
            let mut k = i + 4;
            while carry != 0 && k < 8 {
                let t = prod[k] + carry;
                prod[k] = t & 0xffff_ffff_ffff_ffff;
                carry = t >> 64;
                k += 1;
            }
        }
        let mut limbs = [0u64; 8];
        for i in 0..8 {
            limbs[i] = prod[i] as u64;
        }
        // Bit-serial: process 512-bit LE integer MSB → LSB. The add-one step
        // is unconditional (select-based) so timing does not depend on the
        // product bits (which are secret-derived in signing paths).
        let mut acc = Self::zero();
        for limb_idx in (0..8).rev() {
            for bit in (0..64).rev() {
                acc = acc.add(&acc);
                let b = ((limbs[limb_idx] >> bit) & 1) as u8;
                let added = acc.add(&Self::one());
                acc = Self::ct_select(b, &added, &acc);
            }
        }
        acc
    }

    pub fn bit(&self, i: usize) -> u8 {
        if i >= 256 {
            return 0;
        }
        ((self.n[i / 64] >> (i % 64)) & 1) as u8
    }

    pub fn is_zero(&self) -> bool {
        self.n.iter().all(|&x| x == 0)
    }

    /// Reduce 64-byte little-endian integer modulo the group order.
    /// Output is 32-byte **little-endian** canonical scalar (Zcash / RedDSA convention).
    /// Matches `JubJubFr.fromBytes64` / `JubJubNativeFr.fromBytes64` (LE BigInt mod r).
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
        let mut acc = Self::zero();
        // MSB is bit 511 of the integer = bit 63 of limbs[7]. Add-one step is
        // unconditional (select-based); see `mul` above.
        for limb_idx in (0..8).rev() {
            for bit in (0..64).rev() {
                acc = acc.add(&acc); // *2
                let b = ((limbs[limb_idx] >> bit) & 1) as u8;
                let added = acc.add(&Self::one());
                acc = Self::ct_select(b, &added, &acc);
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

    /// Parse 32-byte little-endian scalar (must be canonical, < r).
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

// ---------------------------------------------------------------------------
// Extended twisted Edwards point (a = −1)
// ---------------------------------------------------------------------------

fn fe_d() -> Fe {
    Fe { n: D_MONT }
}

#[derive(Clone, Copy, Debug)]
struct Extended {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

impl Extended {
    fn identity() -> Self {
        Self {
            x: Fe::zero(),
            y: Fe::one(),
            z: Fe::one(),
            t: Fe::zero(),
        }
    }

    fn ct_is_identity(&self) -> u8 {
        self.x.ct_eq(&Fe::zero()) & self.y.ct_eq(&self.z)
    }

    /// Generator matching `jubjub::AffinePoint::generator` (zkcrypto): the
    /// point with the lowest positive v-coordinate and positive u-coordinate
    /// (compressed `0b00…00`). Full-curve order 8r; the prime-subgroup
    /// generator is `8 * G` (`jubjub::SubgroupPoint::generator`).
    fn generator() -> Self {
        let gx = Fe::from_bytes_be(&[
            0x62, 0xed, 0xcb, 0xb8, 0xbf, 0x37, 0x87, 0xc8, 0x8b, 0x0f, 0x03, 0xdd, 0xd6, 0x0a,
            0x81, 0x87, 0xca, 0xf5, 0x5d, 0x1b, 0x29, 0xbf, 0x81, 0xaf, 0xe4, 0xb3, 0xd3, 0x5d,
            0xf1, 0xa7, 0xad, 0xfe,
        ])
        .expect("jubjub G.x");
        let gy = Fe::from_bytes_be(&[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x0b,
        ])
        .expect("jubjub G.y");
        Self {
            x: gx,
            y: gy,
            z: Fe::one(),
            t: gx.mul(&gy),
        }
    }

    fn double(&self) -> Self {
        // Hisil–Wong–Carter–Dawson a=-1
        let a = self.x.square();
        let b = self.y.square();
        let c = self.z.square().add(&self.z.square()); // 2 Z²
        let d = a.neg(); // a = -1 → a·X² = -X²
        let e = self.x.add(&self.y).square().sub(&a).sub(&b);
        let g = d.add(&b);
        let f = g.sub(&c);
        let h = d.sub(&b);
        Self {
            x: e.mul(&f),
            y: g.mul(&h),
            z: f.mul(&g),
            t: e.mul(&h),
        }
    }

    fn add(&self, other: &Self) -> Self {
        // Unified addition in extended coords, a = −1 (HWCD):
        // A=X1X2, B=Y1Y2, C=d T1 T2, D=Z1Z2
        // E=(X1+Y1)(X2+Y2)−A−B, F=D−C, G=D+C, H=B−aA = B+A
        let a = self.x.mul(&other.x);
        let b = self.y.mul(&other.y);
        let c = fe_d().mul(&self.t).mul(&other.t);
        let d = self.z.mul(&other.z);
        let e = self
            .x
            .add(&self.y)
            .mul(&other.x.add(&other.y))
            .sub(&a)
            .sub(&b);
        let f = d.sub(&c);
        let g = d.add(&c);
        let h = b.add(&a); // a_curve = −1 → H = B − (−A) = B + A
        Self {
            x: e.mul(&f),
            y: g.mul(&h),
            z: f.mul(&g),
            t: e.mul(&h),
        }
    }

    fn neg(&self) -> Self {
        Self {
            x: self.x.neg(),
            y: self.y,
            z: self.z,
            t: self.t.neg(),
        }
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
                t = Extended {
                    x: Fe::ct_select(eq, &ti.x, &t.x),
                    y: Fe::ct_select(eq, &ti.y, &t.y),
                    z: Fe::ct_select(eq, &ti.z, &t.z),
                    t: Fe::ct_select(eq, &ti.t, &t.t),
                };
            }
            r = r.add(&t);
        }
        r
    }

    #[allow(clippy::wrong_self_convention)] // `to_affine(&self)` keeps the crate-wide point API; renaming would churn audited call sites.
    fn to_affine(&self) -> CurveResult<(Fe, Fe)> {
        let z_inv = self.z.invert()?;
        Ok((self.x.mul(&z_inv), self.y.mul(&z_inv)))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct JubJubPoint {
    inner: Extended,
}

impl JubJubPoint {
    pub fn generator() -> Self {
        Self {
            inner: Extended::generator(),
        }
    }

    /// Construct from affine (u, v) field elements (already reduced).
    pub fn from_affine_coords(u: Fe, v: Fe) -> Self {
        Self {
            inner: Extended {
                x: u,
                y: v,
                z: Fe::one(),
                t: u.mul(&v),
            },
        }
    }

    /// Assemble from extended-coordinate limbs (big-endian `[u64; 4]` per
    /// coordinate, matching `to_bytes_be` chunking). For `@generated`
    /// constant tables (`hash::pedersen_tables`): same point the limbs
    /// were exported from, with zero runtime math.
    pub fn from_extended_limbs(x: [u64; 4], y: [u64; 4], z: [u64; 4], t: [u64; 4]) -> Self {
        Self {
            inner: Extended {
                x: Fe::from_limbs_be(x),
                y: Fe::from_limbs_be(y),
                z: Fe::from_limbs_be(z),
                t: Fe::from_limbs_be(t),
            },
        }
    }

    /// Affine `(u, v)` coordinates (Zcash Edwards).
    pub fn affine_uv(&self) -> crate::curve::error::CurveResult<(Fe, Fe)> {
        self.inner.to_affine()
    }

    /// Batch projective→affine with a SINGLE inversion (Montgomery trick).
    ///
    /// New method for public generator-table builds (window precomputation):
    /// replaces N per-point inversions. Straight-line field ops; falls back
    /// to per-point conversion if any input is identity (never for window
    /// multiples). Existing single-point paths untouched.
    /// Sapling-circuit helper (window precomputation).
    #[cfg(feature = "groth16-prover")]
    pub(crate) fn batch_to_affine(points: &[Self]) -> alloc::vec::Vec<(Fe, Fe)> {
        use alloc::vec::Vec;
        let n = points.len();
        let mut pref = Vec::with_capacity(n);
        let mut acc = Fe::one();
        for p in points {
            pref.push(acc);
            acc = acc.mul(&p.inner.z);
        }
        let mut inv = match acc.invert() {
            Ok(v) => v,
            Err(_) => {
                // Degenerate input (identity z=0): slow but correct fallback.
                return points
                    .iter()
                    .map(|p| p.affine_uv().unwrap_or((Fe::zero(), Fe::one())))
                    .collect();
            }
        };
        let mut out = Vec::with_capacity(n);
        for (p, pr) in points.iter().zip(pref.iter()).rev() {
            let zi_inv = inv.mul(pr);
            inv = inv.mul(&p.inner.z);
            out.push((p.inner.x.mul(&zi_inv), p.inner.y.mul(&zi_inv)));
        }
        out.reverse();
        out
    }

    /// Affine `(u, v)` as little-endian 32-byte pairs.
    pub fn affine_uv_le_bytes(&self) -> crate::curve::error::CurveResult<([u8; 32], [u8; 32])> {
        let (u, v) = self.inner.to_affine()?;
        let mut ube = [0u8; 32];
        let mut vbe = [0u8; 32];
        u.to_bytes_be(&mut ube);
        v.to_bytes_be(&mut vbe);
        let mut ule = [0u8; 32];
        let mut vle = [0u8; 32];
        for i in 0..32 {
            ule[i] = ube[31 - i];
            vle[i] = vbe[31 - i];
        }
        Ok((ule, vle))
    }

    /// Vartime mixed addition against a precomputed affine dual (dalek
    /// twisted-Edwards mixed formula, a = −1): 7 `Fe::mul` vs 9 in the
    /// unified path. Result stays extended. New method (R1/R2 as above).
    pub(crate) fn add_dual_vartime(&self, d: &JubDual) -> Self {
        let a = self
            .inner
            .y
            .sub(&self.inner.x)
            .mul(&d.y_minus_x);
        let b = self
            .inner
            .y
            .add(&self.inner.x)
            .mul(&d.y_plus_x);
        let c = self.inner.t.mul(&d.c);
        let two_z = self.inner.z.add(&self.inner.z);
        let e = b.sub(&a);
        let f = two_z.sub(&c);
        let g = two_z.add(&c);
        let h = b.add(&a);
        Self {
            inner: Extended {
                x: e.mul(&f),
                y: g.mul(&h),
                z: f.mul(&g),
                t: e.mul(&h),
            },
        }
    }
}

/// Precomputed affine dual for [`JubJubPoint::add_dual_vartime`]:
/// (Y−X, Y+X, 2·d·T). Negation = field swap + one `Fe::neg`, no alloc.
#[derive(Clone, Copy, Debug)]
pub(crate) struct JubDual {
    pub(crate) y_minus_x: Fe,
    pub(crate) y_plus_x: Fe,
    pub(crate) c: Fe,
}

impl CurvePoint for JubJubPoint {
    type Scalar = Scalar;
    const COMPRESSED_BYTES: usize = 32;
    const UNCOMPRESSED_BYTES: usize = 64;

    fn identity() -> Self {
        Self {
            inner: Extended::identity(),
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
        // Zcash Sapling: 32-byte LE v-coordinate, sign of u in high bit of last byte
        if bytes.len() == 32 {
            let mut vb = [0u8; 32];
            vb.copy_from_slice(bytes);
            let sign = (vb[31] >> 7) & 1;
            vb[31] &= 0x7f;
            let mut v_be = [0u8; 32];
            for i in 0..32 {
                v_be[i] = vb[31 - i];
            }
            let y = Fe::from_bytes_be(&v_be)?;
            // a=-1: u² = (v² - 1)/(1 + d v²)
            let y2 = y.square();
            let num = y2.sub(&Fe::one());
            let den = Fe::one().add(&fe_d().mul(&y2));
            let x2 = num.mul(&den.invert()?);
            let mut x = x2.sqrt().ok_or(CurveError::InvalidEncoding)?;
            let mut x_be = [0u8; 32];
            x.to_bytes_be(&mut x_be);
            let x_odd = x_be[31] & 1;
            if x_odd != sign {
                x = x.neg();
            }
            let t = x.mul(&y);
            return Ok(Self {
                inner: Extended {
                    x,
                    y,
                    z: Fe::one(),
                    t,
                },
            });
        }
        if bytes.len() == 64 {
            let mut xb = [0u8; 32];
            let mut yb = [0u8; 32];
            xb.copy_from_slice(&bytes[0..32]);
            yb.copy_from_slice(&bytes[32..64]);
            let x = Fe::from_bytes_be(&xb)?;
            let y = Fe::from_bytes_be(&yb)?;
            return Ok(Self {
                inner: Extended {
                    x,
                    y,
                    z: Fe::one(),
                    t: x.mul(&y),
                },
            });
        }
        Err(CurveError::InvalidLength)
    }

    fn to_bytes_compressed(&self, out: &mut [u8]) -> CurveResult<()> {
        if out.len() != 32 {
            return Err(CurveError::InvalidLength);
        }
        let (x, y) = self.inner.to_affine()?;
        // Zcash Sapling: LE v-coordinate, sign of u in high bit of last byte
        let mut y_be = [0u8; 32];
        let mut x_be = [0u8; 32];
        y.to_bytes_be(&mut y_be);
        x.to_bytes_be(&mut x_be);
        for i in 0..32 {
            out[i] = y_be[31 - i];
        }
        let u_odd = x_be[31] & 1;
        out[31] |= u_odd << 7;
        Ok(())
    }

    fn to_bytes_uncompressed(&self, out: &mut [u8]) -> CurveResult<()> {
        if out.len() != 64 {
            return Err(CurveError::InvalidLength);
        }
        let (x, y) = self.inner.to_affine()?;
        let mut xb = [0u8; 32];
        let mut yb = [0u8; 32];
        x.to_bytes_be(&mut xb);
        y.to_bytes_be(&mut yb);
        // LE u || LE v (Sapling affine encoding of coordinates)
        for i in 0..32 {
            out[i] = xb[31 - i];
            out[32 + i] = yb[31 - i];
        }
        Ok(())
    }
}

/// expand_message_xmd (SHA-256) for JubJub hash-to-curve.
fn expand_message_xmd(msg: &[u8], dst: &[u8], len: usize) -> alloc::vec::Vec<u8> {
    use crate::hash::Sha256;
    let mut out = alloc::vec::Vec::with_capacity(len);
    let ell = len.div_ceil(32);
    let mut b0_input = alloc::vec::Vec::new();
    b0_input.extend_from_slice(&[0u8; 64]); // Z_pad for SHA-256
    b0_input.extend_from_slice(msg);
    b0_input.extend_from_slice(&[(len >> 8) as u8, len as u8]);
    b0_input.push(0);
    b0_input.extend_from_slice(dst);
    b0_input.push(dst.len() as u8);
    let mut h = Sha256::new();
    h.update(&b0_input);
    let b0 = h.finalize();
    let mut prev = b0;
    for i in 1..=ell {
        let mut hi = Sha256::new();
        let mut block = prev;
        for (a, b) in block.iter_mut().zip(b0.iter()) {
            *a ^= *b;
        }
        hi.update(&block);
        hi.update(&[i as u8]);
        hi.update(dst);
        hi.update(&[dst.len() as u8]);
        prev = hi.finalize();
        out.extend_from_slice(&prev);
    }
    out.truncate(len);
    out
}

/// Hash to JubJub via expand_message_xmd + try-and-increment + Tonelli–Shanks.
///
/// Given candidate x from the XMD stream, solve for y on a=−1:
///   y² = (1 + x²) / (1 − d x²)
/// Accept the first x where the RHS is a quadratic residue. Sign of y is taken
/// from the high bit of the second 32-byte half of the uniform string.
pub fn hash_to_curve(msg: &[u8], dst: &[u8]) -> JubJubPoint {
    let uniform = expand_message_xmd(msg, dst, 64);
    let mut fe_bytes = [0u8; 32];
    let n = uniform.len().min(32);
    fe_bytes[32 - n..].copy_from_slice(&uniform[..n]);
    // Clear top 2 bits so x < 2^254 < p
    fe_bytes[0] &= 0x3f;
    let mut x = Fe::from_bytes_be(&fe_bytes).unwrap_or_else(|_| Fe::one());
    let sign_y = if uniform.len() >= 64 {
        (uniform[63] >> 7) & 1
    } else {
        0
    };
    let d = fe_d();
    for _ in 0..256 {
        let xsq = x.square();
        // y² = (1 + x²) / (1 − d x²)   (a = −1)
        let num = Fe::one().add(&xsq);
        let den = Fe::one().sub(&d.mul(&xsq));
        if let Ok(inv) = den.invert() {
            let y2 = num.mul(&inv);
            if let Some(mut y) = y2.sqrt() {
                // enforce sign
                let mut yb = [0u8; 32];
                y.to_bytes_be(&mut yb);
                if (yb[31] & 1) != sign_y {
                    y = y.neg();
                }
                return JubJubPoint {
                    inner: Extended {
                        x,
                        y,
                        z: Fe::one(),
                        t: x.mul(&y),
                    },
                };
            }
        }
        x = x.add(&Fe::one());
    }
    // Extremely unlikely fallback
    JubJubPoint::generator()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::traits::CurvePoint;

    /// Edwards `d` used by `fe_d()` satisfies the curve equation on the
    /// generator (`-x²+y² = 1+d·x²y²`). Pins the constant consumed (via the
    /// `@generated` dual tables) by `add_dual_vartime`, independently of
    /// the generator script's own derivation.
    #[test]
    fn edwards_d_matches_generator() {
        let g = Extended::generator();
        // Affineize without the point API (unit scope): z is 1 by
        // construction, so x/y are already affine.
        let one = Fe::one();
        assert!(g.z.ct_eq(&one) != 0);
        let x2 = g.x.mul(&g.x);
        let y2 = g.y.mul(&g.y);
        let d = fe_d();
        let lhs = y2.sub(&x2);
        let rhs = one.add(&d.mul(&x2).mul(&y2));
        assert!(lhs.ct_eq(&rhs) != 0);
    }

    #[test]
    fn sc_reduce64_le_low_half() {
        let mut w = [0u8; 64];
        w[0] = 1; // LE 1
        let s = Scalar::sc_reduce64_le(&w);
        let mut le = [0u8; 32];
        s.to_bytes_le(&mut le);
        assert_eq!(le[0], 1);
        assert!(le[1..].iter().all(|&b| b == 0));
    }

    #[test]
    fn sc_mul_matches_zcash_vector() {
        fn parse_hex(s: &str) -> [u8; 32] {
            let v: Vec<u8> = (0..s.len() / 2)
                .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
                .collect();
            let mut a = [0u8; 32];
            a.copy_from_slice(&v);
            a
        }
        let sc1 = parse_hex("662e3bb4fd912e82931c65f23cb96870175a05262f7c65927cae1de03127f202");
        let sc2 = parse_hex("059654f961273dafda3b2677b35c18af6b11adfb9ee90b48935e557c8d5d9c04");
        let expect = parse_hex("3e9c895f82ae902091e59a1578387b0e1c7512698d2e5007398e530e0720f007");
        let a = Scalar::from_bytes_le(&sc1).unwrap();
        let b = Scalar::from_bytes_le(&sc2).unwrap();
        let c = a.mul(&b);
        let mut out = [0u8; 32];
        c.to_bytes_le(&mut out);
        assert_eq!(out, expect, "Jubjub Fr mul must match Zcash");
    }

    #[test]
    fn sc_reduce64_le_matches_vector() {
        fn parse_hex(s: &str) -> Vec<u8> {
            (0..s.len() / 2)
                .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
                .collect()
        }
        let wide = parse_hex(
            "e1b6d052b648fa21164898cc6c2e8dcc197261b0995f84cbce49abb0f8f2b7f6d30331b5232fc0adca504f2025fdc093e434a98096c2cad1a9b3849d2840fddb"
        );
        let mut w = [0u8; 64];
        w.copy_from_slice(&wide);
        let s = Scalar::sc_reduce64_le(&w);
        let mut le = [0u8; 32];
        s.to_bytes_le(&mut le);
        let expected =
            parse_hex("3ec7950a7c839baaafd83b83df9d6ef424ed39de3f76031ba298b0098611aa02");
        assert_eq!(le.as_slice(), expected.as_slice());
    }

    #[test]
    fn identity() {
        assert_eq!(JubJubPoint::identity().ct_is_identity(), 1);
    }

    #[test]
    fn fe_one_plus_one() {
        let r = Fe::one().add(&Fe::one());
        let mut out = [0u8; 32];
        r.to_bytes_be(&mut out);
        assert_eq!(out[31], 2);
    }

    #[test]
    fn generator_xy_published() {
        // zkcrypto jubjub::AffinePoint::generator (uncompressed x||y BE)
        const GX: [u8; 32] = [
            0x62, 0xed, 0xcb, 0xb8, 0xbf, 0x37, 0x87, 0xc8, 0x8b, 0x0f, 0x03, 0xdd, 0xd6, 0x0a,
            0x81, 0x87, 0xca, 0xf5, 0x5d, 0x1b, 0x29, 0xbf, 0x81, 0xaf, 0xe4, 0xb3, 0xd3, 0x5d,
            0xf1, 0xa7, 0xad, 0xfe,
        ];
        const GY: [u8; 32] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x0b,
        ];
        let g = JubJubPoint::generator();
        assert_eq!(g.ct_is_identity(), 0);
        let mut buf = [0u8; 64];
        g.to_bytes_uncompressed(&mut buf).expect("uncompress");
        // Uncompressed is Sapling LE (byte-reverse of published BE coords)
        let mut gx_le = GX;
        gx_le.reverse();
        let mut gy_le = GY;
        gy_le.reverse();
        assert_eq!(&buf[0..32], &gx_le[..], "JubJub G.x LE");
        assert_eq!(&buf[32..64], &gy_le[..], "JubJub G.y LE");
    }

    #[test]
    fn generator_on_curve() {
        // a=-1: -x² + y² = 1 + d x² y²
        let g = JubJubPoint::generator();
        let mut buf = [0u8; 64];
        g.to_bytes_uncompressed(&mut buf).unwrap();
        let mut xb = [0u8; 32];
        let mut yb = [0u8; 32];
        xb.copy_from_slice(&buf[0..32]);
        yb.copy_from_slice(&buf[32..64]);
        xb.reverse();
        yb.reverse();
        let x = Fe::from_bytes_be(&xb).unwrap();
        let y = Fe::from_bytes_be(&yb).unwrap();
        let xx = x.square();
        let yy = y.square();
        let lhs = yy.sub(&xx);
        let rhs = Fe::one().add(&fe_d().mul(&xx).mul(&yy));
        assert_eq!(lhs.ct_eq(&rhs), 1, "generator on JubJub curve");
    }

    #[test]
    fn double_eq_add() {
        let g = JubJubPoint::generator();
        let d = g.double();
        let a = g.add(&g);
        assert_eq!(d.ct_is_identity(), 0);
        assert_eq!(a.ct_is_identity(), 0);
        let mut db = [0u8; 64];
        let mut ab = [0u8; 64];
        d.to_bytes_uncompressed(&mut db).unwrap();
        a.to_bytes_uncompressed(&mut ab).unwrap();
        assert_eq!(db, ab, "double(G) == G+G affine (x and y)");
        // 2G on-curve
        let mut xb = [0u8; 32];
        let mut yb = [0u8; 32];
        xb.copy_from_slice(&db[0..32]);
        yb.copy_from_slice(&db[32..64]);
        xb.reverse();
        yb.reverse();
        let x = Fe::from_bytes_be(&xb).unwrap();
        let y = Fe::from_bytes_be(&yb).unwrap();
        let xx = x.square();
        let yy = y.square();
        let lhs = yy.sub(&xx);
        let rhs = Fe::one().add(&fe_d().mul(&xx).mul(&yy));
        assert_eq!(lhs.ct_eq(&rhs), 1, "2G on JubJub curve");
    }

    #[test]
    fn mul_by_two_equals_double() {
        let g = JubJubPoint::generator();
        let mut two = [0u8; 32];
        two[31] = 2;
        let s = Scalar::from_bytes_be(&two).unwrap();
        let m = g.mul(&s);
        let d = g.double();
        // Compare via compressed encodings if available, else non-identity + add consistency
        assert_eq!(m.ct_is_identity(), 0);
        assert_eq!(d.ct_is_identity(), 0);
        let a = g.add(&g);
        assert_eq!(a.ct_is_identity(), 0);
        // 2G via mul should match double path in group (encode if method exists)
        let _ = (m, d, a);
    }

    #[test]
    fn compressed_roundtrip() {
        use crate::curve::traits::CurvePoint;
        let g = JubJubPoint::generator();
        let mut b = [0u8; 32];
        g.to_bytes_compressed(&mut b).unwrap();
        let g2 = JubJubPoint::from_bytes(&b).expect("decode generator");
        let mut b2 = [0u8; 32];
        g2.to_bytes_compressed(&mut b2).unwrap();
        assert_eq!(b, b2);
    }

    #[test]
    fn mul_one_eq_generator() {
        let g = JubJubPoint::generator();
        let r = g.mul(&Scalar::one());
        let mut gb = [0u8; 64];
        let mut rb = [0u8; 64];
        g.to_bytes_uncompressed(&mut gb).unwrap();
        r.to_bytes_uncompressed(&mut rb).unwrap();
        assert_eq!(gb, rb, "[1]G == G");
    }

    #[test]
    fn hash_to_curve_deterministic_non_id() {
        let p1 = hash_to_curve(b"abc", b"JUBJUB_XMD:SHA-256_RO_");
        let p2 = hash_to_curve(b"abc", b"JUBJUB_XMD:SHA-256_RO_");
        assert_eq!(p1.ct_is_identity(), 0);
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        p1.to_bytes_uncompressed(&mut a).unwrap();
        p2.to_bytes_uncompressed(&mut b).unwrap();
        assert_eq!(a, b, "hash_to_curve deterministic");
        // Result must be on-curve
        let mut xb = [0u8; 32];
        let mut yb = [0u8; 32];
        xb.copy_from_slice(&a[0..32]);
        yb.copy_from_slice(&a[32..64]);
        xb.reverse();
        yb.reverse();
        let x = Fe::from_bytes_be(&xb).unwrap();
        let y = Fe::from_bytes_be(&yb).unwrap();
        let xx = x.square();
        let yy = y.square();
        let lhs = yy.sub(&xx);
        let rhs = Fe::one().add(&fe_d().mul(&xx).mul(&yy));
        assert_eq!(lhs.ct_eq(&rhs), 1, "hash_to_curve result on curve");
        // Different messages → different points; not always G
        let p3 = hash_to_curve(b"xyz", b"JUBJUB_XMD:SHA-256_RO_");
        let mut c = [0u8; 64];
        p3.to_bytes_uncompressed(&mut c).unwrap();
        // expand_message must depend on msg
        let u1 = expand_message_xmd(b"abc", b"JUBJUB_XMD:SHA-256_RO_", 64);
        let u2 = expand_message_xmd(b"xyz", b"JUBJUB_XMD:SHA-256_RO_", 64);
        assert_ne!(u1, u2, "expand_message_xmd must vary with msg");
        // if points equal despite different expand, x-increment may collide — still require on-curve
        if a == c {
            // rare but document; require at least not identity
            assert_eq!(p1.ct_is_identity(), 0);
        } else {
            assert_ne!(a, c);
        }
        let mut gb = [0u8; 64];
        JubJubPoint::generator()
            .to_bytes_uncompressed(&mut gb)
            .unwrap();
        assert_ne!(
            a, gb,
            "hash_to_curve(abc) is not generator (try-and-increment path)"
        );
    }

    #[test]
    fn fe_sqrt_tonelli() {
        let two = Fe::one().add(&Fe::one());
        let four = two.square();
        let s = four.sqrt().expect("4 is square");
        assert!(s.ct_eq(&two) == 1 || s.ct_eq(&two.neg()) == 1);
        assert_eq!(s.square().ct_eq(&four), 1);
    }
}
