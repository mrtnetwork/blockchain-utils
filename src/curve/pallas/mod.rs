//! Pallas curve (Pasta / Halo2).
//!
//! Short Weierstrass: y² = x³ + 5 over Fq.
//! Full Jacobian arithmetic, constant-time scalar multiplication.

use crate::ct::{ct_eq, ct_select_u8};
use crate::curve::error::{CurveError, CurveResult};
use crate::curve::traits::{CurvePoint, FieldElement, Scalar as ScalarTrait};

/// Pallas base field p (big-endian).
pub const P_BE: [u8; 32] = [
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x22, 0x46, 0x98, 0xfc, 0x09, 0x4c, 0xf9, 0x1b, 0x99, 0x2d, 0x30, 0xed, 0x00, 0x00, 0x00, 0x01,
];

/// Pallas group order q (big-endian) = Vesta base field.
pub const N_BE: [u8; 32] = [
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x22, 0x46, 0x98, 0xfc, 0x09, 0x94, 0xa8, 0xdd, 0x8c, 0x46, 0xeb, 0x21, 0x00, 0x00, 0x00, 0x01,
];

fn p_limbs() -> [u64; 4] {
    // LE: p = 0x4000…0000224698fc094cf91b992d30ed00000001
    [
        0x992d_30ed_0000_0001,
        0x2246_98fc_094c_f91b,
        0x0000_0000_0000_0000,
        0x4000_0000_0000_0000,
    ]
}

fn r256_p() -> [u64; 4] {
    [
        0x3478_6d38_ffff_fffd,
        0x992c_350b_e419_14ad,
        0xffff_ffff_ffff_ffff,
        0x3fff_ffff_ffff_ffff,
    ]
}

/// -p^{-1} mod 2^{64} for Montgomery reduction (constant-time CIOS).
const P_INV: u64 = 0x992d_30ec_ffff_ffff;

/// R² = (2^{256})² mod p — used to map canonical → Montgomery.
fn r2_p() -> [u64; 4] {
    [
        0x8c78_ecb3_0000_000f,
        0xd7d3_0dbd_8b0d_e0e7,
        0x7797_a99b_c3c9_5d18,
        0x096d_41af_7b9c_b714,
    ]
}

fn n_limbs() -> [u64; 4] {
    // Pallas order = Vesta base field
    [
        0x8c46_eb21_0000_0001,
        0x2246_98fc_0994_a8dd,
        0x0000_0000_0000_0000,
        0x4000_0000_0000_0000,
    ]
}

fn r256_n() -> [u64; 4] {
    [
        0x5b2b_3e9c_ffff_fffd,
        0x992c_350b_e342_0567,
        0xffff_ffff_ffff_ffff,
        0x3fff_ffff_ffff_ffff,
    ]
}

// ---------------------------------------------------------------------------
// Field
// ---------------------------------------------------------------------------

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
    /// Montgomery one = R mod p (not integer 1).
    pub fn one() -> Self {
        Self { n: r256_p() }
    }

    /// Reduce 64 uniform LE bytes mod p (halo2 `from_uniform_bytes`
    /// semantics): 8 LE u64 limbs reduced via R, into Montgomery domain.
    /// Used for the official Halo2-Verify-Key transcript repr.
    pub fn from_uniform_bytes64(uniform: &[u8; 64]) -> Self {
        let mut limbs = [0u64; 8];
        for (i, li) in limbs.iter_mut().enumerate() {
            let o = i * 8;
            *li = u64::from_le_bytes([
                uniform[o],
                uniform[o + 1],
                uniform[o + 2],
                uniform[o + 3],
                uniform[o + 4],
                uniform[o + 5],
                uniform[o + 6],
                uniform[o + 7],
            ]);
        }
        let c = reduce_512_via_r(&limbs, &r256_p(), &p_limbs());
        Self::mont_mul_raw(&c.n, &r2_p())
    }

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
        let need = self.ge_p();
        Fe::ct_select(need, &self.sub_p(), self)
    }

    fn ge_mod(&self, m: &[u64; 4]) -> u8 {
        let mut gt = 0u8;
        let mut eq = 1u8;
        for i in (0..4).rev() {
            gt |= eq & u8::from(self.n[i] > m[i]);
            eq &= u8::from(self.n[i] == m[i]);
        }
        gt | eq
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
        if fe.ge_p() == 1 {
            return Err(CurveError::InvalidEncoding);
        }
        // Canonical → Montgomery: c · R² · R^{−1} = cR
        Ok(Self::mont_mul_raw(&fe.n, &r2_p()))
    }

    pub fn to_bytes_be(&self, out: &mut [u8; 32]) {
        // Montgomery → canonical
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
    /// Variable-time in the exponent (mul-skip + early exit on bit-length).
    /// All in-repo callers pass public constants (powers of two, domain
    /// sizes); never use with a secret exponent. Secret paths use Fermat
    /// `invert`/`pow` ladders above, which are branchless.
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

    // ---- Pasta domain constants (Montgomery limbs, precomputed) ----

    /// 2^32-th root of unity.
    pub fn root_of_unity() -> Self {
        Self {
            n: [
                11713220832667294704,
                10413392179731184095,
                18133385229535560846,
                4524191781424318170,
            ],
        }
    }

    /// Coset generator `zeta`.
    pub fn zeta() -> Self {
        Self {
            n: [
                144709982554297661,
                11424548785947195278,
                3055531117462046310,
                1574013144934742134,
            ],
        }
    }

    /// `2^-1 mod p`.
    pub fn two_inv() -> Self {
        Self {
            n: [
                7409212017489215487,
                15976914419795035876,
                18446744073709551615,
                4611686018427387903,
            ],
        }
    }

    /// Permutation separator `delta`.
    pub fn delta() -> Self {
        Self {
            n: [
                6441811782492557681,
                14395083426726340918,
                2822291232967272332,
                642607708868163409,
            ],
        }
    }

    /// Small integer `< 2^128` (always `< m`).
    pub fn from_u128_reduce(v: u128) -> Self {
        let l = [v as u64, (v >> 64) as u64, 0, 0];
        Self::mont_mul_raw(&l, &r2_p())
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

    /// Constant-time Montgomery multiplication: returns a·b·R^{−1} mod p.
    pub fn mul(&self, other: &Self) -> Self {
        Self::mont_mul_raw(&self.n, &other.n)
    }

    /// Variable-time field addition: same value as [`add`](Self::add).
    ///
    /// Separate function for prover/batch paths only. Single conditional
    /// subtract instead of [`add`](Self::add)'s double reduction: valid
    /// because every in-repo producer emits canonical limbs (< p), and for
    /// `a, b < p` we have `a + b < 2p < 2^256` (carry impossible), so one
    /// subtract always suffices. Callers MUST pass canonical inputs; the
    /// 156-word assembly oracle guards every switched call site.
    /// The constant-time [`add`](Self::add) is unchanged.
    #[inline]
    pub fn add_vartime(&self, other: &Self) -> Self {
        let mut n = [0u64; 4];
        let mut carry = 0u64;
        for ((ni, si), oi) in n.iter_mut().zip(self.n.iter()).zip(other.n.iter()) {
            let t = *si as u128 + *oi as u128 + carry as u128;
            *ni = t as u64;
            carry = (t >> 64) as u64;
        }
        let mut r = Self { n };
        // Canonical inputs => carry == 0; single subtract suffices.
        let need = (carry != 0) as u8 | r.ge_p();
        r = Fe::ct_select(need, &r.sub_p(), &r);
        r
    }

    /// Variable-time field subtraction: same value as [`sub`](Self::sub).
    /// Same canonical-input contract as [`add_vartime`](Self::add_vartime).
    #[inline]
    pub fn sub_vartime(&self, other: &Self) -> Self {
        self.add_vartime(&other.neg())
    }

    /// Variable-time Montgomery multiplication: same value as [`mul`](Self::mul).
    ///
    /// Straight-line schoolbook + SOS reduction (HAC Algorithm 14.32 shape):
    /// 16 `mac` chains fully unrolled, `#[inline(always)]` helpers, no
    /// data-dependent branches or loop-carried index arithmetic. Separate
    /// function for prover/batch paths only; the constant-time
    /// [`mul`](Self::mul) is unchanged. Inputs must be canonical (< p);
    /// output is canonical.
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
        // Schoolbook rows (16 macs).
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
        // SOS reduction rows (16 macs + 4 adcs).
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
        // Single conditional subtract (< 2p input): sbb chain (borrow is
        // 0 or all-ones mask) + masked add-back.
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

    /// Variable-time fused multiply-add: `(self * other + addend) mod p`.
    ///
    /// Separate function for batch/prover paths only. Computes the exact same
    /// value as `self.mul(other).add(addend)` via the proven primitives.
    /// NOTE: a "single REDC with the addend folded into the unreduced
    /// product" is NOT correct in Montgomery form: the product `T = A·B`
    /// needs `REDC(T) = X·Y·R`, but folding `C = Z·R` in as an integer gives
    /// `REDC(T + C) = X·Y·R + Z` (missing one factor R on the addend).
    /// Correct fusion would add `C·R`, which costs more than it saves, so
    /// this stays as REDC-then-add (the add itself has no REDC).
    /// Makes no constant-time claims; never use on secret-dependent
    /// branches. The constant-time [`mul`] is unchanged.
    pub fn mul_vartime_add(&self, other: &Self, addend: &Self) -> Self {
        self.mul_vartime(other).add_vartime(addend)
    }

    /// Montgomery product of two raw limb arrays (CIOS-style REDC).
    #[inline]
    fn mont_mul_raw(a: &[u64; 4], b: &[u64; 4]) -> Self {
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
            while c != 0 && k < 8 {
                let z = t[k] as u128 + c;
                t[k] = z as u64;
                c = z >> 64;
                k += 1;
            }
        }
        // REDC: for i in 0..4, add (t[i]*INV)*p shifted
        for i in 0..4 {
            let m = t[i].wrapping_mul(P_INV);
            let mut carry = 0u128;
            for j in 0..4 {
                let z = t[i + j] as u128 + (m as u128) * (p[j] as u128) + carry;
                t[i + j] = z as u64;
                carry = z >> 64;
            }
            let mut k = i + 4;
            while k < 8 {
                let z = t[k] as u128 + carry;
                t[k] = z as u64;
                carry = z >> 64;
                k += 1;
            }
        }
        let n = [t[4], t[5], t[6], t[7]];
        let mut r = Self { n };
        // CT conditional subtract p
        let need = r.ge_p();
        r = Fe::ct_select(need, &r.sub_p(), &r);
        r
    }

    pub fn square(&self) -> Self {
        self.mul(self)
    }

    /// Variable-time square: same value as [`square`](Self::square).
    /// Canonical-input contract, prover/batch paths only.
    pub fn square_vartime(&self) -> Self {
        self.mul_vartime(self)
    }

    pub fn invert(&self) -> CurveResult<Self> {
        if self.is_zero() {
            return Err(CurveError::NotInvertible);
        }
        // Exponent is public (p-2); ladder is branchless via ct_select.
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

    pub fn is_zero(&self) -> bool {
        self.reduce().n.iter().fold(0u64, |a, &x| a | x) == 0
    }
}

/// Reduce 8×u64 product via R = 2^256 mod modulus (no i128 overflow).
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
        // while hi > 0: add hi * (2^256 mod p) = hi * R into n
        // R provided as _r
        // Fixed-iteration residual fold (bound covers worst-case carry chain).
        for _ in 0..32 {
            let h = hi & 0xffff_ffff_ffff_ffff;
            hi >>= 64;
            let mut carry = 0u128;
            for j in 0..4 {
                let t = n[j] as u128 + h * (_r[j] as u128) + carry;
                n[j] = t as u64;
                carry = t >> 64;
            }
            hi += carry;
        }
        acc = Fe { n };
        // conditional subtract p until < p
        for _ in 0..8 {
            let need = acc.ge_mod(modulus);
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

// ---------------------------------------------------------------------------
// Scalar
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

    /// Reduce 64 uniform LE bytes mod r (halo2 `from_uniform_bytes`
    /// semantics, e.g. `ToScalar` / PRF-expand outputs). Horner with 2^64.
    pub fn from_uniform_bytes64(uniform: &[u8; 64]) -> Self {
        let mut two64 = Self::one();
        for _ in 0..64 {
            two64 = two64.add(&two64);
        }
        let mut acc = Self::zero();
        for i in (0..8).rev() {
            let o = i * 8;
            let limb = u64::from_le_bytes([
                uniform[o],
                uniform[o + 1],
                uniform[o + 2],
                uniform[o + 3],
                uniform[o + 4],
                uniform[o + 5],
                uniform[o + 6],
                uniform[o + 7],
            ]);
            // acc = acc * 2^64 + limb (limb < 2^64 < r, fits directly).
            acc = acc.mul(&two64);
            let mut l = Self::zero();
            l.n[0] = limb;
            acc = acc.add(&l);
        }
        acc
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

    fn ge_n(&self) -> u8 {
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
    fn reduce(&self) -> Self {
        let need = self.ge_n();
        let subbed = self.sub_n();
        let mask = ((need & 1) as u64).wrapping_neg();
        let mut n = [0u64; 4];
        for ((ni, si), slf) in n.iter_mut().zip(subbed.n.iter()).zip(self.n.iter()) {
            *ni = (*si & mask) | (*slf & !mask);
        }
        Self { n }
    }
    /// Branchless select for secret paths: `choice==1` → `a`, else `b`.
    /// Masked, no branch; `choice` is reduced to one bit with black_box.
    #[inline]
    fn ct_select_ct(choice: u8, a: &Self, b: &Self) -> Self {
        let c = core::hint::black_box(choice) & 1;
        let mask = (c as u64).wrapping_neg();
        let mut n = [0u64; 4];
        for ((ni, ai), bi) in n.iter_mut().zip(a.n.iter()).zip(b.n.iter()) {
            *ni = (*ai & mask) | (*bi & !mask);
        }
        Self { n }
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
        if s.ge_n() == 1 {
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
        let mut r = Self { n };
        let need = (carry != 0) as u8 | r.ge_n();
        let subbed = r.sub_n();
        let mask = ((need & 1) as u64).wrapping_neg();
        for i in 0..4 {
            r.n[i] = (subbed.n[i] & mask) | (r.n[i] & !mask);
        }
        r.reduce()
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
        let raw = Self { n };
        let z = self.is_zero() as u8;
        let mask = (z as u64).wrapping_neg();
        for ((ni, si), ri) in n.iter_mut().zip(self.n.iter()).zip(raw.n.iter()) {
            *ni = (*si & mask) | (*ri & !mask);
        }
        Self { n }
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

    /// Reduce 64-byte little-endian integer modulo the Pallas scalar order.
    /// Output is 32-byte **little-endian** canonical scalar.
    /// Matches `PallasFq.fromBytes64` (LE BigInt mod r).
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
        // MSB is bit 511 of the integer = bit 63 of limbs[7]
        // Branchless: always add, select between acc+1 and acc via mask
        // (no `if bit==1` skip). Secret-safe; public-input callers pay one
        // extra masked add per bit (negligible vs MSM). Proof-hot loops that
        // need raw speed must call `sc_reduce64_le_vartime` instead.
        let one = Self::one();
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

    /// Variable-time twin of [`sc_reduce64_le`](Self::sc_reduce64_le) for
    /// proof/transcript paths only (public 64-byte inputs). Skips the
    /// zero-bit add. Same value, faster. Never use on secrets.
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
        if s.ge_n() == 1 {
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
// Jacobian point  y² = x³ + 5
// ---------------------------------------------------------------------------

/// Curve constant 5 in Montgomery form (field elements are Mont-encoded).
fn fe_b() -> Fe {
    Fe::mont_mul_raw(&[5, 0, 0, 0], &r2_p())
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

    /// Generator: (-1, 2) is a known point on y² = x³ + 5.
    fn generator() -> Self {
        let x = Fe::one().neg(); // -1
        let y = Fe::one().add(&Fe::one()); // 2
        Self {
            x,
            y,
            z: Fe::one(),
            infinity: 0,
        }
    }

    fn double(&self) -> Self {
        // Jacobian doubling for a=0 (inversion-free):
        // S = 4XY², M = 3X², X' = M²-2S, Y' = M(S-X')-8Y⁴, Z' = 2YZ
        let yy = self.y.square();
        let mut s = self.x.mul(&yy);
        s = s.add(&s);
        s = s.add(&s);
        let xx = self.x.square();
        let m = xx.add(&xx).add(&xx);
        let x3 = m.square().sub(&s).sub(&s);
        let mut y4 = yy.square();
        y4 = y4.add(&y4);
        y4 = y4.add(&y4);
        y4 = y4.add(&y4);
        let y3 = m.mul(&s.sub(&x3)).sub(&y4);
        let yz = self.y.mul(&self.z);
        let z3 = yz.add(&yz);
        let computed = Self {
            x: x3,
            y: y3,
            z: z3,
            infinity: 0,
        };
        let y_zero = self.y.ct_eq(&Fe::zero());
        let to_id = self.infinity | y_zero;
        Self::ct_select(to_id, &Self::identity(), &computed)
    }

    fn add(&self, other: &Self) -> Self {
        // Always evaluate mixed-add and double; CT-select exceptional cases.
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
        // inf1 → other; inf2 ∧ ¬inf1 → self
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
    /// Batching/MSM paths only. The constant-time [`add`](Self::add) is unchanged.
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

    /// Variable-time addition for batching paths only (see Vesta docs).
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

    /// Variable-time doubling for batching paths only (a=0 formula).
    fn double_vartime(&self) -> Self {
        if self.infinity == 1 {
            return Self::identity();
        }
        let yy = self.y.mul_vartime(&self.y);
        let mut s = self.x.mul_vartime(&yy);
        s = s.add_vartime(&s);
        s = s.add_vartime(&s);
        let xx = self.x.mul_vartime(&self.x);
        let m = xx.add_vartime(&xx).add_vartime(&xx);
        let x3 = m.mul_vartime(&m).sub_vartime(&s).sub_vartime(&s);
        let mut y4 = yy.mul_vartime(&yy);
        y4 = y4.add_vartime(&y4);
        y4 = y4.add_vartime(&y4);
        y4 = y4.add_vartime(&y4);
        let y3 = m.mul_vartime(&s.sub_vartime(&x3)).sub_vartime(&y4);
        let yz = self.y.mul_vartime(&self.z);
        let z3 = yz.add_vartime(&yz);
        Self {
            x: x3,
            y: y3,
            z: z3,
            infinity: 0,
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
pub struct PallasPoint {
    inner: Jac,
}

impl PallasPoint {
    pub fn generator() -> Self {
        Self {
            inner: Jac::generator(),
        }
    }

    /// Affine point with `z = R` (Montgomery one). For compile-time generator tables.
    pub const fn from_affine_mont_limbs(x: [u64; 4], y: [u64; 4]) -> Self {
        const Z_ONE: [u64; 4] = [
            0x3478_6d38_ffff_fffd,
            0x992c_350b_e419_14ad,
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

impl PallasPoint {
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

    /// Variable-time addition (batching/MSM paths only; see Vesta docs).
    pub fn add_vartime(&self, other: &Self) -> Self {
        Self {
            inner: self.inner.add_vartime(&other.inner),
        }
    }

    /// Variable-time mixed addition: `other` must be AFFINE.
    pub fn add_mixed_vartime(&self, other: &Self) -> Self {
        Self {
            inner: self.inner.add_mixed_vartime(&other.inner),
        }
    }

    /// Variable-time doubling (batching/MSM paths only).
    pub fn double_vartime(&self) -> Self {
        Self {
            inner: self.inner.double_vartime(),
        }
    }

    /// Variable-time single-scalar multiplication (4-bit window, direct index).
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
        if bytes.len() != 32 {
            return Err(CurveError::InvalidLength);
        }
        let mut b = [0u8; 32];
        b.copy_from_slice(bytes);
        from_bytes_pasta(&b)
    }

    /// Pasta compressed encode (identity → zeros).
    pub fn to_compressed(&self) -> CurveResult<[u8; 32]> {
        Ok(to_bytes_pasta(self))
    }

    /// Identity conversion (single point type).
    pub fn to_projective(&self) -> CurveResult<Self> {
        Ok(*self)
    }

    /// Debug string in Halo2 format `Pallas(x: 0x.., y: 0x..)`.
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
            return alloc::string::String::from("Pallas(identity)");
        }
        let (x, y, _) = match self.to_affine_le() {
            Ok(v) => v,
            Err(_) => return alloc::string::String::from("Pallas(identity)"),
        };
        let mut s = alloc::string::String::from("Pallas(x: ");
        s.push_str(&hex_be_le(&x));
        s.push_str(", y: ");
        s.push_str(&hex_be_le(&y));
        s.push(')');
        s
    }
}

/// Pippenger bucket multi-scalar multiplication (**variable-time** batching).
/// Same contract as the Vesta version.
///
/// # Timing: variable-time, prover-only
/// Uses only `*_vartime` field/point ops, secret-indexed buckets and
/// zero-skips. Same sum as the naive loop. Never use with secret scalars;
/// secret paths must use `CurvePoint::mul` (fixed-window CT).
pub fn pippenger_msm(bases: &[PallasPoint], scalars: &[Scalar]) -> PallasPoint {
    pippenger_msm_vartime(bases, scalars)
}

/// Variable-time Pippenger core (see [`pippenger_msm`]).
pub fn pippenger_msm_vartime(bases: &[PallasPoint], scalars: &[Scalar]) -> PallasPoint {
    let n = core::cmp::min(bases.len(), scalars.len());
    if n < 32 {
        // Small sizes: naive loop with variable-time single mul (fast path).
        let mut acc = PallasPoint::identity();
        for i in 0..n {
            if scalars[i].is_zero() {
                continue;
            }
            acc = acc.add_vartime(&bases[i].mul_vartime(&scalars[i]));
        }
        return acc;
    }
    const W: usize = 8;
    const NW: usize = 256 / W;
    let mut sbytes: alloc::vec::Vec<[u8; 32]> = alloc::vec::Vec::with_capacity(n);
    let mut nonzero: alloc::vec::Vec<bool> = alloc::vec::Vec::with_capacity(n);
    for s in scalars.iter().take(n) {
        let mut b = [0u8; 32];
        s.to_bytes_le(&mut b);
        nonzero.push(b.iter().any(|&x| x != 0));
        sbytes.push(b);
    }
    let all_affine = bases
        .iter()
        .take(n)
        .all(|b| b.inner.z.ct_eq(&Fe::one()) == 1);
    let mut result = PallasPoint::identity();
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
            result = result.add_vartime(&pallas_window_sum(
                j, bases, &sbytes, &nonzero, all_affine, n,
            ));
        }
        return result;
    }
    // Parallel windows, sequential combine (identical sums either way).
    let mut sums = alloc::vec![PallasPoint::identity(); NW];
    let chunk = NW.div_ceil(nworkers);
    crate::multicore::scope(|s| {
        let mut guards = alloc::vec::Vec::new();
        for (ci, slot) in sums.chunks_mut(chunk).enumerate() {
            let start = ci * chunk;
            let (bases, sbytes, nonzero) = (&bases[..n], &sbytes[..], &nonzero[..]);
            guards.push(s.spawn(move || {
                for (k, dst) in slot.iter_mut().enumerate() {
                    *dst = pallas_window_sum(start + k, bases, sbytes, nonzero, all_affine, n);
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
fn pallas_window_sum(
    j: usize,
    bases: &[PallasPoint],
    sbytes: &[[u8; 32]],
    nonzero: &[bool],
    all_affine: bool,
    n: usize,
) -> PallasPoint {
    const NB: usize = 1 << 8;
    let mut buckets = alloc::vec![PallasPoint::identity(); NB];
    for i in 0..n {
        if !nonzero[i] {
            continue;
        }
        // W=8: window j is byte j (LE scalars).
        let d = sbytes[i][j] as usize;
        if d == 0 {
            continue;
        }
        buckets[d] = if all_affine {
            buckets[d].add_mixed_vartime(&bases[i])
        } else {
            buckets[d].add_vartime(&bases[i])
        };
    }
    let mut running = PallasPoint::identity();
    let mut sum = PallasPoint::identity();
    for d in (1..NB).rev() {
        running = running.add_vartime(&buckets[d]);
        sum = sum.add_vartime(&running);
    }
    sum
}

impl PartialEq for PallasPoint {
    fn eq(&self, other: &Self) -> bool {
        // Canonical compressed encoding (affine-normalized; identity → zeros).
        self.to_compressed().unwrap_or([0u8; 32]) == other.to_compressed().unwrap_or([0u8; 32])
    }
}
impl Eq for PallasPoint {}

impl CurvePoint for PallasPoint {
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
        // Orchard / pasta wire: 32-byte LE x with y-sign in high bit of last byte.
        if bytes.len() == 32 {
            let mut b = [0u8; 32];
            b.copy_from_slice(bytes);
            return from_bytes_pasta(&b);
        }
        if bytes.len() == 64 {
            // Uncompressed: LE x || LE y
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
        // Pasta / Orchard LE compressed encoding
        let b = to_bytes_pasta(self);
        out.copy_from_slice(&b);
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
    /// Legendre symbol via Euler: a^((p-1)/2) → 1 square, p-1 nonsquare, 0 zero.
    /// Variable-time Legendre symbol. **Public input only.**
    pub fn legendre(&self) -> i8 {
        if self.is_zero() {
            return 0;
        }
        // (p-1)/2 exponent
        let mut exp = P_BE;
        // divide by 2: shift right 1 bit from BE
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

    /// Tonelli–Shanks sqrt for p ≡ 1 (mod 16), 2-adicity 32.
    /// Variable-time Tonelli-Shanks. **Public input only.**
    pub fn sqrt(&self) -> CurveResult<Self> {
        if self.is_zero() {
            return Ok(Fe::zero());
        }
        if self.legendre() != 1 {
            return Err(CurveError::NotInvertible);
        }
        // Find non-residue z
        let mut z = Fe::one().add(&Fe::one()); // mont(2)
        while z.legendre() != -1 {
            z = z.add(&Fe::one());
        }
        // p-1 = 2^S * Q, S=32
        let s = 32u32;
        // Q = (p-1)/2^32
        let mut q_bytes = P_BE;
        // subtract 1 then shift right 32 bits
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
        // shift right 32 bits = 4 bytes
        for i in (4..32).rev() {
            q_bytes[i] = q_bytes[i - 4];
        }
        for q in q_bytes.iter_mut().take(4) {
            *q = 0;
        }
        // m = S, c = z^Q, r = a^((Q+1)/2), t = a^Q
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
        // (Q+1)/2
        let mut qp1 = q_bytes;
        // add 1 then /2
        let mut carry = 1u32;
        for i in (0..32).rev() {
            let v = qp1[i] as u32 + carry;
            qp1[i] = (v & 0xff) as u8;
            carry = v >> 8;
        }
        // shift right 1
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
            // find least i such that t^(2^i) = 1
            let mut i = 1u32;
            let mut t2i = t.square();
            while t2i.ct_eq(&Fe::one()) != 1 && i < m {
                t2i = t2i.square();
                i += 1;
            }
            // b = c^(2^(m-i-1))
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
        // Sign bit of the *canonical* representative (Montgomery → normal form)
        let c = Self::mont_mul_raw(&self.n, &[1, 0, 0, 0]).reduce();
        (c.n[0] & 1) as u8
    }

    /// Pasta-compatible `sqrt_ratio(num, div)`:
    /// - if num/div is square → (1, sqrt)
    /// - if nonsquare → (0, sqrt(ROOT_OF_UNITY * num/div)) for SSWU y2 path
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
                // ROOT_OF_UNITY (pasta Fp::from_raw)
                let root = Fe::mont_mul_raw(
                    &[
                        0xbdad_6fab_d87e_a32f,
                        0xea32_2bf2_b7bb_7584,
                        0x3621_2083_0561_f81a,
                        0x2bce_74de_ac30_ebda,
                    ],
                    &r2_p(),
                );
                let y = ratio.mul(&root).sqrt().unwrap_or(Fe::one());
                (0, y)
            }
        }
    }
}


/// Test-only canonical-limbs -> Montgomery conversion (test vectors).
#[cfg(test)]
fn fe_from_limbs(n: [u64; 4]) -> Fe {
    // pasta_curves `Fp::from_raw` = limbs * R² (canonical → Montgomery)
    Fe::mont_mul_raw(&n, &r2_p())
}

/// Montgomery limbs (precomputed; replaces per-call `fe_from_limbs`).
const ISO_A: Fe = Fe::from_raw_mont([0x7fc5d29077bb08de, 0x93090252cf122108, 0x49f63ff5da1145bb, 0x1c6d4f087137f0dc]);
/// Montgomery limbs (precomputed; replaces per-call `fe_from_limbs`).
const ISO_B: Fe = Fe::from_raw_mont([0xf7f22478ffffec3d, 0xa6dec35433e1339b, 0xfffffffffffffd5a, 0x3fffffffffffffff]);
/// Montgomery limbs (precomputed; replaces per-call `fe_from_limbs`).
const CURVE_B: Fe = Fe::from_raw_mont([0xa1a55e68ffffffed, 0x74c2a54b4f4982f3, 0xfffffffffffffffd, 0x3fffffffffffffff]);
/// Montgomery limbs (precomputed; replaces per-call `fe_from_limbs`).
const SSWU_Z: Fe = Fe::from_raw_mont([0x1d2df02400000034, 0xf6571331e3a2999b, 0x6, 0x0]);
/// Montgomery limbs (precomputed; replaces per-call `fe_from_limbs`).
const SSWU_THETA: Fe = Fe::from_raw_mont([0x97dab5ad640e0fd1, 0x99ef2612d070f1aa, 0x3f4540189980a2ac, 0x297a133b8b69562f]);
/// Isogeny constants in Montgomery form (zero runtime conversion).
/// Source: pasta_curves `ISOGENY` limbs converted once via `fe_from_limbs`;
/// values are `to_raw_mont` dumps — do not hand-edit.
const ISO_FES: [Fe; 13] = [
    Fe::from_raw_mont([0xc6e037a01c71c71d, 0x130ac6c4e8b8fc2b, 0x0, 0x4000000000000000]),
    Fe::from_raw_mont([0x4c6e64f2323d5cee, 0x501f41cfd25ec1f0, 0x5dee76e883f5ca7, 0x33183c981332cc59]),
    Fe::from_raw_mont([0x6a3ee7799df56376, 0x126b79ab78c7152f, 0x3260d1c7394f73d9, 0x3faf24198196224d]),
    Fe::from_raw_mont([0x6eeb22cb38e38d91, 0x857a8f27ada1851f, 0xffffffffffffffe9, 0x3fffffffffffffff]),
    Fe::from_raw_mont([0x7fa53608c4284457, 0xe12b216a243a01b1, 0x34d622e2ca3a41e0, 0xbda2158acc92f21]),
    Fe::from_raw_mont([0xa60b71c1a8e17d58, 0x762a4b7ccb2def32, 0x503620030b6137e1, 0x3778ceb0aad59e24]),
    Fe::from_raw_mont([0xcaaf22d9b425ed0a, 0xbc70754050aca717, 0xaaaaaaaaaaaaaaaa, 0x2aaaaaaaaaaaaaaa]),
    Fe::from_raw_mont([0x26373279191eae77, 0xa80fa0e7e92f60f8, 0x82ef73b7441fae53, 0x198c1e4c0999662c]),
    Fe::from_raw_mont([0x64b468a19883c203, 0x8760f32b499db7b0, 0xe0dabda7ccdfe1b, 0x29822f08307bd31b]),
    Fe::from_raw_mont([0xee9add1584bda1bb, 0x5fa29228d90933b, 0x5555555555555568, 0x1555555555555555]),
    Fe::from_raw_mont([0xc0e6983a63c6683, 0x62e3fe9d3afd7f18, 0xcf4134542f5762d1, 0x31c73205032dc6b1]),
    Fe::from_raw_mont([0xbfc7f36afaa47806, 0x1df1b07e4eefdb60, 0xf0a260092223a7a4, 0x266a6c120080da6c]),
    Fe::from_raw_mont([0x6d4ccfb000000870, 0x33aace8e7975d8dc, 0x121, 0x0]),
];

/// Simplified SWU map to IsoEp (Jacobian), then 3-isogeny to Pallas.
fn map_to_curve_sswu(u: &Fe) -> Jac {
    let (a, b, z, theta) = (ISO_A, ISO_B, SSWU_Z, SSWU_THETA);

    let z_u2 = z.mul(&u.square());
    let ta = z_u2.square().add(&z_u2);
    let num_x1 = b.mul(&ta.add(&Fe::one()));
    // div = a * (-ta)  or a*z if ta==0
    let neg_ta = ta.neg();
    let div_sel = Fe::ct_select(ta.is_zero() as u8, &z, &neg_ta);
    let div = a.mul(&div_sel);
    let num2_x1 = num_x1.square();
    let div2 = div.square();
    let div3 = div2.mul(&div);
    let num_gx1 = num2_x1.add(&a.mul(&div2)).mul(&num_x1).add(&b.mul(&div3));

    let num_x2 = z_u2.mul(&num_x1);

    // Pasta sqrt_ratio: square → sqrt(gx1); nonsquare → sqrt(ω·gx1) for y2 path
    let (gx1_is_square, y1) = Fe::sqrt_ratio(&num_gx1, &div3);
    let y2 = theta.mul(&z_u2).mul(u).mul(&y1);
    let num_x = Fe::ct_select(gx1_is_square, &num_x1, &num_x2);
    let y = Fe::ct_select(gx1_is_square, &y1, &y2);
    // sgn0 match — CT, no branch
    let y = Fe::ct_select(u.is_odd() ^ y.is_odd(), &y.neg(), &y);
    // Jacobian on IsoEp then 3-isogeny → Pallas (per-u map; sum on Ep)
    iso_map_3(&Jac {
        x: num_x.mul(&div),
        y: y.mul(&div3),
        z: div,
        infinity: 0,
    })
}

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

/// expand_message_xmd with SHA-256 (RFC 9380 section 5.4.1).
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

/// Map L uniform bytes to a field element (big-endian integer mod p).
fn fe_from_uniform_bytes_le(buf: &[u8]) -> Fe {
    let mut limbs = [0u64; 8];
    let n = buf.len().min(64);
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

/// Hash to Pallas (RFC 9380: expand_message_xmd -> SSWU -> isogeny).
/// L=48 bytes per field element (ceil((log2(p)+128)/8)).
pub fn hash_to_curve(msg: &[u8], dst: &[u8]) -> PallasPoint {
    const L: usize = 48;
    let uniform = expand_message_xmd(msg, dst, 2 * L);
    let u0 = fe_from_uniform_bytes(&uniform[..L]);
    let u1 = fe_from_uniform_bytes(&uniform[L..2 * L]);
    // iso(SSWU(u0)) + iso(SSWU(u1)) on Pallas (isogeny is a group homomorphism)
    let p0 = map_to_curve_sswu(&u0);
    let p1 = map_to_curve_sswu(&u1);
    PallasPoint { inner: p0.add(&p1) }
}

/// Pasta / Halo2 `hash_to_curve`: BLAKE2b-XMD expand + SSWU + 3-isogeny.
///
/// `domain_prefix` is e.g. `"z.cash:SinsemillaQ"`; curve id is `"pallas"`.
pub fn hash_to_curve_pasta(domain_prefix: &str, message: &[u8]) -> PallasPoint {
    let (u0, u1) = expand_message_xmd_blake2b(domain_prefix, "pallas", message);
    let p0 = map_to_curve_sswu(&fe_from_uniform_bytes_le(&u0));
    let p1 = map_to_curve_sswu(&fe_from_uniform_bytes_le(&u1));
    // iso is a group homomorphism ⇒ iso(a)+iso(b) = iso(a+b)
    PallasPoint { inner: p0.add(&p1) }
}

/// BLAKE2b expand_message matching pasta_curves hashtocurve.
fn expand_message_xmd_blake2b(
    domain_prefix: &str,
    curve_id: &str,
    message: &[u8],
) -> (alloc::vec::Vec<u8>, alloc::vec::Vec<u8>) {
    use crate::hash::blake2b::Blake2b;
    const CHUNK: usize = 64;
    let total_len = 22 + curve_id.len() + domain_prefix.len();
    let personal = [0u8; 16];

    let hash = |parts: &[&[u8]]| -> [u8; 64] {
        let mut h = Blake2b::new(CHUNK, None, None, Some(&personal));
        for p in parts {
            h.update(p);
        }
        h.finalize()
    };

    let empty128 = [0u8; 128];
    let len_tag = [0u8, (CHUNK * 2) as u8, 0u8];
    let dash = b"-";
    let suffix = b"_XMD:BLAKE2b_SSWU_RO_";
    let tlen = [total_len as u8];
    let dom = domain_prefix.as_bytes();
    let cid = curve_id.as_bytes();

    let b0 = hash(&[&empty128, message, &len_tag, dom, dash, cid, suffix, &tlen]);
    let b1 = hash(&[&b0, &[1u8], dom, dash, cid, suffix, &tlen]);
    let mut xor = [0u8; 64];
    for i in 0..64 {
        xor[i] = b0[i] ^ b1[i];
    }
    let b2 = hash(&[&xor, &[2u8], dom, dash, cid, suffix, &tlen]);
    let mut r1 = b1.to_vec();
    r1.reverse();
    let mut r2 = b2.to_vec();
    r2.reverse();
    (r1, r2)
}

/// Compressed encoding used by Orchard / pasta: LE x with y-sign in high bit of byte 31.
pub fn to_bytes_pasta(p: &PallasPoint) -> [u8; 32] {
    let mut out = [0u8; 32];
    if p.ct_is_identity() == 1 {
        return out;
    }
    let (x, y) = match p.inner.to_affine() {
        Ok(a) => a,
        Err(_) => return out,
    };
    let mut xb = [0u8; 32];
    let mut yb = [0u8; 32];
    x.to_bytes_be(&mut xb);
    y.to_bytes_be(&mut yb);
    for i in 0..32 {
        out[i] = xb[31 - i];
    }
    out[31] |= (yb[31] & 1) << 7;
    out
}

/// Decode Pasta compressed encoding (LE x, y-sign in high bit of byte 31).
pub fn from_bytes_pasta(bytes: &[u8; 32]) -> CurveResult<PallasPoint> {
    if bytes.iter().all(|&b| b == 0) {
        return Ok(PallasPoint::identity());
    }
    let sign = (bytes[31] >> 7) & 1;
    let mut le = *bytes;
    le[31] &= 0x7f;
    let mut be = [0u8; 32];
    for i in 0..32 {
        be[i] = le[31 - i];
    }
    let x = Fe::from_bytes_be(&be)?;
    // y² = x³ + 5
    let y2 = x.square().mul(&x).add(&fe_b());
    let mut y = y2.sqrt().map_err(|_| CurveError::InvalidPoint)?;
    y = Fe::ct_select(sign ^ y.is_odd(), &y.neg(), &y);
    Ok(PallasPoint {
        inner: Jac {
            x,
            y,
            z: Fe::one(),
            infinity: 0,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mul_vartime_add_matches_mul_add() {
        let le = |v: u64| {
            let mut b = [0u8; 32];
            b[..8].copy_from_slice(&v.to_le_bytes());
            let mut be = [0u8; 32];
            for i in 0..32 {
                be[i] = b[31 - i];
            }
            Fe::from_bytes_be(&be).expect("fe")
        };
        let show = |f: &Fe| {
            let mut be = [0u8; 32];
            f.to_bytes_be(&mut be);
            let mut le = [0u8; 32];
            for i in 0..32 {
                le[i] = be[31 - i];
            }
            u64::from_le_bytes(le[..8].try_into().unwrap())
        };
        for (a, b, c) in [
            (0u64, 0u64, 0u64),
            (1, 0, 0),
            (0, 1, 0),
            (1, 1, 0),
            (1, 1, 1),
            (2, 3, 5),
            (12345, 67890, 0),
            (12345, 67890, 7),
            (0, 0, 1),
            (0, 0, 5),
            (0, 5, 0),
            (5, 0, 0),
        ] {
            let (fa, fb, fc) = (le(a), le(b), le(c));
            let want = fa.mul(&fb).add(&fc);
            let got = fa.mul_vartime_add(&fb, &fc);
            assert_eq!(show(&want), show(&got), "({a},{b},{c})");
        }
    }

    #[test]
    fn vartime_ops_match_ct_ops_random() {
        // Differential: mul/add/sub vartime must equal CT ops on canonical inputs.
        let mut s = 0x243f6a8885a308d3u64;
        let next = move || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        let rnd_fe = |next: &mut dyn FnMut() -> u64| {
            // Random 254-bit canonical value (top two bits clear => < p).
            let mut be = [0u8; 32];
            for i in 0..4 {
                be[i * 8..(i + 1) * 8].copy_from_slice(&next().to_be_bytes());
            }
            be[0] &= 0x3f;
            Fe::from_bytes_be(&be).expect("canonical")
        };
        let mut nx = next;
        for _ in 0..500 {
            let (a, b, c) = (rnd_fe(&mut nx), rnd_fe(&mut nx), rnd_fe(&mut nx));
            assert_eq!(a.mul_vartime(&b).n, a.mul(&b).n, "mul");
            assert_eq!(a.add_vartime(&b).n, a.add(&b).n, "add");
            assert_eq!(a.sub_vartime(&b).n, a.sub(&b).n, "sub");
            assert_eq!(a.mul_vartime_add(&b, &c).n, a.mul(&b).add(&c).n, "mul_add");
            // Chained vartime stays canonical and matches.
            let chained = a.mul_vartime(&b).add_vartime(&c).mul_vartime(&a);
            let expect = a.mul(&b).add(&c).mul(&a);
            assert_eq!(chained.n, expect.n, "chained");
        }
    }

    #[test]
    fn pasta_roundtrip_generator() {
        let g = PallasPoint::generator();
        let b = to_bytes_pasta(&g);
        let g2 = from_bytes_pasta(&b).expect("gen pasta");
        assert_eq!(to_bytes_pasta(&g2), b);

        // Official Orchard SpendAuth basepoint (reddsa)
        let official: [u8; 32] = [
            99, 201, 117, 184, 132, 114, 26, 141, 12, 161, 112, 123, 227, 12, 127, 12, 95, 68, 95,
            62, 124, 24, 141, 59, 6, 214, 241, 40, 179, 35, 85, 183,
        ];
        let p = from_bytes_pasta(&official).expect("orchard spend-auth basepoint");
        assert_eq!(to_bytes_pasta(&p), official, "orchard basepoint roundtrip");

        let binding: [u8; 32] = [
            145, 90, 60, 136, 104, 198, 195, 14, 47, 128, 144, 238, 69, 215, 110, 64, 72, 32, 141,
            234, 91, 35, 102, 79, 187, 9, 164, 15, 85, 68, 244, 7,
        ];
        let p = from_bytes_pasta(&binding).expect("orchard binding basepoint");
        assert_eq!(to_bytes_pasta(&p), binding, "orchard binding roundtrip");
    }

    #[test]
    fn generator_pasta_bytes_locked() {
        // pasta_curves / Halo2: G = (-1, 2)
        let g = PallasPoint::generator();
        let b = to_bytes_pasta(&g);
        assert_eq!(g.ct_is_identity(), 0);
        let g2 = from_bytes_pasta(&b).expect("decode gen");
        assert_eq!(to_bytes_pasta(&g2), b);
        // [0]G = O
        assert_eq!(g.mul(&Scalar::zero()).ct_is_identity(), 1, "[0]G=O");
        // G + (-G) = O
        assert_eq!(g.add(&g.neg()).ct_is_identity(), 1, "G-G=O");
        // 2G via scalar == double, and != O
        let two = Scalar::from_bytes_le(&[
            2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ])
        .unwrap();
        let g2s = g.mul(&two);
        assert_eq!(g2s.ct_is_identity(), 0);
        let (x1, y1) = g2s.inner.to_affine().unwrap();
        let (x2, y2) = g.double().inner.to_affine().unwrap();
        assert_eq!(x1.ct_eq(&x2), 1);
        assert_eq!(y1.ct_eq(&y2), 1);
        // Orchard SpendAuth / Binding basepoints decode (already in pasta_roundtrip)
        assert_ne!(b, [0u8; 32]);
    }

    #[test]
    fn hash_to_curve_runs() {
        let p = hash_to_curve(b"test", b"PALLAS_XMD:SHA-256_SSWU_RO_");
        assert_eq!(p.ct_is_identity(), 0);
    }

    #[test]
    fn identity() {
        assert_eq!(PallasPoint::identity().ct_is_identity(), 1);
    }

    #[test]
    fn fe_add() {
        let r = Fe::one().add(&Fe::one());
        let mut out = [0u8; 32];
        r.to_bytes_be(&mut out);
        assert_eq!(out[31], 2);
    }

    #[test]
    fn generator_not_id() {
        assert_eq!(PallasPoint::generator().ct_is_identity(), 0);
    }

    #[test]
    fn neg_one_bytes() {
        let x = Fe::one().neg();
        let mut out = [0u8; 32];
        x.to_bytes_be(&mut out);
        // p-1 in BE should be P_BE with last byte 0
        let mut expect = P_BE;
        // p-1: subtract 1 from P_BE
        let mut i = 31;
        loop {
            if expect[i] > 0 {
                expect[i] -= 1;
                break;
            }
            expect[i] = 0xff;
            i -= 1;
        }
        assert_eq!(out, expect, "neg(1) bytes");
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
    fn on_curve_generator() {
        let g = PallasPoint::generator();
        let (x, y) = g.inner.to_affine().unwrap();
        let lhs = y.square();
        let rhs = x.square().mul(&x).add(&CURVE_B);
        assert_eq!(lhs.ct_eq(&rhs), 1, "generator on curve");
    }

    #[test]
    fn double_add() {
        let g = PallasPoint::generator();
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
        let g = PallasPoint::generator();
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
        let g = PallasPoint::generator();
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
    fn expand_message_xmd_len() {
        let out = expand_message_xmd(b"abc", b"QUUX-V01-CS02-with-expander-SHA256-128", 32);
        assert_eq!(out.len(), 32);
    }

    #[test]
    fn iso_map_zcash_regression() {
        // pasta test_iso_map input uses from_raw Jacobian coords (canonical * R2)
        let r = Jac {
            x: fe_from_limbs([
                0xc37f_111d_f5c4_419e,
                0x593c_053e_5e23_37ad,
                0x9c6c_fc47_bce1_aba6,
                0x0a88_1e4d_5569_45aa,
            ]),
            y: fe_from_limbs([
                0xf234_e044_3450_2b47,
                0x6979_f7f2_b0ac_f188,
                0xa62e_ec46_f662_cb4e,
                0x035e_5c8a_06d5_cfb4,
            ]),
            z: fe_from_limbs([
                0x11ab_791d_4fb6_f6b4,
                0x575b_aa71_7958_ef1f,
                0x6ac4_e343_558d_cbf3,
                0x3af3_7975_b093_3125,
            ]),
            infinity: 0,
        };
        let p = iso_map_3(&r);
        let (ax, ay) = p.to_affine().expect("affine");
        let lhs = ay.square();
        let rhs = ax.square().mul(&ax).add(&CURVE_B);
        assert_eq!(lhs.ct_eq(&rhs), 1, "iso image on Pallas");
        let p2 = iso_map_3(&r);
        assert_eq!(p.x.ct_eq(&p2.x), 1);
    }

    #[test]
    fn mont_field_roundtrip() {
        // 2 * 3 = 6 in Montgomery domain
        let two = Fe::one().add(&Fe::one());
        let three = two.add(&Fe::one());
        let six = two.mul(&three);
        let six2 = two.add(&two).add(&two);
        assert_eq!(six.ct_eq(&six2), 1);
        // from_bytes / to_bytes
        let mut b = [0u8; 32];
        b[31] = 7;
        let fe = Fe::from_bytes_be(&b).unwrap();
        let mut out = [0u8; 32];
        fe.to_bytes_be(&mut out);
        assert_eq!(out, b);
        // sqrt(4) = 2
        let four = two.mul(&two);
        let s = four.sqrt().expect("sqrt4");
        assert_eq!(s.ct_eq(&two) | s.ct_eq(&two.neg()), 1);
    }

    #[test]
    fn sswu_map_on_curve_ct() {
        for u in [Fe::zero(), Fe::one()] {
            let p = map_to_curve_sswu(&u);
            let (ax, ay) = p.to_affine().expect("affine");
            let lhs = ay.square();
            let rhs = ax.square().mul(&ax).add(&CURVE_B);
            assert_eq!(lhs.ct_eq(&rhs), 1, "SSWU+iso on Pallas");
        }
    }

    #[test]
    fn hash_to_curve_locked_abc() {
        let dst = b"PALLAS_XMD:SHA-256_SSWU_RO_";
        let p = hash_to_curve(b"abc", dst);
        assert_eq!(p.ct_is_identity(), 0);
        let (ax, ay) = p.inner.to_affine().expect("affine");
        let lhs = ay.square();
        let rhs = ax.square().mul(&ax).add(&CURVE_B);
        assert_eq!(lhs.ct_eq(&rhs), 1, "hash on Pallas");
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
    fn generator_neg_add_identity() {
        let g = PallasPoint::generator();
        assert_eq!(g.add(&g.neg()).ct_is_identity(), 1);
        let mut two = [0u8; 32];
        two[31] = 2;
        let s = Scalar::from_bytes_be(&two).unwrap();
        let g2 = g.mul(&s);
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        g2.to_bytes_compressed(&mut a).unwrap();
        g.double().to_bytes_compressed(&mut b).unwrap();
        assert_eq!(a, b);
    }
}

