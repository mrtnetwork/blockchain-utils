//! Ed25519 extended twisted Edwards points and constant-time scalar multiplication.
//!
//! Coordinates (X : Y : Z : T) with x = X/Z, y = Y/Z, xy = T/Z.
//! Formulas follow Hisil–Wong–Carter–Dawson (extended) with a = −1.

use super::fe::Fe;
use super::scalar::Scalar;
use crate::curve::error::{CurveError, CurveResult};
use crate::curve::traits::{CurvePoint, FieldElement};

/// Curve constant d = −121665/121666 mod p (little-endian).
const D_LE: [u8; 32] = [
    0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75, 0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70, 0x00,
    0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c, 0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52,
];

/// Base point B_x (little-endian).
const BX_LE: [u8; 32] = [
    0x1a, 0xd5, 0x25, 0x8f, 0x60, 0x2d, 0x56, 0xc9, 0xb2, 0xa7, 0x25, 0x95, 0x60, 0xc7, 0x2c, 0x69,
    0x5c, 0xdc, 0xd6, 0xfd, 0x31, 0xe2, 0xa4, 0xc0, 0xfe, 0x53, 0x6e, 0xcd, 0xd3, 0x36, 0x69, 0x21,
];

/// Base point B_y = 4/5 (little-endian).
const BY_LE: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];

fn fe_d() -> Fe {
    Fe::from_bytes_le(&D_LE).expect("d")
}

fn fe_2d() -> Fe {
    let d = fe_d();
    d.add(&d)
}

/// Extended projective point.
#[derive(Clone, Copy, Debug)]
pub struct Extended {
    pub x: Fe,
    pub y: Fe,
    pub z: Fe,
    pub t: Fe,
}

impl Extended {
    /// Identity: (0 : 1 : 1 : 0)
    pub fn identity() -> Self {
        Self {
            x: Fe::zero(),
            y: Fe::one(),
            z: Fe::one(),
            t: Fe::zero(),
        }
    }

    pub fn ct_is_identity(&self) -> u8 {
        // X == 0 and Y == Z (affine y = 1, x = 0)
        let xz = self.x.ct_eq(&Fe::zero());
        let yz = self.y.ct_eq(&self.z);
        xz & yz
    }

    pub fn is_identity(&self) -> bool {
        self.ct_is_identity() == 1
    }

    pub fn generator() -> Self {
        let x = Fe::from_bytes_le(&BX_LE).expect("Bx");
        let y = Fe::from_bytes_le(&BY_LE).expect("By");
        Self {
            x,
            y,
            z: Fe::one(),
            t: x.mul(&y),
        }
    }

    pub fn neg(&self) -> Self {
        Self {
            x: self.x.negate(),
            y: self.y,
            z: self.z,
            t: self.t.negate(),
        }
    }

    /// Doubling (extended, a = −1).
    pub fn double(&self) -> Self {
        // A = X^2; B = Y^2; C = 2*Z^2; H = A+B; E = H-(X+Y)^2; G = A-B; F = C+G
        // X3 = E*F; Y3 = G*H; T3 = E*H; Z3 = F*G
        let a = self.x.square();
        let b = self.y.square();
        let c = self.z.square();
        let _c = c.add(&c);
        let h = a.add(&b);
        let _e = {
            let xy = self.x.add(&self.y);
            let xy2 = xy.square();
            h.sub(&xy2)
        };
        // e = H - (X+Y)^2 = X^2 + Y^2 - X^2 - 2XY - Y^2 = -2XY
        // For a=-1 the standard formula uses:
        // Actually use verified formula:
        // A=X^2, B=Y^2, C=2Z^2, D=aA=-A, E=H-(X+Y)^2 wait
        // From ref:
        // X3 = (X+Y)^2 - A - B
        // Y3 = B - A  (since a=-1, D=aA=-A, Y3 = B+D = B-A)
        // Z3 = ...
        let xy = self.x.add(&self.y).square();
        let _e = xy.sub(&a).sub(&b); // (X+Y)^2 - A - B = 2XY
        let _g = a.negate().sub(&b); // -A - B? For a=-1: G = A + a*A no
                                     // Correct Hisil for a=-1:
                                     // A = X1^2
                                     // B = Y1^2
                                     // C = 2*Z1^2
                                     // H = A+B
                                     // E = H - (X1+Y1)^2   → actually E = 2*X*Y with sign?
                                     // Let me use:
                                     // X3 = 2XY * (Y^2 - X^2) wait - use known working:
                                     // From TweetNaCl / ref10 style adapted:
        let aa = self.x.square();
        let bb = self.y.square();
        let zz = self.z.square();
        let zz2 = zz.add(&zz);
        let xy2 = self.x.add(&self.y).square();
        let yy_xx = bb.sub(&aa); // Y^2 - X^2
        let xx_yy = aa.add(&bb); // X^2 + Y^2
        let _e2 = xy2.sub(&xx_yy); // 2XY
        let _c2 = zz2.sub(&yy_xx); // 2Z^2 - (Y^2 - X^2)
                                   // X3 = 2XY * (2Z^2 - (Y^2-X^2))? No
                                   // Standard a=-1 double:
                                   // X3 = (X+Y)^2 - X^2 - Y^2   *   (Y^2 - X^2) ?
                                   // Let's compute:
                                   // X3 = E * F where E = 2XY, F = 2Z^2 - (Y^2 - X^2) wait
                                   // From https://hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html
                                   // dbl-2008-hwcd:
                                   // A = X1^2
                                   // B = Y1^2
                                   // C = 2*Z1^2
                                   // D = a*A   (= -A)
                                   // E = (X1+Y1)^2 - A - B
                                   // G = D + B
                                   // F = G - C
                                   // H = D - B
                                   // X3 = E*F
                                   // Y3 = G*H
                                   // T3 = E*H
                                   // Z3 = F*G
        let d = aa.negate(); // a*A
        let e = xy2.sub(&aa).sub(&bb);
        let g = d.add(&bb);
        let f = g.sub(&zz2);
        let h = d.sub(&bb);
        Self {
            x: e.mul(&f),
            y: g.mul(&h),
            z: f.mul(&g),
            t: e.mul(&h),
        }
    }

    /// Addition of two extended points (unified for a = −1).
    pub fn add(&self, other: &Self) -> Self {
        // add-2008-hwcd-3 (unified, a=-1):
        // A = X1*X2; B = Y1*Y2; C = Z1*T2; D = T1*Z2
        // E = D+C; F = (X1-Y1)*(X2+Y2) + B - A; wait
        // Standard:
        // A = X1*X2
        // B = Y1*Y2
        // C = Z1*T2
        // D = T1*Z2
        // E = D+C
        // F = (X1-Y1)*(X2+Y2)+B-A   ?
        // From EFD unified:
        // A = X1*X2
        // B = Y1*Y2
        // C = Z1*Z2
        // D = T1*T2
        // E = D*(2d) wait for mixed
        // For extended + extended a=-1:
        // A = X1*X2
        // B = Y1*Y2
        // C = Z1*T2
        // D = T1*Z2
        // E = D + C
        // F = (X1 - Y1)*(X2 + Y2) + B - A
        // G = B + A
        // H = D - C
        // X3 = E*F; Y3 = G*H; Z3 = F*G; T3 = E*H
        // Actually the common formula is:
        let a = self.x.mul(&other.x);
        let b = self.y.mul(&other.y);
        let c = self.z.mul(&other.t);
        let d = self.t.mul(&other.z);
        let _e = d.add(&c);
        let _f = {
            let xy1 = self.x.sub(&self.y);
            let xy2 = other.x.add(&other.y);
            xy1.mul(&xy2).add(&b).sub(&a)
        };
        // Wait - verify F: (X1-Y1)(X2+Y2) = X1X2 + X1Y2 - Y1X2 - Y1Y2
        // + B - A = X1X2 + X1Y2 - Y1X2 - Y1Y2 + Y1Y2 - X1X2 = X1Y2 - Y1X2
        // That's not right for addition.
        // Use the correct EFD formula for a=-1:
        // A = X1*X2
        // B = Y1*Y2
        // C = Z1*T2
        // D = T1*Z2
        // E = D+C
        // F = B - a*A = B + A (a=-1)
        // G = B + a*A = B - A
        // H = D - C
        // X3 = E * H ? No:
        // From EFD add-2008-hwcd-2:
        // A = X1*X2
        // B = Y1*Y2
        // C = Z1*T2
        // D = T1*Z2
        // E = D+C
        // F = (X1-Y1)*(X2+Y2) +B -A
        // G = B + A
        // H = D - C
        // X3 = E*F
        // Y3 = G*H
        // Z3 = F*G
        // T3 = E*H
        // And (X1-Y1)*(X2+Y2)+B-A = X1Y2 - Y1X2 as above — that would be for different.
        // Looking at monero/ref10 ge_add:
        // Actually use:
        // A = (Y1-X1)*(Y2-X2)
        // B = (Y1+X1)*(Y2+X2)
        // C = T1*2d*T2
        // D = Z1*2*Z2
        // E = B-A; F = D-C; G = D+C; H = B+A
        // X3 = E*F; Y3 = G*H; Z3 = F*G; T3 = E*H
        let two_d = fe_2d();
        let a = self.y.sub(&self.x).mul(&other.y.sub(&other.x));
        let b = self.y.add(&self.x).mul(&other.y.add(&other.x));
        let c = self.t.mul(&two_d).mul(&other.t);
        let d = self.z.add(&self.z).mul(&other.z);
        let e = b.sub(&a);
        let f = d.sub(&c);
        let g = d.add(&c);
        let h = b.add(&a);
        Self {
            x: e.mul(&f),
            y: g.mul(&h),
            z: f.mul(&g),
            t: e.mul(&h),
        }
    }

    pub fn ct_select(choice: u8, a: &Self, b: &Self) -> Self {
        Self {
            x: Fe::ct_select(choice, &a.x, &b.x),
            y: Fe::ct_select(choice, &a.y, &b.y),
            z: Fe::ct_select(choice, &a.z, &b.z),
            t: Fe::ct_select(choice, &a.t, &b.t),
        }
    }

    /// Constant-time variable-base scalar multiplication (4-bit fixed window).
    ///
    /// Precomputes `{0P..15P}` then processes the scalar MSB-first in 4-bit
    /// windows. Table selection is constant-time; no secret-dependent branches.
    pub fn mul_ct(&self, scalar: &Scalar) -> Self {
        // table[i] = i * self, i = 0..15
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
        // 64 windows of 4 bits, MSB first
        for w in (0..64).rev() {
            r = r.double().double().double().double();
            let mut bits = 0u8;
            for b in 0..4 {
                bits |= scalar.bit(w * 4 + b) << b;
            }
            // CT select table[bits]
            let mut t = Self::identity();
            for (i, ti) in table.iter().enumerate() {
                let eq = crate::ct::ct_eq_u8(bits, i as u8);
                t = Self::ct_select(eq, ti, &t);
            }
            r = r.add(&t);
        }
        r
    }

    /// Legacy bit-by-bit CT mul (kept for comparison / small code paths).
    pub fn mul_ct_bits(&self, scalar: &Scalar) -> Self {
        let mut r = Self::identity();
        let base = *self;
        for i in (0..256).rev() {
            r = r.double();
            let bit = scalar.bit(i);
            let added = r.add(&base);
            r = Self::ct_select(bit, &added, &r);
        }
        r
    }

    /// Variable-time scalar multiplication (public scalars only).
    ///
    /// Same 4-bit fixed windows as [`mul_ct`], but table lookup branches on the
    /// window value (no CT select). Use only for public scalars / verification.
    pub fn mul_vartime(&self, scalar: &Scalar) -> Self {
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
                bits |= scalar.bit(w * 4 + b) << b;
            }
            // Variable-time table select
            r = r.add(&table[bits as usize]);
        }
        r
    }

    /// Variable-time double-scalar: a*A + b*B.
    pub fn mul_vartime_add(a: &Scalar, a_point: &Self, b: &Scalar, b_point: &Self) -> Self {
        a_point.mul_vartime(a).add(&b_point.mul_vartime(b))
    }

    /// Affine (x, y) after inversion.
    pub fn to_affine(&self) -> CurveResult<(Fe, Fe)> {
        let zinv = self.z.invert()?;
        let x = self.x.mul(&zinv);
        let y = self.y.mul(&zinv);
        Ok((x, y))
    }

    /// RFC 8032 encode: 32-byte LE y with sign bit of x in MSB.
    pub fn encode(&self, out: &mut [u8; 32]) -> CurveResult<()> {
        let (x, y) = self.to_affine()?;
        y.to_bytes_le(out);
        let sign = x.is_odd();
        out[31] |= sign << 7;
        Ok(())
    }

    /// RFC 8032 decode.
    pub fn decode(bytes: &[u8; 32]) -> CurveResult<Self> {
        let mut yb = *bytes;
        let sign = (yb[31] >> 7) & 1;
        yb[31] &= 0x7f;
        let y = Fe::from_bytes_canonical(&yb)?;
        // x^2 = (y^2 - 1) / (d y^2 + 1)
        let y2 = y.square();
        let num = y2.sub(&Fe::one());
        let den = fe_d().mul(&y2).add(&Fe::one());
        let den_inv = den.invert().map_err(|_| CurveError::InvalidPoint)?;
        let x2 = num.mul(&den_inv);
        let x = sqrt_mod_p(&x2)?;
        let mut xv = x;
        if xv.is_odd() != sign {
            xv = xv.negate();
        }
        // on-curve check: -x^2 + y^2 == 1 + d x^2 y^2
        let xx = xv.square();
        let yy = y2;
        let lhs = yy.sub(&xx);
        let rhs = Fe::one().add(&fe_d().mul(&xx).mul(&yy));
        if lhs.ct_eq(&rhs) != 1 {
            return Err(CurveError::InvalidPoint);
        }
        Ok(Self {
            x: xv,
            y,
            z: Fe::one(),
            t: xv.mul(&y),
        })
    }
}

/// sqrt for p ≡ 5 (mod 8): candidate a^((p+3)/8), adjust by 2^((p-1)/4) if needed.
fn sqrt_mod_p(a: &Fe) -> CurveResult<Fe> {
    // exp = (p+3)/8
    let _exp: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x0f, // BE of (p+3)/8 — wait LE power loop uses BE style
    ];
    // Better: p = 2^255-19, (p+3)/8 = 2^252 - 2 + ... compute via square-and-mul on known exp bytes BE
    // (p+3)/8 in hex: 0x0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    // Use square chain for correctness
    let _r = *a;
    // a^(2^252 - 2) roughly — use full exp
    // exponent (p+3)/8 as 32 BE bytes:
    // (p+3)/8 = 2^252 - 2 → BE
    let exp_be: [u8; 32] = [
        0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xfe,
    ];
    let mut result = Fe::one();
    let base = *a;
    for byte in exp_be.iter() {
        for bit in (0..8).rev() {
            result = result.square();
            let bit_set = (byte >> bit) & 1;
            let mulled = result.mul(&base);
            result = Fe::ct_select(bit_set, &mulled, &result);
        }
    }
    // check result^2 == a or == -a; if -a multiply by 2^((p-1)/4)
    if result.square().ct_eq(a) == 1 {
        return Ok(result);
    }
    // (p-1)/4 BE
    let i_exp: [u8; 32] = [
        0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xfb,
    ];
    let mut i = Fe::one();
    let b2 = Fe::one().add(&Fe::one());
    for byte in i_exp.iter() {
        for bit in (0..8).rev() {
            i = i.square();
            let bit_set = (byte >> bit) & 1;
            let mulled = i.mul(&b2);
            i = Fe::ct_select(bit_set, &mulled, &i);
        }
    }
    let alt = result.mul(&i);
    if alt.square().ct_eq(a) == 1 {
        return Ok(alt);
    }
    Err(CurveError::InvalidPoint)
}

/// Public Ed25519 point implementing [`CurvePoint`].
#[derive(Clone, Copy, Debug)]
pub struct Ed25519Point {
    inner: Extended,
}

impl Ed25519Point {
    pub fn generator() -> Self {
        Self {
            inner: Extended::generator(),
        }
    }

    /// Access extended coordinates (for Ristretto / advanced maps).
    pub fn as_extended(&self) -> &Extended {
        &self.inner
    }

    /// Build from extended coordinates.
    pub fn from_extended(ge: Extended) -> Self {
        Self { inner: ge }
    }

    /// Variable-time scalar × point (public scalar).
    #[inline]
    pub fn mul_vartime(&self, scalar: &Scalar) -> Self {
        Self {
            inner: self.inner.mul_vartime(scalar),
        }
    }

    /// Variable-time [k]B.
    #[inline]
    pub fn mul_vartime_base(scalar: &Scalar) -> Self {
        Self::generator().mul_vartime(scalar)
    }

    /// Variable-time a*A + b*B.
    #[inline]
    pub fn mul_vartime_add(a: &Scalar, a_p: &Self, b: &Scalar, b_p: &Self) -> Self {
        Self {
            inner: Extended::mul_vartime_add(a, &a_p.inner, b, &b_p.inner),
        }
    }
}

impl CurvePoint for Ed25519Point {
    type Scalar = Scalar;
    const COMPRESSED_BYTES: usize = 32;
    const UNCOMPRESSED_BYTES: usize = 32;

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
            inner: self.inner.mul_ct(scalar),
        }
    }

    fn from_bytes(bytes: &[u8]) -> CurveResult<Self> {
        if bytes.len() != 32 {
            return Err(CurveError::InvalidLength);
        }
        let mut b = [0u8; 32];
        b.copy_from_slice(bytes);
        Ok(Self {
            inner: Extended::decode(&b)?,
        })
    }

    fn to_bytes_compressed(&self, out: &mut [u8]) -> CurveResult<()> {
        if out.len() != 32 {
            return Err(CurveError::InvalidLength);
        }
        let mut buf = [0u8; 32];
        self.inner.encode(&mut buf)?;
        out.copy_from_slice(&buf);
        Ok(())
    }

    fn to_bytes_uncompressed(&self, out: &mut [u8]) -> CurveResult<()> {
        self.to_bytes_compressed(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generator_encode_known() {
        let g = Ed25519Point::generator();
        let mut out = [0u8; 32];
        g.to_bytes_compressed(&mut out).unwrap();
        // RFC 8032 basepoint encoding
        let expected: [u8; 32] = [
            0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66,
        ];
        assert_eq!(out, expected);
    }

    #[test]
    fn roundtrip_generator() {
        let g = Ed25519Point::generator();
        let mut out = [0u8; 32];
        g.to_bytes_compressed(&mut out).unwrap();
        let g2 = Ed25519Point::from_bytes(&out).unwrap();
        let mut out2 = [0u8; 32];
        g2.to_bytes_compressed(&mut out2).unwrap();
        assert_eq!(out, out2);
    }

    #[test]
    fn mul_vartime_matches_ct() {
        let g = Ed25519Point::generator();
        let sc = Scalar::from_bytes_mod_order(&[7u8; 32]);
        let ct = g.mul(&sc);
        let vt = g.mul_vartime(&sc);
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        ct.to_bytes_compressed(&mut a).unwrap();
        vt.to_bytes_compressed(&mut b).unwrap();
        assert_eq!(a, b);
        let base_vt = Ed25519Point::mul_vartime_base(&sc);
        base_vt.to_bytes_compressed(&mut b).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn mul_by_one() {
        let g = Ed25519Point::generator();
        let r = g.mul(&Scalar::one());
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        g.to_bytes_compressed(&mut a).unwrap();
        r.to_bytes_compressed(&mut b).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn mul_by_two_equals_double() {
        let g = Ed25519Point::generator();
        let d = g.double();
        let two = Scalar::one().add(&Scalar::one());
        let m = g.mul(&two);
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        d.to_bytes_compressed(&mut a).unwrap();
        m.to_bytes_compressed(&mut b).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn identity_encode() {
        let id = Ed25519Point::identity();
        let mut out = [0u8; 32];
        id.to_bytes_compressed(&mut out).unwrap();
        // identity encodes as y=1, x=0 → 01 00..00
        assert_eq!(out[0], 1);
        for o in out.iter().skip(1) {
            assert_eq!(*o, 0);
        }
    }
}
