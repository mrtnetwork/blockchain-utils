//! secp256k1 points (affine + Jacobian) and constant-time scalar multiplication.

use super::fe::Fe;
use super::scalar::Scalar;
use crate::curve::error::{CurveError, CurveResult};
use crate::curve::traits::{CurvePoint, FieldElement};

/// Affine point (x, y) or infinity.
#[derive(Clone, Copy, Debug)]
pub struct Affine {
    pub x: Fe,
    pub y: Fe,
    /// 1 if infinity, 0 otherwise (public for infinity flags often).
    pub infinity: u8,
}

/// Jacobian point (X, Y, Z) with x = X/Z^2, y = Y/Z^3.
#[derive(Clone, Copy, Debug)]
pub struct Jacobian {
    pub x: Fe,
    pub y: Fe,
    pub z: Fe,
    pub infinity: u8,
}

impl Affine {
    pub fn infinity() -> Self {
        Self {
            x: Fe::zero(),
            y: Fe::zero(),
            infinity: 1,
        }
    }

    pub fn is_infinity(&self) -> bool {
        self.infinity == 1
    }

    /// Generator G (compressed 02... from SEC).
    pub fn generator() -> Self {
        // Gx, Gy from SEC2
        let gx = Fe::from_bytes_be(&[
            0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87,
            0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B,
            0x16, 0xF8, 0x17, 0x98,
        ])
        .expect("G.x");
        let gy = Fe::from_bytes_be(&[
            0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65, 0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11,
            0x08, 0xA8, 0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19, 0x9C, 0x47, 0xD0, 0x8F,
            0xFB, 0x10, 0xD4, 0xB8,
        ])
        .expect("G.y");
        Self {
            x: gx,
            y: gy,
            infinity: 0,
        }
    }

    pub fn to_jacobian(&self) -> Jacobian {
        if self.is_infinity() {
            return Jacobian::infinity();
        }
        Jacobian {
            x: self.x,
            y: self.y,
            z: Fe::one(),
            infinity: 0,
        }
    }

    /// SEC1 compressed/uncompressed decode.
    pub fn from_bytes(bytes: &[u8]) -> CurveResult<Self> {
        if bytes.is_empty() {
            return Err(CurveError::InvalidLength);
        }
        match bytes[0] {
            // Strict SEC1 lone `0x00`, plus our fixed-buffer `0x00‖zeros`
            // (33/65) so infinity round-trips through fixed-size APIs.
            0x00 if bytes.len() == 1 || bytes.len() == 33 || bytes.len() == 65 => {
                if bytes.iter().all(|b| *b == 0) {
                    Ok(Self::infinity())
                } else {
                    Err(CurveError::InvalidEncoding)
                }
            }
            0x04 if bytes.len() == 65 => {
                let x = Fe::from_bytes(&bytes[1..33])?;
                let y = Fe::from_bytes(&bytes[33..65])?;
                let p = Self { x, y, infinity: 0 };
                if !p.is_on_curve() {
                    return Err(CurveError::InvalidPoint);
                }
                Ok(p)
            }
            0x02 | 0x03 if bytes.len() == 33 => {
                let x = Fe::from_bytes(&bytes[1..33])?;
                let y = lift_x(&x, bytes[0] == 0x03)?;
                let p = Self { x, y, infinity: 0 };
                if !p.is_on_curve() {
                    return Err(CurveError::InvalidPoint);
                }
                Ok(p)
            }
            _ => Err(CurveError::InvalidEncoding),
        }
    }

    pub fn is_on_curve(&self) -> bool {
        if self.is_infinity() {
            return true;
        }
        // y^2 = x^3 + 7
        let y2 = self.y.square();
        let x2 = self.x.square();
        let x3 = x2.mul(&self.x);
        // 7
        let mut b = [0u8; 32];
        b[31] = 7;
        let seven = Fe::from_bytes_be(&b).unwrap_or(Fe::zero());
        let rhs = x3.add(&seven);
        y2.ct_eq(&rhs) == 1
    }

    pub fn to_bytes_compressed(&self, out: &mut [u8; 33]) -> CurveResult<()> {
        if self.is_infinity() {
            // Fixed-buffer ∞ per BIP327 `zeroPk` convention (strict SEC1
            // would be a lone `0x00`, which has no fixed-size slot).
            *out = [0u8; 33];
            return Ok(());
        }
        let mut xb = [0u8; 32];
        self.x.to_bytes_be(&mut xb);
        out[0] = 0x02 | self.y.is_odd();
        out[1..].copy_from_slice(&xb);
        Ok(())
    }

    pub fn to_bytes_uncompressed(&self, out: &mut [u8; 65]) -> CurveResult<()> {
        if self.is_infinity() {
            *out = [0u8; 65];
            return Ok(());
        }
        out[0] = 0x04;
        let mut xb = [0u8; 32];
        let mut yb = [0u8; 32];
        self.x.to_bytes_be(&mut xb);
        self.y.to_bytes_be(&mut yb);
        out[1..33].copy_from_slice(&xb);
        out[33..65].copy_from_slice(&yb);
        Ok(())
    }
}

impl Jacobian {
    pub fn infinity() -> Self {
        Self {
            x: Fe::zero(),
            y: Fe::zero(),
            z: Fe::zero(),
            infinity: 1,
        }
    }

    pub fn is_infinity(&self) -> bool {
        self.infinity == 1
    }

    pub fn from_affine(p: &Affine) -> Self {
        p.to_jacobian()
    }

    /// Double (Jacobian). Always runs the formula; selects identity if input is ∞.
    /// Formulas for a=0: S=4XY², M=3X², X'=M²−2S, Y'=M(S−X')−8Y⁴, Z'=2YZ.
    pub fn double(&self) -> Self {
        let y2 = self.y.square();
        let s = {
            let t = self.x.mul(&y2);
            let t = t.add(&t);
            t.add(&t)
        };
        let m = {
            let x2 = self.x.square();
            x2.add(&x2).add(&x2)
        };
        let m2 = m.square();
        let x3 = m2.sub(&s.add(&s));
        let eight_y4 = {
            let y4 = y2.square();
            let t = y4.add(&y4);
            let t = t.add(&t);
            t.add(&t)
        };
        let y3 = m.mul(&s.sub(&x3)).sub(&eight_y4);
        let z3 = {
            let t = self.y.mul(&self.z);
            t.add(&t)
        };
        let doubled = Self {
            x: x3,
            y: y3,
            z: z3,
            infinity: 0,
        };
        // If input was infinity, result is infinity (CT select).
        Self::ct_select(self.infinity, &Self::infinity(), &doubled)
    }

    /// Add two Jacobian points. Constant-time w.r.t. coordinate values;
    /// infinity flags are selected with masks (no early return on secret ∞).
    pub fn add(&self, other: &Self) -> Self {
        let z1z1 = self.z.square();
        let z2z2 = other.z.square();
        let u1 = self.x.mul(&z2z2);
        let u2 = other.x.mul(&z1z1);
        let s1 = self.y.mul(&other.z).mul(&z2z2);
        let s2 = other.y.mul(&self.z).mul(&z1z1);
        let h = u2.sub(&u1);
        let r = s2.sub(&s1);
        // CT zero tests (no branch on secret coordinates)
        let h_zero = h.ct_eq(&Fe::zero());
        let r_zero = r.ct_eq(&Fe::zero());
        // equal points → double; opposite → infinity
        let doubled = self.double();
        let h2 = h.square();
        let h3 = h2.mul(&h);
        let v = u1.mul(&h2);
        let x3 = r.square().sub(&h3).sub(&v.add(&v));
        let y3 = r.mul(&v.sub(&x3)).sub(&s1.mul(&h3));
        let z3 = h.mul(&self.z).mul(&other.z);
        let summed = Self {
            x: x3,
            y: y3,
            z: z3,
            infinity: 0,
        };
        // Select among: infinity (H=0,R≠0), double (H=0,R=0), sum (H≠0)
        let both_zero = h_zero & r_zero;
        let only_h = h_zero & (1 ^ r_zero);
        let mut out = Self::ct_select(both_zero, &doubled, &summed);
        out = Self::ct_select(only_h, &Self::infinity(), &out);
        // If self is ∞ → other; if other is ∞ → self (after above)
        out = Self::ct_select(self.infinity, other, &out);
        out = Self::ct_select(other.infinity & (self.infinity ^ 1), self, &out);
        // both infinity → infinity
        out = Self::ct_select(self.infinity & other.infinity, &Self::infinity(), &out);
        out
    }

    pub fn neg(&self) -> Self {
        let n = Self {
            x: self.x,
            y: self.y.negate(),
            z: self.z,
            infinity: self.infinity,
        };
        Self::ct_select(self.infinity, self, &n)
    }

    /// Convert to affine (expensive inversion).
    pub fn to_affine(&self) -> CurveResult<Affine> {
        if self.is_infinity() {
            return Ok(Affine::infinity());
        }
        let zinv = self.z.invert()?;
        let zinv2 = zinv.square();
        let zinv3 = zinv2.mul(&zinv);
        Ok(Affine {
            x: self.x.mul(&zinv2),
            y: self.y.mul(&zinv3),
            infinity: 0,
        })
    }

    /// Constant-time scalar multiplication (4-bit fixed window).
    pub fn mul_ct(&self, scalar: &Scalar) -> Self {
        let mut table = [Self::infinity(); 16];
        table[1] = *self;
        for i in 2..16 {
            if i & 1 == 0 {
                table[i] = table[i / 2].double();
            } else {
                table[i] = table[i - 1].add(self);
            }
        }
        let mut r = Self::infinity();
        for w in (0..64).rev() {
            r = r.double().double().double().double();
            let mut bits = 0u8;
            for b in 0..4 {
                bits |= scalar.bit(w * 4 + b) << b;
            }
            let mut t = Self::infinity();
            for (i, ti) in table.iter().enumerate() {
                let eq = crate::ct::ct_eq_u8(bits, i as u8);
                t = Self::ct_select(eq, ti, &t);
            }
            r = r.add(&t);
        }
        r
    }

    /// Bit-by-bit CT mul (fallback).
    pub fn mul_ct_bits(&self, scalar: &Scalar) -> Self {
        let mut r = Self::infinity();
        let base = *self;
        for i in (0..256).rev() {
            r = r.double();
            let bit = scalar.bit(i);
            let added = r.add(&base);
            r = Self::ct_select(bit, &added, &r);
        }
        r
    }

    pub fn ct_select(choice: u8, a: &Jacobian, b: &Jacobian) -> Jacobian {
        Jacobian {
            x: Fe::ct_select(choice, &a.x, &b.x),
            y: Fe::ct_select(choice, &a.y, &b.y),
            z: Fe::ct_select(choice, &a.z, &b.z),
            infinity: crate::ct::ct_select_u8(choice, a.infinity, b.infinity),
        }
    }
}

fn lift_x(x: &Fe, y_odd: bool) -> CurveResult<Fe> {
    let x2 = x.square();
    let x3 = x2.mul(x);
    let mut b = [0u8; 32];
    b[31] = 7;
    let seven = Fe::from_bytes_be(&b).map_err(|_| CurveError::InvalidPoint)?;
    let y2 = x3.add(&seven);
    let y = sqrt_mod_p(&y2)?;
    let mut y_n = y;
    y_n.normalize();
    if (y_n.is_odd() == 1) != y_odd {
        return Ok(y.negate());
    }
    Ok(y)
}

/// Tonelli–Shanks for p ≡ 3 (mod 4): sqrt = a^((p+1)/4).
fn sqrt_mod_p(a: &Fe) -> CurveResult<Fe> {
    // (p+1)/4 = 0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff0c
    let exp: [u8; 32] = [
        0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbf, 0xff,
        0xff, 0x0c,
    ];
    let base = *a;
    let mut result = Fe::one();
    for byte in exp.iter() {
        for bit in (0..8).rev() {
            result = result.square();
            let bit_set = (byte >> bit) & 1;
            let mul = result.mul(&base);
            result = Fe::ct_select(bit_set, &mul, &result);
        }
    }
    // verify
    if result.square().ct_eq(a) != 1 {
        return Err(CurveError::InvalidPoint);
    }
    Ok(result)
}

/// Public secp256k1 point type implementing [`CurvePoint`].
#[derive(Clone, Copy, Debug)]
pub struct Secp256k1Point {
    inner: Jacobian,
}

impl Secp256k1Point {
    /// Generator.
    pub fn generator() -> Self {
        Self {
            inner: Affine::generator().to_jacobian(),
        }
    }

    /// Branchless select: `choice==1` → `a`, else `b`. For secret-parity
    /// adjustments (BIP-340 even-Y) so timing never reveals the parity bit.
    pub fn ct_select(choice: u8, a: &Self, b: &Self) -> Self {
        Self {
            inner: Jacobian::ct_select(choice, &a.inner, &b.inner),
        }
    }

    /// Affine access (normalizes).
    pub fn to_affine(&self) -> CurveResult<Affine> {
        self.inner.to_affine()
    }
}

impl CurvePoint for Secp256k1Point {
    type Scalar = Scalar;
    const COMPRESSED_BYTES: usize = 33;
    const UNCOMPRESSED_BYTES: usize = 65;

    fn identity() -> Self {
        Self {
            inner: Jacobian::infinity(),
        }
    }

    fn ct_is_identity(&self) -> u8 {
        self.inner.infinity
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
        let ge = Affine::from_bytes(bytes)?;
        Ok(Self {
            inner: ge.to_jacobian(),
        })
    }

    fn to_bytes_compressed(&self, out: &mut [u8]) -> CurveResult<()> {
        if out.len() != 33 {
            return Err(CurveError::InvalidLength);
        }
        let ge = self.inner.to_affine()?;
        let mut buf = [0u8; 33];
        ge.to_bytes_compressed(&mut buf)?;
        out.copy_from_slice(&buf);
        Ok(())
    }

    fn to_bytes_uncompressed(&self, out: &mut [u8]) -> CurveResult<()> {
        if out.len() != 65 {
            return Err(CurveError::InvalidLength);
        }
        let ge = self.inner.to_affine()?;
        let mut buf = [0u8; 65];
        ge.to_bytes_uncompressed(&mut buf)?;
        out.copy_from_slice(&buf);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generator_on_curve() {
        assert!(Affine::generator().is_on_curve());
    }

    #[test]
    fn roundtrip_compressed() {
        let g = Secp256k1Point::generator();
        let mut out = [0u8; 33];
        g.to_bytes_compressed(&mut out).unwrap();
        assert_eq!(out[0], 0x02);
        let g2 = Secp256k1Point::from_bytes(&out).unwrap();
        let mut out2 = [0u8; 33];
        g2.to_bytes_compressed(&mut out2).unwrap();
        assert_eq!(out, out2);
    }

    #[test]
    fn mul_by_one() {
        let g = Secp256k1Point::generator();
        let r = g.mul(&Scalar::one());
        let mut a = [0u8; 33];
        let mut b = [0u8; 33];
        g.to_bytes_compressed(&mut a).unwrap();
        r.to_bytes_compressed(&mut b).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn mul_by_two_equals_double() {
        let g = Secp256k1Point::generator();
        let d = g.double();
        let two = Scalar::one().add(&Scalar::one());
        let m = g.mul(&two);
        let mut a = [0u8; 33];
        let mut b = [0u8; 33];
        d.to_bytes_compressed(&mut a).unwrap();
        m.to_bytes_compressed(&mut b).unwrap();
        assert_eq!(a, b);
    }
}
