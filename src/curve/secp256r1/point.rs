//! NIST P-256 points (affine + Jacobian) and constant-time windowed scalar mul.

use super::fe::{Fe, B_BE};
use super::scalar::Scalar;
use crate::curve::error::{CurveError, CurveResult};
use crate::curve::traits::{CurvePoint, FieldElement};

#[derive(Clone, Copy, Debug)]
pub struct Affine {
    pub x: Fe,
    pub y: Fe,
    pub infinity: u8,
}

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

    pub fn generator() -> Self {
        let gx = Fe::from_bytes_be(&[
            0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
            0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45,
            0xd8, 0x98, 0xc2, 0x96,
        ])
        .expect("Gx");
        let gy = Fe::from_bytes_be(&[
            0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f,
            0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68,
            0x37, 0xbf, 0x51, 0xf5,
        ])
        .expect("Gy");
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

    pub fn is_on_curve(&self) -> bool {
        if self.is_infinity() {
            return true;
        }
        // y² = x³ − 3x + b
        let y2 = self.y.square();
        let x2 = self.x.square();
        let x3 = x2.mul(&self.x);
        let three_x = self.x.add(&self.x).add(&self.x);
        let b = Fe::from_bytes_be(&B_BE).unwrap_or(Fe::zero());
        let rhs = x3.sub(&three_x).add(&b);
        y2.ct_eq(&rhs) == 1
    }

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

    /// Double (a = −3). Always evaluate; CT-select identity on infinity.
    pub fn double(&self) -> Self {
        // Jacobian double for a = -3:
        // delta = Z²; gamma = Y²; beta = X*gamma
        // alpha = 3*(X-delta)*(X+delta)
        // X3 = alpha² - 8*beta
        // Z3 = (Y+Z)² - gamma - delta
        // Y3 = alpha*(4*beta - X3) - 8*gamma²
        let delta = self.z.square();
        let gamma = self.y.square();
        let beta = self.x.mul(&gamma);
        let xmd = self.x.sub(&delta);
        let xpd = self.x.add(&delta);
        let alpha = xmd.mul(&xpd);
        let alpha = alpha.add(&alpha).add(&alpha); // 3*(X-δ)*(X+δ)
        let alpha2 = alpha.square();
        let eight_beta = {
            let t = beta.add(&beta);
            let t = t.add(&t);
            t.add(&t)
        };
        let x3 = alpha2.sub(&eight_beta);
        let yz = self.y.add(&self.z).square();
        let z3 = yz.sub(&gamma).sub(&delta);
        let four_beta = beta.add(&beta).add(&beta).add(&beta);
        let gamma2 = gamma.square();
        let eight_g2 = {
            let t = gamma2.add(&gamma2);
            let t = t.add(&t);
            t.add(&t)
        };
        let y3 = alpha.mul(&four_beta.sub(&x3)).sub(&eight_g2);
        let doubled = Self {
            x: x3,
            y: y3,
            z: z3,
            infinity: 0,
        };
        Self::ct_select(self.infinity, &Self::infinity(), &doubled)
    }

    /// Jacobian add — constant-time exceptional cases (∞, equal, opposite).
    pub fn add(&self, other: &Self) -> Self {
        let z1z1 = self.z.square();
        let z2z2 = other.z.square();
        let u1 = self.x.mul(&z2z2);
        let u2 = other.x.mul(&z1z1);
        let s1 = self.y.mul(&other.z).mul(&z2z2);
        let s2 = other.y.mul(&self.z).mul(&z1z1);
        let h = u2.sub(&u1);
        let r = s2.sub(&s1);
        let h_zero = h.ct_eq(&Fe::zero());
        let r_zero = r.ct_eq(&Fe::zero());
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
        let both_zero = h_zero & r_zero;
        let only_h = h_zero & (1 ^ r_zero);
        let mut out = Self::ct_select(both_zero, &doubled, &summed);
        out = Self::ct_select(only_h, &Self::infinity(), &out);
        out = Self::ct_select(self.infinity, other, &out);
        out = Self::ct_select(other.infinity & (self.infinity ^ 1), self, &out);
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
    let three_x = x.add(x).add(x);
    let b = Fe::from_bytes_be(&B_BE).map_err(|_| CurveError::InvalidPoint)?;
    let y2 = x3.sub(&three_x).add(&b);
    let y = sqrt_mod_p(&y2)?;
    let mut yn = y;
    yn.normalize();
    if (yn.is_odd() == 1) != y_odd {
        return Ok(y.negate());
    }
    Ok(y)
}

fn sqrt_mod_p(a: &Fe) -> CurveResult<Fe> {
    // p ≡ 3 (mod 4): sqrt = a^((p+1)/4)
    let exp: [u8; 32] = [
        0x3f, 0xff, 0xff, 0xff, 0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];
    let mut result = Fe::one();
    let base = *a;
    for byte in exp.iter() {
        for bit in (0..8).rev() {
            result = result.square();
            let bit_set = (byte >> bit) & 1;
            let mulled = result.mul(&base);
            result = Fe::ct_select(bit_set, &mulled, &result);
        }
    }
    if result.square().ct_eq(a) != 1 {
        return Err(CurveError::InvalidPoint);
    }
    Ok(result)
}

#[derive(Clone, Copy, Debug)]
pub struct Secp256r1Point {
    inner: Jacobian,
}

impl Secp256r1Point {
    pub fn generator() -> Self {
        Self {
            inner: Affine::generator().to_jacobian(),
        }
    }
}

impl CurvePoint for Secp256r1Point {
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
        let g = Secp256r1Point::generator();
        let mut out = [0u8; 33];
        g.to_bytes_compressed(&mut out).unwrap();
        assert!(out[0] == 0x02 || out[0] == 0x03);
        let g2 = Secp256r1Point::from_bytes(&out).unwrap();
        let mut out2 = [0u8; 33];
        g2.to_bytes_compressed(&mut out2).unwrap();
        assert_eq!(out, out2);
    }

    #[test]
    fn mul_by_one() {
        let g = Secp256r1Point::generator();
        let r = g.mul(&Scalar::one());
        let mut a = [0u8; 33];
        let mut b = [0u8; 33];
        g.to_bytes_compressed(&mut a).unwrap();
        r.to_bytes_compressed(&mut b).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn mul_by_two_equals_double() {
        let g = Secp256r1Point::generator();
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
