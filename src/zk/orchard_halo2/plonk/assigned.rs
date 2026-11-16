//! Implements plonk/assigned logic (`Assigned`: Zero/Trivial/Rational).
//! Exact rational arithmetic preserved. Debug via `format!` (BE `0x` hex
//! for fields); Result style, no `assert!`.

#[cfg(feature = "alloc")]
use alloc::string::String;

use crate::zk::orchard_halo2::error::Halo2Result;
use crate::zk::orchard_halo2::field::PallasFp;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Assigned {
    Zero,
    Trivial(PallasFp),
    Rational { a: PallasFp, b: PallasFp },
}

impl Assigned {
    pub fn zero() -> Self {
        Self::Zero
    }

    pub fn trivial(v: PallasFp) -> Self {
        Self::Trivial(v)
    }

    pub fn from_le_bytes(b: &[u8]) -> Halo2Result<Self> {
        Ok(Self::Trivial(PallasFp::from_le_bytes_checked(b)?))
    }

    pub fn neg(&self) -> Self {
        match *self {
            Self::Zero => Self::Zero,
            Self::Trivial(v) => Self::Trivial(v.neg()),
            Self::Rational { a, b } => Self::Rational { a: a.neg(), b },
        }
    }

    pub fn try_add(&self, rhs: &Self) -> Self {
        match (*self, *rhs) {
            (Self::Zero, _) => *rhs,
            (_, Self::Zero) => *self,
            (Self::Trivial(l), Self::Trivial(r)) => Self::Trivial(l.add_vartime(&r)),
            (Self::Trivial(l), Self::Rational { a, b }) => Self::Rational {
                a: a.add_vartime(&b.mul_vartime(&l)),
                b,
            },
            (Self::Rational { a, b }, Self::Trivial(r)) => Self::Rational {
                a: a.add_vartime(&b.mul_vartime(&r)),
                b,
            },
            (Self::Rational { a: an, b: ad }, Self::Rational { a: bn, b: bd }) => Self::Rational {
                a: an.mul_vartime(&bd).add_vartime(&ad.mul_vartime(&bn)),
                b: ad.mul_vartime(&bd),
            },
        }
    }

    pub fn try_sub(&self, rhs: &Self) -> Self {
        self.try_add(&rhs.neg())
    }

    pub fn try_mul(&self, rhs: &Self) -> Self {
        match (*self, *rhs) {
            (Self::Zero, _) | (_, Self::Zero) => Self::Zero,
            (Self::Trivial(l), Self::Trivial(r)) => Self::Trivial(l.mul_vartime(&r)),
            (Self::Trivial(l), Self::Rational { a, b }) => Self::Rational {
                a: a.mul_vartime(&l),
                b,
            },
            (Self::Rational { a, b }, Self::Trivial(r)) => Self::Rational {
                a: a.mul_vartime(&r),
                b,
            },
            (Self::Rational { a: an, b: ad }, Self::Rational { a: bn, b: bd }) => Self::Rational {
                a: an.mul_vartime(&bn),
                b: ad.mul_vartime(&bd),
            },
        }
    }

    pub fn scale_fp(&self, rhs: PallasFp) -> Self {
        self.try_mul(&Self::Trivial(rhs))
    }

    pub fn numerator(&self) -> PallasFp {
        match *self {
            Self::Zero => PallasFp::zero(),
            Self::Trivial(v) => v,
            Self::Rational { a, .. } => a,
        }
    }

    pub fn denominator(&self) -> Option<PallasFp> {
        match *self {
            Self::Rational { b, .. } => Some(b),
            _ => None,
        }
    }

    pub fn is_zero(&self) -> bool {
        match *self {
            Self::Zero => true,
            Self::Trivial(v) => v.is_zero(),
            Self::Rational { a, b } => a.is_zero() || b.is_zero(),
        }
    }

    pub fn double(&self) -> Self {
        match *self {
            Self::Zero => Self::Zero,
            Self::Trivial(v) => Self::Trivial(v.double()),
            Self::Rational { a, b } => Self::Rational { a: a.double(), b },
        }
    }

    pub fn square(&self) -> Self {
        match *self {
            Self::Zero => Self::Zero,
            Self::Trivial(v) => Self::Trivial(v.square_vartime()),
            Self::Rational { a, b } => Self::Rational {
                a: a.square_vartime(),
                b: b.square_vartime(),
            },
        }
    }

    pub fn invert(&self) -> Self {
        match *self {
            Self::Zero => Self::Zero,
            Self::Trivial(v) => Self::Rational {
                a: PallasFp::one(),
                b: v,
            },
            Self::Rational { a, b } => Self::Rational { a: b, b: a },
        }
    }

    /// Direct evaluation (division by zero → zero, as in reference).
    pub fn evaluate(&self) -> PallasFp {
        match *self {
            Self::Zero => PallasFp::zero(),
            Self::Trivial(v) => v,
            Self::Rational { a, b } => {
                if b == PallasFp::one() {
                    a
                } else {
                    match b.invert() {
                        Ok(inv) => a.mul_vartime(&inv),
                        Err(_) => PallasFp::zero(),
                    }
                }
            }
        }
    }

    /// Cross-multiplied equality (`==`).
    pub fn assigned_eq(&self, o: &Self) -> bool {
        match (*self, *o) {
            (Self::Zero, Self::Zero) => true,
            (Self::Zero, x) | (x, Self::Zero) => x.is_zero(),
            (Self::Rational { b: d, .. }, x) if d.is_zero() => x.is_zero(),
            (x, Self::Rational { b: d, .. }) if d.is_zero() => x.is_zero(),
            (Self::Trivial(l), Self::Trivial(r)) => l == r,
            (Self::Trivial(x), Self::Rational { a: n, b: d }) => x.mul_vartime(&d) == n,
            (Self::Rational { a: n, b: d }, Self::Trivial(x)) => x.mul_vartime(&d) == n,
            (Self::Rational { a: an, b: ad }, Self::Rational { a: bn, b: bd }) => {
                an.mul_vartime(&bd) == ad.mul_vartime(&bn)
            }
        }
    }

    #[cfg(feature = "alloc")]
    pub fn to_debug_string(&self) -> String {
        match self {
            Self::Zero => alloc::string::String::from("Zero()"),
            Self::Trivial(v) => alloc::format!("Trivial({})", v.to_debug_string()),
            Self::Rational { a, b } => {
                alloc::format!("Rational({}, {})", a.to_debug_string(), b.to_debug_string())
            }
        }
    }
}

impl core::ops::Add for Assigned {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        self.try_add(&rhs)
    }
}

impl core::ops::Sub for Assigned {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        self.try_sub(&rhs)
    }
}

impl core::ops::Neg for Assigned {
    type Output = Self;
    fn neg(self) -> Self {
        // Borrow is load-bearing: `(&self).neg()` selects the inherent
        // `Assigned::neg(&self)`; bare `self.neg()` would recurse into this
        // trait method (`unconditional_recursion`).
        #[allow(clippy::needless_borrow)]
        (&self).neg()
    }
}

/// Build from field (`Assigned.from`).
pub fn assigned_from_fp(v: PallasFp) -> Assigned {
    Assigned::Trivial(v)
}

pub fn assigned_from_le(b: &[u8]) -> Halo2Result<Assigned> {
    Assigned::from_le_bytes(b)
}
