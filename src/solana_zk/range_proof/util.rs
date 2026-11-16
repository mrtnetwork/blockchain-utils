//! Bulletproofs scalar/vector utilities (zero-dep port).
//!
//! /// Byte-compatible port of
//! `zk-sdk/src/range_proof/util.rs`: vector polynomials, inner products,
//! power sums over our [`crate::curve::ed25519::Scalar`].

use crate::curve::ed25519::Scalar;

/// Degree-1 vector polynomial `a + b*x` (Bulletproofs `l`/`r`).
pub struct VecPoly1(pub Vec<Scalar>, pub Vec<Scalar>);

impl VecPoly1 {
    /// Zero polynomial of the given size.
    pub fn zero(n: usize) -> Self {
        VecPoly1(vec![Scalar::zero(); n], vec![Scalar::zero(); n])
    }

    /// Inner product `<l(x), r(x)>` as a degree-2 polynomial
    /// (Karatsuba: `t_0`, `t_2` direct, `t_1` via `(l0+l1)·(r0+r1)`).
    pub fn inner_product(&self, rhs: &VecPoly1) -> Option<Poly2> {
        let t0 = inner_product(&self.0, &rhs.0)?;
        let t2 = inner_product(&self.1, &rhs.1)?;
        let l_sum = add_vec(&self.0, &self.1);
        let r_sum = add_vec(&rhs.0, &rhs.1);
        let t1 = inner_product(&l_sum, &r_sum)?
            .add(&t0.neg())
            .add(&t2.neg());
        Some(Poly2(t0, t1, t2))
    }

    /// Evaluate the vector polynomial at `x`.
    pub fn eval(&self, x: &Scalar) -> Vec<Scalar> {
        let mut out = vec![Scalar::zero(); self.0.len()];
        for (o, (a, b)) in out.iter_mut().zip(self.0.iter().zip(self.1.iter())) {
            *o = a.add(&b.mul(x));
        }
        out
    }
}

/// Degree-2 scalar polynomial `a + b*x + c*x^2`.
pub struct Poly2(pub Scalar, pub Scalar, pub Scalar);

impl Poly2 {
    /// Evaluate with Horner's method.
    pub fn eval(&self, x: &Scalar) -> Scalar {
        self.0.add(&x.mul(&self.1.add(&x.mul(&self.2))))
    }
}

/// Powers-of-`x` iterator (`1, x, x^2, ...`).
pub struct ScalarExp {
    /// Base.
    x: Scalar,
    /// Next power.
    next: Scalar,
}

impl Iterator for ScalarExp {
    type Item = Scalar;
    /// Yield the next power.
    fn next(&mut self) -> Option<Scalar> {
        let e = self.next;
        self.next = self.next.mul(&self.x);
        Some(e)
    }
}

/// Powers of `x` starting at `x^0 = 1`.
pub fn exp_iter(x: Scalar) -> ScalarExp {
    ScalarExp {
        x,
        next: Scalar::one(),
    }
}

/// Component-wise vector sum (panics on length mismatch).
pub fn add_vec(a: &[Scalar], b: &[Scalar]) -> Vec<Scalar> {
    assert_eq!(a.len(), b.len(), "vector length mismatch");
    a.iter().zip(b.iter()).map(|(x, y)| x.add(y)).collect()
}

/// First 32 bytes as an array (panics if shorter).
pub fn read32(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&data[..32]);
    out
}

/// Inner product `<a, b>` (`None` on length mismatch).
pub fn inner_product(a: &[Scalar], b: &[Scalar]) -> Option<Scalar> {
    if a.len() != b.len() {
        return None;
    }
    let mut out = Scalar::zero();
    for i in 0..a.len() {
        out = out.add(&a[i].mul(&b[i]));
    }
    Some(out)
}

/// `1 + x + ... + x^(n-1)` (fast doubling for powers of two).
pub fn sum_of_powers(x: &Scalar, n: usize) -> Scalar {
    if !n.is_power_of_two() {
        return exp_iter(*x).take(n).fold(Scalar::zero(), |s, p| s.add(&p));
    }
    if n == 0 {
        return Scalar::zero();
    }
    if n == 1 {
        return Scalar::one();
    }
    let mut m = n;
    let mut result = Scalar::one().add(x);
    let mut factor = *x;
    while m > 2 {
        factor = factor.mul(&factor);
        result = result.add(&factor.mul(&result));
        m /= 2;
    }
    result
}

/// Scalar from a u64 (always < L).
pub fn scalar_u64(v: u64) -> Scalar {
    let mut b = [0u8; 32];
    b[..8].copy_from_slice(&v.to_le_bytes());
    Scalar::from_bytes_mod_order(&b)
}

/// `a - b` for scalars.
pub fn scalar_sub(a: &Scalar, b: &Scalar) -> Scalar {
    a.add(&b.neg())
}
