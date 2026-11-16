//! NTT over ℤ_q[x]/(x^256+1) for ML-DSA (FIPS 204).

use super::field;
use super::params::N;
use super::zetas::ZETAS;

const F: i32 = 8_347_681; // 256^{-1} mod q

pub fn ntt(p: &mut [i32; N]) {
    let mut k = 0usize;
    let mut len = 128usize;
    while len >= 1 {
        let mut start = 0usize;
        while start < N {
            k += 1;
            let zeta = ZETAS[k] as i32;
            for j in start..start + len {
                let t = field::mul(zeta, p[j + len]);
                p[j + len] = field::sub(p[j], t);
                p[j] = field::add(p[j], t);
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

pub fn inv_ntt(p: &mut [i32; N]) {
    let mut k = 256usize;
    let mut len = 1usize;
    while len <= 128 {
        let mut start = 0usize;
        while start < N {
            k -= 1;
            let zeta = ZETAS[k] as i32;
            for j in start..start + len {
                let t = p[j];
                p[j] = field::add(t, p[j + len]);
                p[j + len] = field::mul(zeta, field::sub(p[j + len], t));
            }
            start += 2 * len;
        }
        len <<= 1;
    }
    for c in p.iter_mut() {
        *c = field::mul(*c, F);
    }
}

pub fn multiply_ntt(a: &mut [i32; N], b: &[i32; N]) {
    for i in 0..N {
        a[i] = field::mul(a[i], b[i]);
    }
}
