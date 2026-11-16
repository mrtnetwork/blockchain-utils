//! FIPS 204 parameter sets: ML-DSA-44 / 65 / 87.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    pub k: usize,
    pub l: usize,
    pub eta: i32,
    pub tau: usize,
    pub beta: i32,
    pub gamma1: i32,
    pub gamma2: i32,
    pub omega: usize,
    pub d: u32,
    pub lambda: usize,
}

pub const N: usize = 256;
pub const Q: i32 = 8_380_417;

impl Params {
    pub const fn mldsa44() -> Self {
        Self {
            k: 4,
            l: 4,
            eta: 2,
            tau: 39,
            beta: 78,
            gamma1: 1 << 17,
            gamma2: (Q - 1) / 88,
            omega: 80,
            d: 13,
            lambda: 128,
        }
    }
    pub const fn mldsa65() -> Self {
        Self {
            k: 6,
            l: 5,
            eta: 4,
            tau: 49,
            beta: 196,
            gamma1: 1 << 19,
            gamma2: (Q - 1) / 32,
            omega: 55,
            d: 13,
            lambda: 192,
        }
    }
    pub const fn mldsa87() -> Self {
        Self {
            k: 8,
            l: 7,
            eta: 2,
            tau: 60,
            beta: 120,
            gamma1: 1 << 19,
            gamma2: (Q - 1) / 32,
            omega: 75,
            d: 13,
            lambda: 256,
        }
    }

    pub fn poly_eta_packed_bytes(&self) -> usize {
        let bits = if self.eta == 2 { 3 } else { 4 };
        (N * bits) / 8
    }
    pub fn poly_z_packed_bytes(&self) -> usize {
        if self.gamma1 == 1 << 17 {
            576
        } else {
            640
        }
    }
    pub fn public_key_bytes(&self) -> usize {
        32 + self.k * 320
    }
    pub fn secret_key_bytes(&self) -> usize {
        128 + self.l * self.poly_eta_packed_bytes()
            + self.k * self.poly_eta_packed_bytes()
            + self.k * 416
    }
    pub fn signature_bytes(&self) -> usize {
        self.lambda / 4 + self.l * self.poly_z_packed_bytes() + self.omega + self.k
    }
    pub fn c_tilde_bytes(&self) -> usize {
        self.lambda / 4
    }
}
