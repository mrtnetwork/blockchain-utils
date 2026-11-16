//! Fixed-base 3-bit window tables (`generateCircuitGenerator`).
//!
//! Layout: 84 windows × 8 Edwards points `(u,v)`:
//! window `i` holds `{ O, B, 2B, …, 7B }` where `B = 8^i · G`.

use crate::curve::jubjub::{Fe, JubJubPoint};
use crate::curve::traits::CurvePoint;
use alloc::vec::Vec;

/// One window entry: affine Edwards `(u, v)`.
#[derive(Clone, Copy, Debug)]
pub struct WindowPoint {
    pub u: Fe,
    pub v: Fe,
}

impl WindowPoint {
    pub fn identity() -> Self {
        Self {
            u: Fe::zero(),
            v: Fe::one(),
        }
    }

    pub fn from_point(p: &JubJubPoint) -> Self {
        let (u, v) = p.affine_uv().expect("affine");
        Self { u, v }
    }

    pub fn to_point(&self) -> JubJubPoint {
        JubJubPoint::from_affine_coords(self.u, self.v)
    }
}

/// 84 × 8 fixed-base window table for circuit / native fixed-base mul.
pub type CircuitWindows = Vec<[WindowPoint; 8]>;

/// Cached fixed-base tables for the official Sapling generators (Bellman-style).
/// Regenerating 84×7 Edwards adds per `fixed_base_mul` is pure waste on the hot path.
#[cfg(feature = "std")]
mod window_cache {
    use super::*;
    use crate::zk::sapling::constants::{
        note_commitment_randomness_generator, nullifier_position_generator,
        proof_generation_key_generator, spending_key_generator,
        value_commitment_randomness_generator, value_commitment_value_generator,
    };
    use std::sync::OnceLock;

    static SPEND_KEY: OnceLock<CircuitWindows> = OnceLock::new();
    static PROOF_GEN: OnceLock<CircuitWindows> = OnceLock::new();
    static VC_VALUE: OnceLock<CircuitWindows> = OnceLock::new();
    static VC_RAND: OnceLock<CircuitWindows> = OnceLock::new();
    static NOTE_RCM: OnceLock<CircuitWindows> = OnceLock::new();
    static NF_POS: OnceLock<CircuitWindows> = OnceLock::new();

    fn point_key(p: &JubJubPoint) -> [u8; 32] {
        let mut b = [0u8; 32];
        let _ = p.to_bytes_compressed(&mut b);
        b
    }

    pub fn get(base: &JubJubPoint) -> Option<&'static CircuitWindows> {
        let k = point_key(base);
        macro_rules! check {
            ($gen:expr, $slot:expr) => {{
                let g = $gen();
                let mut gb = [0u8; 32];
                let _ = g.to_bytes_compressed(&mut gb);
                if k == gb {
                    return Some($slot.get_or_init(|| generate_circuit_windows(&g)));
                }
            }};
        }
        check!(spending_key_generator, SPEND_KEY);
        check!(proof_generation_key_generator, PROOF_GEN);
        check!(value_commitment_value_generator, VC_VALUE);
        check!(value_commitment_randomness_generator, VC_RAND);
        check!(note_commitment_randomness_generator, NOTE_RCM);
        check!(nullifier_position_generator, NF_POS);
        None
    }
}

/// Return window table for `base`, using a process-wide cache for Sapling generators.
pub fn windows_for_base(base: &JubJubPoint) -> CircuitWindows {
    #[cfg(feature = "std")]
    {
        if let Some(w) = window_cache::get(base) {
            return w.clone();
        }
    }
    generate_circuit_windows(base)
}

/// Borrow cached windows when available (avoids clone on the circuit hot path).
#[cfg(feature = "std")]
pub fn windows_for_base_ref(base: &JubJubPoint) -> Option<&'static CircuitWindows> {
    window_cache::get(base)
}

/// Build windows matching the reference implementation.generateCircuitGenerator`.
///
/// Native points stay projective through the 84×7 adds; a SINGLE batch
/// inversion converts all 588 at the end (was: 672 per-point inversions —
/// the dominant cost of spend synthesis).
pub fn generate_circuit_windows(base: &JubJubPoint) -> CircuitWindows {
    const WINDOWS: usize = 84;
    const PER_WINDOW: usize = 7;
    let mut pts = Vec::with_capacity(WINDOWS * PER_WINDOW);
    let mut gen = *base;
    for _ in 0..WINDOWS {
        let mut g = gen;
        // coeffs[1..8] = gen, 2gen, …, 7gen
        for _ in 0..PER_WINDOW {
            pts.push(g);
            g = g.add(&gen);
        }
        // next window base = 8 · gen
        gen = g;
    }
    let affines = JubJubPoint::batch_to_affine(&pts);
    let mut windows = Vec::with_capacity(WINDOWS);
    for w in affines.as_chunks::<PER_WINDOW>().0 {
        let mut coeffs = [WindowPoint::identity(); 8];
        for (i, (u, v)) in w.iter().enumerate() {
            coeffs[i + 1] = WindowPoint { u: *u, v: *v };
        }
        windows.push(coeffs);
    }
    windows
}

/// Fixed-base mul from LE bits with full 84 windows (pad bits with false).
pub fn fixed_base_mul_le_bits(base: &JubJubPoint, bits_le: &[bool]) -> JubJubPoint {
    let windows = windows_for_base(base);
    let mut bits = bits_le.to_vec();
    // pad to 252 bits (84 windows × 3)
    while bits.len() < 252 {
        bits.push(false);
    }
    bits.truncate(252);
    let mut result: Option<JubJubPoint> = None;
    for (w, window) in windows.iter().enumerate() {
        let i = w * 3;
        let a = bits[i];
        let b = bits[i + 1];
        let c = bits[i + 2];
        let idx = (a as usize) | ((b as usize) << 1) | ((c as usize) << 2);
        let p = window[idx].to_point();
        result = Some(match result {
            None => p,
            Some(r) => r.add(&p),
        });
    }
    result.unwrap_or_else(JubJubPoint::identity)
}

/// LE bits of a u64 (64 bits).
pub fn u64_to_bits_le(v: u64) -> [bool; 64] {
    let mut bits = [false; 64];
    for (i, slot) in bits.iter_mut().enumerate() {
        *slot = ((v >> i) & 1) == 1;
    }
    bits
}

/// LE bits of a 32-byte scalar (256 bits; circuit uses Fr capacity often 255).
pub fn bytes_le_to_bits(bytes: &[u8]) -> alloc::vec::Vec<bool> {
    let mut bits = alloc::vec::Vec::with_capacity(bytes.len() * 8);
    for &b in bytes {
        for i in 0..8 {
            bits.push(((b >> i) & 1) == 1);
        }
    }
    bits
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::jubjub::Scalar;
    use crate::zk::sapling::constants::{spending_key_generator, value_commitment_value_generator};

    fn scalar_from_u64(v: u64) -> Scalar {
        let mut le = [0u8; 32];
        le[..8].copy_from_slice(&v.to_le_bytes());
        Scalar::from_bytes_le(&le).expect("scalar")
    }

    #[test]
    fn window_mul_matches_scalar_mul_small() {
        let base = value_commitment_value_generator();
        let v = 10u64;
        let bits = u64_to_bits_le(v);
        let via_win = fixed_base_mul_le_bits(&base, &bits);
        let via_sc = base.mul(&scalar_from_u64(v));
        let (u1, v1) = via_win.affine_uv().unwrap();
        let (u2, v2) = via_sc.affine_uv().unwrap();
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        u1.to_bytes_be(&mut a);
        u2.to_bytes_be(&mut b);
        assert_eq!(a, b);
        v1.to_bytes_be(&mut a);
        v2.to_bytes_be(&mut b);
        assert_eq!(a, b);
    }

    #[test]
    fn window_table_size() {
        let w = generate_circuit_windows(&spending_key_generator());
        assert_eq!(w.len(), 84);
        // identity first entry of each window
        let mut ube = [0u8; 32];
        w[0][0].u.to_bytes_be(&mut ube);
        assert_eq!(ube, [0u8; 32]);
        let mut vbe = [0u8; 32];
        w[0][0].v.to_bytes_be(&mut vbe);
        // v of identity window entry is one (BE last byte).
        assert_eq!(vbe[31], 1);
    }
}
