//! Implements transcript/transcript logic (Halo2-Transcript, Blake2b).
//! Wire order is LE: points/scalars absorbed as LE bytes with 1-byte tags
//! (`0x01` point, `0x02` scalar); challenge squeezes with `0x00` tag into
//! 64 bytes reduced mod p (`fromBytes64`). Debug via `format!`;
//! Result style, no `assert!`.

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

use crate::zk::orchard_halo2::blake2b::Blake2b;
use crate::zk::orchard_halo2::error::{Halo2Error, Halo2Result};
use crate::zk::orchard_halo2::field::PallasFp;

pub const TRANSCRIPT_PERSONALIZATION: &[u8; 16] = b"Halo2-Transcript";
pub const TRANSCRIPT_TAG_CHALLENGE: u8 = 0;
pub const TRANSCRIPT_TAG_POINT: u8 = 1;
pub const TRANSCRIPT_TAG_SCALAR: u8 = 2;

pub struct TranscriptCore {
    state: Blake2b,
}

impl TranscriptCore {
    pub fn new() -> Halo2Result<Self> {
        Ok(Self {
            state: Blake2b::new(TRANSCRIPT_PERSONALIZATION)?,
        })
    }

    pub fn clean_state(&mut self) -> Halo2Result<()> {
        self.state = Blake2b::new(TRANSCRIPT_PERSONALIZATION)?;
        Ok(())
    }

    /// Squeeze challenge: absorb `0x00`, digest 64 bytes, reduce mod p (LE).
    pub fn squeeze_challenge(&mut self) -> Halo2Result<PallasFp> {
        self.state.update(&[TRANSCRIPT_TAG_CHALLENGE]);
        let digest = self.state.clone().finalize();
        let out = PallasFp::from_le_bytes64_wrapping(&digest)?;
        Ok(out)
    }

    /// Absorb a Vesta point (x,y LE). Identity → Err. No `assert!`.
    pub fn common_point(&mut self, x_le: &[u8; 32], y_le: &[u8; 32]) -> Halo2Result<()> {
        if x_le == &[0u8; 32] && y_le == &[0u8; 32] {
            return Err(Halo2Error::operation_failed(
                "transcript::common_point",
                "identity point not allowed",
            ));
        }
        let _ = crate::zk::orchard_halo2::field::VestaFq::from_le_array(x_le)?;
        let _ = crate::zk::orchard_halo2::field::VestaFq::from_le_array(y_le)?;
        self.state.update(&[TRANSCRIPT_TAG_POINT]);
        self.state.update(x_le);
        self.state.update(y_le);
        Ok(())
    }

    pub fn common_scalar(&mut self, scalar_le: &[u8; 32]) -> Halo2Result<()> {
        let _ = PallasFp::from_le_array(scalar_le)?;
        self.state.update(&[TRANSCRIPT_TAG_SCALAR]);
        self.state.update(scalar_le);
        Ok(())
    }

    #[cfg(feature = "alloc")]
    pub fn to_debug_string(&self) -> String {
        alloc::string::String::from("Transcript(Halo2-Transcript)")
    }
}

#[cfg(feature = "alloc")]
pub struct TranscriptWriter {
    core: TranscriptCore,
    buffer_le: Vec<u8>,
}

#[cfg(feature = "alloc")]
impl TranscriptWriter {
    pub fn new() -> Halo2Result<Self> {
        Ok(Self {
            core: TranscriptCore::new()?,
            buffer_le: Vec::new(),
        })
    }

    /// Write a compressed 32-byte LE point (`writePoint`). Decompresses
    /// for hashing (x,y LE); identity → Err. Buffer keeps 32 bytes.
    pub fn write_point(&mut self, compressed: &[u8; 32]) -> Halo2Result<()> {
        let aff = crate::zk::orchard_halo2::curve::VestaAffine::from_compressed(compressed)?;
        if aff.is_identity() {
            return Err(Halo2Error::operation_failed(
                "transcript::common_point",
                "identity point not allowed",
            ));
        }
        let (xb, yb, _) = aff.to_affine_le()?;
        self.core.common_point(&xb, &yb)?;
        self.buffer_le.extend_from_slice(compressed);
        Ok(())
    }

    pub fn write_scalar_le(&mut self, scalar_le: &[u8; 32]) -> Halo2Result<()> {
        self.core.common_scalar(scalar_le)?;
        self.buffer_le.extend_from_slice(scalar_le);
        Ok(())
    }

    /// Absorb-only scalar (`commonScalar`): no proof bytes emitted.
    pub fn absorb_scalar_le(&mut self, scalar_le: &[u8; 32]) -> Halo2Result<()> {
        self.core.common_scalar(scalar_le)
    }

    /// Absorb-only compressed point (`commonPoint`): no proof bytes.
    pub fn absorb_point(&mut self, compressed: &[u8; 32]) -> Halo2Result<()> {
        let aff = crate::zk::orchard_halo2::curve::VestaAffine::from_compressed(compressed)?;
        if aff.is_identity() {
            return Err(Halo2Error::operation_failed(
                "transcript::common_point",
                "identity point not allowed",
            ));
        }
        let (xb, yb, _) = aff.to_affine_le()?;
        self.core.common_point(&xb, &yb)
    }

    pub fn squeeze_challenge(&mut self) -> Halo2Result<PallasFp> {
        self.core.squeeze_challenge()
    }

    pub fn buffer_le(&self) -> &[u8] {
        &self.buffer_le
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buffer_le
    }

    pub fn to_debug_string(&self) -> String {
        alloc::format!("TranscriptWriter(bytes: {})", self.buffer_le.len())
    }
}

#[cfg(feature = "alloc")]
pub struct TranscriptReader<'a> {
    core: TranscriptCore,
    bytes_le: &'a [u8],
    offset: usize,
}

#[cfg(feature = "alloc")]
impl<'a> TranscriptReader<'a> {
    pub fn new(bytes_le: &'a [u8]) -> Halo2Result<Self> {
        Ok(Self {
            core: TranscriptCore::new()?,
            bytes_le,
            offset: 0,
        })
    }

    /// Number of proof bytes read so far.
    ///
    /// Used by the verifier to check that a proof was consumed exactly, which
    /// validates its length for any number of actions in the batch.
    pub fn consumed(&self) -> usize {
        self.offset
    }

    fn read_32_le(&mut self) -> Halo2Result<[u8; 32]> {
        let end = self
            .offset
            .checked_add(32)
            .ok_or_else(|| Halo2Error::operation_failed("transcript::read", "offset overflow"))?;
        if end > self.bytes_le.len() {
            return Err(Halo2Error::operation_failed(
                "transcript::read",
                "out of range",
            ));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.bytes_le[self.offset..end]);
        self.offset = end;
        Ok(out)
    }

    pub fn read_point(&mut self) -> Halo2Result<[u8; 32]> {
        let c = self.read_32_le()?;
        let aff = crate::zk::orchard_halo2::curve::VestaAffine::from_compressed(&c)?;
        if aff.is_identity() {
            return Err(Halo2Error::operation_failed(
                "transcript::common_point",
                "identity point not allowed",
            ));
        }
        let (xb, yb, _) = aff.to_affine_le()?;
        self.core.common_point(&xb, &yb)?;
        Ok(c)
    }

    pub fn read_scalar_le(&mut self) -> Halo2Result<[u8; 32]> {
        let s = self.read_32_le()?;
        self.core.common_scalar(&s)?;
        Ok(s)
    }

    /// Absorb-only (`commonScalar`/`commonPoint` without reading).
    pub fn absorb_scalar_le(&mut self, scalar_le: &[u8; 32]) -> Halo2Result<()> {
        self.core.common_scalar(scalar_le)
    }

    pub fn absorb_point_affine(
        &mut self,
        point: &crate::zk::orchard_halo2::curve::VestaAffine,
    ) -> Halo2Result<()> {
        if point.is_identity() {
            return Err(Halo2Error::operation_failed(
                "transcript::common_point",
                "identity point not allowed",
            ));
        }
        let (xb, yb, _) = point.to_affine_le()?;
        self.core.common_point(&xb, &yb)
    }

    /// Alias matching verifier call sites.
    pub fn common_point_affine(
        &mut self,
        point: &crate::zk::orchard_halo2::curve::VestaAffine,
    ) -> Halo2Result<()> {
        self.absorb_point_affine(point)
    }

    pub fn squeeze_challenge(&mut self) -> Halo2Result<PallasFp> {
        self.core.squeeze_challenge()
    }

    pub fn to_debug_string(&self) -> String {
        alloc::format!(
            "TranscriptReader(offset: {}/{})",
            self.offset,
            self.bytes_le.len()
        )
    }
}
