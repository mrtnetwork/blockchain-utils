//! Merlin transcript construction (STROBE-based).
//!
//! Independent implementation of the Merlin transcript API used by
//! Schnorrkel / sr25519. Protocol description:
//! <https://merlin.cool/> — built on STROBE AD / meta-AD / PRF.
//!
//! Message framing (compatible with the public Merlin rules):
//! ```text
//! append_message(label, msg):
//!   meta-AD( label || LE32(len(msg)) )
//!   AD( msg )
//! challenge_bytes(label, n):
//!   meta-AD( label || LE32(n) )
//!   PRF( n )
//! ```

use crate::strobe::Strobe;

/// Merlin transcript over STROBE128.
#[derive(Clone)]
pub struct Transcript {
    strobe: Strobe,
}

impl Transcript {
    /// Start a new transcript with domain-separation label.
    pub fn new(label: &[u8]) -> Self {
        let strobe = Strobe::new_128(b"Merlin v1.0");
        // Merlin: meta-AD("dom-sep"), AD(label)
        // Equivalent framing used by Schnorrkel: additional_data("dom-sep", label)
        let mut t = Self { strobe };
        t.append_message(b"dom-sep", label);
        t
    }

    /// Append labeled message bytes.
    pub fn append_message(&mut self, label: &[u8], message: &[u8]) {
        let mut meta = alloc::vec::Vec::with_capacity(label.len() + 4);
        meta.extend_from_slice(label);
        let len = (message.len() as u32).to_le_bytes();
        meta.extend_from_slice(&len);
        self.strobe.ad(true, &meta);
        self.strobe.ad(false, message);
    }

    /// Extract `out.len()` challenge bytes under `label`.
    pub fn challenge_bytes(&mut self, label: &[u8], out: &mut [u8]) {
        let mut meta = alloc::vec::Vec::with_capacity(label.len() + 4);
        meta.extend_from_slice(label);
        let len = (out.len() as u32).to_le_bytes();
        meta.extend_from_slice(&len);
        self.strobe.ad(true, &meta);
        let prf = self.strobe.prf(out.len());
        out.copy_from_slice(&prf);
    }

    /// 64-byte challenge reduced to a scalar (wide reduction).
    pub fn challenge_scalar(&mut self, label: &[u8]) -> crate::curve::ed25519::Scalar {
        let mut wide = [0u8; 64];
        self.challenge_bytes(label, &mut wide);
        crate::curve::ed25519::Scalar::from_bytes_wide(&wide)
    }

    /// Clone transcript state (for verify vs sign parallelism).
    pub fn fork(&self) -> Self {
        self.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transcript_deterministic() {
        let mut t = Transcript::new(b"SigningContext");
        t.append_message(b"", b"substrate");
        t.append_message(b"sign-bytes", b"hello");
        let mut a = [0u8; 32];
        t.challenge_bytes(b"sign:c", &mut a);

        let mut t2 = Transcript::new(b"SigningContext");
        t2.append_message(b"", b"substrate");
        t2.append_message(b"sign-bytes", b"hello");
        let mut b = [0u8; 32];
        t2.challenge_bytes(b"sign:c", &mut b);
        assert_eq!(a, b);
    }
}
