//! Scripted test device: queue responses, record requests.
//!
//! ```ignore
//! let mut dev = MockTransport::scripted(vec![ledger_pubkey_response()]);
//! let out = wallet.execute_get_address(&mut dev, &coin, &path)?;
//! assert_eq!(dev.seen().len(), 1);
//! ```

use crate::error::{Error, Result};
use crate::hw::transport::Transport;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

#[cfg(feature = "std")]
use std::time::Duration;

/// FIFO scripted transport for unit tests (no hardware, no USB).
#[derive(Debug)]
pub struct MockTransport {
    script: Vec<Result<Vec<u8>>>,
    seen: Vec<Vec<u8>>,
    cancelled: AtomicBool,
}

impl Clone for MockTransport {
    fn clone(&self) -> Self {
        Self {
            script: self.script.clone(),
            seen: self.seen.clone(),
            cancelled: AtomicBool::new(self.cancelled.load(Ordering::Relaxed)),
        }
    }
}

impl Default for MockTransport {
    fn default() -> Self {
        Self {
            script: Vec::new(),
            seen: Vec::new(),
            cancelled: AtomicBool::new(false),
        }
    }
}

impl MockTransport {
    /// Queue one response per expected `exchange` call.
    pub fn scripted(responses: Vec<Vec<u8>>) -> Self {
        Self {
            script: responses.into_iter().map(Ok).collect(),
            seen: Vec::new(),
            cancelled: AtomicBool::new(false),
        }
    }

    /// Queue one `Result` per expected call — script `Err(...)` to simulate
    /// wedged devices (`Error::TransportTimeout`), rejections, or drops
    /// (`Error::TransportDisconnected`) with zero hardware.
    pub fn scripted_results(script: Vec<Result<Vec<u8>>>) -> Self {
        Self {
            script,
            seen: Vec::new(),
            cancelled: AtomicBool::new(false),
        }
    }

    /// Single canned response.
    pub fn fixed(response: Vec<u8>) -> Self {
        Self::scripted(alloc::vec![response])
    }

    /// Requests received so far (assert APDU bytes in tests).
    pub fn seen(&self) -> &[Vec<u8>] {
        &self.seen
    }

    /// Number of remaining scripted responses.
    pub fn remaining(&self) -> usize {
        self.script.len()
    }
}

impl Transport for MockTransport {
    fn exchange(&mut self, msg: &[u8]) -> Result<Vec<u8>> {
        self.seen.push(msg.to_vec());
        // Cooperative cancellation: a prior `cancel()` poisons the device
        // (mirrors what a host-aborted backend reports as Cancelled).
        if self.cancelled.load(Ordering::Relaxed) {
            return Err(Error::TransportCancelled);
        }
        if self.script.is_empty() {
            return Err(Error::InvalidLength);
        }
        self.script.remove(0)
    }

    /// No clock in the mock: script `Err(Error::TransportTimeout)` to
    /// simulate a wedged device. The deadline argument is recorded nowhere
    /// — assert it at the call site if it matters.
    #[cfg(feature = "std")]
    fn exchange_timeout(&mut self, msg: &[u8], _timeout: Duration) -> Result<Vec<u8>> {
        self.exchange(msg)
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }
}
