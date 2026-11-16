//! Live-device transports for emulators and tests.
//!
//! This module needs `std` (sockets) and is NOT part of the zero-dep core:
//! gate with `--features hw` (default builds include `std`, so it is there).
//! Production USB/BLE/NFC transports live in the app (`ffi`/`wasm` side)
//! and implement the same [`Transport`] trait.
//!
//! [`TcpTransport`] speaks ledgercomm-style APDU-over-TCP, which is what
//! [Speculos](https://github.com/LedgerHQ/speculos) (Ledger Nano S+/X/Flex/
//! Stax emulator) serves: request `u32 BE len || apdu`, response
//! `u32 BE len || apdu-response`. All I/O errors and timeouts become
//! [`Error`], never a panic — a dead emulator looks exactly like a dead
//! device to the caller.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::error::{Error, Result};
use crate::hw::transport::Transport;

/// Max APDU response accepted (64 KiB). Caps memory on garbage input.
pub const MAX_APDU_LEN: usize = 64 * 1024;

/// TCP APDU transport (Speculos / custom test servers).
#[derive(Debug)]
pub struct TcpTransport {
    stream: TcpStream,
}

impl TcpTransport {
    /// Connect with a total per-operation timeout.
    pub fn connect<A: ToSocketAddrs>(addr: A, timeout: Duration) -> Result<Self> {
        let stream = TcpStream::connect(addr).map_err(|_| {
            crate::hw::log::warn("hw::emu", "tcp connect failed");
            Error::TransportUnavailable
        })?;
        stream
            .set_read_timeout(Some(timeout))
            .map_err(|_| Error::TransportWrite)?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|_| Error::TransportWrite)?;
        crate::hw::log::info("hw::emu", "tcp connect");
        Ok(Self { stream })
    }

    /// Wrap an already-connected stream (tests).
    pub fn new(stream: TcpStream) -> Result<Self> {
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|_| Error::TransportWrite)?;
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .map_err(|_| Error::TransportWrite)?;
        Ok(Self { stream })
    }

    fn round_trip(&mut self, msg: &[u8]) -> Result<alloc::vec::Vec<u8>> {
        use std::io::ErrorKind as K;
        let fail = |e: std::io::Error| match e.kind() {
            // Unix reports an expired SO_RCVTIMEO/SO_SNDTIMEO as WouldBlock
            // (EAGAIN); Windows reports TimedOut. On a blocking socket with
            // a deadline set, WouldBlock can only mean the timeout fired.
            K::TimedOut | K::WouldBlock => Error::TransportTimeout,
            K::ConnectionReset | K::ConnectionAborted | K::BrokenPipe | K::UnexpectedEof => {
                Error::TransportDisconnected
            }
            _ => Error::TransportRead,
        };
        if msg.len() > MAX_APDU_LEN {
            return Err(Error::InvalidLength);
        }
        let len = (msg.len() as u32).to_be_bytes();
        self.stream
            .write_all(&len)
            .map_err(|_| Error::TransportWrite)?;
        self.stream
            .write_all(msg)
            .map_err(|_| Error::TransportWrite)?;
        self.stream.flush().map_err(|_| Error::TransportWrite)?;
        let mut hdr = [0u8; 4];
        self.stream.read_exact(&mut hdr).map_err(fail)?;
        let n = u32::from_be_bytes(hdr) as usize;
        if n > MAX_APDU_LEN {
            return Err(Error::InvalidLength);
        }
        let mut out = alloc::vec![0u8; n];
        self.stream.read_exact(&mut out).map_err(fail)?;
        Ok(out)
    }
}

impl Transport for TcpTransport {
    fn exchange(&mut self, msg: &[u8]) -> Result<alloc::vec::Vec<u8>> {
        self.round_trip(msg).inspect_err(|&e| {
            if e != Error::InvalidLength {
                crate::hw::log::warn("hw::emu", "tcp exchange failed");
            }
        })
    }

    fn exchange_timeout(&mut self, msg: &[u8], timeout: Duration) -> Result<alloc::vec::Vec<u8>> {
        self.stream
            .set_read_timeout(Some(timeout))
            .map_err(|_| Error::TransportWrite)?;
        self.stream
            .set_write_timeout(Some(timeout))
            .map_err(|_| Error::TransportWrite)?;
        self.round_trip(msg)
    }
}
